package com.umoja.secure.auth

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import java.time.Instant

/**
 * Session lifecycle state machine. ADR-HARDENING-001 §2, TASK-P1-040-B.
 *
 * Seven states (matching ADR §2's rulings verbatim):
 *
 *   Unauthenticated -> Authenticating -> Authenticated
 *   Authenticated   -> Reauthenticating -> {Authenticated | Revoked |
 *                                           EnrollmentRequired |
 *                                           NetworkFailure}
 *   NetworkFailure  -> Authenticating (user retry)
 *   Revoked, EnrollmentRequired -> terminal
 *
 * `[StoredSession]` is [SessionManager]'s existing storage shape; the
 * state manager reads it via [sessionProvider] and writes back only
 * through [reauth] (which production wires to
 * `SessionManager.authenticate()`).
 *
 * **Single-flight.** Concurrent 401s produce exactly one reauth. A
 * [Mutex] serializes the leader/follower setup; a
 * [CompletableDeferred] is the "same future" ADR §2 prescribes — the
 * leader completes it, followers await it. Bare mutex alone would
 * serialize five reauths (each caller runs the lambda in turn); the
 * deferred is what makes five callers share one result. This is the
 * first `Mutex` and first `CompletableDeferred` in the codebase —
 * named here so future readers see the two-pattern shape and the
 * reasoning.
 *
 * **Boundary: what lives in 040-D, not here.** ADR §2 assigns two
 * more responsibilities to the *interceptor*, not the state manager:
 *  - Recursion guard: `/auth/challenge` and `/auth/verify` 401s must
 *    not trigger re-auth. Enforced by URL prefix at the interceptor
 *    layer.
 *  - Retry-original-call: the interceptor buffers the failed request,
 *    calls `reauthenticate()`, and re-executes the buffered call once
 *    on success. The state manager does not retry — it transitions
 *    state and returns.
 * 040-B's class is correct without either; 040-D wires both.
 *
 * **Fail-toward-recovery on malformed expiry.** [isExpired] treats an
 * unparseable `expiresAt` as expired. ADR §1: a fielded user must
 * never be stranded. An unparseable date is indistinguishable from
 * corruption; treating it as expired routes the user through re-auth
 * (which recovers if the backend is healthy) rather than trusting a
 * value we cannot read (which would strand the user with a stale
 * token).
 *
 * Task: TASK-P1-040-B
 * ADR: ADR-HARDENING-001 §2, §9 v0.2 items 2-3
 */
class SessionStateManager(
    private val reauth: suspend () -> ReauthOutcome,
    private val sessionProvider: () -> StoredSession?,
    private val clock: () -> Long = System::currentTimeMillis,
) {
    sealed class State {
        /** No session token. Pre-app-start, or after local clear. */
        object Unauthenticated : State()

        /** Challenge-response in flight (app-start, user retry). */
        object Authenticating : State()

        /** Normal operation. */
        data class Authenticated(val token: String, val expiresAt: String) : State()

        /** 401 received from any API; reauth in flight. */
        object Reauthenticating : State()

        /** Server rejected reauth with `device_revoked`. Terminal. */
        object Revoked : State()

        /** Reauth failed on transport. Retryable. */
        data class NetworkFailure(val reason: String) : State()

        /**
         * Reauth rejected with `unauthorized` but device status was
         * `active` (backend inconsistency; ADR §2). Terminal until
         * user clears and re-enrolls.
         */
        object EnrollmentRequired : State()
    }

    /**
     * Outcome of one reauth attempt, as seen by [SessionStateManager].
     * Distinct from [SessionManager.AuthOutcome] because the state
     * manager cares about the routing semantics (terminal vs
     * retryable vs success), not about the wire taxonomy.
     * Production wiring in 040-C maps AuthOutcome -> ReauthOutcome.
     */
    sealed class ReauthOutcome {
        data class Success(val session: StoredSession) : ReauthOutcome()
        object DeviceRevoked : ReauthOutcome()
        object EnrollmentRequired : ReauthOutcome()
        data class NetworkFailure(val reason: String) : ReauthOutcome()
    }

    private val _state = MutableStateFlow<State>(State.Unauthenticated)
    val state: StateFlow<State> = _state.asStateFlow()

    private val reauthMutex = Mutex()
    private var reauthInFlight: CompletableDeferred<ReauthOutcome>? = null

    /**
     * App-start entry point. Reads the stored session, decides whether
     * it is expired, and runs reauth if needed. Per ADR §2's
     * "app-start expiry check" ruling: a session expired while the app
     * was closed routes to re-auth silently, not to a button tap.
     */
    suspend fun initialize(): State = withContext(Dispatchers.IO) {
        val session = sessionProvider()
        if (session == null) {
            _state.value = State.Unauthenticated
            return@withContext State.Unauthenticated
        }
        if (isExpired(session.expiresAt)) {
            _state.value = State.Authenticating
            return@withContext performReauth()
        }
        val authenticated = State.Authenticated(session.sessionToken, session.expiresAt)
        _state.value = authenticated
        authenticated
    }

    /**
     * Entry point for any caller that hit a 401. The interceptor
     * (040-D) calls this after receiving a 401 from a non-auth
     * endpoint. Also the user-retry entry point from [NetworkFailure].
     *
     * Terminal states ([Revoked], [EnrollmentRequired]) return
     * immediately without invoking [reauth] — retrying a terminal
     * failure would either spin or mislead.
     */
    suspend fun reauthenticate(): State = withContext(Dispatchers.IO) {
        when (_state.value) {
            is State.Revoked, is State.EnrollmentRequired -> _state.value
            is State.Unauthenticated -> {
                _state.value = State.Authenticating
                performReauth()
            }
            is State.Authenticated -> {
                _state.value = State.Reauthenticating
                performReauth()
            }
            is State.NetworkFailure -> {
                _state.value = State.Authenticating
                performReauth()
            }
            is State.Authenticating, is State.Reauthenticating -> {
                performReauth()
            }
        }
    }

    /**
     * Reset to [State.Unauthenticated]. Called by AppRoot after logout
     * clears local storage; without this, [state] would lie (still
     * [State.Authenticated]) after the session token is removed from
     * [SessionManager]. A single unsynchronized [MutableStateFlow]
     * write because terminal reset has no concurrent-caller semantics
     * to serialize -- unlike [reauthenticate], there is no network
     * call to single-flight; the caller (logout handler) drives the
     * sequencing.
     *
     * Does not clear [reauthInFlight] -- if a reauth is racing with a
     * logout, the reauth's eventual completion will transition state
     * to whichever outcome it returns. That race is not user-visible
     * (logout already nulled the token; a subsequent reauth sees no
     * session and returns NetworkFailure or EnrollmentRequired, not
     * Authenticated), but the possible stale write is documented here
     * rather than guarded. 040-C-2 wires logout so a reauth is not in
     * flight when clear() is called (logout is a deliberate user
     * action, not a 401 response). If a future flow allows reauth
     * concurrent with logout, revisit.
     */
    suspend fun clear(): State = withContext(Dispatchers.IO) {
        _state.value = State.Unauthenticated
        State.Unauthenticated
    }

    /**
     * Single-flight core. Returns the (possibly cached) outcome.
     * Leader executes [reauth]; followers await the shared deferred.
     * Leader clears [reauthInFlight] in a finally so a crash between
     * `reauth()` and `complete()` does not strand followers on a
     * deferred that will never complete.
     */
    private suspend fun performReauth(): State {
        val (isLeader, deferred) = reauthMutex.withLock {
            reauthInFlight?.let { false to it } ?: run {
                val d = CompletableDeferred<ReauthOutcome>()
                reauthInFlight = d
                true to d
            }
        }
        if (!isLeader) {
            val outcome = try {
                deferred.await()
            } catch (e: Exception) {
                ReauthOutcome.NetworkFailure(e.message ?: "unknown")
            }
            return mapOutcome(outcome)
        }
        val outcome = try {
            reauth()
        } catch (e: Exception) {
            ReauthOutcome.NetworkFailure(e.message ?: "unknown")
        }
        try {
            deferred.complete(outcome)
        } finally {
            reauthMutex.withLock { reauthInFlight = null }
        }
        return mapOutcome(outcome)
    }

    private fun mapOutcome(outcome: ReauthOutcome): State {
        val next = when (outcome) {
            is ReauthOutcome.Success ->
                State.Authenticated(outcome.session.sessionToken, outcome.session.expiresAt)
            ReauthOutcome.DeviceRevoked -> State.Revoked
            ReauthOutcome.EnrollmentRequired -> State.EnrollmentRequired
            is ReauthOutcome.NetworkFailure -> State.NetworkFailure(outcome.reason)
        }
        _state.value = next
        return next
    }

    private fun isExpired(expiresAt: String): Boolean = try {
        Instant.parse(expiresAt).toEpochMilli() <= clock()
    } catch (_: Exception) {
        true
    }
}
