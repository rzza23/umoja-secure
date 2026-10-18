package com.umoja.secure.crypto

import com.umoja.secure.transport.IdentityChangeApi
import com.umoja.secure.transport.IdentityChangeApiException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.withContext
import java.security.PublicKey

/**
 * Orchestrates the identity-change flow: poll, verify, store, ack-post.
 *
 * Sits between [IdentityChangeApi] and [ReplacementNoticeStore], and
 * above the UI. The UI drives [refresh] / [ackAndPost] and reads
 * [version] + [gateFor]; it never calls the API or store directly.
 * Policy lives here, persistence in the store, wire in the API.
 *
 * **version is a write-notification, not a data cache.** The UI collects
 * [version] via collectAsState and re-derives gate state on each tick
 * with `remember(version, peerId) { controller.gateFor(peerId) }`. The
 * store reads are cheap (encrypted prefs); caching a StateFlow of
 * notices would invite drift from the store's truth. Any successful
 * write path (refresh completion, ack-post completion) bumps version.
 *
 * **Gate derivation.** [gateFor] filters the store's notices by
 * `toDeviceId` and returns the newest by `issuedAt`. PENDING and
 * ACKED_REJECT are blocked; ACKED_ACCEPT and no-match are unblocked.
 * Returns the [ReplacementNoticeStore.StoredNotice] alongside the
 * reason — the UI needs it to render "device X" and offer the ack
 * dialog. The store's `BlockState` (reason only) stays available for
 * any future caller; the controller uses the richer shape it needs.
 * `GateState` is deliberately a distinct type — two `BlockState`s in
 * the same package would be a rename waiting to happen.
 *
 * **Ack flow = sign → POST → markAcked.** The order is load-bearing:
 * [ackAndPost] signs via the store's `ack()` (no persist), posts to the
 * API, and only calls `markAcked()` on POST success. Crash between POST
 * and markAcked recovers on retry — the backend PK
 * (notice_hash, acking_device_id) is idempotent, so a second POST
 * returns 201 with the same ack_hash. This is the Q2 contract: local
 * state follows confirmed delivery, never precedes it.
 *
 * **API as function parameters.** `listNotices` and `postAck` are
 * callbacks, not a concrete [IdentityChangeApi] — the shipped class is
 * final and extracting an interface for testability would touch a
 * just-shipped file. Production wires method references; tests wire
 * lambdas. Same pattern as `signingFn` in [ReplacementNoticeStore].
 *
 * Task: TASK-P1-030 030e-c 3d
 * ADR: ADR-IDENTITY-CHANGE-001 §5, §7
 */
class IdentityChangeController(
    private val listNotices: (String) -> List<IdentityChangeApi.RemoteNotice>,
    private val postAck: (String, String, String) -> IdentityChangeApi.AckResponse,
    private val store: ReplacementNoticeStore,
    private val sessionTokenProvider: () -> String?,
    private val trustedKeys: Set<PublicKey>,
    private val failureLog: VerificationFailureStore? = null,
) {
    private val _version = MutableStateFlow(0L)
    val version: StateFlow<Long> = _version.asStateFlow()

    sealed class GateState {
        object Unblocked : GateState()
        data class Blocked(
            val reason: Reason,
            val notice: ReplacementNoticeStore.StoredNotice,
        ) : GateState()
        enum class Reason { PENDING, REJECTED }
    }

    sealed class AckResult {
        object Success : AckResult()
        data class Failure(val code: String) : AckResult()
    }

    /**
     * Poll the backend, verify-and-store each notice, bump [version] on
     * completion. Per-notice signature failures are skipped — one bad
     * notice does not poison the whole refresh. Transport failures
     * return failure and do NOT bump version (nothing changed locally).
     */
    suspend fun refresh(): Result<Unit> = withContext(Dispatchers.IO) {
        val token = sessionTokenProvider()
            ?: return@withContext Result.failure(IllegalStateException("no_session"))
        val remote = try {
            listNotices(token)
        } catch (e: IdentityChangeApiException) {
            return@withContext Result.failure(e)
        }
        for (r in remote) {
            store.recordNotice(
                canonical = r.canonicalUtf8.toByteArray(Charsets.UTF_8),
                signatureBase64url = r.signatureBase64url,
                trustedKeys = trustedKeys,
            )
        }
        _version.value++
        Result.success(Unit)
    }

    /**
     * Sign the ack, POST it, persist local state only on success.
     * See class KDoc for the sign → POST → markAcked contract.
     */
    suspend fun ackAndPost(
        notice: ReplacementNoticeStore.StoredNotice,
        decision: AckDecision,
    ): Result<AckResult> = withContext(Dispatchers.IO) {
        val token = sessionTokenProvider()
            ?: run {
                failureLog?.record(VerificationFailureStore.ArtifactType.ACK, "no_session", ByteArray(0))
                return@withContext Result.success(AckResult.Failure("no_session"))
            }
        val signed = try {
            store.ack(notice.noticeHash, decision)
        } catch (_: Exception) {
            failureLog?.record(VerificationFailureStore.ArtifactType.ACK, "ack_sign_failed", ByteArray(0))
            return@withContext Result.success(AckResult.Failure("ack_sign_failed"))
        }
        try {
            postAck(signed.canonicalUtf8, signed.signatureBase64url, token)
        } catch (e: IdentityChangeApiException) {
            failureLog?.record(VerificationFailureStore.ArtifactType.ACK, e.code, signed.canonicalUtf8.toByteArray())
            return@withContext Result.success(AckResult.Failure(e.code))
        }
        store.markAcked(notice.noticeHash, decision)
        _version.value++
        Result.success(AckResult.Success)
    }

    /**
     * Derive the send-gate state for a peer. Synchronous — the store is
     * a cheap read. Callers `remember(version, peerId)` so store changes
     * propagate to composition.
     */
    fun gateFor(peerId: String): GateState {
        val notices = store.allNotices().filter { it.toDeviceId == peerId }
        val newest = notices.maxByOrNull { it.issuedAt } ?: return GateState.Unblocked
        return when (newest.state) {
            ReplacementNoticeStore.State.PENDING ->
                GateState.Blocked(GateState.Reason.PENDING, newest)
            ReplacementNoticeStore.State.ACKED_REJECT ->
                GateState.Blocked(GateState.Reason.REJECTED, newest)
            ReplacementNoticeStore.State.ACKED_ACCEPT ->
                GateState.Unblocked
        }
    }
}