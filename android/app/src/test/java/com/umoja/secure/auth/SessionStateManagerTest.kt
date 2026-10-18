package com.umoja.secure.auth

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.yield
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class SessionStateManagerTest {

    private val validSession = StoredSession(
        sessionToken = "test-token",
        expiresAt = "2099-01-01T00:00:00.000Z",
        role = "user",
    )

    private val expiredSession = StoredSession(
        sessionToken = "old-token",
        expiresAt = "2020-01-01T00:00:00.000Z",
        role = "user",
    )

    private fun newManager(
        reauth: suspend () -> SessionStateManager.ReauthOutcome,
        sessionProvider: () -> StoredSession? = { validSession },
    ): SessionStateManager = SessionStateManager(
        reauth = reauth,
        sessionProvider = sessionProvider,
    )

    private fun successOutcome(session: StoredSession = validSession) =
        SessionStateManager.ReauthOutcome.Success(session)

    @Test
    fun `TEST-SESSION-EXPIRED-AUTO-REAUTH`() = runBlocking {
        var reauthCalls = 0
        val fresh = StoredSession("fresh-token", "2099-12-31T00:00:00.000Z", "user")
        val mgr = newManager(
            reauth = { reauthCalls++; successOutcome(fresh) },
            sessionProvider = { expiredSession },
        )
        val result = mgr.initialize()
        assertEquals(1, reauthCalls)
        assertTrue(result is SessionStateManager.State.Authenticated)
        assertEquals("fresh-token", (result as SessionStateManager.State.Authenticated).token)
    }

    @Test
    fun `TEST-SESSION-CONCURRENT-401-SINGLE-REAUTH`() = runBlocking {
        var reauthCalls = 0
        val gate = CompletableDeferred<Unit>()
        val mgr = newManager(
            reauth = {
                reauthCalls++
                gate.await()
                successOutcome()
            },
            sessionProvider = { validSession },
        )
        mgr.initialize()
        val results = (1..5).map {
            async(Dispatchers.Default) { mgr.reauthenticate() }
        }
        // Wait for leader to enter reauth().
        awaitCondition { reauthCalls >= 1 }
        // delay (not yield) so followers on Dispatchers.Default have
        // real wall-clock time to reach performReauth and become
        // followers awaiting the leader's deferred. yield() only
        // releases the runBlocking thread; it does not release
        // Default-pool coroutines. Without this, followers can arrive
        // after the leader completes and each become a fresh leader
        // (reauthCalls > 1). No observable signal for "follower
        // awaiting" exists on the state manager's public surface, so
        // a bounded delay is the honest test seam.
        delay(200)
        // Load-bearing single-flight check: while the leader is still
        // inside reauth(), no follower has become a new leader.
        assertEquals(
            "single-flight violated during leader block: ${reauthCalls} reauths",
            1, reauthCalls,
        )
        gate.complete(Unit)
        val outcomes = results.awaitAll()
        assertEquals(
            "single-flight violated after await: ${reauthCalls} reauths",
            1, reauthCalls,
        )
        // outcomes is List<State> (awaitAll returns it). Iterating
        // `results` would iterate Deferred<State> and always fail
        // `it is Authenticated` — the bug this test hit on first run.
        outcomes.forEachIndexed { i, r ->
            assertTrue(
                "result[$i] should be Authenticated, got $r",
                r is SessionStateManager.State.Authenticated,
            )
        }
    }

    @Test
    fun `TEST-SESSION-REVOKED-TERMINAL`() = runBlocking {
        var reauthCalls = 0
        val mgr = newManager(
            reauth = { reauthCalls++; SessionStateManager.ReauthOutcome.DeviceRevoked },
            sessionProvider = { validSession },
        )
        mgr.initialize()
        val first = mgr.reauthenticate()
        assertTrue(first is SessionStateManager.State.Revoked)
        assertEquals(1, reauthCalls)
        val second = mgr.reauthenticate()
        assertTrue(second is SessionStateManager.State.Revoked)
        assertEquals(1, reauthCalls)
    }

    @Test
    fun `TEST-SESSION-NETWORK-DURING-REAUTH`() = runBlocking {
        var reauthCalls = 0
        var nextOutcome: SessionStateManager.ReauthOutcome =
            SessionStateManager.ReauthOutcome.NetworkFailure("connection_lost")
        val mgr = newManager(
            reauth = { reauthCalls++; nextOutcome },
            sessionProvider = { validSession },
        )
        mgr.initialize()
        val first = mgr.reauthenticate()
        assertTrue(first is SessionStateManager.State.NetworkFailure)
        assertEquals(1, reauthCalls)
        nextOutcome = successOutcome()
        val second = mgr.reauthenticate()
        assertTrue(second is SessionStateManager.State.Authenticated)
        assertEquals(2, reauthCalls)
    }

    @Test
    fun `TEST-SESSION-ENROLLMENT-REQUIRED-TERMINAL`() = runBlocking {
        var reauthCalls = 0
        val mgr = newManager(
            reauth = {
                reauthCalls++
                SessionStateManager.ReauthOutcome.EnrollmentRequired
            },
            sessionProvider = { validSession },
        )
        mgr.initialize()
        val first = mgr.reauthenticate()
        assertTrue(first is SessionStateManager.State.EnrollmentRequired)
        assertEquals(1, reauthCalls)
        val second = mgr.reauthenticate()
        assertTrue(second is SessionStateManager.State.EnrollmentRequired)
        assertEquals(1, reauthCalls)
    }

    @Test
    fun `INITIALIZE-VALID-SESSION`() = runBlocking {
        var reauthCalls = 0
        val mgr = newManager(
            reauth = { reauthCalls++; error("must not be called") },
            sessionProvider = { validSession },
        )
        val result = mgr.initialize()
        assertEquals(0, reauthCalls)
        assertTrue(result is SessionStateManager.State.Authenticated)
        assertEquals("test-token", (result as SessionStateManager.State.Authenticated).token)
    }

    @Test
    fun `INITIALIZE-NO-SESSION`() = runBlocking {
        var reauthCalls = 0
        val mgr = newManager(
            reauth = { reauthCalls++; error("must not be called") },
            sessionProvider = { null },
        )
        val result = mgr.initialize()
        assertEquals(0, reauthCalls)
        assertTrue(result is SessionStateManager.State.Unauthenticated)
    }

    @Test
    fun `INITIALIZE-MALFORMED-EXPIRY-ATTEMPTS-REAUTH`() = runBlocking {
        var reauthCalls = 0
        val malformed = StoredSession("token", "not-a-date", "user")
        val mgr = newManager(
            reauth = { reauthCalls++; successOutcome() },
            sessionProvider = { malformed },
        )
        val result = mgr.initialize()
        assertEquals(1, reauthCalls)
        assertTrue(result is SessionStateManager.State.Authenticated)
    }

    @Test
    fun `REAUTH-LAMBDA-THROWS-MAPS-TO-NETWORK-FAILURE`() = runBlocking {
        val mgr = newManager(
            reauth = { throw RuntimeException("boom") },
            sessionProvider = { validSession },
        )
        mgr.initialize()
        val result = mgr.reauthenticate()
        assertTrue(result is SessionStateManager.State.NetworkFailure)
    }

    @Test
    fun `REAUTH-ON-UNAUTHENTICATED-TRANSITIONS-VIA-AUTHENTICATING`() = runBlocking {
        var reauthCalls = 0
        val mgr = newManager(
            reauth = { reauthCalls++; successOutcome() },
            sessionProvider = { null },
        )
        mgr.initialize()
        val result = mgr.reauthenticate()
        assertEquals(1, reauthCalls)
        assertTrue(result is SessionStateManager.State.Authenticated)
    }

    @Test
    fun `REAUTH-STATE-FLOW-EMITS-TERMINAL-STATE`() = runBlocking {
        val mgr = newManager(
            reauth = { SessionStateManager.ReauthOutcome.DeviceRevoked },
            sessionProvider = { validSession },
        )
        mgr.initialize()
        mgr.reauthenticate()
        assertTrue(mgr.state.value is SessionStateManager.State.Revoked)
    }

    @Test
    fun `REAUTH-AFTER-SUCCESS-CAN-RETRIGGER`() = runBlocking {
        var reauthCalls = 0
        val mgr = newManager(
            reauth = { reauthCalls++; successOutcome() },
            sessionProvider = { validSession },
        )
        mgr.initialize()
        mgr.reauthenticate()
        assertEquals(1, reauthCalls)
        mgr.reauthenticate()
        assertEquals(2, reauthCalls)
    }

    private suspend fun awaitCondition(
        timeoutMs: Long = 2_000,
        block: () -> Boolean,
    ) {
        val start = System.currentTimeMillis()
        while (!block()) {
            if (System.currentTimeMillis() - start > timeoutMs) {
                throw AssertionError("condition not met within ${timeoutMs}ms")
            }
            yield()
        }
    }
}
