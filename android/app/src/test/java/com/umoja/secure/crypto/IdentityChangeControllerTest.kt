package com.umoja.secure.crypto

import com.umoja.secure.storage.KeyValueStore
import com.umoja.secure.transport.IdentityChangeApi
import com.umoja.secure.transport.IdentityChangeApiException
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.util.Base64

/**
 * Tests for IdentityChangeController.
 *
 * No real network, no real Keystore. API is injected as two lambdas
 * (production wires method references on [IdentityChangeApi]); the
 * store uses an in-memory KeyValueStore and a BouncyCastle signing
 * lambda, mirroring the ReplacementNoticeStore test pattern.
 */
class IdentityChangeControllerTest {

    private class InMemoryStore : KeyValueStore {
        val map = mutableMapOf<String, String>()
        override fun get(key: String): String? = map[key]
        override fun put(key: String, value: String) { map[key] = value }
        override fun remove(key: String) { map.remove(key) }
        override fun has(key: String): Boolean = map.containsKey(key)
    }

    private fun keyPair(): KeyPair {
        MatrixSigner.matrixDigestRaw(byteArrayOf())  // load BC
        return KeyPairGenerator.getInstance("Ed25519").generateKeyPair()
    }

    private fun signedNoticeBytes(kp: KeyPair): Pair<ByteArray, String> {
        val signed = SignedReplacementNotice(
            domain = SignedReplacementNotice.DOMAIN,
            notice = ReplacementNotice(
                fromDeviceId = "device-old",
                fromDeviceAuthKey = "A".repeat(43),
                toDeviceId = "device-new",
                toDeviceAuthKey = "B".repeat(43),
                issuedAt = "2026-10-17T00:00:00Z",
            ),
        )
        val canonical = jcsCanonicalizeString(signed.toJsonMap()).toByteArray(Charsets.UTF_8)
        val sig = ReplacementNoticeSigner.sign(signed, kp.private)
        return canonical to sig
    }

    private fun b64u(bytes: ByteArray): String =
        Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)

    private fun newStore(kp: KeyPair): ReplacementNoticeStore = ReplacementNoticeStore(
        store = InMemoryStore(),
        signingFn = { digest ->
            val sig = java.security.Signature.getInstance("Ed25519")
            sig.initSign(kp.private); sig.update(digest); sig.sign()
        },
        ackingDeviceId = "self-device",
    )

    private val defaultTokenProvider: () -> String? = { "test-session-token" }

    private fun remoteNotice(canonical: ByteArray, sig: String): IdentityChangeApi.RemoteNotice =
        IdentityChangeApi.RemoteNotice(
            noticeHash = "H".repeat(43),
            canonicalUtf8 = String(canonical, Charsets.UTF_8),
            signatureBase64url = sig,
            fromDeviceId = "device-old",
            toDeviceId = "device-new",
            createdAt = "2026-10-17T00:00:00Z",
        )

    @Test
    fun `refresh stores verified notices and bumps version`() = runBlocking {
        val kp = keyPair()
        val (canonical, sig) = signedNoticeBytes(kp)
        val store = newStore(kp)
        val c = IdentityChangeController(
            listNotices = { listOf(remoteNotice(canonical, sig)) },
            postAck = { _, _, _ -> IdentityChangeApi.AckResponse("h", "t") },
            store = store,
            sessionTokenProvider = defaultTokenProvider,
            trustedKeys = setOf(kp.public),
        )
        val r = c.refresh()
        assertTrue(r.isSuccess)
        assertEquals(1, store.pendingNotices().size)
        assertEquals(1L, c.version.value)
    }

    @Test
    fun `refresh skips bad-signature notices but still bumps version`() = runBlocking {
        val kp = keyPair()
        val (canonical, _) = signedNoticeBytes(kp)
        val store = newStore(kp)
        val c = IdentityChangeController(
            listNotices = { listOf(remoteNotice(canonical, "AAAA")) },  // bad sig
            postAck = { _, _, _ -> IdentityChangeApi.AckResponse("h", "t") },
            store = store,
            sessionTokenProvider = defaultTokenProvider,
            trustedKeys = setOf(kp.public),
        )
        c.refresh()
        assertEquals(0, store.pendingNotices().size)
        assertEquals(1L, c.version.value)
    }

    @Test
    fun `refresh returns failure and does not bump on network error`() = runBlocking {
        val kp = keyPair()
        val store = newStore(kp)
        val c = IdentityChangeController(
            listNotices = { throw IdentityChangeApiException("network_error") },
            postAck = { _, _, _ -> IdentityChangeApi.AckResponse("h", "t") },
            store = store,
            sessionTokenProvider = defaultTokenProvider,
            trustedKeys = setOf(kp.public),
        )
        assertTrue(c.refresh().isFailure)
        assertEquals(0L, c.version.value)
    }

    @Test
    fun `refresh returns failure on missing session token`() = runBlocking {
        val kp = keyPair()
        val store = newStore(kp)
        val c = IdentityChangeController(
            listNotices = { error("must not be called") },
            postAck = { _, _, _ -> error("must not be called") },
            store = store,
            sessionTokenProvider = { null },
            trustedKeys = setOf(kp.public),
        )
        assertTrue(c.refresh().isFailure)
        assertEquals(0L, c.version.value)
    }

    @Test
    fun `ackAndPost signs posts persists and bumps on success`() = runBlocking {
        val kp = keyPair()
        val (canonical, sig) = signedNoticeBytes(kp)
        val store = newStore(kp)
        var postCalled = false
        val c = IdentityChangeController(
            listNotices = { listOf(remoteNotice(canonical, sig)) },
            postAck = { _, _, _ ->
                postCalled = true
                IdentityChangeApi.AckResponse("h", "t")
            },
            store = store,
            sessionTokenProvider = defaultTokenProvider,
            trustedKeys = setOf(kp.public),
        )
        c.refresh()
        val notice = store.pendingNotices().single()
        val r = c.ackAndPost(notice, AckDecision.ACCEPT)
        assertTrue(postCalled)
        assertEquals(IdentityChangeController.AckResult.Success, r.getOrNull())
        // Accepted notices are no longer pending — read allNotices().
        assertEquals(ReplacementNoticeStore.State.ACKED_ACCEPT, store.allNotices().single().state)
        assertEquals(2L, c.version.value)
    }

    @Test
    fun `ackAndPost does not persist when API fails`() = runBlocking {
        val kp = keyPair()
        val (canonical, sig) = signedNoticeBytes(kp)
        val store = newStore(kp)
        val c = IdentityChangeController(
            listNotices = { listOf(remoteNotice(canonical, sig)) },
            postAck = { _, _, _ -> throw IdentityChangeApiException("invalid_signature") },
            store = store,
            sessionTokenProvider = defaultTokenProvider,
            trustedKeys = setOf(kp.public),
        )
        c.refresh()
        val notice = store.pendingNotices().single()
        val r = c.ackAndPost(notice, AckDecision.ACCEPT)
        assertEquals(IdentityChangeController.AckResult.Failure("invalid_signature"), r.getOrNull())
        // Still pending — POST failed, markAcked was not called.
        assertEquals(ReplacementNoticeStore.State.PENDING, store.allNotices().single().state)
        assertEquals(1L, c.version.value)  // only the refresh bump
    }

    @Test
    fun `ackAndPost returns failure when session missing`() = runBlocking {
        val kp = keyPair()
        val (canonical, sig) = signedNoticeBytes(kp)
        val store = newStore(kp)
        val c = IdentityChangeController(
            listNotices = { listOf(remoteNotice(canonical, sig)) },
            postAck = { _, _, _ -> error("must not be called") },
            store = store,
            sessionTokenProvider = defaultTokenProvider,
            trustedKeys = setOf(kp.public),
        )
        c.refresh()
        val notice = store.pendingNotices().single()
        val c2 = IdentityChangeController(
            listNotices = { error("x") },
            postAck = { _, _, _ -> error("must not be called") },
            store = store,
            sessionTokenProvider = { null },
            trustedKeys = setOf(kp.public),
        )
        val r = c2.ackAndPost(notice, AckDecision.ACCEPT)
        assertEquals(IdentityChangeController.AckResult.Failure("no_session"), r.getOrNull())
    }

    @Test
    fun `gateFor unblocked when no notice for peer`() {
        val kp = keyPair()
        val c = IdentityChangeController(
            listNotices = { error("x") },
            postAck = { _, _, _ -> error("x") },
            store = newStore(kp),
            sessionTokenProvider = defaultTokenProvider,
            trustedKeys = setOf(kp.public),
        )
        assertEquals(IdentityChangeController.GateState.Unblocked, c.gateFor("unknown"))
    }

    @Test
    fun `gateFor blocked pending for newest pending notice`() = runBlocking {
        val kp = keyPair()
        val (canonical, sig) = signedNoticeBytes(kp)
        val store = newStore(kp)
        val c = IdentityChangeController(
            listNotices = { listOf(remoteNotice(canonical, sig)) },
            postAck = { _, _, _ -> IdentityChangeApi.AckResponse("h", "t") },
            store = store,
            sessionTokenProvider = defaultTokenProvider,
            trustedKeys = setOf(kp.public),
        )
        c.refresh()
        val g = c.gateFor("device-new")
        assertTrue(g is IdentityChangeController.GateState.Blocked)
        assertEquals(
            IdentityChangeController.GateState.Reason.PENDING,
            (g as IdentityChangeController.GateState.Blocked).reason,
        )
    }

    @Test
    fun `gateFor blocked rejected after rejection`() = runBlocking {
        val kp = keyPair()
        val (canonical, sig) = signedNoticeBytes(kp)
        val store = newStore(kp)
        val c = IdentityChangeController(
            listNotices = { listOf(remoteNotice(canonical, sig)) },
            postAck = { _, _, _ -> IdentityChangeApi.AckResponse("h", "t") },
            store = store,
            sessionTokenProvider = defaultTokenProvider,
            trustedKeys = setOf(kp.public),
        )
        c.refresh()
        c.ackAndPost(store.pendingNotices().single(), AckDecision.REJECT)
        val g = c.gateFor("device-new")
        assertTrue(g is IdentityChangeController.GateState.Blocked)
        assertEquals(
            IdentityChangeController.GateState.Reason.REJECTED,
            (g as IdentityChangeController.GateState.Blocked).reason,
        )
    }

    @Test
    fun `gateFor unblocked after acceptance`() = runBlocking {
        val kp = keyPair()
        val (canonical, sig) = signedNoticeBytes(kp)
        val store = newStore(kp)
        val c = IdentityChangeController(
            listNotices = { listOf(remoteNotice(canonical, sig)) },
            postAck = { _, _, _ -> IdentityChangeApi.AckResponse("h", "t") },
            store = store,
            sessionTokenProvider = defaultTokenProvider,
            trustedKeys = setOf(kp.public),
        )
        c.refresh()
        c.ackAndPost(store.pendingNotices().single(), AckDecision.ACCEPT)
        assertEquals(IdentityChangeController.GateState.Unblocked, c.gateFor("device-new"))
    }

    @Test
    fun `gateFor picks newest notice by issuedAt when multiple target same peer`() = runBlocking {
        val kp = keyPair()

        fun mk(issuedAt: String): IdentityChangeApi.RemoteNotice {
            val signed = SignedReplacementNotice(
                domain = SignedReplacementNotice.DOMAIN,
                notice = ReplacementNotice(
                    fromDeviceId = "device-old",
                    fromDeviceAuthKey = "A".repeat(43),
                    toDeviceId = "device-new",
                    toDeviceAuthKey = "B".repeat(43),
                    issuedAt = issuedAt,
                ),
            )
            val canonical = jcsCanonicalizeString(signed.toJsonMap()).toByteArray()
            val sig = ReplacementNoticeSigner.sign(signed, kp.private)
            return remoteNotice(canonical, sig)
        }

        val older = mk("2026-10-15T00:00:00Z")
        val newer = mk("2026-10-17T00:00:00Z")
        val store = newStore(kp)
        val c = IdentityChangeController(
            listNotices = { listOf(older, newer) },
            postAck = { _, _, _ -> IdentityChangeApi.AckResponse("h", "t") },
            store = store,
            sessionTokenProvider = defaultTokenProvider,
            trustedKeys = setOf(kp.public),
        )
        c.refresh()
        val g = c.gateFor("device-new")
        assertTrue(g is IdentityChangeController.GateState.Blocked)
        val blocked = g as IdentityChangeController.GateState.Blocked
        assertEquals("2026-10-17T00:00:00Z", blocked.notice.issuedAt)
    }

    @Test
    fun `TEST-DIAG-ACK-FAILURE-LOGGED records ack POST failure`() = runBlocking {
        MatrixSigner.matrixDigestRaw(byteArrayOf())
        val kp = keyPair()
        val (canonical, sig) = signedNoticeBytes(kp)
        val failureLog = VerificationFailureStore(InMemoryStore())
        val store = newStore(kp)
        val c = IdentityChangeController(
            listNotices = { listOf(remoteNotice(canonical, sig)) },
            postAck = { _, _, _ -> throw IdentityChangeApiException("invalid_signature") },
            store = store,
            sessionTokenProvider = defaultTokenProvider,
            trustedKeys = setOf(kp.public),
            failureLog = failureLog,
        )
        c.refresh()
        val notice = store.pendingNotices().single()
        val r = c.ackAndPost(notice, AckDecision.ACCEPT)
        assertTrue(r.getOrNull() is IdentityChangeController.AckResult.Failure)

        val entries = failureLog.entries()
        assertEquals(1, entries.size)
        assertEquals(
            VerificationFailureStore.ArtifactType.ACK,
            entries[0].artifactType,
        )
        assertEquals("invalid_signature", entries[0].reason)
    }
}
