package com.umoja.secure.crypto

import com.umoja.secure.storage.KeyValueStore
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.Signature
import java.util.Base64

/**
 * Tests for ReplacementNoticeStore.
 *
 * In-memory KeyValueStore so the suite runs on the JVM without a
 * Context. Fresh Ed25519 keypairs sign the notices and acks; the same
 * keypair is used as the trusted set so the flow is self-consistent.
 *
 * Signing goes through a BouncyCastle-backed lambda, matching the
 * production signingFn contract. Every ack produced by [ack] round-
 * trips through [IdentityChangeAckSigner.verify] against the same
 * keypair's public key — that assertion proves the store's signing
 * path is wired correctly end-to-end.
 *
 * Task: TASK-P1-030 030e-c 3b
 * ADR: ADR-IDENTITY-CHANGE-001 §3, §5, §7
 */
class ReplacementNoticeStoreTest {

    private class InMemoryStore : KeyValueStore {
        private val map = mutableMapOf<String, String>()
        override fun put(key: String, value: String) { map[key] = value }
        override fun get(key: String): String? = map[key]
        override fun remove(key: String) { map.remove(key) }
        override fun has(key: String): Boolean = map.containsKey(key)
    }

    private val keyPair: KeyPair =
        KeyPairGenerator.getInstance("Ed25519").generateKeyPair()

    private val signingFn: (ByteArray) -> ByteArray = { digest ->
        Signature.getInstance("Ed25519").run {
            initSign(keyPair.private)
            update(digest)
            sign()
        }
    }

    private fun newStore(underlying: KeyValueStore = InMemoryStore()) =
        ReplacementNoticeStore(underlying, signingFn, "device-self-001")

    private fun signedNotice(
        from: String = "device-old-001",
        to: String = "device-new-002",
        issuedAt: String = "2026-10-17T00:00:00Z",
    ): Pair<ByteArray, String> {
        val signed = SignedReplacementNotice(
            domain = SignedReplacementNotice.DOMAIN,
            notice = ReplacementNotice(
                fromDeviceId = from,
                fromDeviceAuthKey = "A".repeat(43),
                toDeviceId = to,
                toDeviceAuthKey = "B".repeat(43),
                issuedAt = issuedAt,
            ),
        )
        val canonical = jcsCanonicalizeString(signed.toJsonMap()).toByteArray(Charsets.UTF_8)
        val sig = ReplacementNoticeSigner.sign(signed, keyPair.private)
        return canonical to sig
    }

    private fun trustedSet() = setOf(keyPair.public)

    // ---------- recordNotice ----------

    @Test
    fun `TEST-NOTICE-STORE-RECORD-PENDING stores a verified notice as pending`() {
        val store = newStore()
        val (canonical, sig) = signedNotice()
        val result = store.recordNotice(canonical, sig, trustedSet())

        assertTrue(result is ReplacementNoticeStore.RecordResult.Pending)
        val pending = store.pendingNotices()
        assertEquals(1, pending.size)
        assertEquals("device-old-001", pending[0].fromDeviceId)
        assertEquals("device-new-002", pending[0].toDeviceId)
        assertEquals(ReplacementNoticeStore.State.PENDING, pending[0].state)
    }

    @Test
    fun `TEST-NOTICE-STORE-RECORD-BAD-SIGNATURE rejects and does not persist`() {
        val store = newStore()
        val (canonical, _) = signedNotice()
        val badSig = "A".repeat(86)
        val result = store.recordNotice(canonical, badSig, trustedSet())

        assertTrue(result is ReplacementNoticeStore.RecordResult.Invalid)
        assertEquals("signature", (result as ReplacementNoticeStore.RecordResult.Invalid).reason)
        assertEquals(0, store.pendingNotices().size)
    }

    @Test
    fun `TEST-NOTICE-STORE-RECORD-BAD-FORMAT rejects non-wrapper bytes with valid signature`() {
        val store = newStore()
        // Sign arbitrary non-wrapper bytes: verification passes, parse
        // fails, return Invalid("malformed"), do not persist.
        val notJson = "not-json".toByteArray(Charsets.UTF_8)
        val arbitrarySig = Base64.getUrlEncoder().withoutPadding().encodeToString(
            Signature.getInstance("Ed25519").run {
                initSign(keyPair.private)
                update(MessageDigest.getInstance("SHA-256").digest(notJson))
                sign()
            },
        )
        val result = store.recordNotice(notJson, arbitrarySig, trustedSet())

        assertTrue(result is ReplacementNoticeStore.RecordResult.Invalid)
        assertEquals("malformed", (result as ReplacementNoticeStore.RecordResult.Invalid).reason)
        assertEquals(0, store.pendingNotices().size)
    }

    @Test
    fun `TEST-NOTICE-STORE-RECORD-IDEMPOTENT same notice twice returns one row`() {
        val store = newStore()
        val (canonical, sig) = signedNotice()

        val r1 = store.recordNotice(canonical, sig, trustedSet())
        val r2 = store.recordNotice(canonical, sig, trustedSet())

        assertTrue(r1 is ReplacementNoticeStore.RecordResult.Pending)
        assertTrue(r2 is ReplacementNoticeStore.RecordResult.Pending)
        assertEquals(1, store.pendingNotices().size)
    }

    // ---------- blockStateFor ----------

    @Test
    fun `TEST-NOTICE-STORE-BLOCK-UNBLOCKED with no notice`() {
        val store = newStore()
        assertTrue(store.blockStateFor("device-new-002") is ReplacementNoticeStore.BlockState.Unblocked)
    }

    @Test
    fun `TEST-NOTICE-STORE-BLOCK-PENDING while awaiting decision`() {
        val store = newStore()
        val (canonical, sig) = signedNotice()
        store.recordNotice(canonical, sig, trustedSet())

        val state = store.blockStateFor("device-new-002")
        assertTrue(state is ReplacementNoticeStore.BlockState.Blocked)
        assertEquals(
            ReplacementNoticeStore.BlockState.Reason.PENDING,
            (state as ReplacementNoticeStore.BlockState.Blocked).reason,
        )
    }

    @Test
    fun `TEST-NOTICE-STORE-BLOCK-AFTER-ACCEPT unblocks`() {
        val store = newStore()
        val (canonical, sig) = signedNotice()
        val r = store.recordNotice(canonical, sig, trustedSet()) as ReplacementNoticeStore.RecordResult.Pending
        store.markAcked(r.noticeHash, AckDecision.ACCEPT)

        assertTrue(store.blockStateFor("device-new-002") is ReplacementNoticeStore.BlockState.Unblocked)
    }

    @Test
    fun `TEST-NOTICE-STORE-BLOCK-AFTER-REJECT stays blocked`() {
        val store = newStore()
        val (canonical, sig) = signedNotice()
        val r = store.recordNotice(canonical, sig, trustedSet()) as ReplacementNoticeStore.RecordResult.Pending
        store.markAcked(r.noticeHash, AckDecision.REJECT)

        val state = store.blockStateFor("device-new-002")
        assertTrue(state is ReplacementNoticeStore.BlockState.Blocked)
        assertEquals(
            ReplacementNoticeStore.BlockState.Reason.REJECTED,
            (state as ReplacementNoticeStore.BlockState.Blocked).reason,
        )
    }

    @Test
    fun `TEST-NOTICE-STORE-BLOCK-NEWEST-WINS newer notice supersedes older`() {
        val store = newStore()
        val (c1, s1) = signedNotice(issuedAt = "2026-10-17T00:00:00Z")
        val r1 = store.recordNotice(c1, s1, trustedSet()) as ReplacementNoticeStore.RecordResult.Pending
        store.markAcked(r1.noticeHash, AckDecision.REJECT)

        val (c2, s2) = signedNotice(issuedAt = "2026-10-17T01:00:00Z")
        store.recordNotice(c2, s2, trustedSet())

        val state = store.blockStateFor("device-new-002")
        assertTrue(state is ReplacementNoticeStore.BlockState.Blocked)
        assertEquals(
            ReplacementNoticeStore.BlockState.Reason.PENDING,
            (state as ReplacementNoticeStore.BlockState.Blocked).reason,
        )
    }

    // ---------- ack ----------

    @Test
    fun `TEST-NOTICE-STORE-ACK-SIGNS returns ack whose signature verifies`() {
        val store = newStore()
        val (canonical, sig) = signedNotice()
        val r = store.recordNotice(canonical, sig, trustedSet()) as ReplacementNoticeStore.RecordResult.Pending

        val ack = store.ack(r.noticeHash, AckDecision.ACCEPT)
        assertEquals(r.noticeHash, ack.wrapper.ack.noticeHash)
        assertEquals("device-self-001", ack.wrapper.ack.ackingDeviceId)
        assertEquals("accept", ack.wrapper.ack.decision)
        assertTrue(IdentityChangeAckSigner.verify(ack.wrapper, ack.signatureBase64url, keyPair.public))
        assertEquals(jcsCanonicalizeString(ack.wrapper.toJsonMap()), ack.canonicalUtf8)
    }

    @Test
    fun `TEST-NOTICE-STORE-MARKACKED-TRANSITIONS moves pending to acked`() {
        val store = newStore()
        val (canonical, sig) = signedNotice()
        val r = store.recordNotice(canonical, sig, trustedSet()) as ReplacementNoticeStore.RecordResult.Pending
        assertEquals(1, store.pendingNotices().size)

        store.markAcked(r.noticeHash, AckDecision.ACCEPT)
        assertEquals(0, store.pendingNotices().size)
    }

    @Test
    fun `TEST-NOTICE-STORE-MARKACKED-IDEMPOTENT second call is a no-op`() {
        val store = newStore()
        val (canonical, sig) = signedNotice()
        val r = store.recordNotice(canonical, sig, trustedSet()) as ReplacementNoticeStore.RecordResult.Pending

        store.markAcked(r.noticeHash, AckDecision.ACCEPT)
        store.markAcked(r.noticeHash, AckDecision.REJECT)

        assertTrue(store.blockStateFor("device-new-002") is ReplacementNoticeStore.BlockState.Unblocked)
    }

    // ---------- persistence ----------

    @Test
    fun `TEST-NOTICE-STORE-PERSISTENCE survives new store instance`() {
        val underlying = InMemoryStore()
        val store1 = ReplacementNoticeStore(underlying, signingFn, "device-self-001")
        val (canonical, sig) = signedNotice()
        store1.recordNotice(canonical, sig, trustedSet())

        val store2 = ReplacementNoticeStore(underlying, signingFn, "device-self-001")
        assertEquals(1, store2.pendingNotices().size)
        assertTrue(store2.blockStateFor("device-new-002") is ReplacementNoticeStore.BlockState.Blocked)
    }

    @Test
    fun `TEST-NOTICE-STORE-CLEAR wipes everything`() {
        val store = newStore()
        val (canonical, sig) = signedNotice()
        store.recordNotice(canonical, sig, trustedSet())
        assertEquals(1, store.pendingNotices().size)

        store.clear()
        assertEquals(0, store.pendingNotices().size)
        assertTrue(store.blockStateFor("device-new-002") is ReplacementNoticeStore.BlockState.Unblocked)
    }

    @Test
    fun `TEST-DIAG-NOTICE-FAILURE-LOGGED records notice signature failure`() {
        MatrixSigner.matrixDigestRaw(byteArrayOf())
        val underlying = InMemoryStore()
        val failureLog = VerificationFailureStore(underlying)
        val kp = KeyPairGenerator.getInstance("Ed25519").generateKeyPair()
        val signingFn: (ByteArray) -> ByteArray = { digest ->
            val sig = java.security.Signature.getInstance("Ed25519")
            sig.initSign(kp.private)
            sig.update(digest)
            sig.sign()
        }
        val store = ReplacementNoticeStore(
            store = underlying,
            signingFn = signingFn,
            ackingDeviceId = "self-device",
            failureLog = failureLog,
        )

        val result = store.recordNotice(
            canonical = "not-a-notice".toByteArray(),
            signatureBase64url = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(ByteArray(64)),
            trustedKeys = setOf(kp.public),
        )
        assertTrue(result is ReplacementNoticeStore.RecordResult.Invalid)

        val entries = failureLog.entries()
        assertEquals(1, entries.size)
        assertEquals(
            VerificationFailureStore.ArtifactType.NOTICE,
            entries[0].artifactType,
        )
        assertEquals("signature", entries[0].reason)
    }
}
