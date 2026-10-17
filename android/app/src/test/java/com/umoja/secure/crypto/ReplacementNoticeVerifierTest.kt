package com.umoja.secure.crypto

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.KeyPairGenerator

/**
 * Tests for ReplacementNoticeVerifier.
 *
 * Mirrors MatrixVerifierTest's shape: raw-bytes verification against
 * a Set<PublicKey>, fails closed on empty set, delegates the Ed25519
 * primitive to MatrixSigner.verifyRaw.
 *
 * Uses fresh Ed25519 keypairs — the verifier does not care about
 * signing-key custody, only that the supplied trusted key matches the
 * signature over the supplied bytes. Signing for these fixtures goes
 * through ReplacementNoticeSigner.sign (PrivateKey entry point), which
 * is correct for tests since the keypairs are freshly generated.
 *
 * Task: TASK-P1-030 030e-c 3b
 * ADR: ADR-IDENTITY-CHANGE-001 §3, §4
 */
class ReplacementNoticeVerifierTest {

    private fun keyPair() = KeyPairGenerator.getInstance("Ed25519").generateKeyPair()

    private fun signedNotice(): SignedReplacementNotice = SignedReplacementNotice(
        domain = SignedReplacementNotice.DOMAIN,
        notice = ReplacementNotice(
            fromDeviceId = "device-old-001",
            fromDeviceAuthKey = "A".repeat(43),
            toDeviceId = "device-new-002",
            toDeviceAuthKey = "B".repeat(43),
            issuedAt = "2026-10-17T00:00:00Z",
        ),
    )

    private fun canonical(signed: SignedReplacementNotice): ByteArray =
        jcsCanonicalizeString(signed.toJsonMap()).toByteArray(Charsets.UTF_8)

    @Test
    fun `verifies a well-formed notice`() {
        val kp = keyPair()
        val signed = signedNotice()
        val sig = ReplacementNoticeSigner.sign(signed, kp.private)
        assertTrue(
            ReplacementNoticeVerifier.verify(canonical(signed), sig, setOf(kp.public)),
        )
    }

    @Test
    fun `rejects on empty trusted set`() {
        val kp = keyPair()
        val signed = signedNotice()
        val sig = ReplacementNoticeSigner.sign(signed, kp.private)
        assertFalse(
            ReplacementNoticeVerifier.verify(canonical(signed), sig, emptySet()),
        )
    }

    @Test
    fun `rejects on wrong key`() {
        val kp = keyPair()
        val other = keyPair()
        val signed = signedNotice()
        val sig = ReplacementNoticeSigner.sign(signed, kp.private)
        assertFalse(
            ReplacementNoticeVerifier.verify(canonical(signed), sig, setOf(other.public)),
        )
    }

    @Test
    fun `rejects on tampered canonical bytes`() {
        val kp = keyPair()
        val signed = signedNotice()
        val sig = ReplacementNoticeSigner.sign(signed, kp.private)
        val tampered = canonical(signed).copyOf().apply {
            this[0] = (this[0].toInt() xor 1).toByte()
        }
        assertFalse(
            ReplacementNoticeVerifier.verify(tampered, sig, setOf(kp.public)),
        )
    }

    @Test
    fun `rejects on malformed signature length`() {
        val kp = keyPair()
        val signed = signedNotice()
        assertFalse(
            ReplacementNoticeVerifier.verify(canonical(signed), "AAAA", setOf(kp.public)),
        )
    }

    @Test
    fun `rejects on non-base64url signature`() {
        val kp = keyPair()
        val signed = signedNotice()
        assertFalse(
            ReplacementNoticeVerifier.verify(canonical(signed), "@@@@", setOf(kp.public)),
        )
    }
}
