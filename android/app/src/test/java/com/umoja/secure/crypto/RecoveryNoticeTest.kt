package com.umoja.secure.crypto

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.util.Base64

/**
 * Tests for the recovery-notice schema (TASK-P1-035b).
 *
 * Mirrors backend/src/crypto/recovery-notice.test.ts. Coverage:
 *   - Schema roundtrip per type (toJsonMap -> fromJsonMap preserves)
 *   - Wrong-domain rejection per type
 *   - Cross-field rejections:
 *       key_revocation: revoked_provisioning_key_id == fingerprint
 *                        of new_provisioning_key
 *       recovery_key_rotation: new_recovery_key_version <= old
 *   - Malformed field rejection per type (b64u / ISO / positive int)
 *   - Sign/verify roundtrip per type (fresh keypair)
 *   - Tamper rejection per type
 *   - signWithDeviceKey (Keystore-custody path) per type
 *   - Malformed signature length
 *   - 5 cross-language vector tests (R-001 through R-005): for each
 *     vector, [1] canonical bytes match expected_canonical_bytes_utf8,
 *     [2] SHA-256 digest matches expected_sha256_digest_hex, and [3]
 *     the vector's published signature verifies against the vector's
 *     published public key. This is the Kotlin half of the cross-
 *     language proof; the TS half is recovery-notice.test.ts.
 *
 * **The load-bearing acceptance:** if the 5 vector tests pass, the
 * Kotlin schema produces byte-identical canonical bytes, digest, and
 * signature to the TS implementation on identical input. Any drift in
 * the JCS canonicalizer, the SHA-256 digest, or the Ed25519 signing
 * path on either side fails a vector test rather than shipping
 * silently.
 *
 * Task: TASK-P1-035b
 * Build Master: §3.8 (signing protocol)
 * ADR: §2 Q6 (provisioning key compromise)
 * Depends: TASK-P1-035a (TS schema + vectors)
 */
class RecoveryNoticeTest {

    // 43-char base64url values that decode to distinct 32-byte values.
    // keyA = all-zero bytes; keyB, keyC, keyD, keyE = distinct fill.
    private val keyA = "A".repeat(43)
    private val keyB = "B".repeat(43)
    private val keyC = "C".repeat(43)
    private val keyD = "D".repeat(43)
    private val keyE = "E".repeat(43)
    private val keyF = "F".repeat(43)

    // ============================================================
    // Fixtures
    // ============================================================

    private fun validKeyRotation(): SignedKeyRotationNotice =
        SignedKeyRotationNotice(
            domain = SignedKeyRotationNotice.DOMAIN,
            notice = KeyRotationNotice(
                newProvisioningKey = keyB,
                overlapWindowSeconds = 2592000,
                effectiveAt = "2026-10-20T00:00:00Z",
                nonce = "n-rt",
                eventId = "e-rt",
                recoveryKeyVersion = 1,
            ),
        )

    private fun validKeyRevocation(): SignedKeyRevocationNotice =
        SignedKeyRevocationNotice(
            domain = SignedKeyRevocationNotice.DOMAIN,
            notice = KeyRevocationNotice(
                revokedProvisioningKeyId = keyA,
                newProvisioningKey = keyB,
                effectiveAt = "2026-10-20T00:00:00Z",
                nonce = "n-rt",
                eventId = "e-rt",
                recoveryKeyVersion = 1,
            ),
        )

    private fun validRecoveryKeyRotation(): SignedRecoveryKeyRotationNotice =
        SignedRecoveryKeyRotationNotice(
            domain = SignedRecoveryKeyRotationNotice.DOMAIN,
            notice = RecoveryKeyRotationNotice(
                newRecoveryKey = keyD,
                newRecoveryKeyVersion = 2,
                effectiveAt = "2026-10-20T00:00:00Z",
                nonce = "n-rt",
                eventId = "e-rt",
                recoveryKeyVersion = 1,
            ),
        )

    // ============================================================
    // Schema roundtrip
    // ============================================================

    @Test
    fun `TEST-RECOVERY-NOTICE-KR-ROUNDTRIP preserves all fields`() {
        val n = validKeyRotation()
        assertEquals(n, SignedKeyRotationNotice.fromJsonMap(n.toJsonMap()))
    }

    @Test
    fun `TEST-RECOVERY-NOTICE-KRV-ROUNDTRIP preserves all fields`() {
        val n = validKeyRevocation()
        assertEquals(n, SignedKeyRevocationNotice.fromJsonMap(n.toJsonMap()))
    }

    @Test
    fun `TEST-RECOVERY-NOTICE-RKR-ROUNDTRIP preserves all fields`() {
        val n = validRecoveryKeyRotation()
        assertEquals(n, SignedRecoveryKeyRotationNotice.fromJsonMap(n.toJsonMap()))
    }

    // ============================================================
    // Wrong domain rejection
    // ============================================================

    @Test
    fun `TEST-RECOVERY-NOTICE-KR-BAD-DOMAIN rejects wrong domain`() {
        val n = validKeyRotation().copy(domain = "umoja.key-revocation.v1")
        assertThrows(IllegalArgumentException::class.java) {
            SignedKeyRotationNotice.fromJsonMap(n.toJsonMap())
        }
    }

    @Test
    fun `TEST-RECOVERY-NOTICE-KRV-BAD-DOMAIN rejects wrong domain`() {
        val n = validKeyRevocation().copy(domain = "umoja.key-rotation.v1")
        assertThrows(IllegalArgumentException::class.java) {
            SignedKeyRevocationNotice.fromJsonMap(n.toJsonMap())
        }
    }

    @Test
    fun `TEST-RECOVERY-NOTICE-RKR-BAD-DOMAIN rejects wrong domain`() {
        val n = validRecoveryKeyRotation().copy(domain = "umoja.key-rotation.v1")
        assertThrows(IllegalArgumentException::class.java) {
            SignedRecoveryKeyRotationNotice.fromJsonMap(n.toJsonMap())
        }
    }

    // ============================================================
    // Cross-field rejections
    // ============================================================

    @Test
    fun `TEST-RECOVERY-NOTICE-KRV-SELF-REPLACEMENT rejected (fingerprint == new key)`() {
        // Compute the fingerprint of the replacement key, then use it
        // as the revoked key id. A revocation whose replacement equals
        // the revoked key is a contradiction.
        val newKeyRaw = Base64.getUrlDecoder().decode(keyB)
        val fingerprint = Base64.getUrlEncoder().withoutPadding()
            .encodeToString(MessageDigest.getInstance("SHA-256").digest(newKeyRaw))

        val n = validKeyRevocation().copy(
            notice = validKeyRevocation().notice.copy(
                revokedProvisioningKeyId = fingerprint,
                newProvisioningKey = keyB,
            ),
        )
        val e = assertThrows(IllegalArgumentException::class.java) {
            SignedKeyRevocationNotice.fromJsonMap(n.toJsonMap())
        }
        assertEquals(
            "revoked_provisioning_key_id equals fingerprint of new_provisioning_key; " +
                "a revocation cannot name the replacement as the revoked key",
            e.message,
        )
    }

    @Test
    fun `TEST-RECOVERY-NOTICE-RKR-VERSION-NOT-STRICTLY-GREATER rejected`() {
        // new_recovery_key_version == recovery_key_version: same-version
        // rotation is not a rotation.
        val n = validRecoveryKeyRotation().copy(
            notice = validRecoveryKeyRotation().notice.copy(
                newRecoveryKeyVersion = 1,
                recoveryKeyVersion = 1,
            ),
        )
        val e = assertThrows(IllegalArgumentException::class.java) {
            SignedRecoveryKeyRotationNotice.fromJsonMap(n.toJsonMap())
        }
        assertEquals(
            "new_recovery_key_version (1) must strictly exceed recovery_key_version (1)",
            e.message,
        )
    }

    // ============================================================
    // Malformed field rejections (one representative per type)
    // ============================================================

    @Test
    fun `TEST-RECOVERY-NOTICE-KR-BAD-KEY rejected (wrong length b64u)`() {
        val n = validKeyRotation().copy(
            notice = validKeyRotation().notice.copy(newProvisioningKey = "short"),
        )
        assertThrows(IllegalArgumentException::class.java) {
            SignedKeyRotationNotice.fromJsonMap(n.toJsonMap())
        }
    }

    @Test
    fun `TEST-RECOVERY-NOTICE-KRV-BAD-FINGERPRINT rejected (wrong length b64u)`() {
        val n = validKeyRevocation().copy(
            notice = validKeyRevocation().notice.copy(
                revokedProvisioningKeyId = "short",
            ),
        )
        assertThrows(IllegalArgumentException::class.java) {
            SignedKeyRevocationNotice.fromJsonMap(n.toJsonMap())
        }
    }

    @Test
    fun `TEST-RECOVERY-NOTICE-RKR-BAD-VERSION rejected (zero)`() {
        val n = validRecoveryKeyRotation().copy(
            notice = validRecoveryKeyRotation().notice.copy(
                recoveryKeyVersion = 0,
            ),
        )
        assertThrows(IllegalArgumentException::class.java) {
            SignedRecoveryKeyRotationNotice.fromJsonMap(n.toJsonMap())
        }
    }

    // ============================================================
    // Sign/verify roundtrip per type (fresh keypair)
    // ============================================================

    @Test
    fun `TEST-RECOVERY-NOTICE-KR-SIGN-VERIFY round-trips`() {
        val kp = KeyPairGenerator.getInstance("Ed25519").generateKeyPair()
        val n = validKeyRotation()
        val sig = RecoveryNoticeSigner.signKeyRotation(n, kp.private)
        assertTrue(RecoveryNoticeSigner.verifyKeyRotation(n, sig, kp.public))
    }

    @Test
    fun `TEST-RECOVERY-NOTICE-KRV-SIGN-VERIFY round-trips`() {
        val kp = KeyPairGenerator.getInstance("Ed25519").generateKeyPair()
        val n = validKeyRevocation()
        val sig = RecoveryNoticeSigner.signKeyRevocation(n, kp.private)
        assertTrue(RecoveryNoticeSigner.verifyKeyRevocation(n, sig, kp.public))
    }

    @Test
    fun `TEST-RECOVERY-NOTICE-RKR-SIGN-VERIFY round-trips`() {
        val kp = KeyPairGenerator.getInstance("Ed25519").generateKeyPair()
        val n = validRecoveryKeyRotation()
        val sig = RecoveryNoticeSigner.signRecoveryKeyRotation(n, kp.private)
        assertTrue(RecoveryNoticeSigner.verifyRecoveryKeyRotation(n, sig, kp.public))
    }

    // ============================================================
    // Tamper rejection per type
    // ============================================================

    @Test
    fun `TEST-RECOVERY-NOTICE-KR-TAMPER rejected (modified new_provisioning_key)`() {
        val kp = KeyPairGenerator.getInstance("Ed25519").generateKeyPair()
        val n = validKeyRotation()
        val sig = RecoveryNoticeSigner.signKeyRotation(n, kp.private)
        val tampered = n.copy(
            notice = n.notice.copy(newProvisioningKey = keyC),
        )
        assertFalse(RecoveryNoticeSigner.verifyKeyRotation(tampered, sig, kp.public))
    }

    @Test
    fun `TEST-RECOVERY-NOTICE-KRV-TAMPER rejected (modified nonce)`() {
        val kp = KeyPairGenerator.getInstance("Ed25519").generateKeyPair()
        val n = validKeyRevocation()
        val sig = RecoveryNoticeSigner.signKeyRevocation(n, kp.private)
        val tampered = n.copy(
            notice = n.notice.copy(nonce = "different-nonce"),
        )
        assertFalse(RecoveryNoticeSigner.verifyKeyRevocation(tampered, sig, kp.public))
    }

    @Test
    fun `TEST-RECOVERY-NOTICE-RKR-TAMPER rejected (modified new_recovery_key_version)`() {
        val kp = KeyPairGenerator.getInstance("Ed25519").generateKeyPair()
        val n = validRecoveryKeyRotation()
        val sig = RecoveryNoticeSigner.signRecoveryKeyRotation(n, kp.private)
        val tampered = n.copy(
            notice = n.notice.copy(newRecoveryKeyVersion = 3),
        )
        assertFalse(RecoveryNoticeSigner.verifyRecoveryKeyRotation(tampered, sig, kp.public))
    }

    // ============================================================
    // signWithDeviceKey (Keystore-custody path) per type
    //
    // Production wires deviceKeyManager.sign(digest); tests wire a
    // BouncyCastle Signature-based signer with a fresh keypair. The
    // lambda receives the 32-byte SHA-256 digest and returns the raw
    // 64-byte Ed25519 signature (NOT rehashed — same prehash protocol
    // as sign()).
    // ============================================================

    @Test
    fun `TEST-RECOVERY-NOTICE-KR-SIGN-WITH-DEVICE-KEY verifies`() {
        val kp = KeyPairGenerator.getInstance("Ed25519").generateKeyPair()
        val signingFn: (ByteArray) -> ByteArray = { digest ->
            val sig = java.security.Signature.getInstance("Ed25519")
            sig.initSign(kp.private)
            sig.update(digest)
            sig.sign()
        }
        val n = validKeyRotation()
        val sigB64u = RecoveryNoticeSigner.signKeyRotationWithDeviceKey(n, signingFn)
        assertTrue(RecoveryNoticeSigner.verifyKeyRotation(n, sigB64u, kp.public))
    }

    @Test
    fun `TEST-RECOVERY-NOTICE-KRV-SIGN-WITH-DEVICE-KEY verifies`() {
        val kp = KeyPairGenerator.getInstance("Ed25519").generateKeyPair()
        val signingFn: (ByteArray) -> ByteArray = { digest ->
            val sig = java.security.Signature.getInstance("Ed25519")
            sig.initSign(kp.private)
            sig.update(digest)
            sig.sign()
        }
        val n = validKeyRevocation()
        val sigB64u = RecoveryNoticeSigner.signKeyRevocationWithDeviceKey(n, signingFn)
        assertTrue(RecoveryNoticeSigner.verifyKeyRevocation(n, sigB64u, kp.public))
    }

    @Test
    fun `TEST-RECOVERY-NOTICE-RKR-SIGN-WITH-DEVICE-KEY verifies`() {
        val kp = KeyPairGenerator.getInstance("Ed25519").generateKeyPair()
        val signingFn: (ByteArray) -> ByteArray = { digest ->
            val sig = java.security.Signature.getInstance("Ed25519")
            sig.initSign(kp.private)
            sig.update(digest)
            sig.sign()
        }
        val n = validRecoveryKeyRotation()
        val sigB64u = RecoveryNoticeSigner.signRecoveryKeyRotationWithDeviceKey(n, signingFn)
        assertTrue(RecoveryNoticeSigner.verifyRecoveryKeyRotation(n, sigB64u, kp.public))
    }

    @Test
    fun `TEST-RECOVERY-NOTICE-SIGN-WITH-DEVICE-KEY-REJECTS-BAD-FN rejects wrong-length signature`() {
        val kp = KeyPairGenerator.getInstance("Ed25519").generateKeyPair()
        val n = validKeyRotation()
        // A signingFn that returns 32 bytes (wrong). signWithDeviceKey's
        // require(sigBytes.size == 64) fires with a specific message.
        val badFn: (ByteArray) -> ByteArray = { ByteArray(32) }
        val e = assertThrows(IllegalArgumentException::class.java) {
            RecoveryNoticeSigner.signKeyRotationWithDeviceKey(n, badFn)
        }
        assertEquals("signature: expected 64 bytes, got 32", e.message)
    }

    // ============================================================
    // Malformed signature: fail-closed (returns false)
    // ============================================================

    @Test
    fun `TEST-RECOVERY-NOTICE-VERIFY-MALFORMED-SIG fails closed`() {
        val kp = KeyPairGenerator.getInstance("Ed25519").generateKeyPair()
        val n = validKeyRotation()
        // Too short (32 bytes) — verify delegates to MatrixSigner.verifyRaw
        // which returns false on wrong length, NOT throws.
        val shortSig = Base64.getUrlEncoder().withoutPadding().encodeToString(ByteArray(32))
        assertFalse(RecoveryNoticeSigner.verifyKeyRotation(n, shortSig, kp.public))

        // Not base64url at all — same fail-closed path.
        assertFalse(RecoveryNoticeSigner.verifyKeyRotation(n, "!!!not-base64!!!", kp.public))
    }

    // ============================================================
    // Cross-language vector agreement (load-bearing acceptance)
    //
    // For each of R-001..R-005 (3 notice types + 2 boundary cases):
    //   1. Recompute JCS-canonical bytes; assert byte-match to
    //      expected_canonical_bytes_utf8 (proves canonicalizer parity)
    //   2. Recompute SHA-256 digest; assert hex-match to
    //      expected_sha256_digest_hex (proves digest parity)
    //   3. Decode expected_provisioning_public_key_base64url; verify
    //      the vector's published signature (proves Ed25519 parity)
    //
    // The TS half is recovery-notice.test.ts. Together with these,
    // they prove Kotlin and TS produce byte-identical output on
    // identical input. If the JCS canonicalizer, digest, or signer
    // drifts on either side, one of these 5 tests fails.
    // ============================================================

    @Test
    fun `TEST-RECOVERY-NOTICE-VECTOR-FILE-READY (sanity)`() {
        val path = File(repoRoot(), "docs/reference/canonical-recovery-notice-test-vectors.json")
        assertTrue("vector file missing at " + path.absolutePath, path.exists())
        val doc = JSONObject(path.readText())
        assertEquals(true, doc.getBoolean("generated"))
        assertEquals(5, doc.getJSONArray("vectors").length())
    }

    @Test
    fun `TEST-RECOVERY-NOTICE-VECTOR-R001 (key_revocation)`() {
        val v = loadVector("R-001")
        val parsed = SignedKeyRevocationNotice.fromJsonMap(
            jsonObjectToPlainMap(v.getJSONObject("input_wrapper")),
        )
        assertVectorMatches(parsed.toJsonMap(), v) { canonical, sig, pubKey ->
            // Digest parity is checked in assertVectorMatches; here
            // we check that the vector's signature verifies against
            // the vector's published public key over the same bytes.
            MatrixSigner.verifyRaw(canonical, sig, pubKey)
        }
    }

    @Test
    fun `TEST-RECOVERY-NOTICE-VECTOR-R002 (key_rotation)`() {
        val v = loadVector("R-002")
        val parsed = SignedKeyRotationNotice.fromJsonMap(
            jsonObjectToPlainMap(v.getJSONObject("input_wrapper")),
        )
        assertVectorMatches(parsed.toJsonMap(), v) { canonical, sig, pubKey ->
            MatrixSigner.verifyRaw(canonical, sig, pubKey)
        }
    }

    @Test
    fun `TEST-RECOVERY-NOTICE-VECTOR-R003 (recovery_key_rotation)`() {
        val v = loadVector("R-003")
        val parsed = SignedRecoveryKeyRotationNotice.fromJsonMap(
            jsonObjectToPlainMap(v.getJSONObject("input_wrapper")),
        )
        assertVectorMatches(parsed.toJsonMap(), v) { canonical, sig, pubKey ->
            MatrixSigner.verifyRaw(canonical, sig, pubKey)
        }
    }

    @Test
    fun `TEST-RECOVERY-NOTICE-VECTOR-R004 (key_rotation boundary, min overlap)`() {
        val v = loadVector("R-004")
        val parsed = SignedKeyRotationNotice.fromJsonMap(
            jsonObjectToPlainMap(v.getJSONObject("input_wrapper")),
        )
        assertVectorMatches(parsed.toJsonMap(), v) { canonical, sig, pubKey ->
            MatrixSigner.verifyRaw(canonical, sig, pubKey)
        }
    }

    @Test
    fun `TEST-RECOVERY-NOTICE-VECTOR-R005 (recovery_key_rotation boundary, v5-to-v6)`() {
        val v = loadVector("R-005")
        val parsed = SignedRecoveryKeyRotationNotice.fromJsonMap(
            jsonObjectToPlainMap(v.getJSONObject("input_wrapper")),
        )
        assertVectorMatches(parsed.toJsonMap(), v) { canonical, sig, pubKey ->
            MatrixSigner.verifyRaw(canonical, sig, pubKey)
        }
    }

    // ---------- vector helpers ----------

    private fun repoRoot(): File {
        var dir = File(System.getProperty("user.dir")!!)
        for (i in 0 until 10) {
            if (File(dir, "UMOJA-SECURE-BUILD-MASTER.md").exists()) return dir
            dir = dir.parentFile ?: break
        }
        error("could not find repo root from ${System.getProperty("user.dir")}")
    }

    private fun loadVector(id: String): JSONObject {
        val path = File(repoRoot(), "docs/reference/canonical-recovery-notice-test-vectors.json")
        val arr = JSONObject(path.readText()).getJSONArray("vectors")
        for (i in 0 until arr.length()) {
            val v = arr.getJSONObject(i)
            if (v.getString("id") == id) return v
        }
        error("vector $id not found in canonical-recovery-notice-test-vectors.json")
    }

    /**
     * Assert the recomputed canonical bytes match [v]'s
     * expected_canonical_bytes_utf8, the SHA-256 of those bytes
     * matches expected_sha256_digest_hex, and the vector's published
     * signature verifies against the vector's published public key
     * over those bytes (via [verifyFn]).
     *
     * Three separate assertions so a failure names the specific
     * drift: canonicalizer (bytes mismatch), digest (hex mismatch),
     * or signer (verify returns false).
     */
    private fun assertVectorMatches(
        wrapper: Map<String, Any?>,
        v: JSONObject,
        verifyFn: (ByteArray, String, java.security.PublicKey) -> Boolean,
    ) {
        val id = v.getString("id")
        val expectedCanonical = v.getString("expected_canonical_bytes_utf8")
        val canonical = jcsCanonicalizeString(wrapper)
        assertEquals("$id: canonical bytes mismatch (JCS drift)", expectedCanonical, canonical)

        val canonicalBytes = canonical.toByteArray(Charsets.UTF_8)
        val digest = MatrixSigner.matrixDigestRaw(canonicalBytes)
        val digestHex = digest.joinToString("") { "%02x".format(it.toInt() and 0xFF) }
        assertEquals("$id: SHA-256 hex mismatch (digest drift)", v.getString("expected_sha256_digest_hex"), digestHex)

        val sig = v.getString("expected_ed25519_signature_base64url")
        val pubRaw = Base64.getUrlDecoder().decode(v.getString("expected_provisioning_public_key_base64url"))
        val pubKey = MatrixSigner.publicKeyFromRaw(pubRaw)
        assertTrue("$id: signature verify failed against published pubkey (Ed25519 drift)", verifyFn(canonicalBytes, sig, pubKey))
    }
}
