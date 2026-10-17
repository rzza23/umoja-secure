package com.umoja.secure.crypto

import org.bouncycastle.crypto.digests.SHA256Digest
import org.bouncycastle.crypto.generators.HKDFBytesGenerator
import org.bouncycastle.crypto.params.HKDFParameters
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.BeforeClass
import org.junit.Test
import java.io.File
import java.security.PrivateKey
import java.util.Base64

/**
 * Tests for the identity-change-ack signer.
 *
 * Mirrors backend/src/crypto/identity-change-ack.test.ts's
 * cross-language test: signs the A-001 vector with the shared test
 * key and asserts byte-identical output to the TS reference.
 *
 * The test key derivation (HKDF-SHA256, seed + info) matches
 * generate-matrix-vectors.ts and MatrixSignerTest.kt — any drift on
 * either side would produce a different signature and the A-001
 * assertion would fail.
 *
 * Task: TASK-P1-030 030e-c
 * ADR: ADR-IDENTITY-CHANGE-001 §3
 */
class IdentityChangeAckSignerTest {

    companion object {
        private const val SEED_UTF8 =
            "umoja-canonical-matrix-test-vectors-v1-DO-NOT-USE-IN-PRODUCTION"

        private lateinit var testPrivateKey: PrivateKey

        @JvmStatic
        @BeforeClass
        fun setUpClass() {
            testPrivateKey = MatrixSigner.privateKeyFromSeed(deriveTestSeed())
        }

        private fun deriveTestSeed(): ByteArray {
            val ikm = SEED_UTF8.toByteArray(Charsets.UTF_8)
            val hkdf = HKDFBytesGenerator(SHA256Digest())
            hkdf.init(
                HKDFParameters(ikm, ByteArray(0), "ed25519-test-key".toByteArray(Charsets.UTF_8)),
            )
            val out = ByteArray(32)
            hkdf.generateBytes(out, 0, 32)
            return out
        }

        private fun repoRoot(): File {
            var dir = File(System.getProperty("user.dir")!!)
            for (i in 0 until 10) {
                if (File(dir, "UMOJA-SECURE-BUILD-MASTER.md").exists()) return dir
                dir = dir.parentFile ?: break
            }
            error("could not find repo root from ${System.getProperty("user.dir")}")
        }
    }

    // ---------- round-trip with fresh keypair ----------

    @Test
    fun `TEST-ACK-SIGNER-SIGN-VERIFY round-trips`() {
        val kp = java.security.KeyPairGenerator.getInstance("Ed25519").generateKeyPair()
        val signed = SignedIdentityChangeAck(
            domain = SignedIdentityChangeAck.DOMAIN,
            ack = IdentityChangeAck(
                noticeHash = "A".repeat(43),
                ackingDeviceId = "11111111-1111-1111-1111-111111111111",
                decision = "accept",
                issuedAt = "2026-10-17T00:00:00Z",
            ),
        )
        val sig = IdentityChangeAckSigner.sign(signed, kp.private)
        assertTrue(IdentityChangeAckSigner.verify(signed, sig, kp.public))
    }

    @Test
    fun `TEST-ACK-SIGNER-TAMPER-REJECTED rejects modified ack`() {
        val kp = java.security.KeyPairGenerator.getInstance("Ed25519").generateKeyPair()
        val signed = SignedIdentityChangeAck(
            domain = SignedIdentityChangeAck.DOMAIN,
            ack = IdentityChangeAck(
                noticeHash = "A".repeat(43),
                ackingDeviceId = "11111111-1111-1111-1111-111111111111",
                decision = "accept",
                issuedAt = "2026-10-17T00:00:00Z",
            ),
        )
        val sig = IdentityChangeAckSigner.sign(signed, kp.private)
        val tampered = signed.copy(ack = signed.ack.copy(decision = "reject"))
        assertFalse(IdentityChangeAckSigner.verify(tampered, sig, kp.public))
    }

    // ---------- cross-language vector agreement ----------

    @Test
    fun `TEST-ACK-SIGNER-VECTOR-A001 canonical bytes and signature match TS reference`() {
        val path = File(
            repoRoot(),
            "docs/reference/canonical-identity-change-ack-test-vectors.json",
        )
        val arr = JSONObject(path.readText()).getJSONArray("vectors")
        var a001: JSONObject? = null
        for (i in 0 until arr.length()) {
            val v = arr.getJSONObject(i)
            if (v.getString("id") == "A-001") { a001 = v; break }
        }
        assertTrue("A-001 vector missing", a001 != null)
        val v = a001!!

        val expectedCanonical = if (v.isNull("expected_canonical_bytes_utf8")) {
            error("A-001 not populated — run generate-matrix-vectors.ts")
        } else {
            v.getString("expected_canonical_bytes_utf8")
        }

        val parsed = SignedIdentityChangeAck.fromJsonMap(
            jsonObjectToPlainMap(v.getJSONObject("input_wrapper")),
        )

        val actualCanonical = jcsCanonicalizeString(parsed.toJsonMap())
        assertEquals(expectedCanonical, actualCanonical)

        val expectedDigest = v.getString("expected_sha256_digest_hex")
        val actualDigest = IdentityChangeAckSigner.digest(parsed)
            .joinToString("") { "%02x".format(it.toInt() and 0xFF) }
        assertEquals(expectedDigest, actualDigest)

        val expectedSig = v.getString("expected_ed25519_signature_base64url")
        val kotlinSig = IdentityChangeAckSigner.sign(parsed, testPrivateKey)
        assertEquals(
            "Kotlin signer must produce byte-identical signature to TS reference",
            expectedSig,
            kotlinSig,
        )

        val pubRaw = Base64.getUrlDecoder()
            .decode(v.getString("expected_provisioning_public_key_base64url"))
        val pubKey = MatrixSigner.publicKeyFromRaw(pubRaw)
        assertTrue(IdentityChangeAckSigner.verify(parsed, kotlinSig, pubKey))
    }

    // ---------- signWithDeviceKey (production entry point) ----------

    private fun bcSigningFn(kp: java.security.KeyPair): (ByteArray) -> ByteArray =
        { digest ->
            val s = java.security.Signature.getInstance("Ed25519")
            s.initSign(kp.private)
            s.update(digest)
            s.sign()
        }

    @Test
    fun `TEST-ACK-SIGNER-DEVICE-KEY round-trips via BC-backed lambda`() {
        val kp = java.security.KeyPairGenerator.getInstance("Ed25519").generateKeyPair()
        val signed = SignedIdentityChangeAck(
            domain = SignedIdentityChangeAck.DOMAIN,
            ack = IdentityChangeAck(
                noticeHash = "A".repeat(43),
                ackingDeviceId = "11111111-1111-1111-1111-111111111111",
                decision = "accept",
                issuedAt = "2026-10-17T00:00:00Z",
            ),
        )
        val sig = IdentityChangeAckSigner.signWithDeviceKey(signed, bcSigningFn(kp))
        assertTrue(IdentityChangeAckSigner.verify(signed, sig, kp.public))
    }

    @Test
    fun `TEST-ACK-SIGNER-DEVICE-KEY matches PrivateKey entry point`() {
        // Two entry points, same protocol, same key. If signWithDeviceKey
        // produces a different signature than sign for identical input,
        // one of the two paths is wrong. Ed25519 is deterministic
        // (RFC 8032) so byte-identical is the correct expectation.
        val kp = java.security.KeyPairGenerator.getInstance("Ed25519").generateKeyPair()
        val signed = SignedIdentityChangeAck(
            domain = SignedIdentityChangeAck.DOMAIN,
            ack = IdentityChangeAck(
                noticeHash = "A".repeat(43),
                ackingDeviceId = "11111111-1111-1111-1111-111111111111",
                decision = "accept",
                issuedAt = "2026-10-17T00:00:00Z",
            ),
        )
        val viaPrivateKey = IdentityChangeAckSigner.sign(signed, kp.private)
        val viaDeviceKey = IdentityChangeAckSigner.signWithDeviceKey(signed, bcSigningFn(kp))
        assertEquals(viaPrivateKey, viaDeviceKey)
    }

    @Test
    fun `TEST-ACK-SIGNER-DEVICE-KEY rejects wrong-length return from signingFn`() {
        // Defense-in-depth: a misbehaving signingFn returns something
        // that isn't a 64-byte Ed25519 signature. require() catches it
        // before the base64url encode, before it can be stored or sent.
        val signed = SignedIdentityChangeAck(
            domain = SignedIdentityChangeAck.DOMAIN,
            ack = IdentityChangeAck(
                noticeHash = "A".repeat(43),
                ackingDeviceId = "11111111-1111-1111-1111-111111111111",
                decision = "accept",
                issuedAt = "2026-10-17T00:00:00Z",
            ),
        )
        assertThrows(IllegalArgumentException::class.java) {
            IdentityChangeAckSigner.signWithDeviceKey(signed) { ByteArray(32) }
        }
    }

    // ---------- helpers ----------

    private fun jsonObjectToPlainMap(jo: JSONObject): Map<String, Any?> {
        val out = linkedMapOf<String, Any?>()
        for (key in jo.keys()) {
            out[key] = jsonValueToPlain(jo.get(key))
        }
        return out
    }

    private fun jsonValueToPlain(v: Any?): Any? = when (v) {
        null, JSONObject.NULL -> null
        is JSONObject -> jsonObjectToPlainMap(v)
        is JSONArray -> (0 until v.length()).map { jsonValueToPlain(v.get(it)) }
        else -> v
    }
}
