package com.umoja.secure.crypto

import org.bouncycastle.crypto.digests.SHA256Digest
import org.bouncycastle.crypto.generators.HKDFBytesGenerator
import org.bouncycastle.crypto.params.HKDFParameters
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.BeforeClass
import org.junit.Test
import java.io.File
import java.security.PrivateKey
import java.security.PublicKey
import java.util.Base64

/**
 * Tests for MatrixSigner, mirroring backend/src/crypto/matrix-sign.test.ts.
 *
 * Uses the test-only key derived deterministically per the vector file's
 * test_only_key_derivation block. Verifies:
 *   - the protocol produces the same signature as the TS side and the
 *     stored vectors
 *   - tampering any byte of the wrapper invalidates verification
 *   - signing canonical bytes directly (skipping SHA-256 prehash) fails
 *   - a signature from a different key fails verification
 *
 * Task: TASK-P1-026
 */
class MatrixSignerTest {

    companion object {
        private const val SEED_UTF8 =
            "umoja-canonical-matrix-test-vectors-v1-DO-NOT-USE-IN-PRODUCTION"
        private const val EXPECTED_PUBKEY_B64U = "hL_X45qk5WrA9rSxtrQJyRzkDGT0eysDBtuWQosC30M"

        private lateinit var testPrivateKey: PrivateKey
        private lateinit var testPublicKey: PublicKey

        @JvmStatic
        @BeforeClass
        fun setUpClass() {
            val seed = deriveTestSeed()
            testPrivateKey = MatrixSigner.privateKeyFromSeed(seed)

            // Confirm our derivation matches the TS generator. If this
            // fails, HKDF semantics differ between BC and Node — do NOT
            // regenerate the vectors, fix the derivation to match.
            val rawPub = Base64.getUrlDecoder().decode(EXPECTED_PUBKEY_B64U)
            testPublicKey = MatrixSigner.publicKeyFromRaw(rawPub)
        }

        private fun deriveTestSeed(): ByteArray {
            val ikm = SEED_UTF8.toByteArray(Charsets.UTF_8)
            val hkdf = HKDFBytesGenerator(SHA256Digest())
            // TS uses Buffer.alloc(0) as salt. BC treats empty byte array
            // as an empty salt (not HashLen zeros) — same as Node's
            // Buffer.alloc(0). The EXPECTED_PUBKEY_B64U check catches any
            // divergence.
            hkdf.init(HKDFParameters(ikm, ByteArray(0), "ed25519-test-key".toByteArray(Charsets.UTF_8)))
            val out = ByteArray(32)
            hkdf.generateBytes(out, 0, 32)
            return out
        }

        private fun repoRoot(): File {
            var dir = File(System.getProperty("user.dir"))
            for (i in 0 until 10) {
                if (File(dir, "UMOJA-SECURE-BUILD-MASTER.md").exists()) return dir
                dir = dir.parentFile ?: break
            }
            error("could not find repo root from ${System.getProperty("user.dir")}")
        }

        private fun fromOrgJson(value: Any?): Any? = when (value) {
            null, JSONObject.NULL -> null
            is Boolean -> value
            is Int -> value
            is Long -> value
            is Double -> value
            is java.math.BigDecimal -> value.toDouble()
            is java.math.BigInteger -> value.toDouble()
            is String -> value
            is JSONArray -> (0 until value.length()).map { fromOrgJson(value.get(it)) }
            is JSONObject -> {
                val out = LinkedHashMap<String, Any?>()
                val keys = value.keys()
                while (keys.hasNext()) {
                    val k = keys.next()
                    out[k] = fromOrgJson(value.get(k))
                }
                out
            }
            else -> error("unexpected org.json type: ${value::class.qualifiedName}")
        }

        @Suppress("UNCHECKED_CAST")
        private fun parseSignedMatrix(json: JSONObject): SignedMatrix =
            SignedMatrix.fromJsonMap(fromOrgJson(json) as Map<String, Any?>)
    }

    private fun validWrapper(): SignedMatrix = SignedMatrix(
        domain = SignedMatrix.DOMAIN,
        matrix = AuthorizationMatrix(
            version = 1,
            deviceId = "device-001",
            pubDeviceAuthKey = "A".repeat(43),
            pubMessagingIdentityKey = "B".repeat(43),
            pubWipeConfirmationKey = "C".repeat(43),
            clearance = "standard",
            permittedContacts = listOf("device-002"),
            issuedAt = "2026-10-14T00:00:00Z",
        ),
    )

    // ---------- derivation sanity ----------

    @Test
    fun `derived test public key matches the TS generator`() {
        // If this fails, HKDF or key-wrapping differs from Node.
        val raw = Base64.getUrlDecoder().decode(EXPECTED_PUBKEY_B64U)
        val pub = MatrixSigner.publicKeyFromRaw(raw)
        // Round-trip: sign with testPrivateKey, verify with the pubkey
        // we loaded — proves the pair is coherent.
        val wrapper = validWrapper()
        val sig = MatrixSigner.sign(wrapper, testPrivateKey)
        assertTrue(MatrixSigner.verify(wrapper, sig, pub))
    }

    // ---------- against populated test vectors ----------

    @Test
    fun `all vector signatures match and verify`() {
        val vectorsPath = File(repoRoot(), "docs/reference/canonical-matrix-test-vectors.json")
        val doc = JSONObject(vectorsPath.readText())
        assertEquals(true, doc.getBoolean("generated"))

        val vectors = doc.getJSONArray("vectors")
        var tested = 0
        for (i in 0 until vectors.length()) {
            val v = vectors.getJSONObject(i)
            if (!v.has("expected_ed25519_signature_base64url") || v.isNull("expected_ed25519_signature_base64url")) {
                continue
            }
            val id = v.getString("id")
            val signed = parseSignedMatrix(v.getJSONObject("input_wrapper"))
            val expectedSig = v.getString("expected_ed25519_signature_base64url")
            val expectedPub = Base64.getUrlDecoder().decode(
                v.getString("expected_provisioning_public_key_base64url"),
            )
            val pub = MatrixSigner.publicKeyFromRaw(expectedPub)

            // Our signature matches the vector byte-for-byte.
            val ourSig = MatrixSigner.sign(signed, testPrivateKey)
            assertEquals("$id signature mismatch vs vector", expectedSig, ourSig)

            // The vector's signature verifies against the vector's public key.
            assertTrue("$id vector signature did not verify", MatrixSigner.verify(signed, expectedSig, pub))
            tested++
        }
        assertEquals(6, tested)
    }

    // ---------- tamper resistance ----------

    @Test
    fun `valid signature verifies`() {
        val w = validWrapper()
        val sig = MatrixSigner.sign(w, testPrivateKey)
        assertTrue(MatrixSigner.verify(w, sig, testPublicKey))
    }

    @Test
    fun `flipping one character in device_id invalidates verification`() {
        val sig = MatrixSigner.sign(validWrapper(), testPrivateKey)
        val tampered = validWrapper().let {
            it.copy(matrix = it.matrix.copy(deviceId = "device-002"))
        }
        assertFalse(MatrixSigner.verify(tampered, sig, testPublicKey))
    }

    @Test
    fun `changing version invalidates verification`() {
        val sig = MatrixSigner.sign(validWrapper(), testPrivateKey)
        val tampered = validWrapper().let {
            it.copy(matrix = it.matrix.copy(version = 2))
        }
        assertFalse(MatrixSigner.verify(tampered, sig, testPublicKey))
    }

    @Test
    fun `swapping device-auth and messaging-identity keys invalidates verification`() {
        val sig = MatrixSigner.sign(validWrapper(), testPrivateKey)
        val w = validWrapper()
        val tampered = w.copy(
            matrix = w.matrix.copy(
                pubDeviceAuthKey = w.matrix.pubMessagingIdentityKey,
                pubMessagingIdentityKey = w.matrix.pubDeviceAuthKey,
            ),
        )
        assertFalse(MatrixSigner.verify(tampered, sig, testPublicKey))
    }

    @Test
    fun `changing clearance invalidates verification`() {
        val sig = MatrixSigner.sign(validWrapper(), testPrivateKey)
        val tampered = validWrapper().let {
            it.copy(matrix = it.matrix.copy(clearance = "elevated"))
        }
        assertFalse(MatrixSigner.verify(tampered, sig, testPublicKey))
    }

    // ---------- prehash is load-bearing ----------

    @Test
    fun `signing the canonical bytes directly does NOT verify under the digest protocol`() {
        // Construct a signature over the RAW canonical bytes — the
        // deviation Build Master v1.4.2 exists to forbid.
        val wrapper = validWrapper()
        val canonical = jcsCanonicalizeString(wrapper.toJsonMap()).toByteArray(Charsets.UTF_8)
        val sig = java.security.Signature.getInstance("Ed25519")
        sig.initSign(testPrivateKey)
        sig.update(canonical)
        val badSig = Base64.getUrlEncoder().withoutPadding().encodeToString(sig.sign())

        assertFalse(MatrixSigner.verify(wrapper, badSig, testPublicKey))
    }

    @Test
    fun `matrixDigest returns 32 bytes`() {
        assertEquals(32, MatrixSigner.matrixDigest(validWrapper()).size)
    }

    @Test
    fun `matrixDigest is deterministic`() {
        assertTrue(
            MatrixSigner.matrixDigest(validWrapper())
                .contentEquals(MatrixSigner.matrixDigest(validWrapper())),
        )
    }

    // ---------- wrong key ----------

    @Test
    fun `a signature from a different key does not verify`() {
        val otherSeed = ByteArray(32) { 0x42 }
        val otherPriv = MatrixSigner.privateKeyFromSeed(otherSeed)
        val sig = MatrixSigner.sign(validWrapper(), otherPriv)
        assertFalse(MatrixSigner.verify(validWrapper(), sig, testPublicKey))
    }

    // ---------- signature length guard ----------

    @Test
    fun `rejects a signature that is not 64 bytes`() {
        val tooShort = Base64.getUrlEncoder().withoutPadding().encodeToString(ByteArray(32))
        assertThrows(IllegalArgumentException::class.java) {
            MatrixSigner.verify(validWrapper(), tooShort, testPublicKey)
        }
    }
}
