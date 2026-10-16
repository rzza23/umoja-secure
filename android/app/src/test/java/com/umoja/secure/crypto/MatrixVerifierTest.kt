package com.umoja.secure.crypto

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.security.KeyPairGenerator
import java.security.PublicKey
import java.util.Base64

/**
 * Verifier behaviour against the W-series vectors and tamper cases.
 *
 * The six vectors with signature material are W-001..W-005 (positive)
 * and W-006 (negative-wrapper-load-bearing — its vector is a valid
 * signature over the wrapper, and its point is that an implementation
 * verifying the inner matrix alone would fail it). N-001..N-003 have
 * no signature and are canonicalizer scope; excluded here.
 */
class MatrixVerifierTest {

    private fun repoRoot(): File {
        var dir = File(System.getProperty("user.dir")!!)
        for (i in 0 until 10) {
            if (File(dir, "UMOJA-SECURE-BUILD-MASTER.md").exists()) return dir
            dir = dir.parentFile ?: break
        }
        error("could not find repo root from ${System.getProperty("user.dir")}")
    }

    private fun loadSignedVectors(): List<JSONObject> {
        val path = File(repoRoot(), "docs/reference/canonical-matrix-test-vectors.json")
        val doc = JSONObject(path.readText())
        assertEquals(true, doc.getBoolean("generated"))
        val arr = doc.getJSONArray("vectors")
        val out = mutableListOf<JSONObject>()
        for (i in 0 until arr.length()) {
            val v = arr.getJSONObject(i)
            if (v.has("expected_ed25519_signature_base64url") &&
                !v.isNull("expected_ed25519_signature_base64url")) {
                out.add(v)
            }
        }
        return out
    }

    private fun vectorCanonical(v: JSONObject): ByteArray =
        v.getString("expected_canonical_bytes_utf8").toByteArray(Charsets.UTF_8)

    private fun vectorSignature(v: JSONObject): String =
        v.getString("expected_ed25519_signature_base64url")

    private fun vectorPubkey(v: JSONObject): PublicKey {
        val raw = Base64.getUrlDecoder().decode(
            v.getString("expected_provisioning_public_key_base64url"),
        )
        return MatrixSigner.publicKeyFromRaw(raw)
    }

    private fun freshEd25519Public(): PublicKey =
        KeyPairGenerator.getInstance("Ed25519").generateKeyPair().public

    @Test
    fun `all signed vectors verify against their pinned key`() {
        val vectors = loadSignedVectors()
        assertEquals(6, vectors.size)
        for (v in vectors) {
            val id = v.getString("id")
            val ok = MatrixVerifier.verify(
                canonical = vectorCanonical(v),
                signatureBase64url = vectorSignature(v),
                trustedKeys = setOf(vectorPubkey(v)),
            )
            assertTrue("$id did not verify", ok)
        }
    }

    @Test
    fun `tampered canonical bytes fail verification`() {
        val v = loadSignedVectors().first()
        val canonical = vectorCanonical(v).copyOf()
        canonical[canonical.size / 2] = (canonical[canonical.size / 2].toInt() + 1).toByte()
        val ok = MatrixVerifier.verify(
            canonical,
            vectorSignature(v),
            setOf(vectorPubkey(v)),
        )
        assertFalse(ok)
    }

    @Test
    fun `tampered signature fails verification`() {
        val v = loadSignedVectors().first()
        val sig = vectorSignature(v)
        val flipped = (if (sig[0] == 'A') 'B' else 'A') + sig.substring(1)
        val ok = MatrixVerifier.verify(
            vectorCanonical(v),
            flipped,
            setOf(vectorPubkey(v)),
        )
        assertFalse(ok)
    }

    @Test
    fun `wrong public key fails verification`() {
        val v = loadSignedVectors().first()
        val ok = MatrixVerifier.verify(
            vectorCanonical(v),
            vectorSignature(v),
            setOf(freshEd25519Public()),
        )
        assertFalse(ok)
    }

    @Test
    fun `empty trusted set fails closed`() {
        val v = loadSignedVectors().first()
        val ok = MatrixVerifier.verify(
            vectorCanonical(v),
            vectorSignature(v),
            emptySet(),
        )
        assertFalse(ok)
    }

    @Test
    fun `malformed base64url signature fails closed`() {
        val v = loadSignedVectors().first()
        val ok = MatrixVerifier.verify(
            vectorCanonical(v),
            "!!!not-base64!!!",
            setOf(vectorPubkey(v)),
        )
        assertFalse(ok)
    }

    @Test
    fun `wrong-length signature fails closed`() {
        val v = loadSignedVectors().first()
        val ok = MatrixVerifier.verify(
            vectorCanonical(v),
            "AAAA",
            setOf(vectorPubkey(v)),
        )
        assertFalse(ok)
    }

    @Test
    fun `set with correct key plus wrong key still verifies`() {
        val v = loadSignedVectors().first()
        val ok = MatrixVerifier.verify(
            vectorCanonical(v),
            vectorSignature(v),
            setOf(freshEd25519Public(), vectorPubkey(v)),
        )
        assertTrue(ok)
    }

    @Test
    fun `set iteration order does not affect the result`() {
        val v = loadSignedVectors().first()
        val wrongPub = freshEd25519Public()
        val correctPub = vectorPubkey(v)
        val forward = MatrixVerifier.verify(
            vectorCanonical(v),
            vectorSignature(v),
            setOf(wrongPub, correctPub),
        )
        val reversed = MatrixVerifier.verify(
            vectorCanonical(v),
            vectorSignature(v),
            setOf(correctPub, wrongPub),
        )
        assertTrue("forward order", forward)
        assertTrue("reversed order", reversed)
    }
}
