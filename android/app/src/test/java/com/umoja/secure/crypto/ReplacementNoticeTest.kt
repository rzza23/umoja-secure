package com.umoja.secure.crypto

import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.security.KeyPairGenerator
import java.util.Base64

/**
 * Tests for the replacement-notice schema + signing protocol.
 *
 * Mirrors backend/src/crypto/replacement-notice.test.ts. Uses fresh
 * Ed25519 keypairs for sign/verify round-trip; uses the R-series vectors
 * for cross-language canonicalization proof.
 *
 * Task: TASK-P1-030 030e-a
 * Build Master: §3.7, §3.8
 */
class ReplacementNoticeTest {

    private val keyA = "A".repeat(43)
    private val keyB = "B".repeat(43)

    private fun validNotice(): SignedReplacementNotice = SignedReplacementNotice(
        domain = SignedReplacementNotice.DOMAIN,
        notice = ReplacementNotice(
            fromDeviceId = "device-old-001",
            fromDeviceAuthKey = keyA,
            toDeviceId = "device-new-002",
            toDeviceAuthKey = keyB,
            issuedAt = "2026-10-17T00:00:00Z",
        ),
    )

    // ---------- schema ----------

    @Test
    fun `TEST-REPLACEMENT-NOTICE-VALID accepts a well-formed notice`() {
        val n = validNotice()
        assertEquals(n, SignedReplacementNotice.fromJsonMap(n.toJsonMap()))
    }

    @Test
    fun `TEST-REPLACEMENT-NOTICE-SELF-LOOP-REJECTED rejects from === to`() {
        val n = validNotice()
        val mutated = n.copy(
            notice = n.notice.copy(toDeviceId = n.notice.fromDeviceId),
        )
        assertThrows(IllegalArgumentException::class.java) {
            SignedReplacementNotice.fromJsonMap(mutated.toJsonMap())
        }
    }

    @Test
    fun `TEST-REPLACEMENT-NOTICE-BAD-DOMAIN-REJECTED rejects wrong domain`() {
        val n = validNotice()
        val mutated = n.copy(domain = "umoja.authorization-matrix.v1")
        assertThrows(IllegalArgumentException::class.java) {
            SignedReplacementNotice.fromJsonMap(mutated.toJsonMap())
        }
    }

    @Test
    fun `TEST-REPLACEMENT-NOTICE-BAD-KEY-REJECTED rejects malformed auth key`() {
        val n = validNotice()
        val mutated = n.copy(
            notice = n.notice.copy(fromDeviceAuthKey = "too-short"),
        )
        assertThrows(IllegalArgumentException::class.java) {
            SignedReplacementNotice.fromJsonMap(mutated.toJsonMap())
        }
    }

    // ---------- sign / verify ----------

    @Test
    fun `TEST-REPLACEMENT-NOTICE-SIGN-VERIFY round-trips`() {
        val kp = KeyPairGenerator.getInstance("Ed25519").generateKeyPair()
        val n = validNotice()
        val sig = ReplacementNoticeSigner.sign(n, kp.private)
        assertTrue(ReplacementNoticeSigner.verify(n, sig, kp.public))
    }

    @Test
    fun `TEST-REPLACEMENT-NOTICE-TAMPER-REJECTED rejects modified notice`() {
        val kp = KeyPairGenerator.getInstance("Ed25519").generateKeyPair()
        val n = validNotice()
        val sig = ReplacementNoticeSigner.sign(n, kp.private)
        val tampered = n.copy(
            notice = n.notice.copy(toDeviceId = "device-new-999"),
        )
        assertFalse(ReplacementNoticeSigner.verify(tampered, sig, kp.public))
    }

    // ---------- cross-language vector agreement ----------

    @Test
    fun `TEST-REPLACEMENT-NOTICE-VECTOR-R001 canonical bytes match`() {
        val path = File(
            repoRoot(),
            "docs/reference/canonical-replacement-notice-test-vectors.json",
        )
        val arr = JSONObject(path.readText()).getJSONArray("vectors")
        var r001: JSONObject? = null
        for (i in 0 until arr.length()) {
            val v = arr.getJSONObject(i)
            if (v.getString("id") == "R-001") { r001 = v; break }
        }
        assertTrue("R-001 vector missing", r001 != null)
        val v = r001!!

        val expected = if (v.isNull("expected_canonical_bytes_utf8")) {
            error("R-001 expected_canonical_bytes_utf8 not populated — run generate-matrix-vectors.ts")
        } else {
            v.getString("expected_canonical_bytes_utf8")
        }

        val parsed = SignedReplacementNotice.fromJsonMap(
            jsonObjectToPlainMap(v.getJSONObject("input_wrapper")),
        )

        val actualCanonical = jcsCanonicalizeString(parsed.toJsonMap())
        assertEquals(expected, actualCanonical)

        val expectedDigest = v.getString("expected_sha256_digest_hex")
        val actualDigest = ReplacementNoticeSigner.digest(parsed)
            .joinToString("") { "%02x".format(it.toInt() and 0xFF) }
        assertEquals(expectedDigest, actualDigest)

        val pubRaw = Base64.getUrlDecoder()
            .decode(v.getString("expected_provisioning_public_key_base64url"))
        val pubKey = MatrixSigner.publicKeyFromRaw(pubRaw)
        val sig = v.getString("expected_ed25519_signature_base64url")
        assertTrue(ReplacementNoticeSigner.verify(parsed, sig, pubKey))
    }

    // ---------- helpers ----------

    private fun repoRoot(): File {
        var dir = File(System.getProperty("user.dir")!!)
        for (i in 0 until 10) {
            if (File(dir, "UMOJA-SECURE-BUILD-MASTER.md").exists()) return dir
            dir = dir.parentFile ?: break
        }
        error("could not find repo root from ${System.getProperty("user.dir")}")
    }


}
