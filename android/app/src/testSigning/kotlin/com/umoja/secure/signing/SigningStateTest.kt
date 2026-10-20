package com.umoja.secure.signing

import com.umoja.secure.crypto.MatrixBuilder
import com.umoja.secure.crypto.ProvisioningBundle
import com.umoja.secure.crypto.PublicKeyInfo
import com.umoja.secure.crypto.jcsCanonicalizeString
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Tests for [SigningState] -- the offline signing app's state class
 * (TASK-P1-033c).
 *
 * No Compose runtime, no Android context, no real Keystore. Every
 * Keystore interaction is an injected lambda; tests fake them
 * synchronously and assert on StateFlow values after each method.
 *
 * Coroutine framework: runBlocking. kotlinx-coroutines-test is not on
 * the classpath; SigningState's suspend methods wrap
 * withContext(Dispatchers.IO) around the injected lambdas, which are
 * synchronous fakes -- the real dispatcher runs but the work is
 * instantaneous.
 */
class SigningStateTest {

    private fun validCanonical(): String {
        val bundleJson = """
            {"domain":"umoja.enrollment-request.v1",
             "device_id":"11111111-2222-4333-8444-555555555555",
             "pub_device_auth_key":"${"A".repeat(43)}",
             "pub_messaging_identity_key":"${"B".repeat(43)}",
             "pub_wipe_confirmation_key":"${"C".repeat(43)}"}
        """.trimIndent()
        val bundle = ProvisioningBundle.parse(bundleJson)
        val signed = MatrixBuilder.build(
            bundle = bundle,
            clearance = "SECRET",
            permittedContacts = emptyList(),
            version = 1,
        )
        return jcsCanonicalizeString(signed.toJsonMap())
    }

    private fun fakeSpki(): ByteArray {
        // Valid 44-byte Ed25519 SPKI: 12-byte prefix + 32 raw bytes.
        val prefix = byteArrayOf(
            0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65,
            0x70, 0x03, 0x21, 0x00,
        )
        return prefix + ByteArray(32) { 0x41 }
    }

    private fun stateWith(
        hasKeyFn: () -> Boolean = { false },
        ensureKeyPairFn: () -> PublicKeyInfo = {
            PublicKeyInfo(fakeSpki(), 2)
        },
        publicKeyFn: () -> ByteArray? = { fakeSpki() },
        signFn: (ByteArray) -> ByteArray = { ByteArray(64) { 0x7f } },
    ) = SigningState(
        hasKeyFn = hasKeyFn,
        ensureKeyPairFn = ensureKeyPairFn,
        publicKeyFn = publicKeyFn,
        signFn = signFn,
    )

    // ============================================================
    // enterCeremonyMode()
    // ============================================================

    @Test
    fun `enterCeremonyMode on fresh device generates key and exposes pubkey`() = runBlocking {
        val s = stateWith(hasKeyFn = { false })
        s.enterCeremonyMode()
        assertEquals(SigningMode.CEREMONY, s.mode.value)
        assertTrue(s.hasKey.value)
        assertNotNull(s.publicKeyB64u.value)
        // 32 raw bytes -> 43-char base64url (no pad)
        assertEquals(43, s.publicKeyB64u.value?.length)
        assertNull(s.error.value)
    }

    @Test
    fun `enterCeremonyMode refuses when key exists (fail-closed)`() = runBlocking {
        var ensureCalled = false
        val s = stateWith(
            hasKeyFn = { true },
            ensureKeyPairFn = {
                ensureCalled = true
                PublicKeyInfo(fakeSpki(), 2)
            },
        )
        s.enterCeremonyMode()
        assertEquals(SigningMode.CEREMONY, s.mode.value)
        assertTrue(s.hasKey.value)
        assertFalse(ensureCalled) // no key generation on retry
        assertNotNull(s.error.value)
        assertTrue(s.error.value?.contains("already present") ?: false)
    }

    @Test
    fun `enterCeremonyMode reports failure if ensureKeyPairFn throws`() = runBlocking {
        val s = stateWith(
            hasKeyFn = { false },
            ensureKeyPairFn = { throw RuntimeException("keystore unavailable") },
        )
        s.enterCeremonyMode()
        assertNotNull(s.error.value)
        assertTrue(s.error.value?.startsWith("Ceremony failed:") ?: false)
        assertFalse(s.hasKey.value)
    }

    // ============================================================
    // enterOperatingMode()
    // ============================================================

    @Test
    fun `enterOperatingMode refuses when no key (fail-closed)`() = runBlocking {
        val s = stateWith(hasKeyFn = { false })
        s.enterOperatingMode()
        assertEquals(SigningMode.OPERATING, s.mode.value)
        assertFalse(s.hasKey.value)
        assertNotNull(s.error.value)
        assertTrue(s.error.value?.contains("No provisioning key") ?: false)
    }

    @Test
    fun `enterOperatingMode succeeds when key exists`() = runBlocking {
        val s = stateWith(hasKeyFn = { true })
        s.enterOperatingMode()
        assertEquals(SigningMode.OPERATING, s.mode.value)
        assertTrue(s.hasKey.value)
        assertNull(s.error.value)
        assertEquals(
            "Ready to sign — scan or paste a canonical matrix",
            s.statusMessage.value,
        )
    }

    // ============================================================
    // setCanonical()
    // ============================================================

    @Test
    fun `setCanonical on valid JCS input populates canonical and hash`() {
        val s = stateWith()
        val canonical = validCanonical()
        s.setCanonical(canonical)
        assertEquals(canonical, s.canonicalUtf8.value)
        assertNotNull(s.canonicalHashB64u.value)
        // SHA-256 digest base64url -> 43 chars
        assertEquals(43, s.canonicalHashB64u.value?.length)
        assertNull(s.error.value)
    }

    @Test
    fun `setCanonical rejects non-JCS input`() {
        val s = stateWith()
        val canonical = validCanonical()
        // Pretty-print adds whitespace -> no longer JCS-canonical
        val nonCanonical = canonical.replace(",", ", ")
        s.setCanonical(nonCanonical)
        assertNull(s.canonicalUtf8.value)
        assertNotNull(s.error.value)
        assertTrue(s.error.value?.contains("not JCS-canonical") ?: false)
    }

    @Test
    fun `setCanonical rejects malformed JSON`() {
        val s = stateWith()
        s.setCanonical("not-json")
        assertNull(s.canonicalUtf8.value)
        assertNotNull(s.error.value)
        assertTrue(s.error.value?.startsWith("Matrix parse failed:") ?: false)
    }

    @Test
    fun `setCanonical rejects empty input`() {
        val s = stateWith()
        s.setCanonical("   ")
        assertNotNull(s.error.value)
        assertEquals("Canonical matrix is empty", s.error.value)
    }

    @Test
    fun `setCanonical clears prior signature`() = runBlocking {
        val s = stateWith()
        s.setCanonical(validCanonical())
        s.sign()
        assertNotNull(s.signatureB64u.value)
        s.setCanonical(validCanonical())
        assertNull(s.signatureB64u.value)
    }

    // ============================================================
    // sign()
    // ============================================================

    @Test
    fun `sign produces signature from SHA-256 digest`() = runBlocking {
        var capturedDigest: ByteArray? = null
        val s = stateWith(
            signFn = { digest ->
                capturedDigest = digest
                ByteArray(64) { 0x7f }
            },
        )
        s.setCanonical(validCanonical())
        s.sign()
        assertNotNull(capturedDigest)
        assertEquals(32, capturedDigest!!.size) // SHA-256 digest = 32 bytes
        assertNotNull(s.signatureB64u.value)
        // 64 bytes base64url -> 86 chars
        assertEquals(86, s.signatureB64u.value?.length)
    }

    @Test
    fun `sign refuses when no canonical loaded`() = runBlocking {
        val s = stateWith()
        s.sign()
        assertNull(s.signatureB64u.value)
        assertEquals("No matrix loaded", s.error.value)
    }

    @Test
    fun `sign reports error when signFn returns wrong length`() = runBlocking {
        val s = stateWith(
            signFn = { ByteArray(32) { 0x7f } }, // wrong: 32, not 64
        )
        s.setCanonical(validCanonical())
        s.sign()
        assertNull(s.signatureB64u.value)
        assertTrue(s.error.value?.contains("expected 64") ?: false)
    }

    // ============================================================
    // clearSignature()
    // ============================================================

    @Test
    fun `clearSignature clears signature but preserves canonical`() = runBlocking {
        val s = stateWith()
        s.setCanonical(validCanonical())
        s.sign()
        val canonicalBefore = s.canonicalUtf8.value
        assertNotNull(canonicalBefore)
        s.clearSignature()
        assertNull(s.signatureB64u.value)
        assertEquals(canonicalBefore, s.canonicalUtf8.value)
    }
}
