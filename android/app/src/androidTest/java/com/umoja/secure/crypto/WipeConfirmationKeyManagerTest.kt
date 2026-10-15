package com.umoja.secure.crypto

import android.content.Context
import android.util.Base64
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.security.KeyFactory
import java.security.Signature
import java.security.spec.X509EncodedKeySpec

/**
 * Instrumented tests for WipeConfirmationKeyManager.
 *
 * These run on a device or emulator because Android Keystore is
 * device-local. There is no JVM path for this class: KeyGenParameterSpec,
 * Context, and SharedPreferences are Android-only.
 *
 * Emulator caveat: on the Android emulator, Keystore has no hardware
 * backing, so Ed25519 key generation falls through to the BouncyCastle
 * software path with AES-256-GCM Keystore wrapping. That path is
 * functionally correct; it reports SECURITY_LEVEL_SOFTWARE instead of
 * TRUSTED_ENVIRONMENT. TASK-P1-034 verifies TEE-backed Ed25519 on real
 * hardware.
 */
@RunWith(AndroidJUnit4::class)
class WipeConfirmationKeyManagerTest {

    private lateinit var context: Context
    private lateinit var wipe: WipeConfirmationKeyManager

    @Before
    fun setUp() {
        context = InstrumentationRegistry.getInstrumentation().targetContext
        wipe = WipeConfirmationKeyManager(context)
        wipe.deleteKey()
    }

    @After
    fun tearDown() {
        wipe.deleteKey()
    }

    @Test
    fun ensureKeyPairGeneratesPublicKey43Chars() {
        wipe.ensureKeyPair()
        val b64 = wipe.publicKeyBase64Url()
        assertNotNull(b64)
        assertEquals(43, b64!!.length)
        assertTrue(b64.matches(Regex("^[A-Za-z0-9_-]{43}$")))
    }

    @Test
    fun signProducesVerifiableSignature() {
        wipe.ensureKeyPair()
        val message = "wipe-confirmation test payload".toByteArray(Charsets.UTF_8)
        val signature = wipe.sign(message)
        assertEquals(64, signature.size)

        // Recover the SPKI form by reading the same Keystore alias directly.
        // WipeConfirmationKeyManager intentionally does not expose the SPKI
        // form; the test reaches it via DeviceKeyManager with the same alias.
        val delegate = DeviceKeyManager(context = context, alias = WipeConfirmationKeyManager.ALIAS)
        val spki = delegate.publicKey()
        assertNotNull(spki)
        val pub = KeyFactory.getInstance("Ed25519")
            .generatePublic(X509EncodedKeySpec(spki!!))
        val verifier = Signature.getInstance("Ed25519")
        verifier.initVerify(pub)
        verifier.update(message)
        assertTrue("signature must verify against the wipe public key", verifier.verify(signature))
    }

    @Test
    fun signWithoutGenerateThrows() {
        wipe.deleteKey()
        var threw = false
        try {
            wipe.sign("x".toByteArray(Charsets.UTF_8))
        } catch (_: Exception) {
            threw = true
        }
        assertTrue("sign without generated key must throw", threw)
    }

    @Test
    fun publicKeyBase64UrlDecodesTo32Bytes() {
        wipe.ensureKeyPair()
        val b64 = wipe.publicKeyBase64Url()!!
        val decoded = Base64.decode(
            b64,
            Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING,
        )
        assertEquals(32, decoded.size)
    }

    @Test
    fun deleteKeyRemovesIt() {
        wipe.ensureKeyPair()
        assertTrue(wipe.hasKey())
        wipe.deleteKey()
        assertFalse(wipe.hasKey())
    }

    @Test
    fun wipeKeyDiffersFromDeviceAuthKey() {
        // Both keys must be distinct keypairs (distinct Keystore aliases).
        val wipeInfo = wipe.ensureKeyPair()
        val device = DeviceKeyManager(context = context)
        val deviceInfo = device.ensureKeyPair()

        val wipeRaw = DeviceIdentity.rawPublicKey(wipeInfo.spkiEncoded)
        val deviceRaw = DeviceIdentity.rawPublicKey(deviceInfo.spkiEncoded)

        assertFalse(
            "wipe key and device auth key must be different keypairs",
            wipeRaw.contentEquals(deviceRaw),
        )
    }

    @Test
    fun wipeKeySurvivesManagerRecreation() {
        wipe.ensureKeyPair()
        val firstPub = wipe.publicKeyBase64Url()
        assertNotNull(firstPub)

        // Fresh manager instance, same alias. Should read the same key.
        val second = WipeConfirmationKeyManager(context)
        val secondPub = second.publicKeyBase64Url()

        assertNotNull(secondPub)
        assertEquals(firstPub, secondPub)
    }
}
