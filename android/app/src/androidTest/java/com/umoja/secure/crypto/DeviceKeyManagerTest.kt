package com.umoja.secure.crypto

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.security.KeyFactory
import java.security.Signature
import java.security.spec.X509EncodedKeySpec

@RunWith(AndroidJUnit4::class)
class DeviceKeyManagerTest {

    private val testAlias = "umoja.test.identity"
    private val testAlias2 = "umoja.test.identity.2"
    private lateinit var manager: DeviceKeyManager

    @Before
    fun setUp() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        manager = DeviceKeyManager(context = context, alias = testAlias)
        manager.deleteKey()
        DeviceKeyManager(context = context, alias = testAlias2).deleteKey()
    }

    @After
    fun tearDown() {
        manager.deleteKey()
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        DeviceKeyManager(context = context, alias = testAlias2).deleteKey()
    }

    @Test
    fun ensureKeyPairGeneratesUsableEd25519Key() {
        val info = manager.ensureKeyPair()
        assertTrue("Public key encoding should be non-empty", info.spkiEncoded.isNotEmpty())

        val message = "the quick brown fox".toByteArray(Charsets.UTF_8)
        val signature = manager.sign(message)

        val publicKey = KeyFactory.getInstance("Ed25519")
            .generatePublic(X509EncodedKeySpec(info.spkiEncoded))
        val verifier = Signature.getInstance("Ed25519")
        verifier.initVerify(publicKey)
        verifier.update(message)
        assertTrue("Signature should verify with the same message", verifier.verify(signature))
    }

    @Test
    fun signatureDoesNotVerifyForDifferentMessage() {
        manager.ensureKeyPair()
        val signature = manager.sign("original".toByteArray())

        val publicKey = KeyFactory.getInstance("Ed25519")
            .generatePublic(X509EncodedKeySpec(manager.publicKey()!!))
        val verifier = Signature.getInstance("Ed25519")
        verifier.initVerify(publicKey)
        verifier.update("tampered".toByteArray())
        assertFalse("Signature must not verify for a different message", verifier.verify(signature))
    }

    @Test
    fun existingKeyIsReused() {
        val first = manager.ensureKeyPair()
        val second = manager.ensureKeyPair()
        assertArrayEquals(first.spkiEncoded, second.spkiEncoded)
    }

    @Test
    fun deleteKeyRemovesIt() {
        manager.ensureKeyPair()
        assertTrue(manager.hasKey())
        manager.deleteKey()
        assertFalse(manager.hasKey())
    }

    @Test
    fun securityLevelIsReported() {
        val info = manager.ensureKeyPair()
        val level = info.securityLevel
        val valid = setOf(
            DeviceKeyManager.SECURITY_LEVEL_UNKNOWN,
            DeviceKeyManager.SECURITY_LEVEL_SOFTWARE,
            DeviceKeyManager.SECURITY_LEVEL_TRUSTED_ENVIRONMENT,
            DeviceKeyManager.SECURITY_LEVEL_STRONGBOX,
        )
        assertTrue("Security level should be one of $valid, got $level", level in valid)
    }

    @Test
    fun rawPublicKeyIs32Bytes() {
        val info = manager.ensureKeyPair()
        val raw = DeviceIdentity.rawPublicKey(info.spkiEncoded)
        assertEquals(32, raw.size)
    }

    @Test
    fun base64UrlEncodingIs43Characters() {
        val info = manager.ensureKeyPair()
        val encoded = DeviceIdentity.encodePublicKey(info.spkiEncoded)
        assertEquals(43, encoded.length)
        assertTrue(
            "Should match base64url charset",
            encoded.matches(Regex("^[A-Za-z0-9_-]{43}$")),
        )
    }

    @Test
    fun differentKeysProduceDifferentEncodings() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val managerA = DeviceKeyManager(context = context, alias = testAlias)
        val managerB = DeviceKeyManager(context = context, alias = testAlias2)
        managerA.ensureKeyPair()
        managerB.ensureKeyPair()

        val a = DeviceIdentity.encodePublicKey(managerA.publicKey()!!)
        val b = DeviceIdentity.encodePublicKey(managerB.publicKey()!!)
        assertNotEquals(a, b)
    }

    @Test
    fun fingerprintIsStable() {
        val info = manager.ensureKeyPair()
        val f1 = DeviceIdentity.fingerprint(info.spkiEncoded)
        val f2 = DeviceIdentity.fingerprint(info.spkiEncoded)
        assertEquals(f1, f2)
        assertEquals(16, f1.length)
    }
}
