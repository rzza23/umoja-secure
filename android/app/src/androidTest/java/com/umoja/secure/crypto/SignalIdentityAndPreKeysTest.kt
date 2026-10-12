package com.umoja.secure.crypto

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.umoja.secure.storage.SecureStorage
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.signal.libsignal.protocol.ecc.ECPublicKey

@RunWith(AndroidJUnit4::class)
class SignalIdentityAndPreKeysTest {

    private val ns = "test.signal."
    // Reduced batch for tests. The app uses 100.
    private val testBatch = 5

    private lateinit var storage: SecureStorage
    private lateinit var identityStore: SignalIdentityStore
    private lateinit var preKeyStore: SignalPreKeyStore

    @Before
    fun setUp() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        storage = SecureStorage(context)
        storage.allKeys()
            .filter { it.startsWith(ns) }
            .forEach { storage.remove(it) }
        identityStore = SignalIdentityStore(storage, ns)
        preKeyStore = SignalPreKeyStore(storage, ns, testBatch)
    }

    @After
    fun tearDown() {
        storage.allKeys()
            .filter { it.startsWith(ns) }
            .forEach { storage.remove(it) }
    }

    @Test
    fun identityGeneratesAndPersists() {
        assertFalse(identityStore.hasIdentity())
        val first = identityStore.getOrGenerate()
        assertTrue(identityStore.hasIdentity())
        val second = identityStore.getOrGenerate()
        assertTrue(first.serialize().contentEquals(second.serialize()))
    }

    @Test
    fun clearIdentityRemovesIt() {
        identityStore.getOrGenerate()
        assertTrue(identityStore.hasIdentity())
        identityStore.clearIdentity()
        assertFalse(identityStore.hasIdentity())
    }

    @Test
    fun signedPreKeySignsAndVerifiesAgainstIdentity() {
        val identity = identityStore.getOrGenerate()
        val generated = preKeyStore.generateFresh(identity)
        val spk = generated.signedPreKey

        val signedBytes = spk.keyPair.publicKey.serialize()
        assertEquals(64, spk.signature.size)

        val verified = identity.publicKey.publicKey.verifySignature(signedBytes, spk.signature)
        assertTrue("signed prekey signature must verify", verified)
    }

    @Test
    fun signedPreKeySignatureRejectsTamperedBytes() {
        val identity = identityStore.getOrGenerate()
        val generated = preKeyStore.generateFresh(identity)
        val spk = generated.signedPreKey

        val tampered = spk.keyPair.publicKey.serialize()
        tampered[0] = (tampered[0].toInt() xor 0x01).toByte()

        val verified = identity.publicKey.publicKey.verifySignature(tampered, spk.signature)
        assertFalse("tampered bytes should not verify", verified)
    }

    @Test
    fun oneTimePreKeysHaveCorrectCountAndIdMonotonicity() {
        val identity = identityStore.getOrGenerate()
        val generated = preKeyStore.generateFresh(identity)
        assertEquals(testBatch, generated.oneTimePreKeys.size)

        val ids = generated.oneTimePreKeys.map { it.id }
        for (i in 1 until ids.size) {
            assertTrue("ids should increase", ids[i] > ids[i - 1])
        }
    }

    @Test
    fun oneTimePreKeyPublicBytesAre32() {
        val identity = identityStore.getOrGenerate()
        val generated = preKeyStore.generateFresh(identity)
        generated.oneTimePreKeys.forEach { record ->
            val raw = record.keyPair.publicKey.publicKeyBytes
            assertEquals(32, raw.size)
        }
    }

    @Test
    fun signedPreKeyPersistsAcrossStoreReads() {
        val identity = identityStore.getOrGenerate()
        preKeyStore.generateFresh(identity)
        val retrieved = preKeyStore.getSignedPreKey()
        assertNotNull(retrieved)
        val pubBytes = retrieved!!.keyPair.publicKey.publicKeyBytes
        val reconstructed: ECPublicKey = ECPublicKey.fromPublicKeyBytes(pubBytes)
        assertEquals(32, reconstructed.publicKeyBytes.size)
    }

    @Test
    fun registrationIdIsStableAcrossRegeneration() {
        val identity = identityStore.getOrGenerate()
        val first = preKeyStore.generateFresh(identity)
        val second = preKeyStore.generateFresh(identity)
        assertEquals(first.registrationId, second.registrationId)
    }

    @Test
    fun signedPreKeyIdIncrements() {
        val identity = identityStore.getOrGenerate()
        val first = preKeyStore.generateFresh(identity)
        val second = preKeyStore.generateFresh(identity)
        assertTrue(second.signedPreKey.id > first.signedPreKey.id)
    }

    @Test
    fun rawPublicKeysRoundTripThroughFromPublicKeyBytes() {
        val identity = identityStore.getOrGenerate()
        preKeyStore.generateFresh(identity)
        val rawIdentity = identity.publicKey.publicKey.publicKeyBytes
        val reconstructed = ECPublicKey.fromPublicKeyBytes(rawIdentity)
        assertTrue(rawIdentity.contentEquals(reconstructed.publicKeyBytes))
    }

    @Test
    fun kyberPreKeyIsGeneratedAndSigned() {
        val identity = identityStore.getOrGenerate()
        val generated = preKeyStore.generateFresh(identity)

        val kyber = generated.kyberPreKey
        val kyberPubBytes = kyber.keyPair.publicKey.serialize()
        // Kyber-1024 public key serializes to 1568 bytes
        assertEquals("kyber-1024 serialized public key should be 1569 bytes", 1569, kyberPubBytes.size)

        // The signature is produced by the identity key
        val verified = identity.publicKey.publicKey.verifySignature(kyberPubBytes, kyber.signature)
        assertTrue("kyber prekey signature must verify", verified)
    }

    @Test
    fun oneTimeKyberPreKeysHaveExpectedShape() {
        val identity = identityStore.getOrGenerate()
        val generated = preKeyStore.generateFresh(identity)

        assertEquals(testBatch, generated.oneTimeKyberPreKeys.size)
        generated.oneTimeKyberPreKeys.forEach { record ->
            val pubBytes = record.keyPair.publicKey.serialize()
            assertEquals(1569, pubBytes.size)
        }
    }

    @Test
    fun kyberPreKeyPersistsAcrossReads() {
        val identity = identityStore.getOrGenerate()
        preKeyStore.generateFresh(identity)
        val retrieved = preKeyStore.getKyberPreKey()
        assertNotNull(retrieved)
        val pubBytes = retrieved!!.keyPair.publicKey.serialize()
        assertEquals(1569, pubBytes.size)
    }

    @Test
    fun kyberIdIncrements() {
        val identity = identityStore.getOrGenerate()
        val first = preKeyStore.generateFresh(identity)
        val second = preKeyStore.generateFresh(identity)
        assertTrue(second.kyberPreKey.id > first.kyberPreKey.id)
    }
}
