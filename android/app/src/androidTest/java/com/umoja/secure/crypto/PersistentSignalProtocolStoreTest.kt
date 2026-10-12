package com.umoja.secure.crypto

import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Ignore
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
import org.signal.libsignal.protocol.IdentityKey
import org.signal.libsignal.protocol.IdentityKeyPair
import org.signal.libsignal.protocol.SessionBuilder
import org.signal.libsignal.protocol.SessionCipher
import org.signal.libsignal.protocol.SignalProtocolAddress
import org.signal.libsignal.protocol.ecc.ECKeyPair
import org.signal.libsignal.protocol.ecc.ECPublicKey
import org.signal.libsignal.protocol.kem.KEMKeyPair
import org.signal.libsignal.protocol.kem.KEMKeyType
import org.signal.libsignal.protocol.message.PreKeySignalMessage
import org.signal.libsignal.protocol.state.KyberPreKeyRecord
import org.signal.libsignal.protocol.state.PreKeyBundle
import org.signal.libsignal.protocol.state.PreKeyRecord
import org.signal.libsignal.protocol.state.SignedPreKeyRecord

@RunWith(AndroidJUnit4::class)
class PersistentSignalProtocolStoreTest {

    private val aliceNs = "test.store.alice."
    private val bobNs = "test.store.bob."

    private lateinit var storage: SecureStorage

    private fun makeStore(ns: String): PersistentSignalProtocolStore {
        val identity = SignalIdentityStore(storage, ns)
        return PersistentSignalProtocolStore(storage, identity, ns)
    }

    @Before
    fun setUp() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        storage = SecureStorage(context)
        clearNamespace(aliceNs)
        clearNamespace(bobNs)
    }

    @After
    fun tearDown() {
        clearNamespace(aliceNs)
        clearNamespace(bobNs)
        System.gc()
        Thread.sleep(20)
    }

    private fun clearNamespace(ns: String) {
        storage.allKeys()
            .filter { it.startsWith(ns) }
            .forEach { storage.remove(it) }
    }

    // ============================================================
    // Simple persistence tests (one store instance per scope)
    // ============================================================

    @Test
    fun registrationIdIsStableAcrossStoreRecreation() {
        val first = makeStore(aliceNs).getLocalRegistrationId()
        val second = makeStore(aliceNs).getLocalRegistrationId()
        assertEquals(first, second)
    }

    @Test
    fun identityPersistsAcrossStoreRecreation() {
        val id1 = makeStore(aliceNs).getIdentityKeyPair().publicKey.serialize()
        val id2 = makeStore(aliceNs).getIdentityKeyPair().publicKey.serialize()
        assertTrue(id1.contentEquals(id2))
    }

    @Test
    fun signedPreKeyPersists() {
        val alice = makeStore(aliceNs)
        val bundle = alice.generateAndStorePreKeys(oneTimeEcCount = 3, oneTimeKyberCount = 2)
        val id = bundle.signedPreKeyId
        val originalPub = bundle.signedPreKey.keyPair.publicKey.serialize()

        val alice2 = makeStore(aliceNs)
        assertTrue(alice2.containsSignedPreKey(id))
        val loaded = alice2.loadSignedPreKey(id)
        assertEquals(id, loaded.id)
        assertTrue(
            originalPub.contentEquals(loaded.keyPair.publicKey.serialize()),
        )
        assertTrue(
            bundle.signedPreKey.signature.contentEquals(loaded.signature),
        )
    }

    @Test
    fun kyberPreKeyPersists() {
        val alice = makeStore(aliceNs)
        val bundle = alice.generateAndStorePreKeys(oneTimeEcCount = 0, oneTimeKyberCount = 0)
        val id = bundle.kyberPreKeyId

        val alice2 = makeStore(aliceNs)
        assertTrue("kyber prekey id $id must be present after recreation", alice2.containsKyberPreKey(id))
        val loaded = alice2.loadKyberPreKey(id)
        assertEquals("loaded id must match original", id, loaded.id)
    }

    @Test
    fun oneTimeEcPreKeysPersist() {
        val alice = makeStore(aliceNs)
        alice.generateAndStorePreKeys(oneTimeEcCount = 3, oneTimeKyberCount = 0)

        val alice2 = makeStore(aliceNs)
        assertTrue(alice2.containsPreKey(1))
        assertTrue(alice2.containsPreKey(2))
        assertTrue(alice2.containsPreKey(3))
        assertNotNull(alice2.loadPreKey(2))
    }

    @Test
    fun removePreKeyIsPersistent() {
        val alice = makeStore(aliceNs)
        alice.generateAndStorePreKeys(oneTimeEcCount = 3, oneTimeKyberCount = 0)
        alice.removePreKey(2)

        val alice2 = makeStore(aliceNs)
        assertFalse(alice2.containsPreKey(2))
        assertTrue(alice2.containsPreKey(1))
        assertTrue(alice2.containsPreKey(3))
    }

    @Test
    fun peerIdentityPersists() {
        val bob = makeStore(bobNs)
        val bobIdentity = bob.getIdentityKeyPair().publicKey
        val bobBytes = bobIdentity.serialize()
        val bobAddress = SignalProtocolAddress("bob", 1)

        val alice = makeStore(aliceNs)
        val change = alice.saveIdentity(bobAddress, bobIdentity)
        assertEquals(
            org.signal.libsignal.protocol.state.IdentityKeyStore.IdentityChange.NEW_OR_UNCHANGED,
            change,
        )

        val alice2 = makeStore(aliceNs)
        val stored = alice2.getIdentity(bobAddress)
        assertNotNull(stored)
        assertTrue(bobBytes.contentEquals(stored!!.serialize()))
    }

    @Test
    fun identityChangeIsReported() {
        val bobIdentity = IdentityKeyPair.generate().publicKey
        val carolIdentity = IdentityKeyPair.generate().publicKey
        val bobAddress = SignalProtocolAddress("bob", 1)

        val alice = makeStore(aliceNs)
        alice.saveIdentity(bobAddress, bobIdentity)
        val change = alice.saveIdentity(bobAddress, carolIdentity)
        assertEquals(
            org.signal.libsignal.protocol.state.IdentityKeyStore.IdentityChange.REPLACED_EXISTING,
            change,
        )
    }

    @Test
    fun kyberPreKeyMarkedUsedCannotBeReused() {
        val alice = makeStore(aliceNs)
        val bundle = alice.generateAndStorePreKeys(oneTimeEcCount = 0, oneTimeKyberCount = 0)
        val baseKey = ECKeyPair.generate().publicKey

        alice.markKyberPreKeyUsed(bundle.kyberPreKeyId, 1, baseKey)

        var threw = false
        try {
            alice.markKyberPreKeyUsed(bundle.kyberPreKeyId, 1, baseKey)
        } catch (_: Exception) {
            threw = true
        }
        assertTrue("second markKyberPreKeyUsed must throw", threw)
    }

    @Test
    fun signedPreKeySignatureVerifiesAgainstIdentity() {
        val alice = makeStore(aliceNs)
        val generated = alice.generateAndStorePreKeys(oneTimeEcCount = 0, oneTimeKyberCount = 0)
        val spk = generated.signedPreKey
        val identity = alice.getIdentityKeyPair()

        val signedBytes = spk.keyPair.publicKey.serialize()
        assertEquals("signed prekey signature should be 64 bytes", 64, spk.signature.size)

        val verified = identity.publicKey.publicKey.verifySignature(signedBytes, spk.signature)
        assertTrue("signed prekey signature must verify with identity key", verified)
    }

    @Test
    fun kyberPreKeySignatureVerifiesAgainstIdentity() {
        val alice = makeStore(aliceNs)
        val generated = alice.generateAndStorePreKeys(oneTimeEcCount = 0, oneTimeKyberCount = 0)
        val kyber = generated.kyberPreKey
        val identity = alice.getIdentityKeyPair()

        val kyberBytes = kyber.keyPair.publicKey.serialize()
        assertEquals("kyber-1024 serialized public key should be 1569 bytes", 1569, kyberBytes.size)

        val verified = identity.publicKey.publicKey.verifySignature(kyberBytes, kyber.signature)
        assertTrue("kyber prekey signature must verify with identity key", verified)
    }

    @Test
    fun tamperedSignedPreKeySignatureIsRejected() {
        val alice = makeStore(aliceNs)
        val generated = alice.generateAndStorePreKeys(oneTimeEcCount = 0, oneTimeKyberCount = 0)
        val spk = generated.signedPreKey
        val identity = alice.getIdentityKeyPair()

        // Tamper with the signed bytes
        val tampered = spk.keyPair.publicKey.serialize()
        tampered[0] = (tampered[0].toInt() xor 0x01).toByte()

        val verified = identity.publicKey.publicKey.verifySignature(tampered, spk.signature)
        assertFalse("tampered bytes must not verify", verified)
    }

    @Test
    fun successivePreKeyGenerationsUseMonotonicIds() {
        val alice = makeStore(aliceNs)
        val first = alice.generateAndStorePreKeys(oneTimeEcCount = 3, oneTimeKyberCount = 2)
        val second = alice.generateAndStorePreKeys(oneTimeEcCount = 3, oneTimeKyberCount = 2)

        assertTrue(
            "signed prekey id must increase across uploads",
            second.signedPreKeyId > first.signedPreKeyId,
        )
        assertTrue(
            "kyber prekey id must increase across uploads",
            second.kyberPreKeyId > first.kyberPreKeyId,
        )

        val firstEcIds = first.oneTimeEcPreKeys.map { it.id }
        val secondEcIds = second.oneTimeEcPreKeys.map { it.id }
        assertTrue(
            "second batch of EC one-time ids must not overlap first",
            secondEcIds.min() > firstEcIds.max(),
        )
        val firstKyberIds = first.oneTimeKyberPreKeys.map { it.id }
        val secondKyberIds = second.oneTimeKyberPreKeys.map { it.id }
        assertTrue(
            "second batch of Kyber one-time ids must not overlap first",
            secondKyberIds.min() > firstKyberIds.max(),
        )
    }

    @Test
    fun oldOneTimePreKeysRemainLoadableAfterNewBatch() {
        val alice = makeStore(aliceNs)
        val first = alice.generateAndStorePreKeys(oneTimeEcCount = 3, oneTimeKyberCount = 2)
        alice.generateAndStorePreKeys(oneTimeEcCount = 3, oneTimeKyberCount = 2)

        first.oneTimeEcPreKeys.forEach { rec ->
            assertTrue(
                "EC prekey ${rec.id} must still load after a new batch",
                alice.containsPreKey(rec.id),
            )
            assertNotNull(alice.loadPreKey(rec.id))
        }
        first.oneTimeKyberPreKeys.forEach { rec ->
            assertTrue(
                "Kyber prekey ${rec.id} must still load after a new batch",
                alice.containsKyberPreKey(rec.id),
            )
            assertNotNull(alice.loadKyberPreKey(rec.id))
        }
    }
}
