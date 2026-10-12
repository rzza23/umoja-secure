package com.umoja.secure.crypto

import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.signal.libsignal.protocol.IdentityKeyPair
import org.signal.libsignal.protocol.SessionBuilder
import org.signal.libsignal.protocol.SessionCipher
import org.signal.libsignal.protocol.SignalProtocolAddress
import org.signal.libsignal.protocol.ecc.ECKeyPair
import org.signal.libsignal.protocol.kem.KEMKeyPair
import org.signal.libsignal.protocol.kem.KEMKeyType
import org.signal.libsignal.protocol.message.CiphertextMessage
import org.signal.libsignal.protocol.message.PreKeySignalMessage
import org.signal.libsignal.protocol.message.SignalMessage
import org.signal.libsignal.protocol.state.KyberPreKeyRecord
import org.signal.libsignal.protocol.state.PreKeyBundle
import org.signal.libsignal.protocol.state.PreKeyRecord
import org.signal.libsignal.protocol.state.SignedPreKeyRecord
import org.signal.libsignal.protocol.state.impl.InMemorySignalProtocolStore

/**
 * Proves the full Signal Protocol handshake and messaging flow works in
 * Android, using libsignal's own in-memory stores.
 *
 * This is intentionally in-process: no backend, no second emulator, no
 * persistence. Its only purpose is to demonstrate the crypto stack works
 * end to end. Persistence and cross-device integration are 20b-ii and 20c.
 *
 * Flow exercised:
 *   1. Alice and Bob each have an identity keypair and a SignalProtocolStore.
 *   2. Bob publishes a prekey bundle (identity + signed prekey + one-time
 *      prekey + Kyber prekey, PQXDH).
 *   3. Alice runs SessionBuilder.process(bundle) to derive a shared session.
 *   4. Alice encrypts a message. The first message is a PreKeySignalMessage.
 *   5. Bob decrypts it. The Double Ratchet advances on both sides.
 *   6. Bob replies. His message is a SignalMessage (no prekey material).
 *   7. Alice decrypts Bob\'s reply.
 */
@RunWith(AndroidJUnit4::class)
class X3DHInMemoryTest {

    private lateinit var aliceStore: InMemorySignalProtocolStore
    private lateinit var bobStore: InMemorySignalProtocolStore
    private lateinit var aliceAddress: SignalProtocolAddress
    private lateinit var bobAddress: SignalProtocolAddress
    private lateinit var bobBundle: PreKeyBundle

    private val aliceRegistrationId = 1111
    private val bobRegistrationId = 2222

    private val bobDeviceId = 1
    private val bobSignedPreKeyId = 1
    private val bobOneTimePreKeyId = 42
    private val bobKyberPreKeyId = 7

    @Before
    fun setUp() {
        val aliceIdentity = IdentityKeyPair.generate()
        val bobIdentity = IdentityKeyPair.generate()

        aliceStore = InMemorySignalProtocolStore(aliceIdentity, aliceRegistrationId)
        bobStore = InMemorySignalProtocolStore(bobIdentity, bobRegistrationId)

        aliceAddress = SignalProtocolAddress("alice", 1)
        bobAddress = SignalProtocolAddress("bob", bobDeviceId)

        // Bob generates a signed prekey
        val bobSignedPreKeyPair = ECKeyPair.generate()
        val bobSignedPreKeySig = bobIdentity.privateKey.calculateSignature(
            bobSignedPreKeyPair.publicKey.serialize(),
        )
        bobStore.storeSignedPreKey(
            bobSignedPreKeyId,
            SignedPreKeyRecord(
                bobSignedPreKeyId,
                System.currentTimeMillis(),
                bobSignedPreKeyPair,
                bobSignedPreKeySig,
            ),
        )

        // Bob generates a one-time prekey
        val bobOneTimePreKeyPair = ECKeyPair.generate()
        bobStore.storePreKey(
            bobOneTimePreKeyId,
            PreKeyRecord(bobOneTimePreKeyId, bobOneTimePreKeyPair),
        )

        // Bob generates a Kyber (PQXDH) prekey
        val bobKyberKeyPair = KEMKeyPair.generate(KEMKeyType.KYBER_1024)
        val bobKyberSig = bobIdentity.privateKey.calculateSignature(
            bobKyberKeyPair.publicKey.serialize(),
        )
        bobStore.storeKyberPreKey(
            bobKyberPreKeyId,
            KyberPreKeyRecord(
                bobKyberPreKeyId,
                System.currentTimeMillis(),
                bobKyberKeyPair,
                bobKyberSig,
            ),
        )

        // Build the bundle Alice will fetch (in production, over HTTP)
        bobBundle = PreKeyBundle(
            bobRegistrationId,
            bobDeviceId,
            bobOneTimePreKeyId,
            bobOneTimePreKeyPair.publicKey,
            bobSignedPreKeyId,
            bobSignedPreKeyPair.publicKey,
            bobSignedPreKeySig,
            bobIdentity.publicKey,
            bobKyberPreKeyId,
            bobKyberKeyPair.publicKey,
            bobKyberSig,
        )
    }

    @Test
    fun aliceEstablishesSessionFromBobBundle() {
        assertFalse(aliceStore.containsSession(bobAddress))

        val builder = SessionBuilder(aliceStore, bobAddress)
        builder.process(bobBundle)

        assertTrue(aliceStore.containsSession(bobAddress))
        val record = aliceStore.loadSession(bobAddress)
        assertNotNull(record)
        assertEquals(aliceRegistrationId, record!!.localRegistrationId)
        assertEquals(bobRegistrationId, record.remoteRegistrationId)
    }

    @Test
    fun firstMessageIsPreKeySignalMessageAndDecrypts() {
        SessionBuilder(aliceStore, bobAddress).process(bobBundle)

        val aliceCipher = SessionCipher(aliceStore, bobAddress)
        val plaintext = "Hello Bob, this is Alice.".toByteArray(Charsets.UTF_8)
        val ciphertext = aliceCipher.encrypt(plaintext)

        assertEquals(CiphertextMessage.PREKEY_TYPE, ciphertext.type)

        val bobCipher = SessionCipher(bobStore, aliceAddress)
        val decrypted = bobCipher.decrypt(PreKeySignalMessage(ciphertext.serialize()))

        assertTrue(plaintext.contentEquals(decrypted))
    }

    @Test
    fun fullRoundTripWithRatchetAdvancement() {
        SessionBuilder(aliceStore, bobAddress).process(bobBundle)

        val aliceCipher = SessionCipher(aliceStore, bobAddress)
        val bobCipher = SessionCipher(bobStore, aliceAddress)

        // Alice -> Bob: first message is a PreKeySignalMessage
        val aliceMsg = "Hello Bob".toByteArray(Charsets.UTF_8)
        val aliceCt = aliceCipher.encrypt(aliceMsg)
        assertEquals(CiphertextMessage.PREKEY_TYPE, aliceCt.type)

        val bobDecrypted = bobCipher.decrypt(PreKeySignalMessage(aliceCt.serialize()))
        assertTrue(aliceMsg.contentEquals(bobDecrypted))

        // Bob -> Alice: reply is a SignalMessage (session is established)
        val bobMsg = "Hi Alice, I got it.".toByteArray(Charsets.UTF_8)
        val bobCt = bobCipher.encrypt(bobMsg)
        assertEquals(CiphertextMessage.WHISPER_TYPE, bobCt.type)

        val aliceDecrypted = aliceCipher.decrypt(SignalMessage(bobCt.serialize()))
        assertTrue(bobMsg.contentEquals(aliceDecrypted))
    }

    @Test
    fun multipleMessagesInSameDirection() {
        SessionBuilder(aliceStore, bobAddress).process(bobBundle)
        val aliceCipher = SessionCipher(aliceStore, bobAddress)
        val bobCipher = SessionCipher(bobStore, aliceAddress)

        // In Signal Protocol, Alice keeps sending PreKeySignalMessages until
        // she receives a reply from Bob. This is by design: her side of the
        // session is confirmed only when she decrypts a message from him.

        // First message: prekey
        val ct1 = aliceCipher.encrypt("first".toByteArray(Charsets.UTF_8))
        assertEquals(CiphertextMessage.PREKEY_TYPE, ct1.type)
        val pt1 = bobCipher.decrypt(PreKeySignalMessage(ct1.serialize()))
        assertTrue("first".toByteArray(Charsets.UTF_8).contentEquals(pt1))

        // Second message from Alice: still prekey (Bob has not replied)
        val ct2 = aliceCipher.encrypt("second".toByteArray(Charsets.UTF_8))
        assertEquals(CiphertextMessage.PREKEY_TYPE, ct2.type)
        val pt2 = bobCipher.decrypt(PreKeySignalMessage(ct2.serialize()))
        assertTrue("second".toByteArray(Charsets.UTF_8).contentEquals(pt2))

        // Bob replies. This confirms Alice's session end to end.
        val bobReply = bobCipher.encrypt("got them".toByteArray(Charsets.UTF_8))
        assertEquals(CiphertextMessage.WHISPER_TYPE, bobReply.type)
        val aliceGotReply = aliceCipher.decrypt(SignalMessage(bobReply.serialize()))
        assertTrue("got them".toByteArray(Charsets.UTF_8).contentEquals(aliceGotReply))

        // Now Alice's outbound is ratcheted
        val ct3 = aliceCipher.encrypt("third".toByteArray(Charsets.UTF_8))
        assertEquals(CiphertextMessage.WHISPER_TYPE, ct3.type)
        val pt3 = bobCipher.decrypt(SignalMessage(ct3.serialize()))
        assertTrue("third".toByteArray(Charsets.UTF_8).contentEquals(pt3))
    }

    @Test
    fun ciphertextDoesNotContainPlaintext() {
        SessionBuilder(aliceStore, bobAddress).process(bobBundle)
        val aliceCipher = SessionCipher(aliceStore, bobAddress)

        val secret = "UNIQUE_MARKER_STRING_9263741".toByteArray(Charsets.UTF_8)
        val ciphertext = aliceCipher.encrypt(secret)

        val found = containsSubsequence(ciphertext.serialize(), secret)
        assertFalse("ciphertext must not contain plaintext", found)
    }

    @Test
    fun tamperedCiphertextFailsDecryption() {
        SessionBuilder(aliceStore, bobAddress).process(bobBundle)
        val aliceCipher = SessionCipher(aliceStore, bobAddress)
        val bobCipher = SessionCipher(bobStore, aliceAddress)

        val ciphertext = aliceCipher.encrypt("original".toByteArray(Charsets.UTF_8))
        val tampered = ciphertext.serialize().copyOf()
        // Flip a bit in the middle of the payload
        val mid = tampered.size / 2
        tampered[mid] = (tampered[mid].toInt() xor 0x01).toByte()

        var threw = false
        try {
            bobCipher.decrypt(PreKeySignalMessage(tampered))
        } catch (_: Exception) {
            threw = true
        }
        assertTrue("tampered ciphertext must not decrypt cleanly", threw)
    }

    @Test
    fun bothSidesPersistSessionRecords() {
        SessionBuilder(aliceStore, bobAddress).process(bobBundle)
        val aliceCipher = SessionCipher(aliceStore, bobAddress)
        val bobCipher = SessionCipher(bobStore, aliceAddress)

        aliceCipher.encrypt("hi".toByteArray(Charsets.UTF_8))
        val firstMessage = aliceCipher.encrypt("hi again".toByteArray(Charsets.UTF_8))
        bobCipher.decrypt(PreKeySignalMessage(firstMessage.serialize()))

        // Alice has a session with Bob after process()
        assertTrue(aliceStore.containsSession(bobAddress))
        // Bob has a session with Alice after decrypting the first message
        assertTrue(bobStore.containsSession(aliceAddress))
    }

    private fun containsSubsequence(haystack: ByteArray, needle: ByteArray): Boolean {
        if (needle.isEmpty() || needle.size > haystack.size) return false
        outer@ for (i in 0..(haystack.size - needle.size)) {
            for (j in needle.indices) {
                if (haystack[i + j] != needle[j]) continue@outer
            }
            return true
        }
        return false
    }
}
