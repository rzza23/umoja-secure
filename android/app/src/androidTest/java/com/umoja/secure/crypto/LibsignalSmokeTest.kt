package com.umoja.secure.crypto

import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.signal.libsignal.protocol.ecc.ECKeyPair
import org.signal.libsignal.protocol.ecc.ECPublicKey

@RunWith(AndroidJUnit4::class)
class LibsignalSmokeTest {

    @Test
    fun nativeLibraryLoadsAndGeneratesKeyPair() {
        val pair = ECKeyPair.generate()
        assertNotNull(pair)
        assertNotNull(pair.publicKey)
        assertNotNull(pair.privateKey)
    }

    @Test
    fun publicKeySerializesTo33Bytes() {
        val pair = ECKeyPair.generate()
        val serialized = pair.publicKey.serialize()
        assertEquals(33, serialized.size)
    }

    @Test
    fun rawPublicKeyBytesAre32() {
        val pair = ECKeyPair.generate()
        val raw = pair.publicKey.publicKeyBytes
        assertEquals(32, raw.size)
    }

    @Test
    fun privateKeySerializesTo32Bytes() {
        val pair = ECKeyPair.generate()
        val serialized = pair.privateKey.serialize()
        assertEquals(32, serialized.size)
    }

    @Test
    fun signAndVerifyRoundTrip() {
        val pair = ECKeyPair.generate()
        val message = "umoja test message".toByteArray(Charsets.UTF_8)
        val signature = pair.privateKey.calculateSignature(message)
        assertTrue(signature.isNotEmpty())
        val valid = pair.publicKey.verifySignature(message, signature)
        assertTrue(valid)
    }

    @Test
    fun verifyRejectsDifferentMessage() {
        val pair = ECKeyPair.generate()
        val signature = pair.privateKey.calculateSignature("original".toByteArray(Charsets.UTF_8))
        val valid = pair.publicKey.verifySignature("tampered".toByteArray(Charsets.UTF_8), signature)
        assertFalse(valid)
    }

    @Test
    fun publicKeyRoundTripsThroughRawBytes() {
        val pair = ECKeyPair.generate()
        val rawBytes = pair.publicKey.publicKeyBytes
        val reconstructed: ECPublicKey = ECPublicKey.fromPublicKeyBytes(rawBytes)
        assertArrayEquals(rawBytes, reconstructed.publicKeyBytes)
    }

    @Test
    fun twoGeneratedKeyPairsAreDifferent() {
        val a = ECKeyPair.generate()
        val b = ECKeyPair.generate()
        assertFalse(a.publicKey.publicKeyBytes.contentEquals(b.publicKey.publicKeyBytes))
    }
}
