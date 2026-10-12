package com.umoja.secure.crypto

import android.util.Base64
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.security.KeyPairGenerator
import java.security.SecureRandom
import java.security.Security
import java.security.Signature

/**
 * Generates libsignal-compatible prekey material using BouncyCastle.
 *
 * NOTE: This is a Phase-1 stand-in. When libsignal is integrated (Day 18),
 * the key generation and signed-prekey signing will use libsignal's APIs.
 * The output shape (base64url, raw 32-byte public keys, 64-byte signatures)
 * matches what the backend accepts and what libsignal expects.
 *
 * All keys are Ed25519 for the signed prekey signature. The identity key
 * used for signing is our device identity key from DeviceKeyManager.
 */
object PreKeyGenerator {

    private const val SW_PROVIDER = "BC"
    private const val ONE_TIME_PREKEY_BATCH = 100

    init {
        Security.removeProvider(SW_PROVIDER)
        Security.addProvider(BouncyCastleProvider())
    }

    /**
     * A locally generated signed prekey and its signature.
     * The signature is over the raw public key bytes.
     */
    data class SignedPreKey(
        val id: Int,
        val publicKey: ByteArray,
        val signature: ByteArray,
    )

    /**
     * A one-time prekey.
     */
    data class OneTimePreKey(
        val id: Int,
        val publicKey: ByteArray,
    )

    /**
     * Generate a fresh signed prekey. The signature is produced by signing
     * the raw public key bytes with the device identity key.
     */
    fun generateSignedPreKey(
        id: Int,
        identitySigner: (ByteArray) -> ByteArray,
    ): SignedPreKey {
        val generator = KeyPairGenerator.getInstance("Ed25519", SW_PROVIDER)
        val keyPair = generator.generateKeyPair()
        val publicRaw = extractRawPublicKey(keyPair.public.encoded)
        val signature = identitySigner(publicRaw)
        return SignedPreKey(id = id, publicKey = publicRaw, signature = signature)
    }

    /**
     * Generate a batch of one-time prekeys.
     */
    fun generateOneTimePreKeys(count: Int = ONE_TIME_PREKEY_BATCH): List<OneTimePreKey> {
        val random = SecureRandom()
        val startId = (random.nextInt(1_000_000) + 1)
        val generator = KeyPairGenerator.getInstance("Ed25519", SW_PROVIDER)
        return (0 until count).map { offset ->
            val keyPair = generator.generateKeyPair()
            OneTimePreKey(
                id = startId + offset,
                publicKey = extractRawPublicKey(keyPair.public.encoded),
            )
        }
    }

    /**
     * Extract the raw 32-byte Ed25519 public key from X.509 SPKI encoding.
     * Same layout as DeviceIdentity.rawPublicKey.
     */
    private fun extractRawPublicKey(spki: ByteArray): ByteArray {
        require(spki.size == 44) { "Unexpected SPKI size: ${spki.size}" }
        return spki.copyOfRange(12, 44)
    }

    fun toB64Url(bytes: ByteArray): String =
        Base64.encodeToString(bytes, Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)
}
