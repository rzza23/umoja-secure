package com.umoja.secure.crypto

import android.util.Base64
import java.security.MessageDigest

/**
 * Utility for converting the raw Ed25519 public key between the X.509 SPKI
 * encoding returned by Android Keystore and the raw 32-byte form expected
 * by the backend.
 */
object DeviceIdentity {

    private const val ED25519_SPKI_SIZE = 44
    private const val ED25519_RAW_KEY_OFFSET = 12
    private const val ED25519_RAW_KEY_SIZE = 32

    /**
     * Extract the raw 32-byte Ed25519 public key from the X.509 SPKI
     * encoding returned by Android Keystore.
     *
     * Layout:
     *   30 2a              SEQUENCE (42 bytes)
     *     30 05            SEQUENCE (5 bytes)
     *       06 03 2b 65 70   OID 1.3.101.112 (Ed25519)
     *     03 21 00         BIT STRING (33 bytes, 0 unused bits)
     *       <32 raw key bytes>
     *
     * Total: 44 bytes. The raw key begins at offset 12.
     */
    fun rawPublicKey(spkiEncoded: ByteArray): ByteArray {
        require(spkiEncoded.size == ED25519_SPKI_SIZE) {
            "Expected $ED25519_SPKI_SIZE-byte Ed25519 SPKI, got ${spkiEncoded.size}"
        }
        return spkiEncoded.copyOfRange(
            ED25519_RAW_KEY_OFFSET,
            ED25519_RAW_KEY_OFFSET + ED25519_RAW_KEY_SIZE,
        )
    }

    /**
     * Base64url (no padding) encoding of the raw public key.
     * This is the exact format the backend expects for `device_public_key`.
     * Output is always 43 characters.
     */
    fun encodePublicKey(spkiEncoded: ByteArray): String {
        val raw = rawPublicKey(spkiEncoded)
        return Base64.encodeToString(
            raw,
            Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING,
        )
    }

    /**
     * Local fingerprint for display only. Not the backend `device_id`
     * (which is a UUID assigned at enrollment). Not sent to the server.
     * Returns 16 hex characters (first 8 bytes of SHA-256).
     */
    fun fingerprint(spkiEncoded: ByteArray): String {
        val raw = rawPublicKey(spkiEncoded)
        val digest = MessageDigest.getInstance("SHA-256").digest(raw)
        return digest.copyOfRange(0, 8).joinToString("") { "%02x".format(it) }
    }
}
