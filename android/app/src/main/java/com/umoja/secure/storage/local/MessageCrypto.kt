package com.umoja.secure.storage.local

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.nio.ByteBuffer
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Encrypts the plaintext column of the messages table.
 *
 * Key: AES-256-GCM in Android Keystore under a fixed alias. The key is
 * non-exportable. If the Keystore key is lost (app reinstall, Keystore
 * reset), existing messages become unreadable and the DB must be wiped.
 * That is acceptable: the DB is a cache of messages that can be re-fetched
 * from the sender if needed.
 *
 * Layout per value: [12-byte nonce][ciphertext || 16-byte GCM tag]
 */
class MessageCrypto {

    companion object {
        private const val KEYSTORE = "AndroidKeyStore"
        private const val KEY_ALIAS = "umoja.local.db.plaintext.v1"
        private const val GCM_TAG_BITS = 128
        private const val NONCE_BYTES = 12
    }

    private val keyStore: KeyStore =
        KeyStore.getInstance(KEYSTORE).apply { load(null) }

    fun encrypt(plaintext: String): ByteArray {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, getOrCreateKey())
        val nonce = cipher.iv
        val ciphertext = cipher.doFinal(plaintext.toByteArray(Charsets.UTF_8))
        return ByteBuffer.allocate(nonce.size + ciphertext.size)
            .put(nonce)
            .put(ciphertext)
            .array()
    }

    fun decrypt(payload: ByteArray): String {
        require(payload.size > NONCE_BYTES) { "ciphertext too short" }
        val nonce = payload.copyOfRange(0, NONCE_BYTES)
        val ciphertext = payload.copyOfRange(NONCE_BYTES, payload.size)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(
            Cipher.DECRYPT_MODE,
            getOrCreateKey(),
            GCMParameterSpec(GCM_TAG_BITS, nonce),
        )
        val plaintext = cipher.doFinal(ciphertext)
        return String(plaintext, Charsets.UTF_8)
    }

    private fun getOrCreateKey(): SecretKey {
        if (!keyStore.containsAlias(KEY_ALIAS)) {
            val generator = KeyGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_AES,
                KEYSTORE,
            )
            val spec = KeyGenParameterSpec.Builder(
                KEY_ALIAS,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
            )
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .setRandomizedEncryptionRequired(true)
                .build()
            generator.init(spec)
            generator.generateKey()
        }
        return keyStore.getKey(KEY_ALIAS, null) as SecretKey
    }
}
