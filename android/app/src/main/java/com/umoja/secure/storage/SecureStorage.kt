package com.umoja.secure.storage

import android.content.Context
import android.content.SharedPreferences
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Encrypted key-value storage for sensitive app data.
 *
 * Values are AES-256-GCM encrypted with a key held in Android Keystore.
 * The AES key itself never leaves Keystore. Each value has a fresh random IV.
 * The IV length byte and IV are prepended to the ciphertext.
 *
 * Storage layout per value: [IV length (1 byte)][IV][ciphertext]
 *
 * Used for the session token, device_id, org_id, role — anything that must
 * persist across app restarts and should not be readable from raw storage.
 */
class SecureStorage(
    context: Context,
    prefsName: String = DEFAULT_PREFS,
    private val keyAlias: String = DEFAULT_KEY_ALIAS,
) : KeyValueStore {
    companion object {
        const val DEFAULT_PREFS = "umoja.secure.storage"
        const val DEFAULT_KEY_ALIAS = "umoja.secure.storage.aes.v1"
        private const val KEYSTORE = "AndroidKeyStore"
        private const val GCM_TAG_BITS = 128
    }

    private val prefs: SharedPreferences =
        context.getSharedPreferences(prefsName, Context.MODE_PRIVATE)

    private val keyStore: KeyStore =
        KeyStore.getInstance(KEYSTORE).apply { load(null) }

    override fun put(key: String, value: String) {
        val encrypted = encrypt(value.toByteArray(Charsets.UTF_8))
        val encoded = Base64.encodeToString(
            encrypted,
            Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING,
        )
        prefs.edit().putString(key, encoded).apply()
    }

    override fun get(key: String): String? {
        val encoded = prefs.getString(key, null) ?: return null
        return try {
            val payload = Base64.decode(
                encoded,
                Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING,
            )
            String(decrypt(payload), Charsets.UTF_8)
        } catch (_: Exception) {
            // Corrupted or Keystore key invalidated — return null rather than crash
            null
        }
    }

    override fun remove(key: String) {
        prefs.edit().remove(key).apply()
    }

    fun clear() {
        prefs.edit().clear().apply()
    }

    /** Returns the set of all keys currently stored. Values are encrypted. */
    fun allKeys(): Set<String> = prefs.all.keys.toSet()

    override fun has(key: String): Boolean = prefs.contains(key)

    private fun getOrCreateAesKey(): SecretKey {
        if (!keyStore.containsAlias(keyAlias)) {
            val generator = KeyGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_AES,
                KEYSTORE,
            )
            val spec = KeyGenParameterSpec.Builder(
                keyAlias,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
            )
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .build()
            generator.init(spec)
            generator.generateKey()
        }
        return keyStore.getKey(keyAlias, null) as SecretKey
    }

    private fun encrypt(plaintext: ByteArray): ByteArray {
        val key = getOrCreateAesKey()
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, key)
        val iv = cipher.iv
        val ciphertext = cipher.doFinal(plaintext)
        return byteArrayOf(iv.size.toByte()) + iv + ciphertext
    }

    private fun decrypt(payload: ByteArray): ByteArray {
        require(payload.isNotEmpty()) { "Empty ciphertext" }
        val key = getOrCreateAesKey()
        val ivLen = payload[0].toInt()
        require(ivLen in 1..32) { "Invalid IV length" }
        require(payload.size > 1 + ivLen) { "Truncated ciphertext" }
        val iv = payload.copyOfRange(1, 1 + ivLen)
        val ciphertext = payload.copyOfRange(1 + ivLen, payload.size)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(GCM_TAG_BITS, iv))
        return cipher.doFinal(ciphertext)
    }
}
