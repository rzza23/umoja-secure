package com.umoja.secure.crypto

import android.content.Context
import android.content.SharedPreferences
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import android.util.Base64
import androidx.annotation.RequiresApi
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.Security
import java.security.Signature
import java.security.spec.NamedParameterSpec
import java.security.spec.PKCS8EncodedKeySpec
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

class DeviceKeyManager(
    private val context: Context,
    private val alias: String = DEFAULT_ALIAS,
) {
    companion object {
        const val DEFAULT_ALIAS = "umoja.device.identity.v1"
        private const val KEYSTORE = "AndroidKeyStore"
        private const val HW_ALGORITHM = "Ed25519"
        private const val SW_PROVIDER = "BC"
        private const val MIN_API_FOR_ED25519 = Build.VERSION_CODES.TIRAMISU
        private const val MIN_API_FOR_GET_SECURITY_LEVEL = Build.VERSION_CODES.S
        private const val AES_WRAP_ALIAS = "umoja.device.identity.wrap.v1"
        private const val PREFS_NAME = "umoja.device.identity"
        private const val PREF_PUBLIC_KEY_SUFFIX = ".sw_public_key"
        private const val PREF_PRIVATE_KEY_SUFFIX = ".sw_private_key_enc"
        private const val GCM_TAG_BITS = 128

        const val SECURITY_LEVEL_UNKNOWN = -1
        const val SECURITY_LEVEL_SOFTWARE = 0
        const val SECURITY_LEVEL_TRUSTED_ENVIRONMENT = 1
        const val SECURITY_LEVEL_STRONGBOX = 2

        init {
            Security.removeProvider(SW_PROVIDER)
            Security.addProvider(BouncyCastleProvider())
        }
    }

    private val keyStore: KeyStore =
        KeyStore.getInstance(KEYSTORE).apply { load(null) }

    private val prefs: SharedPreferences =
        context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

    private val prefPublicKey: String = alias + PREF_PUBLIC_KEY_SUFFIX
    private val prefPrivateKey: String = alias + PREF_PRIVATE_KEY_SUFFIX

    fun hasKey(): Boolean =
        keyStore.containsAlias(alias) || prefs.contains(prefPrivateKey)

    fun ensureKeyPair(): PublicKeyInfo {
        keyStore.getCertificate(alias)?.let { cert ->
            return PublicKeyInfo(cert.publicKey.encoded, currentHardwareSecurityLevel())
        }
        prefs.getString(prefPublicKey, null)?.let { encoded ->
            val spki = Base64.decode(encoded, Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)
            return PublicKeyInfo(spki, SECURITY_LEVEL_SOFTWARE)
        }
        if (Build.VERSION.SDK_INT >= MIN_API_FOR_ED25519) {
            try {
                return generateHardwareKeyPair()
            } catch (_: Exception) {
                // fall through to software path
            }
        }
        return generateSoftwareKeyPair()
    }

    fun publicKey(): ByteArray? {
        keyStore.getCertificate(alias)?.let { return it.publicKey.encoded }
        val encoded = prefs.getString(prefPublicKey, null) ?: return null
        return Base64.decode(encoded, Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)
    }

    fun sign(data: ByteArray): ByteArray {
        if (Build.VERSION.SDK_INT >= MIN_API_FOR_ED25519 && keyStore.containsAlias(alias)) {
            return signWithHardwareKey(data)
        }
        val encryptedB64 = prefs.getString(prefPrivateKey, null)
            ?: throw CryptoException("Device key not found")
        val encrypted = Base64.decode(
            encryptedB64,
            Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING,
        )
        val pkcs8 = decryptWithAesKeystore(encrypted)
        return signWithSoftwareKey(data, pkcs8)
    }

    fun deleteKey() {
        if (keyStore.containsAlias(alias)) keyStore.deleteEntry(alias)
        prefs.edit().remove(prefPublicKey).remove(prefPrivateKey).apply()
    }

    @RequiresApi(Build.VERSION_CODES.TIRAMISU)
    private fun generateHardwareKeyPair(): PublicKeyInfo {
        val generator = KeyPairGenerator.getInstance(HW_ALGORITHM, KEYSTORE)
        val spec = KeyGenParameterSpec.Builder(
            alias,
            KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY,
        )
            .setAlgorithmParameterSpec(NamedParameterSpec.ED25519)
            .setDigests(KeyProperties.DIGEST_NONE)
            .build()
        generator.initialize(spec)
        val keyPair = generator.generateKeyPair()
        return PublicKeyInfo(keyPair.public.encoded, currentHardwareSecurityLevel())
    }

    @RequiresApi(Build.VERSION_CODES.TIRAMISU)
    private fun signWithHardwareKey(data: ByteArray): ByteArray {
        val privateKey = keyStore.getKey(alias, null) as? PrivateKey
            ?: throw CryptoException("Device key not found in Keystore")
        val signature = Signature.getInstance(HW_ALGORITHM)
        signature.initSign(privateKey)
        signature.update(data)
        return signature.sign()
    }

    private fun currentHardwareSecurityLevel(): Int {
        if (Build.VERSION.SDK_INT < MIN_API_FOR_GET_SECURITY_LEVEL) {
            return SECURITY_LEVEL_UNKNOWN
        }
        val privateKey = keyStore.getKey(alias, null) as? PrivateKey
            ?: return SECURITY_LEVEL_UNKNOWN
        return try {
            val factory = KeyFactory.getInstance(privateKey.algorithm, KEYSTORE)
            val info = factory.getKeySpec(privateKey, KeyInfo::class.java) as KeyInfo
            info.securityLevel
        } catch (_: Exception) {
            SECURITY_LEVEL_UNKNOWN
        }
    }

    private fun generateSoftwareKeyPair(): PublicKeyInfo {
        val generator = KeyPairGenerator.getInstance(HW_ALGORITHM, SW_PROVIDER)
        val keyPair = generator.generateKeyPair()
        val publicSpki = keyPair.public.encoded
        val privatePkcs8 = keyPair.private.encoded

        val encrypted = encryptWithAesKeystore(privatePkcs8)

        prefs.edit()
            .putString(
                prefPublicKey,
                Base64.encodeToString(
                    publicSpki,
                    Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING,
                ),
            )
            .putString(
                prefPrivateKey,
                Base64.encodeToString(
                    encrypted,
                    Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING,
                ),
            )
            .apply()

        return PublicKeyInfo(publicSpki, SECURITY_LEVEL_SOFTWARE)
    }

    private fun signWithSoftwareKey(data: ByteArray, pkcs8: ByteArray): ByteArray {
        val factory = KeyFactory.getInstance(HW_ALGORITHM, SW_PROVIDER)
        val privateKey = factory.generatePrivate(PKCS8EncodedKeySpec(pkcs8))
        val signature = Signature.getInstance(HW_ALGORITHM, SW_PROVIDER)
        signature.initSign(privateKey)
        signature.update(data)
        return signature.sign()
    }

    private fun getOrCreateAesKey(): SecretKey {
        if (!keyStore.containsAlias(AES_WRAP_ALIAS)) {
            val generator = KeyGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_AES,
                KEYSTORE,
            )
            val spec = KeyGenParameterSpec.Builder(
                AES_WRAP_ALIAS,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
            )
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .build()
            generator.init(spec)
            generator.generateKey()
        }
        return keyStore.getKey(AES_WRAP_ALIAS, null) as SecretKey
    }

    private fun encryptWithAesKeystore(data: ByteArray): ByteArray {
        val key = getOrCreateAesKey()
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, key)
        val iv = cipher.iv
        val ciphertext = cipher.doFinal(data)
        return byteArrayOf(iv.size.toByte()) + iv + ciphertext
    }

    private fun decryptWithAesKeystore(payload: ByteArray): ByteArray {
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

data class PublicKeyInfo(
    val spkiEncoded: ByteArray,
    val securityLevel: Int,
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is PublicKeyInfo) return false
        return spkiEncoded.contentEquals(other.spkiEncoded) &&
            securityLevel == other.securityLevel
    }

    override fun hashCode(): Int =
        31 * spkiEncoded.contentHashCode() + securityLevel
}
