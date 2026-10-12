package com.umoja.secure.crypto

import android.content.Context
import android.util.Base64
import com.umoja.secure.storage.SecureStorage
import org.signal.libsignal.protocol.IdentityKeyPair
import org.signal.libsignal.protocol.ecc.ECKeyPair
import org.signal.libsignal.protocol.state.PreKeyRecord
import org.signal.libsignal.protocol.state.SignedPreKeyRecord

/**
 * Generates and stores libsignal signed prekeys and one-time prekeys.
 *
 * All private material stays in encrypted storage. Only public keys and
 * signatures are ever uploaded to the backend.
 *
 * Namespaced for test isolation.
 */
class SignalPreKeyStore(
    private val storage: SecureStorage,
    private val namespace: String = "",
    private val oneTimePreKeyCount: Int = DEFAULT_oneTimePreKeyCount,
) {
    constructor(context: Context) : this(SecureStorage(context))

    companion object {
        const val DEFAULT_oneTimePreKeyCount = 100
        private const val REGISTRATION_ID_MAX = 16383
    }

    private val signedKey = "${namespace}signal.signedprekey.serialized"
    private val signedIdKey = "${namespace}signal.signedprekey.id"
    private val otpNextIdKey = "${namespace}signal.otp.next_id"
    private val regIdKey = "${namespace}signal.registration.id"
    private val otpPrefix = "${namespace}signal.otp."

    data class GeneratedPreKeys(
        val signedPreKey: SignedPreKeyRecord,
        val oneTimePreKeys: List<PreKeyRecord>,
        val registrationId: Int,
    )

    /**
     * Generate fresh prekey material. Overwrites any existing signed prekey.
     * Removes all existing one-time prekeys before generating the new batch.
     * Returns the newly generated records so the caller can upload them.
     */
    fun generateFresh(identityKeyPair: IdentityKeyPair): GeneratedPreKeys {
        val signedRecord = generateSignedPreKey(identityKeyPair)
        storeSignedPreKey(signedRecord)

        clearOneTimePreKeys()
        val otps = generateOneTimePreKeys()
        otps.forEach { storeOneTimePreKey(it) }

        return GeneratedPreKeys(
            signedPreKey = signedRecord,
            oneTimePreKeys = otps,
            registrationId = getOrCreateRegistrationId(),
        )
    }

    fun getSignedPreKey(): SignedPreKeyRecord? {
        val b64 = storage.get(signedKey) ?: return null
        return try {
            SignedPreKeyRecord(decode(b64))
        } catch (_: Exception) {
            null
        }
    }

    fun getRegistrationId(): Int? = storage.get(regIdKey)?.toIntOrNull()

    /** Count of one-time prekeys currently in local storage. */
    fun localOneTimePreKeyCount(): Int =
        storage.allKeys().count { it.startsWith(otpPrefix) }

    fun clearAll() {
        storage.remove(signedKey)
        clearOneTimePreKeys()
    }

    // ----- internal -----

    private fun generateSignedPreKey(identity: IdentityKeyPair): SignedPreKeyRecord {
        val id = nextSignedPreKeyId()
        val keyPair: ECKeyPair = ECKeyPair.generate()
        // Sign the 33-byte public key serialization (type byte + 32 raw bytes),
        // matching what X3DH verifies.
        val signature = identity.privateKey.calculateSignature(keyPair.publicKey.serialize())
        return SignedPreKeyRecord(id, System.currentTimeMillis(), keyPair, signature)
    }

    private fun generateOneTimePreKeys(): List<PreKeyRecord> {
        val baseId = nextOtpBaseId()
        return (0 until oneTimePreKeyCount).map { offset ->
            PreKeyRecord(baseId + offset, ECKeyPair.generate())
        }
    }

    private fun storeSignedPreKey(record: SignedPreKeyRecord) {
        storage.put(signedKey, encode(record.serialize()))
    }

    private fun storeOneTimePreKey(record: PreKeyRecord) {
        storage.put(otpPrefix + record.id, encode(record.serialize()))
    }

    private fun clearOneTimePreKeys() {
        storage.allKeys()
            .filter { it.startsWith(otpPrefix) }
            .forEach { storage.remove(it) }
    }

    private fun nextSignedPreKeyId(): Int {
        val current = storage.get(signedIdKey)?.toIntOrNull() ?: 0
        val next = current + 1
        storage.put(signedIdKey, next.toString())
        return next
    }

    private fun nextOtpBaseId(): Int {
        val current = storage.get(otpNextIdKey)?.toIntOrNull() ?: 1
        storage.put(otpNextIdKey, (current + oneTimePreKeyCount).toString())
        return current
    }

    private fun getOrCreateRegistrationId(): Int {
        storage.get(regIdKey)?.toIntOrNull()?.let { return it }
        val fresh = (1..REGISTRATION_ID_MAX).random()
        storage.put(regIdKey, fresh.toString())
        return fresh
    }

    private fun encode(bytes: ByteArray): String =
        Base64.encodeToString(bytes, Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)

    private fun decode(b64: String): ByteArray =
        Base64.decode(b64, Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)
}
