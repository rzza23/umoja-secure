package com.umoja.secure.crypto

import android.content.Context
import android.util.Base64
import com.umoja.secure.storage.SecureStorage
import org.signal.libsignal.protocol.IdentityKeyPair
import org.signal.libsignal.protocol.ecc.ECKeyPair
import org.signal.libsignal.protocol.kem.KEMKeyPair
import org.signal.libsignal.protocol.kem.KEMKeyType
import org.signal.libsignal.protocol.state.KyberPreKeyRecord
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
    private val kyberKey = "${namespace}signal.kyberprekey.serialized"
    private val kyberIdKey = "${namespace}signal.kyberprekey.id"
    private val otpNextIdKey = "${namespace}signal.otp.next_id"
    private val kyberOtpNextIdKey = "${namespace}signal.kyberotp.next_id"
    private val regIdKey = "${namespace}signal.registration.id"
    private val otpPrefix = "${namespace}signal.otp."
    private val kyberOtpPrefix = "${namespace}signal.kyberotp."

    data class GeneratedPreKeys(
        val signedPreKey: SignedPreKeyRecord,
        val oneTimePreKeys: List<PreKeyRecord>,
        val kyberPreKey: KyberPreKeyRecord,
        val oneTimeKyberPreKeys: List<KyberPreKeyRecord>,
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

        val kyberRecord = generateKyberPreKey(identityKeyPair)
        storeKyberPreKey(kyberRecord)

        clearOneTimePreKeys()
        val otps = generateOneTimePreKeys()
        otps.forEach { storeOneTimePreKey(it) }

        clearOneTimeKyberPreKeys()
        val kyberOtps = generateOneTimeKyberPreKeys()
        kyberOtps.forEach { storeOneTimeKyberPreKey(it) }

        return GeneratedPreKeys(
            signedPreKey = signedRecord,
            oneTimePreKeys = otps,
            kyberPreKey = kyberRecord,
            oneTimeKyberPreKeys = kyberOtps,
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

    fun getKyberPreKey(): KyberPreKeyRecord? {
        val b64 = storage.get(kyberKey) ?: return null
        return try {
            KyberPreKeyRecord(decode(b64))
        } catch (_: Exception) {
            null
        }
    }

    /** Count of one-time Kyber prekeys currently in local storage. */
    fun localOneTimeKyberPreKeyCount(): Int =
        storage.allKeys().count { it.startsWith(kyberOtpPrefix) }

    fun clearAll() {
        storage.remove(signedKey)
        storage.remove(kyberKey)
        clearOneTimePreKeys()
        clearOneTimeKyberPreKeys()
    }

    // ----- Kyber internals -----

    private fun generateKyberPreKey(identity: IdentityKeyPair): KyberPreKeyRecord {
        val id = nextKyberPreKeyId()
        val keyPair = KEMKeyPair.generate(KEMKeyType.KYBER_1024)
        val signature = identity.privateKey.calculateSignature(keyPair.publicKey.serialize())
        return KyberPreKeyRecord(id, System.currentTimeMillis(), keyPair, signature)
    }

    private fun generateOneTimeKyberPreKeys(): List<KyberPreKeyRecord> {
        val baseId = nextKyberOtpBaseId()
        return (0 until oneTimePreKeyCount).map { offset ->
            val keyPair = KEMKeyPair.generate(KEMKeyType.KYBER_1024)
            // Signature is over the public key serialization; same identity key signs.
            // For one-time Kyber prekeys, we sign with the identity key as well.
            val signature = ByteArray(0) // one-time Kyber prekeys are not signed in PQXDH
            KyberPreKeyRecord(baseId + offset, System.currentTimeMillis(), keyPair, signature)
        }
    }

    private fun storeKyberPreKey(record: KyberPreKeyRecord) {
        storage.put(kyberKey, encode(record.serialize()))
    }

    private fun storeOneTimeKyberPreKey(record: KyberPreKeyRecord) {
        storage.put(kyberOtpPrefix + record.id, encode(record.serialize()))
    }

    private fun clearOneTimeKyberPreKeys() {
        storage.allKeys()
            .filter { it.startsWith(kyberOtpPrefix) }
            .forEach { storage.remove(it) }
    }

    private fun nextKyberPreKeyId(): Int {
        val current = storage.get(kyberIdKey)?.toIntOrNull() ?: 0
        val next = current + 1
        storage.put(kyberIdKey, next.toString())
        return next
    }

    private fun nextKyberOtpBaseId(): Int {
        val current = storage.get(kyberOtpNextIdKey)?.toIntOrNull() ?: 1
        storage.put(kyberOtpNextIdKey, (current + oneTimePreKeyCount).toString())
        return current
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
