package com.umoja.secure.crypto

import android.content.Context
import android.util.Base64
import android.util.Log
import com.umoja.secure.storage.SecureStorage
import org.signal.libsignal.protocol.IdentityKey
import org.signal.libsignal.protocol.IdentityKeyPair
import org.signal.libsignal.protocol.InvalidKeyIdException
import org.signal.libsignal.protocol.ReusedBaseKeyException
import org.signal.libsignal.protocol.SignalProtocolAddress
import org.signal.libsignal.protocol.ecc.ECPublicKey
import org.signal.libsignal.protocol.groups.state.SenderKeyRecord
import org.signal.libsignal.protocol.groups.state.SenderKeyStore
import org.signal.libsignal.protocol.kem.KEMKeyPair
import org.signal.libsignal.protocol.kem.KEMKeyType
import org.signal.libsignal.protocol.state.IdentityKeyStore
import org.signal.libsignal.protocol.state.KyberPreKeyRecord
import org.signal.libsignal.protocol.state.KyberPreKeyStore
import org.signal.libsignal.protocol.state.PreKeyRecord
import org.signal.libsignal.protocol.state.PreKeyStore
import org.signal.libsignal.protocol.state.SessionRecord
import org.signal.libsignal.protocol.state.SessionStore
import org.signal.libsignal.protocol.state.SignalProtocolStore
import org.signal.libsignal.protocol.state.SignedPreKeyRecord
import org.signal.libsignal.protocol.state.SignedPreKeyStore
import java.util.UUID

/**
 * Persistent implementation of libsignal\'s SignalProtocolStore.
 *
 * All state lives in SecureStorage (AES-GCM encrypted, key in Android Keystore).
 * Composed with SignalIdentityStore for the local identity keypair.
 *
 * Namespaced so tests can operate on isolated state without touching the
 * app\'s real session data.
 *
 * Groups (SenderKeyStore) are not implemented in Phase 1.
 */
class PersistentSignalProtocolStore(
    private val storage: SecureStorage,
    private val identityStore: SignalIdentityStore,
    private val namespace: String = "",
) : SignalProtocolStore {

    constructor(context: Context) : this(
        SecureStorage(context),
        SignalIdentityStore(context),
    )

    companion object {
        private const val TAG = "UmojaSignalStore"
    }

    // ============================================================
    // IdentityKeyStore (own identity delegates to SignalIdentityStore)
    // ============================================================

    override fun getIdentityKeyPair(): IdentityKeyPair = identityStore.getOrGenerate()

    override fun getLocalRegistrationId(): Int {
        val key = "${namespace}registration.id"
        val existing = storage.get(key)?.toIntOrNull()
        if (existing != null) return existing
        val fresh = (1..16383).random()
        storage.put(key, fresh.toString())
        return fresh
    }

    override fun saveIdentity(
        address: SignalProtocolAddress,
        identityKey: IdentityKey,
    ): IdentityKeyStore.IdentityChange {
        val key = peerIdentityKey(address)
        val existing = storage.get(key)
        val incoming = encode(identityKey.serialize())
        if (existing == null) {
            storage.put(key, incoming)
            return IdentityKeyStore.IdentityChange.NEW_OR_UNCHANGED
        }
        if (existing == incoming) {
            return IdentityKeyStore.IdentityChange.NEW_OR_UNCHANGED
        }
        storage.put(key, incoming)
        Log.w(TAG, "peer identity changed for $address")
        return IdentityKeyStore.IdentityChange.REPLACED_EXISTING
    }

    override fun isTrustedIdentity(
        address: SignalProtocolAddress,
        identityKey: IdentityKey,
        direction: IdentityKeyStore.Direction,
    ): Boolean {
        val existing = storage.get(peerIdentityKey(address)) ?: return true
        return existing == encode(identityKey.serialize())
    }

    override fun getIdentity(address: SignalProtocolAddress): IdentityKey? {
        val stored = storage.get(peerIdentityKey(address)) ?: return null
        return try {
            IdentityKey(decode(stored))
        } catch (e: Exception) {
            Log.w(TAG, "unreadable peer identity for $address", e)
            null
        }
    }

    // ============================================================
    // PreKeyStore
    // ============================================================

    override fun loadPreKey(preKeyId: Int): PreKeyRecord {
        val stored = storage.get(preKeyKey(preKeyId))
            ?: throw InvalidKeyIdException("no prekey $preKeyId")
        return try {
            PreKeyRecord(decode(stored))
        } catch (e: Exception) {
            throw InvalidKeyIdException("corrupt prekey $preKeyId")
        }
    }

    override fun storePreKey(preKeyId: Int, record: PreKeyRecord) {
        storage.put(preKeyKey(preKeyId), encode(record.serialize()))
    }

    override fun containsPreKey(preKeyId: Int): Boolean =
        storage.has(preKeyKey(preKeyId))

    override fun removePreKey(preKeyId: Int) {
        storage.remove(preKeyKey(preKeyId))
    }

    // ============================================================
    // SignedPreKeyStore
    // ============================================================

    override fun loadSignedPreKey(signedPreKeyId: Int): SignedPreKeyRecord {
        val stored = storage.get(signedKey(signedPreKeyId))
            ?: throw InvalidKeyIdException("no signed prekey $signedPreKeyId")
        return try {
            SignedPreKeyRecord(decode(stored))
        } catch (e: Exception) {
            throw InvalidKeyIdException("corrupt signed prekey $signedPreKeyId")
        }
    }

    override fun loadSignedPreKeys(): List<SignedPreKeyRecord> {
        return storage.allKeys()
            .filter { it.startsWith(signedPrefix) }
            .mapNotNull { k ->
                val b64 = storage.get(k) ?: return@mapNotNull null
                try {
                    SignedPreKeyRecord(decode(b64))
                } catch (_: Exception) {
                    null
                }
            }
    }

    override fun storeSignedPreKey(signedPreKeyId: Int, record: SignedPreKeyRecord) {
        storage.put(signedKey(signedPreKeyId), encode(record.serialize()))
    }

    override fun containsSignedPreKey(signedPreKeyId: Int): Boolean =
        storage.has(signedKey(signedPreKeyId))

    override fun removeSignedPreKey(signedPreKeyId: Int) {
        storage.remove(signedKey(signedPreKeyId))
    }

    // ============================================================
    // KyberPreKeyStore
    // ============================================================

    override fun loadKyberPreKey(kyberPreKeyId: Int): KyberPreKeyRecord {
        val stored = storage.get(kyberKey(kyberPreKeyId))
            ?: throw InvalidKeyIdException("no kyber prekey $kyberPreKeyId")
        return try {
            KyberPreKeyRecord(decode(stored))
        } catch (e: Exception) {
            throw InvalidKeyIdException("corrupt kyber prekey $kyberPreKeyId")
        }
    }

    override fun loadKyberPreKeys(): List<KyberPreKeyRecord> {
        return storage.allKeys()
            .filter { it.startsWith(kyberPrefix) && !it.startsWith(kyberUsedPrefix) }
            .mapNotNull { k ->
                val b64 = storage.get(k) ?: return@mapNotNull null
                try {
                    KyberPreKeyRecord(decode(b64))
                } catch (_: Exception) {
                    null
                }
            }
    }

    override fun storeKyberPreKey(kyberPreKeyId: Int, record: KyberPreKeyRecord) {
        storage.put(kyberKey(kyberPreKeyId), encode(record.serialize()))
    }

    override fun containsKyberPreKey(kyberPreKeyId: Int): Boolean =
        storage.has(kyberKey(kyberPreKeyId))

    override fun markKyberPreKeyUsed(
        kyberPreKeyId: Int,
        deviceId: Int,
        baseKey: ECPublicKey,
    ) {
        val flag = storage.get(kyberUsedKey(kyberPreKeyId))
        if (flag != null) {
            throw ReusedBaseKeyException("kyber prekey $kyberPreKeyId already used")
        }
        storage.put(kyberUsedKey(kyberPreKeyId), "1")
        // Remove the prekey material once used, keeping only the flag.
        storage.remove(kyberKey(kyberPreKeyId))
    }

    // ============================================================
    // SessionStore
    // ============================================================

    override fun loadSession(address: SignalProtocolAddress): SessionRecord {
        val stored = storage.get(sessionKey(address)) ?: return SessionRecord()
        return try {
            SessionRecord(decode(stored))
        } catch (e: Exception) {
            Log.w(TAG, "corrupt session for $address; returning fresh", e)
            SessionRecord()
        }
    }

    override fun loadExistingSessions(
        addresses: List<SignalProtocolAddress>,
    ): List<SessionRecord> {
        return addresses.map { loadSession(it) }
    }

    override fun getSubDeviceSessions(name: String): List<Int> {
        val prefix = "${namespace}session.$name."
        return storage.allKeys()
            .filter { it.startsWith(prefix) }
            .mapNotNull { it.removePrefix(prefix).toIntOrNull() }
    }

    override fun storeSession(address: SignalProtocolAddress, record: SessionRecord) {
        storage.put(sessionKey(address), encode(record.serialize()))
    }

    override fun containsSession(address: SignalProtocolAddress): Boolean =
        storage.has(sessionKey(address))

    override fun deleteSession(address: SignalProtocolAddress) {
        storage.remove(sessionKey(address))
    }

    override fun deleteAllSessions(name: String) {
        val prefix = "${namespace}session.$name."
        storage.allKeys()
            .filter { it.startsWith(prefix) }
            .forEach { storage.remove(it) }
    }

    // ============================================================
    // SenderKeyStore (groups) - not implemented in Phase 1
    // ============================================================

    override fun storeSenderKey(
        sender: SignalProtocolAddress,
        distributionId: UUID,
        record: SenderKeyRecord,
    ) {
        throw UnsupportedOperationException("group messaging not implemented in Phase 1")
    }

    override fun loadSenderKey(
        sender: SignalProtocolAddress,
        distributionId: UUID,
    ): SenderKeyRecord? = null

    // ============================================================
    // Internal helpers
    // ============================================================

    private val peerIdentityPrefix = "${namespace}peer.identity."
    private val signedPrefix = "${namespace}signed."
    private val kyberPrefix = "${namespace}kyber."
    private val kyberUsedPrefix = "${namespace}kyber.used."
    private val prekeyPrefix = "${namespace}prekey."
    private val sessionPrefix = "${namespace}session."

    private fun peerIdentityKey(address: SignalProtocolAddress): String =
        "$peerIdentityPrefix${address.name}.${address.deviceId}"

    private fun signedKey(id: Int): String = "$signedPrefix$id"

    private fun kyberKey(id: Int): String = "$kyberPrefix$id"

    private fun kyberUsedKey(id: Int): String = "$kyberUsedPrefix$id"

    private fun preKeyKey(id: Int): String = "$prekeyPrefix$id"

    private fun sessionKey(address: SignalProtocolAddress): String =
        "$sessionPrefix${address.name}.${address.deviceId}"

    private fun encode(bytes: ByteArray): String =
        Base64.encodeToString(bytes, Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)

    private fun decode(b64: String): ByteArray =
        Base64.decode(b64, Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)

    // ============================================================
    // Convenience: generate and store a full prekey batch locally.
    // Used by the sending side to seed its own bundle and by tests.
    // ============================================================

    /**
     * Generate signed prekey + N one-time EC prekeys + Kyber prekey + N
     * one-time Kyber prekeys, all signed with the local identity where
     * applicable, and store them in this store.
     *
     * Returns the bundle metadata (ids and public halves) for upload.
     */
    fun generateAndStorePreKeys(
        oneTimeEcCount: Int,
        oneTimeKyberCount: Int,
    ): GeneratedBundle {
        val identity = getIdentityKeyPair()

        // Signed prekey
        val spkId = 1
        val spkKeyPair = org.signal.libsignal.protocol.ecc.ECKeyPair.generate()
        val spkSignature = identity.privateKey.calculateSignature(spkKeyPair.publicKey.serialize())
        val spk = SignedPreKeyRecord(spkId, System.currentTimeMillis(), spkKeyPair, spkSignature)
        storeSignedPreKey(spkId, spk)

        // Kyber prekey
        val kyberId = 1
        val kyberKeyPair = KEMKeyPair.generate(KEMKeyType.KYBER_1024)
        val kyberSignature = identity.privateKey.calculateSignature(kyberKeyPair.publicKey.serialize())
        val kyber = KyberPreKeyRecord(kyberId, System.currentTimeMillis(), kyberKeyPair, kyberSignature)
        storeKyberPreKey(kyberId, kyber)

        // One-time EC prekeys
        val otpEc = mutableListOf<PreKeyRecord>()
        for (i in 1..oneTimeEcCount) {
            val kp = org.signal.libsignal.protocol.ecc.ECKeyPair.generate()
            val rec = PreKeyRecord(i, kp)
            storePreKey(i, rec)
            otpEc.add(rec)
        }

        // One-time Kyber prekeys
        val otpKyber = mutableListOf<KyberPreKeyRecord>()
        for (i in 2..(oneTimeKyberCount + 1)) {
            val kp = KEMKeyPair.generate(KEMKeyType.KYBER_1024)
            val rec = KyberPreKeyRecord(i, System.currentTimeMillis(), kp, ByteArray(0))
            storeKyberPreKey(i, rec)
            otpKyber.add(rec)
        }

        return GeneratedBundle(
            registrationId = getLocalRegistrationId(),
            identityKey = identity.publicKey,
            signedPreKeyId = spkId,
            signedPreKey = spk,
            kyberPreKeyId = kyberId,
            kyberPreKey = kyber,
            oneTimeEcPreKeys = otpEc,
            oneTimeKyberPreKeys = otpKyber,
        )
    }

    data class GeneratedBundle(
        val registrationId: Int,
        val identityKey: IdentityKey,
        val signedPreKeyId: Int,
        val signedPreKey: SignedPreKeyRecord,
        val kyberPreKeyId: Int,
        val kyberPreKey: KyberPreKeyRecord,
        val oneTimeEcPreKeys: List<PreKeyRecord>,
        val oneTimeKyberPreKeys: List<KyberPreKeyRecord>,
    )
}
