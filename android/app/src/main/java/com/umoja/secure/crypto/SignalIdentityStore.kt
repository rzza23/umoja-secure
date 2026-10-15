package com.umoja.secure.crypto

import android.content.Context
import android.util.Base64
import android.util.Log
import com.umoja.secure.storage.SecureStorage
import org.signal.libsignal.protocol.IdentityKey
import org.signal.libsignal.protocol.IdentityKeyPair
import org.signal.libsignal.protocol.ecc.ECPrivateKey

/**
 * Holds the libsignal Curve25519 identity keypair.
 *
 * Storage format note: we persist the IdentityKey (33 bytes) and the
 * ECPrivateKey (32 bytes) SEPARATELY, and reconstruct the keypair via
 * IdentityKeyPair(IdentityKey, ECPrivateKey).
 *
 * We do NOT use IdentityKeyPair.serialize() / IdentityKeyPair(byte[]) because
 * that reconstruction path crashes libsignal's JNI layer on some emulator
 * images. The two-component form uses simpler constructors that don't crash.
 *
 * A process-wide cache avoids reconstructing repeatedly.
 */
class SignalIdentityStore(
    private val storage: SecureStorage,
    private val namespace: String = "",
) {
    constructor(context: Context) : this(SecureStorage(context))

    private val pubKey = "${namespace}signal.identity.pub"
    private val privKey = "${namespace}signal.identity.priv"
    // Legacy key from before we split pub/priv. Only read for migration.
    private val legacyKey = "${namespace}signal.identity.serialized"

    @Volatile
    private var cached: IdentityKeyPair? = null

    fun hasIdentity(): Boolean =
        cached != null ||
            (storage.has(pubKey) && storage.has(privKey)) ||
            storage.has(legacyKey)

    fun getOrGenerate(): IdentityKeyPair {
        cached?.let { return it }

        val nsKey = namespace.ifEmpty { "default" }
        identityCache[nsKey]?.let {
            cached = it
            return it
        }

        synchronized(this) {
            cached?.let { return it }
            identityCache[nsKey]?.let {
                cached = it
                return it
            }

            // Try the new split-component format
            val pubB64 = storage.get(pubKey)
            val privB64 = storage.get(privKey)
            if (pubB64 != null && privB64 != null) {
                try {
                    val pair = IdentityKeyPair(
                        IdentityKey(decode(pubB64)),
                        ECPrivateKey(decode(privB64)),
                    )
                    cached = pair
                    identityCache[nsKey] = pair
                    return pair
                } catch (e: Exception) {
                    Log.w(TAG, "stored identity (split) unreadable; regenerating", e)
                }
            }

            // Fall back to legacy format if present (migration path). Guarded
            // because this constructor is the one that crashes on emulators;
            // we try it in a subprocess-safe way by catching any exception.
            val legacyB64 = storage.get(legacyKey)
            if (legacyB64 != null) {
                try {
                    val pair = IdentityKeyPair(decode(legacyB64))
                    // Immediately rewrite in the safe format and drop the legacy key
                    persist(pair)
                    storage.remove(legacyKey)
                    cached = pair
                    identityCache[nsKey] = pair
                    return pair
                } catch (e: Exception) {
                    Log.w(TAG, "legacy identity unreadable; regenerating", e)
                    storage.remove(legacyKey)
                }
            }

            // Fresh generation
            val fresh = IdentityKeyPair.generate()
            persist(fresh)
            cached = fresh
            identityCache[nsKey] = fresh
            return fresh
        }
    }

    fun fingerprintOrNull(): String? {
        if (!hasIdentity()) return null
        return try {
            getOrGenerate().publicKey.fingerprint
        } catch (e: Exception) {
            Log.w(TAG, "fingerprint unavailable", e)
            null
        }
    }

    /**
     * The messaging identity public key in the format the authorization
     * matrix and the QR payload expect: raw 32-byte Curve25519 DH public
     * key, base64url, no padding (43 chars).
     *
     * libsignal's IdentityKey.serialize() is 33 bytes — a 0x05 type prefix
     * followed by the 32-byte DH public key. The matrix validator requires
     * 32 bytes (43 base64url chars), so the prefix is stripped here. The
     * full 33-byte serialization is preserved everywhere it already exists
     * (persist, PersistentSignalProtocolStore); this accessor only adds a
     * new projection for the matrix/QR use case.
     */
    fun messagingIdentityKeyBase64Url(): String {
        val serialized = getOrGenerate().publicKey.serialize()
        require(serialized.size == 33) {
            "unexpected identity key serialization length: ${serialized.size}"
        }
        require(serialized[0] == 0x05.toByte()) {
            "unexpected identity key type byte: 0x%02x".format(serialized[0])
        }
        val raw = serialized.copyOfRange(1, 33)
        return Base64.encodeToString(
            raw,
            Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING,
        )
    }

    fun clearIdentity() {
        cached = null
        storage.remove(pubKey)
        storage.remove(privKey)
        storage.remove(legacyKey)
        // Also clear the process-wide cache for this namespace
        identityCache.remove(namespace.ifEmpty { "default" })
    }

    private fun persist(pair: IdentityKeyPair) {
        val pubBytes = pair.publicKey.serialize()   // 33 bytes
        val privBytes = pair.privateKey.serialize() // 32 bytes
        storage.put(pubKey, encode(pubBytes))
        storage.put(privKey, encode(privBytes))
    }

    private fun encode(bytes: ByteArray): String =
        Base64.encodeToString(bytes, Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)

    private fun decode(b64: String): ByteArray =
        Base64.decode(b64, Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)

    companion object {
        private const val TAG = "UmojaSignalId"

        /**
         * Process-wide cache, keyed by namespace. Survives across multiple
         * SignalIdentityStore instances but not across process death.
         */
        private val identityCache = java.util.concurrent.ConcurrentHashMap<String, IdentityKeyPair>()
    }
}
