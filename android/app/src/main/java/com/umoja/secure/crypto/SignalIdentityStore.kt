package com.umoja.secure.crypto

import android.content.Context
import android.util.Base64
import android.util.Log
import com.umoja.secure.storage.SecureStorage
import org.signal.libsignal.protocol.IdentityKeyPair

/**
 * Holds the libsignal Curve25519 identity keypair.
 *
 * This is DISTINCT from the device authentication key (Ed25519 in Android
 * Keystore, see DeviceKeyManager). The device auth key proves possession to
 * the backend. This identity key is used inside the Signal Protocol for
 * X3DH and the Double Ratchet.
 *
 * Storage: the serialized libsignal IdentityKeyPair in encrypted preferences.
 * Once loaded, the keypair is cached in memory for the lifetime of the store
 * to avoid repeated native object construction.
 */
class SignalIdentityStore(
    private val storage: SecureStorage,
    private val namespace: String = "",
) {
    constructor(context: Context) : this(SecureStorage(context))

    private val storageKey = "${namespace}signal.identity.serialized"

    @Volatile
    private var cached: IdentityKeyPair? = null

    fun hasIdentity(): Boolean = cached != null || storage.has(storageKey)

    fun getOrGenerate(): IdentityKeyPair {
        cached?.let { return it }
        synchronized(this) {
            cached?.let { return it }
            val existing = storage.get(storageKey)
            if (existing != null) {
                try {
                    val pair = IdentityKeyPair(decode(existing))
                    cached = pair
                    return pair
                } catch (e: Exception) {
                    Log.w(TAG, "stored identity is unreadable; regenerating", e)
                }
            }
            val pair = IdentityKeyPair.generate()
            storage.put(storageKey, encode(pair.serialize()))
            cached = pair
            return pair
        }
    }

    /** Human-readable fingerprint. Returns null only if no identity exists. */
    fun fingerprintOrNull(): String? {
        if (!hasIdentity()) return null
        return try {
            getOrGenerate().publicKey.fingerprint
        } catch (e: Exception) {
            Log.w(TAG, "fingerprint unavailable", e)
            null
        }
    }

    fun clearIdentity() {
        cached = null
        storage.remove(storageKey)
    }

    private fun encode(bytes: ByteArray): String =
        Base64.encodeToString(bytes, Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)

    private fun decode(b64: String): ByteArray =
        Base64.decode(b64, Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)

    companion object {
        private const val TAG = "UmojaSignalId"
    }
}
