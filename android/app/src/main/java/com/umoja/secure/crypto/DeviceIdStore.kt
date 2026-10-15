package com.umoja.secure.crypto

import com.umoja.secure.storage.SecureStorage
import java.util.UUID

/**
 * Persists the enrolling device's `device_id`.
 *
 * Per the QR format ruling (handoff 3): device_id is device-generated
 * (UUID v4), stored durably, and never regenerated for the lifetime of
 * the cryptographic entity it identifies. A duress wipe destroys
 * SecureStorage contents, including device_id — that is correct
 * behavior. A wiped device is a new cryptographic entity and generates
 * a fresh device_id on next provisioning-mode entry. Do not carve out
 * an exception to preserve device_id across a wipe.
 *
 * Storage: [SecureStorage] (AES-256-GCM at rest, key in Android
 * Keystore). The value is a public UUID, so encryption is overkill, but
 * SecureStorage is synchronous and already tested. No new dependency,
 * no async API to plumb through Compose. The handoff's "DataStore"
 * wording was descriptive, not prescriptive.
 */
class DeviceIdStore(
    private val storage: SecureStorage,
    private val key: String = DEFAULT_KEY,
) {
    companion object {
        const val DEFAULT_KEY: String = "provisioning.device_id"
    }

    /** Returns the stored device_id, or null if none has been generated. */
    fun get(): String? = storage.get(key)

    /**
     * Returns the stored device_id, generating and persisting a fresh
     * UUID v4 on first call. Repeated calls return the same value.
     */
    fun getOrCreate(): String {
        storage.get(key)?.let { return it }
        val fresh = UUID.randomUUID().toString()
        storage.put(key, fresh)
        return fresh
    }

    /**
     * Removes the stored device_id. Only the duress-wipe flow should
     * call this, and only as part of destroying all SecureStorage
     * contents. Do not call from any other path.
     */
    fun clear() {
        storage.remove(key)
    }
}
