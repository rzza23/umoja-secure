package com.umoja.secure.crypto

import android.content.Context

/**
 * Manages the device wipe-confirmation keypair.
 *
 * The wipe-confirmation key is distinct from the device authentication key
 * (see DeviceKeyManager). It is used only in the duress-wipe flow (Build
 * Master 3.4): after the app destroys messaging keys and session material,
 * it uses this key to sign a single fire-and-forget notification to the
 * backend that the wipe completed. The backend verifies the signature
 * against the public half registered at provisioning time.
 *
 * That full flow is TASK-P1-021b. This manager's responsibility in
 * TASK-P1-019 is only to generate the keypair and expose the public half,
 * so the enrolling device can publish it in the provisioning QR.
 *
 * Design: composition, not duplication. All key-generation and storage
 * logic lives in DeviceKeyManager. Passing a distinct alias gives us a
 * distinct Android Keystore entry and a distinct prefs slot for free.
 *
 * Shared AES wrapping key: DeviceKeyManager uses a single AES-256-GCM
 * Keystore key to wrap software-path Ed25519 private keys. The wipe key
 * therefore uses the same AES wrapper as the device auth key. Both private
 * keys are device-local with the same threat model (extraction requires
 * Keystore compromise), so the sharing is acceptable. A future improvement
 * could introduce a per-alias AES wrapper if stricter separation is ever
 * required.
 *
 * Public surface is intentionally minimal: [hasKey], [ensureKeyPair],
 * [publicKeyBase64Url], [sign], [deleteKey]. Raw-bytes access is not
 * exposed; callers that need the public key want the base64url form used
 * by the provisioning QR payload.
 */
class WipeConfirmationKeyManager(context: Context) {

    companion object {
        /**
         * Keystore alias for the wipe-confirmation keypair. Distinct from
         * DeviceKeyManager.DEFAULT_ALIAS so the two keypairs are independent.
         */
        const val ALIAS = "umoja.wipe.confirmation.v1"
    }

    private val delegate = DeviceKeyManager(context = context, alias = ALIAS)

    fun hasKey(): Boolean = delegate.hasKey()

    fun ensureKeyPair(): PublicKeyInfo = delegate.ensureKeyPair()

    /**
     * Base64url (no padding) of the raw 32-byte Ed25519 public key.
     * Output is always 43 characters. Returns null if no key has been
     * generated yet (callers should call [ensureKeyPair] first).
     */
    fun publicKeyBase64Url(): String? {
        val spki = delegate.publicKey() ?: return null
        return DeviceIdentity.encodePublicKey(spki)
    }

    fun sign(data: ByteArray): ByteArray = delegate.sign(data)

    /**
     * Destroys the wipe-confirmation keypair from Android Keystore and
     * clears the public key from prefs.
     *
     * Contract (Build Master 3.4): this key is single-use per device
     * lifetime. It is destroyed by the duress-wipe flow after the wipe
     * notification has been signed and sent, best-effort. Do not call
     * this from any other path. In particular, do not treat it as a
     * reset-and-regenerate: a device that has been provisioned has
     * exactly one wipe-confirmation key, and the backend matrix binds
     * the public half by version. Regenerating would silently
     * invalidate the binding.
     *
     * Implementation is provided by TASK-P1-021b; this manager only
     * exposes the method so the wipe flow has a defined entry point.
     */
    fun deleteKey() {
        delegate.deleteKey()
    }
}
