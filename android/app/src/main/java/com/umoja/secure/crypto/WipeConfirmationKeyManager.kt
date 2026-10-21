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
 * **Re-scope (2026-10-20).** GrapheneOS's OS-level Duress feature is
 * the wipe mechanism. It fires at the system credential-entry layer,
 * destroys the hardware-keystore keys that derive the
 * disk-encryption key, wipes all user profiles and the eSIM, and
 * powers off — before any app code can run. Under this mechanism no
 * wipe-confirmation notification can be sent: the OS has already
 * destroyed the process that would sign it. The keypair is retained
 * for protocol stability — `pub_wipe_confirmation_key` remains in
 * the enrollment QR payload and the matrix schema — and [sign] is
 * reserved for a future wipe-confirmation protocol that may not
 * land on GrapheneOS. See registry §B TASK-P1-021b (re-scoped
 * 2026-10-20).
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

    /**
     * Signs [data] with the wipe-confirmation private key. Returns
     * the raw 64-byte Ed25519 signature.
     *
     * **Reserved for future use (2026-10-20).** Under the GrapheneOS
     * Duress mechanism, the OS destroys the app process before any
     * code can run — no signature is ever produced in production.
     * Retained for a possible future wipe-confirmation protocol; see
     * the class KDoc.
     */
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
     * **Implementation deferred (re-scope 2026-10-20).** TASK-P1-021b
     * was re-scoped — GrapheneOS Duress destroys the OS rather than
     * calling this method; see the class KDoc. The §3.4 single-use
     * contract above remains valid if an app-level wipe flow is ever
     * added; under the current design this method is unused in
     * production. Retained as the defined entry point for that
     * future flow.
     */
    fun deleteKey() {
        delegate.deleteKey()
    }
}
