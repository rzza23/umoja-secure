package com.umoja.secure.signing

import com.umoja.secure.crypto.PublicKeyInfo
import com.umoja.secure.crypto.SignedMatrix
import com.umoja.secure.crypto.jcsCanonicalizeString
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.withContext
import java.security.MessageDigest
import java.util.Base64

/**
 * State and logic for the offline signing app (TASK-P1-033c).
 *
 * Two modes, entered explicitly:
 *
 *   - CEREMONY: first-time setup. Generates the provisioning key via
 *     [ensureKeyPairFn] and exposes the public key so the ceremony
 *     lead can record it (KEY-CUSTODY §2). Refuses to run if the key
 *     already exists -- regeneration is a ceremony decision made
 *     through KEY-CUSTODY §2's documented recovery procedure, not a
 *     button in the app.
 *
 *   - OPERATING: the actual signing. Requires the key to exist
 *     (fail-closed per KEY-CUSTODY §2 and decision 1: no silent
 *     generation). Accepts a canonical matrix string (from a QR scan
 *     of the admin app's output), re-canonicalizes it to confirm it
 *     is JCS-canonical, computes its SHA-256 digest, signs the digest
 *     via [signFn] (per Build Master §3.8 -- Ed25519 over the 32-byte
 *     digest, not the canonical bytes directly).
 *
 * **Lambda injection over interface extraction.** Same pattern as
 * AdminScreenState (Z-2) and SessionStateManager (R-2). Production
 * wires:
 *   - hasKeyFn          -> DeviceKeyManager(context, PROVISIONING_ALIAS)::hasKey
 *   - ensureKeyPairFn   -> DeviceKeyManager(context, PROVISIONING_ALIAS)::ensureKeyPair
 *   - publicKeyFn       -> DeviceKeyManager(context, PROVISIONING_ALIAS)::publicKey
 *   - signFn            -> DeviceKeyManager(context, PROVISIONING_ALIAS)::sign
 *
 * Every one of those is a blocking Keystore call. The suspend methods
 * wrap with `withContext(Dispatchers.IO)` so callers can launch from a
 * Compose scope without blocking Main.
 *
 * **Prehash protocol (§3.8).** [sign] computes SHA-256(canonical bytes)
 * and passes the 32-byte digest to [signFn]. The [DeviceKeyManager]'s
 * sign does NOT rehash -- it produces Ed25519(digest) directly. Same
 * primitive the backend's verifyMatrix uses on the read path.
 *
 * Task: TASK-P1-033c
 * Depends: TASK-P1-029 (ProvisioningKeys split), TASK-P1-033a (backend
 *          route), TASK-P1-033b (admin-side push)
 * Design: docs/ops/KEY-CUSTODY.md §2, §4
 * Protocol: UMOJA-SECURE-BUILD-MASTER.md §3.8
 */
enum class SigningMode {
    CEREMONY,
    OPERATING,
}

class SigningState(
    private val hasKeyFn: () -> Boolean,
    private val ensureKeyPairFn: () -> PublicKeyInfo,
    private val publicKeyFn: () -> ByteArray?,
    private val signFn: (ByteArray) -> ByteArray,
) {
    private val _mode = MutableStateFlow<SigningMode?>(null)
    val mode: StateFlow<SigningMode?> = _mode.asStateFlow()

    private val _hasKey = MutableStateFlow(false)
    val hasKey: StateFlow<Boolean> = _hasKey.asStateFlow()

    private val _publicKeyB64u = MutableStateFlow<String?>(null)
    val publicKeyB64u: StateFlow<String?> = _publicKeyB64u.asStateFlow()

    private val _canonicalUtf8 = MutableStateFlow<String?>(null)
    val canonicalUtf8: StateFlow<String?> = _canonicalUtf8.asStateFlow()

    private val _canonicalHashB64u = MutableStateFlow<String?>(null)
    val canonicalHashB64u: StateFlow<String?> = _canonicalHashB64u.asStateFlow()

    private val _signatureB64u = MutableStateFlow<String?>(null)
    val signatureB64u: StateFlow<String?> = _signatureB64u.asStateFlow()

    private val _error = MutableStateFlow<String?>(null)
    val error: StateFlow<String?> = _error.asStateFlow()

    private val _statusMessage = MutableStateFlow<String?>(null)
    val statusMessage: StateFlow<String?> = _statusMessage.asStateFlow()

    suspend fun enterCeremonyMode() {
        _error.value = null
        _statusMessage.value = null
        if (hasKeyFn()) {
            _mode.value = SigningMode.CEREMONY
            _hasKey.value = true
            _error.value =
                "Provisioning key already present; ceremony refused. " +
                    "Regeneration is a documented recovery procedure " +
                    "(docs/ops/KEY-CUSTODY.md §2), not an app action."
            return
        }
        try {
            val info = withContext(Dispatchers.IO) { ensureKeyPairFn() }
            val pubB64u = encodePublicKeyB64u(info.spkiEncoded)
            _mode.value = SigningMode.CEREMONY
            _hasKey.value = true
            _publicKeyB64u.value = pubB64u
            _statusMessage.value = "Ceremony complete — provisioning key generated"
        } catch (e: Exception) {
            _error.value = "Ceremony failed: ${e.message ?: "unknown"}"
        }
    }

    suspend fun enterOperatingMode() {
        _error.value = null
        _statusMessage.value = null
        val present = withContext(Dispatchers.IO) { hasKeyFn() }
        if (!present) {
            _mode.value = SigningMode.OPERATING
            _hasKey.value = false
            _error.value =
                "No provisioning key present; refusing to sign. " +
                    "Run the ceremony first (docs/ops/KEY-CUSTODY.md §2)."
            return
        }
        _mode.value = SigningMode.OPERATING
        _hasKey.value = true
        _statusMessage.value = "Ready to sign — scan or paste a canonical matrix"
    }

    fun setCanonical(text: String) {
        _error.value = null
        _statusMessage.value = null
        _signatureB64u.value = null
        val trimmed = text.trim()
        if (trimmed.isEmpty()) {
            _error.value = "Canonical matrix is empty"
            return
        }
        try {
            val parsed = parseJsonToPlainMap(trimmed)
            // Validate the schema. SignedMatrix.fromJsonMap throws
            // AuthorizationMatrixError-shaped exceptions on invalid.
            val signed = SignedMatrix.fromJsonMap(parsed)
            val recanonical = jcsCanonicalizeString(signed.toJsonMap())
            if (recanonical != trimmed) {
                _error.value = "Input bytes are not JCS-canonical"
                return
            }
            val digest = MessageDigest.getInstance("SHA-256")
                .digest(recanonical.toByteArray(Charsets.UTF_8))
            val hashB64u = Base64.getUrlEncoder()
                .withoutPadding()
                .encodeToString(digest)
            _canonicalUtf8.value = recanonical
            _canonicalHashB64u.value = hashB64u
            _statusMessage.value = "Matrix loaded — review hash and content"
        } catch (e: Exception) {
            _error.value = "Matrix parse failed: ${e.message ?: "unknown"}"
        }
    }

    suspend fun sign() {
        _error.value = null
        val canonical = _canonicalUtf8.value
        if (canonical == null) {
            _error.value = "No matrix loaded"
            return
        }
        try {
            val digest = MessageDigest.getInstance("SHA-256")
                .digest(canonical.toByteArray(Charsets.UTF_8))
            val sig = withContext(Dispatchers.IO) { signFn(digest) }
            if (sig.size != 64) {
                _error.value =
                    "Signature length ${sig.size}, expected 64"
                return
            }
            _signatureB64u.value = Base64.getUrlEncoder()
                .withoutPadding()
                .encodeToString(sig)
            _statusMessage.value = "Signed — signature ready to export"
        } catch (e: Exception) {
            _error.value = "Sign failed: ${e.message ?: "unknown"}"
        }
    }

    fun clearSignature() {
        _signatureB64u.value = null
        _error.value = null
        _statusMessage.value = null
    }

    private fun encodePublicKeyB64u(spki: ByteArray): String {
        // Strip the SPKI DER wrapper (12-byte header for Ed25519) to
        // get raw 32-byte key, then base64url. Matches the shape
        // expected by ProvisioningKeys / env PROVISIONING_PUBKEY_B64U.
        require(spki.size == 44) {
            "Ed25519 SPKI must be 44 bytes, got ${spki.size}"
        }
        val raw = spki.copyOfRange(12, 44)
        return Base64.getUrlEncoder().withoutPadding().encodeToString(raw)
    }

    private fun parseJsonToPlainMap(text: String): Map<String, Any?> {
        // org.json on JVM test scope: parse via JSONObject then walk
        // to Map. Matches AdminScreenState's CryptoJsonHelpers shape.
        val obj = org.json.JSONObject(text)
        @Suppress("UNCHECKED_CAST")
        return obj.toMap() as Map<String, Any?>
    }

    private fun org.json.JSONObject.toMap(): Map<String, Any?> {
        val out = linkedMapOf<String, Any?>()
        val keys = this.keys()
        while (keys.hasNext()) {
            val k = keys.next()
            out[k] = when (val v = this.get(k)) {
                is org.json.JSONObject -> v.toMap()
                is org.json.JSONArray -> jsonArrayToList(v)
                org.json.JSONObject.NULL -> null
                else -> v
            }
        }
        return out
    }

    private fun jsonArrayToList(arr: org.json.JSONArray): List<Any?> {
        val out = mutableListOf<Any?>()
        for (i in 0 until arr.length()) {
            out.add(
                when (val v = arr.get(i)) {
                    is org.json.JSONObject -> v.toMap()
                    is org.json.JSONArray -> jsonArrayToList(v)
                    org.json.JSONObject.NULL -> null
                    else -> v
                }
            )
        }
        return out
    }
}
