package com.umoja.secure.crypto

import org.json.JSONObject
import java.util.Base64

/**
 * Builds the enrolling-device QR payload for TASK-P1-019.
 *
 * Wire format (owner ruling, 2026-10-14, handoff 3):
 *
 *   {
 *     "domain": "umoja.enrollment-request.v1",
 *     "device_id": "<string, <=64 printable ASCII>",
 *     "pub_device_auth_key": "<base64url 32B>",
 *     "pub_messaging_identity_key": "<base64url 32B>",
 *     "pub_wipe_confirmation_key": "<base64url 32B>"
 *   }
 *
 * The payload is NOT JCS-canonicalized and NOT signed in Phase 1.
 * Field order is stable so screenshots and manual round-trips are
 * reproducible, but the order is not load-bearing: the parser
 * [ProvisioningBundle.parse] does not depend on it. If the payload is
 * ever signed by the device auth key (KI-017 future hardening), order
 * becomes load-bearing and JCS canonicalization must be applied here.
 *
 * This builder's contract is: for any input it accepts, its output
 * parses cleanly through [ProvisioningBundle.parse] and preserves every
 * field value. Test coverage asserts this.
 *
 * Uses java.util.Base64 (JVM-native, available on Android API 26+) so
 * the class remains JVM-testable; android.util.Base64 would have tied
 * it to the Android runtime.
 */
object EnrollmentQrPayload {

    const val DOMAIN: String = ProvisioningBundle.DOMAIN
    const val MAX_DEVICE_ID_LEN: Int = 64

    // In the Kotlin source these are "\x20" and "\x7E"; the Kotlin
    // compiler turns each double-backslash into a single backslash, so
    // the regex engine sees \x20 (space) and \x7E (tilde).
    private val BASE64URL_RE = Regex("^[A-Za-z0-9_-]{43}$")
    private val PRINTABLE_ASCII_RE = Regex("^[\\x20-\\x7E]+$")

    /**
     * Build the JSON payload string.
     *
     * @throws IllegalArgumentException if any input is malformed. The
     *         caller must not emit a QR for input the parser will reject.
     */
    fun build(
        deviceId: String,
        pubDeviceAuthKey: String,
        pubMessagingIdentityKey: String,
        pubWipeConfirmationKey: String,
    ): String {
        requirePrintableAscii(deviceId, "device_id", MAX_DEVICE_ID_LEN)
        requireBase64Url32(pubDeviceAuthKey, "pub_device_auth_key")
        requireBase64Url32(pubMessagingIdentityKey, "pub_messaging_identity_key")
        requireBase64Url32(pubWipeConfirmationKey, "pub_wipe_confirmation_key")

        // Android's org.json.JSONObject is backed by LinkedHashMap and
        // preserves insertion order. The test-scope org.json:json:20240303
        // artifact (used in JVM tests) does the same.
        // Manual serialization for deterministic key order across
        // platforms. Android's org.json.JSONObject preserves insertion
        // order (LinkedHashMap-backed), but the JVM test artifact
        // (org.json:json:20240303) uses HashMap, which does not.
        // Manual assembly guarantees byte-identical output on both.
        // JSONObject.quote handles JSON string escaping uniformly on
        // both platforms for the values we emit (base64url keys and a
        // printable-ASCII device_id).
        val serialized = buildString {
            append('{')
            append("\"domain\":").append(JSONObject.quote(DOMAIN)).append(',')
            append("\"device_id\":").append(JSONObject.quote(deviceId)).append(',')
            append("\"pub_device_auth_key\":").append(JSONObject.quote(pubDeviceAuthKey)).append(',')
            append("\"pub_messaging_identity_key\":").append(JSONObject.quote(pubMessagingIdentityKey)).append(',')
            append("\"pub_wipe_confirmation_key\":").append(JSONObject.quote(pubWipeConfirmationKey))
            append('}')
        }

        // Sanity: the parser must accept our own output. This catches
        // escaping bugs (e.g., a device_id with a quote character) at
        // emit time, before a QR is ever rendered.
        ProvisioningBundle.parse(serialized)

        return serialized
    }

    // ---------- validation helpers ----------
    // File-private mirrors of ProvisioningBundle's validators. KI-016
    // already flags duplicated base64url validators; this widens the
    // duplication from 2 files to 3. Consolidation is a separate task.

    private fun requireString(value: String, field: String): String {
        if (value.isEmpty()) {
            throw IllegalArgumentException("$field: empty string not permitted")
        }
        return value
    }

    private fun requirePrintableAscii(value: String, field: String, maxLen: Int): String {
        val s = requireString(value, field)
        if (!PRINTABLE_ASCII_RE.matches(s)) {
            throw IllegalArgumentException("$field: must be printable ASCII")
        }
        if (s.length > maxLen) {
            throw IllegalArgumentException("$field: exceeds max length $maxLen, got ${s.length}")
        }
        return s
    }

    private fun requireBase64Url32(value: String, field: String): String {
        val s = requireString(value, field)
        if (!BASE64URL_RE.matches(s)) {
            throw IllegalArgumentException("$field: not 43-char base64url (no padding)")
        }
        val decoded = try {
            Base64.getUrlDecoder().decode(s)
        } catch (e: IllegalArgumentException) {
            throw IllegalArgumentException("$field: not decodable as base64url", e)
        }
        if (decoded.size != 32) {
            throw IllegalArgumentException("$field: decodes to ${decoded.size} bytes, expected 32")
        }
        return s
    }
}
