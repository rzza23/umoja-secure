package com.umoja.secure.crypto

import java.util.Base64

/**
 * Authorization matrix — the wire shape that gets signed.
 *
 * Signed unit per Build Master §3.8 and ADR-PROVISIONING-001 §3:
 *
 *   {"domain":"umoja.authorization-matrix.v1","matrix":{...}}
 *
 * The `domain` field provides domain separation. The wrapper — not the
 * inner matrix — is what JCS-canonicalizes, what SHA-256 digests, and
 * what Ed25519 signs.
 *
 * Key material is carried as base64url strings, matching the wire format.
 * Decode to ByteArray only at the point of use (signing primitive,
 * libsignal). Kotlin ByteArray equality is referential; strings are not.
 *
 * Task: TASK-P1-026
 * Build Master: §3.7, §3.8
 * ADR: §3, §4
 */
data class AuthorizationMatrix(
    val version: Int,
    val deviceId: String,
    val pubDeviceAuthKey: String,
    val pubMessagingIdentityKey: String,
    val pubWipeConfirmationKey: String,
    val clearance: String,
    val permittedContacts: List<String>,
    val issuedAt: String,
) {
    /**
     * Convert to the pure-Kotlin map shape that jcsCanonicalize consumes.
     * Keys are the snake_case wire field names, since JCS is over the
     * wire form — not over this Kotlin class's property names.
     *
     * Uses LinkedHashMap for insertion order; JCS sorts keys itself, so
     * the insertion order does not affect the canonical bytes. It only
     * makes debug output readable.
     */
    fun toJsonMap(): Map<String, Any?> = linkedMapOf(
        "version" to version,
        "device_id" to deviceId,
        "pub_device_auth_key" to pubDeviceAuthKey,
        "pub_messaging_identity_key" to pubMessagingIdentityKey,
        "pub_wipe_confirmation_key" to pubWipeConfirmationKey,
        "clearance" to clearance,
        "permitted_contacts" to permittedContacts,
        "issued_at" to issuedAt,
    )

    companion object {
        /**
         * Parse an AuthorizationMatrix from a JSON-decoded map (the shape
         * produced by JSONObject.toMap() or equivalent). Runs the same
         * content checks as the TS validator.
         */
        fun fromJsonMap(m: Map<String, Any?>): AuthorizationMatrix {
            val version = requirePositiveInt(m["version"], "version")
            val deviceId = requireString(m["device_id"], "device_id")
            val pubDeviceAuthKey = requireBase64Url32(m["pub_device_auth_key"], "pub_device_auth_key")
            val pubMessagingIdentityKey = requireBase64Url32(
                m["pub_messaging_identity_key"], "pub_messaging_identity_key",
            )
            val pubWipeConfirmationKey = requireBase64Url32(
                m["pub_wipe_confirmation_key"], "pub_wipe_confirmation_key",
            )
            val clearance = requireString(m["clearance"], "clearance")
            val permittedContacts = requireStringList(m["permitted_contacts"], "permitted_contacts")
            val issuedAt = requireString(m["issued_at"], "issued_at")
            require(ISO8601_UTC_RE.matches(issuedAt)) {
                "issued_at: expected ISO 8601 UTC with trailing Z, got $issuedAt"
            }
            return AuthorizationMatrix(
                version = version,
                deviceId = deviceId,
                pubDeviceAuthKey = pubDeviceAuthKey,
                pubMessagingIdentityKey = pubMessagingIdentityKey,
                pubWipeConfirmationKey = pubWipeConfirmationKey,
                clearance = clearance,
                permittedContacts = permittedContacts,
                issuedAt = issuedAt,
            )
        }
    }
}

/**
 * The signed wrapper. The `domain` field provides domain separation.
 */
data class SignedMatrix(
    val domain: String,
    val matrix: AuthorizationMatrix,
) {
    fun toJsonMap(): Map<String, Any?> = linkedMapOf(
        "domain" to domain,
        "matrix" to matrix.toJsonMap(),
    )

    companion object {
        const val DOMAIN: String = "umoja.authorization-matrix.v1"

        fun fromJsonMap(m: Map<String, Any?>): SignedMatrix {
            val domain = m["domain"]
            require(domain == DOMAIN) {
                "domain: expected \"$DOMAIN\", got ${domain?.let { "\"$it\"" } ?: "null"}"
            }
            @Suppress("UNCHECKED_CAST")
            val inner = m["matrix"] as? Map<String, Any?>
                ?: throw IllegalArgumentException("matrix: expected object")
            return SignedMatrix(domain = DOMAIN, matrix = AuthorizationMatrix.fromJsonMap(inner))
        }
    }
}

// ---------- validation helpers ----------

private val BASE64URL_RE = Regex("^[A-Za-z0-9_-]+$")
private val ISO8601_UTC_RE = Regex("^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(\\.\\d+)?Z$")

private fun requireString(value: Any?, field: String): String {
    val s = value as? String
        ?: throw IllegalArgumentException("$field: expected string, got ${value?.let { it::class.simpleName } ?: "null"}")
    if (s.isEmpty()) {
        throw IllegalArgumentException("$field: empty string not permitted")
    }
    return s
}

private fun requireBase64Url32(value: Any?, field: String): String {
    val s = requireString(value, field)
    if (!BASE64URL_RE.matches(s)) {
        throw IllegalArgumentException("$field: not base64url (no padding, [A-Za-z0-9_-] only)")
    }
    if (s.length != 43) {
        throw IllegalArgumentException(
            "$field: expected 43 base64url chars for 32 bytes, got ${s.length}",
        )
    }
    val decoded = Base64.getUrlDecoder().decode(s)
    if (decoded.size != 32) {
        throw IllegalArgumentException("$field: decodes to ${decoded.size} bytes, expected 32")
    }
    return s
}

private fun requirePositiveInt(value: Any?, field: String): Int {
    val n = when (value) {
        is Int -> value
        is Long -> {
            require(value in Int.MIN_VALUE.toLong()..Int.MAX_VALUE.toLong()) {
                "$field: out of Int range"
            }
            value.toInt()
        }
        else -> throw IllegalArgumentException(
            "$field: expected positive integer, got ${value?.let { it::class.simpleName } ?: "null"}",
        )
    }
    if (n < 1) {
        throw IllegalArgumentException("$field: expected positive integer, got $n")
    }
    return n
}

@Suppress("UNCHECKED_CAST")
private fun requireStringList(value: Any?, field: String): List<String> {
    val list = value as? List<Any?>
        ?: throw IllegalArgumentException("$field: expected array")
    return list.mapIndexed { i, item -> requireString(item, "$field[$i]") }
}
