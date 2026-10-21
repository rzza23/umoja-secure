package com.umoja.secure.crypto

import java.util.Base64

/**
 * Replacement notice — the wire shape that gets signed.
 *
 * Signed unit:
 *
 *   {"domain":"umoja.replacement-notice.v1","notice":{...}}
 *
 * Claims continuity across a device replacement: "D_old (with this auth
 * key) has been replaced by D_new (with this auth key)." Semantically
 * distinct from the authorization matrix: matrix is authorization, this
 * is continuity. The peer verifies the signature against the pinned
 * provisioning key, then asks the human "do you recognize this
 * replacement?" — the answer is a separate peer-signed ack artifact
 * (030e-b).
 *
 * Same cryptographic protocol as the matrix (§3.8): JCS canonicalize →
 * SHA-256 → Ed25519 over the digest → base64url.
 *
 * Counterpart: backend/src/crypto/replacement-notice.ts.
 *
 * Task: TASK-P1-030 030e-a
 * Build Master: §3.7
 */
data class ReplacementNotice(
    val fromDeviceId: String,
    val fromDeviceAuthKey: String,
    val toDeviceId: String,
    val toDeviceAuthKey: String,
    val issuedAt: String,
) {
    fun toJsonMap(): Map<String, Any?> = linkedMapOf(
        "from_device_id" to fromDeviceId,
        "from_device_auth_key" to fromDeviceAuthKey,
        "to_device_id" to toDeviceId,
        "to_device_auth_key" to toDeviceAuthKey,
        "issued_at" to issuedAt,
    )

    companion object {
        fun fromJsonMap(m: Map<String, Any?>): ReplacementNotice {
            val fromDeviceId = requireString(m["from_device_id"], "from_device_id")
            val fromDeviceAuthKey = requireBase64Url32(
                m["from_device_auth_key"], "from_device_auth_key",
            )
            val toDeviceId = requireString(m["to_device_id"], "to_device_id")
            val toDeviceAuthKey = requireBase64Url32(
                m["to_device_auth_key"], "to_device_auth_key",
            )
            val issuedAt = requireString(m["issued_at"], "issued_at")
            require(fromDeviceId != toDeviceId) {
                "from_device_id and to_device_id must differ"
            }
            require(ISO8601_UTC_RE.matches(issuedAt)) {
                "issued_at: expected ISO 8601 UTC with trailing Z, got $issuedAt"
            }
            return ReplacementNotice(
                fromDeviceId = fromDeviceId,
                fromDeviceAuthKey = fromDeviceAuthKey,
                toDeviceId = toDeviceId,
                toDeviceAuthKey = toDeviceAuthKey,
                issuedAt = issuedAt,
            )
        }
    }
}

data class SignedReplacementNotice(
    val domain: String,
    val notice: ReplacementNotice,
) {
    fun toJsonMap(): Map<String, Any?> = linkedMapOf(
        "domain" to domain,
        "notice" to notice.toJsonMap(),
    )

    companion object {
        const val DOMAIN: String = "umoja.replacement-notice.v1"

        fun fromJsonMap(m: Map<String, Any?>): SignedReplacementNotice {
            val domain = m["domain"]
            require(domain == DOMAIN) {
                "domain: expected \"$DOMAIN\", got ${domain?.let { "\"$it\"" } ?: "null"}"
            }
            @Suppress("UNCHECKED_CAST")
            val inner = m["notice"] as? Map<String, Any?>
                ?: throw IllegalArgumentException("notice: expected object")
            return SignedReplacementNotice(
                domain = DOMAIN,
                notice = ReplacementNotice.fromJsonMap(inner),
            )
        }
    }
}

// ---------- validation helpers ----------
