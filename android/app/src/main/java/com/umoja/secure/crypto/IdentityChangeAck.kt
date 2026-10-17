package com.umoja.secure.crypto

import java.util.Base64

/**
 * Identity-change ack — the wire shape that gets signed.
 *
 * Signed unit:
 *
 *   {"domain":"umoja.identity-change-ack.v1","ack":{...}}
 *
 * Claims continuity acknowledgment: "I have seen notice H and
 * [accept|reject] the replacement it describes." Same cryptographic
 * protocol as the matrix and the replacement notice (§3.8): JCS
 * canonicalize → SHA-256 → Ed25519 over the digest → base64url.
 *
 * Signed by the acking device's device auth key (the same key used
 * for session authentication). The backend verifies this signature
 * before storing — see backend/src/identityChange/acks.ts. The Kotlin
 * side in 030e-c is signer-only (a peer signs their own ack); the
 * inbound verifier is a client-side concern that lands with
 * ReplacementNoticeVerifier in this session's second commit.
 *
 * Counterpart: backend/src/crypto/identity-change-ack.ts.
 *
 * Task: TASK-P1-030 030e-c
 * Build Master: §3.7
 * ADR: ADR-IDENTITY-CHANGE-001 §3
 */
data class IdentityChangeAck(
    val noticeHash: String,
    val ackingDeviceId: String,
    val decision: String,
    val issuedAt: String,
) {
    fun toJsonMap(): Map<String, Any?> = linkedMapOf(
        "notice_hash" to noticeHash,
        "acking_device_id" to ackingDeviceId,
        "decision" to decision,
        "issued_at" to issuedAt,
    )

    companion object {
        fun fromJsonMap(m: Map<String, Any?>): IdentityChangeAck {
            val noticeHash = IC_REQUIRE_BASE64URL32(m["notice_hash"], "notice_hash")
            val ackingDeviceId = IC_REQUIRE_STRING(m["acking_device_id"], "acking_device_id")
            val decision = IC_REQUIRE_STRING(m["decision"], "decision")
            val issuedAt = IC_REQUIRE_STRING(m["issued_at"], "issued_at")
            require(decision == "accept" || decision == "reject") {
                "decision: expected \"accept\" or \"reject\", got \"$decision\""
            }
            require(IC_ISO8601_UTC_RE.matches(issuedAt)) {
                "issued_at: expected ISO 8601 UTC with trailing Z, got $issuedAt"
            }
            return IdentityChangeAck(
                noticeHash = noticeHash,
                ackingDeviceId = ackingDeviceId,
                decision = decision,
                issuedAt = issuedAt,
            )
        }
    }
}

data class SignedIdentityChangeAck(
    val domain: String,
    val ack: IdentityChangeAck,
) {
    fun toJsonMap(): Map<String, Any?> = linkedMapOf(
        "domain" to domain,
        "ack" to ack.toJsonMap(),
    )

    companion object {
        const val DOMAIN: String = "umoja.identity-change-ack.v1"

        fun fromJsonMap(m: Map<String, Any?>): SignedIdentityChangeAck {
            val domain = m["domain"]
            require(domain == DOMAIN) {
                "domain: expected \"$DOMAIN\", got ${domain?.let { "\"$it\"" } ?: "null"}"
            }
            @Suppress("UNCHECKED_CAST")
            val inner = m["ack"] as? Map<String, Any?>
                ?: throw IllegalArgumentException("ack: expected object")
            return SignedIdentityChangeAck(
                domain = DOMAIN,
                ack = IdentityChangeAck.fromJsonMap(inner),
            )
        }
    }
}

// ---------- validation helpers ----------
//
// IC_ prefix on BOTH declarations and call sites. Per handoff §7
// (Session F lesson): prefixing declarations without prefixing call
// sites lets an unprefixed call resolve to another file's file-private
// declaration and fail compile. Consistency is what matters.
//
// No custom exception class — Kotlin crypto convention is `require()` →
// IllegalArgumentException, matching AuthorizationMatrix.kt and
// ReplacementNotice.kt. TS's IdentityChangeAckError is a TS idiom
// (Error subclass with .name); Kotlin uses the built-in.

private val IC_BASE64URL32_RE = Regex("^[A-Za-z0-9_-]{43}$")
private val IC_ISO8601_UTC_RE =
    Regex("^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(\\.\\d+)?Z$")

private fun IC_REQUIRE_STRING(value: Any?, field: String): String {
    val s = value as? String
        ?: throw IllegalArgumentException(
            "$field: expected string, got ${value?.let { it::class.simpleName } ?: "null"}",
        )
    if (s.isEmpty()) {
        throw IllegalArgumentException("$field: empty string not permitted")
    }
    return s
}

private fun IC_REQUIRE_BASE64URL32(value: Any?, field: String): String {
    val s = IC_REQUIRE_STRING(value, field)
    if (!IC_BASE64URL32_RE.matches(s)) {
        throw IllegalArgumentException(
            "$field: not base64url (no padding, [A-Za-z0-9_-] only) or wrong length (expected 43)",
        )
    }
    val decoded = Base64.getUrlDecoder().decode(s)
    if (decoded.size != 32) {
        throw IllegalArgumentException(
            "$field: decodes to ${decoded.size} bytes, expected 32",
        )
    }
    return s
}
