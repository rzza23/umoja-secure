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
            val noticeHash = requireBase64Url32(m["notice_hash"], "notice_hash")
            val ackingDeviceId = requireString(m["acking_device_id"], "acking_device_id")
            val decision = requireString(m["decision"], "decision")
            val issuedAt = requireString(m["issued_at"], "issued_at")
            require(decision == "accept" || decision == "reject") {
                "decision: expected \"accept\" or \"reject\", got \"$decision\""
            }
            require(ISO8601_UTC_RE.matches(issuedAt)) {
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
