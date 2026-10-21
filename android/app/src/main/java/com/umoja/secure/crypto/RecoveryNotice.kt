package com.umoja.secure.crypto

/**
 * Recovery notices — the three wire shapes that authorize provisioning-key
 * rotation, provisioning-key revocation, and recovery-key rotation,
 * per Build Master §3.6 and ADR-PROVISIONING-001 §2 Q6.
 *
 * Three signed units, distinguished by domain:
 *
 *   {"domain":"umoja.key-rotation.v1","notice":{...}}
 *   {"domain":"umoja.key-revocation.v1","notice":{...}}
 *   {"domain":"umoja.recovery-key-rotation.v1","notice":{...}}
 *
 * Protocol identical to the matrix and replacement-notice per Build
 * Master §3.8: JCS-canonicalize the wrapper, SHA-256 digest, Ed25519
 * sign the 32-byte digest, base64url no padding. Prehash is
 * load-bearing — Ed25519 signs the digest, not the bytes.
 *
 * **Counterpart: `backend/src/crypto/recovery-notice.ts`.** Both sides
 * must produce byte-identical canonical bytes, digest, and signature
 * for identical inputs. The TS module's KDoc records the field-set
 * completion rationale for `key_rotation` (Build Master §3.6
 * para 1 names only new key + overlap; nonce/event_id/effective_at/
 * recovery_key_version are added by analogy with para 2 for replay
 * protection). That rationale is not duplicated here; see the TS
 * module.
 *
 * **Fingerprint convention.** `KeyRevocationNotice.revokedProvisioningKeyId`
 * is the base64url-encoded SHA-256 of the revoked provisioning public
 * key's raw 32 bytes — 43 chars. Same length as a raw key, different
 * semantics; do not confuse the two.
 *
 * **Cross-field constraints enforced at parse time** (matching TS):
 *   - `KeyRevocationNotice`: `revokedProvisioningKeyId` must not equal
 *     the SHA-256 fingerprint of `newProvisioningKey` (a revocation
 *     whose replacement equals the revoked key is a contradiction).
 *   - `RecoveryKeyRotationNotice`: `newRecoveryKeyVersion` must
 *     strictly exceed `recoveryKeyVersion` (Build Master §3.6 step
 *     5 monotonicity, applied at the wire boundary).
 *
 * **No custom exception class.** Kotlin crypto convention is
 * `require()` → `IllegalArgumentException`, matching
 * [AuthorizationMatrix], [ReplacementNotice], [IdentityChangeAck],
 * [ProvisioningBundle]. TS's `RecoveryNoticeError` is a TS idiom
 * (Error subclass with .name); Kotlin uses the built-in.
 *
 * Task: TASK-P1-035b
 * Build Master: §3.6 (rotation + revocation authority), §3.8 (protocol)
 * ADR: §2 Q6 (provisioning key compromise)
 * Depends: TASK-P1-035a (TS schema + 5 test vectors)
 */
data class KeyRotationNotice(
    val newProvisioningKey: String,
    val overlapWindowSeconds: Int,
    val effectiveAt: String,
    val nonce: String,
    val eventId: String,
    val recoveryKeyVersion: Int,
) {
    fun toJsonMap(): Map<String, Any?> = linkedMapOf(
        "new_provisioning_key" to newProvisioningKey,
        "overlap_window_seconds" to overlapWindowSeconds,
        "effective_at" to effectiveAt,
        "nonce" to nonce,
        "event_id" to eventId,
        "recovery_key_version" to recoveryKeyVersion,
    )

    companion object {
        fun fromJsonMap(m: Map<String, Any?>): KeyRotationNotice {
            val newProvisioningKey = requireBase64Url32(
                m["new_provisioning_key"], "new_provisioning_key",
            )
            val overlapWindowSeconds = requirePositiveInt(
                m["overlap_window_seconds"], "overlap_window_seconds",
            )
            val effectiveAt = requireString(m["effective_at"], "effective_at")
            require(ISO8601_UTC_RE.matches(effectiveAt)) {
                "effective_at: expected ISO 8601 UTC with trailing Z, got $effectiveAt"
            }
            val nonce = requireString(m["nonce"], "nonce")
            val eventId = requireString(m["event_id"], "event_id")
            val recoveryKeyVersion = requirePositiveInt(
                m["recovery_key_version"], "recovery_key_version",
            )
            return KeyRotationNotice(
                newProvisioningKey = newProvisioningKey,
                overlapWindowSeconds = overlapWindowSeconds,
                effectiveAt = effectiveAt,
                nonce = nonce,
                eventId = eventId,
                recoveryKeyVersion = recoveryKeyVersion,
            )
        }
    }
}

data class SignedKeyRotationNotice(
    val domain: String,
    val notice: KeyRotationNotice,
) {
    fun toJsonMap(): Map<String, Any?> = linkedMapOf(
        "domain" to domain,
        "notice" to notice.toJsonMap(),
    )

    companion object {
        const val DOMAIN: String = "umoja.key-rotation.v1"

        fun fromJsonMap(m: Map<String, Any?>): SignedKeyRotationNotice {
            val domain = m["domain"]
            require(domain == DOMAIN) {
                "domain: expected \"$DOMAIN\", got ${domain?.let { "\"$it\"" } ?: "null"}"
            }
            @Suppress("UNCHECKED_CAST")
            val inner = m["notice"] as? Map<String, Any?>
                ?: throw IllegalArgumentException("notice: expected object")
            return SignedKeyRotationNotice(
                domain = DOMAIN,
                notice = KeyRotationNotice.fromJsonMap(inner),
            )
        }
    }
}

data class KeyRevocationNotice(
    val revokedProvisioningKeyId: String,
    val newProvisioningKey: String,
    val effectiveAt: String,
    val nonce: String,
    val eventId: String,
    val recoveryKeyVersion: Int,
) {
    fun toJsonMap(): Map<String, Any?> = linkedMapOf(
        "revoked_provisioning_key_id" to revokedProvisioningKeyId,
        "new_provisioning_key" to newProvisioningKey,
        "effective_at" to effectiveAt,
        "nonce" to nonce,
        "event_id" to eventId,
        "recovery_key_version" to recoveryKeyVersion,
    )

    companion object {
        fun fromJsonMap(m: Map<String, Any?>): KeyRevocationNotice {
            val revokedProvisioningKeyId = requireBase64UrlFingerprint(
                m["revoked_provisioning_key_id"], "revoked_provisioning_key_id",
            )
            val newProvisioningKey = requireBase64Url32(
                m["new_provisioning_key"], "new_provisioning_key",
            )
            val effectiveAt = requireString(m["effective_at"], "effective_at")
            require(ISO8601_UTC_RE.matches(effectiveAt)) {
                "effective_at: expected ISO 8601 UTC with trailing Z, got $effectiveAt"
            }
            val nonce = requireString(m["nonce"], "nonce")
            val eventId = requireString(m["event_id"], "event_id")
            val recoveryKeyVersion = requirePositiveInt(
                m["recovery_key_version"], "recovery_key_version",
            )

            // Cross-field: a revocation whose replacement equals the
            // revoked key is a contradiction. Compute the fingerprint
            // of new_provisioning_key and reject if it matches
            // revoked_provisioning_key_id. Matches TS's check.
            val newKeyRaw = java.util.Base64.getUrlDecoder().decode(newProvisioningKey)
            val newKeyFingerprint = java.util.Base64.getUrlEncoder().withoutPadding()
                .encodeToString(java.security.MessageDigest.getInstance("SHA-256").digest(newKeyRaw))
            require(revokedProvisioningKeyId != newKeyFingerprint) {
                "revoked_provisioning_key_id equals fingerprint of new_provisioning_key; " +
                    "a revocation cannot name the replacement as the revoked key"
            }

            return KeyRevocationNotice(
                revokedProvisioningKeyId = revokedProvisioningKeyId,
                newProvisioningKey = newProvisioningKey,
                effectiveAt = effectiveAt,
                nonce = nonce,
                eventId = eventId,
                recoveryKeyVersion = recoveryKeyVersion,
            )
        }
    }
}

data class SignedKeyRevocationNotice(
    val domain: String,
    val notice: KeyRevocationNotice,
) {
    fun toJsonMap(): Map<String, Any?> = linkedMapOf(
        "domain" to domain,
        "notice" to notice.toJsonMap(),
    )

    companion object {
        const val DOMAIN: String = "umoja.key-revocation.v1"

        fun fromJsonMap(m: Map<String, Any?>): SignedKeyRevocationNotice {
            val domain = m["domain"]
            require(domain == DOMAIN) {
                "domain: expected \"$DOMAIN\", got ${domain?.let { "\"$it\"" } ?: "null"}"
            }
            @Suppress("UNCHECKED_CAST")
            val inner = m["notice"] as? Map<String, Any?>
                ?: throw IllegalArgumentException("notice: expected object")
            return SignedKeyRevocationNotice(
                domain = DOMAIN,
                notice = KeyRevocationNotice.fromJsonMap(inner),
            )
        }
    }
}

data class RecoveryKeyRotationNotice(
    val newRecoveryKey: String,
    val newRecoveryKeyVersion: Int,
    val effectiveAt: String,
    val nonce: String,
    val eventId: String,
    val recoveryKeyVersion: Int,
) {
    fun toJsonMap(): Map<String, Any?> = linkedMapOf(
        "new_recovery_key" to newRecoveryKey,
        "new_recovery_key_version" to newRecoveryKeyVersion,
        "effective_at" to effectiveAt,
        "nonce" to nonce,
        "event_id" to eventId,
        "recovery_key_version" to recoveryKeyVersion,
    )

    companion object {
        fun fromJsonMap(m: Map<String, Any?>): RecoveryKeyRotationNotice {
            val newRecoveryKey = requireBase64Url32(
                m["new_recovery_key"], "new_recovery_key",
            )
            val newRecoveryKeyVersion = requirePositiveInt(
                m["new_recovery_key_version"], "new_recovery_key_version",
            )
            val effectiveAt = requireString(m["effective_at"], "effective_at")
            require(ISO8601_UTC_RE.matches(effectiveAt)) {
                "effective_at: expected ISO 8601 UTC with trailing Z, got $effectiveAt"
            }
            val nonce = requireString(m["nonce"], "nonce")
            val eventId = requireString(m["event_id"], "event_id")
            val recoveryKeyVersion = requirePositiveInt(
                m["recovery_key_version"], "recovery_key_version",
            )

            // Cross-field: Build Master §3.6 step 5 monotonicity.
            // A recovery-key rotation must strictly increase the
            // version; same-version or lower-version is not a rotation.
            // Applied at the wire boundary so P1-036's client sees
            // a well-formed notice or none at all. Matches TS's check.
            require(newRecoveryKeyVersion > recoveryKeyVersion) {
                "new_recovery_key_version ($newRecoveryKeyVersion) must strictly " +
                    "exceed recovery_key_version ($recoveryKeyVersion)"
            }

            return RecoveryKeyRotationNotice(
                newRecoveryKey = newRecoveryKey,
                newRecoveryKeyVersion = newRecoveryKeyVersion,
                effectiveAt = effectiveAt,
                nonce = nonce,
                eventId = eventId,
                recoveryKeyVersion = recoveryKeyVersion,
            )
        }
    }
}

data class SignedRecoveryKeyRotationNotice(
    val domain: String,
    val notice: RecoveryKeyRotationNotice,
) {
    fun toJsonMap(): Map<String, Any?> = linkedMapOf(
        "domain" to domain,
        "notice" to notice.toJsonMap(),
    )

    companion object {
        const val DOMAIN: String = "umoja.recovery-key-rotation.v1"

        fun fromJsonMap(m: Map<String, Any?>): SignedRecoveryKeyRotationNotice {
            val domain = m["domain"]
            require(domain == DOMAIN) {
                "domain: expected \"$DOMAIN\", got ${domain?.let { "\"$it\"" } ?: "null"}"
            }
            @Suppress("UNCHECKED_CAST")
            val inner = m["notice"] as? Map<String, Any?>
                ?: throw IllegalArgumentException("notice: expected object")
            return SignedRecoveryKeyRotationNotice(
                domain = DOMAIN,
                notice = RecoveryKeyRotationNotice.fromJsonMap(inner),
            )
        }
    }
}

// ---------- validation helpers ----------
//
// requireString, requireBase64Url32, requirePositiveInt, and
// ISO8601_UTC_RE live in Base64UrlValidation.kt (shared by
// AuthorizationMatrix, ReplacementNotice, IdentityChangeAck, and
// this file). Only the fingerprint variant is file-private here,
// with a single consumer (KeyRevocationNotice.revokedProvisioningKeyId);
// below the extraction threshold.

private fun requireBase64UrlFingerprint(value: Any?, field: String): String {
    // base64url(SHA-256(...)) is 43 chars for 32 bytes, matching
    // requireBase64Url32's wire shape. The semantic distinction
    // (fingerprint vs raw key) is documented on the field, not
    // enforced separately — a 43-char base64url string always decodes
    // to exactly 32 bytes, so the decode check requireBase64Url32
    // performs is redundant here. TS's requireBase64UrlFingerprint
    // makes the same choice for the same reason.
    val s = requireString(value, field)
    if (!BASE64URL_RE.matches(s)) {
        throw IllegalArgumentException(
            "$field: not base64url (no padding, [A-Za-z0-9_-] only)",
        )
    }
    if (s.length != 43) {
        throw IllegalArgumentException(
            "$field: expected 43 base64url chars for SHA-256 fingerprint, got ${s.length}",
        )
    }
    return s
}
