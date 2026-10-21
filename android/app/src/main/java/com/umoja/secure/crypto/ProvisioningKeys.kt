package com.umoja.secure.crypto

import com.umoja.secure.BuildConfig
import com.umoja.secure.storage.KeyValueStore
import java.security.MessageDigest
import java.security.PublicKey
import java.util.Base64

/**
 * Pinned provisioning and recovery public keys, split by build variant.
 *
 * **PROVISIONING KEY** (TASK-P1-029b, 2026-10-19):
 *
 *   - [TEST_PROVISIONING_PUBKEY_B64U] — the test seed pinned to
 *     `docs/reference/canonical-matrix-test-vectors.json` →
 *     `expected_provisioning_public_key_base64url`. DEBUG builds use
 *     this value. Asserted byte-identical to the vector file by
 *     [ProvisioningKeysTest].
 *   - [PRODUCTION_PROVISIONING_PUBKEY_B64U] — injected at build time
 *     from the custody ceremony's output (see `docs/ops/KEY-CUSTODY.md`
 *     §2, §5.1). Currently a visibly-fake placeholder (32 bytes of
 *     0xFF) — the ceremony that replaces it is TASK-P1-033's
 *     offline-signer integration. A release build still carrying this
 *     placeholder is refused at startup by
 *     [com.umoja.secure.UmojaApplication].
 *   - [CURRENT_PROVISIONING_PUBKEY_B64U] — the value actually used for
 *     matrix verification. Sourced from `BuildConfig.DEBUG`: TEST in
 *     debug, PRODUCTION in release.
 *
 * **RECOVERY KEY** (TASK-P1-035 — NOT touched by P1-029b):
 *
 *   - [RECOVERY_PUBKEY_B64U] — currently a visibly-fake placeholder
 *     (32 zero bytes). The recovery-custody ceremony that generates
 *     the production recovery key is TASK-P1-035's territory (see
 *     `docs/ops/KEY-CUSTODY.md` §3). P1-029b's DEBUG/PROD split does
 *     NOT extend to the recovery key — the recovery key is a single
 *     trust anchor, not a per-build-variant concept.
 *
 * The two keys are separate trust anchors with separate roles:
 *
 *   - The **provisioning key** verifies authorization matrices. During
 *     a rotation overlap window the trusted set contains both the
 *     previous and current provisioning keys. [MatrixVerifier] takes
 *     a Set for exactly this reason.
 *   - The **recovery key** verifies `key_rotation` and `key_revocation`
 *     notices only. It does NOT participate in matrix verification.
 *     Passing it to [MatrixVerifier] is a programming error.
 *
 * Task: TASK-P1-026 (initial), TASK-P1-029b (DEBUG/PROD split, 2026-10-19)
 * Build Master: §3.6
 * ADR: §2 Q6, §3
 * Custody: docs/ops/KEY-CUSTODY.md
 */
object ProvisioningKeys {

    /**
     * Test provisioning key. Derived from the vector file's test-only
     * seed. Used by DEBUG builds. Replaced in release builds by
     * [PRODUCTION_PROVISIONING_PUBKEY_B64U].
     */
    const val TEST_PROVISIONING_PUBKEY_B64U: String =
        "hL_X45qk5WrA9rSxtrQJyRzkDGT0eysDBtuWQosC30M"

    /**
     * Production provisioning key. Injected at build time from the
     * custody ceremony's output (see `docs/ops/KEY-CUSTODY.md` §2,
     * §5.1). **Placeholder:** 43 underscores decode to 32 bytes of
     * 0xFF — not a usable Ed25519 public key, so a release build that
     * accidentally ships this placeholder will fail to verify any
     * matrix and the startup assertion in
     * [com.umoja.secure.UmojaApplication] will refuse to start.
     *
     * Replacing this placeholder is TASK-P1-033's offline-signer
     * integration (the ceremony that generates the production key).
     */
    const val PRODUCTION_PROVISIONING_PUBKEY_B64U: String =
        "___________________________________________"

    /**
     * The provisioning key actually used for matrix verification.
     * Sourced from `BuildConfig.DEBUG`: TEST in debug, PRODUCTION in
     * release. A release build in which this resolves to the test
     * key is refused by the startup assertion in
     * [com.umoja.secure.UmojaApplication].
     */
    val CURRENT_PROVISIONING_PUBKEY_B64U: String =
        if (BuildConfig.DEBUG) TEST_PROVISIONING_PUBKEY_B64U
        else PRODUCTION_PROVISIONING_PUBKEY_B64U

    /**
     * Recovery key placeholder. No test-vector recovery key exists —
     * the W-series vectors cover matrix signing (provisioning key)
     * only. This value decodes to 32 zero bytes.
     *
     * Replaced by TASK-P1-035's recovery-custody ceremony (see
     * `docs/ops/KEY-CUSTODY.md` §3) — NOT by TASK-P1-029b. The
     * DEBUG/PROD split does not apply to the recovery key.
     */
    const val RECOVERY_PUBKEY_B64U: String =
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

    /**
     * SecureStorage key for the previous provisioning public key, set
     * when a `key_rotation` notice is received. Written by
     * [RecoveryNoticeStore.recordKeyRotation] (TASK-P1-036). The overlap
     * end timestamp lives in
     * [STORAGE_KEY_PREVIOUS_PROVISIONING_PUBKEY_OVERLAP_ENDS_AT_MILLIS];
     * window closure is read-gated in [currentTrustedProvisioningKeys]
     * (`now < overlapEndsAtMillis`), not a storage mutation.
     */
    const val STORAGE_KEY_PREVIOUS_PROVISIONING_PUBKEY: String =
        "provisioning.previous_pubkey"

    /**
     * SecureStorage key for the highest `recovery_key_version` seen.
     * Written by [RecoveryNoticeStore.recordKeyRotation] and
     * [RecoveryNoticeStore.recordKeyRevocation] (TASK-P1-036). Shared
     * monotonic counter across both notice types — replay and
     * same-version conflict both reject on `version <= highest`.
     */
    const val STORAGE_KEY_HIGHEST_RECOVERY_KEY_VERSION: String =
        "provisioning.highest_recovery_key_version"

    // ---- TASK-P1-036 (2026-10-21): rotation/revocation state slots ----
    //
    // Written by RecoveryNoticeStore. The current-key slot overrides
    // CURRENT_PROVISIONING_PUBKEY_B64U after a rotation; the overlap-end
    // and revoked-set slots feed currentTrustedProvisioningKeys. All
    // three are read-gated — no timer, no background task.

    /**
     * SecureStorage key for the current provisioning key, written on a
     * `key_rotation` notice. Absent means no rotation has been applied
     * — [effectiveCurrentPubkey] falls back to
     * [CURRENT_PROVISIONING_PUBKEY_B64U] in that case.
     */
    const val STORAGE_KEY_CURRENT_PROVISIONING_PUBKEY: String =
        "provisioning.current_pubkey"

    /**
     * Overlap-window end timestamp (epoch millis) for
     * [STORAGE_KEY_PREVIOUS_PROVISIONING_PUBKEY]. During
     * `[effective_at, effective_at + overlap_window_seconds)`, both
     * previous and current are trusted for matrix verification. After
     * the end, only current. Read-gated on every
     * [currentTrustedProvisioningKeys] call.
     */
    const val STORAGE_KEY_PREVIOUS_PROVISIONING_PUBKEY_OVERLAP_ENDS_AT_MILLIS: String =
        "provisioning.previous_pubkey_overlap_ends_at_millis"

    /**
     * Comma-separated base64url-SHA-256 fingerprints of revoked
     * provisioning keys. A key whose fingerprint is in this set is
     * excluded from [currentTrustedProvisioningKeys] regardless of
     * current/previous role. Matches the wire shape of
     * `KeyRevocationNotice.revokedProvisioningKeyId`.
     */
    const val STORAGE_KEY_REVOKED_PROVISIONING_KEY_FINGERPRINTS: String =
        "provisioning.revoked_fingerprints"

    /**
     * Effective current provisioning key. Prefers the rotation-written
     * override; falls back to [CURRENT_PROVISIONING_PUBKEY_B64U]
     * (BuildConfig-derived) when no rotation has been applied.
     */
    internal fun effectiveCurrentPubkey(store: KeyValueStore): String =
        store.get(STORAGE_KEY_CURRENT_PROVISIONING_PUBKEY)
            ?: CURRENT_PROVISIONING_PUBKEY_B64U

    /**
     * Compute the trusted provisioning key set for matrix verification
     * at [nowMillis].
     *
     *  - Always includes [effectiveCurrentPubkey].
     *  - Includes `previous_provisioning_pubkey` **iff** an overlap
     *    window is open and not expired (`nowMillis < overlapEndsAtMillis`).
     *  - Excludes any key whose fingerprint is in the revoked set.
     *
     * Call at accept-time, not at startup: a rotation applied
     * mid-session must be reflected on the next accept without app
     * restart.
     */
    fun currentTrustedProvisioningKeys(store: KeyValueStore, nowMillis: Long): Set<PublicKey> {
        val keys = mutableSetOf(decodePubkey(effectiveCurrentPubkey(store)))

        val prevB64 = store.get(STORAGE_KEY_PREVIOUS_PROVISIONING_PUBKEY)
        val overlapEndsAt = store.get(STORAGE_KEY_PREVIOUS_PROVISIONING_PUBKEY_OVERLAP_ENDS_AT_MILLIS)
            ?.toLongOrNull() ?: 0L
        if (prevB64 != null && nowMillis < overlapEndsAt) {
            keys += decodePubkey(prevB64)
        }

        val revoked = store.get(STORAGE_KEY_REVOKED_PROVISIONING_KEY_FINGERPRINTS)
            ?.split(",")?.filter { it.isNotBlank() }?.toSet() ?: emptySet()
        if (revoked.isNotEmpty()) {
            keys.retainAll { key -> fingerprintOf(key) !in revoked }
        }
        return keys
    }

    /**
     * Apply a `key_rotation` state transition: previous ← old current,
     * current ← new, overlap window opens until [overlapEndsAtMillis].
     * Called only by [RecoveryNoticeStore.recordKeyRotation] — a direct
     * call bypasses signature verification, order guard, and version
     * bump. `internal` to keep the surface honest within the module.
     */
    internal fun applyKeyRotation(
        store: KeyValueStore,
        oldCurrentPubkeyB64u: String,
        newPubkeyB64u: String,
        overlapEndsAtMillis: Long,
    ) {
        store.put(STORAGE_KEY_PREVIOUS_PROVISIONING_PUBKEY, oldCurrentPubkeyB64u)
        store.put(STORAGE_KEY_PREVIOUS_PROVISIONING_PUBKEY_OVERLAP_ENDS_AT_MILLIS, overlapEndsAtMillis.toString())
        store.put(STORAGE_KEY_CURRENT_PROVISIONING_PUBKEY, newPubkeyB64u)
    }

    /**
     * Add a fingerprint to the revoked set. Idempotent (set semantics).
     * Called only by [RecoveryNoticeStore.recordKeyRevocation].
     */
    internal fun addRevokedFingerprint(store: KeyValueStore, fingerprint: String) {
        val existing = store.get(STORAGE_KEY_REVOKED_PROVISIONING_KEY_FINGERPRINTS)
            ?.split(",")?.filter { it.isNotBlank() }?.toSet() ?: emptySet()
        store.put(
            STORAGE_KEY_REVOKED_PROVISIONING_KEY_FINGERPRINTS,
            (existing + fingerprint).joinToString(","),
        )
    }

    /**
     * Decode a base64url-no-pad 32-byte Ed25519 public key to a
     * [PublicKey]. Delegates to [MatrixSigner.publicKeyFromRaw] — the
     * raw-size guard lives there. Composition over duplication:
     * [MatrixSigner]'s `SPKI_PREFIX` stays private to it.
     */
    internal fun decodePubkey(b64u: String): PublicKey =
        MatrixSigner.publicKeyFromRaw(Base64.getUrlDecoder().decode(b64u))

    /**
     * Base64url-SHA-256 of the raw 32-byte key. Same wire shape
     * `RecoveryNotice.requireBase64UrlFingerprint` emits and the
     * fingerprint field a `key_revocation` notice carries. Delegates
     * the SPKI→raw stripping to [DeviceIdentity.rawPublicKey].
     */
    internal fun fingerprintOf(key: PublicKey): String {
        val raw = DeviceIdentity.rawPublicKey(key.encoded)
        val digest = MessageDigest.getInstance("SHA-256").digest(raw)
        return Base64.getUrlEncoder().withoutPadding().encodeToString(digest)
    }
}
