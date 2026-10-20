package com.umoja.secure.crypto

import com.umoja.secure.BuildConfig

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
     * when a `key_rotation` notice is received and cleared when the
     * overlap window closes. Nothing writes it in P1-026 — it is a
     * structural seam for TASK-P1-036.
     */
    const val STORAGE_KEY_PREVIOUS_PROVISIONING_PUBKEY: String =
        "provisioning.previous_pubkey"

    /**
     * SecureStorage key for the highest `recovery_key_version` seen.
     * Initialized to absent; nothing increments it in P1-026.
     * Structural seam for TASK-P1-036.
     */
    const val STORAGE_KEY_HIGHEST_RECOVERY_KEY_VERSION: String =
        "provisioning.highest_recovery_key_version"
}
