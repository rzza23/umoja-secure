package com.umoja.secure.crypto

/**
 * Pinned provisioning and recovery public keys.
 *
 * **TEST KEYS ONLY.** Replaced by TASK-P1-029 (signing-key custody)
 * before any production build. The provisioning key below is derived
 * per `docs/reference/canonical-matrix-test-vectors.json` →
 * `test_only_key_derivation`, and is asserted byte-identical to that
 * file's `expected_provisioning_public_key_base64url` by
 * [ProvisioningKeysTest]. The recovery key has no test vector and is
 * a visibly-fake placeholder.
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
 * Task: TASK-P1-026
 * Build Master: §3.6
 * ADR: §2 Q6, §3
 */
object ProvisioningKeys {

    /**
     * TEST KEY. Derived from the vector file's test-only seed.
     * Replaced by TASK-P1-029 before any production build.
     */
    const val CURRENT_PROVISIONING_PUBKEY_B64U: String =
        "hL_X45qk5WrA9rSxtrQJyRzkDGT0eysDBtuWQosC30M"

    /**
     * PLACEHOLDER. No test-vector recovery key exists — the W-series
     * vectors cover matrix signing (provisioning key) only. This value
     * decodes to 32 zero bytes and must be replaced by TASK-P1-029
     * before any production build.
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
