package com.umoja.secure.crypto

import com.umoja.secure.storage.KeyValueStore
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import java.security.PublicKey
import java.time.Instant

/**
 * Client-side handler for recovery-key-signed notices:
 * `key_rotation` and `key_revocation`.
 *
 * **Scope (TASK-P1-036).** Two notice types. The third signed type,
 * `recovery_key_rotation`, is NOT handled here: it changes the recovery
 * trust anchor, pinned at [ProvisioningKeys.RECOVERY_PUBKEY_B64U] and
 * requiring an APK rebuild. A runtime handler would introduce a second
 * update path for the trust anchor. See registry §B P1-036 line 263.
 *
 * **Signature authority (per §B lines 265-266, 292; Build Master §3.6
 * §1; ADR §2 Q6; Z-20 D1).** Both notice types verify against the
 * recovery key. §B line 285 says `key_rotation` verifies "against
 * `current_provisioning_pubkey`" — residual pre-Z-20 drift. Implementing
 * it would let a provisioning key authorize its own rotation
 * (escape-from-revocation). The objective bullet is authoritative.
 *
 * **Verify-on-write, trust-on-read.** Both handlers verify before any
 * state write. Reads via [ProvisioningKeys.currentTrustedProvisioningKeys]
 * do not re-verify. Same pattern as [ReplacementNoticeStore].
 *
 * **Fail-closed.** Every rejection makes no state change. Absent
 * `previous_provisioning_pubkey` + a matrix signed by a "future" key →
 * read gate rejects. §B lines 299-301.
 *
 * **Order guard (global).** Reject `recovery_key_version <=
 * highest_recovery_key_version`. Same monotonic counter across types.
 * `<=` (not `<`) rejects same-version conflicts — TEST-RECKEY-010.
 *
 * **Overlap closure.** Read-time: `now < overlapEndsAtMillis`. No timer,
 * no storage mutation. `overlapEndsAtMillis = effective_at +
 * overlap_window_seconds` (both from the notice). §B lines 297-298:
 * duration is data, not magic.
 *
 * **State ownership.** Effective key state lives in [ProvisioningKeys]
 * SecureStorage slots, not here. This class orchestrates verify →
 * order-guard → apply-to-state → bump [version]. Reads go through
 * [ProvisioningKeys] — a caller computing `trustedKeys` for
 * [MatrixStore.accept] does not need a [RecoveryNoticeStore] reference.
 *
 * **Reactivity.** [version] is a write-notification, not a data cache.
 * Same convention as [MatrixStore.version],
 * [IdentityChangeController.version], [VerificationFailureStore.version].
 *
 * Task: TASK-P1-036
 * Design: Build Master §3.6; ADR-PROVISIONING-001 §2 Q6
 */
class RecoveryNoticeStore(
    private val store: KeyValueStore,
    private val recoveryPubkey: PublicKey,
    private val failureLog: VerificationFailureStore? = null,
) {
    private val _version = MutableStateFlow(0L)
    val version: StateFlow<Long> = _version.asStateFlow()

    sealed class ApplyResult {
        data class Accepted(val recoveryKeyVersion: Int) : ApplyResult()
        data class Rejected(val reason: RejectReason, val detail: String = "") : ApplyResult()
    }

    enum class RejectReason { BAD_SIGNATURE, OUT_OF_ORDER }

    /**
     * Apply a `key_rotation` notice. On [ApplyResult.Accepted]:
     *  - previous ← effective current
     *  - current  ← notice.newProvisioningKey
     *  - overlap ends at effective_at + overlap_window_seconds
     *  - highest_recovery_key_version = notice.recoveryKeyVersion
     */
    fun recordKeyRotation(
        signed: SignedKeyRotationNotice,
        signatureBase64url: String,
    ): ApplyResult {
        if (!RecoveryNoticeSigner.verifyKeyRotation(signed, signatureBase64url, recoveryPubkey)) {
            logFailure("key_rotation", signed.toJsonMap())
            return ApplyResult.Rejected(RejectReason.BAD_SIGNATURE)
        }

        val noticeVersion = signed.notice.recoveryKeyVersion
        val highest = highestRecoveryKeyVersion()
        if (noticeVersion <= highest) {
            logFailure("key_rotation out_of_order", signed.toJsonMap())
            return ApplyResult.Rejected(RejectReason.OUT_OF_ORDER, "v=$noticeVersion <= highest=$highest")
        }

        val overlapEndsAtMillis =
            Instant.parse(signed.notice.effectiveAt).toEpochMilli() +
                signed.notice.overlapWindowSeconds * 1000L

        ProvisioningKeys.applyKeyRotation(
            store = store,
            oldCurrentPubkeyB64u = ProvisioningKeys.effectiveCurrentPubkey(store),
            newPubkeyB64u = signed.notice.newProvisioningKey,
            overlapEndsAtMillis = overlapEndsAtMillis,
        )
        store.put(ProvisioningKeys.STORAGE_KEY_HIGHEST_RECOVERY_KEY_VERSION, noticeVersion.toString())

        _version.value = _version.value + 1
        return ApplyResult.Accepted(noticeVersion)
    }

    /**
     * Apply a `key_revocation` notice. On [ApplyResult.Accepted]:
     *  - revoked fingerprint added to the revoked set
     *  - highest_recovery_key_version = notice.recoveryKeyVersion
     *
     * **Revoke-only.** `notice.newProvisioningKey` is parsed but not
     * installed. If the current key is revoked, the trusted set becomes
     * empty and all subsequent matrix accepts fail closed — the correct
     * terminal state until admin provisions a new key via a separate
     * `key_rotation`. Registry §B lines 292-294.
     *
     * Existing stored matrix is NOT cleared. §B line 294: reject
     * *new* matrices signed by the revoked key, preserve stored.
     */
    fun recordKeyRevocation(
        signed: SignedKeyRevocationNotice,
        signatureBase64url: String,
    ): ApplyResult {
        if (!RecoveryNoticeSigner.verifyKeyRevocation(signed, signatureBase64url, recoveryPubkey)) {
            logFailure("key_revocation", signed.toJsonMap())
            return ApplyResult.Rejected(RejectReason.BAD_SIGNATURE)
        }

        val noticeVersion = signed.notice.recoveryKeyVersion
        val highest = highestRecoveryKeyVersion()
        if (noticeVersion <= highest) {
            logFailure("key_revocation out_of_order", signed.toJsonMap())
            return ApplyResult.Rejected(RejectReason.OUT_OF_ORDER, "v=$noticeVersion <= highest=$highest")
        }

        ProvisioningKeys.addRevokedFingerprint(store, signed.notice.revokedProvisioningKeyId)
        store.put(ProvisioningKeys.STORAGE_KEY_HIGHEST_RECOVERY_KEY_VERSION, noticeVersion.toString())

        _version.value = _version.value + 1
        return ApplyResult.Accepted(noticeVersion)
    }

    fun highestRecoveryKeyVersion(): Int =
        store.get(ProvisioningKeys.STORAGE_KEY_HIGHEST_RECOVERY_KEY_VERSION)?.toIntOrNull() ?: 0

    /** Wipe all recovery-notice state. Reverts current key to BuildConfig default. */
    fun clear() {
        store.remove(ProvisioningKeys.STORAGE_KEY_CURRENT_PROVISIONING_PUBKEY)
        store.remove(ProvisioningKeys.STORAGE_KEY_PREVIOUS_PROVISIONING_PUBKEY)
        store.remove(ProvisioningKeys.STORAGE_KEY_PREVIOUS_PROVISIONING_PUBKEY_OVERLAP_ENDS_AT_MILLIS)
        store.remove(ProvisioningKeys.STORAGE_KEY_HIGHEST_RECOVERY_KEY_VERSION)
        store.remove(ProvisioningKeys.STORAGE_KEY_REVOKED_PROVISIONING_KEY_FINGERPRINTS)
        _version.value = _version.value + 1
    }

    private fun logFailure(reason: String, wrapper: Map<String, Any?>) {
        val canonical = jcsCanonicalizeString(wrapper).toByteArray(Charsets.UTF_8)
        failureLog?.record(
            artifactType = VerificationFailureStore.ArtifactType.NOTICE,
            reason = reason,
            canonicalBytes = canonical,
        )
    }
}