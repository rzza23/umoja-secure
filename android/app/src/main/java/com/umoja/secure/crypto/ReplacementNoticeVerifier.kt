package com.umoja.secure.crypto

import java.security.PublicKey

/**
 * Verify an incoming signed replacement notice against a set of trusted
 * provisioning public keys.
 *
 * Per ADR-IDENTITY-CHANGE-001 §3, notices are signed by the provisioning
 * key (offline); the backend stores them verbatim without verifying
 * (§4 — server-blind), and peers verify on receipt against the pinned
 * provisioning key. Trust derives from the signature and the pinned
 * key, not from the transport.
 *
 * Takes raw canonical bytes, not the parsed object — mirrors
 * [MatrixVerifier]'s contract. The received bytes are what's checked;
 * a byte-level attacker who mutates whitespace or key order fails
 * verification even if the JSON is otherwise well-formed.
 *
 * Stateless. Does not touch the filesystem. Phase 1 uses a singleton
 * set constructed by the caller from [ProvisioningKeys]; the
 * [Set] seam exists for the rotation-overlap window (P1-036).
 *
 * The recovery key does NOT participate in notice verification —
 * notices are continuity claims signed by the provisioning key. The
 * recovery key verifies key_rotation / key_revocation notices only.
 *
 * Delegates the Ed25519 primitive to [MatrixSigner.verifyRaw] (fails
 * closed on malformed signature). The method name is matrix-specific
 * by history; the primitive is protocol-neutral and shared across all
 * three signed artifacts. A future consolidation into a neutral
 * `Ed25519Raw` object would move both verifiers together.
 *
 * Task: TASK-P1-030 030e-c 3b
 * ADR: ADR-IDENTITY-CHANGE-001 §3, §4
 */
object ReplacementNoticeVerifier {

    /**
     * Verify [canonical] against [signatureBase64url] using any key in
     * [trustedKeys].
     *
     * Returns true on the first successful verification. Returns false
     * if the signature is malformed or matches no key. Fails closed on
     * an empty set.
     */
    fun verify(
        canonical: ByteArray,
        signatureBase64url: String,
        trustedKeys: Set<PublicKey>,
    ): Boolean {
        if (trustedKeys.isEmpty()) return false
        for (key in trustedKeys) {
            if (MatrixSigner.verifyRaw(canonical, signatureBase64url, key)) {
                return true
            }
        }
        return false
    }
}
