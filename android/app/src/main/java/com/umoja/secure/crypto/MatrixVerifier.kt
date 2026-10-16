package com.umoja.secure.crypto

import java.security.PublicKey

/**
 * Verify a signed authorization matrix against a trusted set of
 * provisioning public keys.
 *
 * Per Build Master §3.6 and ADR-PROVISIONING-001 §3, matrices are
 * verified against the currently-trusted provisioning key(s). During a
 * rotation overlap window the set contains both the previous and the
 * current keys; otherwise it is a singleton. For Phase 1 the set is
 * always a singleton — no rotation occurs in a fresh deployment.
 *
 * The recovery key does NOT participate in matrix verification. It
 * verifies key_rotation and key_revocation notices only. Passing a
 * recovery key here is a programming error; it will not match a valid
 * provisioning signature.
 *
 * Trust derives from the signature and the pinned key, not from the
 * transport. Callers may obtain [canonical] and [signatureBase64url]
 * over any channel — the transport does not need to be trusted.
 * See THREAT-MODEL-001 §7 and ADR §2 Q3.
 *
 * Stateless. Does not touch the filesystem and does NOT enforce
 * anti-rollback: that is a policy check performed by MatrixStore.accept
 * after verification succeeds. Keeping verification pure means the
 * policy rule cannot be bypassed by calling the verifier directly.
 *
 * Task: TASK-P1-026
 * Build Master: §3.6, §3.8
 * ADR: §3
 */
object MatrixVerifier {

    /**
     * Verify [canonical] (the JCS-canonical bytes of the wrapper) against
     * [signatureBase64url] using any key in [trustedKeys].
     *
     * Returns true on the first successful verification. Returns false if
     * the signature is malformed or matches no key. Throws only if a
     * [trustedKeys] entry is malformed, which is a programming error.
     *
     * Fails closed: an empty set returns false.
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
