package com.umoja.secure.crypto

import java.security.PrivateKey
import java.security.PublicKey
import java.security.Signature
import java.util.Base64

/**
 * Identity-change-ack signing and verification.
 *
 * Same protocol as the matrix and the replacement notice (§3.8):
 * canonicalize → SHA-256 digest → Ed25519 over the digest → base64url.
 * Byte-identical signatures to the TS counterpart
 * (backend/src/crypto/identity-change-ack.ts) for the same inputs,
 * proven by the A-001 vector test.
 *
 * Reuses [MatrixSigner.matrixDigestRaw] for the SHA-256 primitive so
 * all three artifact types share one digest implementation.
 * BouncyCastle provider already registered by MatrixSigner's init
 * block, and this path calls into MatrixSigner via digest before
 * Signature.getInstance("Ed25519"), so BC is loaded first.
 *
 * Client 030e-c uses `sign` (peer signs their own ack); the backend
 * does the verifying (see backend/src/identityChange/acks.ts). The
 * `verify` function is included for symmetry with ReplacementNoticeSigner
 * and for tests; the inbound-notice verifier is a separate concern
 * (ReplacementNoticeVerifier, commit 3 of 030e-c).
 *
 * Task: TASK-P1-030 030e-c
 * Build Master: §3.7, §3.8
 * ADR: ADR-IDENTITY-CHANGE-001 §3
 */
object IdentityChangeAckSigner {

    /** SHA-256 digest of the JCS-canonical wrapper. */
    fun digest(signed: SignedIdentityChangeAck): ByteArray {
        val canonical = jcsCanonicalizeString(signed.toJsonMap()).toByteArray(Charsets.UTF_8)
        return MatrixSigner.matrixDigestRaw(canonical)
    }

    /**
     * Sign a [SignedIdentityChangeAck]. Returns base64url (no padding)
     * of the 64-byte Ed25519 signature.
     */
    fun sign(signed: SignedIdentityChangeAck, privateKey: PrivateKey): String {
        val d = digest(signed)
        val sig = Signature.getInstance("Ed25519")
        sig.initSign(privateKey)
        sig.update(d)
        return Base64.getUrlEncoder().withoutPadding().encodeToString(sig.sign())
    }

    /**
     * Verify a [SignedIdentityChangeAck] signature.
     *
     * Contract: throws on malformed input (signature not base64url, or
     * not 64 bytes). Returns true/false for well-formed signatures.
     */
    fun verify(
        signed: SignedIdentityChangeAck,
        signatureBase64url: String,
        publicKey: PublicKey,
    ): Boolean {
        val sigBytes = Base64.getUrlDecoder().decode(signatureBase64url)
        require(sigBytes.size == 64) {
            "signature: expected 64 bytes, got ${sigBytes.size}"
        }
        val d = digest(signed)
        val sig = Signature.getInstance("Ed25519")
        sig.initVerify(publicKey)
        sig.update(d)
        return sig.verify(sigBytes)
    }
}
