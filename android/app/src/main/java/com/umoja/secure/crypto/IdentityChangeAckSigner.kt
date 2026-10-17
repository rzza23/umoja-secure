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

    /**
     * Sign a [SignedIdentityChangeAck] using a device-held signing
     * function. **This is the production entry point.**
     *
     * [sign] takes a [PrivateKey], which is correct for test
     * derivation and the offline vector generator, but unusable in
     * production: the device auth key lives in Android Keystore and
     * is hardware-backed and non-exportable — there is no PrivateKey
     * to hand over. [signWithDeviceKey] bridges that by taking a
     * function that performs the raw signing operation. In production
     * this is `deviceKeyManager.sign(digest)`; in tests it is any
     * Ed25519 signing operation over the supplied digest.
     *
     * Two entry points, two custody models, no convenience overload
     * hiding the constraint. The [require] on [sigBytes].size catches
     * a misbehaving [signingFn] as defense-in-depth, mirroring
     * [verify]'s malformed-signature guard.
     *
     * The caller is responsible for [signingFn] correctness — this
     * function does not catch exceptions from it. A failed underlying
     * signing operation propagates; that is the caller's error to
     * handle, not the store's to swallow.
     */
    fun signWithDeviceKey(
        signed: SignedIdentityChangeAck,
        signingFn: (ByteArray) -> ByteArray,
    ): String {
        val digest = digest(signed)
        val sigBytes = signingFn(digest)
        require(sigBytes.size == 64) {
            "signature: expected 64 bytes, got ${sigBytes.size}"
        }
        return Base64.getUrlEncoder().withoutPadding().encodeToString(sigBytes)
    }
}
