package com.umoja.secure.crypto

import java.security.PrivateKey
import java.security.PublicKey
import java.security.Signature
import java.util.Base64

/**
 * Replacement-notice signing and verification.
 *
 * Same protocol as the matrix (§3.8): canonicalize → SHA-256 digest →
 * Ed25519 over the digest → base64url. Byte-identical signatures to the
 * TS counterpart (backend/src/crypto/replacement-notice.ts) for the same
 * inputs, proven by the R-001 vector test.
 *
 * Reuses [MatrixSigner.matrixDigestRaw] for the SHA-256 primitive so
 * both artifact types share one digest implementation. BouncyCastle
 * provider is registered by [MatrixSigner]'s init block; every path here
 * calls into MatrixSigner (via digest) before calling
 * `Signature.getInstance("Ed25519")`, so BC is loaded first.
 *
 * Task: TASK-P1-030 030e-a
 * Build Master: §3.7, §3.8
 */
object ReplacementNoticeSigner {

    /** SHA-256 digest of the JCS-canonical wrapper. */
    fun digest(signed: SignedReplacementNotice): ByteArray {
        val canonical = jcsCanonicalizeString(signed.toJsonMap()).toByteArray(Charsets.UTF_8)
        return MatrixSigner.matrixDigestRaw(canonical)
    }

    /**
     * Sign a [SignedReplacementNotice]. Returns base64url (no padding)
     * of the 64-byte Ed25519 signature.
     */
    fun sign(signed: SignedReplacementNotice, privateKey: PrivateKey): String {
        val d = digest(signed)
        val sig = Signature.getInstance("Ed25519")
        sig.initSign(privateKey)
        sig.update(d)
        return Base64.getUrlEncoder().withoutPadding().encodeToString(sig.sign())
    }

    /**
     * Verify a [SignedReplacementNotice] signature.
     *
     * Contract: throws on malformed input (signature not base64url, or
     * not 64 bytes). Returns true/false for well-formed signatures.
     * Callers holding wire bytes use the try/catch pattern in
     * [MatrixVerifier.verify] or wrap this directly.
     */
    fun verify(
        signed: SignedReplacementNotice,
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
