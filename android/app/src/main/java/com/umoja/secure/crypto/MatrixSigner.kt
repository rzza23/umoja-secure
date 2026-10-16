package com.umoja.secure.crypto

import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.security.KeyFactory
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.PublicKey
import java.security.Security
import java.security.Signature
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import java.util.Base64

/**
 * Authorization-matrix signing and verification per Build Master §3.8.
 *
 * Protocol (exact):
 *   1. JCS-canonicalize the wrapper {domain,matrix}.
 *   2. SHA-256 of the canonical UTF-8 bytes.
 *   3. Ed25519 sign the 32-byte digest.
 *   4. Encode the 64-byte signature as base64url, no padding.
 *
 * IMPORTANT: Ed25519 signs the SHA-256 digest, NOT the canonical bytes
 * directly. Build Master v1.4.2 corrected §3.6 to align with §3.8 on
 * this point. Do NOT "simplify" by signing the canonical bytes.
 *
 * Counterpart: backend/src/crypto/matrix-sign.ts. Both must produce
 * byte-identical signatures for identical inputs.
 *
 * Uses BouncyCastle (bcprov-jdk18on, already declared) as the Ed25519
 * provider. Signature.getInstance("Ed25519") finds it once registered.
 *
 * Task: TASK-P1-026
 * Build Master: §3.8
 * ADR: §3 (signing protocol)
 */
object MatrixSigner {

    private val PKCS8_PREFIX = byteArrayOf(
        0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03,
        0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
    )

    private val SPKI_PREFIX = byteArrayOf(
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
    )

    init {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(BouncyCastleProvider())
        }
    }

    /**
     * SHA-256 of the given canonical bytes. The primitive underlying both
     * [matrixDigest] and [verifyRaw].
     *
     * Exposed so callers holding already-canonical bytes — e.g. a signed
     * matrix read back from storage — can recompute the digest without
     * re-canonicalizing. See MatrixStore KDoc: canonicalization runs once
     * at receipt; stored matrices are verified by hash-then-verify, never
     * by re-canonicalization.
     */
    fun matrixDigestRaw(canonical: ByteArray): ByteArray =
        MessageDigest.getInstance("SHA-256").digest(canonical)

    /**
     * Compute the SHA-256 digest that gets signed, from a parsed
     * [SignedMatrix]. Canonicalizes the wrapper first.
     *
     * Exposed so callers can inspect the exact bytes without signing.
     */
    fun matrixDigest(signed: SignedMatrix): ByteArray {
        val canonical = jcsCanonicalizeString(signed.toJsonMap()).toByteArray(Charsets.UTF_8)
        return matrixDigestRaw(canonical)
    }

    /**
     * Sign a SignedMatrix. Returns base64url (no padding) of the 64-byte
     * Ed25519 signature.
     */
    fun sign(signed: SignedMatrix, privateKey: PrivateKey): String {
        val digest = matrixDigest(signed)
        val sig = Signature.getInstance("Ed25519")
        sig.initSign(privateKey)
        sig.update(digest)
        return Base64.getUrlEncoder().withoutPadding().encodeToString(sig.sign())
    }

    /**
     * Verify a SignedMatrix signature.
     *
     * @return true if the signature verifies against [publicKey].
     *
     * Contract: throws on malformed input. The signature must decode as
     * base64url and yield exactly 64 bytes, else [IllegalArgumentException].
     * This is correct for callers who have already parsed a [SignedMatrix]
     * — a malformed signature there is a programming error, not attacker
     * input. Callers holding bytes directly from the wire use [verifyRaw],
     * which fails closed (returns false).
     */
    fun verify(signed: SignedMatrix, signatureBase64url: String, publicKey: PublicKey): Boolean {
        val sigBytes = Base64.getUrlDecoder().decode(signatureBase64url)
        require(sigBytes.size == 64) {
            "signature: expected 64 bytes, got ${sigBytes.size}"
        }
        val canonical = jcsCanonicalizeString(signed.toJsonMap()).toByteArray(Charsets.UTF_8)
        return verifyDigest(matrixDigestRaw(canonical), sigBytes, publicKey)
    }

    /**
     * Verify an Ed25519 signature over the SHA-256 digest of [canonical].
     *
     * Fails closed: returns false on a malformed signature (not base64url,
     * or wrong length), a signature mismatch, or any verification failure.
     * This is correct for callers holding bytes from the wire — malformed
     * signatures there are untrusted data. Throws only if [publicKey] is
     * malformed, which is a programming error.
     *
     * Low-level primitive. [verify] is the convenience wrapper that
     * canonicalizes a [SignedMatrix] first and throws on malformed input;
     * callers holding already-canonical bytes call this directly.
     */
    fun verifyRaw(
        canonical: ByteArray,
        signatureBase64url: String,
        publicKey: PublicKey,
    ): Boolean {
        val sigBytes = try {
            Base64.getUrlDecoder().decode(signatureBase64url)
        } catch (_: IllegalArgumentException) {
            return false
        }
        if (sigBytes.size != 64) return false
        return verifyDigest(matrixDigestRaw(canonical), sigBytes, publicKey)
    }

    /**
     * The primitive both [verify] and [verifyRaw] delegate to. Callers
     * have already decoded [sigBytes] and computed [digest].
     */
    private fun verifyDigest(
        digest: ByteArray,
        sigBytes: ByteArray,
        publicKey: PublicKey,
    ): Boolean {
        val sig = Signature.getInstance("Ed25519")
        sig.initVerify(publicKey)
        sig.update(digest)
        return sig.verify(sigBytes)
    }

    /**
     * Wrap a raw 32-byte Ed25519 public key as a [PublicKey]. Used to load
     * the pinned provisioning public key (base64url in the vector file,
     * decoded to raw bytes at use).
     */
    fun publicKeyFromRaw(raw: ByteArray): PublicKey {
        require(raw.size == 32) { "public key: expected 32 raw bytes, got ${raw.size}" }
        val der = SPKI_PREFIX + raw
        return KeyFactory.getInstance("Ed25519").generatePublic(X509EncodedKeySpec(der))
    }

    /**
     * Wrap a raw 32-byte Ed25519 private-key seed as a [PrivateKey].
     *
     * NOTE: for production, the provisioning private key lives in the
     * offline signer's Keystore, not as a raw seed. This is exposed for
     * test vectors and for the offline signer's import path.
     */
    fun privateKeyFromSeed(seed: ByteArray): PrivateKey {
        require(seed.size == 32) { "private key seed: expected 32 bytes, got ${seed.size}" }
        val der = PKCS8_PREFIX + seed
        return KeyFactory.getInstance("Ed25519").generatePrivate(PKCS8EncodedKeySpec(der))
    }
}
