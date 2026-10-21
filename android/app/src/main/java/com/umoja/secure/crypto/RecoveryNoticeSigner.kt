package com.umoja.secure.crypto

import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.security.PrivateKey
import java.security.PublicKey
import java.security.Security
import java.security.Signature
import java.util.Base64

/**
 * Recovery-notice signing and verification per TASK-P1-035b.
 *
 * Twelve functions: for each of the three notice types, four entry
 * points:
 *
 *   digest()              — JCS-canonicalize wrapper, SHA-256 digest
 *   sign()                — sign the digest with a caller-supplied PrivateKey
 *   verify()              — verify against a caller-supplied PublicKey
 *   signWithDeviceKey()   — sign via a caller-supplied (digest -> sig) lambda
 *
 * Protocol per Build Master §3.8: JCS-canonicalize the wrapper,
 * SHA-256 digest, Ed25519 sign the 32-byte digest (the digest IS the
 * Ed25519 message), base64url no padding. Matches [MatrixSigner]'s
 * protocol exactly; the sign/verify primitives are delegated to
 * [MatrixSigner.matrixDigestRaw] and [MatrixSigner.verifyRaw] rather
 * than re-implementing SHA-256 and Ed25519 here.
 *
 * **Why two signing entry points (sign vs signWithDeviceKey).**
 * `sign()` is correct when the caller holds the private key. In
 * production the recovery key lives in the offline signer's Keystore
 * and is non-exportable — there is no `PrivateKey` to hand over.
 * [signWithDeviceKey] bridges that by taking a `(ByteArray) ->
 * ByteArray` function that performs the raw signing operation against
 * the SHA-256 digest. Same split as
 * [IdentityChangeAckSigner.signWithDeviceKey] (Session J), same
 * precedent: two entry points, two custody models, no convenience
 * overload hiding the constraint. The caller is responsible for the
 * signingFn's correctness; a failed underlying signing operation
 * propagates.
 *
 * **Provider registration.** [MatrixSigner]'s companion init registers
 * BouncyCastle on first class-load. Since every function here touches
 * [MatrixSigner] (for digest/verify), the provider is guaranteed
 * registered before `Signature.getInstance("Ed25519")` is called. A
 * defensive re-registration lives in this object's init for callers
 * that invoke a function here in isolation — idempotent, no cost.
 *
 * **Signature shape: fail-closed.** Every `verify*` function
 * delegates to [MatrixSigner.verifyRaw], which fails closed
 * (returns false) on malformed signatures — not base64url, or not
 * exactly 64 bytes — as well as on signature mismatch. Matches
 * [MatrixVerifier] (the client-side verifier for matrices), not
 * [MatrixSigner.verify] (whose throw-on-malformed contract is for
 * callers that have already parsed a typed notice, where a
 * malformed signature is a programming error). Callers here are
 * P1-036's wire-data consumer: bytes come from the network,
 * signatures may be attacker-controlled, and the correct response
 * to malformed input is `false` (reject the notice), not an
 * exception.
 *
 * Task: TASK-P1-035b
 * Build Master: §3.8 (signing protocol)
 * ADR: §2 Q6 (provisioning key compromise)
 * Depends: TASK-P1-035a (schema + 5 test vectors), TASK-P1-026
 *          (MatrixSigner primitives)
 */
object RecoveryNoticeSigner {

    init {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(BouncyCastleProvider())
        }
    }

    // ---------- key_rotation ----------

    /** JCS-canonicalize + SHA-256 of a [SignedKeyRotationNotice]. */
    fun keyRotationDigest(signed: SignedKeyRotationNotice): ByteArray {
        val canonical = jcsCanonicalizeString(signed.toJsonMap()).toByteArray(Charsets.UTF_8)
        return MatrixSigner.matrixDigestRaw(canonical)
    }

    /** Sign with a caller-supplied Ed25519 [PrivateKey]. Returns base64url. */
    fun signKeyRotation(
        signed: SignedKeyRotationNotice,
        privateKey: PrivateKey,
    ): String {
        val digest = keyRotationDigest(signed)
        val sig = Signature.getInstance("Ed25519")
        sig.initSign(privateKey)
        sig.update(digest)
        return Base64.getUrlEncoder().withoutPadding().encodeToString(sig.sign())
    }

    /** Verify against a caller-supplied Ed25519 [PublicKey]. Fails closed (returns false) on malformed or mismatched signatures. */
    fun verifyKeyRotation(
        signed: SignedKeyRotationNotice,
        signatureBase64url: String,
        publicKey: PublicKey,
    ): Boolean {
        val canonical = jcsCanonicalizeString(signed.toJsonMap()).toByteArray(Charsets.UTF_8)
        return MatrixSigner.verifyRaw(canonical, signatureBase64url, publicKey)
    }

    /**
     * Sign via a `(digest) -> signature` lambda. Production wires
     * `deviceKeyManager.sign(digest)`; tests wire any Ed25519 signer.
     * The [require] on `sigBytes.size` catches a misbehaving
     * `signingFn` as defense-in-depth.
     */
    fun signKeyRotationWithDeviceKey(
        signed: SignedKeyRotationNotice,
        signingFn: (ByteArray) -> ByteArray,
    ): String {
        val digest = keyRotationDigest(signed)
        val sigBytes = signingFn(digest)
        require(sigBytes.size == 64) {
            "signature: expected 64 bytes, got ${sigBytes.size}"
        }
        return Base64.getUrlEncoder().withoutPadding().encodeToString(sigBytes)
    }

    // ---------- key_revocation ----------

    /** JCS-canonicalize + SHA-256 of a [SignedKeyRevocationNotice]. */
    fun keyRevocationDigest(signed: SignedKeyRevocationNotice): ByteArray {
        val canonical = jcsCanonicalizeString(signed.toJsonMap()).toByteArray(Charsets.UTF_8)
        return MatrixSigner.matrixDigestRaw(canonical)
    }

    /** Sign with a caller-supplied Ed25519 [PrivateKey]. Returns base64url. */
    fun signKeyRevocation(
        signed: SignedKeyRevocationNotice,
        privateKey: PrivateKey,
    ): String {
        val digest = keyRevocationDigest(signed)
        val sig = Signature.getInstance("Ed25519")
        sig.initSign(privateKey)
        sig.update(digest)
        return Base64.getUrlEncoder().withoutPadding().encodeToString(sig.sign())
    }

    /** Verify against a caller-supplied Ed25519 [PublicKey]. Fails closed (returns false) on malformed or mismatched signatures. */
    fun verifyKeyRevocation(
        signed: SignedKeyRevocationNotice,
        signatureBase64url: String,
        publicKey: PublicKey,
    ): Boolean {
        val canonical = jcsCanonicalizeString(signed.toJsonMap()).toByteArray(Charsets.UTF_8)
        return MatrixSigner.verifyRaw(canonical, signatureBase64url, publicKey)
    }

    /** Sign via a `(digest) -> signature` lambda. Same contract as [signKeyRotationWithDeviceKey]. */
    fun signKeyRevocationWithDeviceKey(
        signed: SignedKeyRevocationNotice,
        signingFn: (ByteArray) -> ByteArray,
    ): String {
        val digest = keyRevocationDigest(signed)
        val sigBytes = signingFn(digest)
        require(sigBytes.size == 64) {
            "signature: expected 64 bytes, got ${sigBytes.size}"
        }
        return Base64.getUrlEncoder().withoutPadding().encodeToString(sigBytes)
    }

    // ---------- recovery_key_rotation ----------

    /** JCS-canonicalize + SHA-256 of a [SignedRecoveryKeyRotationNotice]. */
    fun recoveryKeyRotationDigest(signed: SignedRecoveryKeyRotationNotice): ByteArray {
        val canonical = jcsCanonicalizeString(signed.toJsonMap()).toByteArray(Charsets.UTF_8)
        return MatrixSigner.matrixDigestRaw(canonical)
    }

    /** Sign with a caller-supplied Ed25519 [PrivateKey]. Returns base64url. */
    fun signRecoveryKeyRotation(
        signed: SignedRecoveryKeyRotationNotice,
        privateKey: PrivateKey,
    ): String {
        val digest = recoveryKeyRotationDigest(signed)
        val sig = Signature.getInstance("Ed25519")
        sig.initSign(privateKey)
        sig.update(digest)
        return Base64.getUrlEncoder().withoutPadding().encodeToString(sig.sign())
    }

    /** Verify against a caller-supplied Ed25519 [PublicKey]. Fails closed (returns false) on malformed or mismatched signatures. */
    fun verifyRecoveryKeyRotation(
        signed: SignedRecoveryKeyRotationNotice,
        signatureBase64url: String,
        publicKey: PublicKey,
    ): Boolean {
        val canonical = jcsCanonicalizeString(signed.toJsonMap()).toByteArray(Charsets.UTF_8)
        return MatrixSigner.verifyRaw(canonical, signatureBase64url, publicKey)
    }

    /** Sign via a `(digest) -> signature` lambda. Same contract as [signKeyRotationWithDeviceKey]. */
    fun signRecoveryKeyRotationWithDeviceKey(
        signed: SignedRecoveryKeyRotationNotice,
        signingFn: (ByteArray) -> ByteArray,
    ): String {
        val digest = recoveryKeyRotationDigest(signed)
        val sigBytes = signingFn(digest)
        require(sigBytes.size == 64) {
            "signature: expected 64 bytes, got ${sigBytes.size}"
        }
        return Base64.getUrlEncoder().withoutPadding().encodeToString(sigBytes)
    }
}
