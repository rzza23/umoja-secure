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
 * Uses Node built-in crypto (RFC 8032 Ed25519). No @noble/ed25519
 * dependency on this path — see KI-010 in the handoff. The vector
 * generator (scripts/generate-matrix-vectors.ts) uses the same library,
 * so it is consistent by construction.
 *
 * Task: TASK-P1-026
 * Build Master: §3.8
 * ADR: §3 (signing protocol)
 */
import { createHash, sign, verify, type KeyObject } from 'node:crypto';
import { jcsCanonicalize } from './jcs.js';
import { validateSignedMatrix, type SignedMatrix } from './matrix-schema.js';

/**
 * Compute the SHA-256 digest that gets signed.
 *
 * Exposed separately so callers (tests, cross-check tooling) can inspect
 * the exact bytes without signing.
 */
export function matrixDigest(signed: SignedMatrix | unknown): Buffer {
  // Re-validate even if the caller promises it's a SignedMatrix. Signing
  // a malformed object silently is exactly the kind of bug §3.8 exists
  // to prevent.
  const validated = validateSignedMatrix(signed);
  const canonical = jcsCanonicalize(validated);
  return createHash('sha256').update(canonical).digest();
}

/**
 * Sign a SignedMatrix. Returns base64url (no padding) of the 64-byte
 * Ed25519 signature.
 */
export function signMatrix(signed: SignedMatrix | unknown, privateKey: KeyObject): string {
  const digest = matrixDigest(signed);
  return sign(null, digest, privateKey).toString('base64url');
}

/**
 * Verify a SignedMatrix signature.
 *
 * @param publicKey — either a KeyObject or a raw 32-byte public key
 *   Buffer wrapped as {key, format:'raw'}.
 * @returns true if the signature verifies. Does NOT throw on a bad
 *   signature; only throws on malformed inputs.
 */
export function verifyMatrix(
  signed: SignedMatrix | unknown,
  signatureBase64url: string,
  publicKey: KeyObject | Buffer,
): boolean {
  const digest = matrixDigest(signed);
  const sig = Buffer.from(signatureBase64url, 'base64url');
  if (sig.length !== 64) {
    throw new Error(`signature: expected 64 bytes, got ${sig.length}`);
  }
  // Node accepts a raw 32-byte public key Buffer directly for Ed25519.
  const keyObj = publicKey instanceof Buffer
    ? ({ key: publicKey, format: 'raw' as const, type: 'spki' } as unknown as KeyObject)
    : publicKey;
  return verify(null, digest, keyObj, sig);
}
