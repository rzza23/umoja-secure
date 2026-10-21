/**
 * Recovery-notice signing and verification per TASK-P1-035a.
 *
 * Three notice types, all signed by the current recovery key, per
 * Build Master §3.6 and ADR-PROVISIONING-001 §2 Q6:
 *
 *   1. **key_rotation** — authorize a new provisioning key and open
 *      an overlap window during which matrices signed by either the
 *      previous or current provisioning key are accepted.
 *
 *   2. **key_revocation** — emergency revocation of a compromised
 *      provisioning key. Immediate; no overlap. Names the revoked
 *      key by fingerprint and the replacement key.
 *
 *   3. **recovery_key_rotation** — rotate the recovery key itself
 *      (vN → vN+1). Authorized by the current (vN) recovery key.
 *      Old and new are trusted for a documented overlap; the
 *      monotonicity rules in Build Master §3.6 step 5 prevent
 *      rollback after the window closes.
 *
 * Signed unit (three variants):
 *
 *   {"domain":"umoja.key-rotation.v1","notice":{...}}
 *   {"domain":"umoja.key-revocation.v1","notice":{...}}
 *   {"domain":"umoja.recovery-key-rotation.v1","notice":{...}}
 *
 * Protocol identical to the matrix (Build Master §3.8):
 *   1. JCS-canonicalize the wrapper.
 *   2. SHA-256 of the canonical bytes.
 *   3. Ed25519 sign the 32-byte digest.
 *   4. base64url, no padding.
 *
 * **Field-set completion for key_rotation.** Build Master §3.6 para 1
 * names only "the new provisioning key and the overlap window
 * duration" for key_rotation, whereas para 2 (revocation) enumerates
 * the full replay-protection set. A stale rotation notice replayed
 * after the overlap window closes would downgrade the trusted set
 * to an old key; that is a real attack. The key_rotation field set
 * is therefore completed by analogy with para 2: `nonce`,
 * `event_id`, `effective_at`, and `recovery_key_version` are
 * required for the same reason they are required on revocation.
 * The completion is documented here, not silent.
 *
 * **Fingerprint convention.** `revoked_provisioning_key_id` is the
 * base64url (no-pad) SHA-256 of the raw 32-byte revoked provisioning
 * public key, i.e. 43 chars. The client computes the same value from
 * its pinned current_provisioning_pubkey and compares. Same length
 * as a raw key, different semantics; documented here so a reader
 * does not confuse the two.
 *
 * Task: TASK-P1-035a
 * Build Master: §3.6 (rotation + revocation authority), §3.8 (protocol)
 * ADR: §2 Q6 (provisioning key compromise)
 */
import { createHash, sign, verify, createPublicKey, type KeyObject } from 'node:crypto';
import { jcsCanonicalize } from './jcs.js';

// Ed25519 SPKI DER header for a 32-byte raw public key. Mirrors
// MatrixSigner.SPKI_PREFIX in Kotlin and the constant in
// matrix-sign.ts + replacement-notice.ts. Node's createPublicKey does
// not accept { format: 'raw' } for Ed25519 in this version.
const ED25519_SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');

function rawEd25519PublicKey(raw: Buffer): KeyObject {
  if (raw.length !== 32) {
    throw new Error(`Ed25519 public key: expected 32 raw bytes, got ${raw.length}`);
  }
  return createPublicKey({
    key: Buffer.concat([ED25519_SPKI_PREFIX, raw]),
    format: 'der',
    type: 'spki',
  });
}

// ---------------------------------------------------------------------------
// Domain constants
// ---------------------------------------------------------------------------

export const KEY_ROTATION_DOMAIN = 'umoja.key-rotation.v1' as const;
export const KEY_REVOCATION_DOMAIN = 'umoja.key-revocation.v1' as const;
export const RECOVERY_KEY_ROTATION_DOMAIN = 'umoja.recovery-key-rotation.v1' as const;

// ---------------------------------------------------------------------------
// Notice interfaces
// ---------------------------------------------------------------------------

/**
 * Authorize a new provisioning key; open an overlap window.
 * Signed by the current recovery key.
 */
export interface KeyRotationNotice {
  /** New provisioning public key. Base64url no-pad, 32 bytes decoded. */
  readonly new_provisioning_key: string;
  /** Overlap window duration in seconds. Positive integer. */
  readonly overlap_window_seconds: number;
  /** When this rotation becomes effective. ISO 8601 UTC. */
  readonly effective_at: string;
  /** Replay-protection nonce. Opaque string. */
  readonly nonce: string;
  /** Replay-protection event id. Opaque string. */
  readonly event_id: string;
  /** Monotonic recovery-key version; see Build Master §3.6 step 5. */
  readonly recovery_key_version: number;
}

export interface SignedKeyRotationNotice {
  readonly domain: typeof KEY_ROTATION_DOMAIN;
  readonly notice: KeyRotationNotice;
}

/**
 * Emergency revoke a compromised provisioning key. Immediate; no
 * overlap. Signed by the current recovery key.
 */
export interface KeyRevocationNotice {
  /** base64url(SHA-256(raw 32-byte revoked provisioning pubkey)), 43 chars. */
  readonly revoked_provisioning_key_id: string;
  /** Replacement provisioning public key. Base64url no-pad, 32 bytes. */
  readonly new_provisioning_key: string;
  /** When this revocation becomes effective. ISO 8601 UTC. */
  readonly effective_at: string;
  /** Replay-protection nonce. */
  readonly nonce: string;
  /** Replay-protection event id. */
  readonly event_id: string;
  /** Monotonic recovery-key version. */
  readonly recovery_key_version: number;
}

export interface SignedKeyRevocationNotice {
  readonly domain: typeof KEY_REVOCATION_DOMAIN;
  readonly notice: KeyRevocationNotice;
}

/**
 * Rotate the recovery key itself (vN → vN+1). Signed by the
 * current (vN) recovery key. Both are trusted during the overlap
 * window; monotonicity prevents rollback after.
 */
export interface RecoveryKeyRotationNotice {
  /** New recovery public key. Base64url no-pad, 32 bytes. */
  readonly new_recovery_key: string;
  /** New version (N+1). Must strictly exceed `recovery_key_version`. */
  readonly new_recovery_key_version: number;
  /** When this rotation becomes effective. ISO 8601 UTC. */
  readonly effective_at: string;
  /** Replay-protection nonce. */
  readonly nonce: string;
  /** Replay-protection event id. */
  readonly event_id: string;
  /** Version of the signing (old) recovery key. */
  readonly recovery_key_version: number;
}

export interface SignedRecoveryKeyRotationNotice {
  readonly domain: typeof RECOVERY_KEY_ROTATION_DOMAIN;
  readonly notice: RecoveryKeyRotationNotice;
}

// ---------------------------------------------------------------------------
// Error
// ---------------------------------------------------------------------------

export class RecoveryNoticeError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'RecoveryNoticeError';
  }
}

// ---------------------------------------------------------------------------
// Shared validators
// ---------------------------------------------------------------------------

const BASE64URL_RE = /^[A-Za-z0-9_-]+$/;
const ISO8601_UTC_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$/;

function requireString(value: unknown, field: string): string {
  if (typeof value !== 'string') {
    throw new RecoveryNoticeError(`${field}: expected string, got ${typeof value}`);
  }
  if (value.length === 0) {
    throw new RecoveryNoticeError(`${field}: empty string not permitted`);
  }
  return value;
}

function requireBase64Url32(value: unknown, field: string): string {
  const s = requireString(value, field);
  if (!BASE64URL_RE.test(s)) {
    throw new RecoveryNoticeError(
      `${field}: not base64url (no padding, [A-Za-z0-9_-] only)`,
    );
  }
  if (s.length !== 43) {
    throw new RecoveryNoticeError(
      `${field}: expected 43 base64url chars for 32 bytes, got ${s.length}`,
    );
  }
  const decoded = Buffer.from(s, 'base64url');
  if (decoded.length !== 32) {
    throw new RecoveryNoticeError(
      `${field}: decodes to ${decoded.length} bytes, expected 32`,
    );
  }
  return s;
}

function requireBase64UrlFingerprint(value: unknown, field: string): string {
  // Fingerprints are base64url(SHA-256(...)) = 43 chars for 32 bytes.
  // Same length as a raw key, but different semantics; the caller
  // is responsible for comparing against the right value.
  const s = requireString(value, field);
  if (!BASE64URL_RE.test(s)) {
    throw new RecoveryNoticeError(
      `${field}: not base64url (no padding, [A-Za-z0-9_-] only)`,
    );
  }
  if (s.length !== 43) {
    throw new RecoveryNoticeError(
      `${field}: expected 43 base64url chars for SHA-256 fingerprint, got ${s.length}`,
    );
  }
  return s;
}

function requirePositiveInteger(value: unknown, field: string): number {
  if (typeof value !== 'number' || !Number.isInteger(value) || value < 1) {
    throw new RecoveryNoticeError(
      `${field}: expected positive integer, got ${String(value)}`,
    );
  }
  return value;
}

function requireIso8601Utc(value: unknown, field: string): string {
  const s = requireString(value, field);
  if (!ISO8601_UTC_RE.test(s)) {
    throw new RecoveryNoticeError(
      `${field}: expected ISO 8601 UTC with trailing Z, got ${s}`,
    );
  }
  return s;
}

// ---------------------------------------------------------------------------
// Quartet 1: key_rotation
// ---------------------------------------------------------------------------

/**
 * Validate an unknown value as a SignedKeyRotationNotice.
 *
 * Field-set completion (see module KDoc): Build Master §3.6 para 1
 * names only the new provisioning key + overlap window, but the
 * replay-protection fields (nonce, event_id, effective_at,
 * recovery_key_version) are required by analogy with para 2.
 * A stale rotation notice replayed after the window closes would
 * downgrade the trusted set.
 *
 * @throws RecoveryNoticeError on any shape or content violation.
 */
export function validateKeyRotation(value: unknown): SignedKeyRotationNotice {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    throw new RecoveryNoticeError('key_rotation notice: expected object');
  }
  const w = value as Record<string, unknown>;

  if (w.domain !== KEY_ROTATION_DOMAIN) {
    throw new RecoveryNoticeError(
      `domain: expected "${KEY_ROTATION_DOMAIN}", got ${
        typeof w.domain === 'string' ? JSON.stringify(w.domain) : String(w.domain)
      }`,
    );
  }

  const n = w.notice;
  if (n === null || typeof n !== 'object' || Array.isArray(n)) {
    throw new RecoveryNoticeError('notice: expected object');
  }
  const nn = n as Record<string, unknown>;

  const new_provisioning_key = requireBase64Url32(
    nn.new_provisioning_key,
    'new_provisioning_key',
  );
  const overlap_window_seconds = requirePositiveInteger(
    nn.overlap_window_seconds,
    'overlap_window_seconds',
  );
  const effective_at = requireIso8601Utc(nn.effective_at, 'effective_at');
  const nonce = requireString(nn.nonce, 'nonce');
  const event_id = requireString(nn.event_id, 'event_id');
  const recovery_key_version = requirePositiveInteger(
    nn.recovery_key_version,
    'recovery_key_version',
  );

  return {
    domain: KEY_ROTATION_DOMAIN,
    notice: {
      new_provisioning_key,
      overlap_window_seconds,
      effective_at,
      nonce,
      event_id,
      recovery_key_version,
    },
  };
}

export function keyRotationDigest(
  signed: SignedKeyRotationNotice | unknown,
): Buffer {
  const validated = validateKeyRotation(signed);
  const canonical = jcsCanonicalize(validated);
  return createHash('sha256').update(canonical).digest();
}

export function signKeyRotation(
  signed: SignedKeyRotationNotice | unknown,
  privateKey: KeyObject,
): string {
  const digest = keyRotationDigest(signed);
  return sign(null, digest, privateKey).toString('base64url');
}

export function verifyKeyRotation(
  signed: SignedKeyRotationNotice | unknown,
  signatureBase64url: string,
  publicKey: KeyObject | Buffer,
): boolean {
  const digest = keyRotationDigest(signed);
  const sig = Buffer.from(signatureBase64url, 'base64url');
  if (sig.length !== 64) {
    throw new Error(`signature: expected 64 bytes, got ${sig.length}`);
  }
  const keyObj = publicKey instanceof Buffer ? rawEd25519PublicKey(publicKey) : publicKey;
  return verify(null, digest, keyObj, sig);
}

// ---------------------------------------------------------------------------
// Quartet 2: key_revocation
// ---------------------------------------------------------------------------

/**
 * Validate an unknown value as a SignedKeyRevocationNotice.
 *
 * Cross-field constraint: `revoked_provisioning_key_id` (fingerprint
 * of the revoked key) must not equal the SHA-256 fingerprint of
 * `new_provisioning_key`. A revocation whose replacement equals the
 * revoked key is a contradiction and would fail closed on the client
 * regardless; catching it here makes the validator reject early.
 *
 * @throws RecoveryNoticeError on any shape or content violation.
 */
export function validateKeyRevocation(
  value: unknown,
): SignedKeyRevocationNotice {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    throw new RecoveryNoticeError('key_revocation notice: expected object');
  }
  const w = value as Record<string, unknown>;

  if (w.domain !== KEY_REVOCATION_DOMAIN) {
    throw new RecoveryNoticeError(
      `domain: expected "${KEY_REVOCATION_DOMAIN}", got ${
        typeof w.domain === 'string' ? JSON.stringify(w.domain) : String(w.domain)
      }`,
    );
  }

  const n = w.notice;
  if (n === null || typeof n !== 'object' || Array.isArray(n)) {
    throw new RecoveryNoticeError('notice: expected object');
  }
  const nn = n as Record<string, unknown>;

  const revoked_provisioning_key_id = requireBase64UrlFingerprint(
    nn.revoked_provisioning_key_id,
    'revoked_provisioning_key_id',
  );
  const new_provisioning_key = requireBase64Url32(
    nn.new_provisioning_key,
    'new_provisioning_key',
  );
  const effective_at = requireIso8601Utc(nn.effective_at, 'effective_at');
  const nonce = requireString(nn.nonce, 'nonce');
  const event_id = requireString(nn.event_id, 'event_id');
  const recovery_key_version = requirePositiveInteger(
    nn.recovery_key_version,
    'recovery_key_version',
  );

  const newKeyFingerprint = createHash('sha256')
    .update(Buffer.from(new_provisioning_key, 'base64url'))
    .digest()
    .toString('base64url');
  if (revoked_provisioning_key_id === newKeyFingerprint) {
    throw new RecoveryNoticeError(
      'revoked_provisioning_key_id equals fingerprint of new_provisioning_key; ' +
        'a revocation cannot name the replacement as the revoked key',
    );
  }

  return {
    domain: KEY_REVOCATION_DOMAIN,
    notice: {
      revoked_provisioning_key_id,
      new_provisioning_key,
      effective_at,
      nonce,
      event_id,
      recovery_key_version,
    },
  };
}

export function keyRevocationDigest(
  signed: SignedKeyRevocationNotice | unknown,
): Buffer {
  const validated = validateKeyRevocation(signed);
  const canonical = jcsCanonicalize(validated);
  return createHash('sha256').update(canonical).digest();
}

export function signKeyRevocation(
  signed: SignedKeyRevocationNotice | unknown,
  privateKey: KeyObject,
): string {
  const digest = keyRevocationDigest(signed);
  return sign(null, digest, privateKey).toString('base64url');
}

export function verifyKeyRevocation(
  signed: SignedKeyRevocationNotice | unknown,
  signatureBase64url: string,
  publicKey: KeyObject | Buffer,
): boolean {
  const digest = keyRevocationDigest(signed);
  const sig = Buffer.from(signatureBase64url, 'base64url');
  if (sig.length !== 64) {
    throw new Error(`signature: expected 64 bytes, got ${sig.length}`);
  }
  const keyObj = publicKey instanceof Buffer ? rawEd25519PublicKey(publicKey) : publicKey;
  return verify(null, digest, keyObj, sig);
}

// ---------------------------------------------------------------------------
// Quartet 3: recovery_key_rotation
// ---------------------------------------------------------------------------

/**
 * Validate an unknown value as a SignedRecoveryKeyRotationNotice.
 *
 * Cross-field constraint: `new_recovery_key_version` must strictly
 * exceed `recovery_key_version` (Build Master §3.6 step 5: the new
 * version is monotonic; a same-version or lower-version rotation
 * cannot be a rotation). Catching it here prevents a client from
 * receiving a notice that could only fail at application time.
 *
 * @throws RecoveryNoticeError on any shape or content violation.
 */
export function validateRecoveryKeyRotation(
  value: unknown,
): SignedRecoveryKeyRotationNotice {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    throw new RecoveryNoticeError('recovery_key_rotation notice: expected object');
  }
  const w = value as Record<string, unknown>;

  if (w.domain !== RECOVERY_KEY_ROTATION_DOMAIN) {
    throw new RecoveryNoticeError(
      `domain: expected "${RECOVERY_KEY_ROTATION_DOMAIN}", got ${
        typeof w.domain === 'string' ? JSON.stringify(w.domain) : String(w.domain)
      }`,
    );
  }

  const n = w.notice;
  if (n === null || typeof n !== 'object' || Array.isArray(n)) {
    throw new RecoveryNoticeError('notice: expected object');
  }
  const nn = n as Record<string, unknown>;

  const new_recovery_key = requireBase64Url32(
    nn.new_recovery_key,
    'new_recovery_key',
  );
  const new_recovery_key_version = requirePositiveInteger(
    nn.new_recovery_key_version,
    'new_recovery_key_version',
  );
  const effective_at = requireIso8601Utc(nn.effective_at, 'effective_at');
  const nonce = requireString(nn.nonce, 'nonce');
  const event_id = requireString(nn.event_id, 'event_id');
  const recovery_key_version = requirePositiveInteger(
    nn.recovery_key_version,
    'recovery_key_version',
  );

  if (new_recovery_key_version <= recovery_key_version) {
    throw new RecoveryNoticeError(
      `new_recovery_key_version (${new_recovery_key_version}) must strictly ` +
        `exceed recovery_key_version (${recovery_key_version})`,
    );
  }

  return {
    domain: RECOVERY_KEY_ROTATION_DOMAIN,
    notice: {
      new_recovery_key,
      new_recovery_key_version,
      effective_at,
      nonce,
      event_id,
      recovery_key_version,
    },
  };
}

export function recoveryKeyRotationDigest(
  signed: SignedRecoveryKeyRotationNotice | unknown,
): Buffer {
  const validated = validateRecoveryKeyRotation(signed);
  const canonical = jcsCanonicalize(validated);
  return createHash('sha256').update(canonical).digest();
}

export function signRecoveryKeyRotation(
  signed: SignedRecoveryKeyRotationNotice | unknown,
  privateKey: KeyObject,
): string {
  const digest = recoveryKeyRotationDigest(signed);
  return sign(null, digest, privateKey).toString('base64url');
}

export function verifyRecoveryKeyRotation(
  signed: SignedRecoveryKeyRotationNotice | unknown,
  signatureBase64url: string,
  publicKey: KeyObject | Buffer,
): boolean {
  const digest = recoveryKeyRotationDigest(signed);
  const sig = Buffer.from(signatureBase64url, 'base64url');
  if (sig.length !== 64) {
    throw new Error(`signature: expected 64 bytes, got ${sig.length}`);
  }
  const keyObj = publicKey instanceof Buffer ? rawEd25519PublicKey(publicKey) : publicKey;
  return verify(null, digest, keyObj, sig);
}
