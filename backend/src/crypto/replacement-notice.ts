/**
 * Replacement-notice signing and verification per TASK-P1-030 030e-a.
 *
 * A replacement notice is a domain-separated artifact separate from the
 * authorization matrix. It claims continuity of a person across a
 * device replacement: "D_old (with this auth key) has been replaced by
 * D_new (with this auth key)."
 *
 * Semantics: NOT an authorization claim (that is the matrix's job).
 * The peer receives the signed notice, verifies it against the pinned
 * provisioning key set, and asks the human "do you recognize this
 * replacement?" The ack is a separate artifact, signed by the peer.
 *
 * Signed unit:
 *
 *   {"domain":"umoja.replacement-notice.v1","notice":{...}}
 *
 * Protocol identical to the matrix (Build Master §3.8):
 *   1. JCS-canonicalize the wrapper.
 *   2. SHA-256 of the canonical bytes.
 *   3. Ed25519 sign the 32-byte digest.
 *   4. base64url, no padding.
 *
 * Task: TASK-P1-030 030e-a
 * Build Master: §3.7
 */
import { createHash, sign, verify, createPublicKey, type KeyObject } from 'node:crypto';

// Ed25519 SPKI DER header for a 32-byte raw public key. Mirrors
// MatrixSigner.SPKI_PREFIX in Kotlin. Node's createPublicKey does not
// accept {format: 'raw'} for Ed25519 in this version — SPKI DER wrapping
// is the correct path for both languages.
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
import { jcsCanonicalize } from './jcs.js';

export const REPLACEMENT_NOTICE_DOMAIN = 'umoja.replacement-notice.v1' as const;

export interface ReplacementNotice {
  readonly from_device_id: string;
  readonly from_device_auth_key: string;
  readonly to_device_id: string;
  readonly to_device_auth_key: string;
  readonly issued_at: string;
}

export interface SignedReplacementNotice {
  readonly domain: typeof REPLACEMENT_NOTICE_DOMAIN;
  readonly notice: ReplacementNotice;
}

export class ReplacementNoticeError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ReplacementNoticeError';
  }
}

const BASE64URL_RE = /^[A-Za-z0-9_-]+$/;
const ISO8601_UTC_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$/;

function requireString(value: unknown, field: string): string {
  if (typeof value !== 'string') {
    throw new ReplacementNoticeError(`${field}: expected string, got ${typeof value}`);
  }
  if (value.length === 0) {
    throw new ReplacementNoticeError(`${field}: empty string not permitted`);
  }
  return value;
}

function requireBase64Url32(value: unknown, field: string): string {
  const s = requireString(value, field);
  if (!BASE64URL_RE.test(s)) {
    throw new ReplacementNoticeError(
      `${field}: not base64url (no padding, [A-Za-z0-9_-] only)`,
    );
  }
  if (s.length !== 43) {
    throw new ReplacementNoticeError(
      `${field}: expected 43 base64url chars for 32 bytes, got ${s.length}`,
    );
  }
  const decoded = Buffer.from(s, 'base64url');
  if (decoded.length !== 32) {
    throw new ReplacementNoticeError(
      `${field}: decodes to ${decoded.length} bytes, expected 32`,
    );
  }
  return s;
}

/**
 * Validate an unknown value as a SignedReplacementNotice.
 *
 * @throws ReplacementNoticeError on any shape or content violation.
 */
export function validateReplacementNotice(
  value: unknown,
): SignedReplacementNotice {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    throw new ReplacementNoticeError('replacement notice: expected object');
  }
  const w = value as Record<string, unknown>;

  if (w.domain !== REPLACEMENT_NOTICE_DOMAIN) {
    throw new ReplacementNoticeError(
      `domain: expected "${REPLACEMENT_NOTICE_DOMAIN}", got ${
        typeof w.domain === 'string' ? JSON.stringify(w.domain) : String(w.domain)
      }`,
    );
  }

  const n = w.notice;
  if (n === null || typeof n !== 'object' || Array.isArray(n)) {
    throw new ReplacementNoticeError('notice: expected object');
  }
  const nn = n as Record<string, unknown>;

  const from_device_id = requireString(nn.from_device_id, 'from_device_id');
  const from_device_auth_key = requireBase64Url32(
    nn.from_device_auth_key,
    'from_device_auth_key',
  );
  const to_device_id = requireString(nn.to_device_id, 'to_device_id');
  const to_device_auth_key = requireBase64Url32(
    nn.to_device_auth_key,
    'to_device_auth_key',
  );
  const issued_at = requireString(nn.issued_at, 'issued_at');

  if (from_device_id === to_device_id) {
    throw new ReplacementNoticeError(
      'from_device_id and to_device_id must differ',
    );
  }
  if (!ISO8601_UTC_RE.test(issued_at)) {
    throw new ReplacementNoticeError(
      `issued_at: expected ISO 8601 UTC with trailing Z, got ${issued_at}`,
    );
  }

  return {
    domain: REPLACEMENT_NOTICE_DOMAIN,
    notice: {
      from_device_id,
      from_device_auth_key,
      to_device_id,
      to_device_auth_key,
      issued_at,
    },
  };
}

/**
 * SHA-256 digest of the JCS-canonical wrapper. Exposed separately so
 * callers can inspect the exact signed bytes.
 */
export function replacementNoticeDigest(
  signed: SignedReplacementNotice | unknown,
): Buffer {
  const validated = validateReplacementNotice(signed);
  const canonical = jcsCanonicalize(validated);
  return createHash('sha256').update(canonical).digest();
}

/**
 * Sign a SignedReplacementNotice. Returns base64url (no padding) of the
 * 64-byte Ed25519 signature.
 */
export function signReplacementNotice(
  signed: SignedReplacementNotice | unknown,
  privateKey: KeyObject,
): string {
  const digest = replacementNoticeDigest(signed);
  return sign(null, digest, privateKey).toString('base64url');
}

/**
 * Verify a SignedReplacementNotice signature.
 *
 * @param publicKey — KeyObject or raw 32-byte Buffer.
 * @returns true on valid signature. Does not throw on bad sig; only on
 *   malformed inputs (wrong sig length, etc).
 */
export function verifyReplacementNotice(
  signed: SignedReplacementNotice | unknown,
  signatureBase64url: string,
  publicKey: KeyObject | Buffer,
): boolean {
  const digest = replacementNoticeDigest(signed);
  const sig = Buffer.from(signatureBase64url, 'base64url');
  if (sig.length !== 64) {
    throw new Error(`signature: expected 64 bytes, got ${sig.length}`);
  }
  const keyObj = publicKey instanceof Buffer ? rawEd25519PublicKey(publicKey) : publicKey;
  return verify(null, digest, keyObj, sig);
}
