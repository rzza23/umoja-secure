/**
 * Authorization matrix schema — the wire shape that gets signed.
 *
 * Signed unit per Build Master §3.8 and ADR-PROVISIONING-001 §3:
 *
 *   {"domain":"umoja.authorization-matrix.v1","matrix":{...}}
 *
 * The `domain` field provides domain separation. The wrapper — not the
 * inner matrix — is what JCS-canonicalizes, what SHA-256 digests, and
 * what Ed25519 signs.
 *
 * This module defines the shape and validates it. It does NOT do signing
 * or canonicalization. Those live in jcs.ts and (forthcoming) the signing
 * primitive. Keeping the boundaries separate means the shape can be
 * tested in isolation and the signer can trust its input.
 *
 * Task: TASK-P1-026
 * Build Master: §3.7, §3.8
 * ADR: §3 (signing protocol), §4 (schema)
 */

export const MATRIX_DOMAIN = 'umoja.authorization-matrix.v1' as const;

export interface AuthorizationMatrix {
  /** Monotonically increasing. Serialized by JCS as a bare integer. */
  readonly version: number;

  readonly device_id: string;

  /** Ed25519 device authentication public key. Base64url, no padding, 32 bytes decoded. */
  readonly pub_device_auth_key: string;

  /** Curve25519 libsignal identity public key. Base64url, no padding, 32 bytes decoded. */
  readonly pub_messaging_identity_key: string;

  /** Ed25519 wipe-confirmation public key. Base64url, no padding, 32 bytes decoded. */
  readonly pub_wipe_confirmation_key: string;

  readonly clearance: string;

  /** Order preserved by JCS. Do not sort. */
  readonly permitted_contacts: readonly string[];

  /** ISO 8601 UTC, e.g. "2026-10-14T00:00:00Z". */
  readonly issued_at: string;
}

export interface SignedMatrix {
  readonly domain: typeof MATRIX_DOMAIN;
  readonly matrix: AuthorizationMatrix;
}

export class MatrixSchemaError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'MatrixSchemaError';
  }
}

const BASE64URL_RE = /^[A-Za-z0-9_-]+$/;
const ISO8601_UTC_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$/;

function requireString(value: unknown, field: string): string {
  if (typeof value !== 'string') {
    throw new MatrixSchemaError(`${field}: expected string, got ${typeof value}`);
  }
  if (value.length === 0) {
    throw new MatrixSchemaError(`${field}: empty string not permitted`);
  }
  return value;
}

function requireBase64Url32(value: unknown, field: string): string {
  const s = requireString(value, field);
  if (!BASE64URL_RE.test(s)) {
    throw new MatrixSchemaError(`${field}: not base64url (no padding, [A-Za-z0-9_-] only)`);
  }
  // Decode length check: 32 bytes => 43 chars unpadded (32*8/6 = 42.67 -> 43).
  if (s.length !== 43) {
    throw new MatrixSchemaError(
      `${field}: expected 43 base64url chars for 32 bytes, got ${s.length}`,
    );
  }
  // Verify decode round-trips to exactly 32 bytes.
  const decoded = Buffer.from(s, 'base64url');
  if (decoded.length !== 32) {
    throw new MatrixSchemaError(`${field}: decodes to ${decoded.length} bytes, expected 32`);
  }
  return s;
}

function requirePositiveInteger(value: unknown, field: string): number {
  if (typeof value !== 'number' || !Number.isInteger(value) || value < 1) {
    throw new MatrixSchemaError(`${field}: expected positive integer, got ${String(value)}`);
  }
  return value;
}

/**
 * Validate an unknown value as an AuthorizationMatrix.
 *
 * @throws MatrixSchemaError on any shape or content violation.
 */
export function validateMatrix(value: unknown): AuthorizationMatrix {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    throw new MatrixSchemaError('matrix: expected object');
  }
  const m = value as Record<string, unknown>;

  const version = requirePositiveInteger(m.version, 'version');
  const device_id = requireString(m.device_id, 'device_id');
  const pub_device_auth_key = requireBase64Url32(m.pub_device_auth_key, 'pub_device_auth_key');
  const pub_messaging_identity_key = requireBase64Url32(
    m.pub_messaging_identity_key,
    'pub_messaging_identity_key',
  );
  const pub_wipe_confirmation_key = requireBase64Url32(
    m.pub_wipe_confirmation_key,
    'pub_wipe_confirmation_key',
  );
  const clearance = requireString(m.clearance, 'clearance');

  if (!Array.isArray(m.permitted_contacts)) {
    throw new MatrixSchemaError('permitted_contacts: expected array');
  }
  const permitted_contacts = m.permitted_contacts.map((c, i) =>
    requireString(c, `permitted_contacts[${i}]`),
  );

  const issued_at = requireString(m.issued_at, 'issued_at');
  if (!ISO8601_UTC_RE.test(issued_at)) {
    throw new MatrixSchemaError(`issued_at: expected ISO 8601 UTC with trailing Z, got ${issued_at}`);
  }

  return {
    version,
    device_id,
    pub_device_auth_key,
    pub_messaging_identity_key,
    pub_wipe_confirmation_key,
    clearance,
    permitted_contacts,
    issued_at,
  };
}

/**
 * Validate an unknown value as a SignedMatrix.
 *
 * @throws MatrixSchemaError on any shape or content violation.
 */
export function validateSignedMatrix(value: unknown): SignedMatrix {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    throw new MatrixSchemaError('signed matrix: expected object');
  }
  const s = value as Record<string, unknown>;

  if (s.domain !== MATRIX_DOMAIN) {
    throw new MatrixSchemaError(
      `domain: expected "${MATRIX_DOMAIN}", got ${typeof s.domain === 'string' ? JSON.stringify(s.domain) : String(s.domain)}`,
    );
  }

  return {
    domain: MATRIX_DOMAIN,
    matrix: validateMatrix(s.matrix),
  };
}
