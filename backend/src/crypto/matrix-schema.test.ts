/**
 * Tests for the authorization-matrix schema validator.
 *
 * These test shape only — not signing, not canonicalization. The signing
 * protocol is tested separately in the Ed25519 sign/verify tests.
 *
 * Task: TASK-P1-026
 * ADR:  §4 (schema)
 */
import { describe, it, expect } from 'vitest';
import {
  MATRIX_DOMAIN,
  MatrixSchemaError,
  validateMatrix,
  validateSignedMatrix,
  type AuthorizationMatrix,
  type SignedMatrix,
} from './matrix-schema.js';

// Fixed valid key material. 43 base64url chars decoding to 32 bytes.
const KEY_A = 'A'.repeat(43);
const KEY_B = 'B'.repeat(43);
const KEY_C = 'C'.repeat(43);

function validMatrix(): AuthorizationMatrix {
  return {
    version: 1,
    device_id: 'device-001',
    pub_device_auth_key: KEY_A,
    pub_messaging_identity_key: KEY_B,
    pub_wipe_confirmation_key: KEY_C,
    clearance: 'standard',
    permitted_contacts: ['device-002'],
    issued_at: '2026-10-14T00:00:00Z',
  };
}

describe('validateMatrix — accepts', () => {
  it('a fully valid matrix', () => {
    const m = validMatrix();
    expect(validateMatrix(m)).toEqual(m);
  });

  it('empty permitted_contacts', () => {
    const m = { ...validMatrix(), permitted_contacts: [] };
    expect(validateMatrix(m).permitted_contacts).toEqual([]);
  });

  it('issued_at with fractional seconds', () => {
    const m = { ...validMatrix(), issued_at: '2026-10-14T00:00:00.123Z' };
    expect(validateMatrix(m).issued_at).toBe('2026-10-14T00:00:00.123Z');
  });

  it('high version number', () => {
    const m = { ...validMatrix(), version: 999_999 };
    expect(validateMatrix(m).version).toBe(999_999);
  });
});

describe('validateMatrix — rejects', () => {
  it('non-object', () => {
    expect(() => validateMatrix(null)).toThrow(MatrixSchemaError);
    expect(() => validateMatrix('not an object')).toThrow(MatrixSchemaError);
    expect(() => validateMatrix([])).toThrow(MatrixSchemaError);
  });

  it('missing version', () => {
    const m = validMatrix() as unknown as Record<string, unknown>;
    delete m.version;
    expect(() => validateMatrix(m)).toThrow(/version/);
  });

  it('non-integer version', () => {
    expect(() => validateMatrix({ ...validMatrix(), version: 1.5 })).toThrow(/positive integer/);
  });

  it('zero version', () => {
    expect(() => validateMatrix({ ...validMatrix(), version: 0 })).toThrow(/positive integer/);
  });

  it('negative version', () => {
    expect(() => validateMatrix({ ...validMatrix(), version: -1 })).toThrow(/positive integer/);
  });

  it('empty device_id', () => {
    expect(() => validateMatrix({ ...validMatrix(), device_id: '' })).toThrow(/device_id/);
  });

  it('non-base64url pub_device_auth_key', () => {
    expect(() =>
      validateMatrix({ ...validMatrix(), pub_device_auth_key: 'has spaces' }),
    ).toThrow(/base64url/);
  });

  it('pub_device_auth_key with wrong length', () => {
    expect(() =>
      validateMatrix({ ...validMatrix(), pub_device_auth_key: 'AAAA' }),
    ).toThrow(/43 base64url chars/);
  });

  it('pub_device_auth_key that decodes to wrong byte count', () => {
    // 43 chars but not a valid 32-byte decode: swap a char to change value
    expect(() =>
      validateMatrix({ ...validMatrix(), pub_device_auth_key: '=' + 'A'.repeat(42) }),
    ).toThrow();
  });

  it('non-array permitted_contacts', () => {
    expect(() =>
      validateMatrix({ ...validMatrix(), permitted_contacts: 'not-an-array' }),
    ).toThrow(/array/);
  });

  it('non-string entry in permitted_contacts', () => {
    expect(() =>
      validateMatrix({ ...validMatrix(), permitted_contacts: [1] }),
    ).toThrow(/permitted_contacts\[0\]/);
  });

  it('issued_at without trailing Z', () => {
    expect(() =>
      validateMatrix({ ...validMatrix(), issued_at: '2026-10-14T00:00:00+00:00' }),
    ).toThrow(/ISO 8601 UTC/);
  });

  it('issued_at not a timestamp', () => {
    expect(() => validateMatrix({ ...validMatrix(), issued_at: 'yesterday' })).toThrow(
      /ISO 8601 UTC/,
    );
  });

  it('empty clearance', () => {
    expect(() => validateMatrix({ ...validMatrix(), clearance: '' })).toThrow(/clearance/);
  });
});

describe('validateSignedMatrix — accepts', () => {
  it('a fully valid signed matrix', () => {
    const s: SignedMatrix = { domain: MATRIX_DOMAIN, matrix: validMatrix() };
    expect(validateSignedMatrix(s)).toEqual(s);
  });
});

describe('validateSignedMatrix — rejects', () => {
  it('wrong domain', () => {
    expect(() =>
      validateSignedMatrix({ domain: 'umoja.something-else.v1', matrix: validMatrix() }),
    ).toThrow(/domain/);
  });

  it('missing domain', () => {
    expect(() => validateSignedMatrix({ matrix: validMatrix() })).toThrow(/domain/);
  });

  it('missing matrix', () => {
    expect(() => validateSignedMatrix({ domain: MATRIX_DOMAIN })).toThrow();
  });

  it('nested matrix fails its own validation', () => {
    expect(() =>
      validateSignedMatrix({ domain: MATRIX_DOMAIN, matrix: { version: -1 } }),
    ).toThrow();
  });
});
