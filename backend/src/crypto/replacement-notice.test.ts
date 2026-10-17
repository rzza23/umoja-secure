/**
 * Tests for the replacement-notice schema + signing protocol.
 *
 * Mirrors Android ReplacementNoticeTest.kt. Uses fresh Ed25519 keypairs
 * for sign/verify round-trip; uses the R-series vectors for
 * cross-language canonicalization proof.
 *
 * Task: TASK-P1-030 030e-a
 * Build Master: §3.7, §3.8
 */
import { describe, it, expect } from 'vitest';
import { generateKeyPairSync, createHash } from 'node:crypto';
import { readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import {
  REPLACEMENT_NOTICE_DOMAIN,
  ReplacementNoticeError,
  validateReplacementNotice,
  signReplacementNotice,
  verifyReplacementNotice,
  replacementNoticeDigest,
  type SignedReplacementNotice,
} from './replacement-notice.js';
import { jcsCanonicalize } from './jcs.js';

const KEY_A = 'A'.repeat(43);
const KEY_B = 'B'.repeat(43);
const KEY_C = 'C'.repeat(43);
const KEY_D = 'D'.repeat(43);

function validNotice(): SignedReplacementNotice {
  return {
    domain: REPLACEMENT_NOTICE_DOMAIN,
    notice: {
      from_device_id: 'device-old-001',
      from_device_auth_key: KEY_A,
      to_device_id: 'device-new-002',
      to_device_auth_key: KEY_B,
      issued_at: '2026-10-17T00:00:00Z',
    },
  };
}

function findRepoRoot(): string {
  let dir = process.cwd();
  for (let i = 0; i < 12; i++) {
    if (existsSync(join(dir, 'UMOJA-SECURE-BUILD-MASTER.md'))) return dir;
    const parent = join(dir, '..');
    if (parent === dir) break;
    dir = parent;
  }
  throw new Error('could not find repo root');
}

describe('validateReplacementNotice', () => {
  it('TEST-REPLACEMENT-NOTICE-VALID accepts a well-formed notice', () => {
    const n = validNotice();
    expect(validateReplacementNotice(n)).toEqual(n);
  });

  it('TEST-REPLACEMENT-NOTICE-SELF-LOOP-REJECTED rejects from === to', () => {
    const n = validNotice();
    const mutated: SignedReplacementNotice = {
      ...n,
      notice: { ...n.notice, to_device_id: n.notice.from_device_id },
    };
    expect(() => validateReplacementNotice(mutated)).toThrow(ReplacementNoticeError);
    expect(() => validateReplacementNotice(mutated)).toThrow(/must differ/);
  });

  it('TEST-REPLACEMENT-NOTICE-BAD-DOMAIN-REJECTED rejects wrong domain', () => {
    const n = { ...validNotice(), domain: 'umoja.authorization-matrix.v1' };
    expect(() => validateReplacementNotice(n)).toThrow(/domain/);
  });

  it('TEST-REPLACEMENT-NOTICE-BAD-KEY-REJECTED rejects malformed auth key', () => {
    const n = validNotice();
    const mutated: SignedReplacementNotice = {
      ...n,
      notice: { ...n.notice, from_device_auth_key: 'too-short' },
    };
    expect(() => validateReplacementNotice(mutated)).toThrow(/from_device_auth_key/);
  });
});

describe('signing protocol', () => {
  it('TEST-REPLACEMENT-NOTICE-SIGN-VERIFY round-trips', () => {
    const { privateKey, publicKey } = generateKeyPairSync('ed25519');
    const n = validNotice();
    const sig = signReplacementNotice(n, privateKey);
    expect(verifyReplacementNotice(n, sig, publicKey)).toBe(true);
  });

  it('TEST-REPLACEMENT-NOTICE-TAMPER-REJECTED rejects modified notice', () => {
    const { privateKey, publicKey } = generateKeyPairSync('ed25519');
    const n = validNotice();
    const sig = signReplacementNotice(n, privateKey);
    const tampered: SignedReplacementNotice = {
      ...n,
      notice: { ...n.notice, to_device_id: 'device-new-999' },
    };
    expect(verifyReplacementNotice(tampered, sig, publicKey)).toBe(false);
  });
});

describe('cross-language vector agreement', () => {
  it('TEST-REPLACEMENT-NOTICE-VECTOR-R001 canonical bytes match', () => {
    const path = join(
      findRepoRoot(),
      'docs/reference/canonical-replacement-notice-test-vectors.json',
    );
    const doc = JSON.parse(readFileSync(path, 'utf8')) as {
      vectors: Array<Record<string, unknown>>;
    };
    const v = doc.vectors.find((x) => x.id === 'R-001');
    expect(v, 'R-001 vector missing').toBeDefined();

    const expected = v!.expected_canonical_bytes_utf8 as string | null;
    expect(
      expected,
      'R-001 expected_canonical_bytes_utf8 not populated — run generate-matrix-vectors.ts',
    ).not.toBeNull();

    const validated = validateReplacementNotice(v!.input_wrapper);
    const actual = jcsCanonicalize(validated).toString('utf8');
    expect(actual).toBe(expected);

    // Digest matches
    const expectedDigest = v!.expected_sha256_digest_hex as string;
    const actualDigest = createHash('sha256')
      .update(Buffer.from(actual, 'utf8'))
      .digest('hex');
    expect(actualDigest).toBe(expectedDigest);
    // Also matches what the module produces directly
    expect(replacementNoticeDigest(validated).toString('hex')).toBe(expectedDigest);

    // Signature verifies against embedded public key
    const pubRaw = Buffer.from(
      v!.expected_provisioning_public_key_base64url as string,
      'base64url',
    );
    const sig = v!.expected_ed25519_signature_base64url as string;
    expect(verifyReplacementNotice(validated, sig, pubRaw)).toBe(true);
  });
});
