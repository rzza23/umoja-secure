/**
 * Tests for the authorization-matrix signing protocol (Build Master §3.8).
 *
 * Uses the test-only key from canonical-matrix-test-vectors.json
 * (derived deterministically per the file's test_only_key_derivation
 * block). Verifies:
 *   - the protocol produces the same signature as the vector generator
 *   - tampering any byte of the wrapper invalidates verification
 *   - signing canonical bytes directly (skipping SHA-256 prehash) fails
 *   - a signature from a different key fails verification
 *
 * Task: TASK-P1-026
 */
import { describe, it, expect } from 'vitest';
import { readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import {
  createPrivateKey,
  createPublicKey,
  hkdfSync,
  type KeyObject,
} from 'node:crypto';
import { signMatrix, verifyMatrix, matrixDigest } from './matrix-sign.js';
import { MATRIX_DOMAIN, type SignedMatrix } from './matrix-schema.js';
import { jcsCanonicalize } from './jcs.js';

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

const ROOT = findRepoRoot();
const VECTORS_PATH = join(ROOT, 'docs/reference/canonical-matrix-test-vectors.json');
const SEED_UTF8 = 'umoja-canonical-matrix-test-vectors-v1-DO-NOT-USE-IN-PRODUCTION';
const PKCS8_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');

function testPrivateKey(): KeyObject {
  const seed = Buffer.from(
    hkdfSync('sha256', Buffer.from(SEED_UTF8, 'utf8'), Buffer.alloc(0), 'ed25519-test-key', 32),
  );
  return createPrivateKey({
    key: Buffer.concat([PKCS8_PREFIX, seed]),
    format: 'der',
    type: 'pkcs8',
  });
}

function testPublicKey(): KeyObject {
  return createPublicKey(testPrivateKey());
}

interface Vector {
  id: string;
  input_wrapper: unknown;
  expected_ed25519_signature_base64url: string;
  expected_provisioning_public_key_base64url: string;
}

const doc = JSON.parse(readFileSync(VECTORS_PATH, 'utf8')) as {
  generated: boolean;
  vectors: Vector[];
};

describe('matrix signing — against populated test vectors', () => {
  it('vectors file is generated', () => {
    expect(doc.generated).toBe(true);
  });

  for (const v of doc.vectors) {
    if (!v.expected_ed25519_signature_base64url) continue;

    it(`${v.id}: our signature matches the vector's stored signature`, () => {
      const sig = signMatrix(v.input_wrapper, testPrivateKey());
      expect(sig).toBe(v.expected_ed25519_signature_base64url);
    });

    it(`${v.id}: vector's signature verifies against the test public key`, () => {
      expect(
        verifyMatrix(v.input_wrapper, v.expected_ed25519_signature_base64url, testPublicKey()),
      ).toBe(true);
    });
  }
});

describe('matrix signing — tamper resistance', () => {
  const baseWrapper: SignedMatrix = {
    domain: MATRIX_DOMAIN,
    matrix: {
      version: 1,
      device_id: 'device-001',
      pub_device_auth_key: 'A'.repeat(43),
      pub_messaging_identity_key: 'B'.repeat(43),
      pub_wipe_confirmation_key: 'C'.repeat(43),
      clearance: 'standard',
      permitted_contacts: ['device-002'],
      issued_at: '2026-10-14T00:00:00Z',
    },
  };

  it('a valid signature verifies', () => {
    const sig = signMatrix(baseWrapper, testPrivateKey());
    expect(verifyMatrix(baseWrapper, sig, testPublicKey())).toBe(true);
  });

  it('flipping one character in device_id invalidates verification', () => {
    const sig = signMatrix(baseWrapper, testPrivateKey());
    const tampered: SignedMatrix = {
      ...baseWrapper,
      matrix: { ...baseWrapper.matrix, device_id: 'device-002' },
    };
    expect(verifyMatrix(tampered, sig, testPublicKey())).toBe(false);
  });

  it('changing version invalidates verification', () => {
    const sig = signMatrix(baseWrapper, testPrivateKey());
    const tampered: SignedMatrix = {
      ...baseWrapper,
      matrix: { ...baseWrapper.matrix, version: 2 },
    };
    expect(verifyMatrix(tampered, sig, testPublicKey())).toBe(false);
  });

  it('changing domain invalidates verification', () => {
    const sig = signMatrix(baseWrapper, testPrivateKey());
    // Domain is validated, so tampering it throws before verification.
    expect(() =>
      verifyMatrix({ ...baseWrapper, domain: 'umoja.wrong.v1' }, sig, testPublicKey()),
    ).toThrow();
  });

  it('swapping device-auth and messaging-identity keys invalidates verification', () => {
    const sig = signMatrix(baseWrapper, testPrivateKey());
    const tampered: SignedMatrix = {
      ...baseWrapper,
      matrix: {
        ...baseWrapper.matrix,
        pub_device_auth_key: baseWrapper.matrix.pub_messaging_identity_key,
        pub_messaging_identity_key: baseWrapper.matrix.pub_device_auth_key,
      },
    };
    expect(verifyMatrix(tampered, sig, testPublicKey())).toBe(false);
  });
});

describe('matrix signing — prehash is load-bearing', () => {
  const wrapper: SignedMatrix = {
    domain: MATRIX_DOMAIN,
    matrix: {
      version: 1,
      device_id: 'device-001',
      pub_device_auth_key: 'A'.repeat(43),
      pub_messaging_identity_key: 'B'.repeat(43),
      pub_wipe_confirmation_key: 'C'.repeat(43),
      clearance: 'standard',
      permitted_contacts: [],
      issued_at: '2026-10-14T00:00:00Z',
    },
  };

  it('signing the canonical bytes directly does NOT verify under the digest protocol', () => {
    // Construct a signature over the RAW canonical bytes (no SHA-256
    // prehash) — the deviation Build Master v1.4.2 exists to forbid.
    const { sign: nodeSign } = require('node:crypto') as typeof import('node:crypto');
    const canonical = jcsCanonicalize(wrapper);
    const badSig = nodeSign(null, canonical, testPrivateKey()).toString('base64url');

    // It must NOT verify under the digest protocol.
    expect(verifyMatrix(wrapper, badSig, testPublicKey())).toBe(false);
  });

  it('matrixDigest returns 32 bytes', () => {
    const d = matrixDigest(wrapper);
    expect(d.length).toBe(32);
  });

  it('matrixDigest is deterministic', () => {
    const a = matrixDigest(wrapper);
    const b = matrixDigest(wrapper);
    expect(a.equals(b)).toBe(true);
  });
});

describe('matrix signing — wrong key', () => {
  const wrapper: SignedMatrix = {
    domain: MATRIX_DOMAIN,
    matrix: {
      version: 1,
      device_id: 'device-001',
      pub_device_auth_key: 'A'.repeat(43),
      pub_messaging_identity_key: 'B'.repeat(43),
      pub_wipe_confirmation_key: 'C'.repeat(43),
      clearance: 'standard',
      permitted_contacts: [],
      issued_at: '2026-10-14T00:00:00Z',
    },
  };

  it('a signature from a different key does not verify', () => {
    const otherSeed = Buffer.from(
      hkdfSync('sha256', Buffer.from('different-seed'), Buffer.alloc(0), 'ed25519-test-key', 32),
    );
    const otherKey = createPrivateKey({
      key: Buffer.concat([PKCS8_PREFIX, otherSeed]),
      format: 'der',
      type: 'pkcs8',
    });
    const sig = signMatrix(wrapper, otherKey);
    expect(verifyMatrix(wrapper, sig, testPublicKey())).toBe(false);
  });
});
