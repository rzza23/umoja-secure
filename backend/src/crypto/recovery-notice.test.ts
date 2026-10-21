/**
 * Tests for recovery-notice.ts (TASK-P1-035a).
 *
 * Coverage:
 *   - 5 test vectors (R-001..R-005) — canonical bytes, SHA-256 digest,
 *     Ed25519 signature match the populated expected_* fields. Covers
 *     all three notice types plus two boundary cases (min overlap,
 *     non-contiguous recovery key version).
 *   - TEST-RECKEY-001 through 006 — registry-named tests from P1-035
 *     section-B. The four cross-language tests (002, 003, 005, and
 *     the Kotlin half of 004) are split: this file proves the TS half;
 *     TASK-P1-035b proves Kotlin produces byte-identical output.
 *   - Per-type validator rejection: non-object, wrong domain, missing
 *     fields, malformed base64url / ISO / integer, cross-field
 *     constraints.
 *   - Sign/verify roundtrip per type (valid, tampered, wrong key,
 *     malformed sig length).
 *
 * Vectors live at docs/reference/canonical-recovery-notice-test-vectors.json,
 * populated by scripts/generate-matrix-vectors.ts. The test key is the
 * same HKDF-derived seed used by all test vector files.
 *
 * Prehash protocol (Build Master section 3.8): Ed25519 signs the
 * 32-byte SHA-256 digest of the JCS-canonical bytes, not the bytes
 * directly. Any deviation fails at the first vector test.
 */
import { describe, it, expect } from 'vitest';
import { createPrivateKey, createPublicKey, createHash, hkdfSync, type KeyObject } from 'node:crypto';
import { readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import {
  KEY_ROTATION_DOMAIN,
  KEY_REVOCATION_DOMAIN,
  RECOVERY_KEY_ROTATION_DOMAIN,
  validateKeyRotation,
  keyRotationDigest,
  signKeyRotation,
  verifyKeyRotation,
  validateKeyRevocation,
  keyRevocationDigest,
  signKeyRevocation,
  verifyKeyRevocation,
  validateRecoveryKeyRotation,
  recoveryKeyRotationDigest,
  signRecoveryKeyRotation,
  verifyRecoveryKeyRotation,
  RecoveryNoticeError,
} from './recovery-notice.js';
import { jcsCanonicalize } from './jcs.js';

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

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

const SEED_UTF8 = 'umoja-canonical-matrix-test-vectors-v1-DO-NOT-USE-IN-PRODUCTION';
const PKCS8_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');

function deriveTestPrivateKey(): KeyObject {
  const rawSeed = Buffer.from(
    hkdfSync('sha256', Buffer.from(SEED_UTF8, 'utf8'), Buffer.alloc(0), 'ed25519-test-key', 32),
  );
  const pkcs8 = Buffer.concat([PKCS8_PREFIX, rawSeed]);
  return createPrivateKey({ key: pkcs8, format: 'der', type: 'pkcs8' });
}

function rawPublicKey(priv: KeyObject): Buffer {
  const spki = createPublicKey(priv).export({ format: 'der', type: 'spki' }) as Buffer;
  return spki.subarray(spki.length - 32);
}

interface Vector {
  id: string;
  description: string;
  type: string;
  notice_type: 'key_rotation' | 'key_revocation' | 'recovery_key_rotation';
  input_wrapper: unknown;
  expected_canonical_bytes_utf8: string;
  expected_sha256_digest_hex: string;
  expected_ed25519_signature_base64url: string;
  expected_provisioning_public_key_base64url: string;
}

const VECTORS_PATH = join(
  findRepoRoot(),
  'docs/reference/canonical-recovery-notice-test-vectors.json',
);
const VECTORS_DOC = JSON.parse(readFileSync(VECTORS_PATH, 'utf8')) as {
  generated: boolean;
  vectors: Vector[];
  test_only_key_derivation: { expected_public_key_base64url: string };
};

const PRIV = deriveTestPrivateKey();
const PUB_RAW = rawPublicKey(PRIV);
const PUB_B64U = PUB_RAW.toString('base64url');

// ---------------------------------------------------------------------------
// Sanity: vectors populated + test key matches expected
// ---------------------------------------------------------------------------

describe('recovery-notice (TASK-P1-035a)', () => {
  it('TEST-RECKEY-001: derived test pubkey matches the vector file expected key', () => {
    expect(VECTORS_DOC.generated).toBe(true);
    expect(PUB_B64U).toBe(VECTORS_DOC.test_only_key_derivation.expected_public_key_base64url);
  });

  // -------------------------------------------------------------------------
  // Vector tests (R-001..R-005)
  // -------------------------------------------------------------------------

  for (const v of VECTORS_DOC.vectors) {
    it('vector ' + v.id + ': canonical, digest, and signature match expected', () => {
      // Recompute canonical / digest / signature from input_wrapper.
      // Each per-type validator's digest() is JCS(canonical(validate(input))),
      // so the recomputation is equivalent to what the schema does.
      const validator =
        v.notice_type === 'key_rotation' ? validateKeyRotation :
        v.notice_type === 'key_revocation' ? validateKeyRevocation :
        validateRecoveryKeyRotation;
      const digestFn =
        v.notice_type === 'key_rotation' ? keyRotationDigest :
        v.notice_type === 'key_revocation' ? keyRevocationDigest :
        recoveryKeyRotationDigest;
      const signer =
        v.notice_type === 'key_rotation' ? signKeyRotation :
        v.notice_type === 'key_revocation' ? signKeyRevocation :
        signRecoveryKeyRotation;
      const verifier =
        v.notice_type === 'key_rotation' ? verifyKeyRotation :
        v.notice_type === 'key_revocation' ? verifyKeyRevocation :
        verifyRecoveryKeyRotation;

      const validated = validator(v.input_wrapper);
      const digest = digestFn(validated);
      expect(digest.toString('hex')).toBe(v.expected_sha256_digest_hex);

      const sig = signer(validated, PRIV);
      expect(sig).toBe(v.expected_ed25519_signature_base64url);

      // Cross-check: verifier returns true for the vector's signature
      expect(verifier(validated, v.expected_ed25519_signature_base64url, PUB_RAW)).toBe(true);

      // Canonical bytes round-trip: the JCS form of the validated object
      // equals the stored canonical UTF-8.
      const canonical = jcsCanonicalize(validated);
      expect(canonical.toString('utf8')).toBe(v.expected_canonical_bytes_utf8);
    });
  }

  // -------------------------------------------------------------------------
  // TEST-RECKEY-002 / 003 / 005 — TS halves of cross-language vectors
  // -------------------------------------------------------------------------

  it('TEST-RECKEY-002: key_revocation signature verifies against test key (TS half of R-001)', () => {
    const v = VECTORS_DOC.vectors.find((x) => x.id === 'R-001');
    expect(v).toBeDefined();
    if (!v) return;
    const validated = validateKeyRevocation(v.input_wrapper);
    expect(
      verifyKeyRevocation(validated, v.expected_ed25519_signature_base64url, PUB_RAW),
    ).toBe(true);
  });

  it('TEST-RECKEY-003: key_rotation signature verifies against test key (TS half of R-002)', () => {
    const v = VECTORS_DOC.vectors.find((x) => x.id === 'R-002');
    expect(v).toBeDefined();
    if (!v) return;
    const validated = validateKeyRotation(v.input_wrapper);
    expect(
      verifyKeyRotation(validated, v.expected_ed25519_signature_base64url, PUB_RAW),
    ).toBe(true);
  });

  it('TEST-RECKEY-005: recovery_key_rotation signature verifies against test key (TS half of R-003)', () => {
    const v = VECTORS_DOC.vectors.find((x) => x.id === 'R-003');
    expect(v).toBeDefined();
    if (!v) return;
    const validated = validateRecoveryKeyRotation(v.input_wrapper);
    expect(
      verifyRecoveryKeyRotation(validated, v.expected_ed25519_signature_base64url, PUB_RAW),
    ).toBe(true);
  });

  // -------------------------------------------------------------------------
  // TEST-RECKEY-004 — self-rotation rejected
  // -------------------------------------------------------------------------

  it('TEST-RECKEY-004: key_rotation signed by a different (provisioning) key fails verification', () => {
    // Generate a second keypair — the "compromised provisioning key" —
    // and sign a well-formed key_rotation notice with it. A notice that
    // authorizes rotation must be signed by the recovery key; a
    // provisioning-key-signed rotation is self-rotation and must fail
    // verification against the recovery public key.
    const otherPriv = createPrivateKey({
      key: Buffer.concat([
        PKCS8_PREFIX,
        Buffer.from(hkdfSync('sha256', Buffer.from('different-seed', 'utf8'), Buffer.alloc(0), 'ed25519-test-key', 32)),
      ]),
      format: 'der',
      type: 'pkcs8',
    });
    const otherPubRaw = rawPublicKey(otherPriv);

    const notice = {
      domain: KEY_ROTATION_DOMAIN,
      notice: {
        new_provisioning_key: 'BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB',
        overlap_window_seconds: 2592000,
        effective_at: '2026-10-20T00:00:00Z',
        nonce: '00000000-0000-4000-8000-000000000099',
        event_id: '00000000-0000-4000-8000-0000000000e9',
        recovery_key_version: 1,
      },
    };

    const sigFromOtherKey = signKeyRotation(notice, otherPriv);

    // Signed by "provisioning" key (otherPriv), verified against "recovery"
    // key (PRIV): must fail.
    expect(verifyKeyRotation(notice, sigFromOtherKey, PUB_RAW)).toBe(false);

    // Sanity: the same signature verifies against the key that made it.
    expect(verifyKeyRotation(notice, sigFromOtherKey, otherPubRaw)).toBe(true);
  });

  // -------------------------------------------------------------------------
  // TEST-RECKEY-006 — recovery_key_version field + monotonicity invariant
  // -------------------------------------------------------------------------

  it('TEST-RECKEY-006: recovery_key_version round-trips; new_version <= old_version rejected', () => {
    const v = VECTORS_DOC.vectors.find((x) => x.id === 'R-003');
    expect(v).toBeDefined();
    if (!v) return;
    const validated = validateRecoveryKeyRotation(v.input_wrapper);
    expect(validated.notice.recovery_key_version).toBe(1);
    expect(validated.notice.new_recovery_key_version).toBe(2);

    // Same-version and lower-version rotations rejected by validator.
    const sameVersion = {
      ...validated.notice,
      new_recovery_key_version: validated.notice.recovery_key_version,
    };
    expect(() =>
      validateRecoveryKeyRotation({ domain: RECOVERY_KEY_ROTATION_DOMAIN, notice: sameVersion }),
    ).toThrow(RecoveryNoticeError);

    const lowerVersion = {
      ...validated.notice,
      new_recovery_key_version: validated.notice.recovery_key_version - 1,
    };
    // -1 would be 0 which is also non-positive; use a case where old is 5
    // and new is 4 to isolate the cross-field constraint from the
    // requirePositiveInteger check.
    expect(() =>
      validateRecoveryKeyRotation({
        domain: RECOVERY_KEY_ROTATION_DOMAIN,
        notice: {
          new_recovery_key: 'DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD',
          new_recovery_key_version: 4,
          effective_at: '2026-10-20T00:00:00Z',
          nonce: '00000000-0000-4000-8000-000000000099',
          event_id: '00000000-0000-4000-8000-0000000000e9',
          recovery_key_version: 5,
        },
      }),
    ).toThrow(/strictly exceed/);
  });

  // -------------------------------------------------------------------------
  // -------------------------------------------------------------------------
  // Validator rejections: key_rotation
  // -------------------------------------------------------------------------

  describe('validateKeyRotation rejections', () => {
    function validKR(): unknown {
      return {
        domain: KEY_ROTATION_DOMAIN,
        notice: {
          new_provisioning_key: 'BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB',
          overlap_window_seconds: 2592000,
          effective_at: '2026-10-20T00:00:00Z',
          nonce: 'n-1',
          event_id: 'e-1',
          recovery_key_version: 1,
        },
      };
    }

    it('rejects non-object', () => {
      expect(() => validateKeyRotation(null)).toThrow(RecoveryNoticeError);
      expect(() => validateKeyRotation('string')).toThrow(RecoveryNoticeError);
      expect(() => validateKeyRotation([])).toThrow(RecoveryNoticeError);
    });

    it('rejects wrong domain', () => {
      const v = validKR() as Record<string, unknown>;
      v.domain = KEY_REVOCATION_DOMAIN;
      expect(() => validateKeyRotation(v)).toThrow(/domain: expected/);
    });

    it('rejects malformed new_provisioning_key (wrong length)', () => {
      const v = validKR() as { notice: Record<string, unknown> };
      v.notice.new_provisioning_key = 'short';
      expect(() => validateKeyRotation(v)).toThrow(/expected 43 base64url/);
    });

    it('rejects zero overlap_window_seconds', () => {
      const v = validKR() as { notice: Record<string, unknown> };
      v.notice.overlap_window_seconds = 0;
      expect(() => validateKeyRotation(v)).toThrow(/expected positive integer/);
    });

    it('rejects non-ISO effective_at', () => {
      const v = validKR() as { notice: Record<string, unknown> };
      v.notice.effective_at = '2026-10-20 00:00:00';
      expect(() => validateKeyRotation(v)).toThrow(/expected ISO 8601 UTC/);
    });

    it('rejects non-positive recovery_key_version', () => {
      const v = validKR() as { notice: Record<string, unknown> };
      v.notice.recovery_key_version = -1;
      expect(() => validateKeyRotation(v)).toThrow(/expected positive integer/);
    });
  });

  // -------------------------------------------------------------------------
  // Validator rejections: key_revocation
  // -------------------------------------------------------------------------

  describe('validateKeyRevocation rejections', () => {
    function validKRV(): { domain: string; notice: Record<string, unknown> } {
      return {
        domain: KEY_REVOCATION_DOMAIN,
        notice: {
          revoked_provisioning_key_id: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
          new_provisioning_key: 'BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB',
          effective_at: '2026-10-20T00:00:00Z',
          nonce: 'n-1',
          event_id: 'e-1',
          recovery_key_version: 1,
        },
      };
    }

    it('rejects wrong domain', () => {
      const v = validKRV();
      v.domain = KEY_ROTATION_DOMAIN;
      expect(() => validateKeyRevocation(v)).toThrow(/domain: expected/);
    });

    it('rejects malformed revoked_provisioning_key_id (wrong length)', () => {
      const v = validKRV();
      v.notice.revoked_provisioning_key_id = 'short';
      expect(() => validateKeyRevocation(v)).toThrow(/expected 43 base64url/);
    });

    it('rejects when revoked_provisioning_key_id equals fingerprint of new_provisioning_key', () => {
      const newKeyRaw = Buffer.from(
        'BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB',
        'base64url',
      );
      const fingerprint = createHash('sha256')
        .update(newKeyRaw)
        .digest()
        .toString('base64url');
      const v = validKRV();
      v.notice.revoked_provisioning_key_id = fingerprint;
      expect(() => validateKeyRevocation(v)).toThrow(
        /revocation cannot name the replacement as the revoked key/,
      );
    });

    it('rejects missing new_provisioning_key', () => {
      const v = validKRV();
      delete v.notice.new_provisioning_key;
      expect(() => validateKeyRevocation(v)).toThrow(
        /new_provisioning_key: expected string, got undefined/,
      );
    });
  });

  // -------------------------------------------------------------------------
  // Validator rejections: recovery_key_rotation
  // -------------------------------------------------------------------------

  describe('validateRecoveryKeyRotation rejections', () => {
    function validRKR(): { domain: string; notice: Record<string, unknown> } {
      return {
        domain: RECOVERY_KEY_ROTATION_DOMAIN,
        notice: {
          new_recovery_key: 'DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD',
          new_recovery_key_version: 2,
          effective_at: '2026-10-20T00:00:00Z',
          nonce: 'n-1',
          event_id: 'e-1',
          recovery_key_version: 1,
        },
      };
    }

    it('rejects wrong domain', () => {
      const v = validRKR();
      v.domain = KEY_ROTATION_DOMAIN;
      expect(() => validateRecoveryKeyRotation(v)).toThrow(/domain: expected/);
    });

    it('rejects new_recovery_key_version == recovery_key_version', () => {
      const v = validRKR();
      v.notice.new_recovery_key_version = 1;
      expect(() => validateRecoveryKeyRotation(v)).toThrow(/must strictly exceed/);
    });

    it('rejects malformed new_recovery_key', () => {
      const v = validRKR();
      v.notice.new_recovery_key = 'not-43-chars';
      expect(() => validateRecoveryKeyRotation(v)).toThrow(/expected 43 base64url/);
    });

    it('rejects missing nonce', () => {
      const v = validRKR();
      delete v.notice.nonce;
      expect(() => validateRecoveryKeyRotation(v)).toThrow(
        /nonce: expected string, got undefined/,
      );
    });
  });

  // -------------------------------------------------------------------------
  // Sign/verify roundtrips per type
  // -------------------------------------------------------------------------

  describe('sign/verify roundtrips', () => {
    const notice = {
      domain: KEY_ROTATION_DOMAIN,
      notice: {
        new_provisioning_key: 'BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB',
        overlap_window_seconds: 2592000,
        effective_at: '2026-10-20T00:00:00Z',
        nonce: 'rt-nonce',
        event_id: 'rt-event',
        recovery_key_version: 1,
      },
    };

    it('key_rotation: tampered signature fails verification', () => {
      const sig = signKeyRotation(notice, PRIV);
      const sigBuf = Buffer.from(sig, 'base64url');
      // noUncheckedIndexedAccess: sigBuf[0] is number | undefined.
      // Extract, assert length (signKeyRotation guarantees 64 bytes),
      // write back. Pattern (a) from section 7's typed-query lessons.
      const firstByte = sigBuf[0];
      if (firstByte === undefined) {
        throw new Error('signKeyRotation returned an empty buffer — impossible');
      }
      sigBuf[0] = firstByte ^ 0xff;
      const tampered = sigBuf.toString('base64url');
      expect(verifyKeyRotation(notice, tampered, PUB_RAW)).toBe(false);
    });

    it('key_rotation: malformed signature length throws', () => {
      const shortSig = Buffer.alloc(32).toString('base64url');
      expect(() => verifyKeyRotation(notice, shortSig, PUB_RAW)).toThrow(
        /expected 64 bytes/,
      );
    });

    it('key_rotation: digest is deterministic across calls', () => {
      const d1 = keyRotationDigest(notice);
      const d2 = keyRotationDigest(notice);
      expect(d1.equals(d2)).toBe(true);
      expect(d1.length).toBe(32);
    });
  });
  // -------------------------------------------------------------------------
});
