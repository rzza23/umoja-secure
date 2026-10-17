/**
 * Route-level tests for GET /me/matrix.
 *
 * TASK-P1-037 (matrix transport). Backend does NOT verify the
 * provisioning signature (server-blind per ADR-PROVISIONING-001 §2
 * Q3); it relays the stored bytes verbatim. These tests prove the
 * transport contract: exact bytes stored == exact bytes returned,
 * and those bytes still verify against the pinned provisioning key.
 *
 * Fixture: W-001 from docs/reference/canonical-matrix-test-vectors.json.
 * Signed during Session A's vector generation by the test provisioning
 * key. TEST-MATRIX-VERIFY-ON-RECEIPT-BACKEND uses the same primitive
 * that produced the fixture (Node crypto Ed25519 over SHA-256 digest),
 * so a protocol drift would fail here, not silently in the field.
 *
 * Registry test-name mapping (registry v0.6 §B TASK-P1-037 lists 4):
 *   - TEST-MATRIX-TRANSPORT-FETCH       → this file (test 1)
 *   - TEST-MATRIX-CROSS-DEVICE-REJECTED → this file (test 2)
 *   - TEST-MATRIX-VERIFY-ON-RECEIPT     → this file, renamed
 *                                          -VERIFY-ON-RECEIPT-BACKEND
 *                                          (backend half of the
 *                                          registry test; client
 *                                          half is O-2)
 *   - TEST-MATRIX-STORE-ON-VERIFY-SUCCESS → NOT here; client-side,
 *                                            defers to O-2's JVM
 *                                            MatrixApiTest. Recorded
 *                                            in the O-2 handoff so a
 *                                            future reader does not
 *                                            think it went missing.
 *
 * Two additional tests beyond the registry list:
 *   - TEST-MATRIX-404-NO-MATRIX     (standard coverage)
 *   - TEST-MATRIX-401-UNAUTHENTICATED (standard coverage)
 *
 * Two orgs reserved:
 *   - TEST_ORG_ID   (...0c1) — primary
 *   - TEST_ORG_ID_2 (...0c2) — reserved for cross-org isolation if a
 *                              future matrix test needs it; declared
 *                              now to hold the number space per §7's
 *                              TEST_ORG_ID discipline.
 *
 * Devices accumulate keyed by random UUID (mirroring
 * identity-change.test.ts). Matrix rows are cleaned per test,
 * scoped by org so parallel files cannot interfere.
 */
import { describe, it, expect, beforeAll, afterAll, beforeEach } from 'vitest';
import {
  randomBytes,
  randomUUID,
  createHash,
  verify as cryptoVerify,
  createPublicKey,
  type KeyObject,
} from 'node:crypto';
import { readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import * as ed from '@noble/ed25519';
import { buildApp } from '../src/app.js';
import { pool } from '../src/db/client.js';
import { canonicalizeChallenge, type Challenge } from '../src/auth/canonical.js';

const TEST_ORG_ID = '00000000-0000-0000-0000-0000000000c1';
const TEST_ORG_ID_2 = '00000000-0000-0000-0000-0000000000c2';

// RFC 8410 §4 — SPKI DER prefix for a raw 32-byte Ed25519 pubkey.
// Matches matrix-sign.ts's ED25519_SPKI_PREFIX and Kotlin's
// MatrixSigner.SPKI_PREFIX. Used only to construct a KeyObject for
// cryptoVerify; the transport assertions above do not depend on it.
const ED25519_SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');

interface TestMatrixVector {
  canonical_utf8: string;
  canonical_bytes: Buffer;
  signature_base64url: string;
  pubkey_raw: Buffer;
  version: number;
}

let app: Awaited<ReturnType<typeof buildApp>>;
let w001: TestMatrixVector;

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

function pubkeyObjectFromRaw(raw: Buffer): KeyObject {
  return createPublicKey({
    key: Buffer.concat([ED25519_SPKI_PREFIX, raw]),
    format: 'der',
    type: 'spki',
  });
}

async function createDevice(
  org_id: string,
): Promise<{ device_id: string; privateKey: Uint8Array }> {
  const privateKey = randomBytes(32);
  const pubKey = await ed.getPublicKeyAsync(privateKey);
  const device_id = randomUUID();
  await pool.query(
    `INSERT INTO devices (device_id, org_id, public_key, label, role)
     VALUES ($1, $2, $3, $4, $5)`,
    [device_id, org_id, Buffer.from(pubKey), 'matrix-test', 'user'],
  );
  return { device_id, privateKey };
}

async function mintSession(
  device_id: string,
  privateKey: Uint8Array,
): Promise<string> {
  const chRes = await app.inject({
    method: 'POST',
    url: '/auth/challenge',
    payload: { device_id, purpose: 'auth' },
  });
  if (chRes.statusCode !== 200) {
    throw new Error(`challenge failed: ${chRes.statusCode} ${chRes.body}`);
  }
  const ch = chRes.json().challenge as Challenge;
  const signature = await ed.signAsync(canonicalizeChallenge(ch), privateKey);
  const verifyRes = await app.inject({
    method: 'POST',
    url: '/auth/verify',
    payload: {
      challenge_id: ch.challenge_id,
      signature: Buffer.from(signature).toString('base64url'),
    },
  });
  if (verifyRes.statusCode !== 200) {
    throw new Error(`verify failed: ${verifyRes.statusCode} ${verifyRes.body}`);
  }
  return verifyRes.json().session_token;
}

async function seedMatrix(
  device_id: string,
  canonical: Buffer,
  signature_b64u: string,
  version: number,
): Promise<void> {
  await pool.query(
    `INSERT INTO matrices (device_id, canonical_bytes, signature_base64url, version)
     VALUES ($1, $2, $3, $4)`,
    [device_id, canonical, signature_b64u, version],
  );
}

beforeAll(async () => {
  app = await buildApp();

  const path = join(
    findRepoRoot(),
    'docs/reference/canonical-matrix-test-vectors.json',
  );
  const doc = JSON.parse(readFileSync(path, 'utf8')) as {
    vectors: Array<{
      id: string;
      expected_canonical_bytes_utf8: string;
      expected_ed25519_signature_base64url: string;
      expected_provisioning_public_key_base64url: string;
    }>;
  };
  const w = doc.vectors.find((v) => v.id === 'W-001');
  if (!w) {
    throw new Error('W-001 not found in canonical-matrix-test-vectors.json');
  }

  const canonical_bytes = Buffer.from(w.expected_canonical_bytes_utf8, 'utf8');
  const parsed = JSON.parse(w.expected_canonical_bytes_utf8) as {
    matrix: { version: number };
  };
  w001 = {
    canonical_utf8: w.expected_canonical_bytes_utf8,
    canonical_bytes,
    signature_base64url: w.expected_ed25519_signature_base64url,
    pubkey_raw: Buffer.from(
      w.expected_provisioning_public_key_base64url,
      'base64url',
    ),
    version: parsed.matrix.version,
  };
});

beforeEach(async () => {
  await pool.query(
    `DELETE FROM matrices WHERE device_id IN (
       SELECT device_id FROM devices WHERE org_id = $1 OR org_id = $2
     )`,
    [TEST_ORG_ID, TEST_ORG_ID_2],
  );
});

afterAll(async () => {
  await pool.query(
    `DELETE FROM matrices WHERE device_id IN (
       SELECT device_id FROM devices WHERE org_id = $1 OR org_id = $2
     )`,
    [TEST_ORG_ID, TEST_ORG_ID_2],
  );
  await pool.query('DELETE FROM devices WHERE org_id = $1 OR org_id = $2', [
    TEST_ORG_ID,
    TEST_ORG_ID_2,
  ]);
  await app.close();
});

describe('GET /me/matrix', () => {
  it('TEST-MATRIX-TRANSPORT-FETCH: returns canonical_bytes and signature verbatim', async () => {
    const d = await createDevice(TEST_ORG_ID);
    const token = await mintSession(d.device_id, d.privateKey);
    await seedMatrix(
      d.device_id,
      w001.canonical_bytes,
      w001.signature_base64url,
      w001.version,
    );

    const res = await app.inject({
      method: 'GET',
      url: '/me/matrix',
      headers: { authorization: `Bearer ${token}` },
    });
    expect(res.statusCode).toBe(200);
    const body = res.json();
    expect(body.canonical_utf8).toBe(w001.canonical_utf8);
    expect(body.signature_base64url).toBe(w001.signature_base64url);
  });

  it('TEST-MATRIX-CROSS-DEVICE-REJECTED: device B cannot see device A matrix', async () => {
    const a = await createDevice(TEST_ORG_ID);
    const b = await createDevice(TEST_ORG_ID);
    const tokenB = await mintSession(b.device_id, b.privateKey);
    await seedMatrix(
      a.device_id,
      w001.canonical_bytes,
      w001.signature_base64url,
      w001.version,
    );

    const res = await app.inject({
      method: 'GET',
      url: '/me/matrix',
      headers: { authorization: `Bearer ${tokenB}` },
    });
    expect(res.statusCode).toBe(404);
    expect(res.json()).toEqual({ error: 'matrix_not_found' });
  });

  it('TEST-MATRIX-404-NO-MATRIX: 404 when no matrix is seeded', async () => {
    const d = await createDevice(TEST_ORG_ID);
    const token = await mintSession(d.device_id, d.privateKey);

    const res = await app.inject({
      method: 'GET',
      url: '/me/matrix',
      headers: { authorization: `Bearer ${token}` },
    });
    expect(res.statusCode).toBe(404);
    expect(res.json()).toEqual({ error: 'matrix_not_found' });
  });

  it('TEST-MATRIX-401-UNAUTHENTICATED: 401 without bearer token', async () => {
    const res = await app.inject({
      method: 'GET',
      url: '/me/matrix',
    });
    expect(res.statusCode).toBe(401);
  });

  it('TEST-MATRIX-VERIFY-ON-RECEIPT-BACKEND: returned bytes still verify against pinned key', async () => {
    const d = await createDevice(TEST_ORG_ID);
    const token = await mintSession(d.device_id, d.privateKey);
    await seedMatrix(
      d.device_id,
      w001.canonical_bytes,
      w001.signature_base64url,
      w001.version,
    );

    const res = await app.inject({
      method: 'GET',
      url: '/me/matrix',
      headers: { authorization: `Bearer ${token}` },
    });
    expect(res.statusCode).toBe(200);
    const body = res.json();

    // Reconstruct bytes from the response the way the client will:
    // canonical_utf8 → UTF-8 bytes → SHA-256 digest → Ed25519 verify
    // over the digest. Uses the same primitive that produced the
    // fixture (Node crypto sign(null, digest, key)); a protocol drift
    // fails here, not silently in the field.
    const roundTripped = Buffer.from(body.canonical_utf8, 'utf8');
    const digest = createHash('sha256').update(roundTripped).digest();
    const sig = Buffer.from(body.signature_base64url, 'base64url');
    const ok = cryptoVerify(null, digest, pubkeyObjectFromRaw(w001.pubkey_raw), sig);
    expect(ok).toBe(true);
  });
});
