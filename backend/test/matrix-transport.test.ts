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
  hkdfSync,
  createPrivateKey,
} from 'node:crypto';
import { readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import * as ed from '@noble/ed25519';
import { buildApp } from '../src/app.js';
import { pool } from '../src/db/client.js';
import { canonicalizeChallenge, type Challenge } from '../src/auth/canonical.js';
import {
  MATRIX_DOMAIN,
  validateSignedMatrix,
} from '../src/crypto/matrix-schema.js';
import { signMatrix } from '../src/crypto/matrix-sign.js';
import { jcsCanonicalize } from '../src/crypto/jcs.js';

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
  device_id: string;
}

let app: Awaited<ReturnType<typeof buildApp>>;
let w001: TestMatrixVector;
let testPrivateKey: KeyObject;

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

async function createAdmin(
  org_id: string,
): Promise<{ device_id: string; privateKey: Uint8Array }> {
  const privateKey = randomBytes(32);
  const pubKey = await ed.getPublicKeyAsync(privateKey);
  const device_id = randomUUID();
  await pool.query(
    `INSERT INTO devices (device_id, org_id, public_key, label, role)
     VALUES ($1, $2, $3, $4, $5)`,
    [device_id, org_id, Buffer.from(pubKey), 'matrix-test-admin', 'admin'],
  );
  return { device_id, privateKey };
}

async function createTargetDevice(
  org_id: string,
  device_id: string,
): Promise<void> {
  // Target device IDs come from the matrix body (W-001's
  // matrix.device_id). Role is 'user' -- the target is the
  // provisioned device, not the pusher. Public key is arbitrary;
  // it is not used by the push path (only by the target's own
  // session auth, which these tests do not exercise).
  const pubKey = await ed.getPublicKeyAsync(randomBytes(32));
  await pool.query(
    `INSERT INTO devices (device_id, org_id, public_key, label, role)
     VALUES ($1, $2, $3, $4, $5)
     ON CONFLICT (device_id) DO NOTHING`,
    [device_id, org_id, Buffer.from(pubKey), 'matrix-target', 'user'],
  );
}

/**
 * Derive the test-only Ed25519 private key. Mirrors the derivation in
 * backend/scripts/{generate-matrix-vectors,sign-test-notice,sign-test-matrix}.ts:
 *
 *   HKDF-SHA256(seed_utf8, salt=empty, info='ed25519-test-key', 32)
 *     => raw Ed25519 seed
 *   PKCS8-wrap (RFC 8410, prefix 302e020100300506032b657004220420)
 *     => KeyObject
 *
 * Inlined (not extracted) because this test file is the sole consumer;
 * the three scripts each have their own copy + self-check against the
 * vector file. If a second test file needs it, extract to
 * backend/test/helpers/test-key.ts per section 7's three-file threshold.
 *
 * Called once from beforeAll; the derived key is asserted against
 * w001.pubkey_raw before any test runs (self-check mirrors the scripts'
 * "[self-check] test key derivation verified" guard).
 */
function deriveTestPrivateKey(): KeyObject {
  const rawSeed = Buffer.from(
    hkdfSync(
      'sha256',
      Buffer.from(
        'umoja-canonical-matrix-test-vectors-v1-DO-NOT-USE-IN-PRODUCTION',
        'utf8',
      ),
      Buffer.alloc(0),
      'ed25519-test-key',
      32,
    ),
  );
  const pkcs8 = Buffer.concat([
    Buffer.from('302e020100300506032b657004220420', 'hex'),
    rawSeed,
  ]);
  return createPrivateKey({ key: pkcs8, format: 'der', type: 'pkcs8' });
}

/**
 * Build + sign a matrix with a real UUID device_id. W-001's device_id
 * is 'device-001' (not UUID-shaped); the route's URL param validator
 * requires UUID. The signing key is the same test key
 * env.PROVISIONING_PUBKEY_B64U verifies against, so the route's
 * verify-on-write accepts the push.
 *
 * Uses W-001's shape for pubkeys/clearance/issued_at (A/B/C
 * placeholders), permitted_contacts defaults to ['device-002'] to
 * match W-001. Ed25519 (RFC 8032) uses deterministic nonces -- same
 * input twice produces the same signature (verified in
 * generate-matrix-vectors.ts's KDoc).
 */
function buildSignedMatrix(
  device_id: string,
  version: number,
  permitted_contacts: string[] = ['device-002'],
): {
  device_id: string;
  canonical_utf8: string;
  signature_base64url: string;
  version: number;
} {
  const wrapper = {
    domain: MATRIX_DOMAIN,
    matrix: {
      version,
      device_id,
      pub_device_auth_key: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
      pub_messaging_identity_key: 'BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB',
      pub_wipe_confirmation_key: 'CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC',
      clearance: 'standard',
      permitted_contacts,
      issued_at: '2026-10-14T00:00:00Z',
    },
  };
  const signed = validateSignedMatrix(wrapper);
  const canonical = jcsCanonicalize(signed);
  const signature = signMatrix(signed, testPrivateKey);
  return {
    device_id,
    canonical_utf8: canonical.toString('utf8'),
    signature_base64url: signature,
    version,
  };
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
    matrix: { version: number; device_id: string };
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
    device_id: parsed.matrix.device_id,
  };

  // P1-033a. Derive the test private key, self-check against the
  // vector file's expected pubkey. Mirrors sign-test-matrix.ts's
  // "[self-check] test key derivation verified" guard: if HKDF
  // derivation ever drifts from the generator, this fails loudly
  // before any POST test runs.
  testPrivateKey = deriveTestPrivateKey();
  const spki = createPublicKey(testPrivateKey).export({
    format: 'der',
    type: 'spki',
  }) as Buffer;
  const derivedPubB64u = spki.subarray(spki.length - 32).toString('base64url');
  if (derivedPubB64u !== w.expected_provisioning_public_key_base64url) {
    throw new Error(
      `HKDF derivation mismatch: derived=${derivedPubB64u}, ` +
        `expected=${w.expected_provisioning_public_key_base64url}.`,
    );
  }
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

describe('POST /admin/matrices/:device_id', () => {
  async function setupAdmin(org_id: string = TEST_ORG_ID): Promise<string> {
    const admin = await createAdmin(org_id);
    return mintSession(admin.device_id, admin.privateKey);
  }

  it('TEST-MATRIX-PUSH-VALID: admin pushes signed matrix, 201, row stored', async () => {
    const token = await setupAdmin();
    const matrix = buildSignedMatrix(randomUUID(), 1);
    await createTargetDevice(TEST_ORG_ID, matrix.device_id);

    const res = await app.inject({
      method: 'POST',
      url: `/admin/matrices/${matrix.device_id}`,
      headers: { authorization: `Bearer ${token}` },
      payload: {
        canonical_utf8: matrix.canonical_utf8,
        signature_base64url: matrix.signature_base64url,
      },
    });
    expect(res.statusCode).toBe(201);
    const body = res.json();
    expect(body.device_id).toBe(matrix.device_id);
    expect(body.version).toBe(matrix.version);

    const row = await pool.query<{
      version: number;
      canonical_bytes: Buffer;
      signature_base64url: string;
    }>(
      'SELECT version, canonical_bytes, signature_base64url FROM matrices WHERE device_id = $1',
      [matrix.device_id],
    );
    expect(row.rowCount).toBe(1);
    expect(row.rows[0].version).toBe(matrix.version);
    expect(Buffer.from(row.rows[0].canonical_bytes).toString('utf8')).toBe(
      matrix.canonical_utf8,
    );
    expect(row.rows[0].signature_base64url).toBe(matrix.signature_base64url);
  });

  it('TEST-MATRIX-PUSH-INVALID-SIG: tampered signature rejected 400', async () => {
    const token = await setupAdmin();
    const matrix = buildSignedMatrix(randomUUID(), 1);
    await createTargetDevice(TEST_ORG_ID, matrix.device_id);

    const sigBuf = Buffer.from(matrix.signature_base64url, 'base64url');
    sigBuf[0] = sigBuf[0] ^ 0xff;
    const badSig = sigBuf.toString('base64url');

    const res = await app.inject({
      method: 'POST',
      url: `/admin/matrices/${matrix.device_id}`,
      headers: { authorization: `Bearer ${token}` },
      payload: {
        canonical_utf8: matrix.canonical_utf8,
        signature_base64url: badSig,
      },
    });
    expect(res.statusCode).toBe(400);
    expect(res.json()).toEqual({ error: 'invalid_signature' });
  });

  it('TEST-MATRIX-PUSH-INVALID-BODY: missing signature rejected 400 invalid_request', async () => {
    const token = await setupAdmin();

    const res = await app.inject({
      method: 'POST',
      url: `/admin/matrices/${randomUUID()}`,
      headers: { authorization: `Bearer ${token}` },
      payload: { canonical_utf8: w001.canonical_utf8 },
    });
    expect(res.statusCode).toBe(400);
    expect(res.json()).toEqual({ error: 'invalid_request' });
  });

  it('TEST-MATRIX-PUSH-INVALID-MATRIX: body parses but schema fails, 400 invalid_matrix', async () => {
    const token = await setupAdmin();

    const res = await app.inject({
      method: 'POST',
      url: `/admin/matrices/${randomUUID()}`,
      headers: { authorization: `Bearer ${token}` },
      payload: {
        canonical_utf8: '{"foo":"bar"}',
        signature_base64url: 'A'.repeat(86),
      },
    });
    expect(res.statusCode).toBe(400);
    expect(res.json()).toEqual({ error: 'invalid_matrix' });
  });

  it('TEST-MATRIX-PUSH-DEVICE-ID-MISMATCH: URL param differs from matrix.device_id, 400', async () => {
    const token = await setupAdmin();
    const matrix = buildSignedMatrix(randomUUID(), 1);
    const otherDeviceId = randomUUID();
    await createTargetDevice(TEST_ORG_ID, otherDeviceId);

    const res = await app.inject({
      method: 'POST',
      url: `/admin/matrices/${otherDeviceId}`,
      headers: { authorization: `Bearer ${token}` },
      payload: {
        canonical_utf8: matrix.canonical_utf8,
        signature_base64url: matrix.signature_base64url,
      },
    });
    expect(res.statusCode).toBe(400);
    expect(res.json()).toEqual({ error: 'device_id_mismatch' });
  });

  it('TEST-MATRIX-PUSH-NON-MONOTONIC: same-version re-push rejected 409', async () => {
    const token = await setupAdmin();
    const matrix = buildSignedMatrix(randomUUID(), 1);
    await createTargetDevice(TEST_ORG_ID, matrix.device_id);

    const r1 = await app.inject({
      method: 'POST',
      url: `/admin/matrices/${matrix.device_id}`,
      headers: { authorization: `Bearer ${token}` },
      payload: {
        canonical_utf8: matrix.canonical_utf8,
        signature_base64url: matrix.signature_base64url,
      },
    });
    expect(r1.statusCode).toBe(201);

    const r2 = await app.inject({
      method: 'POST',
      url: `/admin/matrices/${matrix.device_id}`,
      headers: { authorization: `Bearer ${token}` },
      payload: {
        canonical_utf8: matrix.canonical_utf8,
        signature_base64url: matrix.signature_base64url,
      },
    });
    expect(r2.statusCode).toBe(409);
    expect(r2.json()).toEqual({ error: 'matrix_version_not_monotonic' });
  });

  it('TEST-MATRIX-PUSH-DEVICE-NOT-FOUND: target exists in other org, 404 for this admin', async () => {
    // Cross-org: target device in TEST_ORG_ID, admin in TEST_ORG_ID_2.
    const token = await setupAdmin(TEST_ORG_ID_2);
    const matrix = buildSignedMatrix(randomUUID(), 1);
    await createTargetDevice(TEST_ORG_ID, matrix.device_id);

    const res = await app.inject({
      method: 'POST',
      url: `/admin/matrices/${matrix.device_id}`,
      headers: { authorization: `Bearer ${token}` },
      payload: {
        canonical_utf8: matrix.canonical_utf8,
        signature_base64url: matrix.signature_base64url,
      },
    });
    expect(res.statusCode).toBe(404);
    expect(res.json()).toEqual({ error: 'device_not_found' });
  });

  it('TEST-MATRIX-PUSH-UNAUTHENTICATED: 401 without bearer', async () => {
    const res = await app.inject({
      method: 'POST',
      url: `/admin/matrices/${randomUUID()}`,
      payload: {
        canonical_utf8: w001.canonical_utf8,
        signature_base64url: w001.signature_base64url,
      },
    });
    expect(res.statusCode).toBe(401);
  });

  it('TEST-MATRIX-PUSH-FORBIDDEN-USER: user role rejected 403', async () => {
    const user = await createDevice(TEST_ORG_ID);
    const token = await mintSession(user.device_id, user.privateKey);

    const res = await app.inject({
      method: 'POST',
      url: `/admin/matrices/${randomUUID()}`,
      headers: { authorization: `Bearer ${token}` },
      payload: {
        canonical_utf8: w001.canonical_utf8,
        signature_base64url: w001.signature_base64url,
      },
    });
    expect(res.statusCode).toBe(403);
    expect(res.json()).toEqual({ error: 'forbidden' });
  });
});
