/**
 * Route-level tests for the identity-change endpoints.
 *
 * ADR-IDENTITY-CHANGE-001 §8. Two orgs:
 *   - TEST_ORG (primary, ...0b1)
 *   - TEST_ORG_2 (cross-org isolation, ...0b2)
 *
 * Notices are a relay (§4): the service stores verbatim, does NOT
 * verify the provisioning signature. Notice fixture signatures are
 * arbitrary 86-char base64url.
 *
 * Acks ARE verified (§4): the fixture signs with prehash (SHA-256
 * digest → Ed25519), matching the service's verify path per §3.
 * Signing with a wrong key would test the wrong failure mode.
 *
 * beforeEach cleans notices+acks but not devices — devices accumulate
 * keyed by random UUID (mirroring admin.test.ts). Only TEST-NOTICE-
 * IDEMPOTENT and the replay test count rows, and those counts are
 * scoped to the specific org's notices/acks.
 */
import { describe, it, expect, beforeAll, afterAll, beforeEach } from 'vitest';
import { randomBytes, randomUUID, createHash } from 'node:crypto';
import * as ed from '@noble/ed25519';
import { buildApp } from '../src/app.js';
import { pool } from '../src/db/client.js';
import { canonicalizeChallenge, type Challenge } from '../src/auth/canonical.js';
import { REPLACEMENT_NOTICE_DOMAIN } from '../src/crypto/replacement-notice.js';
import { IDENTITY_CHANGE_ACK_DOMAIN } from '../src/crypto/identity-change-ack.js';
import { jcsCanonicalize } from '../src/crypto/jcs.js';

const TEST_ORG = '00000000-0000-0000-0000-0000000000b1';
const TEST_ORG_2 = '00000000-0000-0000-0000-0000000000b2';

interface AuthedDevice {
  device_id: string;
  org_id: string;
  role: string;
  session_token: string;
  privateKey: Uint8Array;
}

let app: Awaited<ReturnType<typeof buildApp>>;

async function createDeviceInDb(
  role: 'owner' | 'admin' | 'user' | 'auditor',
  org_id: string,
): Promise<{ device_id: string; privateKey: Uint8Array }> {
  const privateKey = randomBytes(32);
  const pubKey = await ed.getPublicKeyAsync(privateKey);
  const device_id = randomUUID();
  await pool.query(
    `INSERT INTO devices (device_id, org_id, public_key, label, role)
     VALUES ($1, $2, $3, $4, $5)`,
    [device_id, org_id, Buffer.from(pubKey), `test-${role}`, role],
  );
  return { device_id, privateKey };
}

async function mintSession(device_id: string, privateKey: Uint8Array): Promise<string> {
  const chRes = await app.inject({
    method: 'POST',
    url: '/auth/challenge',
    payload: { device_id, purpose: 'auth' },
  });
  if (chRes.statusCode !== 200) {
    throw new Error(`challenge failed: ${chRes.statusCode} ${chRes.body}`);
  }
  const ch = chRes.json().challenge as Challenge;
  const message = canonicalizeChallenge(ch);
  const signature = await ed.signAsync(message, privateKey);
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

async function createAuthedDevice(
  role: 'owner' | 'admin' | 'user' | 'auditor',
  org_id: string,
): Promise<AuthedDevice> {
  const { device_id, privateKey } = await createDeviceInDb(role, org_id);
  const session_token = await mintSession(device_id, privateKey);
  return { device_id, org_id, role, session_token, privateKey };
}

/**
 * Build a valid-shaped replacement-notice wrapper. Signature is
 * arbitrary 86-char base64url — the notice service does NOT verify
 * signatures (§4 relay).
 */
function buildNoticePayload(
  from_device_id: string,
  to_device_id: string,
): { canonical_utf8: string; signature_base64url: string } {
  const wrapper = {
    domain: REPLACEMENT_NOTICE_DOMAIN,
    notice: {
      from_device_id,
      from_device_auth_key: 'A'.repeat(43),
      to_device_id,
      to_device_auth_key: 'B'.repeat(43),
      issued_at: '2026-10-17T00:00:00Z',
    },
  };
  const canonical = Buffer.from(jcsCanonicalize(wrapper)).toString('utf8');
  const fakeSig = randomBytes(64).toString('base64url');
  return { canonical_utf8: canonical, signature_base64url: fakeSig };
}

/**
 * Build and sign an IdentityChangeAck. Prehash protocol (§3): Ed25519
 * over SHA-256 of JCS-canonical bytes. Must match service's exact
 * sequence — canonicalize → SHA-256 → sign.
 */
async function buildSignedAck(
  notice_hash: string,
  acking_device_id: string,
  decision: 'accept' | 'reject',
  privateKey: Uint8Array,
): Promise<{ canonical_utf8: string; signature_base64url: string }> {
  const wrapper = {
    domain: IDENTITY_CHANGE_ACK_DOMAIN,
    ack: {
      notice_hash,
      acking_device_id,
      decision,
      issued_at: '2026-10-17T00:00:00Z',
    },
  };
  const canonicalBytes = Buffer.from(jcsCanonicalize(wrapper));
  const digest = createHash('sha256').update(canonicalBytes).digest();
  const sig = await ed.signAsync(digest, privateKey);
  return {
    canonical_utf8: canonicalBytes.toString('utf8'),
    signature_base64url: Buffer.from(sig).toString('base64url'),
  };
}

async function createNotice(
  adminSessionToken: string,
  from_device_id: string,
  to_device_id: string,
): Promise<{ notice_hash: string; canonical_utf8: string; signature_base64url: string }> {
  const payload = buildNoticePayload(from_device_id, to_device_id);
  const res = await app.inject({
    method: 'POST',
    url: '/identity-change-notices',
    headers: { authorization: `Bearer ${adminSessionToken}` },
    payload,
  });
  if (res.statusCode !== 201) {
    throw new Error(`notice create failed: ${res.statusCode} ${res.body}`);
  }
  return { notice_hash: res.json().notice_hash as string, ...payload };
}

async function cleanupOrg(org_id: string): Promise<void> {
  await pool.query('DELETE FROM identity_change_acks WHERE org_id = $1', [org_id]);
  await pool.query('DELETE FROM identity_change_notices WHERE org_id = $1', [org_id]);
}

describe('identity-change routes', () => {
  beforeAll(async () => {
    app = await buildApp();
    await app.ready();
  });

  beforeEach(async () => {
    await cleanupOrg(TEST_ORG);
    await cleanupOrg(TEST_ORG_2);
  });

  afterAll(async () => {
    await cleanupOrg(TEST_ORG);
    await cleanupOrg(TEST_ORG_2);
    await pool.query(
      'DELETE FROM devices WHERE org_id = $1 OR org_id = $2',
      [TEST_ORG, TEST_ORG_2],
    );
    await app.close();
    await pool.end();
  });

  // ---------- POST /identity-change-notices ----------

  it('TEST-NOTICE-REJECT-MALFORMED', async () => {
    const admin = await createAuthedDevice('admin', TEST_ORG);
    const res = await app.inject({
      method: 'POST',
      url: '/identity-change-notices',
      headers: { authorization: `Bearer ${admin.session_token}` },
      payload: {
        canonical_utf8: 'not json',
        signature_base64url: 'A'.repeat(86),
      },
    });
    expect(res.statusCode).toBe(400);
    expect(res.json().error).toBe('invalid_request');
  });

  it('TEST-NOTICE-REJECT-UNKNOWN-FROM', async () => {
    const admin = await createAuthedDevice('admin', TEST_ORG);
    const to = await createDeviceInDb('user', TEST_ORG);
    const payload = buildNoticePayload(randomUUID(), to.device_id);
    const res = await app.inject({
      method: 'POST',
      url: '/identity-change-notices',
      headers: { authorization: `Bearer ${admin.session_token}` },
      payload,
    });
    expect(res.statusCode).toBe(400);
    expect(res.json().error).toBe('device_not_found');
  });

  it('TEST-NOTICE-REJECT-UNKNOWN-TO', async () => {
    const admin = await createAuthedDevice('admin', TEST_ORG);
    const from = await createDeviceInDb('user', TEST_ORG);
    const payload = buildNoticePayload(from.device_id, randomUUID());
    const res = await app.inject({
      method: 'POST',
      url: '/identity-change-notices',
      headers: { authorization: `Bearer ${admin.session_token}` },
      payload,
    });
    expect(res.statusCode).toBe(400);
    expect(res.json().error).toBe('device_not_found');
  });

  it('TEST-NOTICE-IDEMPOTENT', async () => {
    const admin = await createAuthedDevice('admin', TEST_ORG);
    const from = await createDeviceInDb('user', TEST_ORG);
    const to = await createDeviceInDb('user', TEST_ORG);
    const payload = buildNoticePayload(from.device_id, to.device_id);

    const res1 = await app.inject({
      method: 'POST',
      url: '/identity-change-notices',
      headers: { authorization: `Bearer ${admin.session_token}` },
      payload,
    });
    const res2 = await app.inject({
      method: 'POST',
      url: '/identity-change-notices',
      headers: { authorization: `Bearer ${admin.session_token}` },
      payload,
    });

    expect(res1.statusCode).toBe(201);
    expect(res2.statusCode).toBe(201);
    expect(res1.json().notice_hash).toBe(res2.json().notice_hash);

    const count = await pool.query<{ c: number }>(
      'SELECT COUNT(*)::int AS c FROM identity_change_notices WHERE org_id = $1',
      [TEST_ORG],
    );
    expect(count.rows[0].c).toBe(1);
  });

  it('TEST-NOTICE-NON-ADMIN-FORBIDDEN', async () => {
    const user = await createAuthedDevice('user', TEST_ORG);
    const from = await createDeviceInDb('user', TEST_ORG);
    const to = await createDeviceInDb('user', TEST_ORG);
    const payload = buildNoticePayload(from.device_id, to.device_id);
    const res = await app.inject({
      method: 'POST',
      url: '/identity-change-notices',
      headers: { authorization: `Bearer ${user.session_token}` },
      payload,
    });
    expect(res.statusCode).toBe(403);
    expect(res.json().error).toBe('forbidden');
  });

  it('TEST-NOTICE-STORED-VERBATIM', async () => {
    const admin = await createAuthedDevice('admin', TEST_ORG);
    const from = await createDeviceInDb('user', TEST_ORG);
    const to = await createDeviceInDb('user', TEST_ORG);
    const payload = buildNoticePayload(from.device_id, to.device_id);
    const res = await app.inject({
      method: 'POST',
      url: '/identity-change-notices',
      headers: { authorization: `Bearer ${admin.session_token}` },
      payload,
    });
    expect(res.statusCode).toBe(201);

    const row = await pool.query<{ canonical_bytes: Buffer; signature_base64url: string }>(
      'SELECT canonical_bytes, signature_base64url FROM identity_change_notices WHERE org_id = $1 LIMIT 1',
      [TEST_ORG],
    );
    expect(row.rowCount).toBe(1);
    expect(row.rows[0].canonical_bytes.toString('utf8')).toBe(payload.canonical_utf8);
    expect(row.rows[0].signature_base64url).toBe(payload.signature_base64url);
  });

  // ---------- POST /identity-change-acks ----------

  it('TEST-ACK-INVALID-SIGNATURE', async () => {
    const admin = await createAuthedDevice('admin', TEST_ORG);
    const from = await createDeviceInDb('user', TEST_ORG);
    const to = await createDeviceInDb('user', TEST_ORG);
    const notice = await createNotice(admin.session_token, from.device_id, to.device_id);

    const acking = await createAuthedDevice('user', TEST_ORG);
    const wrongKey = randomBytes(32);
    const ackPayload = await buildSignedAck(
      notice.notice_hash, acking.device_id, 'accept', wrongKey,
    );

    const res = await app.inject({
      method: 'POST',
      url: '/identity-change-acks',
      headers: { authorization: `Bearer ${acking.session_token}` },
      payload: ackPayload,
    });
    expect(res.statusCode).toBe(400);
    expect(res.json().error).toBe('invalid_signature');

    const count = await pool.query<{ c: number }>(
      'SELECT COUNT(*)::int AS c FROM identity_change_acks WHERE org_id = $1',
      [TEST_ORG],
    );
    expect(count.rows[0].c).toBe(0);
  });

  it('TEST-ACK-WRONG-DEVICE', async () => {
    const admin = await createAuthedDevice('admin', TEST_ORG);
    const from = await createDeviceInDb('user', TEST_ORG);
    const to = await createDeviceInDb('user', TEST_ORG);
    const notice = await createNotice(admin.session_token, from.device_id, to.device_id);

    const session = await createAuthedDevice('user', TEST_ORG);
    const other = await createDeviceInDb('user', TEST_ORG);
    const ackPayload = await buildSignedAck(
      notice.notice_hash, other.device_id, 'accept', other.privateKey,
    );

    const res = await app.inject({
      method: 'POST',
      url: '/identity-change-acks',
      headers: { authorization: `Bearer ${session.session_token}` },
      payload: ackPayload,
    });
    expect(res.statusCode).toBe(400);
    expect(res.json().error).toBe('invalid_request');
  });

  it('TEST-ACK-UNKNOWN-NOTICE', async () => {
    const acking = await createAuthedDevice('user', TEST_ORG);
    const fakeHash = createHash('sha256').update('not-a-real-notice').digest('base64url');
    const payload = await buildSignedAck(
      fakeHash, acking.device_id, 'accept', acking.privateKey,
    );
    const res = await app.inject({
      method: 'POST',
      url: '/identity-change-acks',
      headers: { authorization: `Bearer ${acking.session_token}` },
      payload,
    });
    expect(res.statusCode).toBe(400);
    expect(res.json().error).toBe('unknown_notice');
  });

  it('TEST-ACK-CROSS-ORG-REJECTED', async () => {
    const admin1 = await createAuthedDevice('admin', TEST_ORG);
    const from = await createDeviceInDb('user', TEST_ORG);
    const to = await createDeviceInDb('user', TEST_ORG);
    const notice = await createNotice(admin1.session_token, from.device_id, to.device_id);

    const acking = await createAuthedDevice('user', TEST_ORG_2);
    const ackPayload = await buildSignedAck(
      notice.notice_hash, acking.device_id, 'accept', acking.privateKey,
    );
    const res = await app.inject({
      method: 'POST',
      url: '/identity-change-acks',
      headers: { authorization: `Bearer ${acking.session_token}` },
      payload: ackPayload,
    });
    expect(res.statusCode).toBe(403);
    expect(res.json().error).toBe('cross_org_rejected');
  });

  it('TEST-ACK-REVOKED-DEVICE', async () => {
    // Layer reality: lookupSession (auth/sessions.ts) filters by
    // device status, so a revoked-device session is rejected at the
    // middleware before the ack service is reached. The service's own
    // device_revoked branch (acks.ts) is defense-in-depth for the race
    // window (session valid at middleware time, device revoked before
    // the service's DB query). Not reachable via HTTP in normal
    // operation. Per ADR v0.3 §10, route-level assertion is 401;
    // the 403 device_revoked service branch remains in code for the
    // race case.
    const admin = await createAuthedDevice('admin', TEST_ORG);
    const from = await createDeviceInDb('user', TEST_ORG);
    const to = await createDeviceInDb('user', TEST_ORG);
    const notice = await createNotice(admin.session_token, from.device_id, to.device_id);

    const acking = await createAuthedDevice('user', TEST_ORG);
    await pool.query(
      `UPDATE devices SET status = 'revoked', revoked_at = now() WHERE device_id = $1`,
      [acking.device_id],
    );

    const ackPayload = await buildSignedAck(
      notice.notice_hash, acking.device_id, 'accept', acking.privateKey,
    );
    const res = await app.inject({
      method: 'POST',
      url: '/identity-change-acks',
      headers: { authorization: `Bearer ${acking.session_token}` },
      payload: ackPayload,
    });
    expect(res.statusCode).toBe(401);
    expect(res.json().error).toBe('unauthorized');

    // Confirm nothing landed — the request was rejected before write.
    const count = await pool.query<{ c: number }>(
      'SELECT COUNT(*)::int AS c FROM identity_change_acks WHERE org_id = $1',
      [TEST_ORG],
    );
    expect(count.rows[0].c).toBe(0);
  });

  it('TEST-ACK-REPLAY-IDEMPOTENT', async () => {
    const admin = await createAuthedDevice('admin', TEST_ORG);
    const from = await createDeviceInDb('user', TEST_ORG);
    const to = await createDeviceInDb('user', TEST_ORG);
    const notice = await createNotice(admin.session_token, from.device_id, to.device_id);

    const acking = await createAuthedDevice('user', TEST_ORG);
    const ackPayload = await buildSignedAck(
      notice.notice_hash, acking.device_id, 'accept', acking.privateKey,
    );

    const res1 = await app.inject({
      method: 'POST',
      url: '/identity-change-acks',
      headers: { authorization: `Bearer ${acking.session_token}` },
      payload: ackPayload,
    });
    const res2 = await app.inject({
      method: 'POST',
      url: '/identity-change-acks',
      headers: { authorization: `Bearer ${acking.session_token}` },
      payload: ackPayload,
    });

    expect(res1.statusCode).toBe(201);
    expect(res2.statusCode).toBe(201);
    expect(res1.json().ack_hash).toBe(res2.json().ack_hash);

    const count = await pool.query<{ c: number }>(
      'SELECT COUNT(*)::int AS c FROM identity_change_acks WHERE notice_hash = $1',
      [Buffer.from(notice.notice_hash, 'base64url')],
    );
    expect(count.rows[0].c).toBe(1);
  });

  it('TEST-ACK-INVALID-DECISION', async () => {
    // Route-level validator is the first line of defense; DB CHECK
    // (migration 015) is the last. Asserts rejection before any write.
    const admin = await createAuthedDevice('admin', TEST_ORG);
    const from = await createDeviceInDb('user', TEST_ORG);
    const to = await createDeviceInDb('user', TEST_ORG);
    const notice = await createNotice(admin.session_token, from.device_id, to.device_id);

    const acking = await createAuthedDevice('user', TEST_ORG);
    const wrapper = {
      domain: IDENTITY_CHANGE_ACK_DOMAIN,
      ack: {
        notice_hash: notice.notice_hash,
        acking_device_id: acking.device_id,
        decision: 'maybe',
        issued_at: '2026-10-17T00:00:00Z',
      },
    };
    const canonicalBytes = Buffer.from(jcsCanonicalize(wrapper));
    const digest = createHash('sha256').update(canonicalBytes).digest();
    const sig = await ed.signAsync(digest, acking.privateKey);

    const res = await app.inject({
      method: 'POST',
      url: '/identity-change-acks',
      headers: { authorization: `Bearer ${acking.session_token}` },
      payload: {
        canonical_utf8: canonicalBytes.toString('utf8'),
        signature_base64url: Buffer.from(sig).toString('base64url'),
      },
    });
    expect(res.statusCode).toBe(400);
    expect(res.json().error).toBe('invalid_request');

    const count = await pool.query<{ c: number }>(
      'SELECT COUNT(*)::int AS c FROM identity_change_acks WHERE notice_hash = $1',
      [Buffer.from(notice.notice_hash, 'base64url')],
    );
    expect(count.rows[0].c).toBe(0);
  });

  // ---------- GET /identity-change-notices ----------

  it('TEST-DISCOVERY-RETURNS-ORG-NOTICES', async () => {
    const admin = await createAuthedDevice('admin', TEST_ORG);
    const from = await createDeviceInDb('user', TEST_ORG);
    const to = await createDeviceInDb('user', TEST_ORG);
    const notice = await createNotice(admin.session_token, from.device_id, to.device_id);

    const reader = await createAuthedDevice('user', TEST_ORG);
    const res = await app.inject({
      method: 'GET',
      url: '/identity-change-notices',
      headers: { authorization: `Bearer ${reader.session_token}` },
    });
    expect(res.statusCode).toBe(200);
    const notices = res.json().notices as Array<{ notice_hash: string }>;
    const hashes = notices.map((n) => n.notice_hash);
    expect(hashes).toContain(notice.notice_hash);
  });

  it('TEST-DISCOVERY-CROSS-ORG-ISOLATED', async () => {
    const admin1 = await createAuthedDevice('admin', TEST_ORG);
    const from = await createDeviceInDb('user', TEST_ORG);
    const to = await createDeviceInDb('user', TEST_ORG);
    const notice = await createNotice(admin1.session_token, from.device_id, to.device_id);

    const reader2 = await createAuthedDevice('user', TEST_ORG_2);
    const res = await app.inject({
      method: 'GET',
      url: '/identity-change-notices',
      headers: { authorization: `Bearer ${reader2.session_token}` },
    });
    expect(res.statusCode).toBe(200);
    const hashes = (res.json().notices as Array<{ notice_hash: string }>).map((n) => n.notice_hash);
    expect(hashes).not.toContain(notice.notice_hash);
  });

  // ---------- GET /identity-change-acks/:notice_hash ----------

  it('TEST-ACK-LIST-BY-NOTICE', async () => {
    // Two peers ack differently — one accept, one reject. Both returned.
    const admin = await createAuthedDevice('admin', TEST_ORG);
    const from = await createDeviceInDb('user', TEST_ORG);
    const to = await createDeviceInDb('user', TEST_ORG);
    const notice = await createNotice(admin.session_token, from.device_id, to.device_id);

    const peerAccept = await createAuthedDevice('user', TEST_ORG);
    const peerReject = await createAuthedDevice('user', TEST_ORG);
    const acceptPayload = await buildSignedAck(
      notice.notice_hash, peerAccept.device_id, 'accept', peerAccept.privateKey,
    );
    const rejectPayload = await buildSignedAck(
      notice.notice_hash, peerReject.device_id, 'reject', peerReject.privateKey,
    );

    const r1 = await app.inject({
      method: 'POST',
      url: '/identity-change-acks',
      headers: { authorization: `Bearer ${peerAccept.session_token}` },
      payload: acceptPayload,
    });
    const r2 = await app.inject({
      method: 'POST',
      url: '/identity-change-acks',
      headers: { authorization: `Bearer ${peerReject.session_token}` },
      payload: rejectPayload,
    });
    expect(r1.statusCode).toBe(201);
    expect(r2.statusCode).toBe(201);

    const list = await app.inject({
      method: 'GET',
      url: `/identity-change-acks/${notice.notice_hash}`,
      headers: { authorization: `Bearer ${admin.session_token}` },
    });
    expect(list.statusCode).toBe(200);
    const acks = list.json().acks as Array<{ acking_device_id: string; decision: string }>;
    const byDevice: Record<string, string> = Object.fromEntries(
      acks.map((a) => [a.acking_device_id, a.decision]),
    );
    expect(byDevice[peerAccept.device_id]).toBe('accept');
    expect(byDevice[peerReject.device_id]).toBe('reject');
  });

  it('TEST-ACK-LIST-CROSS-ORG-FORBIDDEN', async () => {
    const admin1 = await createAuthedDevice('admin', TEST_ORG);
    const from = await createDeviceInDb('user', TEST_ORG);
    const to = await createDeviceInDb('user', TEST_ORG);
    const notice = await createNotice(admin1.session_token, from.device_id, to.device_id);

    const reader2 = await createAuthedDevice('user', TEST_ORG_2);
    const res = await app.inject({
      method: 'GET',
      url: `/identity-change-acks/${notice.notice_hash}`,
      headers: { authorization: `Bearer ${reader2.session_token}` },
    });
    expect(res.statusCode).toBe(403);
    expect(res.json().error).toBe('cross_org_rejected');
  });
});
