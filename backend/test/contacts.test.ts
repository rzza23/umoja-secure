import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { randomBytes, randomUUID } from 'node:crypto';
import * as ed from '@noble/ed25519';
import { buildApp } from '../src/app.js';
import { pool } from '../src/db/client.js';
import { canonicalizeChallenge, type Challenge } from '../src/auth/canonical.js';

const TEST_ORG_ID = '00000000-0000-0000-0000-000000000011';

interface TestDevice {
  device_id: string;
  token: string;
  role: string;
}

let app: Awaited<ReturnType<typeof buildApp>>;

async function createAuthedDevice(
  role: 'owner' | 'admin' | 'user' = 'user',
): Promise<TestDevice> {
  const private_key = randomBytes(32);
  const public_key = await ed.getPublicKeyAsync(private_key);
  const device_id = randomUUID();

  await pool.query(
    `INSERT INTO devices (device_id, org_id, public_key, label, role)
     VALUES ($1, $2, $3, $4, $5)`,
    [device_id, TEST_ORG_ID, Buffer.from(public_key), `test-${role}-${device_id.slice(0, 6)}`, role],
  );

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
  const signature = await ed.signAsync(message, private_key);
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
  return { device_id, token: verifyRes.json().session_token, role };
}

function makeCiphertext(size = 64): string {
  return randomBytes(size).toString('base64url');
}

describe('contact authorization', () => {
  beforeAll(async () => {
    app = await buildApp();
    await app.ready();
  });

  afterAll(async () => {
    await pool.query('DELETE FROM contacts WHERE org_id = $1', [TEST_ORG_ID]);
    await pool.query('DELETE FROM envelopes WHERE sender_device_id IN (SELECT device_id FROM devices WHERE org_id = $1)', [TEST_ORG_ID]);
    await pool.query('DELETE FROM one_time_prekeys WHERE device_id IN (SELECT device_id FROM devices WHERE org_id = $1)', [TEST_ORG_ID]);
    await pool.query('DELETE FROM prekey_bundles WHERE device_id IN (SELECT device_id FROM devices WHERE org_id = $1)', [TEST_ORG_ID]);
    await pool.query('DELETE FROM devices WHERE org_id = $1', [TEST_ORG_ID]);
    await app.close();
    await pool.end();
  });

  // ------------------------------------------------------------
  // Admin routes
  // ------------------------------------------------------------
  describe('POST /admin/contacts', () => {
    it('rejects non-admin callers', async () => {
      const user = await createAuthedDevice('user');
      const a = await createAuthedDevice('user');
      const b = await createAuthedDevice('user');
      const res = await app.inject({
        method: 'POST',
        url: '/admin/contacts',
        headers: { authorization: `Bearer ${user.token}` },
        payload: { owner_device_id: a.device_id, contact_device_id: b.device_id },
      });
      expect(res.statusCode).toBe(403);
    });

    it('admin can authorize a pair (both directions created)', async () => {
      const admin = await createAuthedDevice('admin');
      const a = await createAuthedDevice('user');
      const b = await createAuthedDevice('user');
      const res = await app.inject({
        method: 'POST',
        url: '/admin/contacts',
        headers: { authorization: `Bearer ${admin.token}` },
        payload: { owner_device_id: a.device_id, contact_device_id: b.device_id },
      });
      expect(res.statusCode).toBe(204);

      const rows = await pool.query(
        `SELECT owner_device_id, contact_device_id, status
           FROM contacts
          WHERE org_id = $1
            AND ((owner_device_id = $2 AND contact_device_id = $3)
                 OR (owner_device_id = $3 AND contact_device_id = $2))`,
        [TEST_ORG_ID, a.device_id, b.device_id],
      );
      expect(rows.rowCount).toBe(2);
      for (const r of rows.rows) expect(r.status).toBe('active');
    });

    it('rejects self-authorization', async () => {
      const admin = await createAuthedDevice('admin');
      const a = await createAuthedDevice('user');
      const res = await app.inject({
        method: 'POST',
        url: '/admin/contacts',
        headers: { authorization: `Bearer ${admin.token}` },
        payload: { owner_device_id: a.device_id, contact_device_id: a.device_id },
      });
      expect(res.statusCode).toBe(400);
    });
  });

  describe('POST /admin/contacts/:owner/:contact/revoke', () => {
    it('revokes both directions', async () => {
      const admin = await createAuthedDevice('admin');
      const a = await createAuthedDevice('user');
      const b = await createAuthedDevice('user');
      await app.inject({
        method: 'POST',
        url: '/admin/contacts',
        headers: { authorization: `Bearer ${admin.token}` },
        payload: { owner_device_id: a.device_id, contact_device_id: b.device_id },
      });
      const res = await app.inject({
        method: 'POST',
        url: `/admin/contacts/${a.device_id}/${b.device_id}/revoke`,
        headers: { authorization: `Bearer ${admin.token}` },
        payload: { reason: 'test_revoke' },
      });
      expect(res.statusCode).toBe(204);

      const rows = await pool.query(
        `SELECT status FROM contacts WHERE org_id = $1 AND (
           (owner_device_id = $2 AND contact_device_id = $3) OR
           (owner_device_id = $3 AND contact_device_id = $2))`,
        [TEST_ORG_ID, a.device_id, b.device_id],
      );
      for (const r of rows.rows) expect(r.status).toBe('revoked');
    });
  });

  // ------------------------------------------------------------
  // /me/contacts
  // ------------------------------------------------------------
  describe('GET /me/contacts', () => {
    it('returns only authorized peers', async () => {
      const admin = await createAuthedDevice('admin');
      const a = await createAuthedDevice('user');
      const b = await createAuthedDevice('user');
      const c = await createAuthedDevice('user');

      await app.inject({
        method: 'POST',
        url: '/admin/contacts',
        headers: { authorization: `Bearer ${admin.token}` },
        payload: { owner_device_id: a.device_id, contact_device_id: b.device_id },
      });

      const res = await app.inject({
        method: 'GET',
        url: '/me/contacts',
        headers: { authorization: `Bearer ${a.token}` },
      });
      expect(res.statusCode).toBe(200);
      const peers = res.json().contacts as Array<{ peer_device_id: string }>;
      const ids = peers.map((p) => p.peer_device_id);
      expect(ids).toContain(b.device_id);
      expect(ids).not.toContain(c.device_id);
    });
  });

  // ------------------------------------------------------------
  // Enforcement: envelope submission
  // ------------------------------------------------------------
  describe('envelope authorization enforcement', () => {
    it('rejects envelope from unauthorized sender', async () => {
      const sender = await createAuthedDevice('user');
      const recipient = await createAuthedDevice('user');
      const res = await app.inject({
        method: 'POST',
        url: '/envelopes',
        headers: { authorization: `Bearer ${sender.token}` },
        payload: {
          recipient_device_id: recipient.device_id,
          ciphertext: makeCiphertext(),
        },
      });
      expect(res.statusCode).toBe(403);
      expect(res.json().error).toBe('contact_not_authorized');
    });

    it('accepts envelope from authorized sender', async () => {
      const admin = await createAuthedDevice('admin');
      const sender = await createAuthedDevice('user');
      const recipient = await createAuthedDevice('user');
      await app.inject({
        method: 'POST',
        url: '/admin/contacts',
        headers: { authorization: `Bearer ${admin.token}` },
        payload: { owner_device_id: sender.device_id, contact_device_id: recipient.device_id },
      });
      const res = await app.inject({
        method: 'POST',
        url: '/envelopes',
        headers: { authorization: `Bearer ${sender.token}` },
        payload: {
          recipient_device_id: recipient.device_id,
          ciphertext: makeCiphertext(),
        },
      });
      expect(res.statusCode).toBe(201);
    });

    it('rejects envelope after contact is revoked', async () => {
      const admin = await createAuthedDevice('admin');
      const sender = await createAuthedDevice('user');
      const recipient = await createAuthedDevice('user');
      await app.inject({
        method: 'POST',
        url: '/admin/contacts',
        headers: { authorization: `Bearer ${admin.token}` },
        payload: { owner_device_id: sender.device_id, contact_device_id: recipient.device_id },
      });
      await app.inject({
        method: 'POST',
        url: `/admin/contacts/${sender.device_id}/${recipient.device_id}/revoke`,
        headers: { authorization: `Bearer ${admin.token}` },
        payload: { reason: 'test' },
      });
      const res = await app.inject({
        method: 'POST',
        url: '/envelopes',
        headers: { authorization: `Bearer ${sender.token}` },
        payload: {
          recipient_device_id: recipient.device_id,
          ciphertext: makeCiphertext(),
        },
      });
      expect(res.statusCode).toBe(403);
    });
  });

  // ------------------------------------------------------------
  // Enforcement: prekey bundle fetch
  // ------------------------------------------------------------
  describe('prekey fetch authorization enforcement', () => {
    it('rejects bundle fetch from unauthorized caller', async () => {
      const caller = await createAuthedDevice('user');
      const target = await createAuthedDevice('user');
      const res = await app.inject({
        method: 'GET',
        url: `/prekeys/${target.device_id}`,
        headers: { authorization: `Bearer ${caller.token}` },
      });
      expect(res.statusCode).toBe(404);
    });
  });
});
