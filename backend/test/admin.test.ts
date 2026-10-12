import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { randomBytes, randomUUID } from 'node:crypto';
import * as ed from '@noble/ed25519';
import { buildApp } from '../src/app.js';
import { pool } from '../src/db/client.js';
import { canonicalizeChallenge, type Challenge } from '../src/auth/canonical.js';
import {
  notifyDeviceRevoked,
  startRevocationListener,
  stopRevocationListener,
} from '../src/ws/revocation.js';

const TEST_ORG_ID = '00000000-0000-0000-0000-000000000044';

interface TestDevice {
  device_id: string;
  token: string;
  role: string;
}

let app: Awaited<ReturnType<typeof buildApp>>;

async function createAuthedDevice(role: 'owner' | 'admin' | 'user' = 'user'): Promise<TestDevice> {
  const private_key = randomBytes(32);
  const public_key = await ed.getPublicKeyAsync(private_key);
  const device_id = randomUUID();
  await pool.query(
    `INSERT INTO devices (device_id, org_id, public_key, label, role)
     VALUES ($1, $2, $3, $4, $5)`,
    [device_id, TEST_ORG_ID, Buffer.from(public_key), `test-${role}`, role],
  );
  const chRes = await app.inject({
    method: 'POST',
    url: '/auth/challenge',
    payload: { device_id, purpose: 'auth' },
  });
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
  return { device_id, token: verifyRes.json().session_token, role };
}

describe('admin plane', () => {
  beforeAll(async () => {
    app = await buildApp();
    await app.ready();
    await startRevocationListener();
  });

  afterAll(async () => {
    await pool.query(
      'DELETE FROM enrollment_tokens WHERE org_id = $1',
      [TEST_ORG_ID],
    );
    await pool.query('DELETE FROM devices WHERE org_id = $1', [TEST_ORG_ID]);
    await stopRevocationListener();
    await app.close();
    await pool.end();
  });

  describe('POST /admin/enrollment-tokens', () => {
    it('rejects a user role', async () => {
      const u = await createAuthedDevice('user');
      const res = await app.inject({
        method: 'POST',
        url: '/admin/enrollment-tokens',
        headers: { authorization: `Bearer ${u.token}` },
        payload: { role: 'user' },
      });
      expect(res.statusCode).toBe(403);
    });

    it('admin can create a user token', async () => {
      const admin = await createAuthedDevice('admin');
      const res = await app.inject({
        method: 'POST',
        url: '/admin/enrollment-tokens',
        headers: { authorization: `Bearer ${admin.token}` },
        payload: { role: 'user', ttl_seconds: 3600 },
      });
      expect(res.statusCode).toBe(201);
      const body = res.json();
      expect(body.token).toMatch(/^[A-Za-z0-9_-]{43}$/);
      expect(body.token_id).toMatch(/^[0-9a-f-]{36}$/);
    });

    it('admin cannot create an admin token', async () => {
      const admin = await createAuthedDevice('admin');
      const res = await app.inject({
        method: 'POST',
        url: '/admin/enrollment-tokens',
        headers: { authorization: `Bearer ${admin.token}` },
        payload: { role: 'admin' },
      });
      expect(res.statusCode).toBe(403);
    });

    it('owner can create an admin token', async () => {
      const owner = await createAuthedDevice('owner');
      const res = await app.inject({
        method: 'POST',
        url: '/admin/enrollment-tokens',
        headers: { authorization: `Bearer ${owner.token}` },
        payload: { role: 'admin' },
      });
      expect(res.statusCode).toBe(201);
    });
  });

  describe('GET /admin/enrollment-tokens', () => {
    it('lists tokens for org', async () => {
      const admin = await createAuthedDevice('admin');
      await app.inject({
        method: 'POST',
        url: '/admin/enrollment-tokens',
        headers: { authorization: `Bearer ${admin.token}` },
        payload: { role: 'user', ttl_seconds: 3600 },
      });
      const res = await app.inject({
        method: 'GET',
        url: '/admin/enrollment-tokens',
        headers: { authorization: `Bearer ${admin.token}` },
      });
      expect(res.statusCode).toBe(200);
      expect(Array.isArray(res.json().tokens)).toBe(true);
      expect(res.json().tokens.length).toBeGreaterThan(0);
      expect(res.json().tokens[0]).not.toHaveProperty('token');
    });
  });

  describe('POST /admin/devices/:id/revoke', () => {
    it('revokes a device and cascades to sessions', async () => {
      const admin = await createAuthedDevice('admin');
      const victim = await createAuthedDevice('user');

      const res = await app.inject({
        method: 'POST',
        url: `/admin/devices/${victim.device_id}/revoke`,
        headers: { authorization: `Bearer ${admin.token}` },
        payload: { reason: 'test_revoke' },
      });
      expect(res.statusCode).toBe(204);

      const db = await pool.query(
        'SELECT status, revoked_at FROM devices WHERE device_id = $1',
        [victim.device_id],
      );
      expect(db.rows[0].status).toBe('revoked');
      expect(db.rows[0].revoked_at).not.toBeNull();

      // Victim's session no longer works
      const meRes = await app.inject({
        method: 'GET',
        url: '/me',
        headers: { authorization: `Bearer ${victim.token}` },
      });
      expect(meRes.statusCode).toBe(401);
    });

    it('rejects self-revoke', async () => {
      const admin = await createAuthedDevice('admin');
      const res = await app.inject({
        method: 'POST',
        url: `/admin/devices/${admin.device_id}/revoke`,
        headers: { authorization: `Bearer ${admin.token}` },
        payload: { reason: 'oops' },
      });
      expect(res.statusCode).toBe(400);
    });

    it('rejects cross-org revoke', async () => {
      const admin = await createAuthedDevice('admin');
      const otherOrgDeviceId = randomUUID();
      const otherKey = randomBytes(32);
      await pool.query(
        `INSERT INTO devices (device_id, org_id, public_key, label, role)
         VALUES ($1, $2, $3, $4, $5)`,
        [
          otherOrgDeviceId,
          randomUUID(),
          Buffer.from(otherKey),
          'other-org',
          'user',
        ],
      );
      const res = await app.inject({
        method: 'POST',
        url: `/admin/devices/${otherOrgDeviceId}/revoke`,
        headers: { authorization: `Bearer ${admin.token}` },
        payload: { reason: 'test' },
      });
      expect(res.statusCode).toBe(404);
      await pool.query('DELETE FROM devices WHERE device_id = $1', [otherOrgDeviceId]);
    });
  });

  describe('POST /admin/devices/:id/suspend and /resume', () => {
    it('suspends and resumes', async () => {
      const admin = await createAuthedDevice('admin');
      const target = await createAuthedDevice('user');

      const suspend = await app.inject({
        method: 'POST',
        url: `/admin/devices/${target.device_id}/suspend`,
        headers: { authorization: `Bearer ${admin.token}` },
        payload: { reason: 'test' },
      });
      expect(suspend.statusCode).toBe(204);

      // Suspended device cannot authenticate
      const chRes = await app.inject({
        method: 'POST',
        url: '/auth/challenge',
        payload: { device_id: target.device_id, purpose: 'auth' },
      });
      expect(chRes.statusCode).toBe(401);

      const resume = await app.inject({
        method: 'POST',
        url: `/admin/devices/${target.device_id}/resume`,
        headers: { authorization: `Bearer ${admin.token}` },
      });
      expect(resume.statusCode).toBe(204);

      const after = await pool.query(
        'SELECT status FROM devices WHERE device_id = $1',
        [target.device_id],
      );
      expect(after.rows[0].status).toBe('active');
    });
  });

  describe('GET /admin/devices', () => {
    it('lists devices in own org', async () => {
      const admin = await createAuthedDevice('admin');
      const res = await app.inject({
        method: 'GET',
        url: '/admin/devices',
        headers: { authorization: `Bearer ${admin.token}` },
      });
      expect(res.statusCode).toBe(200);
      expect(Array.isArray(res.json().devices)).toBe(true);
      for (const d of res.json().devices) {
        expect(d).not.toHaveProperty('public_key');
      }
    });
  });

  describe('GET /admin/audit/verify', () => {
    it('only owner can verify', async () => {
      const admin = await createAuthedDevice('admin');
      const res = await app.inject({
        method: 'GET',
        url: '/admin/audit/verify',
        headers: { authorization: `Bearer ${admin.token}` },
      });
      expect(res.statusCode).toBe(403);
    });

    it('owner verifies the chain', async () => {
      const owner = await createAuthedDevice('owner');
      const res = await app.inject({
        method: 'GET',
        url: '/admin/audit/verify',
        headers: { authorization: `Bearer ${owner.token}` },
      });
      expect(res.statusCode).toBe(200);
      expect(res.json().intact).toBe(true);
      expect(res.json().total_events).toBeGreaterThan(0);
    });
  });

  describe('audit chain integrity', () => {
    it('rejects mutation of audit_events (append-only trigger)', async () => {
      const before = await pool.query('SELECT event_id FROM audit_events LIMIT 1');
      if (before.rowCount === 0) return;
      const id = before.rows[0].event_id;
      await expect(
        pool.query(`UPDATE audit_events SET event_type = 'tampered' WHERE event_id = $1`, [id]),
      ).rejects.toThrow(/append-only/);
    });
  });
});
