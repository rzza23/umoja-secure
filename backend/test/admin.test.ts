import { describe, it, expect, beforeAll, afterAll, beforeEach } from 'vitest';
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
    await pool.query('DELETE FROM org_matrix_versions WHERE org_id = $1', [TEST_ORG_ID]);
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
        payload: {
          role: 'user',
          bound_public_key: randomBytes(32).toString('base64url'),
        },
      });
      expect(res.statusCode).toBe(403);
    });

    it('admin can create a user token', async () => {
      const admin = await createAuthedDevice('admin');
      const res = await app.inject({
        method: 'POST',
        url: '/admin/enrollment-tokens',
        headers: { authorization: `Bearer ${admin.token}` },
        payload: {
          role: 'user',
          ttl_seconds: 3600,
          bound_public_key: randomBytes(32).toString('base64url'),
        },
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
        payload: {
          role: 'admin',
          bound_public_key: randomBytes(32).toString('base64url'),
        },
      });
      expect(res.statusCode).toBe(403);
    });

    it('owner can create an admin token', async () => {
      const owner = await createAuthedDevice('owner');
      const res = await app.inject({
        method: 'POST',
        url: '/admin/enrollment-tokens',
        headers: { authorization: `Bearer ${owner.token}` },
        payload: {
          role: 'admin',
          bound_public_key: randomBytes(32).toString('base64url'),
        },
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
        payload: {
          role: 'user',
          ttl_seconds: 3600,
          bound_public_key: randomBytes(32).toString('base64url'),
        },
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

  describe('GET/POST /admin/matrix-version', () => {
    beforeEach(async () => {
      await pool.query('DELETE FROM org_matrix_versions WHERE org_id = $1', [TEST_ORG_ID]);
    });

    it('TEST-MATRIX-VERSION-ROUTE-USER-FORBIDDEN rejects user role', async () => {
      const u = await createAuthedDevice('user');
      const get = await app.inject({
        method: 'GET',
        url: '/admin/matrix-version',
        headers: { authorization: `Bearer ${u.token}` },
      });
      expect(get.statusCode).toBe(403);

      const post = await app.inject({
        method: 'POST',
        url: '/admin/matrix-version',
        headers: { authorization: `Bearer ${u.token}` },
        payload: { version: 1 },
      });
      expect(post.statusCode).toBe(403);
    });

    it('TEST-MATRIX-VERSION-ROUTE-VALIDATION rejects invalid bodies', async () => {
      const admin = await createAuthedDevice('admin');
      const invalid = [
        {},
        { version: 0 },
        { version: -1 },
        { version: 1.5 },
        { version: 'one' },
      ];
      for (const payload of invalid) {
        const res = await app.inject({
          method: 'POST',
          url: '/admin/matrix-version',
          headers: { authorization: `Bearer ${admin.token}` },
          payload,
        });
        expect(res.statusCode).toBe(400);
        expect(res.json().error).toBe('invalid_request');
      }
    });

    it('TEST-MATRIX-VERSION-ROUTE-OK GET nulls, POST asserts, GET populated', async () => {
      const admin = await createAuthedDevice('admin');

      const empty = await app.inject({
        method: 'GET',
        url: '/admin/matrix-version',
        headers: { authorization: `Bearer ${admin.token}` },
      });
      expect(empty.statusCode).toBe(200);
      expect(empty.json()).toEqual({
        current_version: null,
        asserted_at: null,
        asserted_by_device_id: null,
      });

      const assertRes = await app.inject({
        method: 'POST',
        url: '/admin/matrix-version',
        headers: { authorization: `Bearer ${admin.token}` },
        payload: { version: 3 },
      });
      expect(assertRes.statusCode).toBe(200);
      const body = assertRes.json();
      expect(body.current_version).toBe(3);
      expect(body.previous_version).toBeNull();
      expect(body.changed).toBe(true);
      expect(body.asserted_by_device_id).toBe(admin.device_id);

      const populated = await app.inject({
        method: 'GET',
        url: '/admin/matrix-version',
        headers: { authorization: `Bearer ${admin.token}` },
      });
      expect(populated.json().current_version).toBe(3);
      expect(populated.json().asserted_by_device_id).toBe(admin.device_id);
    });

    it('TEST-MATRIX-VERSION-ROUTE-REJECT-LOWER returns 409 on lower version', async () => {
      const admin = await createAuthedDevice('admin');
      await app.inject({
        method: 'POST',
        url: '/admin/matrix-version',
        headers: { authorization: `Bearer ${admin.token}` },
        payload: { version: 5 },
      });

      const res = await app.inject({
        method: 'POST',
        url: '/admin/matrix-version',
        headers: { authorization: `Bearer ${admin.token}` },
        payload: { version: 4 },
      });
      expect(res.statusCode).toBe(409);
      expect(res.json().error).toBe('version_below_current');
    });
  });

  describe('enrollment token floor (TASK-P1-030 3b)', () => {
    beforeEach(async () => {
      await pool.query('DELETE FROM org_matrix_versions WHERE org_id = $1', [TEST_ORG_ID]);
    });

    it('TEST-TOKEN-FLOOR-STAMPED stamps current version at issuance', async () => {
      const admin = await createAuthedDevice('admin');

      const assertRes = await app.inject({
        method: 'POST',
        url: '/admin/matrix-version',
        headers: { authorization: `Bearer ${admin.token}` },
        payload: { version: 3 },
      });
      expect(assertRes.statusCode).toBe(200);

      const tokenRes = await app.inject({
        method: 'POST',
        url: '/admin/enrollment-tokens',
        headers: { authorization: `Bearer ${admin.token}` },
        payload: {
          role: 'user',
          ttl_seconds: 3600,
          bound_public_key: randomBytes(32).toString('base64url'),
        },
      });
      expect(tokenRes.statusCode).toBe(201);
      expect(tokenRes.json().enrollment_matrix_version_floor).toBe(3);

      const db = await pool.query(
        'SELECT enrollment_matrix_version_floor FROM enrollment_tokens WHERE token_id = $1',
        [tokenRes.json().token_id],
      );
      expect(db.rows[0].enrollment_matrix_version_floor).toBe(3);
    });

    it('TEST-TOKEN-FLOOR-NULL-WHEN-NO-STATE null when org has no assertion', async () => {
      const admin = await createAuthedDevice('admin');

      const tokenRes = await app.inject({
        method: 'POST',
        url: '/admin/enrollment-tokens',
        headers: { authorization: `Bearer ${admin.token}` },
        payload: {
          role: 'user',
          ttl_seconds: 3600,
          bound_public_key: randomBytes(32).toString('base64url'),
        },
      });
      expect(tokenRes.statusCode).toBe(201);
      expect(tokenRes.json().enrollment_matrix_version_floor).toBeNull();

      const db = await pool.query(
        'SELECT enrollment_matrix_version_floor FROM enrollment_tokens WHERE token_id = $1',
        [tokenRes.json().token_id],
      );
      expect(db.rows[0].enrollment_matrix_version_floor).toBeNull();
    });

    it('TEST-TOKEN-FLOOR-FROZEN stamps at issuance, not at read', async () => {
      const admin = await createAuthedDevice('admin');

      await app.inject({
        method: 'POST',
        url: '/admin/matrix-version',
        headers: { authorization: `Bearer ${admin.token}` },
        payload: { version: 3 },
      });
      const tokenA = await app.inject({
        method: 'POST',
        url: '/admin/enrollment-tokens',
        headers: { authorization: `Bearer ${admin.token}` },
        payload: {
          role: 'user',
          ttl_seconds: 3600,
          bound_public_key: randomBytes(32).toString('base64url'),
        },
      });
      expect(tokenA.json().enrollment_matrix_version_floor).toBe(3);

      await app.inject({
        method: 'POST',
        url: '/admin/matrix-version',
        headers: { authorization: `Bearer ${admin.token}` },
        payload: { version: 7 },
      });
      const tokenB = await app.inject({
        method: 'POST',
        url: '/admin/enrollment-tokens',
        headers: { authorization: `Bearer ${admin.token}` },
        payload: {
          role: 'user',
          ttl_seconds: 3600,
          bound_public_key: randomBytes(32).toString('base64url'),
        },
      });
      expect(tokenB.json().enrollment_matrix_version_floor).toBe(7);

      const reRead = await pool.query(
        `SELECT token_id, enrollment_matrix_version_floor FROM enrollment_tokens
         WHERE token_id = ANY($1)`,
        [[tokenA.json().token_id, tokenB.json().token_id]],
      );
      const byId: Record<string, number | null> = Object.fromEntries(
        reRead.rows.map((r) => [
          r.token_id as string,
          r.enrollment_matrix_version_floor as number | null,
        ]),
      );
      expect(byId[tokenA.json().token_id]).toBe(3);
      expect(byId[tokenB.json().token_id]).toBe(7);
    });

    it('TEST-TOKEN-FLOOR-CONSTRAINT rejects floor = 0 at DB level', async () => {
      await expect(
        pool.query(
          `INSERT INTO enrollment_tokens
             (token_hash, org_id, role, expires_at, created_by,
              bound_public_key, enrollment_matrix_version_floor)
           VALUES ($1, $2, 'user', now() + interval '1 hour', $3, $4, 0)`,
          [randomBytes(32), TEST_ORG_ID, randomUUID(), randomBytes(32)],
        ),
      ).rejects.toThrow(/check constraint|enrollment_matrix_version_floor/i);
    });

    it('TEST-TOKEN-FLOOR-AUDIT floor appears in audit payload', async () => {
      const admin = await createAuthedDevice('admin');

      await app.inject({
        method: 'POST',
        url: '/admin/matrix-version',
        headers: { authorization: `Bearer ${admin.token}` },
        payload: { version: 5 },
      });

      await app.inject({
        method: 'POST',
        url: '/admin/enrollment-tokens',
        headers: { authorization: `Bearer ${admin.token}` },
        payload: {
          role: 'user',
          ttl_seconds: 3600,
          bound_public_key: randomBytes(32).toString('base64url'),
        },
      });

      const audit = await pool.query(
        `SELECT payload FROM audit_events
         WHERE event_type = 'enrollment_token.created'
           AND actor_device_id = $1
         ORDER BY event_id DESC LIMIT 1`,
        [admin.device_id],
      );
      expect(audit.rowCount).toBe(1);
      expect(audit.rows[0].payload.enrollment_matrix_version_floor).toBe(5);
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
