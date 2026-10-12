import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { randomBytes, randomUUID } from 'node:crypto';
import * as ed from '@noble/ed25519';
import { buildApp } from '../src/app.js';
import { pool } from '../src/db/client.js';
import { canonicalizeChallenge, type Challenge } from '../src/auth/canonical.js';

const TEST_ORG_ID = '00000000-0000-0000-0000-000000000088';

interface TestDevice {
  device_id: string;
  private_key: Uint8Array;
  public_key: Uint8Array;
}

async function createTestDevice(): Promise<TestDevice> {
  const private_key = randomBytes(32);
  const public_key = await ed.getPublicKeyAsync(private_key);
  const device_id = randomUUID();
  await pool.query(
    `INSERT INTO devices (device_id, org_id, public_key, label, role)
     VALUES ($1, $2, $3, $4, $5)`,
    [device_id, TEST_ORG_ID, Buffer.from(public_key), 'auth-test', 'user'],
  );
  return { device_id, private_key, public_key };
}

async function requestChallenge(
  app: Awaited<ReturnType<typeof buildApp>>,
  device_id: string,
): Promise<Challenge> {
  const res = await app.inject({
    method: 'POST',
    url: '/auth/challenge',
    payload: { device_id, purpose: 'auth' },
  });
  if (res.statusCode !== 200) {
    throw new Error(`challenge request failed: ${res.statusCode} ${res.body}`);
  }
  return res.json().challenge as Challenge;
}

describe('device authentication', () => {
  let app: Awaited<ReturnType<typeof buildApp>>;

  beforeAll(async () => {
    app = await buildApp();
    await app.ready();
  });

  afterAll(async () => {
    await pool.query('DELETE FROM enrollment_tokens WHERE org_id = $1', [TEST_ORG_ID]);
    await pool.query('DELETE FROM devices WHERE org_id = $1', [TEST_ORG_ID]);
    await app.close();
    await pool.end();
  });

  describe('POST /auth/challenge', () => {
    it('rejects unknown device', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/auth/challenge',
        payload: { device_id: randomUUID(), purpose: 'auth' },
      });
      expect(res.statusCode).toBe(401);
      expect(res.json().error).toBe('unauthorized');
    });

    it('returns challenge for active device', async () => {
      const dev = await createTestDevice();
      const res = await app.inject({
        method: 'POST',
        url: '/auth/challenge',
        payload: { device_id: dev.device_id, purpose: 'auth' },
      });
      expect(res.statusCode).toBe(200);
      const ch = res.json().challenge;
      expect(ch.v).toBe(1);
      expect(ch.purpose).toBe('auth');
      expect(ch.device_id).toBe(dev.device_id);
      expect(ch.nonce).toMatch(/^[A-Za-z0-9_-]{43}$/);
      expect(ch.server_id).toBeTruthy();
      // Ensure stored in DB
      const db = await pool.query(
        'SELECT used FROM auth_challenges WHERE challenge_id = $1',
        [ch.challenge_id],
      );
      expect(db.rowCount).toBe(1);
      expect(db.rows[0].used).toBe(false);
    });
  });

  describe('POST /auth/verify', () => {
    it('issues a session on valid signature', async () => {
      const dev = await createTestDevice();
      const challenge = await requestChallenge(app, dev.device_id);
      const message = canonicalizeChallenge(challenge);
      const signature = await ed.signAsync(message, dev.private_key);

      const res = await app.inject({
        method: 'POST',
        url: '/auth/verify',
        payload: {
          challenge_id: challenge.challenge_id,
          signature: Buffer.from(signature).toString('base64url'),
        },
      });
      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.session_token).toMatch(/^[A-Za-z0-9_-]{43}$/);
      expect(body.device_id).toBe(dev.device_id);
      expect(body.role).toBe('user');
      expect(new Date(body.expires_at).getTime()).toBeGreaterThan(Date.now());

      // DB has the session, revoked_at null
      const db = await pool.query(
        `SELECT revoked_at, expires_at FROM sessions WHERE device_id = $1`,
        [dev.device_id],
      );
      expect(db.rowCount).toBe(1);
      expect(db.rows[0].revoked_at).toBeNull();
    });

    it('rejects invalid signature', async () => {
      const dev = await createTestDevice();
      const challenge = await requestChallenge(app, dev.device_id);
      // Sign with a different key
      const wrongKey = randomBytes(32);
      const message = canonicalizeChallenge(challenge);
      const badSig = await ed.signAsync(message, wrongKey);

      const res = await app.inject({
        method: 'POST',
        url: '/auth/verify',
        payload: {
          challenge_id: challenge.challenge_id,
          signature: Buffer.from(badSig).toString('base64url'),
        },
      });
      expect(res.statusCode).toBe(401);
    });

    it('rejects reuse of challenge', async () => {
      const dev = await createTestDevice();
      const challenge = await requestChallenge(app, dev.device_id);
      const message = canonicalizeChallenge(challenge);
      const signature = await ed.signAsync(message, dev.private_key);
      const sigB64 = Buffer.from(signature).toString('base64url');

      const first = await app.inject({
        method: 'POST',
        url: '/auth/verify',
        payload: { challenge_id: challenge.challenge_id, signature: sigB64 },
      });
      expect(first.statusCode).toBe(200);

      const second = await app.inject({
        method: 'POST',
        url: '/auth/verify',
        payload: { challenge_id: challenge.challenge_id, signature: sigB64 },
      });
      expect(second.statusCode).toBe(401);
    });

    it('rejects expired challenge', async () => {
      const dev = await createTestDevice();
      const challengeId = randomUUID();
      const nonce = randomBytes(32);
      // Insert an already-expired challenge directly
      await pool.query(
        `INSERT INTO auth_challenges
           (challenge_id, device_id, nonce, purpose, issued_at, expires_at)
         VALUES ($1, $2, $3, $4, $5, $6)`,
        [
          challengeId,
          dev.device_id,
          nonce,
          'auth',
          new Date(Date.now() - 3600_000),
          new Date(Date.now() - 1000),
        ],
      );

      const res = await app.inject({
        method: 'POST',
        url: '/auth/verify',
        payload: {
          challenge_id: challengeId,
          signature: Buffer.alloc(64).toString('base64url'),
        },
      });
      expect(res.statusCode).toBe(401);
    });
  });

  describe('GET /me', () => {
    it('rejects without session', async () => {
      const res = await app.inject({ method: 'GET', url: '/me' });
      expect(res.statusCode).toBe(401);
    });

    it('returns device info with a valid session', async () => {
      const dev = await createTestDevice();
      const challenge = await requestChallenge(app, dev.device_id);
      const message = canonicalizeChallenge(challenge);
      const signature = await ed.signAsync(message, dev.private_key);
      const verifyRes = await app.inject({
        method: 'POST',
        url: '/auth/verify',
        payload: {
          challenge_id: challenge.challenge_id,
          signature: Buffer.from(signature).toString('base64url'),
        },
      });
      const token = verifyRes.json().session_token;

      const meRes = await app.inject({
        method: 'GET',
        url: '/me',
        headers: { authorization: `Bearer ${token}` },
      });
      expect(meRes.statusCode).toBe(200);
      expect(meRes.json().device_id).toBe(dev.device_id);
      expect(meRes.json().role).toBe('user');
    });
  });

  describe('POST /auth/logout', () => {
    it('revokes the session', async () => {
      const dev = await createTestDevice();
      const challenge = await requestChallenge(app, dev.device_id);
      const message = canonicalizeChallenge(challenge);
      const signature = await ed.signAsync(message, dev.private_key);
      const verifyRes = await app.inject({
        method: 'POST',
        url: '/auth/verify',
        payload: {
          challenge_id: challenge.challenge_id,
          signature: Buffer.from(signature).toString('base64url'),
        },
      });
      const token = verifyRes.json().session_token;

      const logoutRes = await app.inject({
        method: 'POST',
        url: '/auth/logout',
        headers: { authorization: `Bearer ${token}` },
      });
      expect(logoutRes.statusCode).toBe(204);

      const meRes = await app.inject({
        method: 'GET',
        url: '/me',
        headers: { authorization: `Bearer ${token}` },
      });
      expect(meRes.statusCode).toBe(401);
    });
  });

  describe('device revocation', () => {
    it('rejects challenge requests after device revoked', async () => {
      const dev = await createTestDevice();
      await pool.query(
        `UPDATE devices
         SET status = 'revoked', revoked_at = now(), revoke_reason = 'test'
         WHERE device_id = $1`,
        [dev.device_id],
      );
      const res = await app.inject({
        method: 'POST',
        url: '/auth/challenge',
        payload: { device_id: dev.device_id, purpose: 'auth' },
      });
      expect(res.statusCode).toBe(401);
    });

    it('rejects existing session after device revoked', async () => {
      const dev = await createTestDevice();
      const challenge = await requestChallenge(app, dev.device_id);
      const message = canonicalizeChallenge(challenge);
      const signature = await ed.signAsync(message, dev.private_key);
      const verifyRes = await app.inject({
        method: 'POST',
        url: '/auth/verify',
        payload: {
          challenge_id: challenge.challenge_id,
          signature: Buffer.from(signature).toString('base64url'),
        },
      });
      const token = verifyRes.json().session_token;

      // Confirm session works
      const before = await app.inject({
        method: 'GET',
        url: '/me',
        headers: { authorization: `Bearer ${token}` },
      });
      expect(before.statusCode).toBe(200);

      // Revoke device
      await pool.query(
        `UPDATE devices
         SET status = 'revoked', revoked_at = now(), revoke_reason = 'test'
         WHERE device_id = $1`,
        [dev.device_id],
      );

      // Session no longer valid (lookupSession joins on devices.status = 'active')
      const after = await app.inject({
        method: 'GET',
        url: '/me',
        headers: { authorization: `Bearer ${token}` },
      });
      expect(after.statusCode).toBe(401);
    });
  });
});
