import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { randomBytes, randomUUID } from 'node:crypto';
import * as ed from '@noble/ed25519';
import { buildApp } from '../src/app.js';
import { pool } from '../src/db/client.js';
import { canonicalizeChallenge, type Challenge } from '../src/auth/canonical.js';

const TEST_ORG_ID = '00000000-0000-0000-0000-000000000077';

interface TestDevice {
  device_id: string;
  token: string;
}

async function createAuthedDevice(): Promise<TestDevice> {
  const private_key = randomBytes(32);
  const public_key = await ed.getPublicKeyAsync(private_key);
  const device_id = randomUUID();
  await pool.query(
    `INSERT INTO devices (device_id, org_id, public_key, label, role)
     VALUES ($1, $2, $3, $4, $5)`,
    [device_id, TEST_ORG_ID, Buffer.from(public_key), 'prekey-test', 'user'],
  );

  const app = await buildApp();
  await app.ready();
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
  await app.close();

  return { device_id, token: verifyRes.json().session_token };
}

function b64(len: number): string {
  return randomBytes(len).toString('base64url');
}

function makeUpload(otpCount: number): Record<string, unknown> {
  return {
    identity_key: b64(32),
    signed_prekey_id: 1,
    signed_prekey_public: b64(32),
    signed_prekey_signature: b64(64),
    registration_id: 12345,
    one_time_prekeys: Array.from({ length: otpCount }, (_, i) => ({
      id: i + 1,
      public_key: b64(32),
    })),
  };
}

describe('prekey directory', () => {
  let app: Awaited<ReturnType<typeof buildApp>>;

  beforeAll(async () => {
    app = await buildApp();
    await app.ready();
  });

  afterAll(async () => {
    await pool.query('DELETE FROM one_time_prekeys WHERE device_id IN (SELECT device_id FROM devices WHERE org_id = $1)', [TEST_ORG_ID]);
    await pool.query('DELETE FROM prekey_bundles WHERE device_id IN (SELECT device_id FROM devices WHERE org_id = $1)', [TEST_ORG_ID]);
    await pool.query('DELETE FROM enrollment_tokens WHERE org_id = $1', [TEST_ORG_ID]);
    await pool.query('DELETE FROM devices WHERE org_id = $1', [TEST_ORG_ID]);
    await app.close();
    await pool.end();
  });

  describe('POST /prekeys', () => {
    it('rejects without session', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/prekeys',
        payload: makeUpload(5),
      });
      expect(res.statusCode).toBe(401);
    });

    it('uploads a bundle and one-time prekeys', async () => {
      const dev = await createAuthedDevice();
      const res = await app.inject({
        method: 'POST',
        url: '/prekeys',
        headers: { authorization: `Bearer ${dev.token}` },
        payload: makeUpload(5),
      });
      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.stored_prekeys).toBe(5);
      expect(body.total_unconsumed).toBe(5);
    });

    it('is idempotent on re-upload (same OTP IDs)', async () => {
      const dev = await createAuthedDevice();
      const payload = makeUpload(3);

      const first = await app.inject({
        method: 'POST',
        url: '/prekeys',
        headers: { authorization: `Bearer ${dev.token}` },
        payload,
      });
      expect(first.statusCode).toBe(200);
      expect(first.json().stored_prekeys).toBe(3);

      const second = await app.inject({
        method: 'POST',
        url: '/prekeys',
        headers: { authorization: `Bearer ${dev.token}` },
        payload,
      });
      expect(second.statusCode).toBe(200);
      expect(second.json().stored_prekeys).toBe(0);
      expect(second.json().total_unconsumed).toBe(3);
    });

    it('rejects malformed key length', async () => {
      const dev = await createAuthedDevice();
      const bad = { ...makeUpload(1), identity_key: b64(31) };
      const res = await app.inject({
        method: 'POST',
        url: '/prekeys',
        headers: { authorization: `Bearer ${dev.token}` },
        payload: bad,
      });
      expect(res.statusCode).toBe(400);
    });
  });

  describe('GET /prekeys/status', () => {
    it('returns status for own device', async () => {
      const dev = await createAuthedDevice();
      await app.inject({
        method: 'POST',
        url: '/prekeys',
        headers: { authorization: `Bearer ${dev.token}` },
        payload: makeUpload(7),
      });
      const res = await app.inject({
        method: 'GET',
        url: '/prekeys/status',
        headers: { authorization: `Bearer ${dev.token}` },
      });
      expect(res.statusCode).toBe(200);
      expect(res.json().has_bundle).toBe(true);
      expect(res.json().unconsumed_prekeys).toBe(7);
      expect(res.json().signed_prekey_id).toBe(1);
    });
  });

  describe('GET /prekeys/:device_id', () => {
    it('returns bundle with one one-time prekey and consumes it', async () => {
      const uploader = await createAuthedDevice();
      const fetcher = await createAuthedDevice();
      await app.inject({
        method: 'POST',
        url: '/prekeys',
        headers: { authorization: `Bearer ${uploader.token}` },
        payload: makeUpload(3),
      });

      const first = await app.inject({
        method: 'GET',
        url: `/prekeys/${uploader.device_id}`,
        headers: { authorization: `Bearer ${fetcher.token}` },
      });
      expect(first.statusCode).toBe(200);
      const b1 = first.json();
      expect(b1.device_id).toBe(uploader.device_id);
      expect(b1.one_time_prekey).not.toBeNull();
      const firstOtpId = b1.one_time_prekey.id;

      // Second fetch gets a different OTP
      const second = await app.inject({
        method: 'GET',
        url: `/prekeys/${uploader.device_id}`,
        headers: { authorization: `Bearer ${fetcher.token}` },
      });
      expect(second.statusCode).toBe(200);
      expect(second.json().one_time_prekey.id).not.toBe(firstOtpId);

      // Status confirms two consumed
      const status = await app.inject({
        method: 'GET',
        url: '/prekeys/status',
        headers: { authorization: `Bearer ${uploader.token}` },
      });
      expect(status.json().unconsumed_prekeys).toBe(1);
    });

    it('returns null one_time_prekey when exhausted', async () => {
      const uploader = await createAuthedDevice();
      const fetcher = await createAuthedDevice();
      await app.inject({
        method: 'POST',
        url: '/prekeys',
        headers: { authorization: `Bearer ${uploader.token}` },
        payload: makeUpload(1),
      });

      // Consume the only OTP
      await app.inject({
        method: 'GET',
        url: `/prekeys/${uploader.device_id}`,
        headers: { authorization: `Bearer ${fetcher.token}` },
      });

      const res = await app.inject({
        method: 'GET',
        url: `/prekeys/${uploader.device_id}`,
        headers: { authorization: `Bearer ${fetcher.token}` },
      });
      expect(res.statusCode).toBe(200);
      expect(res.json().one_time_prekey).toBeNull();
    });

    it('returns 404 for unknown device', async () => {
      const fetcher = await createAuthedDevice();
      const res = await app.inject({
        method: 'GET',
        url: `/prekeys/${randomUUID()}`,
        headers: { authorization: `Bearer ${fetcher.token}` },
      });
      expect(res.statusCode).toBe(404);
    });

    it('returns 404 for revoked device', async () => {
      const uploader = await createAuthedDevice();
      const fetcher = await createAuthedDevice();
      await app.inject({
        method: 'POST',
        url: '/prekeys',
        headers: { authorization: `Bearer ${uploader.token}` },
        payload: makeUpload(1),
      });
      await pool.query(
        `UPDATE devices SET status = 'revoked', revoked_at = now(), revoke_reason = 'test' WHERE device_id = $1`,
        [uploader.device_id],
      );
      const res = await app.inject({
        method: 'GET',
        url: `/prekeys/${uploader.device_id}`,
        headers: { authorization: `Bearer ${fetcher.token}` },
      });
      expect(res.statusCode).toBe(404);
    });

    it('rejects without session', async () => {
      const res = await app.inject({
        method: 'GET',
        url: `/prekeys/${randomUUID()}`,
      });
      expect(res.statusCode).toBe(401);
    });
  });
});
