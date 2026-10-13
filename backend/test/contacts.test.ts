import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { randomBytes, randomUUID } from 'node:crypto';
import * as ed from '@noble/ed25519';
import { buildApp } from '../src/app.js';
import { pool } from '../src/db/client.js';
import { canonicalizeChallenge, type Challenge } from '../src/auth/canonical.js';

const TEST_ORG_ID = '00000000-0000-0000-0000-000000000033';

interface TestDevice {
  device_id: string;
  token: string;
  role: 'owner' | 'admin' | 'user';
}

let app: Awaited<ReturnType<typeof buildApp>>;

async function createAuthedDevice(role: 'owner' | 'admin' | 'user' = 'user'): Promise<TestDevice> {
  const private_key = randomBytes(32);
  const public_key = await ed.getPublicKeyAsync(private_key);
  const device_id = randomUUID();
  await pool.query(
    `INSERT INTO devices (device_id, org_id, public_key, label, role)
     VALUES ($1, $2, $3, $4, $5)`,
    [device_id, TEST_ORG_ID, Buffer.from(public_key), `contact-test-${role}`, role],
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

describe('contact authorization', () => {
  beforeAll(async () => {
    app = await buildApp();
    await app.ready();
  });

  afterAll(async () => {
    await pool.query('DELETE FROM contacts WHERE org_id = $1', [TEST_ORG_ID]);
    await pool.query(
      'DELETE FROM envelopes WHERE sender_device_id IN (SELECT device_id FROM devices WHERE org_id = $1)',
      [TEST_ORG_ID],
    );
    await pool.query(
      'DELETE FROM prekey_bundles WHERE device_id IN (SELECT device_id FROM devices WHERE org_id = $1)',
      [TEST_ORG_ID],
    );
    await pool.query(
      'DELETE FROM one_time_prekeys WHERE device_id IN (SELECT device_id FROM devices WHERE org_id = $1)',
      [TEST_ORG_ID],
    );
    await pool.query(
      'DELETE FROM one_time_kyber_prekeys WHERE device_id IN (SELECT device_id FROM devices WHERE org_id = $1)',
      [TEST_ORG_ID],
    );
    await pool.query('DELETE FROM devices WHERE org_id = $1', [TEST_ORG_ID]);
    await app.close();
    await pool.end();
  });

  describe('admin contact management', () => {
    it('admin can authorize two devices', async () => {
      const admin = await createAuthedDevice('admin');
      const alice = await createAuthedDevice('user');
      const bob = await createAuthedDevice('user');

      const res = await app.inject({
        method: 'POST',
        url: '/admin/contacts',
        headers: { authorization: `Bearer ${admin.token}` },
        payload: {
          owner_device_id: alice.device_id,
          contact_device_id: bob.device_id,
          verification_level: 'directory',
        },
      });
      expect(res.statusCode).toBe(204);

      const rows = await pool.query(
        `SELECT owner_device_id, contact_device_id, status
         FROM contacts
         WHERE (owner_device_id = $1 AND contact_device_id = $2)
            OR (owner_device_id = $2 AND contact_device_id = $1)`,
        [alice.device_id, bob.device_id],
      );
      expect(rows.rowCount).toBe(2);
      for (const r of rows.rows) {
        expect(r.status).toBe('active');
      }
    });

    it('rejects self-contact', async () => {
      const admin = await createAuthedDevice('admin');
      const alice = await createAuthedDevice('user');

      const res = await app.inject({
        method: 'POST',
        url: '/admin/contacts',
        headers: { authorization: `Bearer ${admin.token}` },
        payload: {
          owner_device_id: alice.device_id,
          contact_device_id: alice.device_id,
        },
      });
      expect(res.statusCode).toBe(400);
      expect(res.json().error).toBe('cannot_contact_self');
    });

    it('rejects cross-org contact', async () => {
      const admin = await createAuthedDevice('admin');
      const alice = await createAuthedDevice('user');

      const foreignDeviceId = randomUUID();
      await pool.query(
        `INSERT INTO devices (device_id, org_id, public_key, label, role)
         VALUES ($1, $2, $3, $4, $5)`,
        [foreignDeviceId, randomUUID(), Buffer.from(randomBytes(32)), 'foreign', 'user'],
      );

      const res = await app.inject({
        method: 'POST',
        url: '/admin/contacts',
        headers: { authorization: `Bearer ${admin.token}` },
        payload: {
          owner_device_id: alice.device_id,
          contact_device_id: foreignDeviceId,
        },
      });
      expect(res.statusCode).toBe(403);

      await pool.query('DELETE FROM devices WHERE device_id = $1', [foreignDeviceId]);
    });

    it('user role cannot create contacts', async () => {
      const user = await createAuthedDevice('user');
      const alice = await createAuthedDevice('user');

      const res = await app.inject({
        method: 'POST',
        url: '/admin/contacts',
        headers: { authorization: `Bearer ${user.token}` },
        payload: {
          owner_device_id: user.device_id,
          contact_device_id: alice.device_id,
        },
      });
      expect(res.statusCode).toBe(403);
    });

    it('admin can revoke a contact pair', async () => {
      const admin = await createAuthedDevice('admin');
      const alice = await createAuthedDevice('user');
      const bob = await createAuthedDevice('user');

      await app.inject({
        method: 'POST',
        url: '/admin/contacts',
        headers: { authorization: `Bearer ${admin.token}` },
        payload: {
          owner_device_id: alice.device_id,
          contact_device_id: bob.device_id,
        },
      });

      const revoke = await app.inject({
        method: 'POST',
        url: `/admin/contacts/${alice.device_id}/${bob.device_id}/revoke`,
        headers: { authorization: `Bearer ${admin.token}` },
        payload: { reason: 'test_revoke' },
      });
      expect(revoke.statusCode).toBe(204);

      const rows = await pool.query(
        `SELECT status FROM contacts
         WHERE (owner_device_id = $1 AND contact_device_id = $2)
            OR (owner_device_id = $2 AND contact_device_id = $1)`,
        [alice.device_id, bob.device_id],
      );
      for (const r of rows.rows) {
        expect(r.status).toBe('revoked');
      }
    });

    it('lists contacts for the org', async () => {
      const admin = await createAuthedDevice('admin');
      const alice = await createAuthedDevice('user');
      const bob = await createAuthedDevice('user');

      await app.inject({
        method: 'POST',
        url: '/admin/contacts',
        headers: { authorization: `Bearer ${admin.token}` },
        payload: {
          owner_device_id: alice.device_id,
          contact_device_id: bob.device_id,
        },
      });

      const list = await app.inject({
        method: 'GET',
        url: '/admin/contacts',
        headers: { authorization: `Bearer ${admin.token}` },
      });
      expect(list.statusCode).toBe(200);
      const contacts = list.json().contacts as Array<{ owner_device_id: string }>;
      expect(contacts.some((c) => c.owner_device_id === alice.device_id)).toBe(true);
    });
  });

  describe('envelope authorization enforcement', () => {
    it('allows an authorized pair to submit an envelope', async () => {
      const admin = await createAuthedDevice('admin');
      const alice = await createAuthedDevice('user');
      const bob = await createAuthedDevice('user');

      await app.inject({
        method: 'POST',
        url: '/admin/contacts',
        headers: { authorization: `Bearer ${admin.token}` },
        payload: {
          owner_device_id: alice.device_id,
          contact_device_id: bob.device_id,
        },
      });

      const res = await app.inject({
        method: 'POST',
        url: '/envelopes',
        headers: { authorization: `Bearer ${alice.token}` },
        payload: {
          recipient_device_id: bob.device_id,
          ciphertext: randomBytes(64).toString('base64url'),
        },
      });
      expect(res.statusCode).toBe(201);
    });

    it('rejects envelope between unauthorized devices', async () => {
      const alice = await createAuthedDevice('user');
      const bob = await createAuthedDevice('user');

      const res = await app.inject({
        method: 'POST',
        url: '/envelopes',
        headers: { authorization: `Bearer ${alice.token}` },
        payload: {
          recipient_device_id: bob.device_id,
          ciphertext: randomBytes(64).toString('base64url'),
        },
      });
      expect(res.statusCode).toBe(403);
      expect(res.json().error).toBe('not_authorized_contact');
    });

    it('rejects envelope after contact revocation', async () => {
      const admin = await createAuthedDevice('admin');
      const alice = await createAuthedDevice('user');
      const bob = await createAuthedDevice('user');

      await app.inject({
        method: 'POST',
        url: '/admin/contacts',
        headers: { authorization: `Bearer ${admin.token}` },
        payload: {
          owner_device_id: alice.device_id,
          contact_device_id: bob.device_id,
        },
      });

      const ok = await app.inject({
        method: 'POST',
        url: '/envelopes',
        headers: { authorization: `Bearer ${alice.token}` },
        payload: {
          recipient_device_id: bob.device_id,
          ciphertext: randomBytes(64).toString('base64url'),
        },
      });
      expect(ok.statusCode).toBe(201);

      await app.inject({
        method: 'POST',
        url: `/admin/contacts/${alice.device_id}/${bob.device_id}/revoke`,
        headers: { authorization: `Bearer ${admin.token}` },
        payload: { reason: 'test' },
      });

      const blocked = await app.inject({
        method: 'POST',
        url: '/envelopes',
        headers: { authorization: `Bearer ${alice.token}` },
        payload: {
          recipient_device_id: bob.device_id,
          ciphertext: randomBytes(64).toString('base64url'),
        },
      });
      expect(blocked.statusCode).toBe(403);
    });
  });

  describe('prekey fetch authorization enforcement', () => {
    function uploadBody() {
      return {
        identity_key: randomBytes(32).toString('base64url'),
        signed_prekey_id: 1,
        signed_prekey_public: randomBytes(32).toString('base64url'),
        signed_prekey_signature: randomBytes(64).toString('base64url'),
        registration_id: 1234,
        kyber_prekey_id: 1,
        kyber_prekey_public: randomBytes(1568).toString('base64url'),
        kyber_prekey_signature: randomBytes(64).toString('base64url'),
        one_time_prekeys: [{ id: 1, public_key: randomBytes(32).toString('base64url') }],
        one_time_kyber_prekeys: [{ id: 1, public_key: randomBytes(1568).toString('base64url') }],
      };
    }

    it('allows an authorized peer to fetch a bundle', async () => {
      const admin = await createAuthedDevice('admin');
      const alice = await createAuthedDevice('user');
      const bob = await createAuthedDevice('user');

      await app.inject({
        method: 'POST',
        url: '/admin/contacts',
        headers: { authorization: `Bearer ${admin.token}` },
        payload: {
          owner_device_id: alice.device_id,
          contact_device_id: bob.device_id,
        },
      });

      const upload = await app.inject({
        method: 'POST',
        url: '/prekeys',
        headers: { authorization: `Bearer ${bob.token}` },
        payload: uploadBody(),
      });
      expect(upload.statusCode).toBe(200);

      const aliceFetch = await app.inject({
        method: 'GET',
        url: `/prekeys/${bob.device_id}`,
        headers: { authorization: `Bearer ${alice.token}` },
      });
      expect(aliceFetch.statusCode).toBe(200);
    });

    it('rejects prekey fetch from unauthorized device', async () => {
      const alice = await createAuthedDevice('user');
      const bob = await createAuthedDevice('user');

      await app.inject({
        method: 'POST',
        url: '/prekeys',
        headers: { authorization: `Bearer ${bob.token}` },
        payload: uploadBody(),
      });

      const aliceFetch = await app.inject({
        method: 'GET',
        url: `/prekeys/${bob.device_id}`,
        headers: { authorization: `Bearer ${alice.token}` },
      });
      // 404 rather than 403 to avoid leaking device existence
      expect(aliceFetch.statusCode).toBe(404);
    });
  });
});
