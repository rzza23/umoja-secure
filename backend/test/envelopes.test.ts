import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { randomBytes, randomUUID } from 'node:crypto';
import * as ed from '@noble/ed25519';
import { buildApp } from '../src/app.js';
import { pool } from '../src/db/client.js';
import { canonicalizeChallenge, type Challenge } from '../src/auth/canonical.js';
import { authorizePair } from './helpers/authorize.js';

const TEST_ORG_ID = '00000000-0000-0000-0000-000000000066';

interface TestDevice {
  device_id: string;
  token: string;
}

let app: Awaited<ReturnType<typeof buildApp>>;

const activeDevices: string[] = [];

async function createAuthedDevice(): Promise<TestDevice> {
  const private_key = randomBytes(32);
  const public_key = await ed.getPublicKeyAsync(private_key);
  const device_id = randomUUID();
  await pool.query(
    `INSERT INTO devices (device_id, org_id, public_key, label, role)
     VALUES ($1, $2, $3, $4, $5)`,
    [device_id, TEST_ORG_ID, Buffer.from(public_key), 'env-test', 'user'],
  );

  // Auto-authorize this device against every other device in this test file.
  // Envelope tests always intend the two devices to be contacts.
  for (const other of activeDevices) {
    await authorizePair(TEST_ORG_ID, device_id, other);
  }
  activeDevices.push(device_id);
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
  return { device_id, token: verifyRes.json().session_token };
}

function makeCiphertext(size = 64): string {
  return randomBytes(size).toString('base64url');
}

describe('envelope queue', () => {
  beforeAll(async () => {
    app = await buildApp();
    await app.ready();
  });

  afterAll(async () => {
    await pool.query(
      'DELETE FROM envelopes WHERE sender_device_id IN (SELECT device_id FROM devices WHERE org_id = $1)',
      [TEST_ORG_ID],
    );
    await pool.query(
      'DELETE FROM one_time_prekeys WHERE device_id IN (SELECT device_id FROM devices WHERE org_id = $1)',
      [TEST_ORG_ID],
    );
    await pool.query(
      'DELETE FROM prekey_bundles WHERE device_id IN (SELECT device_id FROM devices WHERE org_id = $1)',
      [TEST_ORG_ID],
    );
    await pool.query('DELETE FROM contacts WHERE org_id = $1', [TEST_ORG_ID]);
    await pool.query('DELETE FROM devices WHERE org_id = $1', [TEST_ORG_ID]);
    activeDevices.length = 0;
    await app.close();
    await pool.end();
  });

  describe('POST /envelopes', () => {
    it('rejects without session', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/envelopes',
        payload: { recipient_device_id: randomUUID(), ciphertext: makeCiphertext() },
      });
      expect(res.statusCode).toBe(401);
    });

    it('queues an envelope for an active recipient', async () => {
      const sender = await createAuthedDevice();
      const recipient = await createAuthedDevice();
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
      const body = res.json();
      expect(body.envelope_id).toMatch(/^[0-9a-f-]{36}$/);
      expect(body.expires_at).toBeTruthy();
    });

    it('rejects unknown recipient', async () => {
      const sender = await createAuthedDevice();
      const res = await app.inject({
        method: 'POST',
        url: '/envelopes',
        headers: { authorization: `Bearer ${sender.token}` },
        payload: { recipient_device_id: randomUUID(), ciphertext: makeCiphertext() },
      });
      expect(res.statusCode).toBe(404);
      expect(res.json().error).toBe('recipient_unavailable');
    });

    it('rejects revoked recipient', async () => {
      const sender = await createAuthedDevice();
      const recipient = await createAuthedDevice();
      await pool.query(
        `UPDATE devices SET status = 'revoked', revoked_at = now(), revoke_reason = 'test' WHERE device_id = $1`,
        [recipient.device_id],
      );
      const res = await app.inject({
        method: 'POST',
        url: '/envelopes',
        headers: { authorization: `Bearer ${sender.token}` },
        payload: { recipient_device_id: recipient.device_id, ciphertext: makeCiphertext() },
      });
      expect(res.statusCode).toBe(404);
    });

    it('rejects empty ciphertext', async () => {
      const sender = await createAuthedDevice();
      const recipient = await createAuthedDevice();
      const res = await app.inject({
        method: 'POST',
        url: '/envelopes',
        headers: { authorization: `Bearer ${sender.token}` },
        payload: { recipient_device_id: recipient.device_id, ciphertext: '' },
      });
      expect(res.statusCode).toBe(400);
    });
  });

  describe('GET /envelopes/pending', () => {
    it('lists only own queued envelopes', async () => {
      const alice = await createAuthedDevice();
      const bob = await createAuthedDevice();
      const carol = await createAuthedDevice();

      await app.inject({
        method: 'POST',
        url: '/envelopes',
        headers: { authorization: `Bearer ${alice.token}` },
        payload: { recipient_device_id: bob.device_id, ciphertext: makeCiphertext() },
      });
      await app.inject({
        method: 'POST',
        url: '/envelopes',
        headers: { authorization: `Bearer ${carol.token}` },
        payload: { recipient_device_id: bob.device_id, ciphertext: makeCiphertext() },
      });
      await app.inject({
        method: 'POST',
        url: '/envelopes',
        headers: { authorization: `Bearer ${bob.token}` },
        payload: { recipient_device_id: alice.device_id, ciphertext: makeCiphertext() },
      });

      const bobPending = await app.inject({
        method: 'GET',
        url: '/envelopes/pending',
        headers: { authorization: `Bearer ${bob.token}` },
      });
      expect(bobPending.statusCode).toBe(200);
      const envelopes = bobPending.json().envelopes as Array<{ sender_device_id: string }>;
      expect(envelopes.length).toBe(2);
      for (const e of envelopes) {
        expect([alice.device_id, carol.device_id]).toContain(e.sender_device_id);
      }
    });
  });

  describe('GET /envelopes/:id', () => {
    it('returns ciphertext and transitions to delivered', async () => {
      const sender = await createAuthedDevice();
      const recipient = await createAuthedDevice();
      const ciphertext = makeCiphertext(100);

      const submitRes = await app.inject({
        method: 'POST',
        url: '/envelopes',
        headers: { authorization: `Bearer ${sender.token}` },
        payload: { recipient_device_id: recipient.device_id, ciphertext },
      });
      const envelope_id = submitRes.json().envelope_id;

      const fetchRes = await app.inject({
        method: 'GET',
        url: `/envelopes/${envelope_id}`,
        headers: { authorization: `Bearer ${recipient.token}` },
      });
      expect(fetchRes.statusCode).toBe(200);
      const body = fetchRes.json();
      expect(body.ciphertext).toBe(ciphertext);
      expect(body.sender_device_id).toBe(sender.device_id);

      const db = await pool.query(
        'SELECT status, delivered_at FROM envelopes WHERE envelope_id = $1',
        [envelope_id],
      );
      expect(db.rows[0].status).toBe('delivered');
      expect(db.rows[0].delivered_at).not.toBeNull();
    });

    it('rejects fetch from non-recipient', async () => {
      const sender = await createAuthedDevice();
      const recipient = await createAuthedDevice();
      const other = await createAuthedDevice();

      const submitRes = await app.inject({
        method: 'POST',
        url: '/envelopes',
        headers: { authorization: `Bearer ${sender.token}` },
        payload: { recipient_device_id: recipient.device_id, ciphertext: makeCiphertext() },
      });
      const envelope_id = submitRes.json().envelope_id;

      const fetchRes = await app.inject({
        method: 'GET',
        url: `/envelopes/${envelope_id}`,
        headers: { authorization: `Bearer ${other.token}` },
      });
      expect(fetchRes.statusCode).toBe(404);
    });
  });

  describe('POST /envelopes/:id/ack', () => {
    it('transitions delivered to retrieved', async () => {
      const sender = await createAuthedDevice();
      const recipient = await createAuthedDevice();
      const submitRes = await app.inject({
        method: 'POST',
        url: '/envelopes',
        headers: { authorization: `Bearer ${sender.token}` },
        payload: { recipient_device_id: recipient.device_id, ciphertext: makeCiphertext() },
      });
      const envelope_id = submitRes.json().envelope_id;

      await app.inject({
        method: 'GET',
        url: `/envelopes/${envelope_id}`,
        headers: { authorization: `Bearer ${recipient.token}` },
      });

      const ackRes = await app.inject({
        method: 'POST',
        url: `/envelopes/${envelope_id}/ack`,
        headers: { authorization: `Bearer ${recipient.token}` },
      });
      expect(ackRes.statusCode).toBe(204);

      const db = await pool.query(
        'SELECT status, retrieved_at FROM envelopes WHERE envelope_id = $1',
        [envelope_id],
      );
      expect(db.rows[0].status).toBe('retrieved');
      expect(db.rows[0].retrieved_at).not.toBeNull();
    });

    it('is idempotent on repeat ack', async () => {
      const sender = await createAuthedDevice();
      const recipient = await createAuthedDevice();
      const submitRes = await app.inject({
        method: 'POST',
        url: '/envelopes',
        headers: { authorization: `Bearer ${sender.token}` },
        payload: { recipient_device_id: recipient.device_id, ciphertext: makeCiphertext() },
      });
      const envelope_id = submitRes.json().envelope_id;

      await app.inject({
        method: 'GET',
        url: `/envelopes/${envelope_id}`,
        headers: { authorization: `Bearer ${recipient.token}` },
      });
      await app.inject({
        method: 'POST',
        url: `/envelopes/${envelope_id}/ack`,
        headers: { authorization: `Bearer ${recipient.token}` },
      });
      const second = await app.inject({
        method: 'POST',
        url: `/envelopes/${envelope_id}/ack`,
        headers: { authorization: `Bearer ${recipient.token}` },
      });
      expect(second.statusCode).toBe(204);
    });

    it('rejects ack before delivery (409)', async () => {
      const sender = await createAuthedDevice();
      const recipient = await createAuthedDevice();
      const submitRes = await app.inject({
        method: 'POST',
        url: '/envelopes',
        headers: { authorization: `Bearer ${sender.token}` },
        payload: { recipient_device_id: recipient.device_id, ciphertext: makeCiphertext() },
      });
      const envelope_id = submitRes.json().envelope_id;

      const ackRes = await app.inject({
        method: 'POST',
        url: `/envelopes/${envelope_id}/ack`,
        headers: { authorization: `Bearer ${recipient.token}` },
      });
      expect(ackRes.statusCode).toBe(409);
    });

    it('rejects ack from non-recipient (404)', async () => {
      const sender = await createAuthedDevice();
      const recipient = await createAuthedDevice();
      const other = await createAuthedDevice();
      const submitRes = await app.inject({
        method: 'POST',
        url: '/envelopes',
        headers: { authorization: `Bearer ${sender.token}` },
        payload: { recipient_device_id: recipient.device_id, ciphertext: makeCiphertext() },
      });
      const envelope_id = submitRes.json().envelope_id;

      await app.inject({
        method: 'GET',
        url: `/envelopes/${envelope_id}`,
        headers: { authorization: `Bearer ${recipient.token}` },
      });

      const ackRes = await app.inject({
        method: 'POST',
        url: `/envelopes/${envelope_id}/ack`,
        headers: { authorization: `Bearer ${other.token}` },
      });
      expect(ackRes.statusCode).toBe(404);
    });
  });
});
