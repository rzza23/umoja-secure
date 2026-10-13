import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { randomBytes, randomUUID } from 'node:crypto';
import * as ed from '@noble/ed25519';
import WebSocket from 'ws';
import type { AddressInfo } from 'node:net';
import { buildApp } from '../src/app.js';
import { pool } from '../src/db/client.js';
import { canonicalizeChallenge, type Challenge } from '../src/auth/canonical.js';
import { authorizePair } from './helpers/authorize.js';
import {
  notifyDeviceRevoked,
  startRevocationListener,
  stopRevocationListener,
} from '../src/ws/revocation.js';

const TEST_ORG_ID = '00000000-0000-0000-0000-000000000055';

interface TestDevice {
  device_id: string;
  token: string;
  private_key: Uint8Array;
}

let app: Awaited<ReturnType<typeof buildApp>>;
let port: number;

const activeDevices: string[] = [];

async function createAuthedDevice(): Promise<TestDevice> {
  const private_key = randomBytes(32);
  const public_key = await ed.getPublicKeyAsync(private_key);
  const device_id = randomUUID();
  await pool.query(
    `INSERT INTO devices (device_id, org_id, public_key, label, role)
     VALUES ($1, $2, $3, $4, $5)`,
    [device_id, TEST_ORG_ID, Buffer.from(public_key), 'ws-test', 'user'],
  );
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
  return { device_id, token: verifyRes.json().session_token, private_key };
}

function connect(): WebSocket {
  return new WebSocket(`ws://127.0.0.1:${port}/ws`);
}

async function waitForFrame(
  frames: unknown[],
  predicate: (f: any) => boolean,
  timeoutMs = 5000,
): Promise<any> {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    const found = frames.find(predicate);
    if (found) return found;
    await new Promise((r) => setTimeout(r, 25));
  }
  throw new Error(
    `timeout waiting for frame; got: ${JSON.stringify(frames, null, 2)}`,
  );
}

function attachCollector(ws: WebSocket): unknown[] {
  const frames: unknown[] = [];
  ws.on('message', (raw: Buffer) => {
    try {
      frames.push(JSON.parse(raw.toString('utf8')));
    } catch {
      // ignore non-JSON
    }
  });
  return frames;
}

async function openAndAuth(ws: WebSocket, token: string): Promise<unknown[]> {
  const frames = attachCollector(ws);
  await new Promise<void>((resolve, reject) => {
    ws.once('open', () => resolve());
    ws.once('error', reject);
  });
  ws.send(JSON.stringify({ type: 'auth', session_token: token }));
  await waitForFrame(frames, (f) => f.type === 'auth_ok');
  return frames;
}

function closeAndWait(ws: WebSocket): Promise<number> {
  return new Promise((resolve) => {
    if (ws.readyState === WebSocket.CLOSED) return resolve(1000);
    ws.once('close', (code) => resolve(code));
    ws.close();
  });
}

describe('WebSocket envelope push', () => {
  beforeAll(async () => {
    app = await buildApp();
    await app.listen({ port: 0, host: '127.0.0.1' });
    const addr = app.server.address() as AddressInfo;
    port = addr.port;
    await startRevocationListener();
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
    await stopRevocationListener();
    await app.close();
    await pool.end();
  });

  it('rejects a connection that does not send auth frame', async () => {
    const ws = connect();
    const frames = attachCollector(ws);
    await new Promise<void>((resolve) => ws.once('open', () => resolve()));
    const code = await new Promise<number>((resolve) => {
      ws.once('close', (c) => resolve(c));
    });
    expect(code).toBe(4401);
    expect(frames.length).toBe(0);
  });

  it('rejects an invalid session token', async () => {
    const ws = connect();
    const frames = attachCollector(ws);
    const closedCode = new Promise<number>((resolve) => {
      ws.once('close', (c) => resolve(c));
    });
    await new Promise<void>((resolve) => ws.once('open', () => resolve()));
    ws.send(JSON.stringify({ type: 'auth', session_token: 'not-a-real-token' }));
    await waitForFrame(frames, (f) => f.type === 'auth_fail');
    const code = await closedCode;
    expect(code).toBe(4401);
  });

  it('accepts a valid session and sends auth_ok', async () => {
    const dev = await createAuthedDevice();
    const ws = connect();
    const frames = await openAndAuth(ws, dev.token);
    const ok = frames.find((f: any) => f.type === 'auth_ok') as any;
    expect(ok.ws_id).toBeTruthy();
    expect(ok.revalidate_after_seconds).toBeGreaterThan(0);
    await closeAndWait(ws);
  });

  it('pushes an envelope to a connected recipient', async () => {
    const sender = await createAuthedDevice();
    const recipient = await createAuthedDevice();

    const ws = connect();
    const frames = await openAndAuth(ws, recipient.token);

    const ciphertext = randomBytes(64).toString('base64url');
    const submitRes = await app.inject({
      method: 'POST',
      url: '/envelopes',
      headers: { authorization: `Bearer ${sender.token}` },
      payload: {
        recipient_device_id: recipient.device_id,
        ciphertext,
      },
    });
    expect(submitRes.statusCode).toBe(201);
    const envelope_id = submitRes.json().envelope_id;

    const pushed = await waitForFrame(
      frames,
      (f: any) => f.type === 'envelope' && f.envelope_id === envelope_id,
    );
    expect(pushed.ciphertext).toBe(ciphertext);
    expect(pushed.sender_device_id).toBe(sender.device_id);

    // Envelope marked delivered
    const db = await pool.query(
      'SELECT status FROM envelopes WHERE envelope_id = $1',
      [envelope_id],
    );
    expect(db.rows[0].status).toBe('delivered');

    await closeAndWait(ws);
  });

  it('leaves envelope queued when recipient is offline', async () => {
    const sender = await createAuthedDevice();
    const recipient = await createAuthedDevice();

    const submitRes = await app.inject({
      method: 'POST',
      url: '/envelopes',
      headers: { authorization: `Bearer ${sender.token}` },
      payload: {
        recipient_device_id: recipient.device_id,
        ciphertext: randomBytes(64).toString('base64url'),
      },
    });
    expect(submitRes.statusCode).toBe(201);
    const envelope_id = submitRes.json().envelope_id;

    const db = await pool.query(
      'SELECT status FROM envelopes WHERE envelope_id = $1',
      [envelope_id],
    );
    expect(db.rows[0].status).toBe('queued');
  });

  it('closes connection when device is revoked', async () => {
    const dev = await createAuthedDevice();
    const ws = connect();
    await openAndAuth(ws, dev.token);

    const closedCode = new Promise<number>((resolve) => {
      ws.once('close', (c) => resolve(c));
    });

    await pool.query(
      `UPDATE devices SET status = 'revoked', revoked_at = now(), revoke_reason = 'test' WHERE device_id = $1`,
      [dev.device_id],
    );
    await notifyDeviceRevoked(dev.device_id);

    const code = await closedCode;
    expect(code).toBe(4403);
  });

  it('sends revalidate frame on schedule', async () => {
    const dev = await createAuthedDevice();
    const ws = connect();
    const frames = await openAndAuth(ws, dev.token);

    const reval = await waitForFrame(
      frames,
      (f: any) => f.type === 'revalidate',
      5000,
    );
    expect(reval.challenge).toBeTruthy();
    expect(reval.challenge.device_id).toBe(dev.device_id);

    await closeAndWait(ws);
  });

  it('accepts a valid revalidate_response', async () => {
    const dev = await createAuthedDevice();
    const ws = connect();
    const frames = await openAndAuth(ws, dev.token);

    const reval = await waitForFrame(
      frames,
      (f: any) => f.type === 'revalidate',
      5000,
    );
    const challenge = reval.challenge as Challenge;
    const message = canonicalizeChallenge(challenge);
    const signature = await ed.signAsync(message, dev.private_key);

    ws.send(
      JSON.stringify({
        type: 'revalidate_response',
        signature: Buffer.from(signature).toString('base64url'),
      }),
    );

    await waitForFrame(frames, (f: any) => f.type === 'revalidate_ok');
    await closeAndWait(ws);
  });

  it('closes connection when revalidation fails', async () => {
    const dev = await createAuthedDevice();
    const ws = connect();
    const frames = await openAndAuth(ws, dev.token);

    await waitForFrame(frames, (f: any) => f.type === 'revalidate', 5000);

    const closedCode = new Promise<number>((resolve) => {
      ws.once('close', (c) => resolve(c));
    });

    // Sign with a wrong key
    const wrongKey = randomBytes(32);
    const badSig = await ed.signAsync(randomBytes(32), wrongKey);
    ws.send(
      JSON.stringify({
        type: 'revalidate_response',
        signature: Buffer.from(badSig).toString('base64url'),
      }),
    );

    const code = await closedCode;
    expect(code).toBe(4401);
  });
});
