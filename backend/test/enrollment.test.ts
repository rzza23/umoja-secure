import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { buildApp } from '../src/app.js';
import { pool } from '../src/db/client.js';

const TEST_ORG_ID = '00000000-0000-0000-0000-000000000099';

async function insertToken(opts: {
  tokenPlaintext: string;
  expiresAt: Date;
  createdAt?: Date;
  role?: string;
  used?: boolean;
  revoked?: boolean;
}): Promise<void> {
  const tokenHash = createHash('sha256').update(opts.tokenPlaintext).digest();
  await pool.query(
    `INSERT INTO enrollment_tokens
       (token_hash, org_id, role, expires_at, created_at, created_by, used_at, revoked_at)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
    [
      tokenHash,
      TEST_ORG_ID,
      opts.role ?? 'user',
      opts.expiresAt,
      opts.createdAt ?? new Date(),
      randomUUID(),
      opts.used ? new Date() : null,
      opts.revoked ? new Date() : null,
    ],
  );
}

function makePublicKey(): string {
  return randomBytes(32).toString('base64url');
}

describe('POST /enrollment', () => {
  let app: Awaited<ReturnType<typeof buildApp>>;

  beforeAll(async () => {
    app = await buildApp();
    await app.ready();
  });

  afterAll(async () => {
    // Tokens reference devices via used_by_device_id, so delete tokens first.
    await pool.query('DELETE FROM enrollment_tokens WHERE org_id = $1', [TEST_ORG_ID]);
    await pool.query('DELETE FROM devices WHERE org_id = $1', [TEST_ORG_ID]);
    await app.close();
    await pool.end();
  });

  it('enrolls a device with a valid token', async () => {
    const token = randomBytes(32).toString('base64url');
    await insertToken({ tokenPlaintext: token, expiresAt: new Date(Date.now() + 3600_000) });

    const res = await app.inject({
      method: 'POST',
      url: '/enrollment',
      payload: {
        token,
        device_public_key: makePublicKey(),
        label: 'test-device-1',
      },
    });

    expect(res.statusCode).toBe(201);
    const body = res.json();
    expect(body.device_id).toMatch(/^[0-9a-f-]{36}$/);
    expect(body.org_id).toBe(TEST_ORG_ID);
    expect(body.role).toBe('user');

    const dev = await pool.query(
      'SELECT label FROM devices WHERE device_id = $1',
      [body.device_id],
    );
    expect(dev.rowCount).toBe(1);
    expect(dev.rows[0].label).toBe('test-device-1');
  });

  it('rejects an expired token', async () => {
    const token = randomBytes(32).toString('base64url');
    // Both created_at and expires_at must be in the past to satisfy
    // CHECK (expires_at > created_at). Set created 2h ago, expired 1h ago.
    const now = Date.now();
    await insertToken({
      tokenPlaintext: token,
      createdAt: new Date(now - 2 * 3600_000),
      expiresAt: new Date(now - 1 * 3600_000),
    });

    const res = await app.inject({
      method: 'POST',
      url: '/enrollment',
      payload: { token, device_public_key: makePublicKey(), label: 'test-expired' },
    });

    expect(res.statusCode).toBe(401);
    expect(res.json().error).toBe('invalid_token');
  });

  it('rejects a reused token', async () => {
    const token = randomBytes(32).toString('base64url');
    await insertToken({
      tokenPlaintext: token,
      expiresAt: new Date(Date.now() + 3600_000),
      used: true,
    });

    const res = await app.inject({
      method: 'POST',
      url: '/enrollment',
      payload: { token, device_public_key: makePublicKey(), label: 'test-reused' },
    });

    expect(res.statusCode).toBe(401);
  });

  it('rejects a revoked token', async () => {
    const token = randomBytes(32).toString('base64url');
    await insertToken({
      tokenPlaintext: token,
      expiresAt: new Date(Date.now() + 3600_000),
      revoked: true,
    });

    const res = await app.inject({
      method: 'POST',
      url: '/enrollment',
      payload: { token, device_public_key: makePublicKey(), label: 'test-revoked' },
    });

    expect(res.statusCode).toBe(401);
  });

  it('rejects a duplicate public key', async () => {
    const token1 = randomBytes(32).toString('base64url');
    const token2 = randomBytes(32).toString('base64url');
    await insertToken({ tokenPlaintext: token1, expiresAt: new Date(Date.now() + 3600_000) });
    await insertToken({ tokenPlaintext: token2, expiresAt: new Date(Date.now() + 3600_000) });

    const sameKey = makePublicKey();

    const res1 = await app.inject({
      method: 'POST',
      url: '/enrollment',
      payload: { token: token1, device_public_key: sameKey, label: 'first' },
    });
    expect(res1.statusCode).toBe(201);

    const res2 = await app.inject({
      method: 'POST',
      url: '/enrollment',
      payload: { token: token2, device_public_key: sameKey, label: 'second' },
    });
    expect(res2.statusCode).toBe(409);
    expect(res2.json().error).toBe('device_already_enrolled');
  });

  it('rejects an invalid body', async () => {
    const res = await app.inject({
      method: 'POST',
      url: '/enrollment',
      payload: { token: 'short' },
    });
    expect(res.statusCode).toBe(400);
  });
});
