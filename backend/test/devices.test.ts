import { describe, it, expect, afterAll } from 'vitest';
import { randomUUID } from 'node:crypto';
import { pool } from '../src/db/client.js';

describe('devices table', () => {
  const testDeviceId = randomUUID();

  afterAll(async () => {
    await pool.query('DELETE FROM devices WHERE device_id = $1', [testDeviceId]);
    await pool.end();
  });

  it('inserts and reads back a device row', async () => {
    await pool.query(
      `INSERT INTO devices
         (device_id, org_id, public_key, label, role)
       VALUES ($1, $2, $3, $4, $5)`,
      [
        testDeviceId,
        randomUUID(),
        Buffer.from('a'.repeat(32)),
        'test-device-1',
        'user',
      ],
    );

    const res = await pool.query(
      'SELECT device_id, label, role, status FROM devices WHERE device_id = $1',
      [testDeviceId],
    );

    expect(res.rowCount).toBe(1);
    expect(res.rows[0].label).toBe('test-device-1');
    expect(res.rows[0].role).toBe('user');
    expect(res.rows[0].status).toBe('active');
  });

  it('rejects a revoked device without revoked_at', async () => {
    await expect(
      pool.query(
        `INSERT INTO devices
           (device_id, org_id, public_key, label, role, status)
         VALUES ($1, $2, $3, $4, $5, $6)`,
        [
          randomUUID(),
          randomUUID(),
          Buffer.from('b'.repeat(32)),
          'bad-device',
          'user',
          'revoked',
        ],
      ),
    ).rejects.toThrow();
  });

  it('rejects duplicate public_key', async () => {
    const sharedKey = Buffer.from('c'.repeat(32));

    await pool.query(
      `INSERT INTO devices
         (device_id, org_id, public_key, label, role)
       VALUES ($1, $2, $3, $4, $5)`,
      [randomUUID(), randomUUID(), sharedKey, 'first', 'user'],
    );

    await expect(
      pool.query(
        `INSERT INTO devices
           (device_id, org_id, public_key, label, role)
         VALUES ($1, $2, $3, $4, $5)`,
        [randomUUID(), randomUUID(), sharedKey, 'second', 'user'],
      ),
    ).rejects.toThrow();

    await pool.query('DELETE FROM devices WHERE public_key = $1', [sharedKey]);
  });
});
