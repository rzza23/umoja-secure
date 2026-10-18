import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { randomUUID } from 'node:crypto';
import { pool } from '../src/db/client.js';

/**
 * Behavioral test for migration 017: enrollment_tokens.used_by_device_id
 * foreign key gains ON DELETE SET NULL.
 *
 * Before 017: deleting a device row that was referenced by an
 * enrollment_tokens.used_by_device_id value failed on the FK (NO
 * ACTION). Every other test file works around this by deleting
 * enrollment_tokens before devices in afterAll.
 *
 * After 017: deleting the device succeeds and the token row survives
 * with used_by_device_id = NULL. The audit trail (token exists, was
 * consumed at used_at) is preserved; only the referent is nulled
 * because the referent no longer exists.
 *
 * TEST_ORG_ID: '0d1' — unique per Session C's numbering discipline.
 * Post-close note (from R-4 §3): 'devices_key_unique' + 'devices_pkey'
 * collisions in recovery are unrelated to this test; a fresh UUID per
 * run keeps the key free.
 */

const TEST_ORG_ID = '00000000-0000-0000-0000-0000000000d1';

describe('migration 017: enrollment_tokens.used_by_device_id ON DELETE SET NULL', () => {
  beforeAll(async () => {
    await pool.query('DELETE FROM enrollment_tokens WHERE org_id = $1', [TEST_ORG_ID]);
    await pool.query('DELETE FROM devices WHERE org_id = $1', [TEST_ORG_ID]);
  });

  afterAll(async () => {
    await pool.query('DELETE FROM enrollment_tokens WHERE org_id = $1', [TEST_ORG_ID]);
    await pool.query('DELETE FROM devices WHERE org_id = $1', [TEST_ORG_ID]);
  });

  it('TEST-MIGRATION-017-DEVICE-DELETE-PRESERVES-TOKEN', async () => {
    // Setup: device + consumed token bound to it
    const deviceId = randomUUID();
    await pool.query(
      `INSERT INTO devices (device_id, org_id, public_key, label, role, status)
       VALUES ($1, $2, decode(repeat('ab', 32), 'hex'), 'mig-017-test', 'user', 'active')`,
      [deviceId, TEST_ORG_ID],
    );

    const tokenHash = Buffer.from(
      Array.from({ length: 32 }, (_, i) => (i + 17) & 0xff),
    );
    const creatorId = randomUUID();
    await pool.query(
      `INSERT INTO devices (device_id, org_id, public_key, label, role, status)
       VALUES ($1, $2, decode(repeat('cd', 32), 'hex'), 'mig-017-creator', 'admin', 'active')`,
      [creatorId, TEST_ORG_ID],
    );

    await pool.query(
      `INSERT INTO enrollment_tokens
         (token_hash, org_id, role, created_by, bound_public_key, used_by_device_id, used_at, expires_at)
       VALUES ($1, $2, 'user', $3, decode(repeat('ab', 32), 'hex'), $4, now(), now() + interval '1 hour')`,
      [tokenHash, TEST_ORG_ID, creatorId, deviceId],
    );

    // Confirm the token references the device before deletion.
    const before = await pool.query<{ used_by_device_id: string | null }>(
      `SELECT used_by_device_id FROM enrollment_tokens WHERE token_hash = $1`,
      [tokenHash],
    );
    expect(before.rows[0]?.used_by_device_id).toBe(deviceId);

    // Delete the device — the load-bearing assertion. Before 017 this
    // throws on the NO ACTION FK; after 017 it succeeds.
    await pool.query('DELETE FROM devices WHERE device_id = $1', [deviceId]);

    // Token row survives with nulled referent.
    const after = await pool.query<{
      used_by_device_id: string | null;
      used_at: Date | null;
    }>(
      `SELECT used_by_device_id, used_at FROM enrollment_tokens WHERE token_hash = $1`,
      [tokenHash],
    );
    expect(after.rows.length).toBe(1);
    expect(after.rows[0].used_by_device_id).toBeNull();
    // used_at preserved — the audit trail still shows when the token
    // was consumed; only the referent is nulled.
    expect(after.rows[0].used_at).not.toBeNull();
  });
});
