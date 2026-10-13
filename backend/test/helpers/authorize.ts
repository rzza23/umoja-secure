import { pool } from '../../src/db/client.js';

/**
 * Authorize a mutual contact between two devices directly in the DB.
 * Bypasses the admin API for test setup speed. Not used in production.
 */
export async function authorizePair(
  org_id: string,
  owner_device_id: string,
  contact_device_id: string,
): Promise<void> {
  const actor = owner_device_id;
  for (const [a, b] of [
    [owner_device_id, contact_device_id],
    [contact_device_id, owner_device_id],
  ]) {
    await pool.query(
      `INSERT INTO contacts
         (owner_device_id, contact_device_id, org_id, status,
          verification_level, authorized_by, authorized_at)
       VALUES ($1, $2, $3, 'active', 'directory', $4, now())
       ON CONFLICT (owner_device_id, contact_device_id) DO UPDATE
         SET status = 'active',
             authorized_at = now(),
             revoked_at = NULL,
             revoked_by = NULL,
             revoke_reason = NULL`,
      [a, b, org_id, actor],
    );
  }
}
