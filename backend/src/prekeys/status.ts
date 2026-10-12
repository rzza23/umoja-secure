import { pool } from '../db/client.js';

export interface PreKeyStatus {
  has_bundle: boolean;
  unconsumed_prekeys: number;
  signed_prekey_id: number | null;
  updated_at: string | null;
}

const LOW_WATER_MARK = 20;

export async function getPreKeyStatus(device_id: string): Promise<PreKeyStatus> {
  const bundleRes = await pool.query(
    `SELECT signed_prekey_id, updated_at FROM prekey_bundles WHERE device_id = $1`,
    [device_id],
  );

  const countRes = await pool.query(
    `SELECT count(*)::int AS n FROM one_time_prekeys
     WHERE device_id = $1 AND consumed_at IS NULL`,
    [device_id],
  );

  return {
    has_bundle: bundleRes.rowCount === 1,
    unconsumed_prekeys: countRes.rows[0].n,
    signed_prekey_id:
      bundleRes.rowCount === 1 ? (bundleRes.rows[0].signed_prekey_id as number) : null,
    updated_at:
      bundleRes.rowCount === 1
        ? (bundleRes.rows[0].updated_at as Date).toISOString()
        : null,
  };
}

export { LOW_WATER_MARK };
