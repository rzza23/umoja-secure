import { withTransaction } from '../db/client.js';

export interface PreKeyBundleResponse {
  device_id: string;
  identity_key: string;
  signed_prekey_id: number;
  signed_prekey_public: string;
  signed_prekey_signature: string;
  registration_id: number;
  one_time_prekey: { id: number; public_key: string } | null;
}

export async function fetchPreKeyBundle(
  target_device_id: string,
): Promise<PreKeyBundleResponse | null> {
  return withTransaction(async (tx) => {
    // Target device must be active
    const dev = await tx.query(
      `SELECT status FROM devices WHERE device_id = $1`,
      [target_device_id],
    );
    if (dev.rowCount !== 1 || dev.rows[0].status !== 'active') {
      return null;
    }

    const bundleRes = await tx.query(
      `SELECT identity_key, signed_prekey_id, signed_prekey_public,
              signed_prekey_signature, registration_id
       FROM prekey_bundles WHERE device_id = $1`,
      [target_device_id],
    );
    if (bundleRes.rowCount !== 1) {
      return null;
    }
    const bundle = bundleRes.rows[0];

    // Atomic consumption of one unconsumed one-time prekey
    const otpRes = await tx.query(
      `UPDATE one_time_prekeys
       SET consumed_at = now()
       WHERE device_id = $1 AND prekey_id = (
         SELECT prekey_id FROM one_time_prekeys
         WHERE device_id = $1 AND consumed_at IS NULL
         ORDER BY prekey_id
         LIMIT 1
         FOR UPDATE SKIP LOCKED
       )
       RETURNING prekey_id, public_key`,
      [target_device_id],
    );

    const otp =
      otpRes.rowCount === 1
        ? {
            id: otpRes.rows[0].prekey_id as number,
            public_key: (otpRes.rows[0].public_key as Buffer).toString('base64url'),
          }
        : null;

    return {
      device_id: target_device_id,
      identity_key: (bundle.identity_key as Buffer).toString('base64url'),
      signed_prekey_id: bundle.signed_prekey_id as number,
      signed_prekey_public: (bundle.signed_prekey_public as Buffer).toString('base64url'),
      signed_prekey_signature: (bundle.signed_prekey_signature as Buffer).toString('base64url'),
      registration_id: bundle.registration_id as number,
      one_time_prekey: otp,
    };
  });
}
