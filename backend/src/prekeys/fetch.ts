import { withTransaction } from '../db/client.js';
import { isContactAuthorized } from '../authorization/contacts.js';

export interface PreKeyBundleResponse {
  device_id: string;
  identity_key: string;
  signed_prekey_id: number;
  signed_prekey_public: string;
  signed_prekey_signature: string;
  registration_id: number;
  kyber_prekey_id: number;
  kyber_prekey_public: string;
  kyber_prekey_signature: string;
  one_time_prekey: { id: number; public_key: string } | null;
  one_time_kyber_prekey: { id: number; public_key: string } | null;
}

export async function fetchPreKeyBundle(
  requester_device_id: string,
  target_device_id: string,
): Promise<PreKeyBundleResponse | null> {
  return withTransaction(async (tx) => {
    // A device fetching its own bundle (for client-side status display) is
    // allowed. Otherwise, contact authorization is required.
    if (requester_device_id !== target_device_id) {
      const authorized = await isContactAuthorized(
        tx,
        requester_device_id,
        target_device_id,
      );
      if (!authorized) return null;
    }

    const dev = await tx.query(
      `SELECT status FROM devices WHERE device_id = $1`,
      [target_device_id],
    );
    if (dev.rowCount !== 1 || dev.rows[0].status !== 'active') {
      return null;
    }

    const bundleRes = await tx.query(
      `SELECT identity_key, signed_prekey_id, signed_prekey_public,
              signed_prekey_signature, registration_id,
              kyber_prekey_id, kyber_prekey_public, kyber_prekey_signature
       FROM prekey_bundles WHERE device_id = $1`,
      [target_device_id],
    );
    if (bundleRes.rowCount !== 1) {
      return null;
    }
    const bundle = bundleRes.rows[0];

    if (bundle.kyber_prekey_id === null) {
      // Device has not uploaded Kyber prekeys yet; can't build a PQXDH bundle.
      return null;
    }

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

    const kyberOtpRes = await tx.query(
      `UPDATE one_time_kyber_prekeys
       SET consumed_at = now()
       WHERE device_id = $1 AND prekey_id = (
         SELECT prekey_id FROM one_time_kyber_prekeys
         WHERE device_id = $1 AND consumed_at IS NULL
         ORDER BY prekey_id
         LIMIT 1
         FOR UPDATE SKIP LOCKED
       )
       RETURNING prekey_id, public_key`,
      [target_device_id],
    );

    const otp = otpRes.rowCount === 1
      ? {
          id: otpRes.rows[0].prekey_id as number,
          public_key: (otpRes.rows[0].public_key as Buffer).toString('base64url'),
        }
      : null;

    const kyberOtp = kyberOtpRes.rowCount === 1
      ? {
          id: kyberOtpRes.rows[0].prekey_id as number,
          public_key: (kyberOtpRes.rows[0].public_key as Buffer).toString('base64url'),
        }
      : null;

    return {
      device_id: target_device_id,
      identity_key: (bundle.identity_key as Buffer).toString('base64url'),
      signed_prekey_id: bundle.signed_prekey_id as number,
      signed_prekey_public: (bundle.signed_prekey_public as Buffer).toString('base64url'),
      signed_prekey_signature: (bundle.signed_prekey_signature as Buffer).toString('base64url'),
      registration_id: bundle.registration_id as number,
      kyber_prekey_id: bundle.kyber_prekey_id as number,
      kyber_prekey_public: (bundle.kyber_prekey_public as Buffer).toString('base64url'),
      kyber_prekey_signature: (bundle.kyber_prekey_signature as Buffer).toString('base64url'),
      one_time_prekey: otp,
      one_time_kyber_prekey: kyberOtp,
    };
  });
}
