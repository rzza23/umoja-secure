import { withTransaction } from '../db/client.js';

export interface PreKeyUpload {
  device_id: string;
  identity_key: string;
  signed_prekey_id: number;
  signed_prekey_public: string;
  signed_prekey_signature: string;
  registration_id: number;
  one_time_prekeys: Array<{ id: number; public_key: string }>;
}

export interface PreKeyUploadResult {
  stored_prekeys: number;
  total_unconsumed: number;
}

function decodeB64Url(s: string, expectedLen: number, field: string): Buffer {
  const buf = Buffer.from(s, 'base64url');
  if (buf.length !== expectedLen) {
    throw Object.assign(new Error(`invalid_length:${field}`), { statusCode: 400 });
  }
  return buf;
}

export async function uploadPreKeys(
  input: PreKeyUpload,
): Promise<PreKeyUploadResult> {
  const identityKey = decodeB64Url(input.identity_key, 32, 'identity_key');
  const spkPublic = decodeB64Url(input.signed_prekey_public, 32, 'signed_prekey_public');
  const spkSig = decodeB64Url(input.signed_prekey_signature, 64, 'signed_prekey_signature');

  return withTransaction(async (tx) => {
    // Verify device active
    const dev = await tx.query(
      `SELECT status FROM devices WHERE device_id = $1`,
      [input.device_id],
    );
    if (dev.rowCount !== 1 || dev.rows[0].status !== 'active') {
      throw Object.assign(new Error('unauthorized'), { statusCode: 401 });
    }

    // Upsert prekey bundle (device replaces its own bundle)
    await tx.query(
      `INSERT INTO prekey_bundles
         (device_id, identity_key, signed_prekey_id, signed_prekey_public,
          signed_prekey_signature, registration_id, updated_at)
       VALUES ($1, $2, $3, $4, $5, $6, now())
       ON CONFLICT (device_id) DO UPDATE SET
         identity_key = EXCLUDED.identity_key,
         signed_prekey_id = EXCLUDED.signed_prekey_id,
         signed_prekey_public = EXCLUDED.signed_prekey_public,
         signed_prekey_signature = EXCLUDED.signed_prekey_signature,
         registration_id = EXCLUDED.registration_id,
         updated_at = now()`,
      [
        input.device_id,
        identityKey,
        input.signed_prekey_id,
        spkPublic,
        spkSig,
        input.registration_id,
      ],
    );

    // Insert one-time prekeys (idempotent — first upload of an ID wins)
    let stored = 0;
    for (const otp of input.one_time_prekeys) {
      const pub = decodeB64Url(otp.public_key, 32, 'one_time_prekey');
      const res = await tx.query(
        `INSERT INTO one_time_prekeys (device_id, prekey_id, public_key)
         VALUES ($1, $2, $3)
         ON CONFLICT (device_id, prekey_id) DO NOTHING`,
        [input.device_id, otp.id, pub],
      );
      stored += res.rowCount ?? 0;
    }

    const countRes = await tx.query(
      `SELECT count(*)::int AS n FROM one_time_prekeys
       WHERE device_id = $1 AND consumed_at IS NULL`,
      [input.device_id],
    );

    return {
      stored_prekeys: stored,
      total_unconsumed: countRes.rows[0].n,
    };
  });
}
