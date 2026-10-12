import { withTransaction } from '../db/client.js';

export interface KyberPreKeyUpload {
  id: number;
  public_key: string;   // base64url
  signature: string;    // base64url
}

export interface PreKeyUpload {
  device_id: string;
  identity_key: string;
  signed_prekey_id: number;
  signed_prekey_public: string;
  signed_prekey_signature: string;
  registration_id: number;
  kyber_prekey_id: number;
  kyber_prekey_public: string;
  kyber_prekey_signature: string;
  one_time_prekeys: Array<{ id: number; public_key: string }>;
  one_time_kyber_prekeys: Array<{ id: number; public_key: string }>;
}

export interface PreKeyUploadResult {
  stored_prekeys: number;
  stored_kyber_prekeys: number;
  total_unconsumed: number;
  total_kyber_unconsumed: number;
}

function decodeB64Url(s: string, expectedLen: number, field: string): Buffer {
  const buf = Buffer.from(s, 'base64url');
  if (buf.length !== expectedLen) {
    throw Object.assign(new Error(`invalid_length:${field}`), { statusCode: 400 });
  }
  return buf;
}

function decodeB64UrlRange(s: string, minLen: number, maxLen: number, field: string): Buffer {
  const buf = Buffer.from(s, 'base64url');
  if (buf.length < minLen || buf.length > maxLen) {
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
  // Kyber-1024 public key is 1568 bytes; signature is 64 bytes
  const kyberPublic = decodeB64UrlRange(input.kyber_prekey_public, 800, 2048, 'kyber_prekey_public');
  const kyberSig = decodeB64Url(input.kyber_prekey_signature, 64, 'kyber_prekey_signature');

  return withTransaction(async (tx) => {
    const dev = await tx.query(
      `SELECT status FROM devices WHERE device_id = $1`,
      [input.device_id],
    );
    if (dev.rowCount !== 1 || dev.rows[0].status !== 'active') {
      throw Object.assign(new Error('unauthorized'), { statusCode: 401 });
    }

    await tx.query(
      `INSERT INTO prekey_bundles
         (device_id, identity_key, signed_prekey_id, signed_prekey_public,
          signed_prekey_signature, registration_id,
          kyber_prekey_id, kyber_prekey_public, kyber_prekey_signature,
          updated_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, now())
       ON CONFLICT (device_id) DO UPDATE SET
         identity_key = EXCLUDED.identity_key,
         signed_prekey_id = EXCLUDED.signed_prekey_id,
         signed_prekey_public = EXCLUDED.signed_prekey_public,
         signed_prekey_signature = EXCLUDED.signed_prekey_signature,
         registration_id = EXCLUDED.registration_id,
         kyber_prekey_id = EXCLUDED.kyber_prekey_id,
         kyber_prekey_public = EXCLUDED.kyber_prekey_public,
         kyber_prekey_signature = EXCLUDED.kyber_prekey_signature,
         updated_at = now()`,
      [
        input.device_id,
        identityKey,
        input.signed_prekey_id,
        spkPublic,
        spkSig,
        input.registration_id,
        input.kyber_prekey_id,
        kyberPublic,
        kyberSig,
      ],
    );

    let storedOtp = 0;
    for (const otp of input.one_time_prekeys) {
      const pub = decodeB64Url(otp.public_key, 32, 'one_time_prekey');
      const res = await tx.query(
        `INSERT INTO one_time_prekeys (device_id, prekey_id, public_key)
         VALUES ($1, $2, $3)
         ON CONFLICT (device_id, prekey_id) DO NOTHING`,
        [input.device_id, otp.id, pub],
      );
      storedOtp += res.rowCount ?? 0;
    }

    let storedKyberOtp = 0;
    for (const otp of input.one_time_kyber_prekeys) {
      const pub = decodeB64UrlRange(otp.public_key, 800, 2048, 'one_time_kyber_prekey');
      const res = await tx.query(
        `INSERT INTO one_time_kyber_prekeys (device_id, prekey_id, public_key)
         VALUES ($1, $2, $3)
         ON CONFLICT (device_id, prekey_id) DO NOTHING`,
        [input.device_id, otp.id, pub],
      );
      storedKyberOtp += res.rowCount ?? 0;
    }

    const countRes = await tx.query(
      `SELECT count(*)::int AS n FROM one_time_prekeys
       WHERE device_id = $1 AND consumed_at IS NULL`,
      [input.device_id],
    );
    const kyberCountRes = await tx.query(
      `SELECT count(*)::int AS n FROM one_time_kyber_prekeys
       WHERE device_id = $1 AND consumed_at IS NULL`,
      [input.device_id],
    );

    return {
      stored_prekeys: storedOtp,
      stored_kyber_prekeys: storedKyberOtp,
      total_unconsumed: countRes.rows[0].n,
      total_kyber_unconsumed: kyberCountRes.rows[0].n,
    };
  });
}
