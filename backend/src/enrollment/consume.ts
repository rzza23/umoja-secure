import { createHash, randomUUID } from 'node:crypto';
import { withTransaction } from '../db/client.js';

export class EnrollmentError extends Error {
  constructor(
    public code: string,
    public statusCode: number = 401,
  ) {
    super(code);
    this.name = 'EnrollmentError';
  }
}

export interface EnrollmentInput {
  token: string;
  device_public_key: string;
  label: string;
  attestation?: string;
}

export interface EnrollmentResult {
  device_id: string;
  org_id: string;
  role: string;
}

export async function consumeEnrollmentToken(
  input: EnrollmentInput,
): Promise<EnrollmentResult> {
  const tokenHash = createHash('sha256').update(input.token, 'utf8').digest();
  const publicKey = Buffer.from(input.device_public_key, 'base64url');

  if (publicKey.length !== 32) {
    throw new EnrollmentError('invalid_request', 400);
  }

  return withTransaction(async (tx) => {
    const tok = await tx.query(
      `SELECT token_id, org_id, role, expires_at, used_at, revoked_at
       FROM enrollment_tokens
       WHERE token_hash = $1
       FOR UPDATE`,
      [tokenHash],
    );

    if (tok.rowCount !== 1) throw new EnrollmentError('invalid_token');
    const row = tok.rows[0];
    if (row.revoked_at) throw new EnrollmentError('invalid_token');
    if (row.used_at) throw new EnrollmentError('invalid_token');
    if (new Date(row.expires_at) <= new Date()) {
      throw new EnrollmentError('invalid_token');
    }

    const deviceId = randomUUID();

    try {
      await tx.query(
        `INSERT INTO devices (device_id, org_id, public_key, label, role)
         VALUES ($1, $2, $3, $4, $5)`,
        [deviceId, row.org_id, publicKey, input.label, row.role],
      );
    } catch (err: unknown) {
      const pgErr = err as { code?: string };
      if (pgErr.code === '23505') {
        throw new EnrollmentError('device_already_enrolled', 409);
      }
      throw err;
    }

    await tx.query(
      `UPDATE enrollment_tokens
       SET used_at = now(), used_by_device_id = $2
       WHERE token_id = $1`,
      [row.token_id, deviceId],
    );

    return {
      device_id: deviceId,
      org_id: row.org_id,
      role: row.role,
    };
  });
}
