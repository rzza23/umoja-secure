import { randomBytes, randomUUID } from 'node:crypto';
import { withTransaction } from '../db/client.js';
import { env } from '../config/env.js';
import type { Challenge } from './canonical.js';

export class AuthError extends Error {
  constructor(
    public code: string,
    public statusCode: number = 401,
  ) {
    super(code);
    this.name = 'AuthError';
  }
}

export async function createChallenge(
  device_id: string,
  purpose: Challenge['purpose'],
): Promise<Challenge> {
  return withTransaction(async (tx) => {
    const dev = await tx.query(
      'SELECT status FROM devices WHERE device_id = $1',
      [device_id],
    );
    if (dev.rowCount !== 1) {
      // No device row: treat as unauthorized (preserved).
      throw new AuthError('unauthorized');
    }
    if (dev.rows[0].status !== 'active') {
      // Distinct code for revoked device, per ADR-HARDENING-001 §2.
      // The client's re-auth flow distinguishes this from a generic
      // 401 and routes to AppScreen.Revoked rather than retrying.
      throw new AuthError('device_revoked');
    }

    const challenge_id = randomUUID();
    const nonce = randomBytes(32);
    const issued_at = new Date();
    const expires_at = new Date(
      issued_at.getTime() + env.CHALLENGE_TTL_SECONDS * 1000,
    );

    await tx.query(
      `INSERT INTO auth_challenges
         (challenge_id, device_id, nonce, purpose, issued_at, expires_at)
       VALUES ($1, $2, $3, $4, $5, $6)`,
      [challenge_id, device_id, nonce, purpose, issued_at, expires_at],
    );

    return {
      v: 1,
      purpose,
      challenge_id,
      nonce: nonce.toString('base64url'),
      device_id,
      session_context: null,
      issued_at: issued_at.toISOString(),
      expires_at: expires_at.toISOString(),
      server_id: env.SERVER_ID,
    };
  });
}
