import * as ed from '@noble/ed25519';
import { withTransaction } from '../db/client.js';
import { env } from '../config/env.js';
import { AuthError } from './challenge.js';
import { canonicalizeChallenge, type Challenge } from './canonical.js';

export interface VerifiedDevice {
  device_id: string;
  org_id: string;
  role: string;
}

export async function verifyChallenge(
  challenge_id: string,
  signature_b64url: string,
): Promise<VerifiedDevice> {
  return withTransaction(async (tx) => {
    // Atomic single-use consumption
    const upd = await tx.query(
      `UPDATE auth_challenges
       SET used = true, used_at = now()
       WHERE challenge_id = $1 AND used = false AND expires_at > now()
       RETURNING device_id, nonce, purpose, issued_at, expires_at`,
      [challenge_id],
    );
    if (upd.rowCount !== 1) {
      throw new AuthError('unauthorized');
    }
    const row = upd.rows[0];

    const dev = await tx.query(
      `SELECT device_id, org_id, role, public_key, public_key_alg, status
       FROM devices WHERE device_id = $1`,
      [row.device_id],
    );
    if (dev.rowCount !== 1) {
      // No device row: treat as unauthorized (preserved).
      throw new AuthError('unauthorized');
    }
    if (dev.rows[0].status !== 'active') {
      // Device revoked between challenge issue and verify consumption.
      // Narrow race window; still worth distinguishing so the client
      // routes to AppScreen.Revoked rather than retrying.
      throw new AuthError('device_revoked');
    }
    const device = dev.rows[0];

    const challenge: Challenge = {
      v: 1,
      purpose: row.purpose,
      challenge_id,
      nonce: row.nonce.toString('base64url'),
      device_id: device.device_id,
      session_context: null,
      issued_at: row.issued_at.toISOString(),
      expires_at: row.expires_at.toISOString(),
      server_id: env.SERVER_ID,
    };

    const message = canonicalizeChallenge(challenge);
    const signature = Buffer.from(signature_b64url, 'base64url');
    if (signature.length !== 64) {
      throw new AuthError('unauthorized');
    }

    if (device.public_key_alg !== 'ed25519') {
      throw new AuthError('unsupported_algorithm', 501);
    }

    const valid = await ed.verifyAsync(signature, message, device.public_key);
    if (!valid) {
      throw new AuthError('unauthorized');
    }

    return {
      device_id: device.device_id,
      org_id: device.org_id,
      role: device.role,
    };
  });
}
