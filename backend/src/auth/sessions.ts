import { createHash, randomBytes } from 'node:crypto';
import type { PoolClient } from 'pg';
import { pool, withTransaction } from '../db/client.js';
import { env } from '../config/env.js';

export interface SessionRecord {
  session_id: string;
  device_id: string;
  org_id: string;
  role: string;
  scope: Record<string, unknown>;
  expires_at: Date;
}

function hashToken(token: string): Buffer {
  return createHash('sha256').update(token, 'utf8').digest();
}

export async function createSession(
  device: { device_id: string; org_id: string; role: string },
  scope: Record<string, unknown> = {},
): Promise<{ token: string; session: SessionRecord }> {
  return withTransaction(async (tx) => {
    const token = randomBytes(32).toString('base64url');
    const token_hash = hashToken(token);
    const expires_at = new Date(Date.now() + env.SESSION_TTL_SECONDS * 1000);

    const res = await tx.query(
      `INSERT INTO sessions (token_hash, device_id, org_id, role, scope, expires_at)
       VALUES ($1, $2, $3, $4, $5, $6)
       RETURNING session_id, device_id, org_id, role, scope, expires_at`,
      [token_hash, device.device_id, device.org_id, device.role, scope, expires_at],
    );
    const r = res.rows[0];
    return {
      token,
      session: {
        session_id: r.session_id,
        device_id: r.device_id,
        org_id: r.org_id,
        role: r.role,
        scope: r.scope,
        expires_at: r.expires_at,
      },
    };
  });
}

export async function lookupSession(token: string): Promise<SessionRecord | null> {
  const token_hash = hashToken(token);
  const res = await pool.query(
    `SELECT s.session_id, s.device_id, s.org_id, s.role, s.scope, s.expires_at
     FROM sessions s
     JOIN devices d ON d.device_id = s.device_id
     WHERE s.token_hash = $1
       AND s.revoked_at IS NULL
       AND s.expires_at > now()
       AND d.status = 'active'`,
    [token_hash],
  );
  if (res.rowCount !== 1) return null;
  const r = res.rows[0];
  return {
    session_id: r.session_id,
    device_id: r.device_id,
    org_id: r.org_id,
    role: r.role,
    scope: r.scope,
    expires_at: r.expires_at,
  };
}

export async function revokeSession(
  session_id: string,
  reason: string,
): Promise<void> {
  await withTransaction(async (tx) =>
    tx.query(
      `UPDATE sessions
       SET revoked_at = now(), revoke_reason = $2
       WHERE session_id = $1 AND revoked_at IS NULL`,
      [session_id, reason],
    ),
  );
}

export async function revokeAllSessionsForDevice(
  tx: PoolClient,
  device_id: string,
  reason: string,
): Promise<number> {
  const res = await tx.query(
    `UPDATE sessions
     SET revoked_at = now(), revoke_reason = $2
     WHERE device_id = $1 AND revoked_at IS NULL`,
    [device_id, reason],
  );
  return res.rowCount ?? 0;
}
