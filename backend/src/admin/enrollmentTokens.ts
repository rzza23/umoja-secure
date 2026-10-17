import { createHash, randomBytes } from 'node:crypto';
import { pool, withTransaction } from '../db/client.js';
import { writeAuditEvent } from '../audit/log.js';

export interface CreateTokenInput {
  actor_device_id: string;
  actor_role: string;
  org_id: string;
  role: 'owner' | 'admin' | 'user' | 'auditor';
  label_hint?: string;
  ttl_seconds: number;
  bound_public_key: string;
}

export interface CreateTokenResult {
  token_id: string;
  token: string;
  expires_at: string;
  enrollment_matrix_version_floor: number | null;
}

export async function createEnrollmentToken(
  input: CreateTokenInput,
): Promise<CreateTokenResult> {
  const boundKey = Buffer.from(input.bound_public_key, 'base64url');
  if (boundKey.length !== 32) {
    throw Object.assign(new Error('invalid_bound_public_key'), { statusCode: 400 });
  }

  const token = randomBytes(32).toString('base64url');
  const tokenHash = createHash('sha256').update(token, 'utf8').digest();
  const expiresAt = new Date(Date.now() + input.ttl_seconds * 1000);

  return withTransaction(async (tx) => {
    const floorRes = await tx.query<{ current_version: number | null }>(
      `SELECT current_version FROM org_matrix_versions WHERE org_id = $1`,
      [input.org_id],
    );
    const floor = floorRes.rows[0]?.current_version ?? null;

    const res = await tx.query(
      `INSERT INTO enrollment_tokens
         (token_hash, org_id, role, label_hint, expires_at, created_by, bound_public_key,
          enrollment_matrix_version_floor)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
       RETURNING token_id, expires_at`,
      [
        tokenHash,
        input.org_id,
        input.role,
        input.label_hint ?? null,
        expiresAt,
        input.actor_device_id,
        boundKey,
        floor,
      ],
    );

    await writeAuditEvent(tx, {
      event_type: 'enrollment_token.created',
      actor_device_id: input.actor_device_id,
      actor_role: input.actor_role,
      target_type: 'org',
      target_id: input.org_id,
      payload: {
        role: input.role,
        ttl_seconds: input.ttl_seconds,
        enrollment_matrix_version_floor: floor,
      },
    });

    return {
      token_id: res.rows[0].token_id as string,
      token,
      expires_at: (res.rows[0].expires_at as Date).toISOString(),
      enrollment_matrix_version_floor: floor,
    };
  });
}

export interface ListTokenResult {
  token_id: string;
  org_id: string;
  role: string;
  label_hint: string | null;
  expires_at: string;
  used_at: string | null;
  revoked_at: string | null;
  created_at: string;
}

export async function listEnrollmentTokens(
  org_id: string,
): Promise<ListTokenResult[]> {
  const res = await pool.query(
    `SELECT token_id, org_id, role, label_hint, expires_at, used_at,
            revoked_at, created_at
     FROM enrollment_tokens
     WHERE org_id = $1
     ORDER BY created_at DESC
     LIMIT 200`,
    [org_id],
  );
  return res.rows.map((r) => ({
    token_id: r.token_id as string,
    org_id: r.org_id as string,
    role: r.role as string,
    label_hint: (r.label_hint as string | null) ?? null,
    expires_at: (r.expires_at as Date).toISOString(),
    used_at: r.used_at ? (r.used_at as Date).toISOString() : null,
    revoked_at: r.revoked_at ? (r.revoked_at as Date).toISOString() : null,
    created_at: (r.created_at as Date).toISOString(),
  }));
}

export async function revokeEnrollmentToken(
  token_id: string,
  actor: { device_id: string; role: string; org_id: string },
): Promise<void> {
  await withTransaction(async (tx) => {
    const res = await tx.query(
      `UPDATE enrollment_tokens
       SET revoked_at = now()
       WHERE token_id = $1 AND org_id = $2
         AND revoked_at IS NULL AND used_at IS NULL
       RETURNING token_id`,
      [token_id, actor.org_id],
    );
    if (res.rowCount !== 1) {
      throw Object.assign(new Error('not_found'), { statusCode: 404 });
    }

    await writeAuditEvent(tx, {
      event_type: 'enrollment_token.revoked',
      actor_device_id: actor.device_id,
      actor_role: actor.role,
      target_type: 'enrollment_token',
      target_id: token_id,
    });
  });
}
