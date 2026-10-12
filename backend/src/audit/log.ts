import { createHmac } from 'node:crypto';
import type { PoolClient } from 'pg';
import { env } from '../config/env.js';

export interface AuditInput {
  event_type: string;
  actor_device_id?: string | null;
  actor_role?: string | null;
  target_type?: string | null;
  target_id?: string | null;
  payload?: Record<string, unknown>;
}

function canonicalJson(obj: Record<string, unknown>): string {
  return JSON.stringify(obj, Object.keys(obj).sort());
}

/**
 * Append an audit event inside an existing transaction.
 * Serializes chain writes via a session-scoped advisory lock.
 *
 * IMPORTANT: created_at is generated here and passed explicitly to the
 * INSERT, so the value hashed into event_hash matches the value stored.
 * Relying on the DB DEFAULT now() would break verification.
 */
export async function writeAuditEvent(
  tx: PoolClient,
  input: AuditInput,
): Promise<void> {
  await tx.query(`SELECT pg_advisory_xact_lock(hashtext('audit_events_chain'))`);

  const last = await tx.query<{ event_hash: Buffer }>(
    `SELECT event_hash FROM audit_events ORDER BY event_id DESC LIMIT 1 FOR UPDATE`,
  );
  const lastRow = last.rows[0];
  const prev_hash: Buffer | null = lastRow ? lastRow.event_hash : null;

  const created_at = new Date().toISOString();

  const body = {
    event_type: input.event_type,
    actor_device_id: input.actor_device_id ?? null,
    actor_role: input.actor_role ?? null,
    target_type: input.target_type ?? null,
    target_id: input.target_id ?? null,
    payload: input.payload ?? {},
    created_at,
  };

  const hmac = createHmac('sha256', Buffer.from(env.AUDIT_HASH_KEY, 'hex'));
  hmac.update(prev_hash ?? Buffer.alloc(0));
  hmac.update(canonicalJson(body));
  const event_hash = hmac.digest();

  await tx.query(
    `INSERT INTO audit_events
       (prev_hash, event_hash, event_type, actor_device_id, actor_role,
        target_type, target_id, payload, created_at)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
    [
      prev_hash,
      event_hash,
      input.event_type,
      input.actor_device_id ?? null,
      input.actor_role ?? null,
      input.target_type ?? null,
      input.target_id ?? null,
      input.payload ?? {},
      new Date(created_at),
    ],
  );
}
