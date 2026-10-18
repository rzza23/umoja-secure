import { createHmac } from 'node:crypto';
import { pool } from '../db/client.js';
import { env } from '../config/env.js';
import { canonicalJson } from './canonicalJson.js';

export interface VerifyResult {
  intact: boolean;
  broken_at?: number;
  total_events: number;
}

export async function verifyAuditChain(): Promise<VerifyResult> {
  const res = await pool.query(
    `SELECT event_id, prev_hash, event_hash, event_type, actor_device_id,
            actor_role, target_type, target_id, payload, created_at
     FROM audit_events ORDER BY event_id ASC`,
  );

  const total = res.rowCount ?? 0;
  let expectedPrev: Buffer | null = null;

  for (const row of res.rows) {
    const prev_hash = row.prev_hash as Buffer | null;
    const stored_event_hash = row.event_hash as Buffer;

    // Chain linkage
    if (prev_hash === null) {
      if (expectedPrev !== null) {
        return { intact: false, broken_at: row.event_id as number, total_events: total };
      }
    } else if (!expectedPrev || !prev_hash.equals(expectedPrev)) {
      return { intact: false, broken_at: row.event_id as number, total_events: total };
    }

    const body = {
      event_type: row.event_type as string,
      actor_device_id: row.actor_device_id as string | null,
      actor_role: row.actor_role as string | null,
      target_type: row.target_type as string | null,
      target_id: row.target_id as string | null,
      payload: row.payload as Record<string, unknown>,
      created_at: (row.created_at as Date).toISOString(),
    };

    const hmac = createHmac('sha256', Buffer.from(env.AUDIT_HASH_KEY, 'hex'));
    hmac.update(prev_hash ?? Buffer.alloc(0));
    hmac.update(canonicalJson(body));
    const computed = hmac.digest();

    if (!computed.equals(stored_event_hash)) {
      return { intact: false, broken_at: row.event_id as number, total_events: total };
    }

    expectedPrev = stored_event_hash;
  }

  return { intact: true, total_events: total };
}
