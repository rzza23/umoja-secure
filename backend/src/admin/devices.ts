import type { PoolClient } from 'pg';
import { pool, withTransaction } from '../db/client.js';
import { revokeAllSessionsForDevice } from '../auth/sessions.js';
import { writeAuditEvent } from '../audit/log.js';

export interface AdminActor {
  device_id: string;
  role: string;
  org_id: string;
}

export interface DeviceListEntry {
  device_id: string;
  label: string;
  role: string;
  status: string;
  enrolled_at: string;
  last_seen_at: string | null;
  revoked_at: string | null;
}

export async function listDevices(org_id: string): Promise<DeviceListEntry[]> {
  const res = await pool.query(
    `SELECT device_id, label, role, status, enrolled_at, last_seen_at, revoked_at
     FROM devices
     WHERE org_id = $1
     ORDER BY enrolled_at DESC
     LIMIT 500`,
    [org_id],
  );
  return res.rows.map((r) => ({
    device_id: r.device_id as string,
    label: r.label as string,
    role: r.role as string,
    status: r.status as string,
    enrolled_at: (r.enrolled_at as Date).toISOString(),
    last_seen_at: r.last_seen_at ? (r.last_seen_at as Date).toISOString() : null,
    revoked_at: r.revoked_at ? (r.revoked_at as Date).toISOString() : null,
  }));
}

async function loadTarget(
  tx: PoolClient,
  device_id: string,
  actor_org_id: string,
): Promise<{ device_id: string; status: string; role: string; label: string }> {
  const res = await tx.query(
    `SELECT device_id, status, role, label FROM devices
     WHERE device_id = $1 AND org_id = $2`,
    [device_id, actor_org_id],
  );
  if (res.rowCount !== 1) {
    throw Object.assign(new Error('not_found'), { statusCode: 404 });
  }
  return res.rows[0];
}

export async function revokeDevice(
  target_device_id: string,
  reason: string,
  actor: AdminActor,
): Promise<void> {
  if (target_device_id === actor.device_id) {
    throw Object.assign(new Error('cannot_revoke_self'), { statusCode: 400 });
  }

  await withTransaction(async (tx) => {
    const target = await loadTarget(tx, target_device_id, actor.org_id);
    if (target.status === 'revoked') return;

    await tx.query(
      `UPDATE devices
       SET status = 'revoked', revoked_at = now(), revoke_reason = $2
       WHERE device_id = $1`,
      [target_device_id, reason],
    );

    const sessionsRevoked = await revokeAllSessionsForDevice(
      tx,
      target_device_id,
      'device_revoked',
    );

    await writeAuditEvent(tx, {
      event_type: 'device.revoked',
      actor_device_id: actor.device_id,
      actor_role: actor.role,
      target_type: 'device',
      target_id: target_device_id,
      payload: { reason, sessions_revoked: sessionsRevoked, label: target.label },
    });

    // Notify all backend instances so active WebSocket connections close.
    // pg_notify inside a transaction is delivered on commit.
    await tx.query(`SELECT pg_notify('device_revoked', $1)`, [
      JSON.stringify({ device_id: target_device_id }),
    ]);
  });
}

export async function suspendDevice(
  target_device_id: string,
  reason: string,
  actor: AdminActor,
): Promise<void> {
  await withTransaction(async (tx) => {
    const target = await loadTarget(tx, target_device_id, actor.org_id);
    if (target.status !== 'active') {
      throw Object.assign(new Error('invalid_state'), { statusCode: 409 });
    }
    await tx.query(
      `UPDATE devices
       SET status = 'suspended', suspended_at = now()
       WHERE device_id = $1`,
      [target_device_id],
    );
    await writeAuditEvent(tx, {
      event_type: 'device.suspended',
      actor_device_id: actor.device_id,
      actor_role: actor.role,
      target_type: 'device',
      target_id: target_device_id,
      payload: { reason, label: target.label },
    });
  });
}

export async function resumeDevice(
  target_device_id: string,
  actor: AdminActor,
): Promise<void> {
  await withTransaction(async (tx) => {
    const target = await loadTarget(tx, target_device_id, actor.org_id);
    if (target.status !== 'suspended') {
      throw Object.assign(new Error('invalid_state'), { statusCode: 409 });
    }
    await tx.query(
      `UPDATE devices SET status = 'active', suspended_at = NULL
       WHERE device_id = $1`,
      [target_device_id],
    );
    await writeAuditEvent(tx, {
      event_type: 'device.resumed',
      actor_device_id: actor.device_id,
      actor_role: actor.role,
      target_type: 'device',
      target_id: target_device_id,
      payload: { label: target.label },
    });
  });
}
