import type { PoolClient } from 'pg';
import { pool, withTransaction } from '../db/client.js';
import { writeAuditEvent } from '../audit/log.js';

export class ContactError extends Error {
  constructor(public code: string, public statusCode: number) {
    super(code);
    this.name = 'ContactError';
  }
}

export interface ContactRecord {
  owner_device_id: string;
  contact_device_id: string;
  org_id: string;
  status: string;
  verification_level: string;
  authorized_at: string;
  revoked_at: string | null;
}

export interface ContactView {
  peer_device_id: string;
  peer_label: string;
  status: string;
  verification_level: string;
  authorized_at: string;
}

/**
 * Bidirectional authorization check.
 *
 * Both directions must be status='active' for the pair to be authorized.
 * This is enforced at every point where a message could move between
 * devices (envelope submit, prekey fetch, WS delivery).
 *
 * Runs inside a caller-provided transaction so the check is consistent
 * with whatever write/read is about to happen.
 */
export async function isContactAuthorized(
  tx: PoolClient,
  sender_device_id: string,
  recipient_device_id: string,
): Promise<boolean> {
  if (sender_device_id === recipient_device_id) return false;
  // A pair is authorized only when BOTH directions are active.
  // The two rows (A,B) and (B,A) have different primary keys, so we
  // cannot GROUP BY the pair and expect count=2. Instead we count the
  // matching rows and require exactly 2.
  const res = await tx.query<{ n: number }>(
    `SELECT count(*)::int AS n
       FROM contacts
      WHERE status = 'active'
        AND (
          (owner_device_id = $1 AND contact_device_id = $2) OR
          (owner_device_id = $2 AND contact_device_id = $1)
        )`,
    [sender_device_id, recipient_device_id],
  );
  return (res.rows[0]?.n ?? 0) === 2;
}

/**
 * Convenience wrapper for callers that aren't already in a transaction.
 */
export async function isContactAuthorizedPool(
  sender_device_id: string,
  recipient_device_id: string,
): Promise<boolean> {
  const client = await pool.connect();
  try {
    return await isContactAuthorized(client, sender_device_id, recipient_device_id);
  } finally {
    client.release();
  }
}

/**
 * Authorize a directional contact pair. Admin-only. Creates two rows
 * (both directions) so the pair is active bidirectionally.
 */
export async function authorizeContact(
  actor: { device_id: string; role: string; org_id: string },
  owner_device_id: string,
  contact_device_id: string,
  verification_level: 'directory' | 'qr' = 'directory',
): Promise<void> {
  if (owner_device_id === contact_device_id) {
    throw new ContactError('cannot_authorize_self', 400);
  }

  await withTransaction(async (tx) => {
    // Both devices must exist and be in the same org as the actor
    const devices = await tx.query<{ device_id: string; org_id: string; status: string }>(
      `SELECT device_id, org_id, status
         FROM devices
        WHERE device_id = ANY($1::uuid[])`,
      [[owner_device_id, contact_device_id]],
    );
    if ((devices.rowCount ?? 0) !== 2) {
      throw new ContactError('device_not_found', 404);
    }
    for (const d of devices.rows) {
      if (d.org_id !== actor.org_id) {
        throw new ContactError('cross_org', 403);
      }
      if (d.status === 'revoked') {
        throw new ContactError('device_revoked', 409);
      }
    }

    const pairs: Array<[string, string]> = [
      [owner_device_id, contact_device_id],
      [contact_device_id, owner_device_id],
    ];
    for (const [o, c] of pairs) {
      await tx.query(
        `INSERT INTO contacts
           (owner_device_id, contact_device_id, org_id, status,
            verification_level, authorized_by)
         VALUES ($1, $2, $3, 'active', $4, $5)
         ON CONFLICT (owner_device_id, contact_device_id) DO UPDATE SET
           status = 'active',
           verification_level = EXCLUDED.verification_level,
           authorized_by = EXCLUDED.authorized_by,
           authorized_at = now(),
           revoked_at = NULL,
           revoke_reason = NULL`,
        [o, c, actor.org_id, verification_level, actor.device_id],
      );
    }

    await writeAuditEvent(tx, {
      event_type: 'contact.authorized',
      actor_device_id: actor.device_id,
      actor_role: actor.role,
      target_type: 'contact_pair',
      target_id: `${owner_device_id}:${contact_device_id}`,
      payload: { verification_level },
    });
  });
}

/**
 * Revoke a directional contact pair. Admin-only. Both rows go to 'revoked'.
 */
export async function revokeContact(
  actor: { device_id: string; role: string; org_id: string },
  owner_device_id: string,
  contact_device_id: string,
  reason: string,
): Promise<void> {
  await withTransaction(async (tx) => {
    const res = await tx.query(
      `UPDATE contacts
          SET status = 'revoked',
              revoked_at = now(),
              revoke_reason = $3
        WHERE status <> 'revoked'
          AND org_id = $4
          AND (
            (owner_device_id = $1 AND contact_device_id = $2) OR
            (owner_device_id = $2 AND contact_device_id = $1)
          )`,
      [owner_device_id, contact_device_id, reason, actor.org_id],
    );
    if ((res.rowCount ?? 0) === 0) {
      throw new ContactError('not_found', 404);
    }

    await writeAuditEvent(tx, {
      event_type: 'contact.revoked',
      actor_device_id: actor.device_id,
      actor_role: actor.role,
      target_type: 'contact_pair',
      target_id: `${owner_device_id}:${contact_device_id}`,
      payload: { reason },
    });
  });
}

/**
 * List active contacts for a device, joined with peer labels.
 * Used by GET /me/contacts (self) and GET /admin/contacts (org view).
 */
export async function listContactsForDevice(
  org_id: string,
  device_id: string,
): Promise<ContactView[]> {
  const res = await pool.query(
    `SELECT c.contact_device_id,
            d.label AS peer_label,
            c.status,
            c.verification_level,
            c.authorized_at
       FROM contacts c
       JOIN devices d ON d.device_id = c.contact_device_id
      WHERE c.owner_device_id = $1
        AND c.org_id = $2
        AND c.status = 'active'
        AND d.status = 'active'
      ORDER BY d.label ASC`,
    [device_id, org_id],
  );
  return res.rows.map((r) => ({
    peer_device_id: r.contact_device_id as string,
    peer_label: r.peer_label as string,
    status: r.status as string,
    verification_level: r.verification_level as string,
    authorized_at: (r.authorized_at as Date).toISOString(),
  }));
}

/**
 * List all contacts in an org (admin view, includes revoked/pending).
 */
export async function listAllContacts(org_id: string): Promise<ContactRecord[]> {
  const res = await pool.query(
    `SELECT owner_device_id, contact_device_id, org_id, status,
            verification_level, authorized_at, revoked_at
       FROM contacts
      WHERE org_id = $1
      ORDER BY authorized_at DESC
      LIMIT 1000`,
    [org_id],
  );
  return res.rows.map((r) => ({
    owner_device_id: r.owner_device_id as string,
    contact_device_id: r.contact_device_id as string,
    org_id: r.org_id as string,
    status: r.status as string,
    verification_level: r.verification_level as string,
    authorized_at: (r.authorized_at as Date).toISOString(),
    revoked_at: r.revoked_at ? (r.revoked_at as Date).toISOString() : null,
  }));
}
