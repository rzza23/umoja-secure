import type { PoolClient } from 'pg';
import { pool, withTransaction } from '../db/client.js';
import { writeAuditEvent } from '../audit/log.js';

export interface AdminActor {
  device_id: string;
  role: string;
  org_id: string;
}

export interface ContactEntry {
  owner_device_id: string;
  contact_device_id: string;
  status: string;
  verification_level: string;
  authorized_at: string;
  revoked_at: string | null;
  owner_label: string;
  contact_label: string;
}

export class ContactError extends Error {
  constructor(
    public code: string,
    public statusCode: number = 400,
  ) {
    super(code);
    this.name = 'ContactError';
  }
}

/**
 * True if both directions of the pair are active. Symmetric model.
 * Called from the envelope queue (before routing) and prekey fetch
 * (before serving a peer bundle).
 */
export async function isContactAuthorized(
  a_device_id: string,
  b_device_id: string,
): Promise<boolean> {
  if (a_device_id === b_device_id) return false;
  const res = await pool.query(
    `SELECT 1 FROM contacts
     WHERE ((owner_device_id = $1 AND contact_device_id = $2)
         OR (owner_device_id = $2 AND contact_device_id = $1))
       AND status = 'active'`,
    [a_device_id, b_device_id],
  );
  // Two active rows are required (A->B and B->A). The count tells us.
  return (res.rowCount ?? 0) >= 2;
}

/**
 * Authorize a mutual contact between two devices in the same org.
 * Creates both rows atomically. Idempotent: if rows exist, they are
 * left unchanged (or un-revoked if previously revoked).
 */
export async function authorizeContact(
  actor: AdminActor,
  owner_device_id: string,
  contact_device_id: string,
  verification_level: 'directory' | 'qr' = 'directory',
): Promise<void> {
  if (owner_device_id === contact_device_id) {
    throw new ContactError('cannot_contact_self', 400);
  }

  await withTransaction(async (tx) => {
    // Both devices must exist, be active, and belong to the admin's org.
    const devRes = await tx.query(
      `SELECT device_id, org_id, status FROM devices
       WHERE device_id = ANY($1::uuid[])`,
      [[owner_device_id, contact_device_id]],
    );
    if (devRes.rowCount !== 2) {
      throw new ContactError('device_not_found', 404);
    }
    for (const row of devRes.rows) {
      if (row.org_id !== actor.org_id) {
        throw new ContactError('cross_org_not_allowed', 403);
      }
      if (row.status !== 'active') {
        throw new ContactError('device_inactive', 409);
      }
    }

    for (const [a, b] of [
      [owner_device_id, contact_device_id],
      [contact_device_id, owner_device_id],
    ]) {
      await tx.query(
        `INSERT INTO contacts
           (owner_device_id, contact_device_id, org_id, status,
            verification_level, authorized_by, authorized_at,
            revoked_at, revoked_by, revoke_reason)
         VALUES ($1, $2, $3, 'active', $4, $5, now(), NULL, NULL, NULL)
         ON CONFLICT (owner_device_id, contact_device_id) DO UPDATE
           SET status = 'active',
               verification_level = EXCLUDED.verification_level,
               authorized_by = EXCLUDED.authorized_by,
               authorized_at = now(),
               revoked_at = NULL,
               revoked_by = NULL,
               revoke_reason = NULL`,
        [a, b, actor.org_id, verification_level, actor.device_id],
      );
    }

    await writeAuditEvent(tx, {
      event_type: 'contact.authorized',
      actor_device_id: actor.device_id,
      actor_role: actor.role,
      target_type: 'contact',
      target_id: `${owner_device_id}:${contact_device_id}`,
      payload: { verification_level },
    });
  });
}

/**
 * Revoke both directions of a contact pair.
 */
export async function revokeContact(
  actor: AdminActor,
  owner_device_id: string,
  contact_device_id: string,
  reason: string,
): Promise<void> {
  await withTransaction(async (tx) => {
    const res = await tx.query(
      `UPDATE contacts
       SET status = 'revoked',
           revoked_at = now(),
           revoked_by = $3,
           revoke_reason = $4
       WHERE ((owner_device_id = $1 AND contact_device_id = $2)
           OR (owner_device_id = $2 AND contact_device_id = $1))
         AND org_id = $5
         AND status = 'active'`,
      [owner_device_id, contact_device_id, actor.device_id, reason, actor.org_id],
    );

    if ((res.rowCount ?? 0) === 0) {
      throw new ContactError('contact_not_found', 404);
    }

    await writeAuditEvent(tx, {
      event_type: 'contact.revoked',
      actor_device_id: actor.device_id,
      actor_role: actor.role,
      target_type: 'contact',
      target_id: `${owner_device_id}:${contact_device_id}`,
      payload: { reason, rows_affected: res.rowCount },
    });
  });
}

/**
 * List all active contacts for a device (as owner). Used by the client
 * to populate the contact list.
 */
export async function listContactsForDevice(
  device_id: string,
): Promise<ContactEntry[]> {
  const res = await pool.query(
    `SELECT c.owner_device_id, c.contact_device_id, c.status,
            c.verification_level, c.authorized_at, c.revoked_at,
            d1.label AS owner_label, d2.label AS contact_label
     FROM contacts c
     JOIN devices d1 ON d1.device_id = c.owner_device_id
     JOIN devices d2 ON d2.device_id = c.contact_device_id
     WHERE c.owner_device_id = $1
       AND c.status = 'active'
     ORDER BY c.authorized_at DESC`,
    [device_id],
  );
  return res.rows.map((r) => ({
    owner_device_id: r.owner_device_id as string,
    contact_device_id: r.contact_device_id as string,
    status: r.status as string,
    verification_level: r.verification_level as string,
    authorized_at: (r.authorized_at as Date).toISOString(),
    revoked_at: r.revoked_at ? (r.revoked_at as Date).toISOString() : null,
    owner_label: r.owner_label as string,
    contact_label: r.contact_label as string,
  }));
}

/**
 * List all contacts in an org (admin view).
 */
export async function listContactsForOrg(
  org_id: string,
): Promise<ContactEntry[]> {
  const res = await pool.query(
    `SELECT c.owner_device_id, c.contact_device_id, c.status,
            c.verification_level, c.authorized_at, c.revoked_at,
            d1.label AS owner_label, d2.label AS contact_label
     FROM contacts c
     JOIN devices d1 ON d1.device_id = c.owner_device_id
     JOIN devices d2 ON d2.device_id = c.contact_device_id
     WHERE c.org_id = $1
     ORDER BY c.authorized_at DESC
     LIMIT 500`,
    [org_id],
  );
  return res.rows.map((r) => ({
    owner_device_id: r.owner_device_id as string,
    contact_device_id: r.contact_device_id as string,
    status: r.status as string,
    verification_level: r.verification_level as string,
    authorized_at: (r.authorized_at as Date).toISOString(),
    revoked_at: r.revoked_at ? (r.revoked_at as Date).toISOString() : null,
    owner_label: r.owner_label as string,
    contact_label: r.contact_label as string,
  }));
}
