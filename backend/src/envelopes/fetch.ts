import { withTransaction } from '../db/client.js';

export interface FetchedEnvelope {
  envelope_id: string;
  sender_device_id: string;
  envelope_type: string;
  ciphertext: string;
  created_at: string;
  delivered_at: string;
}

export async function fetchEnvelope(
  envelope_id: string,
  recipient_device_id: string,
): Promise<FetchedEnvelope | null> {
  return withTransaction(async (tx) => {
    const res = await tx.query(
      `SELECT envelope_id, sender_device_id, envelope_type, ciphertext,
              created_at, status, expires_at, delivered_at
       FROM envelopes
       WHERE envelope_id = $1 AND recipient_device_id = $2
       FOR UPDATE`,
      [envelope_id, recipient_device_id],
    );
    if (res.rowCount !== 1) return null;
    const row = res.rows[0];

    if (row.status === 'expired' || row.status === 'dead') return null;

    if (new Date(row.expires_at as Date) <= new Date()) {
      await tx.query(
        `UPDATE envelopes SET status = 'expired' WHERE envelope_id = $1`,
        [envelope_id],
      );
      return null;
    }

    let deliveredAt: Date;
    if (row.status === 'queued') {
      const upd = await tx.query(
        `UPDATE envelopes SET status = 'delivered', delivered_at = now()
         WHERE envelope_id = $1
         RETURNING delivered_at`,
        [envelope_id],
      );
      deliveredAt = upd.rows[0].delivered_at as Date;
    } else {
      deliveredAt = row.delivered_at as Date;
    }

    return {
      envelope_id: row.envelope_id as string,
      sender_device_id: row.sender_device_id as string,
      envelope_type: row.envelope_type as string,
      ciphertext: (row.ciphertext as Buffer).toString('base64url'),
      created_at: (row.created_at as Date).toISOString(),
      delivered_at: deliveredAt.toISOString(),
    };
  });
}
