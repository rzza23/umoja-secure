import { pool } from '../db/client.js';

export interface PendingEnvelope {
  envelope_id: string;
  sender_device_id: string;
  envelope_type: string;
  created_at: string;
  expires_at: string;
  ciphertext_size: number;
}

export async function listPendingEnvelopes(
  recipient_device_id: string,
): Promise<PendingEnvelope[]> {
  const res = await pool.query(
    `SELECT envelope_id, sender_device_id, envelope_type, created_at, expires_at,
            octet_length(ciphertext) AS ciphertext_size
     FROM envelopes
     WHERE recipient_device_id = $1
       AND status = 'queued'
       AND expires_at > now()
     ORDER BY created_at ASC`,
    [recipient_device_id],
  );
  return res.rows.map((r) => ({
    envelope_id: r.envelope_id as string,
    sender_device_id: r.sender_device_id as string,
    envelope_type: r.envelope_type as string,
    created_at: (r.created_at as Date).toISOString(),
    expires_at: (r.expires_at as Date).toISOString(),
    ciphertext_size: r.ciphertext_size as number,
  }));
}
