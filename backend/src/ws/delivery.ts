import { pool } from '../db/client.js';
import { logger } from '../observability/logging.js';
import { registry } from './registry.js';

/**
 * Attempt to push a queued envelope to a connected recipient.
 * If the recipient is connected and the send succeeds, mark the envelope
 * as delivered. Otherwise leave it queued for the client to poll.
 */
export async function tryPushEnvelope(envelope_id: string): Promise<boolean> {
  const rowRes = await pool.query(
    `SELECT envelope_id, sender_device_id, recipient_device_id,
            envelope_type, ciphertext, created_at, status
     FROM envelopes WHERE envelope_id = $1`,
    [envelope_id],
  );
  if (rowRes.rowCount !== 1) return false;
  const row = rowRes.rows[0];
  if (row.status !== 'queued') return false;

  const recipient_id = row.recipient_device_id as string;
  if (!registry.isConnected(recipient_id)) return false;

  const sent = registry.sendToDevice(recipient_id, {
    type: 'envelope',
    envelope_id: row.envelope_id,
    sender_device_id: row.sender_device_id,
    envelope_type: row.envelope_type,
    ciphertext: (row.ciphertext as Buffer).toString('base64url'),
    created_at: (row.created_at as Date).toISOString(),
  });

  if (!sent) return false;

  const upd = await pool.query(
    `UPDATE envelopes
     SET status = 'delivered', delivered_at = now()
     WHERE envelope_id = $1 AND status = 'queued'`,
    [envelope_id],
  );
  if ((upd.rowCount ?? 0) > 0) {
    logger.info({ envelope_id }, 'envelope pushed over websocket');
    return true;
  }
  return false;
}
