import { withTransaction } from '../db/client.js';

export class AckError extends Error {
  constructor(
    public code: string,
    public statusCode: number,
  ) {
    super(code);
    this.name = 'AckError';
  }
}

export async function acknowledgeEnvelope(
  envelope_id: string,
  recipient_device_id: string,
): Promise<void> {
  return withTransaction(async (tx) => {
    const res = await tx.query(
      `SELECT status FROM envelopes
       WHERE envelope_id = $1 AND recipient_device_id = $2
       FOR UPDATE`,
      [envelope_id, recipient_device_id],
    );
    if (res.rowCount !== 1) throw new AckError('not_found', 404);
    const status = res.rows[0].status as string;

    if (status === 'retrieved') return;
    if (status === 'expired' || status === 'dead') throw new AckError('gone', 410);
    if (status === 'queued' || status === 'locked') {
      throw new AckError('not_delivered', 409);
    }

    await tx.query(
      `UPDATE envelopes SET status = 'retrieved', retrieved_at = now()
       WHERE envelope_id = $1`,
      [envelope_id],
    );
  });
}
