import { withTransaction } from '../db/client.js';
import { tryPushEnvelope } from '../ws/delivery.js';
import { isContactAuthorized } from '../authorization/contacts.js';

export class EnvelopeError extends Error {
  constructor(
    public code: string,
    public statusCode: number = 400,
  ) {
    super(code);
    this.name = 'EnvelopeError';
  }
}

export interface SubmitInput {
  sender_device_id: string;
  recipient_device_id: string;
  ciphertext: string;
  envelope_type?: 'message' | 'call_signal' | 'ack';
  ttl_seconds?: number;
}

export interface SubmitResult {
  envelope_id: string;
  expires_at: string;
}

const DEFAULT_TTL_SECONDS = 30 * 24 * 3600;
const MAX_CIPHERTEXT_BYTES = 1_048_576;

export async function submitEnvelope(input: SubmitInput): Promise<SubmitResult> {
  const ciphertext = Buffer.from(input.ciphertext, 'base64url');
  if (ciphertext.length === 0 || ciphertext.length > MAX_CIPHERTEXT_BYTES) {
    throw new EnvelopeError('invalid_ciphertext', 400);
  }

  const envelopeType = input.envelope_type ?? 'message';
  const ttl = input.ttl_seconds ?? DEFAULT_TTL_SECONDS;
  const expiresAt = new Date(Date.now() + ttl * 1000);

  const result = await withTransaction(async (tx) => {
    const sender = await tx.query(
      'SELECT status FROM devices WHERE device_id = $1',
      [input.sender_device_id],
    );
    if (sender.rowCount !== 1 || sender.rows[0].status !== 'active') {
      throw new EnvelopeError('unauthorized', 401);
    }

    const recipient = await tx.query(
      'SELECT status FROM devices WHERE device_id = $1',
      [input.recipient_device_id],
    );
    if (recipient.rowCount !== 1 || recipient.rows[0].status !== 'active') {
      throw new EnvelopeError('recipient_unavailable', 404);
    }

    if (input.sender_device_id !== input.recipient_device_id) {
      const authorized = await isContactAuthorized(
        input.sender_device_id,
        input.recipient_device_id,
      );
      if (!authorized) {
        throw new EnvelopeError('not_authorized_contact', 403);
      }
    }

    const res = await tx.query(
      `INSERT INTO envelopes
         (sender_device_id, recipient_device_id, ciphertext, envelope_type, expires_at)
       VALUES ($1, $2, $3, $4, $5)
       RETURNING envelope_id, expires_at`,
      [
        input.sender_device_id,
        input.recipient_device_id,
        ciphertext,
        envelopeType,
        expiresAt,
      ],
    );

    return {
      envelope_id: res.rows[0].envelope_id as string,
      expires_at: (res.rows[0].expires_at as Date).toISOString(),
    };
  });

  // Push attempt happens AFTER the transaction commits
  try {
    await tryPushEnvelope(result.envelope_id);
  } catch {
    // Push failure is fine — envelope stays queued for polling
  }

  return result;
}
