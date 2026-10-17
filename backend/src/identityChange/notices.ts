import { createHash } from 'node:crypto';
import { withTransaction } from '../db/client.js';
import {
  ReplacementNoticeError,
  validateReplacementNotice,
} from '../crypto/replacement-notice.js';
import { deviceIdSchema } from '../enrollment/deviceId.js';

export class IdentityChangeNoticeError extends Error {
  constructor(
    public readonly code: string,
    public readonly statusCode: number,
  ) {
    super(code);
    this.name = 'IdentityChangeNoticeError';
  }
}

export interface CreateNoticeInput {
  org_id: string;
  canonical_utf8: string;
  signature_base64url: string;
}

export interface CreateNoticeResult {
  notice_hash: string;
  created_at: string;
}

/**
 * POST /identity-change-notices service.
 *
 * ADR-IDENTITY-CHANGE-001 §4: notices are a RELAY. The backend stores
 * verbatim and does NOT verify the provisioning signature — that key
 * is client-pinned only (server-blind, ADR-PROVISIONING-001 §2 Q3).
 * Peers reject forged notices on signature at the client. Only shape
 * is validated here, plus org membership of the referenced devices
 * (so a hostile admin cannot stuff the notice table with devices from
 * another org — TEST-NOTICE-REJECT-UNKNOWN-FROM/TO).
 *
 * No audit event in 030e-b. If audit is desired it belongs in a
 * separate commit that also adds the event_type to audit/log.ts's
 * whitelist, so it does not smuggle an unrelated change here.
 */
export async function createIdentityChangeNotice(
  input: CreateNoticeInput,
): Promise<CreateNoticeResult> {
  let parsed: unknown;
  try {
    parsed = JSON.parse(input.canonical_utf8);
  } catch {
    throw new IdentityChangeNoticeError('invalid_request', 400);
  }

  let signed: ReturnType<typeof validateReplacementNotice>;
  try {
    signed = validateReplacementNotice(parsed);
  } catch (err) {
    if (err instanceof ReplacementNoticeError) {
      throw new IdentityChangeNoticeError('invalid_request', 400);
    }
    throw err;
  }
  const notice = signed.notice;

  if (
    !deviceIdSchema.safeParse(notice.from_device_id).success ||
    !deviceIdSchema.safeParse(notice.to_device_id).success
  ) {
    throw new IdentityChangeNoticeError('invalid_request', 400);
  }

  const canonicalBytes = Buffer.from(input.canonical_utf8, 'utf8');
  const noticeHash = createHash('sha256').update(canonicalBytes).digest();

  return withTransaction(async (tx) => {
    const dev = await tx.query<{ device_id: string; org_id: string }>(
      `SELECT device_id, org_id FROM devices
       WHERE device_id = ANY($1::uuid[])`,
      [[notice.from_device_id, notice.to_device_id]],
    );
    if (dev.rowCount !== 2) {
      throw new IdentityChangeNoticeError('device_not_found', 400);
    }
    for (const row of dev.rows) {
      if (row.org_id !== input.org_id) {
        throw new IdentityChangeNoticeError('device_not_found', 400);
      }
    }

    const insert = await tx.query<{ created_at: Date }>(
      `INSERT INTO identity_change_notices
         (notice_hash, org_id, from_device_id, to_device_id,
          canonical_bytes, signature_base64url)
       VALUES ($1, $2, $3, $4, $5, $6)
       ON CONFLICT (notice_hash) DO NOTHING
       RETURNING created_at`,
      [
        noticeHash,
        input.org_id,
        notice.from_device_id,
        notice.to_device_id,
        canonicalBytes,
        input.signature_base64url,
      ],
    );

    let createdAt: Date;
    if (insert.rowCount === 1) {
      createdAt = insert.rows[0]!.created_at;
    } else {
      const exists = await tx.query<{ created_at: Date }>(
        `SELECT created_at FROM identity_change_notices WHERE notice_hash = $1`,
        [noticeHash],
      );
      createdAt = exists.rows[0]!.created_at;
    }

    return {
      notice_hash: noticeHash.toString('base64url'),
      created_at: createdAt.toISOString(),
    };
  });
}

export interface ListNoticesResult {
  notices: Array<{
    notice_hash: string;
    canonical_utf8: string;
    signature_base64url: string;
    from_device_id: string;
    to_device_id: string;
    created_at: string;
  }>;
}

/**
 * GET /identity-change-notices service.
 *
 * ADR §5 Option C: returns up to 500 most recent notices in the
 * caller's org. NOT filtered by permitted_contacts — the backend does
 * not store matrices (P1-026 is client-side). Client filters locally
 * by its accepted matrix. The org boundary IS the trust perimeter
 * (§5), so returning all org notices leaks no relationship info.
 */
export async function listIdentityChangeNotices(
  org_id: string,
): Promise<ListNoticesResult> {
  return withTransaction(async (tx) => {
    const res = await tx.query<{
      notice_hash: Buffer;
      canonical_bytes: Buffer;
      signature_base64url: string;
      from_device_id: string;
      to_device_id: string;
      created_at: Date;
    }>(
      `SELECT notice_hash, canonical_bytes, signature_base64url,
              from_device_id, to_device_id, created_at
       FROM identity_change_notices
       WHERE org_id = $1
       ORDER BY created_at DESC
       LIMIT 500`,
      [org_id],
    );
    return {
      notices: res.rows.map((r) => ({
        notice_hash: r.notice_hash.toString('base64url'),
        canonical_utf8: r.canonical_bytes.toString('utf8'),
        signature_base64url: r.signature_base64url,
        from_device_id: r.from_device_id,
        to_device_id: r.to_device_id,
        created_at: r.created_at.toISOString(),
      })),
    };
  });
}