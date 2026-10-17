import { createHash } from 'node:crypto';
import * as ed from '@noble/ed25519';
import { withTransaction } from '../db/client.js';
import {
  IdentityChangeAckError,
  identityChangeAckDigest,
  validateIdentityChangeAck,
} from '../crypto/identity-change-ack.js';

export class AckRouteError extends Error {
  constructor(
    public readonly code: string,
    public readonly statusCode: number,
  ) {
    super(code);
    this.name = 'AckRouteError';
  }
}

export interface CreateAckInput {
  actor_device_id: string;
  actor_org_id: string;
  canonical_utf8: string;
  signature_base64url: string;
}

export interface CreateAckResult {
  ack_hash: string;
  created_at: string;
}

/**
 * POST /identity-change-acks service. THE TRUST MOMENT (§7).
 *
 * Per ADR-IDENTITY-CHANGE-001 §3, the ack signing protocol is
 * Ed25519 over SHA-256 of JCS-canonical bytes — PREHASH, not
 * direct-message. §7 step 8 shorthand ("verifyAsync(signature,
 * canonical_bytes, ...)") is imprecise; §3 is authoritative for the
 * crypto protocol. Same `@noble/ed25519.verifyAsync` primitive as
 * `auth/verify.ts`, different protocol (verifyChallenge uses the
 * direct-message path; this uses prehash). Two paths, one primitive,
 * no shared surface. Do not unify — different protocols, different
 * signing rules (see handoff §4 KI-008 for the analogous
 * canonicalizer note).
 */
export async function createIdentityChangeAck(
  input: CreateAckInput,
): Promise<CreateAckResult> {
  let parsed: unknown;
  try {
    parsed = JSON.parse(input.canonical_utf8);
  } catch {
    throw new AckRouteError('invalid_request', 400);
  }

  let signed: ReturnType<typeof validateIdentityChangeAck>;
  try {
    signed = validateIdentityChangeAck(parsed);
  } catch (err) {
    if (err instanceof IdentityChangeAckError) {
      throw new AckRouteError('invalid_request', 400);
    }
    throw err;
  }
  const ack = signed.ack;

  // ADR §7 step 2: cannot ack as someone else.
  if (ack.acking_device_id !== input.actor_device_id) {
    throw new AckRouteError('invalid_request', 400);
  }

  const canonicalBytes = Buffer.from(input.canonical_utf8, 'utf8');
  const signatureBytes = Buffer.from(input.signature_base64url, 'base64url');
  if (signatureBytes.length !== 64) {
    throw new AckRouteError('invalid_signature', 400);
  }
  const ackHash = createHash('sha256').update(canonicalBytes).digest();
  const noticeHashBytes = Buffer.from(ack.notice_hash, 'base64url');

  return withTransaction(async (tx) => {
    // ADR §7 step 4: notice exists.
    const notice = await tx.query<{ org_id: string }>(
      `SELECT org_id FROM identity_change_notices WHERE notice_hash = $1`,
      [noticeHashBytes],
    );
    const noticeRow = notice.rows[0];
    if (notice.rowCount !== 1 || !noticeRow) {
      throw new AckRouteError('unknown_notice', 400);
    }
    // ADR §7 step 5: same-org.
    if (noticeRow.org_id !== input.actor_org_id) {
      throw new AckRouteError('cross_org_rejected', 403);
    }

    // ADR §7 steps 6-7: acking device active + ed25519.
    const dev = await tx.query<{
      status: string;
      public_key: Buffer;
      public_key_alg: string;
    }>(
      `SELECT status, public_key, public_key_alg
       FROM devices WHERE device_id = $1`,
      [ack.acking_device_id],
    );
    const device = dev.rows[0];
    if (dev.rowCount !== 1 || !device || device.status !== 'active') {
      throw new AckRouteError('device_revoked', 403);
    }
    if (device.public_key_alg !== 'ed25519') {
      throw new AckRouteError('unsupported_algorithm', 501);
    }

    // ADR §7 step 8, corrected per §3: prehash verify.
    const digest = identityChangeAckDigest(canonicalBytes);
    const valid = await ed.verifyAsync(
      signatureBytes,
      digest,
      device.public_key,
    );
    if (!valid) {
      throw new AckRouteError('invalid_signature', 400);
    }

    // ADR §7 step 9: INSERT ON CONFLICT DO NOTHING (replay idempotence).
    const insert = await tx.query<{ created_at: Date }>(
      `INSERT INTO identity_change_acks
         (notice_hash, acking_device_id, org_id, decision,
          canonical_bytes, signature_base64url)
       VALUES ($1, $2, $3, $4, $5, $6)
       ON CONFLICT (notice_hash, acking_device_id) DO NOTHING
       RETURNING created_at`,
      [
        noticeHashBytes,
        ack.acking_device_id,
        input.actor_org_id,
        ack.decision,
        canonicalBytes,
        input.signature_base64url,
      ],
    );

    let createdAt: Date;
    if (insert.rowCount === 1) {
      createdAt = insert.rows[0]!.created_at;
    } else {
      const exists = await tx.query<{ created_at: Date }>(
        `SELECT created_at FROM identity_change_acks
         WHERE notice_hash = $1 AND acking_device_id = $2`,
        [noticeHashBytes, ack.acking_device_id],
      );
      createdAt = exists.rows[0]!.created_at;
    }

    return {
      ack_hash: ackHash.toString('base64url'),
      created_at: createdAt.toISOString(),
    };
  });
}

export interface ListAcksResult {
  acks: Array<{
    acking_device_id: string;
    decision: string;
    created_at: string;
  }>;
}

/**
 * GET /identity-change-acks/:notice_hash service.
 *
 * Returns decision + acking_device_id + created_at. Does NOT return
 * ack canonical bytes or signatures — the signature has already been
 * verified server-side (ADR §7 last paragraph). A peer that wants
 * cryptographic proof of another peer's decision is out of scope
 * for 030e-b.
 */
export async function listAcksByNotice(
  notice_hash_b64u: string,
  caller_org_id: string,
): Promise<ListAcksResult> {
  const noticeHashBytes = Buffer.from(notice_hash_b64u, 'base64url');
  return withTransaction(async (tx) => {
    const notice = await tx.query<{ org_id: string }>(
      `SELECT org_id FROM identity_change_notices WHERE notice_hash = $1`,
      [noticeHashBytes],
    );
    const noticeRow = notice.rows[0];
    if (notice.rowCount !== 1 || !noticeRow) {
      throw new AckRouteError('unknown_notice', 400);
    }
    if (noticeRow.org_id !== caller_org_id) {
      throw new AckRouteError('cross_org_rejected', 403);
    }
    const acks = await tx.query<{
      acking_device_id: string;
      decision: string;
      created_at: Date;
    }>(
      `SELECT acking_device_id, decision, created_at
       FROM identity_change_acks
       WHERE notice_hash = $1
       ORDER BY created_at ASC`,
      [noticeHashBytes],
    );
    return {
      acks: acks.rows.map((r) => ({
        acking_device_id: r.acking_device_id,
        decision: r.decision,
        created_at: r.created_at.toISOString(),
      })),
    };
  });
}