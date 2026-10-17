import { createHash } from 'node:crypto';

export const IDENTITY_CHANGE_ACK_DOMAIN = 'umoja.identity-change-ack.v1' as const;

export type AckDecision = 'accept' | 'reject';

export interface IdentityChangeAck {
  notice_hash: string;
  acking_device_id: string;
  decision: AckDecision;
  issued_at: string;
}

export interface SignedIdentityChangeAck {
  domain: typeof IDENTITY_CHANGE_ACK_DOMAIN;
  ack: IdentityChangeAck;
}

export class IdentityChangeAckError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'IdentityChangeAckError';
  }
}

// Prefixed per handoff §7 convention: this is the second file to
// introduce requireString / requireBase64Url32 / ISO8601_UTC_RE.
// Sibling replacement-notice.ts keeps its own file-private copies
// unprefixed; the prefix here prevents accidental cross-file reads
// during editing (the Session F bug class in Kotlin, applied here as
// cheap defense-in-depth even though TS file-private scope would
// already fail compilation).
const IC_BASE64URL32_RE = /^[A-Za-z0-9_-]{43}$/;
const IC_ISO8601_UTC_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$/;

function IC_REQUIRE_STRING(value: unknown, field: string): string {
  if (typeof value !== 'string' || value.length === 0) {
    throw new IdentityChangeAckError(`${field}: expected non-empty string`);
  }
  return value;
}

function IC_REQUIRE_BASE64URL32(value: unknown, field: string): string {
  const s = IC_REQUIRE_STRING(value, field);
  if (!IC_BASE64URL32_RE.test(s)) {
    throw new IdentityChangeAckError(
      `${field}: expected base64url 32-byte value (43 chars, no padding)`,
    );
  }
  return s;
}

/**
 * Validate an unknown value as a SignedIdentityChangeAck.
 *
 * @throws IdentityChangeAckError on any shape or content violation.
 */
export function validateIdentityChangeAck(
  value: unknown,
): SignedIdentityChangeAck {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    throw new IdentityChangeAckError('identity-change-ack: expected object');
  }
  const w = value as Record<string, unknown>;

  if (w.domain !== IDENTITY_CHANGE_ACK_DOMAIN) {
    throw new IdentityChangeAckError(
      `domain: expected "${IDENTITY_CHANGE_ACK_DOMAIN}", got ${
        typeof w.domain === 'string' ? JSON.stringify(w.domain) : String(w.domain)
      }`,
    );
  }

  const a = w.ack;
  if (a === null || typeof a !== 'object' || Array.isArray(a)) {
    throw new IdentityChangeAckError('ack: expected object');
  }
  const aa = a as Record<string, unknown>;

  const notice_hash = IC_REQUIRE_BASE64URL32(aa.notice_hash, 'notice_hash');
  const acking_device_id = IC_REQUIRE_STRING(aa.acking_device_id, 'acking_device_id');
  const decision_raw = IC_REQUIRE_STRING(aa.decision, 'decision');
  const issued_at = IC_REQUIRE_STRING(aa.issued_at, 'issued_at');

  if (decision_raw !== 'accept' && decision_raw !== 'reject') {
    throw new IdentityChangeAckError(
      `decision: expected "accept" or "reject", got ${JSON.stringify(decision_raw)}`,
    );
  }
  const decision: AckDecision = decision_raw;

  if (!IC_ISO8601_UTC_RE.test(issued_at)) {
    throw new IdentityChangeAckError(
      `issued_at: expected ISO 8601 UTC with trailing Z, got ${issued_at}`,
    );
  }

  return {
    domain: IDENTITY_CHANGE_ACK_DOMAIN,
    ack: {
      notice_hash,
      acking_device_id,
      decision,
      issued_at,
    },
  };
}

/**
 * SHA-256 digest of the ack wrapper. This is the message Ed25519 signs
 * (prehash protocol, per ADR-IDENTITY-CHANGE-001 §3: "Ed25519 over
 * SHA-256 of JCS-canonical bytes").
 *
 * Takes RAW bytes — the function does NOT re-canonicalize, unlike
 * replacementNoticeDigest. The ack verifier is backend-side and must
 * enforce BYTE-IDENTITY between what the client signed and what the
 * backend stored (migration 015 comment: "canonical_bytes is BYTEA,
 * not JSONB. The trust artifact is byte-identity with what was
 * signed"). A reordering attacker who submits JSON-equivalent but
 * differently-serialized bytes would pass a re-canonicalizing verifier
 * — that would break the byte-identity property. The client signer
 * canonicalizes before calling this; the backend verifier calls this
 * on the exact received bytes.
 *
 * The sibling replacementNoticeDigest DOES re-canonicalize. That is
 * correct for the notice path (client-side verification of a relayed
 * artifact, where JSON-equivalence is the contract) but wrong for the
 * ack path (backend-side storage-anchored verification). Two
 * protocols, two digest contracts, do not unify.
 */
export function identityChangeAckDigest(raw: Buffer | string): Buffer {
  const buf = typeof raw === 'string' ? Buffer.from(raw, 'utf8') : raw;
  return createHash('sha256').update(buf).digest();
}