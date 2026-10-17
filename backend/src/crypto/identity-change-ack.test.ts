import { describe, expect, it } from 'vitest';
import { createHash } from 'node:crypto';
import {
  IDENTITY_CHANGE_ACK_DOMAIN,
  IdentityChangeAckError,
  identityChangeAckDigest,
  validateIdentityChangeAck,
  type SignedIdentityChangeAck,
} from './identity-change-ack.js';

const VALID_NOTICE_HASH = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
const VALID_DEVICE_ID = '11111111-1111-1111-1111-111111111111';

function validAck(): SignedIdentityChangeAck {
  return {
    domain: IDENTITY_CHANGE_ACK_DOMAIN,
    ack: {
      notice_hash: VALID_NOTICE_HASH,
      acking_device_id: VALID_DEVICE_ID,
      decision: 'accept',
      issued_at: '2026-10-17T12:00:00Z',
    },
  };
}

describe('identity-change-ack validator', () => {
  it('TEST-ACK-VALIDATOR-VALID: accepts a well-formed ack and returns the wrapper', () => {
    const out = validateIdentityChangeAck(validAck());
    expect(out.domain).toBe(IDENTITY_CHANGE_ACK_DOMAIN);
    expect(out.ack.decision).toBe('accept');
    expect(out.ack.notice_hash).toBe(VALID_NOTICE_HASH);
  });

  it('TEST-ACK-VALIDATOR-REJECT-NON-OBJECT: rejects null / string / array', () => {
    for (const bad of [null, 'string', [], 42]) {
      expect(() => validateIdentityChangeAck(bad)).toThrow(IdentityChangeAckError);
    }
  });

  it('TEST-ACK-VALIDATOR-REJECT-WRONG-DOMAIN: rejects a domain mismatch', () => {
    const v = validAck() as unknown as Record<string, unknown>;
    v.domain = 'umoja.replacement-notice.v1';
    expect(() => validateIdentityChangeAck(v)).toThrow(/domain: expected/);
  });

  it('TEST-ACK-VALIDATOR-REJECT-MISSING-ACK: rejects a missing ack object', () => {
    expect(() =>
      validateIdentityChangeAck({ domain: IDENTITY_CHANGE_ACK_DOMAIN }),
    ).toThrow(/ack: expected object/);
  });

  it('TEST-ACK-VALIDATOR-REJECT-BAD-DECISION: rejects decision outside {accept, reject}', () => {
    const v = validAck() as unknown as { ack: Record<string, unknown> };
    v.ack.decision = 'maybe';
    expect(() => validateIdentityChangeAck(v)).toThrow(/decision: expected/);
  });

  it('TEST-ACK-VALIDATOR-REJECT-BAD-NOTICE-HASH: rejects notice_hash that is not 43-char base64url', () => {
    for (const bad of ['', 'short', 'A'.repeat(44), 'A'.repeat(42), 'A'.repeat(43) + '=']) {
      const v = validAck() as unknown as { ack: Record<string, unknown> };
      v.ack.notice_hash = bad;
      expect(() => validateIdentityChangeAck(v)).toThrow(/notice_hash/);
    }
  });

  it('TEST-ACK-VALIDATOR-DIGEST-IS-SHA256-OF-RAW-BYTES: digest is byte-identity over the input', () => {
    const raw = '{"domain":"umoja.identity-change-ack.v1","ack":{}}';
    const expected = createHash('sha256').update(raw, 'utf8').digest();
    expect(identityChangeAckDigest(raw).equals(expected)).toBe(true);
    expect(identityChangeAckDigest(Buffer.from(raw, 'utf8')).equals(expected)).toBe(true);
  });
});