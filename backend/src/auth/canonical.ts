export interface Challenge {
  v: 1;
  purpose: 'auth' | 'ws_revalidate' | 'sensitive_op';
  challenge_id: string;
  nonce: string;
  device_id: string;
  session_context: string | null;
  issued_at: string;
  expires_at: string;
  server_id: string;
}

/**
 * Deterministic canonical encoding for challenge signing.
 * Keys sorted ascending, no whitespace, prefix "v1:".
 * Must produce byte-identical output to Android CanonicalChallenge.encode.
 */
export function canonicalizeChallenge(c: Challenge): Buffer {
  const ordered = {
    v: c.v,
    purpose: c.purpose,
    challenge_id: c.challenge_id,
    nonce: c.nonce,
    device_id: c.device_id,
    session_context: c.session_context ?? '',
    issued_at: c.issued_at,
    expires_at: c.expires_at,
    server_id: c.server_id,
  };
  const json = JSON.stringify(ordered, Object.keys(ordered).sort());
  return Buffer.from('v1:' + json, 'utf8');
}
