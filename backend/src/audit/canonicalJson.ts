/**
 * Deterministic JSON serialization for the audit hash chain HMAC.
 *
 * **Not JCS.** JCS (RFC 8785) is used elsewhere in this codebase for
 * matrix, notice, and ack signing (see backend/src/crypto/jcs.ts).
 * This function is a shallow top-level-key sort only -- nested object
 * key order is whatever `JSON.stringify` emits. For the audit body
 * shape (flat: event_type, actor_device_id, actor_role, target_type,
 * target_id, payload, created_at) this is stable and self-consistent:
 * both log.ts (which computes the hash at write time) and verify.ts
 * (which recomputes it during chain verification) call this same
 * function on the same body shape.
 *
 * **Known pre-existing concern, not fixed here:** the shallow sort
 * means nested payload objects could reorder (Postgres JSONB does not
 * guarantee key order), which would produce a different HMAC at
 * verify time and break the audit chain with a misleading
 * "broken_at: N" result. Extraction preserves the current behavior
 * byte-identically -- changing the HMAC would invalidate every
 * existing audit chain. If this becomes a real problem, changing the
 * audit hash requires a chain migration, not a small fix.
 *
 * **Why this file exists (Session U-1 KI-008):** the function was
 * duplicated byte-identically in log.ts and verify.ts. If a future
 * change added sorting to one but not the other, every audit chain
 * verification would fail silently -- the write path and the verify
 * path would compute different HMACs on the same body. Extracting
 * eliminates the drift risk.
 *
 * Not to be confused with `jcsCanonicalize` in crypto/jcs.ts, which
 * is a full RFC 8785 implementation with different properties.
 */
export function canonicalJson(obj: Record<string, unknown>): string {
  return JSON.stringify(obj, Object.keys(obj).sort());
}
