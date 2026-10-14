/**
 * RFC 8785 JSON Canonicalization Scheme (JCS).
 *
 * This is the Umoja authorization-matrix signing canonicalizer.
 *
 * It is DISTINCT from:
 *   - backend/src/auth/canonical.ts   (challenge-response protocol)
 *   - canonicalJson in backend/src/audit/   (audit hash chain)
 *
 * Do not unify them. They serve different protocols with different
 * signing rules. The challenge and audit canonicalizers do NOT prehash;
 * the matrix protocol REQUIRES SHA-256 prehash (Build Master §3.8).
 *
 * Spec:          https://www.rfc-editor.org/rfc/rfc8785.txt
 * Conformance:   docs/reference/jcs-conformance/
 *                docs/reference/rfc8785-number-samples.json
 * Build Master:  §3.8
 * Task:          TASK-P1-026
 */

export class JcsError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'JcsError';
  }
}

/**
 * Canonicalize a JSON value per RFC 8785.
 *
 * Returns the canonical UTF-8 bytes. Callers that need the string form
 * should use jcsCanonicalizeString.
 *
 * @throws {JcsError} if the value contains any type or value that JCS
 *                    does not permit (NaN, Infinity, BigInt, undefined,
 *                    function, symbol, sparse arrays, objects with a
 *                    toJSON method).
 */
export function jcsCanonicalize(value: unknown): Buffer {
  return Buffer.from(jcsCanonicalizeString(value), 'utf8');
}

/**
 * Canonicalize a JSON value per RFC 8785, returning the canonical string.
 * The string's UTF-8 bytes are what gets hashed and signed.
 */
export function jcsCanonicalizeString(value: unknown): string {
  return serialize(value);
}

function serialize(value: unknown): string {
  if (value === null) return 'null';

  switch (typeof value) {
    case 'boolean':
      return value ? 'true' : 'false';

    case 'number': {
      if (!Number.isFinite(value)) {
        // RFC 8785 §3.2.2.3: NaN, Infinity, -Infinity are not permitted.
        throw new JcsError('JCS does not permit NaN, Infinity, or -Infinity');
      }
      // JSON.stringify(Number) already produces ECMAScript-compliant
      // output — exactly what JCS mandates. Do not reimplement number
      // formatting here.
      //
      // Notably: JSON.stringify(-0) === "0" (matches JCS), and
      // JSON.stringify(1e21) === "1e+21" (matches JCS).
      return JSON.stringify(value);
    }

    case 'string':
      // JSON.stringify(String) produces the ECMAScript string
      // serialization that JCS mandates. Control characters are escaped;
      // printable non-ASCII is emitted as raw UTF-8 when the result is
      // encoded to bytes.
      return JSON.stringify(value);

    case 'bigint':
      throw new JcsError('JCS does not permit BigInt');

    case 'undefined':
      throw new JcsError('JCS does not permit undefined');

    case 'function':
      throw new JcsError('JCS does not permit functions');

    case 'symbol':
      throw new JcsError('JCS does not permit symbols');
  }

  // Objects and arrays from here.

  if (Array.isArray(value)) {
    let out = '[';
    for (let i = 0; i < value.length; i++) {
      if (i > 0) out += ',';
      if (!(i in value)) {
        throw new JcsError('JCS does not permit sparse arrays');
      }
      out += serialize(value[i]);
    }
    out += ']';
    return out;
  }

  const obj = value as Record<string, unknown>;

  // Reject objects with a toJSON method. The RFC 8785 example calls it;
  // we reject it, because a matrix has no legitimate reason to expose one
  // and it would introduce non-determinism at the signing boundary.
  if (typeof obj.toJSON === 'function') {
    throw new JcsError(
      'JCS does not permit objects with a toJSON method; call toJSON() first and pass the result',
    );
  }

  // RFC 8785 §3.2.3: sort object keys by UTF-16 code unit order.
  const keys = Object.keys(obj).sort(utf16Compare);

  let out = '{';
  let first = true;
  for (const key of keys) {
    if (!first) out += ',';
    first = false;
    out += JSON.stringify(key);
    out += ':';
    out += serialize(obj[key]);
  }
  out += '}';
  return out;
}

/**
 * Compare two strings by UTF-16 code unit order. RFC 8785 §3.2.3.
 *
 * Not locale-aware, not Unicode-aware, not human-collation. Compares
 * charCodeAt values one by one.
 */
function utf16Compare(a: string, b: string): number {
  const la = a.length;
  const lb = b.length;
  const n = Math.min(la, lb);
  for (let i = 0; i < n; i++) {
    const ca = a.charCodeAt(i);
    const cb = b.charCodeAt(i);
    if (ca !== cb) return ca - cb;
  }
  return la - lb;
}
