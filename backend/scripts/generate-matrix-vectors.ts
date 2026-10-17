/**
 * Populate expected_* fields in docs/reference/canonical-matrix-test-vectors.json.
 *
 * For each vector that has the four expected_* fields (the W-series),
 * compute:
 *   - canonical bytes (via jcsCanonicalize)
 *   - SHA-256 digest of those bytes
 *   - Ed25519 signature over the 32-byte digest
 *   - Ed25519 public key
 *
 * Test-only key derivation follows the file's test_only_key_derivation
 * block: HKDF-SHA256(seed, info='ed25519-test-key', 32 bytes) => Ed25519
 * private key seed, wrapped in PKCS8 DER.
 *
 * Uses Node's built-in crypto — no @noble/ed25519 dependency. Test vectors
 * are correctness artifacts, not the production signing path.
 *
 * The operation is deterministic: HKDF is deterministic, and Ed25519
 * (RFC 8032) uses deterministic nonces. Re-running produces byte-identical
 * output.
 *
 * Each generated signature is immediately verified before being written.
 *
 * Usage:
 *   cd backend && npx tsx scripts/generate-matrix-vectors.ts
 *
 * Task: TASK-P1-026
 * Resolves: KI-004
 */
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import {
  createHash,
  createPrivateKey,
  createPublicKey,
  sign,
  verify,
  hkdfSync,
  type KeyObject,
} from 'node:crypto';
import { jcsCanonicalize } from '../src/crypto/jcs.js';

function findRepoRoot(): string {
  let dir = process.cwd();
  for (let i = 0; i < 12; i++) {
    if (existsSync(join(dir, 'UMOJA-SECURE-BUILD-MASTER.md'))) return dir;
    const parent = join(dir, '..');
    if (parent === dir) break;
    dir = parent;
  }
  throw new Error('could not find repo root');
}

const ROOT = findRepoRoot();
const MATRIX_VECTORS_PATH = join(ROOT, 'docs/reference/canonical-matrix-test-vectors.json');
const NOTICE_VECTORS_PATH = join(ROOT, 'docs/reference/canonical-replacement-notice-test-vectors.json');

const SEED_UTF8 = 'umoja-canonical-matrix-test-vectors-v1-DO-NOT-USE-IN-PRODUCTION';
// PKCS8 wrapper for a 32-byte Ed25519 seed. RFC 8410.
const PKCS8_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');

function deriveTestPrivateKey(): KeyObject {
  const rawSeed = Buffer.from(hkdfSync('sha256', Buffer.from(SEED_UTF8, 'utf8'), Buffer.alloc(0), 'ed25519-test-key', 32));
  const pkcs8 = Buffer.concat([PKCS8_PREFIX, rawSeed]);
  return createPrivateKey({ key: pkcs8, format: 'der', type: 'pkcs8' });
}

function rawPublicKey(priv: KeyObject): Buffer {
  const spki = createPublicKey(priv).export({ format: 'der', type: 'spki' }) as Buffer;
  // SPKI for Ed25519 is 44 bytes: 12-byte header + 32-byte raw pubkey.
  return spki.subarray(spki.length - 32);
}

interface Vector {
  id: string;
  input_wrapper?: unknown;
  expected_canonical_bytes_utf8?: string | null;
  expected_sha256_digest_hex?: string | null;
  expected_ed25519_signature_base64url?: string | null;
  expected_provisioning_public_key_base64url?: string | null;
  [k: string]: unknown;
}

interface Doc {
  vectors: Vector[];
  generated?: boolean;
  generated_at?: string;
  [k: string]: unknown;
}

function processDoc(path: string, priv: KeyObject, pubB64u: string): number {
  const doc = JSON.parse(readFileSync(path, 'utf8')) as Doc;
  let filled = 0;
  for (const v of doc.vectors) {
    if (!('expected_canonical_bytes_utf8' in v)) continue;

    if (v.input_wrapper === undefined) {
      throw new Error(`${v.id}: has expected_* fields but no input_wrapper`);
    }

    const canonical = jcsCanonicalize(v.input_wrapper);
    const digest = createHash('sha256').update(canonical).digest();
    const signature = sign(null, digest, priv);

    if (!verify(null, digest, createPublicKey(priv), signature)) {
      throw new Error(`${v.id}: generated signature failed immediate verification`);
    }

    v.expected_canonical_bytes_utf8 = canonical.toString('utf8');
    v.expected_sha256_digest_hex = digest.toString('hex');
    v.expected_ed25519_signature_base64url = signature.toString('base64url');
    v.expected_provisioning_public_key_base64url = pubB64u;
    filled++;
  }

  if (filled === 0) {
    throw new Error(`${path}: no vectors were filled — schema mismatch?`);
  }

  doc.generated = true;
  doc.generated_at = new Date().toISOString();

  writeFileSync(path, JSON.stringify(doc, null, 2) + '\n');
  return filled;
}

function main(): void {
  const priv = deriveTestPrivateKey();
  const pubB64u = rawPublicKey(priv).toString('base64url');

  const matrixFilled = processDoc(MATRIX_VECTORS_PATH, priv, pubB64u);
  console.log(`Matrix vectors filled: ${matrixFilled}`);

  const noticeFilled = processDoc(NOTICE_VECTORS_PATH, priv, pubB64u);
  console.log(`Notice vectors filled: ${noticeFilled}`);

  console.log(`Public key: ${pubB64u}`);
}

main();
