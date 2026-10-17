/**
 * Seed a signed test replacement notice into identity_change_notices.
 *
 * Purpose: manual emulator verification of 030e-c 3d-2 (ChatScreen
 * banner surfacing, ack flow) and 3d-3b (foreground lifecycle polling).
 * The client verifies incoming notices against
 * ProvisioningKeys.CURRENT_PROVISIONING_PUBKEY_B64U, so a row with
 * random bytes would fail signature verification at recordNotice and
 * never reach the banner. This tool signs with the SAME test key the
 * vector generator uses, so the client accepts it.
 *
 * Direct DB insert (not POST /identity-change-notices):
 *   The POST path is already covered by 17 backend route tests. The
 *   verification this tool supports is client-side — "does ChatScreen
 *   surface the banner for a correctly-signed notice?". Going through
 *   the DB avoids the admin-session-token extraction dance for a
 *   purpose that doesn't exercise auth.
 *
 * Requires --from and --to device UUIDs. Both must already exist in
 * devices (FK constraint). If either is missing, fails before INSERT
 * with a clear error. Seed devices via psql first:
 *
 *   INSERT INTO devices (device_id, org_id, public_key, public_key_alg, role, status)
 *   VALUES ('<uuid>', '<org-uuid>', decode('<64-hex>', 'hex'), 'ed25519', 'user', 'active');
 *
 * Self-check: derives the test private key from the vector-file seed,
 * derives the public key, and refuses to run if it doesn't match the
 * vector file's expected_provisioning_public_key_base64url. If HKDF
 * derivation ever drifts from the generator, the helper fails loudly
 * rather than silently seeding rows the client will reject.
 *
 * Usage:
 *   cd backend
 *   npx tsx --env-file=.env scripts/sign-test-notice.ts \
 *     --from <from-device-uuid> \
 *     --to <to-device-uuid> \
 *     [--issued-at <iso8601-utc>]
 *
 * Task: TASK-P1-030 030e-c 3d verification
 */
import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import {
  createHash,
  createPrivateKey,
  createPublicKey,
  sign,
  hkdfSync,
  type KeyObject,
} from 'node:crypto';
import { jcsCanonicalize } from '../src/crypto/jcs.js';
import {
  REPLACEMENT_NOTICE_DOMAIN,
  validateReplacementNotice,
  type SignedReplacementNotice,
} from '../src/crypto/replacement-notice.js';
import { withTransaction } from '../src/db/client.js';

const SEED_UTF8 = 'umoja-canonical-matrix-test-vectors-v1-DO-NOT-USE-IN-PRODUCTION';
// PKCS8 wrapper for a 32-byte Ed25519 seed. RFC 8410.
const PKCS8_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');

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

/**
 * Identical to generate-matrix-vectors.ts's deriveTestPrivateKey.
 * Kept duplicated rather than extracted to a shared module so the
 * derivation stays visible at the point of use — if either side
 * drifts, the self-check below catches it at runtime.
 */
function deriveTestPrivateKey(): KeyObject {
  const rawSeed = Buffer.from(
    hkdfSync(
      'sha256',
      Buffer.from(SEED_UTF8, 'utf8'),
      Buffer.alloc(0),
      'ed25519-test-key',
      32,
    ),
  );
  const pkcs8 = Buffer.concat([PKCS8_PREFIX, rawSeed]);
  return createPrivateKey({ key: pkcs8, format: 'der', type: 'pkcs8' });
}

function rawPublicKey(priv: KeyObject): Buffer {
  const spki = createPublicKey(priv).export({ format: 'der', type: 'spki' }) as Buffer;
  // SPKI for Ed25519 is 44 bytes: 12-byte header + 32-byte raw pubkey.
  return spki.subarray(spki.length - 32);
}

function loadExpectedPubKey(): string {
  const path = join(findRepoRoot(), 'docs/reference/canonical-matrix-test-vectors.json');
  const doc = JSON.parse(readFileSync(path, 'utf8')) as {
    vectors?: Array<{ expected_provisioning_public_key_base64url?: string }>;
  };
  const found = doc.vectors
    ?.find((v) => typeof v.expected_provisioning_public_key_base64url === 'string')
    ?.expected_provisioning_public_key_base64url;
  if (!found) {
    throw new Error(
      `${path}: no vector with expected_provisioning_public_key_base64url`,
    );
  }
  return found;
}

interface Args {
  from: string;
  to: string;
  issuedAt: string;
}

function parseArgs(): Args {
  const argv = process.argv.slice(2);
  const get = (flag: string): string | undefined => {
    const i = argv.indexOf(flag);
    return i >= 0 && i + 1 < argv.length ? argv[i + 1] : undefined;
  };
  const from = get('--from');
  const to = get('--to');
  if (!from || !to) {
    console.error(
      'Usage: npx tsx --env-file=.env scripts/sign-test-notice.ts ' +
        '--from <from-device-uuid> --to <to-device-uuid> [--issued-at <iso8601-utc>]',
    );
    process.exit(1);
  }
  const issuedAt = get('--issued-at') ?? new Date().toISOString();
  return { from, to, issuedAt };
}

async function run(): Promise<void> {
  const { from: fromId, to: toId, issuedAt } = parseArgs();

  // 1. Derive test key, self-check against vector file.
  const priv = deriveTestPrivateKey();
  const derivedPub = rawPublicKey(priv).toString('base64url');
  const expectedPub = loadExpectedPubKey();
  if (derivedPub !== expectedPub) {
    throw new Error(
      `HKDF derivation mismatch:\n  derived:   ${derivedPub}\n  expected:  ${expectedPub}\n` +
        'Refusing to seed — see the derivation comment at the top of this file.',
    );
  }
  console.log(`[self-check] test key derivation verified (pub=${derivedPub})`);

  // 2. Look up devices, get org_id + public_key from devices table.
  const devRes = await withTransaction(async (tx) =>
    tx.query<{ device_id: string; org_id: string; public_key: Buffer }>(
      `SELECT device_id, org_id, public_key
       FROM devices
       WHERE device_id = ANY($1::uuid[])`,
      [[fromId, toId]],
    ),
  );

  if (devRes.rowCount !== 2) {
    const found = new Set(devRes.rows.map((r) => r.device_id));
    const missing = [fromId, toId].filter((id) => !found.has(id));
    throw new Error(
      `device(s) not found: ${missing.join(', ')} — seed via psql first ` +
        '(see the psql example in this file\'s header comment)',
    );
  }

  const fromRow = devRes.rows.find((r) => r.device_id === fromId)!;
  const toRow = devRes.rows.find((r) => r.device_id === toId)!;

  if (fromRow.org_id !== toRow.org_id) {
    throw new Error(
      `devices in different orgs: ${fromRow.org_id} vs ${toRow.org_id}`,
    );
  }
  if (fromRow.public_key.length !== 32) {
    throw new Error(
      `device ${fromId}: public_key expected 32 bytes, got ${fromRow.public_key.length}`,
    );
  }
  if (toRow.public_key.length !== 32) {
    throw new Error(
      `device ${toId}: public_key expected 32 bytes, got ${toRow.public_key.length}`,
    );
  }

  // 3. Build, validate, canonicalize, sign.
  const wrapper = {
    domain: REPLACEMENT_NOTICE_DOMAIN,
    notice: {
      from_device_id: fromId,
      from_device_auth_key: fromRow.public_key.toString('base64url'),
      to_device_id: toId,
      to_device_auth_key: toRow.public_key.toString('base64url'),
      issued_at: issuedAt,
    },
  } as const;

  const signed: SignedReplacementNotice = validateReplacementNotice(wrapper);
  const canonical = jcsCanonicalize(signed);
  // Per ADR-IDENTITY-CHANGE-001 §7 step 4 and migration 015:
  //   notice_hash = SHA-256(canonical_utf8 bytes)
  // which is the same digest the prehash signing protocol signs.
  const noticeHash = createHash('sha256').update(canonical).digest();
  const signature = sign(null, noticeHash, priv);

  // 4. INSERT. ON CONFLICT DO NOTHING makes re-runs with identical
  //    --issued-at idempotent (same notice_hash → no-op). Different
  //    --issued-at produces a different hash → new row (which is what
  //    you want when you're seeding multiple distinct test notices).
  const insert = await withTransaction(async (tx) =>
    tx.query<{ notice_hash: Buffer; created_at: Date }>(
      `INSERT INTO identity_change_notices
         (notice_hash, org_id, from_device_id, to_device_id,
          canonical_bytes, signature_base64url)
       VALUES ($1, $2, $3, $4, $5, $6)
       ON CONFLICT (notice_hash) DO NOTHING
       RETURNING notice_hash, created_at`,
      [
        noticeHash,
        fromRow.org_id,
        fromId,
        toId,
        canonical,
        signature.toString('base64url'),
      ],
    ),
  );

  const hashB64u = noticeHash.toString('base64url');

  if ((insert.rowCount ?? 0) === 1) {
    const createdAt = insert.rows[0]!.created_at;
    console.log(`[inserted] notice_hash=${hashB64u}`);
    console.log(`  org_id=${fromRow.org_id}`);
    console.log(`  from=${fromId}`);
    console.log(`  to=${toId}`);
    console.log(`  issued_at=${issuedAt}`);
    console.log(`  created_at=${createdAt.toISOString()}`);
    console.log('');
    console.log('Next:');
    console.log('  - Open a chat with the "to" device on the target emulator');
    console.log('    (chat-open triggers refresh), or');
    console.log('  - Background + foreground the app (3d-3b foreground trigger)');
    console.log('  - Expect: inline banner "Device replacement awaiting your acknowledgment"');
  } else {
    console.log(`[no-op] notice_hash=${hashB64u} already present — nothing to do`);
  }
}

run().catch((err) => {
  console.error(err instanceof Error ? err.message : String(err));
  process.exit(1);
});
