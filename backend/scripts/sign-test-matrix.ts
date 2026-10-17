/**
 * Seed a signed authorization matrix into the matrices table.
 *
 * Purpose: manual emulator verification of TASK-P1-037 O-2 (MatrixApi
 * fetch + AppRoot wiring + MatrixStore.accept). The client verifies
 * incoming matrices against ProvisioningKeys.CURRENT_PROVISIONING_
 * PUBKEY_B64U, so a row with random bytes would fail signature
 * verification and never reach MatrixStore.accept(). This tool signs
 * with the SAME test key the vector generator uses, so the client
 * accepts it.
 *
 * Direct DB insert/UPSERT (not a POST path):
 *   The POST write path is P1-033's "admin attaches signature and
 *   pushes" — not in this task. Until that lands, seeding directly is
 *   the only way to populate the table. Same pattern as
 *   sign-test-notice.ts (TASK-P1-030 030e-c).
 *
 * Requires --device <uuid>. The device must already exist in devices
 * (FK constraint). If missing, fails before INSERT with a clear error.
 *
 * Self-check: derives the test private key from the vector-file seed,
 * derives the public key, and refuses to run if it doesn't match the
 * vector file's expected_provisioning_public_key_base64url. If HKDF
 * derivation ever drifts from the generator, the helper fails loudly
 * rather than silently seeding rows the client will reject.
 *
 * Synthetic key fields: `pub_messaging_identity_key` and
 * `pub_wipe_confirmation_key` are read from `devices` if present
 * (enrollDevice populates them via the QR path) and synthesized from
 * random bytes if null. For transport verification the matrix verifies
 * against the provisioning key regardless of these values — the client
 * does not inspect them during MatrixStore.accept(). A real enrollment
 * flow always populates them; they are synthetic only for seed-via-DB
 * dev/emulator testing.
 *
 * UPSERT, not INSERT: migration 016's updated_at invariant requires
 * the write path to set updated_at = now() explicitly on conflict. A
 * re-run with the same --version replaces the row in place; a re-run
 * with a higher --version is the update path.
 *
 * Usage:
 *   cd backend
 *   npx tsx --env-file=.env scripts/sign-test-matrix.ts \
 *     --device <device-uuid> \
 *     [--version <int>] \
 *     [--clearance <string>] \
 *     [--permitted-contacts <uuid,uuid,...>] \
 *     [--issued-at <iso8601-utc>]
 *
 * Task: TASK-P1-037 O-2
 * ADR: ADR-HARDENING-001 §6
 */
import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import {
  createPrivateKey,
  createPublicKey,
  hkdfSync,
  randomBytes,
  type KeyObject,
} from 'node:crypto';
import {
  MATRIX_DOMAIN,
  validateSignedMatrix,
  type SignedMatrix,
} from '../src/crypto/matrix-schema.js';
import { jcsCanonicalize } from '../src/crypto/jcs.js';
import { signMatrix } from '../src/crypto/matrix-sign.js';
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
 * Identical to generate-matrix-vectors.ts / sign-test-notice.ts's
 * deriveTestPrivateKey. Duplicated (not extracted) per
 * sign-test-notice.ts's reasoning — derivation stays visible at the
 * point of use; self-check below catches drift. If a third seed script
 * appears, extract to a shared module (§7 three-file threshold).
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
  device: string;
  version: number;
  clearance: string;
  permittedContacts: string[];
  issuedAt: string;
}

function parseArgs(): Args {
  const argv = process.argv.slice(2);
  const get = (flag: string): string | undefined => {
    const i = argv.indexOf(flag);
    return i >= 0 && i + 1 < argv.length ? argv[i + 1] : undefined;
  };
  const device = get('--device');
  if (!device) {
    console.error(
      'Usage: npx tsx --env-file=.env scripts/sign-test-matrix.ts ' +
        '--device <device-uuid> [--version <int>] [--clearance <string>] ' +
        '[--permitted-contacts <uuid,uuid,...>] [--issued-at <iso8601-utc>]',
    );
    process.exit(1);
  }
  const versionRaw = get('--version') ?? '1';
  const version = Number(versionRaw);
  if (!Number.isInteger(version) || version < 1) {
    console.error(`--version: expected positive integer, got ${versionRaw}`);
    process.exit(1);
  }
  const clearance = get('--clearance') ?? 'user';
  const contactsRaw = get('--permitted-contacts');
  const permittedContacts = contactsRaw
    ? contactsRaw.split(',').map((s) => s.trim()).filter((s) => s.length > 0)
    : [];
  const issuedAt = get('--issued-at') ?? new Date().toISOString();
  return { device, version, clearance, permittedContacts, issuedAt };
}

async function run(): Promise<void> {
  const args = parseArgs();

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

  // 2. Look up device row.
  const devRes = await withTransaction(async (tx) =>
    tx.query<{
      device_id: string;
      org_id: string;
      public_key: Buffer;
      messaging_identity_key: Buffer | null;
      public_wipe_confirmation_key: Buffer | null;
    }>(
      `SELECT device_id, org_id, public_key, messaging_identity_key,
              public_wipe_confirmation_key
       FROM devices WHERE device_id = $1`,
      [args.device],
    ),
  );
  const row = devRes.rows[0];
  if (!row) {
    throw new Error(
      `device not found: ${args.device} — enroll via the normal flow first`,
    );
  }
  if (row.public_key.length !== 32) {
    throw new Error(
      `device ${args.device}: public_key expected 32 bytes, got ${row.public_key.length}`,
    );
  }

  // 3. Build the wrapper. pub_messaging_identity_key and
  //    pub_wipe_confirmation_key are synthetic if the DB columns are
  //    null (see file KDoc).
  const messagingKeyB64u =
    row.messaging_identity_key && row.messaging_identity_key.length === 32
      ? row.messaging_identity_key.toString('base64url')
      : randomBytes(32).toString('base64url');
  const wipeKeyB64u =
    row.public_wipe_confirmation_key && row.public_wipe_confirmation_key.length === 32
      ? row.public_wipe_confirmation_key.toString('base64url')
      : randomBytes(32).toString('base64url');

  const wrapper = {
    domain: MATRIX_DOMAIN,
    matrix: {
      version: args.version,
      device_id: args.device,
      pub_device_auth_key: row.public_key.toString('base64url'),
      pub_messaging_identity_key: messagingKeyB64u,
      pub_wipe_confirmation_key: wipeKeyB64u,
      clearance: args.clearance,
      permitted_contacts: args.permittedContacts,
      issued_at: args.issuedAt,
    },
  } as const;

  const signed: SignedMatrix = validateSignedMatrix(wrapper);
  const canonical = jcsCanonicalize(signed);
  const signature = signMatrix(signed, priv);

  // 4. UPSERT. ON CONFLICT DO UPDATE sets updated_at explicitly per
  //    migration 016's invariant (DEFAULT only covers the initial
  //    INSERT).
  const insert = await withTransaction(async (tx) =>
    tx.query<{ created_at: Date; updated_at: Date }>(
      `INSERT INTO matrices
         (device_id, canonical_bytes, signature_base64url, version)
       VALUES ($1, $2, $3, $4)
       ON CONFLICT (device_id) DO UPDATE SET
         canonical_bytes = EXCLUDED.canonical_bytes,
         signature_base64url = EXCLUDED.signature_base64url,
         version = EXCLUDED.version,
         updated_at = now()
       RETURNING created_at, updated_at`,
      [args.device, canonical, signature, args.version],
    ),
  );
  const returned = insert.rows[0]!;

  console.log(`[upserted] device=${args.device}`);
  console.log(`  org_id=${row.org_id}`);
  console.log(`  version=${args.version}`);
  console.log(`  clearance=${args.clearance}`);
  console.log(`  permitted_contacts=[${args.permittedContacts.join(',')}]`);
  console.log(`  issued_at=${args.issuedAt}`);
  console.log(`  created_at=${returned.created_at.toISOString()}`);
  console.log(`  updated_at=${returned.updated_at.toISOString()}`);
  console.log('');
  console.log('Next:');
  console.log('  - Force-stop and reopen the app on the target emulator');
  console.log('    (Authenticated entry triggers MatrixApi.fetch -> accept)');
  console.log('  - Verify via Diagnostics read-back or observe send-gate');
  console.log('    behavior after TASK-P1-038 lands');
}

run().catch((err) => {
  console.error(err instanceof Error ? err.message : String(err));
  process.exit(1);
});
