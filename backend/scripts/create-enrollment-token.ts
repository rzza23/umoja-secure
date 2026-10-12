import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { pool } from '../src/db/client.js';
import { logger } from '../src/observability/logging.js';

interface Args {
  orgId: string;
  role: string;
  ttlHours: number;
  labelHint?: string;
}

function parseArgs(): Args {
  const args = process.argv.slice(2);
  const get = (name: string): string | undefined => {
    const idx = args.indexOf(`--${name}`);
    return idx >= 0 ? args[idx + 1] : undefined;
  };

  const orgId = get('org-id');
  if (!orgId) {
    console.error(
      'Usage: npx tsx --env-file=.env scripts/create-enrollment-token.ts ' +
        '--org-id <uuid> [--role user] [--ttl-hours 24] [--label-hint "Alice Pixel"]',
    );
    process.exit(1);
  }

  return {
    orgId,
    role: get('role') ?? 'user',
    ttlHours: Number(get('ttl-hours') ?? '24'),
    labelHint: get('label-hint'),
  };
}

async function main() {
  const { orgId, role, ttlHours, labelHint } = parseArgs();

  const token = randomBytes(32).toString('base64url');
  const tokenHash = createHash('sha256').update(token, 'utf8').digest();
  const expiresAt = new Date(Date.now() + ttlHours * 3600_000);

  await pool.query(
    `INSERT INTO enrollment_tokens
       (token_hash, org_id, role, label_hint, expires_at, created_by)
     VALUES ($1, $2, $3, $4, $5, $6)`,
    [tokenHash, orgId, role, labelHint ?? null, expiresAt, randomUUID()],
  );

  logger.info({ orgId, role, expiresAt }, 'enrollment token created');

  console.log('');
  console.log('Token (shown once -- save it now):');
  console.log(token);
  console.log('');
}

main()
  .catch((err) => {
    logger.error({ err }, 'failed');
    process.exit(1);
  })
  .finally(() => void pool.end());
