import { z } from 'zod';

const EnvSchema = z.object({
  NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
  PORT: z.coerce.number().int().positive().default(8080),
  HOST: z.string().default('0.0.0.0'),
  LOG_LEVEL: z
    .enum(['fatal', 'error', 'warn', 'info', 'debug', 'trace'])
    .default('info'),
  DATABASE_URL: z.string().min(1),
  SESSION_TTL_SECONDS: z.coerce.number().int().positive().default(43200),
  CHALLENGE_TTL_SECONDS: z.coerce.number().int().positive().default(60),
  WS_REVALIDATE_SECONDS: z.coerce.number().int().positive().default(300),
  WS_HEARTBEAT_SECONDS: z.coerce.number().int().positive().default(30),
  WS_AUTH_TIMEOUT_SECONDS: z.coerce.number().int().positive().default(10),
  RATE_LIMIT_AUTH_PER_MIN: z.coerce.number().int().positive().default(30),
  RATE_LIMIT_CHALLENGE_PER_MIN: z.coerce.number().int().positive().default(60),
  AUDIT_HASH_KEY: z
    .string()
    .regex(/^[0-9a-fA-F]{64}$/, 'AUDIT_HASH_KEY must be 32 bytes hex (64 chars)'),
  SERVER_ID: z.string().min(1).default('umoja-backend-1'),
  // P1-033a. The provisioning public key used to verify
  // POST /admin/matrices/:device_id bodies. Optional at schema
  // level; loadEnv enforces test-vs-production rules below.
  PROVISIONING_PUBKEY_B64U: z
    .string()
    .regex(
      /^[A-Za-z0-9_-]{43}$/,
      'PROVISIONING_PUBKEY_B64U must be 43-char base64url (32 raw bytes)',
    )
    .optional(),
});

export type Env = z.infer<typeof EnvSchema>;

function loadEnv(): Env {
  const parsed = EnvSchema.safeParse(process.env);
  if (!parsed.success) {
    // eslint-disable-next-line no-console
    console.error('Invalid environment configuration:');
    // eslint-disable-next-line no-console
    console.error(parsed.error.flatten().fieldErrors);
    process.exit(1);
  }
  // P1-033a. Test-vs-production gate, parallel to the client-side
  // check at ProvisioningKeys.kt + UmojaApplication.kt (TASK-P1-029b).
  // The backend MUST NOT verify matrices against the test key in
  // production, and MUST NOT start with the 43-underscore placeholder.
  // Reasoning: docs/ops/KEY-CUSTODY.md section 5.1.
  const TEST_KEY = 'hL_X45qk5WrA9rSxtrQJyRzkDGT0eysDBtuWQosC30M';
  const PLACEHOLDER = '___________________________________________';
  let pubkey = parsed.data.PROVISIONING_PUBKEY_B64U;
  if (!pubkey) {
    if (parsed.data.NODE_ENV === 'test') {
      pubkey = TEST_KEY;
    } else {
      // eslint-disable-next-line no-console
      console.error(
        'PROVISIONING_PUBKEY_B64U is required in non-test environments. ' +
          'See docs/ops/KEY-CUSTODY.md section 5.1.',
      );
      process.exit(1);
    }
  }
  if (parsed.data.NODE_ENV === 'production' && pubkey === TEST_KEY) {
    // eslint-disable-next-line no-console
    console.error(
      'PROVISIONING_PUBKEY_B64U cannot be the test key in production ' +
        '(docs/ops/KEY-CUSTODY.md section 5.1).',
    );
    process.exit(1);
  }
  if (parsed.data.NODE_ENV === 'production' && pubkey === PLACEHOLDER) {
    // eslint-disable-next-line no-console
    console.error(
      'PROVISIONING_PUBKEY_B64U is still the ceremony placeholder ' +
        '(docs/ops/KEY-CUSTODY.md section 5.1). Replace it before ' +
        'running the production backend.',
    );
    process.exit(1);
  }
  return { ...parsed.data, PROVISIONING_PUBKEY_B64U: pubkey };
}

export const env: Env = loadEnv();
