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
  RATE_LIMIT_AUTH_PER_MIN: z.coerce.number().int().positive().default(30),
  RATE_LIMIT_CHALLENGE_PER_MIN: z.coerce.number().int().positive().default(60),
  AUDIT_HASH_KEY: z
    .string()
    .regex(/^[0-9a-fA-F]{64}$/, 'AUDIT_HASH_KEY must be 32 bytes hex (64 chars)'),
  SERVER_ID: z.string().min(1).default('umoja-backend-1'),
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
  return parsed.data;
}

export const env: Env = loadEnv();
