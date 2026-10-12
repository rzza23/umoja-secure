import { pino } from 'pino';
import { env } from '../config/env.js';

const isDevelopment = env.NODE_ENV === 'development';

/**
 * Paths redacted from all log output. Both top-level and nested variants
 * are listed because pino's `*` wildcard only matches nested keys.
 */
export const REDACT_PATHS: readonly string[] = [
  // Request/response headers and bodies (nested)
  'req.headers.authorization',
  'req.headers.cookie',
  'req.body.token',
  'req.body.signature',
  'req.body.session_token',
  'req.body.ciphertext',
  'req.body.ack_token',
  'req.body.attestation',
  'res.body.token',
  'res.body.session_token',
  'res.body.ciphertext',
  // Top-level sensitive keys
  'private_key',
  'privateKey',
  'password',
  'secret',
  // Nested sensitive keys
  '*.private_key',
  '*.privateKey',
  '*.password',
  '*.secret',
];

export const REDACT_CENSOR = '[REDACTED]';

export const logger = pino({
  level: env.LOG_LEVEL,
  redact: { paths: [...REDACT_PATHS], censor: REDACT_CENSOR },
  transport: isDevelopment
    ? {
        target: 'pino-pretty',
        options: {
          colorize: true,
          translateTime: 'SYS:standard',
          ignore: 'pid,hostname',
        },
      }
    : undefined,
});

export type Logger = typeof logger;
