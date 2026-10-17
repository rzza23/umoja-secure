import pg from 'pg';
import { env } from '../config/env.js';
import { logger } from '../observability/logging.js';

const { Pool } = pg;
type PoolClient = pg.PoolClient;

// Per-worker pool cap. Vitest defaults to `forks` with
// maxWorkers = CPU cores - 1; on a 12-thread Mac that is 11 workers.
// 20 conns/worker × 11 workers = 220 against Postgres max_connections
// 100 — under full-suite load, pool.connect() hit the 5s timeout and
// returned 500s in auth.test.ts (KI-022). 5 × 11 = 55 is safe.
// Production unchanged.
const poolMax = process.env.NODE_ENV === 'test' ? 5 : 20;
console.error('POOLMAX-DEBUG:', poolMax, 'NODE_ENV:', process.env.NODE_ENV);

export const pool = new Pool({
  connectionString: env.DATABASE_URL,
  max: poolMax,
  idleTimeoutMillis: 30_000,
  connectionTimeoutMillis: 5_000,
});

pool.on('error', (err) => {
  logger.error({ err }, 'unexpected error on idle postgres client');
});

export async function withTransaction<T>(
  fn: (tx: PoolClient) => Promise<T>,
): Promise<T> {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const result = await fn(client);
    await client.query('COMMIT');
    return result;
  } catch (err) {
    try {
      await client.query('ROLLBACK');
    } catch (rollbackErr) {
      logger.error({ err: rollbackErr }, 'rollback failed');
    }
    throw err;
  } finally {
    client.release();
  }
}

export async function shutdownDb(): Promise<void> {
  await pool.end();
}
