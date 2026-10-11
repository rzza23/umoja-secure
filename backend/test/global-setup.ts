import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import pg from 'pg';

const TEST_DB_NAME = 'umoja_test';
const ADMIN_URL = 'postgres://umoja:umoja@localhost:5432/umoja';
const TEST_URL = `postgres://umoja:umoja@localhost:5432/${TEST_DB_NAME}`;

export default async function setup() {
  const { Pool } = pg;

  // 1. Ensure the test database exists
  const adminPool = new Pool({ connectionString: ADMIN_URL });
  const exists = await adminPool.query(
    'SELECT 1 FROM pg_database WHERE datname = $1',
    [TEST_DB_NAME],
  );
  if (exists.rowCount === 0) {
    await adminPool.query(`CREATE DATABASE ${TEST_DB_NAME}`);
  }
  await adminPool.end();

  // 2. Reset schema in test DB
  const pool = new Pool({ connectionString: TEST_URL });
  await pool.query('DROP SCHEMA public CASCADE');
  await pool.query('CREATE SCHEMA public');

  // 3. Apply migrations in order
  await pool.query(`
    CREATE TABLE IF NOT EXISTS schema_migrations (
      version TEXT PRIMARY KEY,
      applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
    )
  `);

  const migrationsDir = join(process.cwd(), 'migrations');
  const files = readdirSync(migrationsDir)
    .filter((f) => f.endsWith('.sql'))
    .sort();

  for (const file of files) {
    const version = file.replace(/\.sql$/, '');
    const sql = readFileSync(join(migrationsDir, file), 'utf8');
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      await client.query(sql);
      await client.query(
        'INSERT INTO schema_migrations (version) VALUES ($1)',
        [version],
      );
      await client.query('COMMIT');
    } catch (err) {
      await client.query('ROLLBACK');
      throw err;
    } finally {
      client.release();
    }
  }

  await pool.end();
}
