import { pool } from '../src/db/client.js';
import { logger } from '../src/observability/logging.js';
import { runMigrations } from '../src/db/migrator.js';

async function main() {
  try {
    const count = await runMigrations(pool, (msg, meta) => logger.info(meta ?? {}, msg));
    if (count === 0) {
      logger.info('no migrations to apply');
    } else {
      logger.info({ count }, 'migrations complete');
    }
  } finally {
    await pool.end();
  }
}

main().catch((err) => {
  logger.error({ err }, 'migrate failed');
  process.exit(1);
});
