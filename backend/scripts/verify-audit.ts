import { pool } from '../src/db/client.js';
import { logger } from '../src/observability/logging.js';
import { verifyAuditChain } from '../src/audit/verify.js';

async function main() {
  try {
    const result = await verifyAuditChain();
    if (!result.intact) {
      logger.error(
        { broken_at: result.broken_at, total_events: result.total_events },
        'audit chain is BROKEN',
      );
      process.exit(2);
    }
    logger.info(
      { total_events: result.total_events },
      'audit chain intact',
    );
    process.exit(0);
  } finally {
    await pool.end();
  }
}

main().catch((err) => {
  logger.error({ err }, 'verify-audit failed');
  process.exit(1);
});
