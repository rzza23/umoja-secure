import { env } from './config/env.js';
import { logger } from './observability/logging.js';
import { pool, shutdownDb } from './db/client.js';
import { buildApp } from './app.js';
import { startRevocationListener, stopRevocationListener } from './ws/revocation.js';
import { registry } from './ws/registry.js';

async function start() {
  let app: Awaited<ReturnType<typeof buildApp>> | undefined;
  try {
    await pool.query('SELECT 1');
    app = await buildApp();
    await app.listen({ port: env.PORT, host: env.HOST });
    await startRevocationListener();
    logger.info({ port: env.PORT, host: env.HOST }, 'backend listening');
  } catch (err) {
    logger.error({ err }, 'startup failed');
    process.exit(1);
  }

  const shutdown = async (signal: string) => {
    logger.info({ signal }, 'shutting down');
    try {
      registry.clear();
      await stopRevocationListener();
      if (app) await app.close();
      await shutdownDb();
    } catch (err) {
      logger.error({ err }, 'error during shutdown');
    } finally {
      process.exit(0);
    }
  };

  process.on('SIGTERM', () => void shutdown('SIGTERM'));
  process.on('SIGINT', () => void shutdown('SIGINT'));
}

void start();
