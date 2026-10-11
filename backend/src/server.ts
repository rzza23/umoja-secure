import Fastify from 'fastify';
import helmet from '@fastify/helmet';
import cors from '@fastify/cors';
import rateLimit from '@fastify/rate-limit';

import { env } from './config/env.js';
import { logger } from './observability/logging.js';
import { pool, shutdownDb } from './db/client.js';
import { healthRoutes } from './routes/health.js';

async function buildApp() {
  const app = Fastify({
    loggerInstance: logger,
    trustProxy: false,
    bodyLimit: 1024 * 1024,
    disableRequestLogging: false,
  });

  await app.register(helmet, {
    contentSecurityPolicy: false,
  });

  await app.register(cors, {
    origin: false,
  });

  await app.register(rateLimit, {
    max: 100,
    timeWindow: '1 minute',
    keyGenerator: (req) =>
      (req.headers['x-device-id'] as string | undefined) ?? req.ip,
  });

  await app.register(healthRoutes);

  return app;
}

async function start() {
  let app: Awaited<ReturnType<typeof buildApp>> | undefined;
  try {
    await pool.query('SELECT 1');
    app = await buildApp();
    await app.listen({ port: env.PORT, host: env.HOST });
    logger.info({ port: env.PORT, host: env.HOST }, 'backend listening');
  } catch (err) {
    logger.error({ err }, 'startup failed');
    process.exit(1);
  }

  const shutdown = async (signal: string) => {
    logger.info({ signal }, 'shutting down');
    try {
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
