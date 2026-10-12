import Fastify from 'fastify';
import helmet from '@fastify/helmet';
import cors from '@fastify/cors';
import rateLimit from '@fastify/rate-limit';

import { logger } from './observability/logging.js';
import { healthRoutes } from './routes/health.js';
import { enrollmentRoutes } from './routes/enrollment.js';
import { authRoutes } from './routes/auth.js';
import { meRoutes } from './routes/me.js';

export async function buildApp() {
  const app = Fastify({
    loggerInstance: logger,
    trustProxy: false,
    bodyLimit: 1024 * 1024,
  });

  await app.register(helmet, { contentSecurityPolicy: false });
  await app.register(cors, { origin: false });
  await app.register(rateLimit, {
    max: 100,
    timeWindow: '1 minute',
    keyGenerator: (req) =>
      (req.headers['x-device-id'] as string | undefined) ?? req.ip,
  });

  await app.register(healthRoutes);
  await app.register(enrollmentRoutes);
  await app.register(authRoutes);
  await app.register(meRoutes);

  return app;
}
