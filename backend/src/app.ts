import Fastify from 'fastify';
import helmet from '@fastify/helmet';
import cors from '@fastify/cors';
import rateLimit from '@fastify/rate-limit';

import { logger } from './observability/logging.js';
import { healthRoutes } from './routes/health.js';
import { enrollmentRoutes } from './routes/enrollment.js';
import { authRoutes } from './routes/auth.js';
import { meRoutes } from './routes/me.js';
import { prekeyRoutes } from './routes/prekeys.js';
import { envelopeRoutes } from './routes/envelopes.js';
import { adminRoutes } from './routes/admin.js';
import { contactsRoutes } from './routes/contacts.js';
import { wsRoutes } from './ws/server.js';

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
  await app.register(prekeyRoutes);
  await app.register(envelopeRoutes);
  await app.register(adminRoutes);
  await app.register(contactsRoutes);
  await app.register(wsRoutes);

  return app;
}
