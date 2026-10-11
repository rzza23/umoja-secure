import type { FastifyPluginAsync } from 'fastify';
import { pool } from '../db/client.js';

export const healthRoutes: FastifyPluginAsync = async (app) => {
  app.get('/health', async () => ({
    status: 'ok',
    version: process.env['npm_package_version'] ?? '0.1.0',
    uptime: process.uptime(),
  }));

  app.get('/ready', async (_req, reply) => {
    try {
      await pool.query('SELECT 1');
      return { status: 'ready' };
    } catch {
      return reply.code(503).send({ status: 'not_ready' });
    }
  });
};
