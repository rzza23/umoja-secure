import type { FastifyPluginAsync } from 'fastify';
import { pool } from '../db/client.js';
import { requireSession } from '../auth/middleware.js';
import { listContactsForDevice } from '../authorization/contacts.js';

export const meRoutes: FastifyPluginAsync = async (app) => {
  app.get('/me', { preHandler: requireSession() }, async (req, reply) => {
    if (!req.device) {
      return reply.code(401).send({ error: 'unauthorized' });
    }
    const res = await pool.query(
      `SELECT device_id, org_id, label, role, status
       FROM devices WHERE device_id = $1`,
      [req.device.device_id],
    );
    if (res.rowCount !== 1) {
      return reply.code(401).send({ error: 'unauthorized' });
    }
    const r = res.rows[0];
    return {
      device_id: r.device_id,
      org_id: r.org_id,
      label: r.label,
      role: r.role,
    };
  });

  app.get(
    '/me/contacts',
    { preHandler: requireSession() },
    async (req, reply) => {
      if (!req.device) return reply.code(401).send({ error: 'unauthorized' });
      const contacts = await listContactsForDevice(
        req.device.org_id,
        req.device.device_id,
      );
      return reply.send({ contacts });
    },
  );
};
