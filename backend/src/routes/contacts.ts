import type { FastifyPluginAsync } from 'fastify';
import { requireSession } from '../auth/middleware.js';
import { listContactsForDevice } from '../authorization/contacts.js';

/**
 * User-facing contacts.
 *
 * Returns the active authorized contacts for the authenticated device.
 * Used by the client to populate the Contacts screen and to validate that
 * a peer is reachable before offering to send.
 */
export const contactsRoutes: FastifyPluginAsync = async (app) => {
  app.get('/contacts', { preHandler: requireSession() }, async (req, reply) => {
    if (!req.device) return reply.code(401).send({ error: 'unauthorized' });
    const contacts = await listContactsForDevice(req.device.device_id);
    return reply.send({
      contacts: contacts.map((c) => ({
        device_id: c.contact_device_id,
        label: c.contact_label,
        verification_level: c.verification_level,
        authorized_at: c.authorized_at,
      })),
    });
  });
};
