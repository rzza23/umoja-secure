import type { FastifyPluginAsync } from 'fastify';
import { z } from 'zod';
import { requireSession } from '../auth/middleware.js';
import {
  ContactError,
  authorizeContact,
  revokeContact,
  listAllContacts,
} from '../authorization/contacts.js';
import {
  createEnrollmentToken,
  listEnrollmentTokens,
  revokeEnrollmentToken,
} from '../admin/enrollmentTokens.js';
import {
  listDevices,
  revokeDevice,
  suspendDevice,
  resumeDevice,
  type AdminActor,
} from '../admin/devices.js';
import {
  MatrixVersionError,
  assertMatrixVersion,
  getMatrixVersion,
} from '../admin/matrixVersions.js';

const CreateTokenBody = z.object({
  role: z.enum(['owner', 'admin', 'user', 'auditor']),
  label_hint: z.string().max(64).optional(),
  ttl_seconds: z.number().int().min(60).max(86400).default(86400),
  bound_public_key: z.string().regex(/^[A-Za-z0-9_-]{43}$/),
});

const ReasonBody = z.object({ reason: z.string().min(1).max(256) });
const CreateContactBody = z.object({
  owner_device_id: z.string().uuid(),
  contact_device_id: z.string().uuid(),
  verification_level: z.enum(['directory', 'qr']).default('directory'),
});

const ContactPairParams = z.object({
  owner: z.string().uuid(),
  contact: z.string().uuid(),
});
const IdParams = z.object({ id: z.string().uuid() });

const AssertMatrixVersionBody = z.object({
  version: z.number().int().min(1),
});

export const adminRoutes: FastifyPluginAsync = async (app) => {
  const requireAdmin = requireSession(['owner', 'admin']);
  const requireOwner = requireSession(['owner']);

  function actorOf(req: import('fastify').FastifyRequest): AdminActor {
    if (!req.device) throw new Error('no device attached');
    return {
      device_id: req.device.device_id,
      role: req.device.role,
      org_id: req.device.org_id,
    };
  }

  // ---------- Enrollment tokens ----------

  app.post(
    '/admin/enrollment-tokens',
    { preHandler: requireAdmin },
    async (req, reply) => {
      const parse = CreateTokenBody.safeParse(req.body);
      if (!parse.success) return reply.code(400).send({ error: 'invalid_request' });

      // Only owners can create owner/admin tokens
      if (
        (parse.data.role === 'owner' || parse.data.role === 'admin') &&
        req.device!.role !== 'owner'
      ) {
        return reply.code(403).send({ error: 'forbidden' });
      }

      const actor = actorOf(req);
      const result = await createEnrollmentToken({
        actor_device_id: actor.device_id,
        actor_role: actor.role,
        org_id: actor.org_id,
        role: parse.data.role,
        label_hint: parse.data.label_hint,
        ttl_seconds: parse.data.ttl_seconds,
        bound_public_key: parse.data.bound_public_key,
      });
      return reply.code(201).send(result);
    },
  );

  app.get(
    '/admin/enrollment-tokens',
    { preHandler: requireAdmin },
    async (req, reply) => {
      const actor = actorOf(req);
      const tokens = await listEnrollmentTokens(actor.org_id);
      return reply.send({ tokens });
    },
  );

  app.post(
    '/admin/enrollment-tokens/:id/revoke',
    { preHandler: requireAdmin },
    async (req, reply) => {
      const params = IdParams.safeParse(req.params);
      if (!params.success) return reply.code(400).send({ error: 'invalid_request' });
      try {
        await revokeEnrollmentToken(params.data.id, actorOf(req));
        return reply.code(204).send();
      } catch (err) {
        const e = err as { statusCode?: number };
        if (e.statusCode === 404) return reply.code(404).send({ error: 'not_found' });
        throw err;
      }
    },
  );

  // ---------- Matrix version ----------

  app.get(
    '/admin/matrix-version',
    { preHandler: requireAdmin },
    async (req, reply) => {
      const actor = actorOf(req);
      const state = await getMatrixVersion(actor.org_id);
      return reply.send(state);
    },
  );

  app.post(
    '/admin/matrix-version',
    { preHandler: requireAdmin },
    async (req, reply) => {
      const parse = AssertMatrixVersionBody.safeParse(req.body);
      if (!parse.success) {
        return reply.code(400).send({ error: 'invalid_request' });
      }
      try {
        const result = await assertMatrixVersion({
          actor_device_id: req.device!.device_id,
          actor_role: req.device!.role,
          org_id: req.device!.org_id,
          version: parse.data.version,
        });
        return reply.code(200).send(result);
      } catch (err) {
        if (err instanceof MatrixVersionError) {
          return reply.code(err.statusCode).send({ error: err.code });
        }
        throw err;
      }
    },
  );

  // ---------- Devices ----------

  app.get('/admin/devices', { preHandler: requireAdmin }, async (req, reply) => {
    const actor = actorOf(req);
    const devices = await listDevices(actor.org_id);
    return reply.send({ devices });
  });

  app.post(
    '/admin/devices/:id/revoke',
    { preHandler: requireAdmin },
    async (req, reply) => {
      const params = IdParams.safeParse(req.params);
      const body = ReasonBody.safeParse(req.body);
      if (!params.success || !body.success) {
        return reply.code(400).send({ error: 'invalid_request' });
      }
      try {
        await revokeDevice(params.data.id, body.data.reason, actorOf(req));
        return reply.code(204).send();
      } catch (err) {
        const e = err as { statusCode?: number };
        if (e.statusCode === 404) return reply.code(404).send({ error: 'not_found' });
        if (e.statusCode === 400) return reply.code(400).send({ error: 'cannot_revoke_self' });
        throw err;
      }
    },
  );

  app.post(
    '/admin/devices/:id/suspend',
    { preHandler: requireAdmin },
    async (req, reply) => {
      const params = IdParams.safeParse(req.params);
      const body = ReasonBody.safeParse(req.body);
      if (!params.success || !body.success) {
        return reply.code(400).send({ error: 'invalid_request' });
      }
      try {
        await suspendDevice(params.data.id, body.data.reason, actorOf(req));
        return reply.code(204).send();
      } catch (err) {
        const e = err as { statusCode?: number };
        if (e.statusCode === 404) return reply.code(404).send({ error: 'not_found' });
        if (e.statusCode === 409) return reply.code(409).send({ error: 'invalid_state' });
        throw err;
      }
    },
  );

  app.post(
    '/admin/devices/:id/resume',
    { preHandler: requireAdmin },
    async (req, reply) => {
      const params = IdParams.safeParse(req.params);
      if (!params.success) return reply.code(400).send({ error: 'invalid_request' });
      try {
        await resumeDevice(params.data.id, actorOf(req));
        return reply.code(204).send();
      } catch (err) {
        const e = err as { statusCode?: number };
        if (e.statusCode === 404) return reply.code(404).send({ error: 'not_found' });
        if (e.statusCode === 409) return reply.code(409).send({ error: 'invalid_state' });
        throw err;
      }
    },
  );

  // ---------- Contacts ----------

  app.get('/admin/contacts', { preHandler: requireAdmin }, async (req, reply) => {
    const actor = actorOf(req);
    const contacts = await listAllContacts(actor.org_id);
    return reply.send({ contacts });
  });

  app.post('/admin/contacts', { preHandler: requireAdmin }, async (req, reply) => {
    const parse = CreateContactBody.safeParse(req.body);
    if (!parse.success) return reply.code(400).send({ error: 'invalid_request' });
    try {
      await authorizeContact(
        actorOf(req),
        parse.data.owner_device_id,
        parse.data.contact_device_id,
        parse.data.verification_level,
      );
      return reply.code(204).send();
    } catch (err) {
      if (err instanceof ContactError) {
        return reply.code(err.statusCode).send({ error: err.code });
      }
      throw err;
    }
  });

  app.post(
    '/admin/contacts/:owner/:contact/revoke',
    { preHandler: requireAdmin },
    async (req, reply) => {
      const params = ContactPairParams.safeParse(req.params);
      const body = ReasonBody.safeParse(req.body);
      if (!params.success || !body.success) {
        return reply.code(400).send({ error: 'invalid_request' });
      }
      try {
        await revokeContact(
          actorOf(req),
          params.data.owner,
          params.data.contact,
          body.data.reason,
        );
        return reply.code(204).send();
      } catch (err) {
        if (err instanceof ContactError) {
          return reply.code(err.statusCode).send({ error: err.code });
        }
        throw err;
      }
    },
  );

  // ---------- Audit ----------

  app.get(
    '/admin/audit/verify',
    { preHandler: requireOwner },
    async (_req, reply) => {
      const { verifyAuditChain } = await import('../audit/verify.js');
      const result = await verifyAuditChain();
      return reply.send(result);
    },
  );
};
