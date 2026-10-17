import type { FastifyPluginAsync } from 'fastify';
import { z } from 'zod';
import { requireSession } from '../auth/middleware.js';
import {
  IdentityChangeNoticeError,
  createIdentityChangeNotice,
  listIdentityChangeNotices,
} from '../identityChange/notices.js';
import {
  AckRouteError,
  createIdentityChangeAck,
  listAcksByNotice,
} from '../identityChange/acks.js';

const SignedArtifactBody = z.object({
  canonical_utf8: z.string().min(1).max(8192),
  signature_base64url: z.string().regex(/^[A-Za-z0-9_-]{86}$/),
});

const NoticeHashParams = z.object({
  notice_hash: z.string().regex(/^[A-Za-z0-9_-]{43}$/),
});

const ANY_ROLE = ['owner', 'admin', 'user', 'auditor'] as const;

export const identityChangeRoutes: FastifyPluginAsync = async (app) => {
  const requireAdmin = requireSession(['owner', 'admin']);
  const requireAnyRole = requireSession([...ANY_ROLE]);

  app.post(
    '/identity-change-notices',
    { preHandler: requireAdmin },
    async (req, reply) => {
      const parse = SignedArtifactBody.safeParse(req.body);
      if (!parse.success) {
        return reply.code(400).send({ error: 'invalid_request' });
      }
      try {
        const result = await createIdentityChangeNotice({
          org_id: req.device!.org_id,
          canonical_utf8: parse.data.canonical_utf8,
          signature_base64url: parse.data.signature_base64url,
        });
        return reply.code(201).send(result);
      } catch (err) {
        if (err instanceof IdentityChangeNoticeError) {
          return reply.code(err.statusCode).send({ error: err.code });
        }
        req.log.error({ err }, 'identity-change-notice create failed');
        return reply.code(500).send({ error: 'internal_error' });
      }
    },
  );

  app.get(
    '/identity-change-notices',
    { preHandler: requireAnyRole },
    async (req, reply) => {
      try {
        const result = await listIdentityChangeNotices(req.device!.org_id);
        return reply.send(result);
      } catch (err) {
        req.log.error({ err }, 'identity-change-notice list failed');
        return reply.code(500).send({ error: 'internal_error' });
      }
    },
  );

  app.post(
    '/identity-change-acks',
    { preHandler: requireAnyRole },
    async (req, reply) => {
      const parse = SignedArtifactBody.safeParse(req.body);
      if (!parse.success) {
        return reply.code(400).send({ error: 'invalid_request' });
      }
      try {
        const result = await createIdentityChangeAck({
          actor_device_id: req.device!.device_id,
          actor_org_id: req.device!.org_id,
          canonical_utf8: parse.data.canonical_utf8,
          signature_base64url: parse.data.signature_base64url,
        });
        return reply.code(201).send(result);
      } catch (err) {
        if (err instanceof AckRouteError) {
          return reply.code(err.statusCode).send({ error: err.code });
        }
        req.log.error({ err }, 'identity-change-ack create failed');
        return reply.code(500).send({ error: 'internal_error' });
      }
    },
  );

  app.get(
    '/identity-change-acks/:notice_hash',
    { preHandler: requireAnyRole },
    async (req, reply) => {
      const parse = NoticeHashParams.safeParse(req.params);
      if (!parse.success) {
        return reply.code(400).send({ error: 'invalid_request' });
      }
      try {
        const result = await listAcksByNotice(
          parse.data.notice_hash,
          req.device!.org_id,
        );
        return reply.send(result);
      } catch (err) {
        if (err instanceof AckRouteError) {
          return reply.code(err.statusCode).send({ error: err.code });
        }
        req.log.error({ err }, 'identity-change-ack list failed');
        return reply.code(500).send({ error: 'internal_error' });
      }
    },
  );
};