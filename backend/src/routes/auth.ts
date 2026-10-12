import type { FastifyPluginAsync } from 'fastify';
import { z } from 'zod';
import { AuthError, createChallenge } from '../auth/challenge.js';
import { verifyChallenge } from '../auth/verify.js';
import { createSession, revokeSession } from '../auth/sessions.js';
import { requireSession } from '../auth/middleware.js';

const ChallengeBody = z.object({
  device_id: z.string().uuid(),
  purpose: z.literal('auth').default('auth'),
});

const VerifyBody = z.object({
  challenge_id: z.string().uuid(),
  signature: z.string().min(40).max(200),
});

export const authRoutes: FastifyPluginAsync = async (app) => {
  app.post('/auth/challenge', async (req, reply) => {
    const parse = ChallengeBody.safeParse(req.body);
    if (!parse.success) {
      return reply.code(400).send({ error: 'invalid_request' });
    }
    try {
      const challenge = await createChallenge(
        parse.data.device_id,
        parse.data.purpose,
      );
      return reply.send({ challenge });
    } catch (err) {
      if (err instanceof AuthError) {
        return reply.code(err.statusCode).send({ error: err.code });
      }
      req.log.error({ err }, 'challenge failed');
      return reply.code(500).send({ error: 'internal_error' });
    }
  });

  app.post('/auth/verify', async (req, reply) => {
    const parse = VerifyBody.safeParse(req.body);
    if (!parse.success) {
      return reply.code(400).send({ error: 'invalid_request' });
    }
    try {
      const device = await verifyChallenge(
        parse.data.challenge_id,
        parse.data.signature,
      );
      const { token, session } = await createSession(device);
      return reply.send({
        session_token: token,
        expires_at: session.expires_at.toISOString(),
        device_id: device.device_id,
        role: device.role,
      });
    } catch (err) {
      if (err instanceof AuthError) {
        return reply.code(err.statusCode).send({ error: err.code });
      }
      req.log.error({ err }, 'verify failed');
      return reply.code(500).send({ error: 'internal_error' });
    }
  });

  app.post(
    '/auth/logout',
    { preHandler: requireSession() },
    async (req, reply) => {
      if (!req.device) {
        return reply.code(401).send({ error: 'unauthorized' });
      }
      await revokeSession(req.device.session_id, 'user_logout');
      req.log.info(
        { device_id: req.device.device_id },
        'session revoked',
      );
      return reply.code(204).send();
    },
  );
};
