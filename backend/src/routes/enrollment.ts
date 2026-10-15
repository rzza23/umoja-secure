import type { FastifyPluginAsync } from 'fastify';
import { z } from 'zod';
import { EnrollmentError, consumeEnrollmentToken } from '../enrollment/consume.js';

const EnrollmentBody = z.object({
  token: z.string().min(16).max(128),
  device_public_key: z.string().regex(/^[A-Za-z0-9_-]{43}$/),
  label: z.string().min(1).max(64),
  attestation: z.string().max(8192).optional(),
});

export const enrollmentRoutes: FastifyPluginAsync = async (app) => {
  app.post('/enrollment', async (req, reply) => {
    const parse = EnrollmentBody.safeParse(req.body);
    if (!parse.success) {
      return reply.code(400).send({ error: 'invalid_request' });
    }

    try {
      const result = await consumeEnrollmentToken(parse.data);
      req.log.info({ device_id: result.device_id }, 'device enrolled');
      return reply.code(201).send(result);
    } catch (err) {
      if (err instanceof EnrollmentError) {
        req.log.warn(
          { error: err.code, device_public_key: parse.data.device_public_key, label: parse.data.label },
          'enrollment rejected',
        );
        return reply.code(err.statusCode).send({ error: err.code });
      }
      req.log.error({ err }, 'enrollment failed');
      return reply.code(500).send({ error: 'internal_error' });
    }
  });
};
