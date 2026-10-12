import type { FastifyPluginAsync } from 'fastify';
import { z } from 'zod';
import { requireSession } from '../auth/middleware.js';
import { EnvelopeError, submitEnvelope } from '../envelopes/submit.js';
import { listPendingEnvelopes } from '../envelopes/list.js';
import { fetchEnvelope } from '../envelopes/fetch.js';
import { AckError, acknowledgeEnvelope } from '../envelopes/ack.js';

const SubmitBody = z.object({
  recipient_device_id: z.string().uuid(),
  ciphertext: z.string().min(1).max(2_000_000),
  envelope_type: z.enum(['message', 'call_signal', 'ack']).default('message'),
  ttl_seconds: z.number().int().positive().max(365 * 24 * 3600).optional(),
});

export const envelopeRoutes: FastifyPluginAsync = async (app) => {
  app.post('/envelopes', { preHandler: requireSession() }, async (req, reply) => {
    if (!req.device) return reply.code(401).send({ error: 'unauthorized' });
    const parse = SubmitBody.safeParse(req.body);
    if (!parse.success) return reply.code(400).send({ error: 'invalid_request' });

    try {
      const result = await submitEnvelope({
        sender_device_id: req.device.device_id,
        ...parse.data,
      });
      req.log.info(
        {
          envelope_id: result.envelope_id,
          recipient_device_id: parse.data.recipient_device_id,
        },
        'envelope queued',
      );
      return reply.code(201).send(result);
    } catch (err) {
      if (err instanceof EnvelopeError) {
        return reply.code(err.statusCode).send({ error: err.code });
      }
      req.log.error({ err }, 'envelope submit failed');
      return reply.code(500).send({ error: 'internal_error' });
    }
  });

  app.get(
    '/envelopes/pending',
    { preHandler: requireSession() },
    async (req, reply) => {
      if (!req.device) return reply.code(401).send({ error: 'unauthorized' });
      const list = await listPendingEnvelopes(req.device.device_id);
      return reply.send({ envelopes: list });
    },
  );

  app.get(
    '/envelopes/:id',
    { preHandler: requireSession() },
    async (req, reply) => {
      if (!req.device) return reply.code(401).send({ error: 'unauthorized' });
      const params = z.object({ id: z.string().uuid() }).safeParse(req.params);
      if (!params.success) return reply.code(400).send({ error: 'invalid_request' });

      const envelope = await fetchEnvelope(params.data.id, req.device.device_id);
      if (!envelope) return reply.code(404).send({ error: 'not_found' });
      return reply.send(envelope);
    },
  );

  app.post(
    '/envelopes/:id/ack',
    { preHandler: requireSession() },
    async (req, reply) => {
      if (!req.device) return reply.code(401).send({ error: 'unauthorized' });
      const params = z.object({ id: z.string().uuid() }).safeParse(req.params);
      if (!params.success) return reply.code(400).send({ error: 'invalid_request' });

      try {
        await acknowledgeEnvelope(params.data.id, req.device.device_id);
        return reply.code(204).send();
      } catch (err) {
        if (err instanceof AckError) {
          return reply.code(err.statusCode).send({ error: err.code });
        }
        req.log.error({ err }, 'ack failed');
        return reply.code(500).send({ error: 'internal_error' });
      }
    },
  );
};
