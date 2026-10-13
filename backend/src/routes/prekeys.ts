import type { FastifyPluginAsync } from 'fastify';
import { z } from 'zod';
import { requireSession } from '../auth/middleware.js';
import { uploadPreKeys } from '../prekeys/upload.js';
import { fetchPreKeyBundle } from '../prekeys/fetch.js';
import { getPreKeyStatus } from '../prekeys/status.js';

const PreKeyUploadBody = z.object({
  identity_key: z.string().regex(/^[A-Za-z0-9_-]{43}$/),
  signed_prekey_id: z.number().int().positive(),
  signed_prekey_public: z.string().regex(/^[A-Za-z0-9_-]{43}$/),
  signed_prekey_signature: z.string().regex(/^[A-Za-z0-9_-]{86}$/),
  registration_id: z.number().int().positive(),
  kyber_prekey_id: z.number().int().positive(),
  // Kyber-1024 public key: 1568 raw bytes -> 2091 base64url chars.
  // Accept a generous range to handle version differences.
  kyber_prekey_public: z.string().min(1000).max(3000),
  kyber_prekey_signature: z.string().regex(/^[A-Za-z0-9_-]{86}$/),
  one_time_prekeys: z
    .array(
      z.object({
        id: z.number().int().positive(),
        public_key: z.string().regex(/^[A-Za-z0-9_-]{43}$/),
      }),
    )
    .max(500),
  one_time_kyber_prekeys: z
    .array(
      z.object({
        id: z.number().int().positive(),
        public_key: z.string().min(1000).max(3000),
      }),
    )
    .max(500)
    .default([]),
});

export const prekeyRoutes: FastifyPluginAsync = async (app) => {
  app.post('/prekeys', { preHandler: requireSession() }, async (req, reply) => {
    if (!req.device) return reply.code(401).send({ error: 'unauthorized' });
    const parse = PreKeyUploadBody.safeParse(req.body);
    if (!parse.success) return reply.code(400).send({ error: 'invalid_request' });

    try {
      const result = await uploadPreKeys({
        device_id: req.device.device_id,
        ...parse.data,
      });
      req.log.info(
        { device_id: req.device.device_id, ...result },
        'prekeys uploaded',
      );
      return reply.code(200).send(result);
    } catch (err) {
      const e = err as { statusCode?: number; message?: string };
      if (e.statusCode === 401) return reply.code(401).send({ error: 'unauthorized' });
      if (e.statusCode === 400) return reply.code(400).send({ error: 'invalid_request' });
      req.log.error({ err }, 'prekey upload failed');
      return reply.code(500).send({ error: 'internal_error' });
    }
  });

  app.get(
    '/prekeys/status',
    { preHandler: requireSession() },
    async (req, reply) => {
      if (!req.device) return reply.code(401).send({ error: 'unauthorized' });
      const status = await getPreKeyStatus(req.device.device_id);
      return reply.send(status);
    },
  );

  app.get(
    '/prekeys/:device_id',
    { preHandler: requireSession() },
    async (req, reply) => {
      if (!req.device) return reply.code(401).send({ error: 'unauthorized' });
      const params = z.object({ device_id: z.string().uuid() }).safeParse(req.params);
      if (!params.success) return reply.code(400).send({ error: 'invalid_request' });

      const bundle = await fetchPreKeyBundle(
        req.device.device_id,
        params.data.device_id,
      );
      if (!bundle) return reply.code(404).send({ error: 'not_found' });
      return reply.send(bundle);
    },
  );
};
