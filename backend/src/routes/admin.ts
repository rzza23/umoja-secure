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

import { pool } from '../db/client.js';
import { env } from '../config/env.js';
import { jcsCanonicalize } from '../crypto/jcs.js';
import { validateSignedMatrix, type SignedMatrix } from '../crypto/matrix-schema.js';
import { verifyMatrix } from '../crypto/matrix-sign.js';

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

  // ---------- Matrices ----------

  /**
   * POST /admin/matrices/:device_id -- admin pushes a signed
   * authorization matrix for a target device.
   *
   * Build Master §3.6 step 8: "**Admin app** attaches the
   * signature and pushes the signed matrix." Admin-scoped: the
   * admin's session authenticates; the URL names the target device
   * being provisioned.
   *
   * **Verify-on-write.** The backend verifies the provisioning
   * signature server-side against `PROVISIONING_PUBKEY_B64U`
   * (docs/ops/KEY-CUSTODY.md §5.1). The corresponding
   * `GET /me/matrix` relays (its KDoc names the asymmetry). Per
   * ADR-IDENTITY-CHANGE-001 §4's ruling ("verify when you can,
   * relay when you can't"), the backend has the key here, so it
   * verifies.
   *
   * **Invariant enforcement** (migration 016's pre-announced
   * missing invariant):
   *   - `parse(canonical).matrix.device_id === urlParam`
   *   - `version` stored = `parse(canonical).matrix.version`
   *   - non-monotonic push rejected 409
   *
   * **Rotation seam.** Single key today
   * (`env.PROVISIONING_PUBKEY_B64U`). P1-036 extends to a
   * `{previous, current}` set during overlap; this route must
   * accept either key when that lands.
   *
   * Task: TASK-P1-033a
   * Build Master: §3.6 step 8
   * ADR: ADR-PROVISIONING-001 §3, ADR-IDENTITY-CHANGE-001 §4
   */
  app.post(
    '/admin/matrices/:device_id',
    { preHandler: requireAdmin },
    async (req, reply) => {
      const params = z
        .object({ device_id: z.string().uuid() })
        .safeParse(req.params);
      if (!params.success) {
        return reply.code(400).send({ error: 'invalid_request' });
      }
      const body = z
        .object({
          canonical_utf8: z.string().min(1).max(65536),
          signature_base64url: z.string().regex(/^[A-Za-z0-9_-]{86}$/),
        })
        .safeParse(req.body);
      if (!body.success) {
        return reply.code(400).send({ error: 'invalid_request' });
      }

      // Parse + validate the canonical matrix. validateSignedMatrix
      // throws MatrixSchemaError on any schema violation; we treat
      // that as 400 invalid_matrix.
      let parsed: SignedMatrix;
      try {
        parsed = validateSignedMatrix(JSON.parse(body.data.canonical_utf8));
      } catch {
        return reply.code(400).send({ error: 'invalid_matrix' });
      }

      // Verify the provisioning signature. verifyMatrix re-canonicalizes
      // per §3.8, so a client sending non-canonical bytes that parse
      // to the same matrix will fail here -- correct behavior, the
      // ceremony requires JCS.
      const pubkeyB64u = env.PROVISIONING_PUBKEY_B64U;
      if (!pubkeyB64u) {
        // loadEnv guarantees this (test default or provided); reachable
        // only if env.ts invariants change.
        throw new Error('PROVISIONING_PUBKEY_B64U not loaded');
      }
      const ok = verifyMatrix(
        parsed,
        body.data.signature_base64url,
        Buffer.from(pubkeyB64u, 'base64url'),
      );
      if (!ok) {
        return reply.code(400).send({ error: 'invalid_signature' });
      }

      // Device-id invariant: the matrix's device_id must equal the
      // URL param. Migration 016's KDoc pre-announced this as the
      // write-path check that was missing.
      if (parsed.matrix.device_id !== params.data.device_id) {
        return reply.code(400).send({ error: 'device_id_mismatch' });
      }

      // Confirm the target device exists in the admin's org
      // (defense-in-depth; the FK would fail at INSERT otherwise,
      // but 404 is a better signal than an FK 500).
      const target = await pool.query<{ device_id: string }>(
        `SELECT device_id FROM devices WHERE device_id = $1 AND org_id = $2`,
        [params.data.device_id, req.device!.org_id],
      );
      if (target.rowCount !== 1) {
        return reply.code(404).send({ error: 'device_not_found' });
      }

      // Non-monotonic reject. Client MatrixStore.accept enforces
      // this on receipt; mirrored here at the write boundary so a
      // compromised admin session cannot downgrade a matrix.
      const existing = await pool.query<{ version: number }>(
        `SELECT version FROM matrices WHERE device_id = $1`,
        [params.data.device_id],
      );
      const existingRow = existing.rows[0];
      if (
        existingRow !== undefined &&
        parsed.matrix.version <= existingRow.version
      ) {
        return reply.code(409).send({
          error: 'matrix_version_not_monotonic',
        });
      }

      // Store canonical bytes (re-canonicalized via jcsCanonicalize,
      // so stored form == verified form).
      const canonical_bytes = jcsCanonicalize(parsed);

      await pool.query(
        `INSERT INTO matrices
           (device_id, canonical_bytes, signature_base64url, version)
         VALUES ($1, $2, $3, $4)
         ON CONFLICT (device_id) DO UPDATE
           SET canonical_bytes = EXCLUDED.canonical_bytes,
               signature_base64url = EXCLUDED.signature_base64url,
               version = EXCLUDED.version,
               updated_at = now()`,
        [
          params.data.device_id,
          canonical_bytes,
          body.data.signature_base64url,
          parsed.matrix.version,
        ],
      );

      return reply.code(201).send({
        device_id: params.data.device_id,
        version: parsed.matrix.version,
      });
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
