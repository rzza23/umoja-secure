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

  /**
   * GET /me/matrix — current signed authorization matrix for the
   * caller's device.
   *
   * Response: `{canonical_utf8, signature_base64url}`. The client
   * decodes canonical_utf8 to bytes, verifies the Ed25519 signature
   * against the pinned provisioning key, and calls MatrixStore.accept
   * only on successful verification. Version lives inside the
   * canonical bytes, not in the response — the client derives it by
   * parsing, never trusts the server's report (MatrixStore KDoc:
   * "parse is convenience, not trust").
   *
   * Backend does NOT verify the provisioning signature. It has no
   * provisioning public key (server-blind per ADR-PROVISIONING-001
   * §2 Q3). Matrices are relayed verbatim — same relay semantics as
   * identity-change notices (ADR-IDENTITY-CHANGE-001 §4). Peers
   * verify on receipt against the pinned key; authority derives from
   * the signature and the pin, not from the transport.
   *
   * 404 with `matrix_not_found` when no matrix has been seeded for
   * the caller's device. The client treats this as "no matrix yet" —
   * logs and continues, does not crash (registry §B TASK-P1-037:
   * "verification failure on fetch does NOT crash; logs and
   * continues"). The existing MatrixStore contents are preserved.
   *
   * The JOIN on devices is defense-in-depth against a future refactor
   * that bypasses req.device.device_id's session-derived scoping —
   * matches lookupSession's shape in auth/middleware.
   *
   * Task: TASK-P1-037
   * ADR: ADR-HARDENING-001 §6
   */
  app.get(
    '/me/matrix',
    { preHandler: requireSession() },
    async (req, reply) => {
      if (!req.device) return reply.code(401).send({ error: 'unauthorized' });
      const res = await pool.query<{
        canonical_bytes: Buffer;
        signature_base64url: string;
      }>(
        `SELECT m.canonical_bytes, m.signature_base64url
         FROM matrices m
         JOIN devices d ON d.device_id = m.device_id
         WHERE m.device_id = $1 AND d.org_id = $2`,
        [req.device.device_id, req.device.org_id],
      );
      const r = res.rows[0];
      if (!r) {
        return reply.code(404).send({ error: 'matrix_not_found' });
      }
      return reply.send({
        canonical_utf8: r.canonical_bytes.toString('utf8'),
        signature_base64url: r.signature_base64url,
      });
    },
  );
};
