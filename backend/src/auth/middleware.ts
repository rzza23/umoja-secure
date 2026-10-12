import type { FastifyRequest, FastifyReply } from 'fastify';
import { lookupSession } from './sessions.js';

export type Role = 'owner' | 'admin' | 'user' | 'auditor';

declare module 'fastify' {
  interface FastifyRequest {
    device?: {
      device_id: string;
      org_id: string;
      role: Role;
      session_id: string;
    };
  }
}

export function requireSession(roles?: Role[]) {
  return async (req: FastifyRequest, reply: FastifyReply) => {
    const auth = req.headers.authorization;
    if (!auth || !auth.startsWith('Bearer ')) {
      return reply.code(401).send({ error: 'unauthorized' });
    }
    const token = auth.slice('Bearer '.length).trim();

    let session;
    try {
      session = await lookupSession(token);
    } catch {
      // Fail closed on DB error
      return reply.code(503).send({ error: 'service_unavailable' });
    }
    if (!session) {
      return reply.code(401).send({ error: 'unauthorized' });
    }

    const role = session.role as Role;
    if (roles && !roles.includes(role)) {
      return reply.code(403).send({ error: 'forbidden' });
    }

    req.device = {
      device_id: session.device_id,
      org_id: session.org_id,
      role,
      session_id: session.session_id,
    };
  };
}
