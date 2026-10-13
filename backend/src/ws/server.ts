import type { FastifyPluginAsync, FastifyRequest } from 'fastify';
import websocket from '@fastify/websocket';
import { randomUUID } from 'node:crypto';
import type { WebSocket } from 'ws';

import { logger } from '../observability/logging.js';
import { env } from '../config/env.js';
import { lookupSession } from '../auth/sessions.js';
import { registry, type Connection } from './registry.js';
import { AuthError, createChallenge } from '../auth/challenge.js';
import { canonicalizeChallenge } from '../auth/canonical.js';

interface AuthFrame {
  type: 'auth';
  session_token: string;
}

export const wsRoutes: FastifyPluginAsync = async (app) => {
  await app.register(websocket);

  app.get('/ws', { websocket: true }, (socket: WebSocket, _req: FastifyRequest) => {
    let conn: Connection | null = null;
    let authed = false;
    let revalidateTimer: NodeJS.Timeout | null = null;
    let heartbeatTimer: NodeJS.Timeout | null = null;
    let authTimer: NodeJS.Timeout | null = null;
    let lastChallenge: { challenge_id: string; canonical: Buffer } | null = null;

    const cleanup = () => {
      if (authTimer) clearTimeout(authTimer);
      if (revalidateTimer) clearInterval(revalidateTimer);
      if (heartbeatTimer) clearInterval(heartbeatTimer);
      if (conn) registry.unregister(conn);
      conn = null;
    };

    // Enforce auth within WS_AUTH_TIMEOUT_SECONDS
    authTimer = setTimeout(() => {
      if (!authed) {
        logger.info({ ws_id: conn?.ws_id }, 'ws auth timeout');
        socket.close(4401, 'auth timeout');
      }
    }, env.WS_AUTH_TIMEOUT_SECONDS * 1000);

    socket.on('message', async (raw: Buffer) => {
      let frame: { type?: string; [k: string]: unknown };
      try {
        frame = JSON.parse(raw.toString('utf8'));
      } catch {
        socket.send(JSON.stringify({ type: 'error', code: 'bad_json' }));
        return;
      }

      if (!frame.type) {
        socket.send(JSON.stringify({ type: 'error', code: 'missing_type' }));
        return;
      }

      // First frame must be auth
      if (!authed) {
        if (frame.type !== 'auth') {
          socket.close(4401, 'auth required');
          return;
        }
        const f = frame as unknown as AuthFrame;
        if (typeof f.session_token !== 'string') {
          socket.close(4401, 'invalid auth frame');
          return;
        }
        let session;
        try {
          session = await lookupSession(f.session_token);
        } catch {
          socket.close(1011, 'lookup failed');
          return;
        }
        if (!session) {
          socket.send(JSON.stringify({ type: 'auth_fail', reason: 'invalid_session' }));
          socket.close(4401, 'invalid session');
          return;
        }

        authed = true;
        if (authTimer) {
          clearTimeout(authTimer);
          authTimer = null;
        }

        conn = {
          ws: socket,
          device_id: session.device_id,
          session_id: session.session_id,
          ws_id: randomUUID(),
          last_revalidated_at: Date.now(),
          is_alive: true,
        };
        registry.register(conn);

        socket.send(
          JSON.stringify({
            type: 'auth_ok',
            ws_id: conn.ws_id,
            revalidate_after_seconds: env.WS_REVALIDATE_SECONDS,
          }),
        );

        logger.info(
          { device_id: session.device_id, ws_id: conn.ws_id },
          'ws authenticated',
        );

        // Schedule revalidation
        revalidateTimer = setInterval(() => {
          if (!conn) return;
          void (async () => {
            try {
              const challenge = await createChallenge(conn!.device_id, 'auth');
              lastChallenge = {
                challenge_id: challenge.challenge_id,
                canonical: canonicalizeChallenge(challenge),
              };
              socket.send(JSON.stringify({ type: 'revalidate', challenge }));
            } catch (err) {
              if (err instanceof AuthError && err.code === 'unauthorized') {
                socket.close(4403, 'device revoked');
              } else {
                logger.error({ err }, 'revalidate schedule failed');
                socket.close(1011, 'revalidate failed');
              }
            }
          })();
        }, env.WS_REVALIDATE_SECONDS * 1000);

        // Schedule heartbeat
        heartbeatTimer = setInterval(() => {
          if (!conn) return;
          if (!conn.is_alive) {
            logger.info({ ws_id: conn.ws_id }, 'ws heartbeat timeout');
            socket.close(4408, 'heartbeat timeout');
            return;
          }
          conn.is_alive = false;
          socket.send(JSON.stringify({ type: 'ping' }));
        }, env.WS_HEARTBEAT_SECONDS * 1000);

        return;
      }

      // Authed frames
      if (!conn) return;

      if (frame.type === 'pong') {
        conn.is_alive = true;
        return;
      }

      if (frame.type === 'revalidate_response') {
        const sig = frame.signature;
        if (typeof sig !== 'string' || !lastChallenge) {
          socket.close(4401, 'invalid revalidate frame');
          return;
        }
        // Delegate signature verification to the standard verify path.
        try {
          const { verifyChallenge } = await import('../auth/verify.js');
          await verifyChallenge(lastChallenge.challenge_id, sig);
          conn.last_revalidated_at = Date.now();
          lastChallenge = null;
          socket.send(JSON.stringify({ type: 'revalidate_ok' }));
        } catch {
          socket.send(JSON.stringify({ type: 'revalidate_fail' }));
          socket.close(4401, 'revalidate rejected');
        }
        return;
      }

      socket.send(
        JSON.stringify({ type: 'error', code: 'unknown_type', got: frame.type }),
      );
    });

    socket.on('close', () => {
      if (conn) {
        logger.info({ device_id: conn.device_id, ws_id: conn.ws_id }, 'ws closed');
      }
      cleanup();
    });

    socket.on('error', (err) => {
      logger.warn({ err: err.message }, 'ws error');
    });
  });
};
