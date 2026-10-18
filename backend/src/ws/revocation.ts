import { pool } from '../db/client.js';
import { logger } from '../observability/logging.js';
import { registry } from './registry.js';

const CHANNEL = 'device_revoked';
const RECONNECT_DELAY_MS = 5000;

/**
 * Minimal interface a pg-client-shaped object must satisfy for the
 * listener. Structural typing lets tests pass a fake without pg.
 */
export interface RevocationClient {
  query(sql: string): Promise<unknown>;
  on(event: string, handler: (arg?: unknown) => void): void;
  release(err?: Error): void;
}

/**
 * Injected dependencies for [createRevocationListener]. Every effect
 * the listener has on the outside world is a dependency, so the
 * reconnect-and-re-reconcile state machine is testable without a real
 * Postgres connection.
 */
export interface RevocationListenerDeps {
  connect(): Promise<RevocationClient>;
  reconcile(): Promise<number>;
  scheduleReconnect(fn: () => void, delayMs: number): unknown;
  cancelReconnect(handle: unknown): void;
  onNotification(device_id: string): void;
  logger: {
    info: (obj: unknown, msg?: string) => void;
    warn: (obj: unknown, msg?: string) => void;
    error: (obj: unknown, msg?: string) => void;
  };
}

export interface RevocationListener {
  start(): Promise<void>;
  stop(): Promise<void>;
  isConnected(): boolean;
  isReconnectPending(): boolean;
}

/**
 * TASK-P1-042: reconnect + re-reconcile on listener connection loss.
 *
 * Behavior:
 * - LISTEN on the `device_revoked` channel.
 * - On connection loss (`end` event), schedule a bounded reconnect
 *   (fixed 5s interval — matches the ≤5s closure target's tolerance).
 * - On every successful connect, `reconcile()` runs *before* the
 *   listener reports ready. Startup is a connect; reconnects are
 *   connects; same reconcile path. A revocation that lands during
 *   the disconnected window is caught by the reconcile query;
 *   a revocation after reconcile begins is caught by the
 *   notification handler (LISTEN active throughout reconcile).
 * - `stop()` cancels any pending reconnect, so the process shuts
 *   down cleanly.
 *
 * Reconnect state machine (extracted so the three named tests can
 * exercise it without a real Postgres connection):
 *
 *   stop()?  --> bail (no connect)
 *   connect fails  --> scheduleReconnect
 *   connect succeeds  --> LISTEN  --> reconcile  --> ready
 *   during wait  --> `end` fires --> scheduleReconnect (guarded)
 *   stop() while reconnect pending  --> cancelReconnect
 *
 * The 5-minute per-connection revalidation cycle (ws/server.ts) is
 * the independent mid-run backstop and remains unchanged by this
 * fix (per TASK-P1-042 non-goals: "Do NOT touch the 5-minute
 * revalidation cycle").
 */
export function createRevocationListener(
  deps: RevocationListenerDeps,
): RevocationListener {
  let client: RevocationClient | null = null;
  let reconnectHandle: unknown = null;
  let isStopping = false;

  async function connectAndListen(): Promise<void> {
    if (isStopping) return;

    let newClient: RevocationClient;
    try {
      newClient = await deps.connect();
    } catch (err) {
      deps.logger.error({ err }, 'revocation listener connect failed');
      scheduleReconnect();
      return;
    }

    // If stop was called while we were awaiting connect, release and bail.
    if (isStopping) {
      try {
        newClient.release();
      } catch {
        /* ignore */
      }
      return;
    }

    try {
      await newClient.query(`LISTEN ${CHANNEL}`);
    } catch (err) {
      deps.logger.error({ err }, 'revocation listener LISTEN failed');
      try {
        newClient.release();
      } catch {
        /* ignore */
      }
      scheduleReconnect();
      return;
    }

    client = newClient;

    newClient.on('notification', (msg) => {
      const m = msg as { channel?: string; payload?: string } | undefined;
      if (!m || m.channel !== CHANNEL || !m.payload) return;
      try {
        const payload = JSON.parse(m.payload) as { device_id?: string };
        if (payload.device_id) deps.onNotification(payload.device_id);
      } catch (err) {
        deps.logger.error({ err }, 'bad revocation payload');
      }
    });

    newClient.on('error', (err) => {
      // pg emits 'error' then 'end' on connection loss. Reconnect
      // scheduling happens in the 'end' handler — see comment there.
      deps.logger.error({ err }, 'revocation listener error');
    });

    newClient.on('end', () => {
      deps.logger.warn({}, 'revocation listener connection ended');
      client = null;
      scheduleReconnect();
    });

    // Reconcile AFTER LISTEN is active. Any device revoked during the
    // gap is caught by this broad query; any revocation after this
    // query starts fires a notification the live listener handles.
    // The listener is not considered "ready" until this completes.
    try {
      const closed = await deps.reconcile();
      if (closed > 0) {
        deps.logger.info(
          { closed },
          'reconciled revoked devices on listener connect',
        );
      }
    } catch (err) {
      // Reconcile failure must not break the connection — the 5-min
      // revalidation backstop (defense 3) covers missed reconciliations.
      deps.logger.error({ err }, 'reconcile on reconnect failed');
    }
  }

  function scheduleReconnect(): void {
    if (isStopping) return;
    if (reconnectHandle !== null) return;
    reconnectHandle = deps.scheduleReconnect(() => {
      reconnectHandle = null;
      void connectAndListen();
    }, RECONNECT_DELAY_MS);
  }

  return {
    async start() {
      await connectAndListen();
    },
    async stop() {
      isStopping = true;
      if (reconnectHandle !== null) {
        deps.cancelReconnect(reconnectHandle);
        reconnectHandle = null;
      }
      const c = client;
      client = null;
      if (c) {
        try {
          await c.query(`UNLISTEN ${CHANNEL}`);
        } catch {
          /* ignore */
        }
        try {
          c.release();
        } catch {
          /* ignore */
        }
      }
    },
    isConnected: () => client !== null,
    isReconnectPending: () => reconnectHandle !== null,
  };
}

// ============================================================
// Production wiring
// ============================================================

const listener = createRevocationListener({
  connect: () => pool.connect(),
  reconcile: async () => {
    const res = await pool.query<{ device_id: string }>(
      `SELECT device_id FROM devices WHERE status = 'revoked'`,
    );
    let total = 0;
    for (const row of res.rows) {
      total += registry.closeByDevice(row.device_id, 4403, 'device revoked');
    }
    return total;
  },
  scheduleReconnect: (fn, ms) => setTimeout(fn, ms),
  cancelReconnect: (h) => clearTimeout(h as NodeJS.Timeout),
  onNotification: (device_id) => {
    const n = registry.closeByDevice(device_id, 4403, 'device revoked');
    if (n > 0) {
      logger.info(
        { device_id, closed: n },
        'closed websockets for revoked device',
      );
    }
  },
  logger,
});

export async function startRevocationListener(): Promise<void> {
  return listener.start();
}

export async function stopRevocationListener(): Promise<void> {
  return listener.stop();
}

/**
 * Notify all backend instances that a device has been revoked.
 * Call this from the admin plane after committing the revocation.
 */
export async function notifyDeviceRevoked(device_id: string): Promise<void> {
  await pool.query(`SELECT pg_notify($1, $2)`, [
    CHANNEL,
    JSON.stringify({ device_id }),
  ]);
}
