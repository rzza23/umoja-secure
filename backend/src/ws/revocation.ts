import { pool } from '../db/client.js';
import { logger } from '../observability/logging.js';
import { registry } from './registry.js';

const CHANNEL = 'device_revoked';

let listenerClient: import('pg').PoolClient | null = null;

/**
 * Start a dedicated LISTEN connection on the `device_revoked` channel.
 * When a notification arrives, close all WebSocket connections for that device.
 * Also performs a reconciliation pass on startup: any device already marked
 * revoked has its active connections closed.
 */
export async function startRevocationListener(): Promise<void> {
  listenerClient = await pool.connect();
  await listenerClient.query(`LISTEN ${CHANNEL}`);

  listenerClient.on('notification', (msg) => {
    if (msg.channel !== CHANNEL || !msg.payload) return;
    try {
      const payload = JSON.parse(msg.payload) as { device_id?: string };
      if (payload.device_id) {
        const n = registry.closeByDevice(
          payload.device_id,
          4403,
          'device revoked',
        );
        if (n > 0) {
          logger.info(
            { device_id: payload.device_id, closed: n },
            'closed websockets for revoked device',
          );
        }
      }
    } catch (err) {
      logger.error({ err }, 'bad revocation payload');
    }
  });

  listenerClient.on('error', (err) => {
    logger.error({ err }, 'revocation listener error');
  });

  // Reconciliation: close any connections for devices already revoked
  await reconcileRevokedDevices();
}

async function reconcileRevokedDevices(): Promise<void> {
  const res = await pool.query<{ device_id: string }>(
    `SELECT device_id FROM devices WHERE status = 'revoked'`,
  );
  let total = 0;
  for (const row of res.rows) {
    total += registry.closeByDevice(row.device_id, 4403, 'device revoked');
  }
  if (total > 0) {
    logger.info({ closed: total }, 'reconciled revoked devices on startup');
  }
}

export async function stopRevocationListener(): Promise<void> {
  if (listenerClient) {
    try {
      await listenerClient.query(`UNLISTEN ${CHANNEL}`);
    } catch {
      // ignore
    }
    listenerClient.release();
    listenerClient = null;
  }
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
