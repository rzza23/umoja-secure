import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { buildApp } from '../src/app.js';
import { pool, withTransaction } from '../src/db/client.js';
import { verifyAuditChain } from '../src/audit/verify.js';
import { writeAuditEvent } from '../src/audit/log.js';

describe('audit chain verification', () => {
  let app: Awaited<ReturnType<typeof buildApp>>;

  beforeAll(async () => {
    app = await buildApp();
    await app.ready();
  });

  afterAll(async () => {
    await app.close();
    await pool.end();
  });

  it('reports intact for a freshly written chain', async () => {
    await withTransaction(async (tx) => {
      await writeAuditEvent(tx, {
        event_type: 'test.chain.a',
        target_type: 'test',
        target_id: 'a',
      });
    });
    await withTransaction(async (tx) => {
      await writeAuditEvent(tx, {
        event_type: 'test.chain.b',
        target_type: 'test',
        target_id: 'b',
      });
    });

    const result = await verifyAuditChain();
    expect(result.intact).toBe(true);
    expect(result.total_events).toBeGreaterThanOrEqual(2);
    expect(result.broken_at).toBeUndefined();
  });

  it('detects tampering and reports the first broken event_id', async () => {
    await withTransaction(async (tx) => {
      await writeAuditEvent(tx, {
        event_type: 'test.tamper.target',
        target_type: 'test',
        target_id: 't',
      });
    });

    const row = await pool.query(
      `SELECT event_id, event_type FROM audit_events
       WHERE event_type = 'test.tamper.target' LIMIT 1`,
    );
    const event_id = row.rows[0].event_id as number;
    const original_type = row.rows[0].event_type as string;

    // Bypass the append-only trigger to simulate a compromise
    await pool.query('ALTER TABLE audit_events DISABLE TRIGGER audit_no_update');
    try {
      await pool.query(
        `UPDATE audit_events SET event_type = 'tampered' WHERE event_id = $1`,
        [event_id],
      );
    } finally {
      await pool.query('ALTER TABLE audit_events ENABLE TRIGGER audit_no_update');
    }

    const tampered = await verifyAuditChain();
    expect(tampered.intact).toBe(false);
    expect(tampered.broken_at).toBe(event_id);

    // Restore to leave the DB clean for subsequent tests
    await pool.query('ALTER TABLE audit_events DISABLE TRIGGER audit_no_update');
    try {
      await pool.query(
        `UPDATE audit_events SET event_type = $2 WHERE event_id = $1`,
        [event_id, original_type],
      );
    } finally {
      await pool.query('ALTER TABLE audit_events ENABLE TRIGGER audit_no_update');
    }

    const restored = await verifyAuditChain();
    expect(restored.intact).toBe(true);
  });
});
