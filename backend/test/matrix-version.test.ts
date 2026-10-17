import { describe, it, expect, beforeAll, afterAll, beforeEach } from 'vitest';
import { randomBytes, randomUUID } from 'node:crypto';
import { buildApp } from '../src/app.js';
import { pool } from '../src/db/client.js';
import {
  assertMatrixVersion,
  getMatrixVersion,
} from '../src/admin/matrixVersions.js';

const ORG = '00000000-0000-0000-0000-0000000000a1';
const EMPTY_ORG = '00000000-0000-0000-0000-0000000000a2';

async function insertDevice(opts: { role?: string } = {}): Promise<string> {
  const deviceId = randomUUID();
  const publicKey = randomBytes(32).toString('base64url');
  await pool.query(
    `INSERT INTO devices (device_id, org_id, public_key, label, role)
     VALUES ($1, $2, $3, $4, $5)`,
    [deviceId, ORG, Buffer.from(publicKey, 'base64url'), 'matrix-test', opts.role ?? 'admin'],
  );
  return deviceId;
}

async function auditCount(orgId: string): Promise<number> {
  const r = await pool.query<{ count: string }>(
    `SELECT COUNT(*)::text AS count FROM audit_events
     WHERE event_type = 'matrix_version.asserted' AND target_id = $1`,
    [orgId],
  );
  return parseInt(r.rows[0].count, 10);
}

describe('matrix version', () => {
  let app: Awaited<ReturnType<typeof buildApp>>;

  beforeAll(async () => {
    app = await buildApp();
    await app.ready();
  });

  beforeEach(async () => {
    await pool.query('DELETE FROM org_matrix_versions WHERE org_id = $1', [ORG]);
    await pool.query('DELETE FROM devices WHERE org_id = $1', [ORG]);
  });

  afterAll(async () => {
    await pool.query(
      'DELETE FROM org_matrix_versions WHERE org_id = $1 OR org_id = $2',
      [ORG, EMPTY_ORG],
    );
    await pool.query(
      'DELETE FROM devices WHERE org_id = $1 OR org_id = $2',
      [ORG, EMPTY_ORG],
    );
    await app.close();
    await pool.end();
  });

  it('TEST-MATRIX-VERSION-RECORD first assertion creates row with previous_version=null', async () => {
    const deviceId = await insertDevice();
    const result = await assertMatrixVersion({
      actor_device_id: deviceId,
      actor_role: 'admin',
      org_id: ORG,
      version: 3,
    });

    expect(result.current_version).toBe(3);
    expect(result.previous_version).toBeNull();
    expect(result.changed).toBe(true);
    expect(result.asserted_by_device_id).toBe(deviceId);
    expect(result.asserted_at).toMatch(/^\d{4}-\d{2}-\d{2}T/);

    const audit = await pool.query(
      `SELECT payload FROM audit_events
       WHERE event_type = 'matrix_version.asserted' AND target_id = $1
       ORDER BY event_id DESC LIMIT 1`,
      [ORG],
    );
    expect(audit.rowCount).toBe(1);
    expect(audit.rows[0].payload).toEqual({ version: 3, previous_version: null });
  });

  it('TEST-MATRIX-VERSION-UPSERT second assertion records previous_version', async () => {
    const first = await insertDevice();
    await assertMatrixVersion({
      actor_device_id: first, actor_role: 'admin', org_id: ORG, version: 3,
    });
    const before = await auditCount(ORG);

    const second = await insertDevice();
    const result = await assertMatrixVersion({
      actor_device_id: second, actor_role: 'admin', org_id: ORG, version: 5,
    });

    expect(result.current_version).toBe(5);
    expect(result.previous_version).toBe(3);
    expect(result.changed).toBe(true);
    expect(result.asserted_by_device_id).toBe(second);
    expect(await auditCount(ORG)).toBe(before + 1);

    const audit = await pool.query(
      `SELECT payload FROM audit_events
       WHERE event_type = 'matrix_version.asserted' AND target_id = $1
       ORDER BY event_id DESC LIMIT 1`,
      [ORG],
    );
    expect(audit.rows[0].payload).toEqual({ version: 5, previous_version: 3 });
  });

  it('TEST-MATRIX-VERSION-QUERY nulls for empty org, populated otherwise', async () => {
    const empty = await getMatrixVersion(EMPTY_ORG);
    expect(empty).toEqual({
      current_version: null,
      asserted_at: null,
      asserted_by_device_id: null,
    });

    const deviceId = await insertDevice();
    await assertMatrixVersion({
      actor_device_id: deviceId, actor_role: 'admin', org_id: ORG, version: 2,
    });
    const populated = await getMatrixVersion(ORG);
    expect(populated.current_version).toBe(2);
    expect(populated.asserted_by_device_id).toBe(deviceId);
    expect(populated.asserted_at).toMatch(/^\d{4}-\d{2}-\d{2}T/);
  });

  it('TEST-MATRIX-VERSION-EQUAL-IDEMPOTENT same version is a no-op', async () => {
    const first = await insertDevice();
    await assertMatrixVersion({
      actor_device_id: first, actor_role: 'admin', org_id: ORG, version: 7,
    });
    const before = await auditCount(ORG);
    const priorState = await getMatrixVersion(ORG);

    const second = await insertDevice();
    const result = await assertMatrixVersion({
      actor_device_id: second, actor_role: 'admin', org_id: ORG, version: 7,
    });

    expect(result.changed).toBe(false);
    expect(result.current_version).toBe(7);
    expect(await auditCount(ORG)).toBe(before);

    const afterState = await getMatrixVersion(ORG);
    expect(afterState).toEqual(priorState);
  });

  it('TEST-MATRIX-VERSION-REJECT-LOWER lower version throws, state unchanged', async () => {
    const first = await insertDevice();
    await assertMatrixVersion({
      actor_device_id: first, actor_role: 'admin', org_id: ORG, version: 5,
    });
    const before = await auditCount(ORG);
    const priorState = await getMatrixVersion(ORG);

    const second = await insertDevice();
    await expect(
      assertMatrixVersion({
        actor_device_id: second, actor_role: 'admin', org_id: ORG, version: 4,
      }),
    ).rejects.toMatchObject({ code: 'version_below_current', statusCode: 409 });

    const afterState = await getMatrixVersion(ORG);
    expect(afterState).toEqual(priorState);
    expect(await auditCount(ORG)).toBe(before);
  });

  it('TEST-MATRIX-VERSION-ROUTE-AUTH unauthenticated requests are rejected', async () => {
    const getRes = await app.inject({ method: 'GET', url: '/admin/matrix-version' });
    expect([401, 403]).toContain(getRes.statusCode);

    const postRes = await app.inject({
      method: 'POST',
      url: '/admin/matrix-version',
      payload: { version: 1 },
    });
    expect([401, 403]).toContain(postRes.statusCode);
  });
});
