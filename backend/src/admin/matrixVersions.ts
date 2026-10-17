import { withTransaction } from '../db/client.js';
import { writeAuditEvent } from '../audit/log.js';

export class MatrixVersionError extends Error {
  constructor(
    public code: string,
    public statusCode: number,
  ) {
    super(code);
    this.name = 'MatrixVersionError';
  }
}

export interface AssertMatrixVersionInput {
  actor_device_id: string;
  actor_role: string;
  org_id: string;
  version: number;
}

export interface MatrixVersionState {
  current_version: number | null;
  asserted_at: string | null;
  asserted_by_device_id: string | null;
}

export interface AssertMatrixVersionResult extends MatrixVersionState {
  previous_version: number | null;
  changed: boolean;
}

export async function getMatrixVersion(
  org_id: string,
): Promise<MatrixVersionState> {
  return withTransaction(async (tx) => {
    const result = await tx.query<{
      current_version: number;
      asserted_at: Date;
      asserted_by_device_id: string;
    }>(
      `SELECT current_version, asserted_at, asserted_by_device_id
         FROM org_matrix_versions
        WHERE org_id = $1`,
      [org_id],
    );
    const row = result.rows[0];
    if (!row) {
      return {
        current_version: null,
        asserted_at: null,
        asserted_by_device_id: null,
      };
    }
    return {
      current_version: row.current_version,
      asserted_at: row.asserted_at.toISOString(),
      asserted_by_device_id: row.asserted_by_device_id,
    };
  });
}

export async function assertMatrixVersion(
  input: AssertMatrixVersionInput,
): Promise<AssertMatrixVersionResult> {
  return withTransaction(async (tx) => {
    const current = await tx.query<{
      current_version: number;
      asserted_at: Date;
      asserted_by_device_id: string;
    }>(
      `SELECT current_version, asserted_at, asserted_by_device_id
         FROM org_matrix_versions
        WHERE org_id = $1
        FOR UPDATE`,
      [input.org_id],
    );
    const prev = current.rows[0];

    if (prev && input.version < prev.current_version) {
      throw new MatrixVersionError('version_below_current', 409);
    }

    if (prev && input.version === prev.current_version) {
      return {
        current_version: prev.current_version,
        previous_version: prev.current_version,
        asserted_at: prev.asserted_at.toISOString(),
        asserted_by_device_id: prev.asserted_by_device_id,
        changed: false,
      };
    }

    const previous_version = prev ? prev.current_version : null;

    const upserted = await tx.query<{ asserted_at: Date }>(
      `INSERT INTO org_matrix_versions
         (org_id, current_version, asserted_at, asserted_by_device_id)
       VALUES ($1, $2, now(), $3)
       ON CONFLICT (org_id) DO UPDATE
         SET current_version = EXCLUDED.current_version,
             asserted_at = EXCLUDED.asserted_at,
             asserted_by_device_id = EXCLUDED.asserted_by_device_id
       RETURNING asserted_at`,
      [input.org_id, input.version, input.actor_device_id],
    );

    await writeAuditEvent(tx, {
      event_type: 'matrix_version.asserted',
      actor_device_id: input.actor_device_id,
      actor_role: input.actor_role,
      target_type: 'org',
      target_id: input.org_id,
      payload: { version: input.version, previous_version },
    });

    return {
      current_version: input.version,
      previous_version,
      asserted_at: upserted.rows[0]!.asserted_at.toISOString(),
      asserted_by_device_id: input.actor_device_id,
      changed: true,
    };
  });
}