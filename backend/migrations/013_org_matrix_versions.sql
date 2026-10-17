-- Migration 013: org_matrix_versions.
--
-- Per Build Master §3.7 step 1 and TASK-P1-030 sub-task 3a: the
-- backend records the current authorization-matrix version per org.
-- This is state, not history — one row per org, upserted on assertion.
--
-- History lives in audit_events. Every state-changing assertion writes
-- event_type 'matrix_version.asserted' with payload
-- { version, previous_version } in the same transaction. Idempotent
-- assertions (version equal to current) write no audit event.
--
-- Purpose (Phase 1 framing): cross-session and cross-admin audit —
-- catching "the new admin doesn't know what the last admin signed."
-- Not attack-prevention. Anti-rollback is enforced client-side
-- (MatrixStore.highestSeenVersion, P1-026). The floor recorded here
-- is asserted by the same admin who will later assert the next
-- version; both come from the same party in Phase 1.
--
-- No orgs table exists. org_id is a bare UUID, matching
-- enrollment_tokens.org_id.

CREATE TABLE org_matrix_versions (
  org_id                 UUID PRIMARY KEY,
  current_version        INTEGER NOT NULL CHECK (current_version >= 1),
  asserted_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
  asserted_by_device_id  UUID NOT NULL REFERENCES devices(device_id)
);
