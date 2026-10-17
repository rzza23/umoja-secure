-- Migration 016: matrices.
--
-- Per TASK-P1-037 and ADR-HARDENING-001 §6.
--
-- Stores the current signed authorization matrix per device. One row
-- per device (device_id PRIMARY KEY) — Phase 1 shape. Version
-- monotonicity is enforced by the client's MatrixStore.accept() and
-- reflected in the version column for admin queries (closes KI-018 on
-- the matrix path).
--
-- Backend does NOT verify the provisioning signature. Matrices are
-- relayed verbatim from admin to device (server-blind per
-- ADR-PROVISIONING-001 §2 Q3). Peers verify on receipt against the
-- pinned provisioning key. A future reviewer will ask "why doesn't the
-- backend check?" — this comment is the answer.
--
-- Three invariants the DB layer cannot enforce:
--
--   * version must equal parse(canonical_bytes).matrix.version. Route
--     code sets it from the parsed matrix, not from the request body.
--     Mismatch is undetectable at the DB layer; MatrixStore.accept()
--     verifies bytes, not the column. Denormalized from the bytes for
--     query convenience — same pattern as migration 013's
--     org_matrix_versions.current_version and migration 014's
--     enrollment_matrix_version_floor.
--
--   * updated_at is set by the write path's UPSERT
--     (ON CONFLICT DO UPDATE SET updated_at = now()). The DEFAULT only
--     covers the initial INSERT. Without an explicit SET, updated_at
--     silently lies after a re-push.
--
--   * matrix.device_id must equal the row's device_id. Enforced
--     client-side by MatrixStore.accept() checking the wrapper —
--     currently NOT checked (filed as an ADR-PROVISIONING-001 §7
--     future-hardening item; reachable surface appears with P1-033's
--     write path, since GET /me/matrix already scopes by
--     req.device.device_id).
--
-- signature_base64url length CHECK (86 chars = 64 bytes Ed25519
-- base64url no-pad) is defense-in-depth beyond route validation,
-- matching audit_events.event_hash, enrollment_tokens.token_hash, and
-- identity_change_notices.signature_base64url.
--
-- No ON DELETE CASCADE. Devices are never deleted (only revoked);
-- losing matrices with the device would be a bug, not a feature. If a
-- future purge operation is added, the FK will block it — correctly.
-- Matches migration 015's convention.

CREATE TABLE matrices (
  device_id            UUID PRIMARY KEY REFERENCES devices(device_id),
  canonical_bytes      BYTEA NOT NULL,
  signature_base64url  TEXT NOT NULL
                       CHECK (char_length(signature_base64url) = 86),
  version              INT NOT NULL CHECK (version >= 1),
  created_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at           TIMESTAMPTZ NOT NULL DEFAULT now()
);
