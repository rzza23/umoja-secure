-- Migration 015: identity_change_notices and identity_change_acks.
--
-- Per TASK-P1-030 sub-task 030e-b and ADR-IDENTITY-CHANGE-001.
--
-- Storage for the peer identity-change notification flow (§3.7 step 8-9):
-- admins post signed replacement notices, peers post signed acks, both
-- retrieved by peers to drive the acknowledge-or-reject UI.
--
-- Trust asymmetry (ADR §4):
--   - Notices are a RELAY. Backend stores canonical_bytes verbatim and
--     never verifies the provisioning signature — that key is client-
--     pinned only (ADR-PROVISIONING-001 §2 Q3, server-blind).
--   - Acks are VERIFIED. Backend has the device auth public key in
--     devices.public_key (from enrollment) and verifies the ack
--     signature before insert (route logic, not this migration).
--
-- canonical_bytes is BYTEA, not JSONB. The trust artifact is byte-
-- identity with what was signed; JSONB round-trip could reorder keys
-- or normalize numbers, invalidating signature checks on read-back.
--
-- Cross-org consistency (from_device_id, to_device_id, and org_id all
-- in the same org) is validated by route logic, not by DB constraint.
-- Matches the enrollment_tokens.org_id pattern: bare UUID, no FK to
-- orgs because no orgs table exists. Route is the trust gate.
--
-- signature_base64url length check (86 chars = 64 bytes Ed25519
-- base64url no-pad) is defense-in-depth beyond the ADR §6 sketch,
-- matching the pattern of audit_events.event_hash and
-- enrollment_tokens.token_hash. Route validation is the trust gate;
-- this constraint catches a route bug before it lands as bad data.
--
-- Replay idempotence via PRIMARY KEY (notice_hash, acking_device_id):
-- a repeated ack is a no-op, not a duplicate row. Client can safely
-- retry on network failure.
--
-- No ON DELETE CASCADE. Devices are never deleted (only revoked), and
-- losing replacement history would be a bug not a feature. If a future
-- purge operation is added, the FK will block it — correctly.

CREATE TABLE identity_change_notices (
  notice_hash         BYTEA PRIMARY KEY
                      CHECK (octet_length(notice_hash) = 32),
  org_id              UUID NOT NULL,
  from_device_id      UUID NOT NULL REFERENCES devices(device_id),
  to_device_id        UUID NOT NULL REFERENCES devices(device_id),
  canonical_bytes     BYTEA NOT NULL,
  signature_base64url TEXT NOT NULL
                      CHECK (char_length(signature_base64url) = 86),
  created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_notices_org  ON identity_change_notices(org_id, created_at DESC);
CREATE INDEX idx_notices_from ON identity_change_notices(from_device_id);
CREATE INDEX idx_notices_to   ON identity_change_notices(to_device_id);

CREATE TABLE identity_change_acks (
  notice_hash         BYTEA NOT NULL
                      REFERENCES identity_change_notices(notice_hash),
  acking_device_id    UUID NOT NULL REFERENCES devices(device_id),
  org_id              UUID NOT NULL,
  decision            TEXT NOT NULL CHECK (decision IN ('accept', 'reject')),
  canonical_bytes     BYTEA NOT NULL,
  signature_base64url TEXT NOT NULL
                      CHECK (char_length(signature_base64url) = 86),
  created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (notice_hash, acking_device_id)
);

CREATE INDEX idx_acks_notice ON identity_change_acks(notice_hash);
