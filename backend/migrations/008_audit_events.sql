CREATE TABLE audit_events (
  event_id           BIGSERIAL PRIMARY KEY,
  prev_hash          BYTEA,
  event_hash         BYTEA NOT NULL UNIQUE CHECK (octet_length(event_hash) = 32),
  event_type         TEXT NOT NULL,
  actor_device_id    UUID,
  actor_role         TEXT,
  target_type        TEXT,
  target_id          TEXT,
  payload            JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at         TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_audit_type_time ON audit_events (event_type, created_at);
CREATE INDEX idx_audit_actor     ON audit_events (actor_device_id, created_at);
CREATE INDEX idx_audit_target    ON audit_events (target_type, target_id);

CREATE OR REPLACE FUNCTION prevent_audit_mutation() RETURNS trigger AS $$
BEGIN
  RAISE EXCEPTION 'audit_events is append-only';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER audit_no_update
  BEFORE UPDATE ON audit_events
  FOR EACH ROW EXECUTE FUNCTION prevent_audit_mutation();

CREATE TRIGGER audit_no_delete
  BEFORE DELETE ON audit_events
  FOR EACH ROW EXECUTE FUNCTION prevent_audit_mutation();
