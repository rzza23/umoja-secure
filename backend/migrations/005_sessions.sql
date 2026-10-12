CREATE TABLE sessions (
  session_id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  token_hash         BYTEA NOT NULL UNIQUE CHECK (octet_length(token_hash) = 32),
  device_id          UUID NOT NULL REFERENCES devices(device_id) ON DELETE CASCADE,
  org_id             UUID NOT NULL,
  role               TEXT NOT NULL,
  scope              JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_seen_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at         TIMESTAMPTZ NOT NULL,
  revoked_at         TIMESTAMPTZ,
  revoke_reason      TEXT,
  client_ip_hash     BYTEA,
  user_agent_hash    BYTEA,
  CONSTRAINT session_expiry CHECK (expires_at > created_at),
  CONSTRAINT session_revoke_consistency
    CHECK ((revoked_at IS NULL) OR (revoke_reason IS NOT NULL))
);

CREATE INDEX idx_sessions_device        ON sessions (device_id);
CREATE INDEX idx_sessions_active_device ON sessions (device_id)
  WHERE revoked_at IS NULL;
CREATE INDEX idx_sessions_expiry        ON sessions (expires_at)
  WHERE revoked_at IS NULL;
