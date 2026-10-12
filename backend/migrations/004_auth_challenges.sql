CREATE TABLE auth_challenges (
  challenge_id       UUID PRIMARY KEY,
  device_id          UUID NOT NULL REFERENCES devices(device_id) ON DELETE CASCADE,
  nonce              BYTEA NOT NULL CHECK (octet_length(nonce) = 32),
  purpose            TEXT NOT NULL
                     CHECK (purpose IN ('auth','ws_revalidate','sensitive_op')),
  session_context    TEXT,
  issued_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at         TIMESTAMPTZ NOT NULL,
  used               BOOLEAN NOT NULL DEFAULT false,
  used_at            TIMESTAMPTZ,
  CONSTRAINT challenge_expiry CHECK (expires_at > issued_at),
  CONSTRAINT challenge_used_consistency
    CHECK ((used = true) = (used_at IS NOT NULL))
);

CREATE INDEX idx_challenges_device  ON auth_challenges (device_id);
CREATE INDEX idx_challenges_pending ON auth_challenges (expires_at)
  WHERE used = false;
