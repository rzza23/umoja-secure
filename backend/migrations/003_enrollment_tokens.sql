CREATE TABLE enrollment_tokens (
  token_id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  token_hash         BYTEA NOT NULL UNIQUE CHECK (octet_length(token_hash) = 32),
  org_id             UUID NOT NULL,
  role               TEXT NOT NULL
                     CHECK (role IN ('owner','admin','user','auditor')),
  label_hint         TEXT,
  single_use         BOOLEAN NOT NULL DEFAULT true,
  expires_at         TIMESTAMPTZ NOT NULL,
  used_at            TIMESTAMPTZ,
  used_by_device_id  UUID REFERENCES devices(device_id),
  revoked_at         TIMESTAMPTZ,
  created_by         UUID NOT NULL,
  created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
  CONSTRAINT enrollment_token_expiry CHECK (expires_at > created_at)
);

CREATE INDEX idx_enrollment_tokens_org    ON enrollment_tokens (org_id);
CREATE INDEX idx_enrollment_tokens_unused ON enrollment_tokens (expires_at)
  WHERE used_at IS NULL AND revoked_at IS NULL;
