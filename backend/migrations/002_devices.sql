CREATE TABLE devices (
  device_id                     UUID PRIMARY KEY,
  org_id                        UUID NOT NULL,
  public_key                    BYTEA NOT NULL,
  public_key_alg                TEXT NOT NULL DEFAULT 'ed25519'
                                CHECK (public_key_alg IN ('ed25519', 'ecdsa-p256')),
  public_wipe_confirmation_key  BYTEA,
  messaging_identity_key        BYTEA,
  label                         TEXT NOT NULL
                                CHECK (char_length(label) BETWEEN 1 AND 64),
  role                          TEXT NOT NULL
                                CHECK (role IN ('owner', 'admin', 'user', 'auditor')),
  status                        TEXT NOT NULL DEFAULT 'active'
                                CHECK (status IN ('active', 'suspended', 'revoked')),
  enrolled_at                   TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_seen_at                  TIMESTAMPTZ,
  revoked_at                    TIMESTAMPTZ,
  revoke_reason                 TEXT,
  suspended_at                  TIMESTAMPTZ,
  CONSTRAINT devices_revoke_consistency
    CHECK ((status = 'revoked') = (revoked_at IS NOT NULL)),
  CONSTRAINT devices_key_unique UNIQUE (public_key)
);

CREATE INDEX idx_devices_org         ON devices (org_id);
CREATE INDEX idx_devices_status      ON devices (status);
CREATE INDEX idx_devices_active_org  ON devices (org_id) WHERE status = 'active';
