CREATE TABLE prekey_bundles (
  device_id                 UUID PRIMARY KEY REFERENCES devices(device_id) ON DELETE CASCADE,
  identity_key              BYTEA NOT NULL CHECK (octet_length(identity_key) = 32),
  signed_prekey_id          INT NOT NULL CHECK (signed_prekey_id > 0),
  signed_prekey_public      BYTEA NOT NULL CHECK (octet_length(signed_prekey_public) = 32),
  signed_prekey_signature   BYTEA NOT NULL CHECK (octet_length(signed_prekey_signature) = 64),
  registration_id           INT NOT NULL CHECK (registration_id > 0),
  updated_at                TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE one_time_prekeys (
  device_id   UUID NOT NULL REFERENCES devices(device_id) ON DELETE CASCADE,
  prekey_id   INT NOT NULL CHECK (prekey_id > 0),
  public_key  BYTEA NOT NULL CHECK (octet_length(public_key) = 32),
  consumed_at TIMESTAMPTZ,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (device_id, prekey_id)
);

CREATE INDEX idx_otp_unconsumed ON one_time_prekeys (device_id)
  WHERE consumed_at IS NULL;
