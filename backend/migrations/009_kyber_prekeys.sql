-- Extend prekey_bundles with post-quantum Kyber prekey columns.
-- libsignal 0.86.x requires Kyber prekeys as part of PQXDH.
-- Existing rows have NULL for these columns and must be refreshed by the
-- device (the app now generates and uploads them).

ALTER TABLE prekey_bundles
  ADD COLUMN kyber_prekey_id          INT,
  ADD COLUMN kyber_prekey_public      BYTEA,
  ADD COLUMN kyber_prekey_signature   BYTEA;

-- One-time Kyber prekeys are stored separately. Similar to one_time_prekeys
-- but with a larger public key (1568 bytes for Kyber-1024).
CREATE TABLE one_time_kyber_prekeys (
  device_id   UUID NOT NULL REFERENCES devices(device_id) ON DELETE CASCADE,
  prekey_id   INT NOT NULL CHECK (prekey_id > 0),
  public_key  BYTEA NOT NULL CHECK (octet_length(public_key) BETWEEN 100 AND 2048),
  consumed_at TIMESTAMPTZ,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (device_id, prekey_id)
);

CREATE INDEX idx_otkp_unconsumed ON one_time_kyber_prekeys (device_id)
  WHERE consumed_at IS NULL;
