CREATE TABLE envelopes (
  envelope_id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  sender_device_id     UUID NOT NULL REFERENCES devices(device_id) ON DELETE CASCADE,
  recipient_device_id  UUID NOT NULL REFERENCES devices(device_id) ON DELETE CASCADE,
  ciphertext           BYTEA NOT NULL CHECK (octet_length(ciphertext) BETWEEN 1 AND 1048576),
  envelope_type        TEXT NOT NULL DEFAULT 'message'
                       CHECK (envelope_type IN ('message', 'call_signal', 'ack')),
  status               TEXT NOT NULL DEFAULT 'queued'
                       CHECK (status IN ('queued', 'locked', 'delivered', 'retrieved', 'expired', 'dead')),
  attempts             INT NOT NULL DEFAULT 0 CHECK (attempts >= 0),
  max_attempts         INT NOT NULL DEFAULT 5 CHECK (max_attempts > 0),
  next_attempt_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  locked_by            TEXT,
  locked_at            TIMESTAMPTZ,
  created_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at           TIMESTAMPTZ NOT NULL,
  delivered_at         TIMESTAMPTZ,
  retrieved_at         TIMESTAMPTZ,
  ack_token            UUID,
  dead_reason          TEXT,
  CONSTRAINT envelope_expiry CHECK (expires_at > created_at),
  CONSTRAINT envelope_locked_consistency
    CHECK ((status = 'locked') = (locked_at IS NOT NULL AND locked_by IS NOT NULL))
);

CREATE INDEX idx_envelopes_pickup
  ON envelopes (status, next_attempt_at)
  WHERE status IN ('queued','locked');

CREATE INDEX idx_envelopes_recipient
  ON envelopes (recipient_device_id, status);

CREATE INDEX idx_envelopes_expiry
  ON envelopes (expires_at)
  WHERE status NOT IN ('expired','dead');
