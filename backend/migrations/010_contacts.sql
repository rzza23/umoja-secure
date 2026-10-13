-- Contact authorization matrix.
--
-- Model: symmetric. An active row (A -> B) plus an active row (B -> A)
-- constitutes a mutual authorized contact. The admin plane creates both
-- rows atomically when authorizing two devices to communicate.
--
-- This keeps the query simple (isContactAuthorized checks both rows) and
-- matches how messaging apps normally behave. Clearance is enforced by
-- which contacts the admin chooses to authorize, not by directional rules.
--
-- Verification level:
--   directory: org-signed directory entry. Medium trust.
--   qr:        user scanned the peer's identity key. High trust.
-- Key change always downgrades to unverified on the client.

CREATE TABLE contacts (
  owner_device_id     UUID NOT NULL REFERENCES devices(device_id) ON DELETE CASCADE,
  contact_device_id   UUID NOT NULL REFERENCES devices(device_id) ON DELETE CASCADE,
  org_id              UUID NOT NULL,
  status              TEXT NOT NULL DEFAULT 'active'
                      CHECK (status IN ('active', 'revoked')),
  verification_level  TEXT NOT NULL DEFAULT 'directory'
                      CHECK (verification_level IN ('directory', 'qr')),
  authorized_by       UUID NOT NULL,
  authorized_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
  revoked_at          TIMESTAMPTZ,
  revoked_by          UUID,
  revoke_reason       TEXT,
  PRIMARY KEY (owner_device_id, contact_device_id),
  CONSTRAINT contacts_self_check CHECK (owner_device_id <> contact_device_id),
  CONSTRAINT contacts_revoke_consistency
    CHECK ((status = 'revoked') = (revoked_at IS NOT NULL))
);

CREATE INDEX idx_contacts_owner_active ON contacts (owner_device_id)
  WHERE status = 'active';
CREATE INDEX idx_contacts_contact_active ON contacts (contact_device_id)
  WHERE status = 'active';
CREATE INDEX idx_contacts_org ON contacts (org_id);
