-- Contact authorization matrix.
--
-- Phase 1 model: backend-enforced authorization between two devices.
-- A device can only send to (and fetch prekeys for) another device if
-- BOTH directions are status='active' in this table.
--
-- The org-signed JCS authorization matrix (Build Master §3.7, §3.8)
-- supersedes this as the source of truth later; this table remains as
-- the enforcement cache when the admin pushes a signed matrix.

CREATE TABLE contacts (
    owner_device_id UUID NOT NULL REFERENCES devices(device_id) ON DELETE CASCADE,
    contact_device_id UUID NOT NULL REFERENCES devices(device_id) ON DELETE CASCADE,
    org_id UUID NOT NULL,
    status TEXT NOT NULL
        CHECK (status IN ('pending','active','blocked','revoked'))
        DEFAULT 'active',
    verification_level TEXT NOT NULL
        CHECK (verification_level IN ('directory','qr'))
        DEFAULT 'directory',
    authorized_by UUID NOT NULL,
    authorized_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at TIMESTAMPTZ,
    revoke_reason TEXT,
    PRIMARY KEY (owner_device_id, contact_device_id),
    CONSTRAINT contacts_no_self CHECK (owner_device_id <> contact_device_id),
    CONSTRAINT contacts_revoke_consistency
        CHECK ((status = 'revoked') = (revoked_at IS NOT NULL))
);

CREATE INDEX idx_contacts_owner_active
    ON contacts (owner_device_id) WHERE status = 'active';
CREATE INDEX idx_contacts_contact_active
    ON contacts (contact_device_id) WHERE status = 'active';
CREATE INDEX idx_contacts_org
    ON contacts (org_id);
