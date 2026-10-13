-- Reconcile contacts schema.
--
-- The dev DB was migrated with an earlier version of 010 that included
-- a revoked_by column. The file on disk (migrations/010_contacts.sql)
-- does not include it, so a fresh test DB (which drops public and
-- re-applies from file) lacks the column.
--
-- This migration adds the column if missing. It is idempotent: on the
-- dev DB it is a no-op because the column already exists.
--
-- Per Build Master §7, applied migrations are immutable. Reconcile with
-- a new migration rather than editing 010.

ALTER TABLE contacts ADD COLUMN IF NOT EXISTS revoked_by UUID;
