-- Migration 014: enrollment_matrix_version_floor on enrollment_tokens.
--
-- Per TASK-P1-030 sub-task 3b: when a token is issued, stamp the
-- current authorization-matrix version (org_matrix_versions.current_version)
-- as a floor. Floor semantics apply only to tokens issued after this
-- migration; pre-existing tokens have NULL (no floor constraint).
--
-- Nullable by design: the first device in a fresh org enrolls before
-- any version has been asserted, so there is nothing to floor against.
-- The CHECK enforces positivity when the value is present.

ALTER TABLE enrollment_tokens
  ADD COLUMN enrollment_matrix_version_floor INTEGER
    CHECK (enrollment_matrix_version_floor IS NULL OR enrollment_matrix_version_floor >= 1);
