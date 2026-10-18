-- 017: enrollment_tokens.used_by_device_id ON DELETE SET NULL
--
-- Session R-4 hit this: deleting a device row that had ever consumed
-- an enrollment token failed on enrollment_tokens_used_by_device_id_fkey
-- (currently NO ACTION). Test cleanup in every backend test file works
-- around this by deleting enrollment_tokens before devices:
--
--   afterAll(async () => {
--     await pool.query('DELETE FROM enrollment_tokens WHERE org_id = $1', ...);
--     await pool.query('DELETE FROM devices WHERE org_id = $1', ...);
--   });
--
-- That ordering is a workaround, not a design. The audit-preservation
-- argument for keeping the token row after device deletion is real
-- (operators can see "token X was consumed by a now-deleted device"),
-- but NO ACTION turns that into a deletion blocker instead. SET NULL
-- preserves the audit trail (token row survives, used_by nulled) while
-- allowing the device row to be removed.
--
-- `used_at` is NOT nulled -- it still records when the token was
-- consumed. Only `used_by_device_id` loses its referent, which is
-- accurate: the device is gone.
--
-- Session U-2 backlog item from R-4's §3 close. Does not change any
-- existing test's behavior (tests already delete tokens first), but
-- permits a new test that deletes devices directly.

ALTER TABLE enrollment_tokens
  DROP CONSTRAINT enrollment_tokens_used_by_device_id_fkey,
  ADD CONSTRAINT enrollment_tokens_used_by_device_id_fkey
    FOREIGN KEY (used_by_device_id) REFERENCES devices(device_id)
    ON DELETE SET NULL;
