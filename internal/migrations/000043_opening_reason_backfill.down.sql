-- Irreversible by design, and a no-op rather than a lie.
--
-- The up migration filled in a display value that was missing because of a
-- coding bug, not because of a schema decision. There is no way to tell a
-- backfilled opening_reason from one the live path wrote, and no reason to
-- want to: clearing every value would throw away the 9 rows that were always
-- correct along with the 137 that were repaired.
--
-- Rolling back the SCHEMA that owns this column is migration 000042's down.
SELECT 1;
