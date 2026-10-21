-- Reverses 000036. Dropping the column drops its index with it, but the index
-- is dropped explicitly first so this file reads as the exact inverse of the up
-- migration rather than relying on a cascade.
--
-- Note what rolling back actually costs: correlation reverts to fingerprint-only,
-- so incidents that had accumulated findings for several reasons on one object
-- keep those findings (findings.incident_id is untouched here) but new findings
-- for those same objects will open separate incidents again. No data is lost;
-- the grouping just stops being applied going forward.
DROP INDEX IF EXISTS incidents_object_key_idx;
ALTER TABLE incidents DROP COLUMN IF EXISTS object_key;
