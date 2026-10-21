-- Reversible, unlike 000043's data-only backfill: the column this adds is the
-- only place the backfilled value lives, so dropping it removes both the
-- schema change and the data in one step, leaving 000041's table exactly as it
-- was. The audit events the backfill read from are untouched, so re-applying
-- 000044 recovers the same values.
ALTER TABLE incident_tolerations DROP COLUMN incident_id;
