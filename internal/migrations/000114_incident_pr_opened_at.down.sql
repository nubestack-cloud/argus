-- Drops the column and, with it, the backfill: the timeline_events rows the
-- backfill read are untouched, so re-applying the up migration reconstructs
-- exactly the same values. Nothing else depends on this column.
ALTER TABLE incidents DROP COLUMN pr_opened_at;
