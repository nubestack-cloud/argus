DROP INDEX IF EXISTS incidents_related_workload_key_idx;
DROP INDEX IF EXISTS incidents_object_group_idx;
ALTER TABLE incidents DROP COLUMN object_group_id;
ALTER TABLE incidents DROP COLUMN related_workload_key;
