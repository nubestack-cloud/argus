DROP INDEX IF EXISTS incidents_workload_key_idx;
DROP INDEX IF EXISTS incidents_workload_group_idx;
ALTER TABLE incidents DROP COLUMN workload_group_id;
ALTER TABLE incidents DROP COLUMN opening_reason;
ALTER TABLE incidents DROP COLUMN workload_key;
