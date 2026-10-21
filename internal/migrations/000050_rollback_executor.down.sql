-- Reversible. The compensating actions themselves are not lost by this: they are
-- still in each execution's audit event, where they were before this migration —
-- which is exactly the arrangement this migration existed to improve on, so a
-- rollback here restores a working-but-worse state rather than a broken one.
DROP INDEX IF EXISTS remediation_executions_undoable_idx;
ALTER TABLE remediation_executions
  DROP CONSTRAINT IF EXISTS remediation_executions_rollback_complete;
ALTER TABLE remediation_executions
  DROP COLUMN IF EXISTS forward_applied_value,
  DROP COLUMN IF EXISTS rolled_back_by_execution_id,
  DROP COLUMN IF EXISTS rollback_description,
  DROP COLUMN IF EXISTS rollback_params,
  DROP COLUMN IF EXISTS rollback_action_type;
