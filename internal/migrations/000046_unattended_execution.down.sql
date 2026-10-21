-- Reversible. Dropping the switch returns the installation to "every execution
-- needs a human", which is the safe direction for a rollback to take.
DROP INDEX IF EXISTS remediation_executions_unattended_recent_idx;
ALTER TABLE remediation_executions DROP COLUMN IF EXISTS unattended;
ALTER TABLE org_settings
  DROP COLUMN IF EXISTS autonomy_unattended_execution_enabled,
  DROP COLUMN IF EXISTS autonomy_max_unattended_per_cluster,
  DROP COLUMN IF EXISTS autonomy_max_unattended_fleet_wide,
  DROP COLUMN IF EXISTS autonomy_unattended_window_seconds;
