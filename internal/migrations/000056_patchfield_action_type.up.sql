-- Add PatchField to the action_type CHECK constraint.
--
-- **This is the second time this exact bug has happened**, which is the only
-- interesting thing about the migration. Migration 000040 exists because
-- PatchResourceLimits and RevertContainerImage were built with, in its own words,
-- "full Go-side support" and never added here. PatchField was then built the same
-- way — action type, permission allowlist, params marshalling, agent tool,
-- execution-tool mapping, tests at every layer — and the first attempt to persist
-- one failed with the identical error:
--
--   ERROR: new row for relation "remediation_recommendations" violates
--   check constraint "remediation_recommendations_action_type_check"
--
-- 000040 fixed the instance and left nothing behind to catch a recurrence, so the
-- recurrence arrived. A migration cannot prevent the next one either, so this time
-- the guard goes with it: TestActionTypeCheckConstraintAcceptsEveryActionType
-- drives the real constraint from remediation.AllActionTypes() and fails when a
-- new type is added without a migration.
--
-- Why the constraint exists at all rather than trusting the Go enum: this table is
-- written by the analysis path and read by the approval and execution paths, and a
-- row naming a type nothing can execute is a plan that reaches an approver and then
-- cannot run. The constraint makes that unrepresentable at rest, including against
-- a direct SQL edit.
ALTER TABLE remediation_recommendations DROP CONSTRAINT remediation_recommendations_action_type_check;
ALTER TABLE remediation_recommendations ADD CONSTRAINT remediation_recommendations_action_type_check
  CHECK (action_type IN ('ScaleDeployment', 'RestartPod', 'PatchResourceLimits', 'RevertContainerImage', 'PatchField', 'OpenPR'));
