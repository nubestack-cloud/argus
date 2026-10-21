-- Add CreateResource to the action_type CHECK constraint.
--
-- BACKLOG.md F9's last genuinely-buildable remaining action type
-- (replaceResource stays explicitly out of scope — see that entry's own
-- text). This is the exact widening step migrations 000040, 000056, 000072
-- and 000076 each already had to make for their own new
-- internal/remediation.ActionType values, and F9's own text names this step
-- specifically as the one "forgotten twice" — guarded against a repeat by
-- TestActionTypeCheckConstraintAcceptsEveryActionType
-- (internal/orchestrator/actiontype_constraint_db_test.go), which drives the
-- real constraint from remediation.AllActionTypes() rather than a
-- hand-copied list — this migration is what makes that test pass for
-- CreateResource rather than fail loudly.
ALTER TABLE remediation_recommendations DROP CONSTRAINT remediation_recommendations_action_type_check;
ALTER TABLE remediation_recommendations ADD CONSTRAINT remediation_recommendations_action_type_check
  CHECK (action_type IN ('ScaleDeployment', 'RestartPod', 'PatchResourceLimits', 'RevertContainerImage', 'PatchField', 'OpenPR', 'StructuredPatch', 'AnnotateResource', 'LabelResource', 'DeleteResource', 'CreateResource'));
