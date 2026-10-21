-- Add AnnotateResource, LabelResource and DeleteResource to the action_type
-- CHECK constraint.
--
-- BACKLOG.md F9's three genuinely-buildable remaining action types
-- (createResource/replaceResource stay explicitly out of scope — see that
-- entry's own text). This is the exact widening step migrations 000040,
-- 000056 and 000072 each already had to make for their own new
-- internal/remediation.ActionType values, and F9's own text names this step
-- specifically: "migration 000040 exists only because [this step] was
-- forgotten twice, and it fails silently until production." Guarded against
-- a repeat by TestActionTypeCheckConstraintAcceptsEveryActionType
-- (internal/orchestrator/actiontype_constraint_db_test.go), which drives the
-- real constraint from remediation.AllActionTypes() rather than a
-- hand-copied list — this migration is what makes that test pass for these
-- three rather than fail loudly.
ALTER TABLE remediation_recommendations DROP CONSTRAINT remediation_recommendations_action_type_check;
ALTER TABLE remediation_recommendations ADD CONSTRAINT remediation_recommendations_action_type_check
  CHECK (action_type IN ('ScaleDeployment', 'RestartPod', 'PatchResourceLimits', 'RevertContainerImage', 'PatchField', 'OpenPR', 'StructuredPatch', 'AnnotateResource', 'LabelResource', 'DeleteResource'));
