-- PROJECT.md PG15: add CordonNode and DrainNode to the action_type CHECK
-- constraint, the same widening 000040/000056/000072/000076/000079 each made
-- for their own new action types. TestActionTypeCheckConstraintAcceptsEveryActionType
-- drives the real constraint from remediation.AllActionTypes().
ALTER TABLE remediation_recommendations DROP CONSTRAINT remediation_recommendations_action_type_check;
ALTER TABLE remediation_recommendations ADD CONSTRAINT remediation_recommendations_action_type_check
  CHECK (action_type IN ('ScaleDeployment', 'RestartPod', 'PatchResourceLimits', 'RevertContainerImage', 'PatchField', 'OpenPR', 'StructuredPatch', 'AnnotateResource', 'LabelResource', 'DeleteResource', 'CreateResource', 'CordonNode', 'DrainNode'));
