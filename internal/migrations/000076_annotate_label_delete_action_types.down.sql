ALTER TABLE remediation_recommendations DROP CONSTRAINT remediation_recommendations_action_type_check;
ALTER TABLE remediation_recommendations ADD CONSTRAINT remediation_recommendations_action_type_check
  CHECK (action_type IN ('ScaleDeployment', 'RestartPod', 'PatchResourceLimits', 'RevertContainerImage', 'PatchField', 'OpenPR', 'StructuredPatch'));
