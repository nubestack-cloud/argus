-- Reverses 000040. Restores the original three-value constraint.
--
-- If any PatchResourceLimits or RevertContainerImage rows exist at rollback
-- time, this DROP+ADD will fail — correctly: silently deleting or truncating
-- real remediation-recommendation history to make a rollback succeed would
-- be a worse outcome than a rollback that stops and says why. Delete or
-- migrate those rows first if a rollback past this point is genuinely needed.
ALTER TABLE remediation_recommendations DROP CONSTRAINT remediation_recommendations_action_type_check;
ALTER TABLE remediation_recommendations ADD CONSTRAINT remediation_recommendations_action_type_check
  CHECK (action_type IN ('ScaleDeployment', 'RestartPod', 'OpenPR'));
