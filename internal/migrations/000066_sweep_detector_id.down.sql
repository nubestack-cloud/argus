-- Reverses 000066. Restores the original two-value constraint.
--
-- If any row's disabled_detector_ids already contains 'k8s-sweep' at
-- rollback time, this DROP+ADD will fail -- correctly: silently dropping a
-- value out of an operator's stored configuration to make a rollback
-- succeed would be a worse outcome than a rollback that stops and says why.
-- Clear it from org_settings.disabled_detector_ids first if a rollback past
-- this point is genuinely needed. Same reasoning as 000040's down migration.
ALTER TABLE org_settings DROP CONSTRAINT org_settings_disabled_detector_ids_valid;
ALTER TABLE org_settings ADD CONSTRAINT org_settings_disabled_detector_ids_valid
  CHECK (disabled_detector_ids <@ ARRAY['k8s-warning-events', 'k8s-pod-conditions']::text[]);
