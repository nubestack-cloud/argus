ALTER TABLE org_settings
  DROP CONSTRAINT IF EXISTS org_settings_disabled_detector_ids_valid,
  DROP COLUMN IF EXISTS disabled_detector_ids,
  DROP COLUMN IF EXISTS storm_protection_max_new_incidents,
  DROP COLUMN IF EXISTS storm_protection_window_seconds;
