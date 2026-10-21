ALTER TABLE org_settings
  DROP CONSTRAINT IF EXISTS org_settings_autonomy_breaker_window_seconds_check,
  DROP CONSTRAINT IF EXISTS org_settings_autonomy_breaker_fleet_wide_check,
  DROP CONSTRAINT IF EXISTS org_settings_autonomy_breaker_per_cluster_check;

ALTER TABLE org_settings
  DROP COLUMN IF EXISTS autonomy_breaker_window_seconds,
  DROP COLUMN IF EXISTS autonomy_breaker_fleet_wide,
  DROP COLUMN IF EXISTS autonomy_breaker_per_cluster,
  DROP COLUMN IF EXISTS autonomy_breaker_enabled;

DROP TABLE IF EXISTS circuit_breaker_trips;
