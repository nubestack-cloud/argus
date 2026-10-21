ALTER TABLE org_settings
  DROP COLUMN IF EXISTS analysis_max_iterations,
  DROP COLUMN IF EXISTS analysis_time_limit_seconds;
