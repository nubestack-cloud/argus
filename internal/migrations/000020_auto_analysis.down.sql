ALTER TABLE incidents DROP COLUMN auto_analysis_attempted_at;
ALTER TABLE org_settings
  DROP COLUMN auto_analysis_enabled,
  DROP COLUMN auto_analysis_min_severity;
