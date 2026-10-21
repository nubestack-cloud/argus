ALTER TABLE org_settings
  DROP COLUMN IF EXISTS audit_retention_days,
  DROP COLUMN IF EXISTS incident_retention_days,
  DROP COLUMN IF EXISTS finding_retention_days;
