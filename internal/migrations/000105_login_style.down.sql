ALTER TABLE org_settings DROP CONSTRAINT IF EXISTS org_settings_login_style_check;
ALTER TABLE org_settings DROP COLUMN IF EXISTS login_style;
