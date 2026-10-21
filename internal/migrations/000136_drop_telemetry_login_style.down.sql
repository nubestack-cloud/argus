-- Allows "telemetry" again. An install the up migration reset stays on the
-- default: which style it had is not recorded anywhere.
ALTER TABLE org_settings DROP CONSTRAINT IF EXISTS org_settings_login_style_check;
ALTER TABLE org_settings ADD CONSTRAINT org_settings_login_style_check
  CHECK (login_style IS NULL OR login_style IN ('aperture', 'sentinel', 'telemetry'));
