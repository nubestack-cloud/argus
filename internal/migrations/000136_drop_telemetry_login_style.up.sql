-- The "telemetry" sign-in style is gone; two remain (aperture, sentinel).
--
-- An install that had chosen it goes back to "not chosen" (NULL), which
-- resolves to settings.DefaultLoginStyle in code, rather than being pinned to
-- whichever style happens to be the default today.
UPDATE org_settings SET login_style = NULL WHERE login_style = 'telemetry';

ALTER TABLE org_settings DROP CONSTRAINT IF EXISTS org_settings_login_style_check;
ALTER TABLE org_settings ADD CONSTRAINT org_settings_login_style_check
  CHECK (login_style IS NULL OR login_style IN ('aperture', 'sentinel'));
