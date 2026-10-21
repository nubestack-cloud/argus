-- The sign-in screen's visual style, chosen by an operator in Settings.
--
-- On org_settings rather than per user, because the people it is shown to are
-- by definition NOT authenticated yet: there is no user to hang a preference
-- off when this value is read. It is an install-wide branding choice, the same
-- category as notify_webhook_url, and it is read by an unauthenticated
-- endpoint (GET /api/v1/auth/sso/providers) — which is exactly why the column
-- holds a short enum-shaped identifier and nothing else. Whatever goes in here
-- is visible to anyone who can reach the login page, so it must never become a
-- place to put a name, a hostname or a message.
--
-- NULL means "not chosen", which resolves to the default in code
-- (settings.DefaultLoginStyle) rather than being written here, so the default
-- can move without a data migration.
ALTER TABLE org_settings ADD COLUMN IF NOT EXISTS login_style text;

-- The allowed values, enforced in the database as well as in the API handler.
-- Belt and braces on purpose: this string is interpolated into a DOM attribute
-- on an unauthenticated page, so the cheapest possible guarantee that it can
-- only ever be one of four known words is worth having in two places.
ALTER TABLE org_settings DROP CONSTRAINT IF EXISTS org_settings_login_style_check;
ALTER TABLE org_settings ADD CONSTRAINT org_settings_login_style_check
  CHECK (login_style IS NULL OR login_style IN ('aperture', 'sentinel', 'telemetry'));
