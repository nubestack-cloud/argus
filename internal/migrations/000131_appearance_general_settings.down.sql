-- Rolling back returns every installation to the behaviour before this
-- migration: OverviewPage always starts at 14 days, the UI is always teal,
-- the self-service password floor is the hardcoded 12-character constant, and
-- refresh tokens never expire early for inactivity — the exact defaults each
-- column above carried, so nothing here is a behaviour change beyond "no
-- longer operator-adjustable."
ALTER TABLE org_settings DROP CONSTRAINT IF EXISTS org_settings_session_idle_timeout_minutes_check;
ALTER TABLE org_settings DROP COLUMN IF EXISTS session_idle_timeout_minutes;
ALTER TABLE org_settings DROP CONSTRAINT IF EXISTS org_settings_min_password_length_check;
ALTER TABLE org_settings DROP COLUMN IF EXISTS min_password_length;
ALTER TABLE org_settings DROP CONSTRAINT IF EXISTS org_settings_primary_color_id_check;
ALTER TABLE org_settings DROP COLUMN IF EXISTS primary_color_id;
ALTER TABLE org_settings DROP CONSTRAINT IF EXISTS org_settings_overview_default_window_days_check;
ALTER TABLE org_settings DROP COLUMN IF EXISTS overview_default_window_days;
