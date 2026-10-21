-- org_settings' Appearance and General sections, PROJECT.md 2026-10-14.
--
-- OVERVIEW_DEFAULT_WINDOW_DAYS. OverviewPage's "incidents opened" window has
-- always had exactly two selectable values, 14 and 30 (web/src/pages/
-- OverviewPage.tsx's segmented control), hardcoded client-side to always start
-- at 14. This is that default, promoted to an org-wide, admin-set preference —
-- the CHECK mirrors the UI's own closed set rather than accepting an arbitrary
-- day count, because the segmented control has nowhere to render a third
-- option and a value outside {14, 30} would have to fall back to one of them
-- silently anyway.
--
-- PRIMARY_COLOR_ID. Which of index.css's named `data-accent` presets
-- (web/src/index.css's "Primary colour presets" block) the whole app renders
-- with. An id, not a stored colour: the actual hex values — and their
-- measured contrast ratios — live only in index.css, so this column can never
-- drift out of sync with what a preset actually looks like, and an operator
-- can never set an uncalibrated colour that fails WCAG by typing one in.
-- 'teal' is the shipped default (#3c7d7d, unchanged from before this
-- migration) and needs no CSS attribute at all — see index.css's base --accent
-- block.
--
-- MIN_PASSWORD_LENGTH. Was internal/authz.MinPasswordLength, a hardcoded
-- constant of 12, enforced only on the one self-service change-password path
-- (internal/api/auth.go's handleChangePassword) — the admin-set-password and
-- bootstrap paths generate their own high-entropy passwords and have always
-- bypassed it by design (see password.go's doc comment). This column replaces
-- the constant as the live, operator-adjustable floor for that one path;
-- authz.MinPasswordLength stays as the DEFAULT and as the fallback a caller
-- with no DB access (migration tooling, tests) still gets. 8–128 bounds a
-- deliberately generous range: below 8 is not a meaningful floor for anything
-- NIST-influenced, and above 128 serves no purpose this product has.
--
-- SESSION_IDLE_TIMEOUT_MINUTES. Null means "no idle limit" — today's exact
-- behaviour (a refresh token is good for its full 30-day
-- authz.RefreshTokenTTL regardless of activity) — matching the nil-means-off
-- convention retention/detection/cost already use on this table. When set,
-- authz.RotateRefreshTokenDetailed compares it against the PRESENTED token's
-- own issued_at (no new column needed: a token is re-minted at every rotation,
-- so issued_at IS "when this chain was last actively used") and refuses
-- rotation once that gap is exceeded, ending the chain the same way a reused
-- token does. 5 minutes to 7 days (10080) bounds it to something an operator
-- could plausibly want; a tighter or looser number than either end is almost
-- certainly a typo, not a policy.
ALTER TABLE org_settings
  ADD COLUMN overview_default_window_days smallint NOT NULL DEFAULT 14
    CONSTRAINT org_settings_overview_default_window_days_check
    CHECK (overview_default_window_days IN (14, 30)),
  ADD COLUMN primary_color_id text NOT NULL DEFAULT 'teal'
    CONSTRAINT org_settings_primary_color_id_check
    CHECK (primary_color_id IN ('teal', 'blue', 'violet', 'slate', 'forest')),
  ADD COLUMN min_password_length smallint NOT NULL DEFAULT 12
    CONSTRAINT org_settings_min_password_length_check
    CHECK (min_password_length BETWEEN 8 AND 128),
  ADD COLUMN session_idle_timeout_minutes integer
    CONSTRAINT org_settings_session_idle_timeout_minutes_check
    CHECK (session_idle_timeout_minutes IS NULL
           OR session_idle_timeout_minutes BETWEEN 5 AND 10080);
