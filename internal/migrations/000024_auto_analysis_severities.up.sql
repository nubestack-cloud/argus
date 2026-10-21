-- Replaces migration 000020's single "minimum severity" threshold with a
-- genuine checklist of individually-selectable severities -- the user asked
-- for this directly: someone might want `high` and `critical` auto-analyzed
-- but explicitly NOT `medium`, which no ordered threshold can express (a
-- threshold can only ever express a contiguous "this and everything more
-- severe" range).
--
-- auto_analysis_severities text[] is the set. text[], not jsonb: this
-- codebase already has a precedent for exactly this shape -- migration
-- 000007_repos_and_integrations's `targets`/`on_events` columns, a flat set
-- of enum-ish strings -- and that is a closer match than
-- service_principals/grants' `capability_set`/`scope` jsonb columns, which
-- hold richer, non-flat structures (a capability set keyed by resource,
-- scope objects with nested cluster/namespace fields), not a flat set of one
-- four-value enum. pgx v5 scans/encodes a Postgres text[] to/from a bare Go
-- []string natively (see internal/settings' updated Resolve/Update), so no
-- new dependency or array-codec helper is needed either.
--
-- NOT NULL DEFAULT '{}' -- unlike 000020's auto_analysis_min_severity, there
-- is no separate "every severity qualifies" sentinel value to preserve: an
-- empty array/slice already IS the natural "nothing selected" state a
-- checklist with every box unchecked visually implies, so no third
-- NULL-with-its-own-meaning state is needed the way the old column had. See
-- internal/settings.Config's doc comment for the one genuinely subtle
-- semantic decision this task makes explicit: AutoAnalysisEnabled=true with
-- an empty/nil AutoAnalysisSeverities means "nothing gets auto-analyzed,"
-- NOT "everything" -- a meaningfully different, safer default than what an
-- all-unchecked checklist might otherwise be assumed to mean, and the
-- opposite of the old column's NULL-means-everything default. An admin who
-- wants every severity auto-analyzed now has to check all four boxes
-- explicitly, same as checking any other subset.
--
-- The CHECK constraint (`<@`, PostgreSQL's array-containment operator: "is
-- every element of the left array also an element of the right array")
-- enforces the same four-value severity enum every other severity column in
-- this codebase already uses (internal/tunnel/protocol.go's Finding.Severity
-- doc comment; mirrored by 000020's own now-superseded CHECK) -- re-checked
-- at the PUT /api/v1/admin/settings boundary too (internal/api/settings.go),
-- same discipline 000020 already established for the single-value case. It
-- does not forbid duplicate entries (e.g. `{high,high}`) -- that is
-- harmless to selectEligible's set-membership check, so, matching this
-- codebase's "validate what actually matters, don't over-constrain" style,
-- duplicate rejection lives only at the API boundary (a real 400, so a
-- confused client finds out immediately) rather than as a second, more
-- elaborate DB constraint.
ALTER TABLE org_settings
  ADD COLUMN auto_analysis_severities text[] NOT NULL DEFAULT '{}';

-- Backfill: translate every existing installation's old threshold into the
-- exact equivalent contiguous set, so upgrading this migration never
-- silently changes what an already-configured hub auto-analyzes -- a
-- threshold of `high` (meaning "high and everything more severe") becomes
-- literally `{high,critical}`, not an empty checklist that would silently
-- turn auto-analysis inert for every incident. NULL (the old "every severity
-- qualifies" sentinel) becomes all four values, its exact equivalent. This
-- is the one deliberate exception to this codebase's migrations otherwise
-- never doing a data backfill (checked: no other *.up.sql here has an
-- UPDATE) -- justified specifically because the alternative (leaving the new
-- column at its all-rows-get-the-DEFAULT '{}') would silently and
-- irreversibly disable auto-analysis for any hub that had it on, which is a
-- worse outcome than one extra, well-documented UPDATE.
UPDATE org_settings SET auto_analysis_severities = CASE auto_analysis_min_severity
  WHEN 'low'      THEN ARRAY['low', 'medium', 'high', 'critical']
  WHEN 'medium'   THEN ARRAY['medium', 'high', 'critical']
  WHEN 'high'     THEN ARRAY['high', 'critical']
  WHEN 'critical' THEN ARRAY['critical']
  ELSE                 ARRAY['low', 'medium', 'high', 'critical'] -- NULL: "every severity qualifies"
END;

ALTER TABLE org_settings
  ADD CONSTRAINT org_settings_auto_analysis_severities_valid
    CHECK (auto_analysis_severities <@ ARRAY['low', 'medium', 'high', 'critical']::text[]);

-- Dropped in the same migration, not kept-around-unused: nothing else in
-- this codebase reads auto_analysis_min_severity besides the code this same
-- task is changing (internal/settings, internal/autoanalyze,
-- internal/api/settings.go, web/src/pages/SettingsPage.tsx), so there is no
-- reason to carry a dead column forward.
ALTER TABLE org_settings DROP COLUMN auto_analysis_min_severity;
