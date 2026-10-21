-- Adds the operator-facing "automatic investigation" toggle this task
-- exists for: whether a newly-detected incident gets POST
-- /api/v1/incidents/{id}/analyze run against it automatically (by
-- internal/autoanalyze's poller) instead of waiting for someone to click
-- "Analyze," plus which severities qualify -- fully configurable, not a
-- hardcoded threshold.
--
-- auto_analysis_enabled follows a DIFFERENT null convention than every other
-- org_settings column added so far (migration 000018's header comment,
-- reaffirmed by 000019): it is NOT NULL DEFAULT false, not nullable-meaning-
-- "fall back to an env var." That's deliberate, not an oversight -- this is
-- a brand-new setting with no prior env-var-only existence to preserve
-- backward compatibility for (internal/settings.Config's doc comment on
-- AutoAnalysisEnabled/AutoAnalysisMinSeverity spells this out), so there is
-- no third "unconfigured, consult some other source" state to represent:
-- an installation that has never touched this setting and one that has
-- explicitly turned it off are the same thing, plain false.
--
-- auto_analysis_min_severity DOES stay nullable, but with a different
-- meaning than 000018/000019's "unconfigured" null: here, NULL is a real,
-- directly-selectable value an admin can choose on purpose -- "every
-- severity qualifies," the sensible default the moment auto-analysis is
-- turned on. It mirrors the four-value severity enum every other severity
-- column in this codebase already uses (internal/tunnel/protocol.go's
-- Finding.Severity doc comment; incidents.severity itself carries no DB
-- CHECK constraint of its own, so this column's CHECK is a deliberate,
-- extra bit of validation for a column that specifically governs whether an
-- LLM call gets triggered automatically, not a mechanical copy of an
-- existing constraint).
--
-- No new secret, so (matching 000019's same call) this doesn't change
-- org_settings' deliberate no-RLS posture (000018's comment) or add any new
-- masking logic to internal/api/settings.go's response.
ALTER TABLE org_settings
  ADD COLUMN auto_analysis_enabled     boolean NOT NULL DEFAULT false,
  ADD COLUMN auto_analysis_min_severity text
    CHECK (auto_analysis_min_severity IS NULL
           OR auto_analysis_min_severity IN ('low', 'medium', 'high', 'critical'));

-- auto_analysis_attempted_at is incidents' side of the same feature --
-- internal/autoanalyze's poller's own coordination column, the exact same
-- shape and role as notified_at (migration 000017's comment): NULL means
-- "this poller has never attempted this incident," and nothing else in the
-- codebase ever writes to it. A manual POST /incidents/{id}/analyze click
-- does NOT touch this column -- it's specifically "has the AUTOMATIC path
-- already had its one attempt," not "has this incident ever been
-- analyzed," so a person can always still click Analyze by hand regardless
-- of what this column says (see internal/autoanalyze's package doc comment
-- for the retry-policy rationale this column exists to support: attempt
-- each incident automatically at most once, ever, rather than hot-looping on
-- a broken incident every poll tick).
--
-- Nullable with no default other than NULL, same backfill rationale as
-- notified_at: every pre-existing incident on a hub upgraded onto this
-- migration starts unattempted, so it becomes eligible for auto-analysis
-- (subject to the severity/enabled settings above and whether it already
-- has an analysis) on the very next poll tick rather than being silently
-- skipped forever.
--
-- No new RLS policy needed, for the same reason 000017 needed none: a plain
-- column on an existing table (incidents) whose RLS policies already cover
-- every row regardless of column set.
ALTER TABLE incidents ADD COLUMN auto_analysis_attempted_at timestamptz;
