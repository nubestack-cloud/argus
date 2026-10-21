-- Three sweepers each turned an ABSENCE of evidence into a confident outcome.
-- This migration carries the schema half of the two fixes that need one.
--
-- 1. internal/autoanalyze: an automatic investigation that FAILED (provider
--    error, tunnel stall, "no usable AI provider") left the incident in
--    Investigating and stamped auto_analysis_attempted_at regardless of
--    outcome. The candidate query excludes Investigating, so the incident was
--    never retried and never moved again -- it read as "mid-investigation"
--    forever, with the reason recorded nowhere at all. Three columns replace
--    that single attempted-or-not bit with an honest record: how many times
--    the automatic path has actually tried, what went wrong last time, and
--    when it is next allowed to try. auto_analysis_attempted_at keeps its
--    original meaning unchanged -- "the automatic path is DONE with this
--    incident" -- and is now written only on a real conclusion (an analysis
--    persisted, an object confirmed gone, or the retry bound reached), never
--    on a failure that is still going to be retried.
--
-- 2. internal/orchestrator/validation.go: ValidationSweeper started from
--    targetState = Resolved and, when it could NOT re-read the applied value
--    or re-run the original rule, changed only the explanatory sentence
--    before committing Resolved anyway. A disconnected cluster therefore
--    turned "we could not tell" into "we verified it worked" -- the strongest
--    claim this product makes, on the weakest possible basis. It now keeps
--    the incident in Validating and retries; once the bound is spent it lands
--    in ValidationUnknown instead.
--
-- ValidationUnknown is a new state rather than a reuse of an existing one,
-- for exactly the reason migration 000081 gave for ExecutionUnknown: Resolved
-- asserts the fix worked, Reopened asserts it did not, Failed asserts the
-- execution failed, and NeedsHumanInvestigation asserts the INVESTIGATION
-- stopped short. All four are claims. This state is the absence of one -- the
-- change was applied and ARGUS could not confirm whether it held -- and
-- saying that plainly is the entire content of the gap it closes.
--
-- Widening incidents_state_check follows the precedent 000062 (Diagnosed) and
-- 000081 (ExecutionUnknown) already set: a new enum member needs its CHECK
-- widened explicitly; nothing does this automatically.

ALTER TABLE incidents DROP CONSTRAINT incidents_state_check;
ALTER TABLE incidents ADD CONSTRAINT incidents_state_check CHECK (state IN (
  'Detected', 'Investigating', 'RecommendationReady', 'NeedsHumanInvestigation',
  'AwaitingApproval', 'Executing', 'AwaitingMerge', 'Validating',
  'Resolved', 'Failed', 'Reopened', 'Dismissed', 'Diagnosed', 'ExecutionUnknown',
  'ValidationUnknown'
));

-- auto_analysis_attempts counts real, completed automatic attempts against
-- this incident. NOT NULL DEFAULT 0 rather than nullable: "never attempted"
-- and "attempted zero times" are the same fact here, so there is no third
-- state to represent (contrast auto_analysis_attempted_at, whose NULL does
-- carry a distinct meaning).
--
-- Deliberately NOT incremented for a hub-level configuration failure ("no
-- usable AI provider"): that is not this incident's fault and must not spend
-- this incident's budget -- internal/autoanalyze throttles its whole sweep
-- instead, so the backlog survives a misconfiguration and resumes on its own
-- the moment a provider is configured. See recordAnalysisFailure.
ALTER TABLE incidents ADD COLUMN auto_analysis_attempts integer NOT NULL DEFAULT 0;

-- The last failure's reason, kept so it survives the process that logged it.
-- Truncated at the write site, and only ever the error text this codebase
-- itself produced -- never a raw provider response body.
ALTER TABLE incidents ADD COLUMN auto_analysis_last_error text;

-- The backoff gate. NULL means "eligible now", which is also every
-- pre-existing row's value on upgrade, so nothing already in the table is
-- newly excluded by this migration. The candidate query reads it directly.
ALTER TABLE incidents ADD COLUMN auto_analysis_retry_after timestamptz;

-- Partial: the overwhelming majority of rows have NULL here, and the
-- candidate query's interest is exactly the ones that do not.
CREATE INDEX incidents_auto_analysis_retry_after_idx
  ON incidents (auto_analysis_retry_after)
  WHERE auto_analysis_retry_after IS NOT NULL;
