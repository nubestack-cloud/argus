-- BACKLOG.md C6: nothing recorded whether an analysis was triggered by a
-- human (POST /incidents/{id}/analyze) or by internal/autoanalyze.Poller's
-- unattended sweep. The only existing proxy,
-- incidents.auto_analysis_attempted_at, lives on the INCIDENT rather than
-- the ANALYSIS, is set unconditionally regardless of the investigation's
-- outcome (success, partial, or failure alike), and was never surfaced via
-- GET /incidents/{id} or the UI at all.
--
-- Nullable, and deliberately NOT backfilled — unlike cost_basis (migration
-- 000033), where every pre-existing row was truthfully known to have come
-- from the one backend that existed at the time ('metered'), there is no
-- honest way to attribute a historical analyses row between manual and auto
-- after the fact. The only available proxy is exactly the fragile join
-- BACKLOG C6's own "fix shape" note rejected: matching an analysis's
-- created_at against incidents.auto_analysis_attempted_at would misattribute
-- a manual re-analyze run after an earlier automatic one. NULL means
-- "written before this column existed, attribution unknown" — never
-- guessed at (see argus-context's "never fabricate" discipline).
--
-- Every future INSERT goes through internal/api.PersistAnalysis — the one
-- function both handleAnalyzeIncident (manual) and internal/autoanalyze.Poller
-- (auto) call to write an analyses row — which now requires callers to pass
-- one of the two values below explicitly.
ALTER TABLE analyses
  ADD COLUMN triggered_by text
    CHECK (triggered_by IS NULL OR triggered_by IN ('manual', 'auto'));
