-- PROJECT.md M1: POST /incidents/{id}/analyze answers 202 and investigates in
-- the background, so GET /incidents/{id} reports the run — when it started
-- (analysisStartedAt) and why it failed if it did (analysisError) — and the
-- claim checks for a run already in flight. All of that is READ from the
-- incident's own timeline (the latest InvestigationStarted event, and an
-- AnalysisFailed event naming it) rather than stored a second time on
-- incidents, so it is looked up on every incident page load and every claim.
--
-- timeline_events had no index at all, so each of those lookups — and the
-- existing GET /incidents/{id}/timeline — scanned the whole table. This index
-- serves "the latest event of this type on this incident" directly and the
-- per-incident timeline listing by its leading column.
CREATE INDEX IF NOT EXISTS timeline_events_incident_type_time
  ON timeline_events (incident_id, event_type, occurred_at DESC);
