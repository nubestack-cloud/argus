-- Adds the investigation loop's two bounds (internal/llm/toolloop.go's
-- Investigate: max model round-trips, wall-clock time limit) to org_settings,
-- closing the gap WORKLOG.md §25 flagged explicitly: those bounds were
-- ARGUS_ANALYSIS_MAX_ITERATIONS/ARGUS_ANALYSIS_TIME_LIMIT_SECONDS env vars
-- only, read fresh per call but with no live-editable-via-API path the way
-- the LLM base URL/model already have (internal/settings,
-- PUT /api/v1/admin/settings).
--
-- Same convention every other org_settings column already uses (migration
-- 000018_org_settings.up.sql's header comment), applied consistently rather
-- than reinvented for these two: NULL means "not set in the DB, fall back to
-- the env var, then internal/llm's own hardcoded default
-- (defaultMaxIterations/defaultTimeLimit in toolloop.go)." A cleared value
-- (PUT with the field present as JSON null) is also stored as NULL, for the
-- same reason 000018 already establishes -- there is no distinct "keep a
-- literal zero/negative" state in this design, and resolveBounds has always
-- treated a non-positive value as invalid input anyway.
--
-- No new secret here (these are plain tuning numbers, not credentials), so
-- unlike llm_api_key/notify_webhook_url this doesn't change org_settings'
-- deliberate no-RLS posture (000018's comment) or add any new masking logic
-- to internal/api/settings.go's response -- the actual configured value (or
-- lack of one) is safe to return as-is over GET.
ALTER TABLE org_settings
  ADD COLUMN analysis_max_iterations     int,
  ADD COLUMN analysis_time_limit_seconds int;
