-- Widen org_settings_disabled_detector_ids_valid (migration 000026) to admit
-- 'k8s-sweep' -- BUGS.md 83.
--
-- internal/agent/sweep_detector.go's third Detection Controller (a periodic
-- List-based sweep, not a watch) has sent Findings with
-- DetectorID: "k8s-sweep" (its own sweepDetectorID constant) since it was
-- built, covering 13 checks (replica-count shortfalls, wedged PVCs, failed
-- Jobs, NotReady/pressured Nodes, blocked HPAs, endpoint-less Services,
-- missing Ingress backends) -- but this constraint, internal/api/settings.go's
-- knownDetectorIDs, and its own error message never learned the ID. An
-- operator who wanted to silence a noisy sweep check the same way they can
-- already silence k8s-warning-events or k8s-pod-conditions had no way to:
-- the PUT /api/v1/admin/settings request was rejected before it ever reached
-- this constraint.
--
-- Same drop-and-recreate shape 000040/000056 already established for
-- widening this exact kind of CHECK -- Postgres has no ALTER ... ADD
-- CONSTRAINT variant that widens an existing CHECK's value set in place.
--
-- internal/gateway/finding.go's handleFinding doc comment already explains
-- why this is a hub-side-only filter: the agent keeps running the sweep
-- detector regardless of this setting (there is no hub-to-agent config-push
-- path in internal/tunnel's protocol), the hub just drops what it already
-- received before it becomes a findings row or an incident. Nothing about
-- that mechanism changes here -- this migration only lets 'k8s-sweep' name
-- itself in the set handleFinding's filter already checks membership
-- against.
ALTER TABLE org_settings DROP CONSTRAINT org_settings_disabled_detector_ids_valid;
ALTER TABLE org_settings ADD CONSTRAINT org_settings_disabled_detector_ids_valid
  CHECK (disabled_detector_ids <@ ARRAY['k8s-warning-events', 'k8s-pod-conditions', 'k8s-sweep']::text[]);
