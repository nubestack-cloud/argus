-- Adds the first real, hub-side, live-editable configuration for the
-- detection layer (internal/agent/detector.go, pod_conditions_detector.go,
-- internal/gateway/finding.go) -- closing a gap STATUS.md's Phase 1 row has
-- flagged across many rounds: "the fuller detection framework
-- (RemediationPolicy CRD, dedup/storm-protection, multi-detector precedence
-- -- today both detectors are hardcoded, not policy-driven)."
--
-- This is deliberately NOT the RemediationPolicy CRD lld/06-detection-framework.md
-- §6-7 describes -- that's real, separate, cluster-side controller
-- infrastructure, out of scope here. This is the pragmatic hub-side slice:
-- two genuinely new controls internal/gateway/finding.go's handleFinding
-- enforces on findings AFTER an agent has already sent them (see that file's
-- updated doc comment for exactly why hub-side filtering, not agent-side
-- suppression, is what "disabling a detector" means today -- there is no
-- hub-to-agent config-push path in internal/tunnel's protocol yet).
--
-- disabled_detector_ids: which detector IDs' findings the hub drops before
-- they are ever recorded or become an incident. text[], not a bespoke
-- boolean-per-detector pair of columns, so a future third detector doesn't
-- need its own migration to become disable-able through this same
-- mechanism -- only the CHECK constraint's allowed-values list needs
-- extending when a new detector ID is introduced (mirrors migration
-- 000024_auto_analysis_severities' enum-locked text[] approach exactly).
-- Empty array (the default) means "every detector's findings are accepted"
-- -- today's actual behavior, unchanged until an admin opts a detector out.
-- The two values below must exactly match
-- internal/agent/detector.go's warningEventsDetectorID and
-- internal/agent/pod_conditions_detector.go's podConditionsDetectorID
-- constants (also mirrored in internal/api/settings.go's
-- validDetectorIDs) -- there is no single shared Go constant across the
-- agent/hub module boundary to enforce this instead (the agent and hub are
-- different deployables; internal/tunnel.Finding.DetectorID is the wire
-- contract that ties them together, not a shared enum type).
--
-- storm_protection_max_new_incidents / storm_protection_window_seconds:
-- lld/06-detection-framework.md's own storm-protection ceiling (STATUS.md's
-- repeated gap note), scoped down to the concrete, real thing this task
-- builds: if a cluster has already produced storm_protection_max_new_incidents
-- brand-new (not-yet-seen) incidents within the trailing
-- storm_protection_window_seconds, internal/gateway's handleFinding stops
-- creating further new incidents from that cluster for the remainder of the
-- window (existing incidents still update normally; the finding itself is
-- still recorded, with incident_id left NULL, not silently dropped -- see
-- that file's updated doc comment).
--
-- All three columns default to "off"/unlimited (empty array, NULL, NULL) --
-- following the exact precedent set by migration 000021's retention columns
-- and 000020's original auto-analysis threshold: a NEW behavior that could
-- change what an already-running installation does (here: incidents that
-- would otherwise have been created silently aren't) ships opt-in, never a
-- surprise sprung by an unrelated upgrade. An admin who wants storm
-- protection has to turn it on explicitly, exactly like retention.
--
-- storm_protection_max_new_incidents and storm_protection_window_seconds are
-- deliberately NOT cross-validated against each other by a CHECK constraint
-- here (Postgres CHECK constraints can reference multiple columns, but
-- "both null or both non-null" is exactly the kind of rule this codebase
-- already puts at the API boundary instead of the schema layer when the
-- DB-level version would be awkward to express cleanly -- see migration
-- 000024's comment on duplicate-severity rejection for the identical
-- reasoning) -- internal/api/settings.go's PUT handler rejects "one set,
-- other missing" with a real 400, directly implementing
-- lld/06-detection-framework.md §7's own validation rule ("a
-- dedup.windowSeconds of zero or unset alongside a nonzero minOccurrences
-- ... is meaningless and silently never fires -- better to reject").
--
-- No env-var fallback tier for any of these three columns, matching
-- auto_analysis_enabled/auto_analysis_severities' precedent
-- (internal/settings.Config's doc comment) -- brand-new settings with no
-- prior ARGUS_DETECTION_* env var whose behavior needs preserving.
ALTER TABLE org_settings
  ADD COLUMN disabled_detector_ids text[] NOT NULL DEFAULT '{}',
  ADD COLUMN storm_protection_max_new_incidents int
    CHECK (storm_protection_max_new_incidents IS NULL OR storm_protection_max_new_incidents > 0),
  ADD COLUMN storm_protection_window_seconds int
    CHECK (storm_protection_window_seconds IS NULL OR storm_protection_window_seconds > 0);

ALTER TABLE org_settings
  ADD CONSTRAINT org_settings_disabled_detector_ids_valid
    CHECK (disabled_detector_ids <@ ARRAY['k8s-warning-events', 'k8s-pod-conditions']::text[]);
