-- PROJECT.md F31: GET /api/v1/findings' "suppressed" disposition cannot say
-- WHICH of the two things that can suppress a promotable finding actually
-- did — internal/api/findings.go's own doc comment states this plainly:
-- "The row cannot say WHICH of those two suppressed it — nothing durable
-- records that distinction". That answer existed only in audit_events, one
-- row per suppression, named finding_suppressed_by_toleration or
-- storm_protection_suppressed_new_incident — readable, but only by an
-- operator who already holds audit:read and is willing to go look, for
-- every single suppressed row on the Signals screen one at a time.
--
-- This column makes the finding row say it directly, going forward.
-- internal/gateway/finding.go's handleFinding sets it exactly once, at
-- INSERT, alongside the SAME toleration/storm-protection branch that already
-- writes the audit event — so the two can never disagree about which fired,
-- because they are set from the same local variable in the same
-- transaction. See finding.go's suppressionReasonToleration/
-- suppressionReasonStormProtection for the closed vocabulary.
--
-- NULL for every finding that is not suppressed (correlated, and
-- retained_unpromoted), and — because this is written at INSERT time only,
-- never backfilled — also NULL for every suppressed finding recorded before
-- this migration. internal/api/findings.go's disposition derivation
-- (findingDispositionOf) does not read this column at all: "suppressed" is
-- still derived exactly as before (incident_id IS NULL AND promotable), so a
-- pre-migration suppressed row keeps its disposition and simply carries no
-- reason, which the UI must render as "not recorded" rather than guessing.
ALTER TABLE findings
  ADD COLUMN suppression_reason text
    CHECK (suppression_reason IN ('toleration', 'storm_protection'));
