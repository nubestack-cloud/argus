-- incident_tolerations.incident_id — the incident a rule was created FROM.
--
-- WHY THIS EXISTS, GIVEN THAT 000041 DELIBERATELY DID NOT HAVE IT
--
-- A toleration is always created from one already-open incident an operator
-- has looked at (internal/api/tolerations.go's handleTolerateIncident, which
-- dismisses that incident in the same transaction), so the link has always
-- been a real fact about the row — it was simply never stored, because the
-- first two rounds of work on this page did not need it:
--
--   * WORKLOG §129 argued for this column and was talked out of it. §130's
--     reshape then showed the page's real question — "what error is being
--     silenced here?" — is answered better WITHOUT it, by the findings the
--     rule has actually suppressed (findings rows with incident_id NULL,
--     already stored, already exactly attributable). That reasoning still
--     holds: those are live, the incident is closed and historical.
--
--   * BUGS.md item 37 asks for something those suppressed findings cannot
--     supply at all. A finding carries a reason and a message; it does not
--     carry WHY the condition is expected, and it does not carry the
--     remediation ARGUS had proposed. Both of those live on the originating
--     incident — analyses.root_cause and the remediation_recommendations row
--     joined through it — and there is no other path from a toleration to
--     either of them. Object key plus reason would find *an* incident on the
--     same object, not the one this decision was made about.
--
-- So this is not a re-litigation of §130: the suppressed-findings panel stays
-- exactly as it is, and this column adds the half of the story that is only
-- reachable from the incident.
--
-- WHY IT IS NULLABLE
--
-- Three cases that are all normal rather than broken, and must render as "not
-- recorded" instead of blocking a row from existing:
--
--   1. Every row created before this migration (see the backfill below —
--      recoverable only where the audit trail names the incident).
--   2. A rule whose incident has aged out of the retention window
--      (`incidents` is range-partitioned on first_seen; dropping a partition
--      is how retention is enforced, lld/05-data-model.md §9), while the rule
--      itself is open-ended and outlives it.
--   3. Any rule created outside handleTolerateIncident.
--
-- NO FOREIGN KEY, AND THIS IS NOT AN OMISSION
--
-- `incidents` is PARTITION BY RANGE (first_seen) with PRIMARY KEY
-- (id, first_seen) — there is no unique constraint on id alone, so no column
-- can reference it. findings.incident_id (000004) and analyses.incident_id
-- (000005) are plain text columns for exactly the same reason; this matches
-- them rather than inventing a new convention.
--
-- NO INDEX, DELIBERATELY
--
-- Nothing queries tolerations BY incident: the only traversal is
-- toleration → incident, which uses the incidents primary key. Adding an
-- index here would cost every insert and serve no read. The hot path
-- (internal/gateway/finding.go's "is there an active rule for this
-- (cluster, object)") is unchanged and still served by
-- incident_tolerations_active_idx.
--
-- SOURCE OF THE BACKFILLED VALUE
--
-- handleTolerateIncident's own audit event, which has recorded
-- details->>'incidentId' alongside details->>'tolerationId' since the feature
-- shipped (000041/WORKLOG §110) — the tamper-evident record of the decision
-- itself, and the only stored source that names the exact incident rather
-- than guessing at one.
--
-- Filtered on details->>'action' = 'tolerate_incident' specifically, not on
-- the presence of a tolerationId key: the suppression trail
-- (details->>'event' = 'finding_suppressed_by_toleration') carries a
-- tolerationId too and carries no incidentId at all, and on the dev database
-- it outnumbers the creation events 107 to 1.
--
-- DISTINCT ON (..., occurred_at ASC) picks the FIRST creation event for a
-- given rule id. Rule ids are ULIDs and never reused, so this is
-- one-row-per-rule in practice; the ordering makes that deterministic rather
-- than relying on it.
--
-- Measured on the dev database before this ran: 2 rows, 1 recoverable. The
-- other is a hand-inserted row from the original DELETE round-trip test
-- (WORKLOG §110's verification step) — no API call created it, so no audit
-- event names its incident, and it correctly stays NULL. A backfill that
-- reached for (cluster_id, object_key) to fill that gap would be attributing
-- a decision to an incident nobody recorded it against, which is worse than
-- the honest blank the API and UI already handle.
ALTER TABLE incident_tolerations ADD COLUMN incident_id text;

UPDATE incident_tolerations t
   SET incident_id = created.incident_id
  FROM (
        SELECT DISTINCT ON (details->>'tolerationId')
               details->>'tolerationId' AS toleration_id,
               details->>'incidentId'   AS incident_id
          FROM audit_events
         WHERE details->>'action' = 'tolerate_incident'
           AND details->>'tolerationId' IS NOT NULL
           AND details->>'incidentId' IS NOT NULL
         ORDER BY details->>'tolerationId', occurred_at ASC
       ) AS created
 WHERE created.toleration_id = t.id
   AND t.incident_id IS NULL;
