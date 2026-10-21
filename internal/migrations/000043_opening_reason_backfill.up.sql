-- Backfill incidents.opening_reason.
--
-- WHY THIS IS NEEDED
--
-- opening_reason was added by migration 000042 for replica-level correlation,
-- which groups on (cluster_id, workload_key, opening_reason). Because that
-- grouping needs workload_key anyway, internal/gateway/finding.go only ever
-- SET opening_reason when workload_key was non-empty — the two were written
-- from a single `if`. workload_key in turn requires the finding to name an
-- owning workload, which only the pod-conditions and sweep detectors supply;
-- the event-based detector never does.
--
-- The consequence, measured on the dev database before this ran: 143 of 152
-- incidents had opening_reason NULL. So a column whose own 000042 comment calls
-- it "independently useful for display (\"opened by: OOMKilled\")" was in fact
-- populated on 6% of rows — useless for display, and misleadingly so, since a
-- UI rendering it would show a label on a handful of rows and blanks
-- everywhere else. That reads as broken rather than as incomplete.
--
-- finding.go now sets opening_reason unconditionally (it is a property of the
-- finding that opened the incident, not of whether that finding happened to
-- resolve a workload). This migration fixes the rows already stored.
--
-- WHY THIS CANNOT AFFECT REPLICA CORRELATION
--
-- internal/replicagroup's queries match `workload_key = $2`, and SQL equality
-- never matches NULL — so an incident with an opening_reason but no
-- workload_key is invisible to that grouping, exactly as it was before.
-- Recompute is also called behind its own separate `workloadKey != ""` guard
-- (finding.go), not the one that used to gate this column. Decoupling the two
-- therefore changes what is DISPLAYED and nothing about what is GROUPED.
--
-- SOURCE OF THE BACKFILLED VALUE
--
-- The reason of the incident's EARLIEST finding, which is as close as stored
-- data gets to "the reason it opened". Not MAX(reason) or the newest: 000042
-- is explicit that workload_key and opening_reason "are set ONCE, at incident
-- creation ... they never change afterward even if a later, different-reason
-- finding updates this same incident", and a backfill that picked the latest
-- reason would quietly violate that contract for historical rows while the
-- live path honours it.
--
-- Only rows where opening_reason IS NULL are touched, so the 9 incidents that
-- already had a correctly-written value keep it. Findings recorded under storm
-- protection carry incident_id NULL and so cannot match — correct, since they
-- opened nothing.
UPDATE incidents i
   SET opening_reason = earliest.reason
  FROM (
        SELECT DISTINCT ON (incident_id) incident_id, reason
          FROM findings
         WHERE incident_id IS NOT NULL
           AND reason IS NOT NULL
           AND reason <> ''
         ORDER BY incident_id, occurred_at ASC, ingested_at ASC
       ) AS earliest
 WHERE earliest.incident_id = i.id
   AND i.opening_reason IS NULL;
