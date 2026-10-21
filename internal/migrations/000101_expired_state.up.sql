-- PROJECT.md T2, decided 2026-09-07: a distinct Expired outcome for a BULK
-- or AUTOMATIC closure ("ARGUS would no longer raise an incident for any of
-- these"), as opposed to Dismissed, which after this migration means only
-- "a named person looked at THIS incident and decided it did not need
-- action." internal/orchestrator/state.go's StateExpired doc comment has
-- the full argument; this migration does the two things that argument
-- requires: widen the enum, and reclassify the rows that were already
-- closed under the mechanism this state now names honestly.
--
-- Widening incidents_state_check follows the precedent 000062 (Diagnosed),
-- 000081 (ExecutionUnknown), 000094 (ValidationUnknown) and 000095
-- (PlanRejected) already set.
ALTER TABLE incidents DROP CONSTRAINT incidents_state_check;
ALTER TABLE incidents ADD CONSTRAINT incidents_state_check CHECK (state IN (
  'Detected', 'Investigating', 'RecommendationReady', 'NeedsHumanInvestigation',
  'AwaitingApproval', 'Executing', 'AwaitingMerge', 'Validating',
  'Resolved', 'Failed', 'Reopened', 'Dismissed', 'Diagnosed', 'ExecutionUnknown',
  'ValidationUnknown', 'PlanRejected', 'Expired'
));

-- Reclassification, not a fresh judgement call — this is the one part of
-- 000095's own "deliberately NOT backfilled" precedent that does NOT apply
-- here, and the reason is structural, not a change of heart: 000095 (Plan
-- Rejected) had no durable, machine-readable way to tell which historical
-- Dismissed rows were really a plan rejection versus an ordinary human
-- dismissal, so guessing from history was exactly the thing that migration
-- refused to do. This one has such a key: internal/api/
-- incident_promotion_reconcile.go's promotionReconcileClose has, since it
-- was written, recorded 'promotion_evidence_reconciliation' on the timeline
-- event's own detail->>'reason' for every incident it ever closed — the
-- bulk mechanism this state exists to name, with no ambiguity about which
-- rows went through it. Reclassifying THOSE specific rows is not guessing
-- at history; it is applying the state that mechanism should always have
-- used, now that it can be named, to the exact rows it is documented to
-- have touched.
--
-- Scoped narrowly on purpose: only rows still IN Dismissed today. An
-- incident that went Dismissed via this mechanism and was later
-- re-investigated by a human (a real, legal edge — Dismissed has no
-- outgoing edges, so this is actually impossible today, but the WHERE
-- clause states the intent explicitly rather than relying on that being
-- true forever) must not be silently relabeled out from under whatever
-- state it is actually in now.
UPDATE incidents
   SET state = 'Expired'
 WHERE state = 'Dismissed'
   AND EXISTS (
     SELECT 1 FROM timeline_events te
      WHERE te.incident_id = incidents.id
        AND te.event_type = 'IncidentDismissed'
        AND te.payload->>'reason' = 'promotion_evidence_reconciliation'
   );
