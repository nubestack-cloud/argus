-- PROJECT.md B138. Read migration 000092's header first — this migration
-- corrects it, it does not re-derive its intent.
--
-- 000092 added findings.signal_class/confidence/impact with defaults
-- ('fault','verified','degraded') — the pre-evidence behaviour, so a legacy
-- agent's Finding kept opening incidents exactly as before — then backfilled
-- three legacy generic-mechanism reasons (GenericConditionAnomaly:*,
-- GenericDanglingReference:*, GenericPeerConditionShapeOutlier) to
-- ('anomaly','unverified','none'), the honest tuple for a mechanism whose
-- name was already stable on the wire before these columns existed.
--
-- That backfill ran exactly once, against whatever rows existed at the
-- moment it ran. Any writer that does not know these three columns exist —
-- a hub build older than internal/gateway/promotion.go's
-- normalizeFindingEvidence, still serving the tunnel mid rolling-deploy, or a
-- rolled-back image — issues an INSERT that never mentions them, so Postgres
-- fills in the schema default ('fault','verified','degraded') right back in,
-- re-creating exactly the rows 000092 corrected. Not hypothetical: measured
-- on the development database at 490 such rows on 2026-09-05 (a 35-minute
-- window between the migration running and the ingestion gate deploying),
-- 494 on 2026-09-08, 460 on 2026-09-18. The net decrease is retention
-- cleanup, not new writes — max(occurred_at) across the bad set is still
-- 2026-09-05 09:12:02 UTC, so nothing has re-created one of these rows since
-- the gate deployed in THIS environment — but the exposure a rolled-back or
-- lagging hub image reopens is real, not closed by luck alone.
--
-- internal/gateway/finding.go's handleFinding calls
-- internal/gateway/promotion.go's normalizeFindingEvidence for every Finding
-- a CURRENT hub build handles (confirmed at finding.go's handleFinding, the
-- call site is inside the correlation transaction, before
-- shouldPromoteFinding is ever consulted), so the gap is already closed for
-- any writer running this code. It cannot be closed there for a writer
-- running OLDER code — there is no hub-code fix for a binary that predates
-- the fix. Closing that half needs a mechanism that runs independent of
-- which hub binary performs the write, which means the database:
--
--   1. A BEFORE INSERT OR UPDATE trigger applies the identical, narrow
--      correction to every write, present and future, regardless of which
--      hub build performs it — a lagging or rolled-back writer's INSERT
--      still goes through this table, so it cannot bypass a trigger the way
--      it bypasses a hub-code fix. The predicate is deliberately identical
--      to, and no broader than, isPreEvidenceDefault/legacyGenericAnomaly in
--      internal/gateway/promotion.go — see that file's WouldPromoteStoredFinding
--      doc comment for why exactly this triple has exactly one possible
--      author today. internal/gateway/legacy_generic_evidence_trigger_db_test.go
--      pins this trigger's behaviour, including that it leaves every OTHER
--      tuple (a real fault, or a generic row already correctly classed)
--      untouched.
--   2. Re-running the narrowed form of 000092's UPDATE now corrects every
--      row already stored, without touching a row that a legitimate future
--      mechanism (the condition-polarity gate, earned fault promotion) has
--      deliberately moved off the schema default — this WHERE clause only
--      ever matches the exact triple nothing in this codebase currently
--      emits for a Generic* reason on purpose.
--
-- Both steps are naturally idempotent: once a row no longer carries the
-- exact default triple, neither the trigger's IF nor the UPDATE's WHERE
-- matches it again, so re-running this file's body is always safe and never
-- duplicates or undoes its own earlier work.
--
-- Read-time defense in depth (WouldPromoteStoredFinding, used by internal/api's
-- promotion reconciliation) is UNCHANGED by this migration and keeps working
-- even once every stored row is honest — belt and suspenders, not either/or.
-- Do not weaken it on the strength of this migration existing.

CREATE OR REPLACE FUNCTION findings_reconcile_legacy_generic_evidence()
RETURNS trigger AS $$
BEGIN
  IF (NEW.reason LIKE 'GenericConditionAnomaly:%'
      OR NEW.reason LIKE 'GenericDanglingReference:%'
      OR NEW.reason = 'GenericPeerConditionShapeOutlier')
     AND NEW.signal_class = 'fault'
     AND NEW.confidence = 'verified'
     AND NEW.impact = 'degraded' THEN
    NEW.signal_class := 'anomaly';
    NEW.confidence := 'unverified';
    NEW.impact := 'none';
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS findings_legacy_generic_evidence ON findings;
CREATE TRIGGER findings_legacy_generic_evidence
  BEFORE INSERT OR UPDATE ON findings
  FOR EACH ROW
  EXECUTE FUNCTION findings_reconcile_legacy_generic_evidence();

-- Narrowed re-run of 000092's backfill: only the exact pre-evidence default
-- triple on a legacy generic reason, never a row any current mechanism
-- deliberately classed that way.
UPDATE findings
   SET signal_class = 'anomaly', confidence = 'unverified', impact = 'none'
 WHERE (reason LIKE 'GenericConditionAnomaly:%'
    OR reason LIKE 'GenericDanglingReference:%'
    OR reason = 'GenericPeerConditionShapeOutlier')
   AND signal_class = 'fault'
   AND confidence = 'verified'
   AND impact = 'degraded';
