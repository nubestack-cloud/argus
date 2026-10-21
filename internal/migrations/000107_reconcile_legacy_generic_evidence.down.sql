-- Reverses only the trigger/function this migration added. The UPDATE it
-- ran is a data correction, not a schema change — like 000092's own backfill,
-- it is not undone on rollback (undoing it would mean deliberately
-- reintroducing rows this migration proved are wrong).
DROP TRIGGER IF EXISTS findings_legacy_generic_evidence ON findings;
DROP FUNCTION IF EXISTS findings_reconcile_legacy_generic_evidence();
