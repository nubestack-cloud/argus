-- Reversible with no data loss beyond the record itself: the columns are
-- advisory, and dropping them restores the previous behaviour — in which a plan
-- superseded by a merged pull request stays approvable. Worth saying plainly,
-- because that behaviour is the one that would have re-broken a workload.
ALTER TABLE remediation_recommendations
  DROP CONSTRAINT IF EXISTS remediation_recommendations_superseded_together;
ALTER TABLE remediation_recommendations
  DROP COLUMN IF EXISTS superseded_by_url,
  DROP COLUMN IF EXISTS superseded_at;
