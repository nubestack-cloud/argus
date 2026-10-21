-- Reverts BACKLOG.md H1's backfill. Restores the original (incorrect)
-- cost_basis value these two specific rows carried before the fix, for
-- migration-rollback symmetry only — 'metered' is not the honest value,
-- this down migration exists to undo the up migration precisely, not to
-- reintroduce the label as correct.
UPDATE analyses
   SET cost_basis = 'metered'
 WHERE id IN ('an_01m0jnkk30w3jpg3b999hqgrmf', 'an_01m0jnmsmn60gazjb1vwm56mxk')
   AND cost_basis = 'subscription';
