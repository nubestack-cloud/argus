-- Reverts migration 000108's backfill, for migration-rollback symmetry
-- only — 'metered' is not the honest value for these rows, matching
-- migration 000080's own down file's framing.
--
-- Caveat this down file cannot fully avoid: the up migration is
-- criterion-based (see its own header), not an id list, so this reversal
-- re-applies the same criterion rather than replaying an exact row set. If
-- the fixed cli-runner binary has already written NEW, genuinely-earned
-- cost_basis='subscription' rows under the same "no api provider, no
-- pricing configured" condition by the time this runs, this down migration
-- will also relabel those back to 'metered' — an unavoidable consequence of
-- reverting a criterion-based data backfill rather than a schema change,
-- and a reason to prefer forward-fixing over rolling this back once real
-- traffic has passed through the corrected code.
UPDATE analyses
   SET cost_basis = 'metered'
 WHERE cost_basis = 'subscription'
   AND cost_usd > 0
   AND NOT EXISTS (SELECT 1 FROM ai_providers WHERE kind = 'api')
   AND NOT EXISTS (
         SELECT 1 FROM org_settings
          WHERE price_per_million_input_tokens IS NOT NULL
             OR price_per_million_cached_tokens IS NOT NULL
             OR price_per_million_output_tokens IS NOT NULL
       );
