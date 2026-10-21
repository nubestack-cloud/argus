-- PROJECT.md B169: cmd/cli-runner's costBasisFor labelled a subscription-
-- authenticated CLI run 'metered' whenever ARGUS_CLI_AUTH_MODE went unset,
-- because the ONLY signal it consulted for "this is notional, not charged
-- money" was an operator-declared mode rather than anything the runner
-- already knew about its own credential. The code is fixed (costBasisFor
-- now derives the answer from which credential env var the run actually
-- authenticated with — CLAUDE_CODE_OAUTH_TOKEN implies subscription,
-- independent of ARGUS_CLI_AUTH_MODE); this migration is the one-time
-- backfill for the rows the old logic already wrote wrong.
--
-- Live-measured 2026-09-18: 21 analyses.metered rows with cost_usd > 0, all
-- model='claude-sonnet-4-5-20250929' — this deployment's one-and-only
-- ai_providers row is kind='cli' (created 2026-08-21, the same day as
-- migration 000080's two hand-corrected rows), no ai_providers row of
-- kind='api' has ever existed, and org_settings' three
-- price_per_million_* columns are all NULL, so no per-token dollar billing
-- has ever been configured here. (The board item's own "18" is now stale —
-- three more accumulated on 2026-09-18 alone, which is exactly the ongoing
-- pollution this migration and its code fix together stop.)
--
-- Deliberately criterion-based rather than a hardcoded id list (unlike
-- migration 000080's two-row hand fix, and unlike BACKLOG.md/PROJECT.md
-- B138's one-shot UPDATE against a moving target): this WHERE clause is
-- safe to re-run — by hand, via the same query this migration runs, against
-- `psql` — if more rows accumulate in the gap between this migration
-- applying and the fixed cli-runner binary actually deploying, without
-- needing a new migration enumerating new ids each time.
--
-- Scoped so it is a no-op on any deployment that has ever configured real
-- per-token pricing or an 'api'-kind provider, rather than blindly
-- relabelling every 'metered' row: those are exactly the two structural
-- facts (checked live above) that make "any nonzero-cost 'metered' row here
-- is definitionally mislabelled" true for THIS deployment, and the
-- correction must not apply anywhere that fact doesn't hold.
UPDATE analyses
   SET cost_basis = 'subscription'
 WHERE cost_basis = 'metered'
   AND cost_usd > 0
   AND NOT EXISTS (SELECT 1 FROM ai_providers WHERE kind = 'api')
   AND NOT EXISTS (
         SELECT 1 FROM org_settings
          WHERE price_per_million_input_tokens IS NOT NULL
             OR price_per_million_cached_tokens IS NOT NULL
             OR price_per_million_output_tokens IS NOT NULL
       );
