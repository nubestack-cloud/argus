-- Closes the repeatedly-flagged, honest gap WORKLOG.md §28/§49 both
-- documented rather than papered over: analyses.cost_usd has been a real
-- column since migration 000005, populated with a literal 0 on every row
-- (internal/api/analyze.go's persistAnalysis) because no per-model USD
-- pricing table existed anywhere in this codebase to compute a real number
-- from. This migration adds that pricing table -- NOT hardcoded to any real
-- vendor's current rate card (pricing moves, and a hardcoded rate goes
-- stale silently), but an operator-configured one, following the exact
-- same convention every other org_settings column already uses (migration
-- 000018's header comment) and the no-env-var-tier precedent a brand-new
-- setting with no prior ARGUS_* variable gets (migrations 000020/000024/
-- 000026/000028).
--
-- price_per_million_input_tokens / price_per_million_cached_tokens /
-- price_per_million_output_tokens: nullable numeric(10,4), matching
-- analyses.cost_usd's own precision (migration 000005) and the $/Mtok unit
-- DESIGN.md §16.3's worked cost model already uses
-- throughout ("$2 / $10 per Mtok"), so an operator copying a number from
-- that section's table, or from whichever provider's own published pricing
-- page, doesn't have to convert units first. NULL (the default, on every
-- fresh install) means "no pricing configured" -- internal/settings.Config's
-- ComputeCostUSD treats "not all three set" as exactly that, computing a
-- real, honest cost_usd of 0, never a guessed rate. The three are
-- deliberately NOT independently optional in practice -- internal/api/
-- settings.go's PUT handler rejects a request that sets some but not all
-- three (see validateCostSettingsRequest) -- because a partial price table
-- would compute a systematically WRONG total, which is worse than an honest
-- zero; the schema itself doesn't need a CHECK constraint to enforce that
-- (three independent nullable columns, no cross-column CHECK), matching
-- migration 000026's identical choice to enforce storm-protection's
-- must-be-set-together rule at the API boundary instead of the schema layer.
--
-- daily_spend_ceiling_usd: nullable numeric(10,4). NULL (the default) means
-- "no ceiling" -- today's actual, unbounded behavior, unchanged until an
-- operator sets one; a positive value is a real, explicit daily spend cap
-- internal/api.SpendCeilingBreached checks today's already-accumulated real
-- spend (SUM(analyses.cost_usd) for analyses created today) against, before
-- internal/autoanalyze starts any further unsupervised investigation for
-- the rest of that UTC calendar day. See internal/autoanalyze's own updated
-- doc comment for exactly how a breached ceiling is enforced (skip, logged
-- clearly) and internal/api/analyze.go's handleAnalyzeIncident for why the
-- MANUAL analyze path deliberately does NOT block on it (a human explicitly
-- clicking "Analyze" on one specific incident is a deliberate, bounded
-- action, not the kind of unsupervised repeated spend 04-consolidated-
-- design.md §16.4's ceiling is protecting against) -- documented, not a
-- silent asymmetry.
--
-- This is a deliberately simplified, single, org-wide ceiling -- NOT
-- DESIGN.md §16.4's full hierarchical
-- org/tenant/cluster/policy ceiling structure (that requires per-tenant and
-- per-cluster budget rows and attribution this codebase's confirmed
-- single-org, single-tenant scope (§5.1) has no other use for yet -- see
-- STATUS.md for the full reasoning). One ceiling, checked against one
-- org-wide daily total, following this table's own existing "one singleton
-- row" shape (migration 000018's singletonID) exactly.
ALTER TABLE org_settings
  ADD COLUMN price_per_million_input_tokens numeric(10,4)
    CHECK (price_per_million_input_tokens IS NULL OR price_per_million_input_tokens >= 0),
  ADD COLUMN price_per_million_cached_tokens numeric(10,4)
    CHECK (price_per_million_cached_tokens IS NULL OR price_per_million_cached_tokens >= 0),
  ADD COLUMN price_per_million_output_tokens numeric(10,4)
    CHECK (price_per_million_output_tokens IS NULL OR price_per_million_output_tokens >= 0),
  ADD COLUMN daily_spend_ceiling_usd numeric(10,4)
    CHECK (daily_spend_ceiling_usd IS NULL OR daily_spend_ceiling_usd > 0);
