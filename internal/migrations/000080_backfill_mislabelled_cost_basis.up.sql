-- BACKLOG.md H1 (decided 2026-08-30): backfill two permanently mislabelled
-- analyses.cost_basis rows to the honest value, 'subscription'.
--
-- an_01m0jnkk30w3jpg3b999hqgrmf and an_01m0jnmsmn60gazjb1vwm56mxk (both
-- 2026-08-21, this deployment's earliest real investigations) were written
-- with cost_basis='metered' and a real, non-zero cost_usd ($0.0717/$0.0563),
-- but this deployment has only ever run the CLI backend under
-- ARGUS_CLI_AUTH_MODE=subscription (confirmed live, CAPABILITIES.md §6x;
-- BACKLOG.md H2's N=247 measured sample is entirely cost_basis='subscription'
-- for the same reason) — no per-token dollar billing has ever occurred here.
-- 'metered' is a factual claim about how cost_usd was derived, and for these
-- two rows it is false: the amount is notional ("what this would have cost
-- on the API"), not a real charge, exactly like every other real
-- investigation this deployment has ever recorded.
--
-- Why a migration and not a documented accept: cost_basis is analysis
-- metadata, not a hash-chained audit event (audit_events' own no-rewrite
-- rule does not apply here), and todaySpendUsd sums cost_usd across whatever
-- 'metered' rows exist for the day — leaving these mislabelled would keep
-- reporting money that was never charged as if it were. The write path that
-- produced this (an early gap in the CLI backend's own cost_basis wiring,
-- since fixed) cannot reproduce it going forward — this is a one-time
-- correction of stale rows, not a recurring condition to guard against.
--
-- Scoped to these two ids by name, not by a pattern (e.g. "empty model"):
-- several other cost_basis='metered' rows are correctly metered fake-model
-- test fixtures (fake-llm-server/fake-spend-test-model, 2026-08-23 through
-- 2026-08-27) and must not be touched.
UPDATE analyses
   SET cost_basis = 'subscription'
 WHERE id IN ('an_01m0jnkk30w3jpg3b999hqgrmf', 'an_01m0jnmsmn60gazjb1vwm56mxk')
   AND cost_basis = 'metered';
