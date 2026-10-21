-- BACKLOG.md P2: drops the 7 tables lld/08-remediation-contracts.md §2b names
-- as superseded and never holding a row — migration 000006's original
-- plan/approval/execution schema, replaced by the flatter
-- remediation_recommendations set (migration 000027) before anything was
-- ever written to these. internal/migrations/schema_coverage_test.go's
-- notImplementedTables registry carried each of them with "Candidate for a
-- DROP migration" (remediation_plans, plan_actions, executions,
-- action_results, approvals, pull_requests) or an equivalent superseded note
-- (validations); this is that migration, unblocked now that F17
-- (2026-08-25) reintroduced the route concept as incidents.route/
-- route_reason/applier rather than reviving remediation_plans.channel, so
-- dropping the original no longer risks re-adding an equivalent of what it
-- removes.
--
-- Dropped in dependency order (children before the parents they reference)
-- rather than as one multi-table statement or CASCADE, so the order a reader
-- sees is the order Postgres actually needs, not a magic word papering over
-- it.
DROP TABLE action_results;
DROP TABLE validations;
DROP TABLE pull_requests;
DROP TABLE approvals;
DROP TABLE plan_actions;
DROP TABLE executions;
DROP TABLE remediation_plans;
