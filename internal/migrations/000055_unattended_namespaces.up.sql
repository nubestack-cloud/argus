-- Namespace scoping for unattended execution.
--
-- Unattended execution had no namespace boundary of any kind: enabling it enabled
-- it for every namespace on every connected cluster. That was measured rather than
-- theorised — with the switch on, the eligible backlog on the test fleet included
-- incidents in `kube-system`, `cattle-monitoring-system` and `argocd`, plus two
-- real workloads on a cluster explicitly designated look-don't-touch. Nothing was
-- acted on, but only because the model happened to propose no plan for them and
-- one cluster happened to be disconnected. That is luck, not a guardrail.
--
-- The column is a LIST OF PERMITTED namespaces and it defaults to empty, which
-- means "nowhere". An empty allowlist denying rather than permitting is the same
-- rule internal/gitops/clone.go already applies to repository hosts, for the same
-- reason stated there: an exposure that cannot be sized cannot be accepted. So
-- switching unattended execution on is now two decisions — that it may act, and
-- where — and the second cannot be skipped by omission.
--
-- A denylist was the alternative and is rejected. A denylist has to enumerate
-- everything dangerous, so it is wrong by default on any cluster with a namespace
-- whose name nobody thought of, and it makes the safe outcome depend on the
-- completeness of a list nobody can complete.
ALTER TABLE org_settings
  ADD COLUMN autonomy_unattended_namespaces text[] NOT NULL DEFAULT '{}';

COMMENT ON COLUMN org_settings.autonomy_unattended_namespaces IS
  'Namespaces where unattended execution may act. Empty means nowhere, deliberately: an empty allowlist denies rather than permits.';
