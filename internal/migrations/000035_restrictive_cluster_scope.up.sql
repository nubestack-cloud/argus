-- Make cluster scope actually narrow again. See lld/02-authz-spec.md §6/§10.2,
-- lld/05-data-model.md §6.
--
-- CORRECTION to migrations 000011, 000012, 000013 and 000015. Their SQL is
-- already applied and is deliberately NOT edited by this migration (an applied
-- migration's text is history, not documentation) — this header is the
-- correction record instead.
--
-- Each of those four migrations added a PERMISSIVE, tenant_id-keyed policy
-- beside migration 000009's cluster-keyed policy on the same table, and each
-- justified it with a sentence of the form: "Postgres ORs multiple permissive
-- policies together for the same command, so this is additive, not a
-- weakening — the existing cluster_id-based policy still applies and still
-- narrows access further." The first clause is correct. The conclusion drawn
-- from it is wrong, and it is the whole point of this migration.
--
-- Postgres combines permissive policies for the same command with OR, so the
-- effective read/write predicate on clusters/audit_events/findings/incidents/
-- analyses has been, since 000011:
--
--     tenant_id = current_setting('app.tenant_id')
--       OR cluster_id = ANY(app.accessible_cluster_ids)
--
-- A predicate OR'd with a tenant-wide one cannot narrow anything. Once
-- app.tenant_id matches, every row belonging to that tenant is visible no
-- matter what app.accessible_cluster_ids contains — the cluster branch can
-- only ever ADD rows (in fact it could add rows from a DIFFERENT tenant, if a
-- cluster ID from another tenant were ever put in the list). So
-- app.accessible_cluster_ids has been decorative on these five tables, not a
-- second narrowing layer.
--
-- This is harmless *today* only because nothing populates that variable for a
-- general-purpose caller: internal/api/middleware.go's requireAuth passes nil,
-- as does every other hub caller of internal/data.SetRequestScope except the
-- four that already know exactly one cluster (internal/gateway's
-- handleInventoryDelta/handleFinding, internal/autoanalyze's investigateOne,
-- internal/api's handleGetCluster). It stops being harmless the moment
-- per-cluster grant resolution (authz-spec §6, still unbuilt — STATUS.md §2)
-- starts filling that list in: a viewer scoped to one cluster would silently
-- read the whole fleet, while the middleware, the grant model and the session
-- variable all still looked correct. That is the failure mode this fixes,
-- before it can ship.
--
-- FIX. The tenant_id policy stays the only PERMISSIVE (row-admitting) policy;
-- cluster narrowing is re-expressed as a RESTRICTIVE policy, which Postgres
-- AND's with the OR of the permissive ones. RESTRICTIVE is chosen over a
-- single merged predicate on purpose: it is the shape that cannot be
-- re-broken the same way. A future migration that adds one more permissive
-- policy to one of these tables — which is exactly how this bug happened,
-- four times in five migrations — still cannot widen past a restrictive one.
--
-- SEMANTICS of app.accessible_cluster_ids, now load-bearing rather than
-- decorative:
--
--   * unset, or set to the empty string -> NO cluster narrowing: the caller
--     sees every row of their tenant. This branch is required, not a
--     loophole. Every hub caller today passes nil (SetRequestScope joins that
--     to ""), and every fleet-wide screen in the product — the incident list,
--     the overview, insights, spend, the audit log — depends on it. Without
--     this branch the restrictive policy would evaluate
--     `cluster_id = ANY(string_to_array(NULL, ','))` -> NULL -> false and
--     block every row for every caller, which is precisely the total-block
--     bug 000011/000012/000013/000015 were each reacting to.
--
--   * non-empty -> only rows whose cluster is in the list, AND'd on top of
--     the tenant predicate. Both constraints now apply.
--
--   * CONTRACT for whoever implements per-cluster grant resolution: an
--     AllClusters grant must pass an EMPTY list (meaning "no narrowing"). A
--     grant that resolves to ZERO concrete clusters must NOT be expressed as
--     an empty list — that means "unrestricted" here. Deny such a request at
--     the application layer instead, or pass a sentinel value that matches no
--     cluster. This is the one sharp edge in the design and it is deliberate:
--     the alternative (empty list = zero rows) would require every existing
--     caller to enumerate the whole fleet on every request just to keep
--     working.
--
-- audit_events IS TREATED DIFFERENTLY, on purpose: its dead cluster-keyed
-- policy is dropped and NO restrictive cluster policy replaces it, leaving it
-- tenant-scoped only. Two independent reasons:
--
--   (a) It is the one table here whose cluster_id is nullable, and most rows
--       have no cluster at all — 143 of 168 rows (85%) in the dev database at
--       the time of writing: logins, capability denials, settings changes,
--       user management, enrollment-token issuance. Migration 000012's
--       comment (b) already spelled this out. A cluster predicate on this
--       table cannot express "the org-level events plus these clusters'
--       events" without effectively re-admitting the org-level rows anyway.
--
--   (b) More importantly, internal/audit.RecordEvent reads the audit hash
--       chain's tip (SELECT hash FROM audit_events ORDER BY occurred_at DESC
--       LIMIT 1) inside the CALLER's transaction, and some callers have
--       already narrowed that transaction to one cluster before the write
--       (internal/gateway/finding.go's storm-protection event is the live
--       example). Under an RLS-filtered tip read, that call would chain the
--       new row onto a stale prev_hash whenever the true tip belonged to a
--       different cluster — silently forking the global chain, which
--       `argusctl audit verify` would then report as tampering forever. RLS
--       is the wrong layer for per-cluster audit visibility. It belongs in
--       internal/api/audit.go's list query as an explicit WHERE clause (with
--       an explicit decision about org-level, cluster-less events), or behind
--       a scope-independent tip read in internal/audit — neither of which is
--       this migration's to write.
--
-- Not covered here, and deliberately: the other tables from 000009's
-- cluster-keyed loop (cluster_facts, evidence, timeline_events, token_usage,
-- remediation_plans, plan_actions, approvals, executions, action_results,
-- pull_requests, validations, local_guardrail_snapshots) still have a single
-- permissive cluster-keyed policy and no tenant policy, so nothing OR's their
-- narrowing away — they were never part of this bug. Their "empty list = zero
-- rows" behaviour is left exactly as it is; changing it would widen access on
-- tables that have no tenant predicate to fall back on. The newer
-- remediation_recommendations / remediation_approval_decisions /
-- remediation_executions tables carry a cluster_id but only a tenant-keyed
-- policy (migrations 000027/000031); they are not part of this bug either
-- (nothing to defeat), but they will need the restrictive treatment below
-- when per-cluster grants land.

-- clusters is special-cased for the same reason it was in 000009: its own row
-- IS the cluster, so the identifying column is `id`, not `cluster_id`.
DROP POLICY IF EXISTS clusters_scope ON clusters;
CREATE POLICY clusters_cluster_scope ON clusters AS RESTRICTIVE
  USING (
    COALESCE(current_setting('app.accessible_cluster_ids', true), '') = ''
    OR id = ANY(string_to_array(current_setting('app.accessible_cluster_ids', true), ','))
  )
  WITH CHECK (
    COALESCE(current_setting('app.accessible_cluster_ids', true), '') = ''
    OR id = ANY(string_to_array(current_setting('app.accessible_cluster_ids', true), ','))
  );

-- findings, incidents and analyses all have a NOT NULL cluster_id, so the
-- uniform predicate below is exact for every row — no nullable-column case to
-- reason about (unlike audit_events, see (a) above).
--
-- USING and WITH CHECK are both spelled out rather than relying on "WITH CHECK
-- defaults to USING": this is a security control, and it should not depend on
-- a reader (or a future editor) remembering that defaulting rule.
DO $$
DECLARE
  t text;
  pred text;
BEGIN
  pred := 'COALESCE(current_setting(''app.accessible_cluster_ids'', true), '''') = ''''
           OR cluster_id = ANY(string_to_array(current_setting(''app.accessible_cluster_ids'', true), '',''))';
  FOREACH t IN ARRAY ARRAY['findings', 'incidents', 'analyses'] LOOP
    EXECUTE format('DROP POLICY IF EXISTS %I_scope ON %I', t, t);
    EXECUTE format(
      'CREATE POLICY %I_cluster_scope ON %I AS RESTRICTIVE USING (%s) WITH CHECK (%s)',
      t, t, pred, pred
    );
  END LOOP;
END $$;

-- See (a)/(b) above: dropped, not replaced.
DROP POLICY IF EXISTS audit_events_scope ON audit_events;
