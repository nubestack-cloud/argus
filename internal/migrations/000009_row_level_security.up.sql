-- Row-level security. See lld/02-authz-spec.md §10.2, lld/05-data-model.md §6.
--
-- PRECONDITIONS this migration depends on (checked by a startup health check in
-- internal/data — SR-2, lld/01-threat-model.md):
--   1. The application connects as `argus_app`, never as the migration-owning role.
--   2. `argus_app` has no BYPASSRLS attribute.
--   3. The connection pool runs in session-pooling mode (PgBouncer or equivalent) so
--      `SET LOCAL` inside an explicit transaction actually persists for the request —
--      transaction-mode pooling silently breaks this (see lld/01-threat-model.md T1).
-- FORCE ROW LEVEL SECURITY makes RLS apply even to the table owner, so a bug that
-- accidentally runs a query as the owning role still can't bypass scope.

DO $$
BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'argus_app') THEN
    CREATE ROLE argus_app NOLOGIN;
  END IF;
END $$;

GRANT USAGE ON SCHEMA public TO argus_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO argus_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO argus_app;

-- Cluster-scoped tables: predicate on app.accessible_cluster_ids, a session-local
-- text[] the API layer computes from the caller's effective grants (authz-spec §6),
-- resolving any ClusterGroup/AllClusters scope to the current concrete cluster list,
-- and sets via set_config('app.accessible_cluster_ids', $1, true) — parameterised,
-- inside an explicit transaction, never string-interpolated.
--
-- `clusters` itself is special-cased: every other table in this list references a
-- cluster via a `cluster_id` column, but `clusters`' own row IS the cluster, so its
-- identifying column is `id`, not `cluster_id` — a generic loop assuming the column
-- name is uniform would (and during initial implementation, did) fail here.
ALTER TABLE clusters ENABLE ROW LEVEL SECURITY;
ALTER TABLE clusters FORCE ROW LEVEL SECURITY;
CREATE POLICY clusters_scope ON clusters
  USING (id = ANY(string_to_array(current_setting('app.accessible_cluster_ids', true), ',')));

DO $$
DECLARE
  t text;
BEGIN
  FOREACH t IN ARRAY ARRAY[
    'cluster_facts', 'local_guardrail_snapshots',
    'findings', 'incidents', 'analyses', 'evidence', 'timeline_events',
    'remediation_plans', 'plan_actions', 'approvals', 'executions', 'action_results',
    'pull_requests', 'validations',
    'audit_events', 'token_usage'
  ] LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
    EXECUTE format(
      'CREATE POLICY %I_scope ON %I USING (cluster_id = ANY(string_to_array(current_setting(''app.accessible_cluster_ids'', true), '','')))',
      t, t
    );
  END LOOP;
END $$;

-- Tenant-only-scoped tables: no cluster_id, so RLS keys on app.tenant_id instead.
-- With a single organisation this predicate is always true in practice, but it's kept
-- live (not stubbed out) so hosting a second organisation later is a config change,
-- not a schema change (DESIGN.md §5.1's consolidation notes).
DO $$
DECLARE
  t text;
BEGIN
  FOREACH t IN ARRAY ARRAY[
    'users', 'identities', 'service_principals', 'grants', 'identity_mappings',
    'refresh_tokens', 'cluster_groups', 'remediation_policies', 'policy_versions',
    'repository_bindings', 'integrations', 'notification_routes'
  ] LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
    EXECUTE format(
      'CREATE POLICY %I_scope ON %I USING (tenant_id = current_setting(''app.tenant_id'', true))',
      t, t
    );
  END LOOP;
END $$;
