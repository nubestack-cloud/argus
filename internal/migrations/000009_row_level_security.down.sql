DO $$
DECLARE
  t text;
BEGIN
  FOREACH t IN ARRAY ARRAY[
    'clusters', 'cluster_facts', 'local_guardrail_snapshots',
    'findings', 'incidents', 'analyses', 'evidence', 'timeline_events',
    'remediation_plans', 'plan_actions', 'approvals', 'executions', 'action_results',
    'pull_requests', 'validations',
    'audit_events', 'token_usage',
    'users', 'identities', 'service_principals', 'grants', 'identity_mappings',
    'refresh_tokens', 'cluster_groups', 'remediation_policies', 'policy_versions',
    'repository_bindings', 'integrations', 'notification_routes'
  ] LOOP
    EXECUTE format('DROP POLICY IF EXISTS %I_scope ON %I', t, t);
    EXECUTE format('ALTER TABLE %I NO FORCE ROW LEVEL SECURITY', t);
    EXECUTE format('ALTER TABLE %I DISABLE ROW LEVEL SECURITY', t);
  END LOOP;
END $$;

REVOKE ALL ON ALL TABLES IN SCHEMA public FROM argus_app;
REVOKE USAGE ON SCHEMA public FROM argus_app;
