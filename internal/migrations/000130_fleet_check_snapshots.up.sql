-- The Overview's fleet checks: the last answer each connected cluster's agent
-- gave to four read-only inventory tools (certificates, posture, Helm
-- releases, GitOps apps), reduced to counts by the hub and kept one row per
-- cluster and check. A hub worker refreshes them on an interval, so the fleet
-- page reads one aggregate instead of calling every agent four times on load.
--
-- summary/summary_at are the last SUCCESSFUL answer and stay put when a later
-- attempt fails; error/error_at record that failure beside it, so a reader can
-- say "as of 3 h ago, the latest read failed" rather than losing the figure or
-- presenting it as current.
CREATE TABLE fleet_check_snapshots (
  tenant_id   text NOT NULL REFERENCES organisations(id),
  cluster_id  text NOT NULL REFERENCES clusters(id) ON DELETE CASCADE,
  check_name  text NOT NULL CHECK (check_name IN ('certificates', 'posture', 'helm', 'gitops')),
  summary     jsonb,
  summary_at  timestamptz,
  error       text,
  error_at    timestamptz,
  PRIMARY KEY (cluster_id, check_name)
);

ALTER TABLE fleet_check_snapshots ENABLE ROW LEVEL SECURITY;
ALTER TABLE fleet_check_snapshots FORCE ROW LEVEL SECURITY;
CREATE POLICY fleet_check_snapshots_tenant_scope ON fleet_check_snapshots
  USING (tenant_id = current_setting('app.tenant_id', true));
CREATE POLICY fleet_check_snapshots_cluster_scope ON fleet_check_snapshots AS RESTRICTIVE
  USING (
    COALESCE(current_setting('app.accessible_cluster_ids', true), '') = ''
    OR cluster_id = ANY(string_to_array(current_setting('app.accessible_cluster_ids', true), ','))
  )
  WITH CHECK (
    COALESCE(current_setting('app.accessible_cluster_ids', true), '') = ''
    OR cluster_id = ANY(string_to_array(current_setting('app.accessible_cluster_ids', true), ','))
  );

GRANT SELECT, INSERT, UPDATE, DELETE ON fleet_check_snapshots TO argus_app;
