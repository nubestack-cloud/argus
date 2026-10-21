-- docs/CLUSTER_INSIGHT_SPECS.md CI-S5: upgrade-readiness scan results, one row
-- per scan. The hub schedules one scan per connected cluster per day for the
-- next Kubernetes minor, and records on-demand scans for other targets.
CREATE TABLE upgrade_scans (
  id               text PRIMARY KEY,
  tenant_id        text NOT NULL REFERENCES organisations(id),
  cluster_id       text NOT NULL REFERENCES clusters(id) ON DELETE CASCADE,
  current_version  text NOT NULL DEFAULT '',
  target_version   text NOT NULL DEFAULT '',
  verdict          text NOT NULL DEFAULT '',
  reviewed_through text NOT NULL DEFAULT '',
  result           jsonb NOT NULL,
  scanned_at       timestamptz NOT NULL DEFAULT now(),
  requested_by     text
);

CREATE INDEX upgrade_scans_cluster_time ON upgrade_scans (cluster_id, scanned_at DESC);

ALTER TABLE upgrade_scans ENABLE ROW LEVEL SECURITY;
ALTER TABLE upgrade_scans FORCE ROW LEVEL SECURITY;
CREATE POLICY upgrade_scans_tenant_scope ON upgrade_scans
  USING (tenant_id = current_setting('app.tenant_id', true));
CREATE POLICY upgrade_scans_cluster_scope ON upgrade_scans AS RESTRICTIVE
  USING (
    COALESCE(current_setting('app.accessible_cluster_ids', true), '') = ''
    OR cluster_id = ANY(string_to_array(current_setting('app.accessible_cluster_ids', true), ','))
  )
  WITH CHECK (
    COALESCE(current_setting('app.accessible_cluster_ids', true), '') = ''
    OR cluster_id = ANY(string_to_array(current_setting('app.accessible_cluster_ids', true), ','))
  );

GRANT SELECT, INSERT, UPDATE, DELETE ON upgrade_scans TO argus_app;
