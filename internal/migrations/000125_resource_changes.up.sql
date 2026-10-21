-- docs/CLUSTER_INSIGHT_SPECS.md CI-S2: field-level changes to cluster objects,
-- recorded by the agent's object cache and shipped over the tunnel. Values on
-- secret-bearing paths never arrive here (the agent hashes env and ConfigMap
-- values at capture and redacts change values again at egress), so a row
-- holds paths, short values and summaries only.
--
-- Retention is bounded (internal/resourcechanges' sweeper; org setting
-- resourceChanges.retentionDays, default 14).
CREATE TABLE resource_changes (
  id          text PRIMARY KEY,
  tenant_id   text NOT NULL REFERENCES organisations(id),
  cluster_id  text NOT NULL REFERENCES clusters(id) ON DELETE CASCADE,
  observed_at timestamptz NOT NULL,
  received_at timestamptz NOT NULL DEFAULT now(),
  seq         bigserial,
  kind        text NOT NULL,
  api_group   text NOT NULL DEFAULT '',
  namespace   text NOT NULL DEFAULT '',
  name        text NOT NULL,
  uid         text NOT NULL DEFAULT '',
  owner_kind  text NOT NULL DEFAULT '',
  owner_name  text NOT NULL DEFAULT '',
  op          text NOT NULL CHECK (op IN ('add', 'update', 'delete')),
  fields      jsonb NOT NULL DEFAULT '[]',
  summary     text NOT NULL DEFAULT ''
);

CREATE INDEX resource_changes_cluster_time ON resource_changes (cluster_id, observed_at DESC);
CREATE INDEX resource_changes_object ON resource_changes (cluster_id, namespace, kind, name, observed_at DESC);
CREATE INDEX resource_changes_owner ON resource_changes (cluster_id, namespace, owner_kind, owner_name, observed_at DESC);

-- A window in which changes were lost (agent buffer overflow, a failed send)
-- — the UI says the history is incomplete there instead of implying nothing
-- changed.
CREATE TABLE resource_change_gaps (
  id          text PRIMARY KEY,
  tenant_id   text NOT NULL REFERENCES organisations(id),
  cluster_id  text NOT NULL REFERENCES clusters(id) ON DELETE CASCADE,
  gap_from    timestamptz NOT NULL,
  gap_to      timestamptz NOT NULL,
  reason      text NOT NULL DEFAULT '',
  received_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX resource_change_gaps_cluster_time ON resource_change_gaps (cluster_id, gap_to DESC);

-- RLS: permissive tenant policy plus restrictive cluster narrowing, the shape
-- 000037_mcp_tool_calls established for tables created after 000035.
ALTER TABLE resource_changes ENABLE ROW LEVEL SECURITY;
ALTER TABLE resource_changes FORCE ROW LEVEL SECURITY;
CREATE POLICY resource_changes_tenant_scope ON resource_changes
  USING (tenant_id = current_setting('app.tenant_id', true));
CREATE POLICY resource_changes_cluster_scope ON resource_changes AS RESTRICTIVE
  USING (
    COALESCE(current_setting('app.accessible_cluster_ids', true), '') = ''
    OR cluster_id = ANY(string_to_array(current_setting('app.accessible_cluster_ids', true), ','))
  )
  WITH CHECK (
    COALESCE(current_setting('app.accessible_cluster_ids', true), '') = ''
    OR cluster_id = ANY(string_to_array(current_setting('app.accessible_cluster_ids', true), ','))
  );

ALTER TABLE resource_change_gaps ENABLE ROW LEVEL SECURITY;
ALTER TABLE resource_change_gaps FORCE ROW LEVEL SECURITY;
CREATE POLICY resource_change_gaps_tenant_scope ON resource_change_gaps
  USING (tenant_id = current_setting('app.tenant_id', true));
CREATE POLICY resource_change_gaps_cluster_scope ON resource_change_gaps AS RESTRICTIVE
  USING (
    COALESCE(current_setting('app.accessible_cluster_ids', true), '') = ''
    OR cluster_id = ANY(string_to_array(current_setting('app.accessible_cluster_ids', true), ','))
  )
  WITH CHECK (
    COALESCE(current_setting('app.accessible_cluster_ids', true), '') = ''
    OR cluster_id = ANY(string_to_array(current_setting('app.accessible_cluster_ids', true), ','))
  );

GRANT SELECT, INSERT, UPDATE, DELETE ON resource_changes TO argus_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON resource_change_gaps TO argus_app;
GRANT USAGE, SELECT ON SEQUENCE resource_changes_seq_seq TO argus_app;
