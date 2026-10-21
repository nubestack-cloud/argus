DROP POLICY IF EXISTS timeline_events_tenant_scope ON timeline_events;
DROP POLICY IF EXISTS timeline_events_cluster_scope ON timeline_events;

CREATE POLICY timeline_events_scope ON timeline_events
  USING (cluster_id = ANY(string_to_array(current_setting('app.accessible_cluster_ids', true), ',')));
