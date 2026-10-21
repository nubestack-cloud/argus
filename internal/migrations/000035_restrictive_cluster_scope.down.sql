-- Restores the pre-000035 state exactly: the permissive, cluster-keyed
-- policies migration 000009 created (and 000011 renamed nothing of), with the
-- restrictive ones removed. Note that rolling this back re-introduces the bug
-- 000035's header documents — permissive policies OR, so cluster scope stops
-- narrowing anything again.
DROP POLICY IF EXISTS clusters_cluster_scope ON clusters;
CREATE POLICY clusters_scope ON clusters
  USING (id = ANY(string_to_array(current_setting('app.accessible_cluster_ids', true), ',')));

DO $$
DECLARE
  t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['findings', 'incidents', 'analyses'] LOOP
    EXECUTE format('DROP POLICY IF EXISTS %I_cluster_scope ON %I', t, t);
    EXECUTE format(
      'CREATE POLICY %I_scope ON %I USING (cluster_id = ANY(string_to_array(current_setting(''app.accessible_cluster_ids'', true), '','')))',
      t, t
    );
  END LOOP;
END $$;

CREATE POLICY audit_events_scope ON audit_events
  USING (cluster_id = ANY(string_to_array(current_setting('app.accessible_cluster_ids', true), ',')));
