DROP POLICY IF EXISTS evidence_cluster_scope ON evidence;
DROP POLICY IF EXISTS evidence_tenant_scope ON evidence;
CREATE POLICY evidence_scope ON evidence
  USING (cluster_id = ANY(string_to_array(current_setting('app.accessible_cluster_ids', true), ',')));

DROP INDEX IF EXISTS evidence_incident_idx;

ALTER TABLE evidence DROP COLUMN IF EXISTS error;
ALTER TABLE evidence DROP COLUMN IF EXISTS result;
ALTER TABLE evidence DROP COLUMN IF EXISTS args;
ALTER TABLE evidence DROP CONSTRAINT IF EXISTS evidence_outcome_valid;
ALTER TABLE evidence DROP COLUMN IF EXISTS outcome;
ALTER TABLE evidence DROP COLUMN IF EXISTS tool;
ALTER TABLE evidence DROP COLUMN IF EXISTS incident_id;
ALTER TABLE evidence ALTER COLUMN object_store_key SET NOT NULL;
