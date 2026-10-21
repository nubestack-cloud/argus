-- Real remediation execution's own outcome record — the "did this actually
-- happen" table neither migration 000006's unused executions/action_results
-- (wrong shape: those reference remediation_plans/plan_actions, not
-- remediation_recommendations, see 000027's own comment) nor
-- remediation_approval_decisions (records the human decision, not what the
-- cluster did afterward) can serve. One row per attempted execution —
-- exactly one per approved recommendation in the normal case, since nothing
-- in this codebase retries an execution automatically, but not a UNIQUE
-- constraint on recommendation_id: a stale-resourceVersion failure followed
-- by a human re-approving is a second, distinct attempt against the same
-- recommendation.
CREATE TABLE remediation_executions (
  id                          text PRIMARY KEY,   -- 'exec_...' (domain.PrefixExecution)
  recommendation_id           text NOT NULL REFERENCES remediation_recommendations(id),
  incident_id                 text NOT NULL,
  tenant_id                   text NOT NULL,
  cluster_id                  text NOT NULL,
  outcome                     text NOT NULL CHECK (outcome IN ('succeeded', 'failed')),
  error                       text,               -- required when outcome = 'failed'; NULL when succeeded. Not a CHECK — see remediation_approval_decisions.reason's own precedent for why this stays an API-layer invariant, not a DB one.
  resource_version_precondition text,             -- the resourceVersion fetched fresh at approval time and embedded in the patch's precondition (lld/08 §5) — recorded so a "why did this fail" investigation doesn't need to reconstruct it from logs.
  executed_at                 timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX remediation_executions_recommendation_idx ON remediation_executions (recommendation_id, executed_at DESC);
CREATE INDEX remediation_executions_incident_idx ON remediation_executions (incident_id, executed_at DESC);

ALTER TABLE remediation_executions ENABLE ROW LEVEL SECURITY;
ALTER TABLE remediation_executions FORCE ROW LEVEL SECURITY;
CREATE POLICY remediation_executions_tenant_scope ON remediation_executions
  USING (tenant_id = current_setting('app.tenant_id', true));
GRANT SELECT, INSERT, UPDATE, DELETE ON remediation_executions TO argus_app;
