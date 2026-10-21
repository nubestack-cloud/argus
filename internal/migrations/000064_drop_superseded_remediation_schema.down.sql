-- Recreates the 7 tables exactly as migration 000006 declared them, plus the
-- RLS enablement and per-table cluster_id-scope policy migration 000009's
-- generic loop applied to each — migration 000035 explicitly left this
-- group's RLS untouched ("not covered here... their empty list = zero rows
-- behaviour is left exactly as it is"), so 000009's original shape is the
-- correct and complete thing to restore, not something a later migration
-- also changed.
--
-- Created in dependency order (parents before the children that reference
-- them) — the reverse of the up-migration's drop order.

CREATE TABLE remediation_plans (
  id                  text PRIMARY KEY,
  incident_id         text NOT NULL,
  tenant_id           text NOT NULL,
  cluster_id          text NOT NULL,
  plan_hash           text NOT NULL,
  channel             text NOT NULL CHECK (channel IN ('pullRequest','inPlace','guidance')),
  risk                text NOT NULL,
  confidence          numeric(4,3) NOT NULL,
  policy_version_id   text REFERENCES policy_versions(id),
  rollback            jsonb,
  validation_intent   jsonb NOT NULL,
  expires_at          timestamptz NOT NULL,
  signature           text NOT NULL,
  created_at          timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX remediation_plans_hash_idx ON remediation_plans (plan_hash);

CREATE TABLE plan_actions (
  id              text PRIMARY KEY,
  plan_id         text NOT NULL REFERENCES remediation_plans(id),
  tenant_id       text NOT NULL,
  cluster_id      text NOT NULL,
  seq             int NOT NULL,
  type            text NOT NULL,
  target          jsonb NOT NULL,
  patch           jsonb,
  preconditions   jsonb NOT NULL DEFAULT '[]',
  rollback        jsonb,
  risk            text NOT NULL,
  UNIQUE (plan_id, seq)
);

CREATE TABLE approvals (
  id              text PRIMARY KEY,
  plan_id         text NOT NULL REFERENCES remediation_plans(id),
  tenant_id       text NOT NULL,
  cluster_id      text NOT NULL,
  actor_id        text NOT NULL,
  verdict         text NOT NULL CHECK (verdict IN ('approved','rejected')),
  reason          text,
  plan_hash       text NOT NULL,
  source          text NOT NULL CHECK (source IN ('ui','slack','api')),
  auth_method     text NOT NULL,
  created_at      timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE executions (
  id              text PRIMARY KEY,
  plan_id         text NOT NULL REFERENCES remediation_plans(id),
  tenant_id       text NOT NULL,
  cluster_id      text NOT NULL,
  outcome         text NOT NULL,
  started_at      timestamptz NOT NULL,
  finished_at     timestamptz,
  snapshot_ref    text
);

CREATE TABLE pull_requests (
  id                      text PRIMARY KEY,
  plan_id                 text NOT NULL REFERENCES remediation_plans(id),
  tenant_id               text NOT NULL,
  cluster_id              text NOT NULL,
  repository_binding_id   text NOT NULL,
  provider_pr_id          text NOT NULL,
  url                     text NOT NULL,
  state                   text NOT NULL,
  ci_status               text,
  created_at              timestamptz NOT NULL DEFAULT now(),
  merged_at               timestamptz
);

CREATE TABLE validations (
  id              text PRIMARY KEY,
  execution_id    text NOT NULL REFERENCES executions(id),
  tenant_id       text NOT NULL,
  cluster_id      text NOT NULL,
  probes          jsonb NOT NULL,
  outcome         text NOT NULL,
  evaluated_at    timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE action_results (
  id              text PRIMARY KEY,
  execution_id    text NOT NULL REFERENCES executions(id),
  plan_action_id  text NOT NULL REFERENCES plan_actions(id),
  tenant_id       text NOT NULL,
  cluster_id      text NOT NULL,
  status          text NOT NULL,
  detail          jsonb,
  executed_at     timestamptz NOT NULL DEFAULT now()
);

DO $$
DECLARE
  t text;
BEGIN
  FOREACH t IN ARRAY ARRAY[
    'remediation_plans', 'plan_actions', 'approvals', 'executions', 'action_results',
    'pull_requests', 'validations'
  ] LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
    EXECUTE format(
      'CREATE POLICY %I_scope ON %I USING (cluster_id = ANY(string_to_array(current_setting(''app.accessible_cluster_ids'', true), '','')))',
      t, t
    );
  END LOOP;
END $$;
