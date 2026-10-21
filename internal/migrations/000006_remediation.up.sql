-- See lld/05-data-model.md §3.6, lld/08-remediation-contracts.md.
--
-- lld/05-data-model.md §6 requires every scope-bearing table to carry its own
-- denormalized tenant_id/cluster_id for RLS-policy simplicity (a single-table
-- predicate, never a join). The §3.6 DDL sketch in that same document missed
-- adding those columns to the plan/execution child tables below — fixed here
-- during implementation rather than carried forward as a silent inconsistency.

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
