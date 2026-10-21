-- Append-only, hash-chained audit log. See lld/05-data-model.md §3.8, §7 (hash design).
--
-- IMPORTANT: the hash covers only the core fields listed below — tenant_id, actor_id,
-- capability, scope, cluster_id, outcome, occurred_at, prev_hash. `details` is deliberately
-- EXCLUDED from the hash input so it can be redacted under its own shorter retention
-- window without invalidating the chain (closes SR-15/SR-21 — see lld/01-threat-model.md
-- and lld/05-data-model.md §7 for why this split exists; do not "simplify" it later by
-- hashing the whole row).
--
-- Partitioned monthly like findings/incidents, but UNLIKE them this table's partitions
-- are never dropped wholesale for retention — see lld/05-data-model.md §9.

CREATE TABLE audit_events (
  id                  text NOT NULL,
  tenant_id           text NOT NULL,
  actor_id            text,
  actor_auth_method   text,
  source_ip           inet,
  capability          text,
  scope               jsonb,
  cluster_id          text,
  outcome             text NOT NULL,
  occurred_at         timestamptz NOT NULL DEFAULT now(),
  details             jsonb,
  prev_hash           text NOT NULL,
  hash                text NOT NULL,
  PRIMARY KEY (id, occurred_at)
) PARTITION BY RANGE (occurred_at);

CREATE TABLE audit_events_default PARTITION OF audit_events DEFAULT;

CREATE INDEX audit_events_actor_idx ON audit_events (actor_id, occurred_at DESC);
CREATE INDEX audit_events_cluster_idx ON audit_events (cluster_id, occurred_at DESC);

CREATE TABLE token_usage (
  id                  text PRIMARY KEY,
  tenant_id           text NOT NULL,
  cluster_id          text,
  incident_id         text,
  model               text NOT NULL,
  task_tier           text NOT NULL,
  tokens_billed_in    bigint NOT NULL,
  tokens_out          bigint NOT NULL,
  cost_usd            numeric(10,4) NOT NULL,
  recorded_at         timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX token_usage_cluster_time_idx ON token_usage (cluster_id, recorded_at);
CREATE INDEX token_usage_tenant_time_idx ON token_usage (tenant_id, recorded_at);
