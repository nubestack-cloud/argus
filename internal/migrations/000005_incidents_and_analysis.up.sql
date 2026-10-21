-- See lld/05-data-model.md §3.5, lld/08-remediation-contracts.md §2 (state machine).

CREATE TABLE incidents (
  id                  text NOT NULL,
  tenant_id           text NOT NULL,
  cluster_id          text NOT NULL REFERENCES clusters(id),
  fleet_group_id      text,
  fingerprint         text NOT NULL,
  severity            text NOT NULL,
  state               text NOT NULL CHECK (state IN (
    'Detected','Investigating','RecommendationReady','NeedsHumanInvestigation',
    'AwaitingApproval','Executing','AwaitingMerge','Validating',
    'Resolved','Failed','Reopened','Dismissed'
  )),
  first_seen          timestamptz NOT NULL,
  last_seen           timestamptz NOT NULL,
  occurrence_count    int NOT NULL DEFAULT 1,
  linked_incident_id  text,
  archived_at         timestamptz,
  PRIMARY KEY (id, first_seen)
) PARTITION BY RANGE (first_seen);

CREATE TABLE incidents_default PARTITION OF incidents DEFAULT;

CREATE INDEX incidents_cluster_state_idx ON incidents (cluster_id, state, severity, first_seen DESC);
CREATE INDEX incidents_fleet_group_idx ON incidents (fleet_group_id) WHERE fleet_group_id IS NOT NULL;

CREATE TABLE analyses (
  id                  text PRIMARY KEY,
  incident_id         text NOT NULL,
  tenant_id           text NOT NULL,
  cluster_id          text NOT NULL,
  prompt_version      text NOT NULL,
  model               text NOT NULL,
  causal_chain        jsonb NOT NULL,
  ruled_out           jsonb NOT NULL DEFAULT '[]',
  root_cause          jsonb,
  confidence          numeric(4,3),
  iterations          int NOT NULL,
  duration_ms         int NOT NULL,
  tokens_billed_in    bigint NOT NULL,
  tokens_cache_read   bigint NOT NULL,
  tokens_out          bigint NOT NULL,
  cost_usd            numeric(10,4) NOT NULL,
  created_at          timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE evidence (
  id                text PRIMARY KEY,
  analysis_id       text NOT NULL REFERENCES analyses(id),
  tenant_id         text NOT NULL,
  cluster_id        text NOT NULL,
  kind              text NOT NULL,
  object_store_key  text NOT NULL,
  size_bytes        int NOT NULL,
  redacted          boolean NOT NULL DEFAULT true,
  captured_at       timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE timeline_events (
  id              text PRIMARY KEY,
  incident_id     text NOT NULL,
  tenant_id       text NOT NULL,
  cluster_id      text NOT NULL,  -- denormalized per §6's RLS convention; missing from the LLD-05 sketch, fixed here
  event_type      text NOT NULL,
  payload         jsonb NOT NULL,
  occurred_at     timestamptz NOT NULL DEFAULT now()
);
