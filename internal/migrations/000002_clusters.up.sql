-- Cluster/fleet inventory. See lld/03-agent-protocol.md §8, lld/05-data-model.md §3.2.

CREATE TABLE clusters (
  id                  text PRIMARY KEY,
  tenant_id           text NOT NULL REFERENCES organisations(id),
  display_name        text NOT NULL,
  labels              jsonb NOT NULL DEFAULT '{}',
  -- lld/03-agent-protocol.md §4's full cluster state machine. Missing from the
  -- original DDL sketch (this table had no CHECK at all) — added directly here
  -- rather than as a later migration, since nothing has shipped against the gap.
  state               text NOT NULL CHECK (state IN (
    'PendingApproval', 'Provisioning', 'Active', 'Degraded', 'Disconnected',
    'IncompatibleVersion', 'Rejected', 'Archived'
  )),
  shard_id            text NOT NULL,
  agent_version       text,
  cert_serial         text,
  cluster_fingerprint text NOT NULL,
  last_heartbeat_at   timestamptz,
  accepted_by         text REFERENCES users(id),
  created_at          timestamptz NOT NULL DEFAULT now(),
  archived_at         timestamptz
);
CREATE UNIQUE INDEX clusters_fingerprint_active_idx ON clusters (cluster_fingerprint) WHERE archived_at IS NULL;
CREATE INDEX clusters_labels_gin_idx ON clusters USING gin (labels);

CREATE TABLE cluster_groups (
  id              text PRIMARY KEY,
  tenant_id       text NOT NULL REFERENCES organisations(id),
  name            text NOT NULL,
  label_selector  jsonb NOT NULL
);

CREATE TABLE cluster_facts (
  cluster_id      text PRIMARY KEY REFERENCES clusters(id),
  facts           jsonb NOT NULL,
  updated_at      timestamptz NOT NULL DEFAULT now()
);

-- Evidence ABOUT the LocalGuardrail CR (its self-reported hash), never its content.
-- The hub has zero RBAC on LocalGuardrail itself (lld/04-rbac-profiles.md §6) — do not
-- add a column here that would tempt storing guardrail content; that would defeat the
-- whole point of the split.
CREATE TABLE local_guardrail_snapshots (
  id              text PRIMARY KEY,
  cluster_id      text NOT NULL REFERENCES clusters(id),
  reported_hash   text NOT NULL,
  reported_at     timestamptz NOT NULL DEFAULT now()
);
