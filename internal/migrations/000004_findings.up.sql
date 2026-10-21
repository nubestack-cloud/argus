-- Detection layer output. Monthly range-partitioned on occurred_at (lld/05-data-model.md §5) —
-- dropping a month-old partition is how 30-day retention (lld/05 §9) is actually enforced,
-- not a DELETE scan. A DEFAULT partition catches anything not yet covered by a dated
-- partition; a scheduled job must keep creating next-month partitions ahead of time so
-- writes never actually land in the default one in steady state.

CREATE TABLE findings (
  id                text NOT NULL,
  tenant_id         text NOT NULL,
  cluster_id        text NOT NULL REFERENCES clusters(id),
  detector_id       text NOT NULL,
  detector_version  text NOT NULL,
  fingerprint       text NOT NULL,
  gvk               text NOT NULL,
  namespace         text,
  object_name       text,
  object_uid        text,
  resource_version  text,
  reason            text,
  message           text,
  occurrence_count  int NOT NULL DEFAULT 1,
  severity          text NOT NULL,
  occurred_at       timestamptz NOT NULL,
  ingested_at       timestamptz NOT NULL DEFAULT now(),
  incident_id       text,
  PRIMARY KEY (id, occurred_at)
) PARTITION BY RANGE (occurred_at);

CREATE TABLE findings_default PARTITION OF findings DEFAULT;

CREATE INDEX findings_cluster_fingerprint_idx ON findings (cluster_id, fingerprint, occurred_at DESC);
