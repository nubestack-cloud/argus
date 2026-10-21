-- BACKLOG.md L2 (decided 2026-08-30): the storage half of past-incident
-- retrieval. Decision D6 (lld/14-adrs.md) already picked `pgvector` for the
-- vector store; DESIGN.md §16.2 already defaults the `embedding` task tier to
-- a self-hosted local model (`bge-m3`, 1024-dim, 8k window); DESIGN.md §910
-- specifies what to embed: "Resolved incidents — embedding of (symptom, root
-- cause, fix, outcome)."
--
-- This migration ONLY adds storage. Nothing in this repo reads this table
-- yet — retrieval into the investigation prompt is explicitly deferred per
-- the same decision (BACKLOG.md L2's own text: "do NOT wire retrieval into
-- the investigation prompt until it would actually return something
-- useful"). Do not treat this table's existence as license to add a
-- search_knowledge tool ahead of that decision being revisited.

CREATE EXTENSION IF NOT EXISTS vector;

-- One row per analysis that has been successfully embedded — NOT one row per
-- analysis. An analysis with no row here has not yet been embedded (never
-- attempted, Ollama unreachable at the time, etc.) rather than embedded with
-- a fabricated placeholder vector; internal/knowledge's backfill sweep finds
-- these via a LEFT JOIN against `analyses` and retries them. This is the
-- "nullable / a retriable queue" the task decision calls for, implemented as
-- row absence rather than a nullable `embedding` column, since pgvector's
-- NOT NULL constraint then guarantees every row that DOES exist carries a
-- real vector, never a NULL or zero one masquerading as one.
--
-- outcome_final records whether embedded_text's "outcome" component reflects
-- a terminal incident state (Resolved/Dismissed, internal/orchestrator.
-- IsTerminalState) at the time this row was last written. An analysis
-- embedded while its incident is still open is embedded with whatever is
-- known ("outcome not yet known" — never a fabricated one), and
-- outcome_final stays false so the same backfill sweep re-embeds it later
-- once the incident actually reaches a terminal state — the "nullable /
-- updatable" behaviour the task decision asks for, without adding a second
-- trigger point in every incident-closing code path.
CREATE TABLE analysis_embeddings (
  analysis_id     text PRIMARY KEY REFERENCES analyses(id),
  incident_id     text NOT NULL,               -- denormalized: avoids a join from every future retrieval query back through analyses.
  tenant_id       text NOT NULL,               -- denormalized per lld/05-data-model.md §6's convention.
  cluster_id      text NOT NULL,               -- denormalized per the same convention; also this table's RLS predicate column, below.
  model           text NOT NULL,               -- the embedding model that produced `embedding` (e.g. 'bge-m3') — DESIGN.md §16.2's own note that changing embedding model requires a full reindex is why this is recorded per row, not assumed global.
  embedded_text   text NOT NULL,               -- the exact (symptom, root cause, fix, outcome) text that was embedded — kept so a future reindex or audit doesn't have to reconstruct it from scratch.
  embedding       vector(1024) NOT NULL,       -- bge-m3's dimension (DESIGN.md §16.2). NOT NULL is deliberate: see the row-absence note above.
  outcome_final   boolean NOT NULL DEFAULT false,
  created_at      timestamptz NOT NULL DEFAULT now(),
  updated_at      timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX analysis_embeddings_incident_idx ON analysis_embeddings (incident_id);

-- No ANN index (ivfflat/hnsw) yet — deliberately. Retrieval (L2's deferred
-- second half) isn't wired into anything, so there is no query pattern yet
-- to tune one against; add it when retrieval lands, per the decision's own
-- "don't build the expensive, uncertain part yet" reasoning.

ALTER TABLE analysis_embeddings ENABLE ROW LEVEL SECURITY;
ALTER TABLE analysis_embeddings FORCE ROW LEVEL SECURITY;

-- NOT the single permissive cluster-keyed policy migration 000009's generic
-- loop used to use on findings/incidents/analyses — migration 000035 had to
-- correct that shape three times over (its comment is the full account) once
-- a cross-cluster, tenant-wide reader showed up, because "empty
-- app.accessible_cluster_ids list" meant "zero rows," not "no narrowing."
-- This table has exactly that same access pattern from day one: writes are
-- always cluster-scoped (internal/knowledge's per-analysis embed sets scope
-- to the one cluster the analysis belongs to, same shape as
-- internal/autoanalyze.investigateOne), but the backfill sweep
-- (internal/knowledge's RunBackfillSweep) has to see every analysis
-- tenant-wide to find the ones still missing a row here, the same shape as
-- internal/autoanalyze.collectEligible — both call SetRequestScope with a
-- nil cluster list. So this table is given 000035's settled two-policy
-- shape directly, rather than starting with the bug and needing a follow-up
-- migration to fix it: a PERMISSIVE tenant_id policy (admits every row of
-- the single tenant when accessible_cluster_ids is unset/empty) plus a
-- RESTRICTIVE cluster_id policy (narrows to the list when one is actually
-- set). See migration 000035's own comment for the full reasoning, the
-- USING/WITH CHECK duplication rationale, and the "empty list = no
-- narrowing" contract this depends on.
CREATE POLICY analysis_embeddings_tenant_scope ON analysis_embeddings
  USING (tenant_id = current_setting('app.tenant_id', true));

CREATE POLICY analysis_embeddings_cluster_scope ON analysis_embeddings AS RESTRICTIVE
  USING (
    COALESCE(current_setting('app.accessible_cluster_ids', true), '') = ''
    OR cluster_id = ANY(string_to_array(current_setting('app.accessible_cluster_ids', true), ','))
  )
  WITH CHECK (
    COALESCE(current_setting('app.accessible_cluster_ids', true), '') = ''
    OR cluster_id = ANY(string_to_array(current_setting('app.accessible_cluster_ids', true), ','))
  );

GRANT SELECT, INSERT, UPDATE, DELETE ON analysis_embeddings TO argus_app;
