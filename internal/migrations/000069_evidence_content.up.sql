-- Give the `evidence` table (migration 000005) a real writer and a real
-- reader. BACKLOG.md B2 / lld/11-ui-design.md §4's GET
-- /incidents/{id}/evidence/{evId}. Before this migration nothing wrote a row
-- here at all (STATUS.md §2, BUGS.md 84's correction note) and its RLS policy
-- had never been exercised by a real caller.
--
-- WHY THIS TABLE NOW, AND WHY ITS SHAPE CHANGES: internal/llm/toolloop.go's
-- api-backend investigation loop already carries each tool call's full
-- Args/Result inline in analyses.causal_chain (ToolCallRecord — a documented
-- MVP simplification of exactly this table, see that struct's own doc
-- comment). This migration gives each of those tool calls a second, durable
-- home with a stable id (domain.PrefixEvidence, "ev_...") a UI can fetch by
-- itself, per lld/11 §4's "fetched lazily per causal-chain-step expansion,
-- never eagerly bundled into the analysis response" — the shape the inline
-- simplification never had room for.
--
-- MinIO vs inline in Postgres: lld/05-data-model.md's original sketch put
-- object_store_key here because it assumed a real object store. No
-- deployment this repo ships (docker-compose or the Helm chart) runs one
-- today (STATUS.md), and blocking evidence drill-down on standing up MinIO
-- first would trade a real, working, redacted-and-bounded feature for an
-- infrastructure dependency nothing else in the stack needs yet. The content
-- captured here is already small and already bounded by the tool surface's
-- own caps (get_logs: tailLines default 200, hard-capped 5000;
-- list_resources: limit default 50, hard-capped 200; describe_resource: one
-- object) — nowhere near what would justify a blob store. So: store the
-- (already redacted) content INLINE, in `result`/`error` below, and leave
-- object_store_key nullable and unused for now rather than inventing a fake
-- key for a store that does not exist. The column stays, rather than being
-- dropped, so a real object-store backend can be introduced later as a
-- per-row choice (large content goes to the key, small content stays inline)
-- without another migration to re-add it.
ALTER TABLE evidence ALTER COLUMN object_store_key DROP NOT NULL;

-- Denormalized like every other cluster-scoped table (lld/05 §6) AND
-- specifically so GET /incidents/{id}/evidence/{evId} can check "this
-- evidence row actually belongs to the incident named in the URL" with a
-- plain equality, the same defense-in-depth incidents.object_key gives
-- correlation — RLS (below) is what actually enforces tenant/cluster
-- isolation; this column is what stops evId belonging to a DIFFERENT
-- incident on a cluster the caller can otherwise read from resolving through
-- the wrong incident's page.
ALTER TABLE evidence ADD COLUMN incident_id text NOT NULL DEFAULT '';
ALTER TABLE evidence ALTER COLUMN incident_id DROP DEFAULT;

-- Which MCP tool this evidence came from (get_events, get_logs,
-- describe_resource, list_resources, get_owner_chain, get_gitops_ownership).
-- Not CHECK-constrained, matching mcp_tool_calls' tool column (migration
-- 000037) and for the identical reason: that set is defined in Go and grows
-- there, and a CHECK would turn "a tool was added" into a failed insert on
-- the investigation hot path.
ALTER TABLE evidence ADD COLUMN tool text NOT NULL DEFAULT '';
ALTER TABLE evidence ALTER COLUMN tool DROP DEFAULT;

-- ok/error, mirroring mcp_tool_calls.outcome exactly (same spelling, same
-- reason: the writer and reader must agree, and reusing the established
-- vocabulary is cheaper than inventing a second one for the same fact).
ALTER TABLE evidence ADD COLUMN outcome text NOT NULL DEFAULT 'ok';
ALTER TABLE evidence ALTER COLUMN outcome DROP DEFAULT;
ALTER TABLE evidence ADD CONSTRAINT evidence_outcome_valid CHECK (outcome IN ('ok', 'error'));

-- The tool call's arguments. Never expected to carry secret material (they
-- are namespace/name/gvk-shaped, per internal/llm/toolloop.go's
-- toolDefinitions), but stored as exactly what the model sent, for the same
-- "show the actual investigation, not a paraphrase of it" reason the
-- causal_chain simplification exists at all.
ALTER TABLE evidence ADD COLUMN args jsonb NOT NULL DEFAULT '{}'::jsonb;

-- Exactly one of these two is set, matching outcome — enforced at the
-- application layer (internal/api.persistEvidence), not a CHECK: the two
-- columns' NULL-ness already makes "which happened" unambiguous to read, and
-- a CHECK spelling out "outcome='ok' iff result is not null" buys nothing a
-- reader can't already see from the data, for one more constraint to keep in
-- sync with the Go code that writes it.
--
-- `result` is the already-redacted tool result exactly as it crossed the
-- tunnel — internal/redact's agent-side chokepoints (ToolExecutor.Execute)
-- ran on this content before it ever left the cluster, and nothing in this
-- write path re-reads or re-fetches it. No size bound is applied here beyond
-- the tool surface's own agent-side caps (see this file's header) — a second,
-- independent truncation layer on top of an already-JSON-valid payload would
-- either have to re-parse it to truncate safely or risk storing invalid JSON,
-- for a case the existing caps already make rare.
ALTER TABLE evidence ADD COLUMN result jsonb;
-- Same 2000-byte bound as mcp_tool_calls.error / maxToolCallErrorLen
-- (internal/api/evidence.go), and the same reasoning: a tool failure's text
-- comes from the cluster's own API server and has no guaranteed size, and an
-- unbounded row for a column only a human debugging one call ever reads is a
-- real, unbounded cost for no benefit.
ALTER TABLE evidence ADD COLUMN error text;

CREATE INDEX evidence_incident_idx ON evidence (incident_id);

-- RLS. The single permissive cluster-keyed policy migration 000009 gave this
-- table has never had a real caller, and it has a sharp edge that would make
-- one now: with app.accessible_cluster_ids unset (every unrestricted,
-- AllClusters-granted caller today — internal/api/middleware.go's
-- requireAuth only narrows it when the resolved grant set is NOT
-- unrestricted), `string_to_array('', ',')` is `{}` in Postgres, so
-- `cluster_id = ANY('{}')` is false for every row, for every caller, always.
-- migration 000035's header calls this "left exactly as it is" for the other
-- tables in this table's cohort, and that was the right call while nothing
-- read any of them — narrowing further than "no real reader" is impossible.
-- The first real reader changes that calculus: as written, GET
-- /incidents/{id}/evidence/{evId} would 404 for every caller with ordinary,
-- unrestricted access, which is not a narrowing, it is a table nobody can
-- ever read. Given that the fix has to happen once evidence.go's queries land
-- to be exercised at all, replacing the permissive cluster-only policy with
-- the tenant-permissive-plus-cluster-restrictive shape mcp_tool_calls
-- (migration 000037) already established for exactly this table's own
-- cohort is that fix, applied here rather than left for a second migration
-- for the same reason 000037 was born with it instead of retrofitting it
-- later.
DROP POLICY IF EXISTS evidence_scope ON evidence;
CREATE POLICY evidence_tenant_scope ON evidence
  USING (tenant_id = current_setting('app.tenant_id', true));
CREATE POLICY evidence_cluster_scope ON evidence AS RESTRICTIVE
  USING (
    COALESCE(current_setting('app.accessible_cluster_ids', true), '') = ''
    OR cluster_id = ANY(string_to_array(current_setting('app.accessible_cluster_ids', true), ','))
  )
  WITH CHECK (
    COALESCE(current_setting('app.accessible_cluster_ids', true), '') = ''
    OR cluster_id = ANY(string_to_array(current_setting('app.accessible_cluster_ids', true), ','))
  );
