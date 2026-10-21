-- PROJECT.md B151: the cli backend's own tool calls have never had their
-- CONTENT recorded anywhere the hub can later check against — only the fact
-- of the call (mcp_tool_calls, migration 000037) or the API backend's own
-- real-time dispatch (evidence, migration 000005/000069, keyed to an
-- analysis_id that does not exist yet while a cli-backend investigation is
-- still running). The consequence, found live: a cli-backend investigation's
-- causal-chain step named a tool call "corroborated": true — meaning only
-- "a call of this name was dispatched and did not error" — right next to a
-- Finding whose specific cited facts were never checked against anything.
-- That gap is why a live `CreateResource` execution wrote factually wrong
-- data to a real cluster object with nothing in the product's own evidence
-- trail able to catch it.
--
-- 000037's own header explains, correctly, why mcp_tool_calls itself stays
-- content-free: its callers (the blast-radius budget, the circuit breaker)
-- only ever need a count, and copying customer cluster state into that
-- table for their sake would be the wrong trade. That reasoning does not
-- change here — this is a DIFFERENT, ADDITIONAL table, written by the exact
-- same call site (internal/mcp/server.go's handleToolCall) for the exact
-- same reason evidence (000005/000069) already exists for the api backend:
-- "what did this one tool call see" is a real, distinct question from "how
-- much work happened", and a product whose first promise is "evidence, not
-- assertions" cannot make that promise on the mutation path for the ONE
-- backend this deployment actually runs (confirmed live 2026-09-07: this
-- org's only configured ai_providers row has kind='cli' — the api backend's
-- own evidence table, real and correct as far as it goes, has never once
-- been exercised by a live investigation here).
--
-- SHAPE, deliberately close to evidence's:
--
--   * No analysis_id — same reason mcp_tool_calls has none: the analyses row
--     is written after the investigation returns, while these rows are
--     written during it. Keyed to (cluster_id, incident_id, tool), matched
--     up after the fact by internal/llm.crossCheckCausalChain the same way
--     it already matches against mcp_tool_calls today, just with content
--     available this time.
--   * args/result are jsonb, nullable — result is NULL exactly when outcome
--     is 'error' (mirroring evidence's own args/result/error three-way,
--     BUGS.md's established pattern for "one of these three, never a
--     meaningless zero value in the other two").
--   * redacted is NOT NULL DEFAULT true and is never set false by any writer
--     — the redaction guarantee (argus-context non-negotiable 9,
--     internal/redact) already applies unconditionally, agent-side, before
--     this content ever reaches the hub, for every tool regardless of which
--     backend is asking. This column exists so a query can assert that
--     invariant rather than trust it silently, matching evidence's own
--     column for the identical reason.
CREATE TABLE mcp_tool_call_content (
  id          text PRIMARY KEY,   -- 'mtcc_...' (domain.PrefixMCPToolCallContent)
  tenant_id   text NOT NULL,
  cluster_id  text NOT NULL,
  incident_id text NOT NULL,
  tool        text NOT NULL,
  outcome     text NOT NULL CHECK (outcome IN ('ok', 'error')),
  args        jsonb NOT NULL,
  result      jsonb,
  error       text,
  redacted    boolean NOT NULL DEFAULT true,
  created_at  timestamptz NOT NULL DEFAULT now()
);

-- Every read is "this one incident's calls of this tool, most recent first"
-- (internal/llm's ledger lookup, matching mcp_tool_calls' own read shape).
CREATE INDEX mcp_tool_call_content_incident_idx ON mcp_tool_call_content (incident_id, created_at DESC);

-- RLS: identical shape to mcp_tool_calls (migration 000037) — see that
-- migration's own comment for the full reasoning (a PERMISSIVE tenant policy,
-- a RESTRICTIVE cluster-narrowing policy, both spelled out rather than relying
-- on the defaulting rule). This table is written from the exact same
-- transaction-per-call site mcp_tool_calls already is, which already resolves
-- and sets scope the same established out-of-request way.
ALTER TABLE mcp_tool_call_content ENABLE ROW LEVEL SECURITY;
ALTER TABLE mcp_tool_call_content FORCE ROW LEVEL SECURITY;
CREATE POLICY mcp_tool_call_content_tenant_scope ON mcp_tool_call_content
  USING (tenant_id = current_setting('app.tenant_id', true));
CREATE POLICY mcp_tool_call_content_cluster_scope ON mcp_tool_call_content AS RESTRICTIVE
  USING (
    COALESCE(current_setting('app.accessible_cluster_ids', true), '') = ''
    OR cluster_id = ANY(string_to_array(current_setting('app.accessible_cluster_ids', true), ','))
  )
  WITH CHECK (
    COALESCE(current_setting('app.accessible_cluster_ids', true), '') = ''
    OR cluster_id = ANY(string_to_array(current_setting('app.accessible_cluster_ids', true), ','))
  );

GRANT SELECT, INSERT, UPDATE, DELETE ON mcp_tool_call_content TO argus_app;
