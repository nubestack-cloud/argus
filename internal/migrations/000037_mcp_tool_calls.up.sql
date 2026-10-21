-- Which questions an investigation actually asked the cluster.
--
-- The cli backend (internal/llm/cli_investigator.go, lld/14-adrs.md ADR-17)
-- does not own the tool-calling loop: the CLI drives it and calls back into
-- the hub's MCP server (internal/mcp), so this process never observes the
-- intermediate turns and analyses.causal_chain is stored EMPTY for those runs.
-- That emptiness is deliberate and stays deliberate — synthesising a causal
-- chain the hub did not witness would render as evidence, which is worse than
-- rendering nothing. The observed consequence is what this table fixes: a real
-- investigation made 13 MCP tool calls against a live cluster and produced a
-- correct, high-confidence root cause, and the incident page showed a verdict
-- with no visible work behind it. Auditable and oracular is the whole
-- difference between an operator trusting the verdict and not.
--
-- The facts were already resolved and already thrown away. internal/mcp
-- resolves each call's cluster AND incident from the scoped token (token.go's
-- Grant, SR-24 — never from runner-supplied parameters) and logged one line
-- per call: `mcp: tool describe_resource cluster=cl_… incident=inc_… ok`. This
-- table is that log line, kept.
--
-- SHAPE. Deliberately not a second causal_chain:
--
--   * No arguments and no result payload. Results are large and are raw
--     cluster data (namespaces, image tags, log lines) — persisting them would
--     put a copy of the customer's cluster state in the hub's own database for
--     the sake of a count, and would make this table the largest one here by
--     an order of magnitude. The product question is which questions were
--     asked, not what came back; internal/mcp/server.go's recording site
--     restates this so the omission reads as a decision rather than an
--     oversight.
--   * Keyed to the incident, not to an analysis. There is no analysis id to
--     key on: the analyses row is written after the investigation returns,
--     while these rows are written during it, and the MCP grant carries only
--     cluster + incident. An incident analysed twice therefore accumulates
--     both runs' calls, which is why internal/api surfaces this as the
--     incident's evidence rather than as a field of one analysis.
--   * No foreign keys, matching remediation_executions (000031), whose
--     incident_id is likewise a bare text column. Two reasons here rather than
--     one: the writer runs on the MCP listener's own connection during a live
--     tool call and must never fail that call (a FK gives it a brand-new
--     failure mode — a concurrently archived or demo-cleared incident), and
--     this is a record of something that happened, not a relationship to
--     something that still exists.
CREATE TABLE mcp_tool_calls (
  id          text PRIMARY KEY,   -- 'mtc_...' (domain.PrefixMCPToolCall)
  tenant_id   text NOT NULL,
  -- Both resolved from the scoped token, never from the caller. Stored
  -- together because the cluster is what the RLS narrowing below keys on and
  -- the incident is what every read keys on.
  cluster_id  text NOT NULL,
  incident_id text NOT NULL,
  -- The MCP tool name as offered (llm.InvestigationToolSchemas): get_events,
  -- get_logs, describe_resource, list_resources, get_owner_chain,
  -- get_gitops_ownership. Not constrained by a CHECK, deliberately: that set
  -- is defined in Go and grows there, and a CHECK would turn "a tool was added
  -- without a migration" into a failed insert on the investigation hot path —
  -- i.e. into exactly the bookkeeping-breaks-investigations failure this
  -- table's writer is built to avoid. An unrecognised name is a labelling
  -- problem in the UI, which handles it, not a data-integrity problem.
  tool        text NOT NULL,
  outcome     text NOT NULL CHECK (outcome IN ('ok', 'error')),
  -- Required when outcome = 'error', NULL when 'ok'. Not a CHECK, following
  -- remediation_executions.error's own precedent for why this stays an
  -- application-layer invariant.
  error       text,
  -- How long the tool call itself took, gateway round trip included. Recorded
  -- because "the investigation spent 40s in get_logs" is the first question
  -- asked of a slow run, and it cannot be reconstructed later from anything
  -- else.
  duration_ms integer NOT NULL,
  created_at  timestamptz NOT NULL DEFAULT now()
);

-- Every read is "this one incident's calls" (internal/api's per-incident
-- aggregate). No created_at in the index: unlike remediation_executions'
-- incident index, nothing here orders or paginates — the aggregate reads the
-- whole (small) set for one incident and folds it in Go.
CREATE INDEX mcp_tool_calls_incident_idx ON mcp_tool_calls (incident_id);

-- **RLS ON, unlike ai_providers (000034).** That migration's decision to omit
-- it was correct for what it is and is the wrong precedent for this table, so
-- the distinction is recorded here rather than left to be inferred:
--
--   * ai_providers is a single org-wide CONFIGURATION set, read on the
--     investigation hot path by settings.Resolve through a BARE POOL
--     CONNECTION with no app.tenant_id set. A tenant policy there hid every
--     row and silently broke provider resolution. Nothing about that
--     reasoning transfers.
--   * mcp_tool_calls is per-incident, per-cluster OPERATIONAL data — the same
--     class as incidents/findings/analyses, all of which have RLS — and both
--     of its accessors run inside a real transaction that has already set
--     app.tenant_id: reads come from internal/api's request transaction
--     (middleware.go's requireAuth), and writes come from internal/api's
--     RecordMCPToolCall, which opens its own transaction and calls
--     data.SingleOrganisationID + data.SetRequestScope — the established
--     out-of-request pattern (gateway/health.go's sweep, orchestrator/
--     validation.go, notify/notifier.go). So the failure mode that forced
--     000034's hand structurally cannot occur here, and omitting RLS would
--     leave the newest table in the schema as the one place a future
--     cross-tenant read is not stopped by the database.
--
-- The tenant policy is the only PERMISSIVE one, and cluster narrowing is
-- expressed as a RESTRICTIVE policy — the shape 000035 had to retrofit onto
-- findings/incidents/analyses after four migrations had each added a
-- permissive tenant policy beside a permissive cluster policy and OR'd the
-- narrowing away. 000035's header notes that the newer remediation_* tables
-- "will need the restrictive treatment when per-cluster grants land"; a table
-- created after that correction should be born with it instead of joining that
-- backlog. Semantics are 000035's exactly, including the sharp edge: an unset
-- or empty app.accessible_cluster_ids means NO narrowing (every hub caller
-- that reads fleet-wide passes nil), and a grant resolving to zero clusters
-- must be denied at the application layer rather than expressed as an empty
-- list. USING and WITH CHECK are both spelled out for the restrictive policy
-- rather than relying on the defaulting rule, matching 000035.
ALTER TABLE mcp_tool_calls ENABLE ROW LEVEL SECURITY;
ALTER TABLE mcp_tool_calls FORCE ROW LEVEL SECURITY;
CREATE POLICY mcp_tool_calls_tenant_scope ON mcp_tool_calls
  USING (tenant_id = current_setting('app.tenant_id', true));
CREATE POLICY mcp_tool_calls_cluster_scope ON mcp_tool_calls AS RESTRICTIVE
  USING (
    COALESCE(current_setting('app.accessible_cluster_ids', true), '') = ''
    OR cluster_id = ANY(string_to_array(current_setting('app.accessible_cluster_ids', true), ','))
  )
  WITH CHECK (
    COALESCE(current_setting('app.accessible_cluster_ids', true), '') = ''
    OR cluster_id = ANY(string_to_array(current_setting('app.accessible_cluster_ids', true), ','))
  );

-- Explicit grant, redundant but deliberate: 000009's ALTER DEFAULT PRIVILEGES
-- already grants these four on every table created after it, and every
-- migration since 000010 has spelled the grant out anyway rather than relying
-- on it (000016's and 000018's comments call this belt-and-suspenders
-- explicitly). Matching that is worth more than saving a line.
--
-- The obvious narrowing — SELECT and INSERT only, since these rows are an
-- append-only record of things that already happened and no code path updates
-- or deletes one — was considered and rejected. It cannot be expressed as a
-- narrower GRANT at all: 000009's default privileges have already granted
-- UPDATE/DELETE by the time this statement runs, so it would take an explicit
-- REVOKE, making this the one table in the schema whose privileges differ from
-- every other, including audit_events — the table with the strongest
-- tamper-evidence requirement here, which keeps the full set and relies on its
-- hash chain instead. A lone exception that surprises the next writer of a
-- retention or demo-data sweep is a worse trade than append-only being an
-- application-level property, as it already is everywhere else here.
GRANT SELECT, INSERT, UPDATE, DELETE ON mcp_tool_calls TO argus_app;
