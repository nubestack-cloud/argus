---
name: argus-add-mcp-tool
description: Add a read-only tool to one of ARGUS's three tool surfaces — the investigation loop the model drives (both the api and cli backends), the cluster-inspection allowlist behind POST /clusters/{id}/inspect/{tool} that the UI and personal MCP clients use, or the hub-side personal MCP catalogue — with the agent executor, redaction classification, role routing, allowlists and tests each surface needs. Use when asked to add an MCP tool, a diagnostic or investigation tool, a new thing the model can look at, or a new cluster-inspection view backed by the agent.
argument-hint: [tool name and what it reads, e.g. "get_hpa_status — HPA targets and current metrics"]
---

# Add a tool

Apply [`argus-context`](../argus-context/SKILL.md) first, especially non-negotiables 3 (MCP is not
an authorization boundary) and 9 (redaction at capture). Every tool here is **read-only**. Anything
that writes is a remediation action ([`argus-add-remediation-action`](../argus-add-remediation-action/SKILL.md)).

## 1. Which surface?

| Surface | Who calls it | Where the list lives |
|---|---|---|
| **Investigation** | The model, during analysis. The `api` backend runs the loop in the hub; the `cli` backend runs it in `cmd/cli-runner` over MCP. | `internal/llm/toolloop.go`'s `toolDefinitions` (always offered) and the conditional defs that `offeredToolDefinitions` adds per cluster or incident. The `cli` MCP surface is projected from the same list (`InvestigationToolSchemas`), so the two cannot drift. |
| **Cluster inspection** | The cluster page's tabs, and people's own MCP clients through a personal access token. | The allowlist in `internal/api/cluster_inspect.go`. |
| **Hub-side personal MCP** | People's MCP clients, for hub data (incidents, clusters, search). | `userMCPCatalogue` in `internal/api/mcp_user.go`. Each tool runs its REST handler in a transaction that is always rolled back. |

Most new cluster-reading tools start as inspection tools. Offer one to the model only when an
investigation needs it, because each tool offered costs tokens on every turn.

## 2. The agent side (investigation and inspection tools)

- **Executor** in `internal/agent`: a `tools_<name>.go` file with a typed args struct, decoded and
  validated (reject an unknown GVK or a malformed name), and a `case` in `tools.go`'s dispatch.
- **Reads go through the agent's client** under the `argus-investigate` identity. If it needs a
  resource the ClusterRole lacks, that is an RBAC change in
  `deploy/helm/argus-agent/templates/clusterrole.yaml`; route it through
  [`argus-security-review`](../argus-security-review/SKILL.md). Never Secrets, `pods/exec` or
  `nodes/proxy`.
- **Redaction**: classify the tool in `internal/agent/redact_egress_test.go`'s
  `toolRedactionCoverage`. The test fails until you do. `ToolExecutor.Execute` redacts the output
  by field class and pattern; make sure free-text fields go through it, rather than around it.
- **Role routing**: a read tool must **not** be in `tunnel.writeToolRoles`, so it is dispatched to
  the read-only connection.
- **Bounded output**: cap list lengths and log tails, and say in the result when you capped, with the
  true total. A tunnel frame has a size limit.
- **Degrade**: a missing CRD or a forbidden read returns a typed "not available here" answer, not an
  error the model or the UI must interpret.

## 3. Per surface

**Investigation tool.** Add its schema to `toolDefinitions`, or as a conditional def gated in
`offeredToolDefinitions` when it depends on an opt-in grant or a configured integration, as
`dry_run_patch` and `query_metrics` do. Both what is **advertised** and what a returned call is
**allowed** to invoke go through that one function. Never add a tool to only one of the two. Update the
prompt's description of the tools if it lists them. Remember the tool's output is untrusted data in
the prompt; the safety that matters is downstream (closed action schema, risk floor, approval).

**Inspection tool.** Add the name to `cluster_inspect.go`'s allowlist, so it is reachable both for
the UI and for personal MCP clients. Add the response schema to `docs/openapi.yaml`, run
`npm run generate-api-types`, and add a typed client function. For a UI view, continue with
[`argus-add-screen`](../argus-add-screen/SKILL.md).

**Hub-side MCP tool.** Add an entry to `userMCPCatalogue`, naming the capability it requires and
the REST handler it runs. It inherits scope narrowing and the rolled-back transaction from the mount.
Never add a mutating tool there: the surface is read-only by construction, and the addendum in
`lld/01-threat-model.md` says why.

External MCP servers (third-party tools the model could call) are not built. Adding one is a
security design, not a scaffold; start with the threat model.

## 4. Tests

- An executor test with the fake clientset: the normal case, a malformed argument, a missing kind.
- The redaction coverage test passing with the new classification. If the output carries free text,
  add a case showing a planted credential is redacted.
- For an investigation tool: the existing tests that pin the advertised list to the allowed list,
  and the `api` list to the `cli` projection, still pass.
- Live: call it through `POST /clusters/{id}/inspect/{tool}` (or an analysis that uses it) on a lab
  cluster ([`argus-live-test`](../argus-live-test/SKILL.md)).

## Output

The surface, the args and result schema, the RBAC it relies on, its redaction classification, how it
bounds its output, the allowlist entries added, and the tests.
