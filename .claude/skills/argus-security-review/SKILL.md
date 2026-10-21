---
name: argus-security-review
description: Review an ARGUS change against its own threat model (lld/01-threat-model.md, misuse cases T1–T21 and requirements SR-1–SR-24) — scope isolation and RLS, the three service identities, capture-time redaction, what model output can cause, approval integrity, tunnel identity, outbound egress, the CLI runner's sandbox, and supply chain. Use for any change touching auth, sessions, RLS, credentials, signing, the tunnel, agent RBAC, a capability or route, remediation, MCP/tool surfaces, or outbound calls; not as a generic security checklist.
argument-hint: [diff, branch, path or area — defaults to the working-tree diff]
---

# ARGUS security review

Apply [`argus-context`](../argus-context/SKILL.md) first: its non-negotiables are the rules this
review enforces. The authority is **`lld/01-threat-model.md`**:

- §4 for the trust boundaries;
- §6 for the misuse cases (T1–T21);
- §8 for the requirements register (SR-1–SR-24) and, just below it, the audited implementation
  status of each;
- the dated addenda at the end for later boundary moves (cluster-insight egress, personal access
  tokens and the user MCP endpoint, the refresh-token grace).

Read the parts the diff touches. This skill does not restate them.

[`argus-review`](../argus-review/SKILL.md) is the general done-gate. It carries a lighter version
of the RLS and capability checks. This is the deeper pass, run as well as it, not instead.

Target: `$ARGUMENTS`, or the working-tree diff.

## How to review

For each misuse case below, decide whether the diff can affect it, and say so either way. "Not
applicable" is an answer; silence is not. Check the code, not the comment above it: this codebase
annotates code with the rules it claims to meet, and a claim is evidence of intent only.

When the diff touches an SR whose status in §8 is **Open** or **Partial**, say whether the change
moves it, and never assume it is handled because the requirement exists.

## The misuse cases, mapped to where they live in code

| Case | What to check in the diff |
|---|---|
| **T1** cross-scope data access | Every query on an RLS table runs on a scoped transaction (`rc.Tx`; `data.SetRequestScope`). Scope comes from the authenticated session and `authz.AccessibleClusterIDs`, never from a request parameter. Cluster-scoped grants narrow RLS now; a new path that skips `requireAuth` skips that too. Background jobs set scope explicitly. |
| **T2** hub compromise → fleet reach | The hub holds no cluster credentials; it reaches clusters only through agent-dialled tunnels. Nothing new lets the hub push RBAC, CRDs or arbitrary manifests to a spoke. |
| **T3** prompt injection | Cluster, repository and issue text reach the model as data. What stops a successful injection is downstream: the closed action schema, `resolution.PermittedActionTypes`, the deterministic risk floor (`internal/remediation/risk.go`, which the model may only raise) and approval. A change that weakens any of those is the finding. |
| **T4** command injection | No path from model output to a shell or to an arbitrary API call. Actions are typed (`internal/remediation/plan.go`'s `validActionTypes`); no generic string-patch type (SR-4). |
| **T5** agent credential theft | Tunnel identity binds certificate to cluster (`internal/gateway`); an archived or unknown cluster is refused. A write tool goes only to a `RoleRemediate` connection (`tunnel.RoleForTool`/`writeToolRoles`). |
| **T6** confused deputy on Git credentials | A repository URL is checked against the registered binding and allowed hosts before a credential is attached; the dial goes through `internal/outbound`. |
| **T7** malicious repository content | Rendering stays in `internal/render/sandbox` (single-use pod, no network, no host mounts, no Docker socket). Repository edits stay inside path confinement (`ForbiddenPath`, the synced directory); nothing writes CI files. |
| **T8** secrets into evidence or prompts | Redaction is at capture, in the agent (`internal/redact`, via `ToolExecutor.Execute` and the tunnel writer's `Finding.Message` filter). A new agent tool is classified in `internal/agent/redact_egress_test.go`. `Secret` objects are never fetched. No redaction moves to the hub, and no bypass flag is added. |
| **T9** approval forgery | Approval binds actor, time, plan hash, target UID and `resourceVersion`, and expiry, and is single-use. Any change to the plan or target invalidates it. |
| **T10** escalation via self-authored policy | A grant cannot widen itself; capability checks use the server's catalogue (`internal/authz/permissions.go`). |
| **T11** runaway automation | Unattended execution stays behind its master switch and namespace allowlist (`internal/api/unattended.go`); blast-radius caps, the circuit breaker, freeze windows and batch halt-on-failure stay unconditional. |
| **T12** LLM spend | A new analysis trigger goes through the spend-ceiling check (SR-13's open atomicity gap included). |
| **T13** supply chain | Images pinned by digest (`scripts/pin-image-digests.sh`); base images distroless and non-root; no new unpinned download in the Dockerfile. |
| **T14** insider super-admin | Audit writes stay on the hash chain (`internal/audit`); `argusctl audit verify` still verifies. |
| **T15** SSRF | Every hub-initiated HTTP call to an admin-configured URL uses `internal/outbound`, which refuses private, link-local and metadata ranges unless allowlisted. |
| **T16** stored XSS | No `dangerouslySetInnerHTML` on evidence- or cluster-derived content; links built from cluster data are not `javascript:`. |
| **T17** token validation | JWT parsing stays in `internal/authz/jwt.go` with the pinned algorithm, issuer, audience and expiry. Personal access tokens and MCP tokens are scoped as the addenda describe. |
| **T18** timing | `crypto/subtle` or `hmac.Equal` for every secret comparison. |
| **T19** TOCTOU | The precondition rides in the mutating call (`resourceVersion`), not check-then-apply (SR-20; `patch_field` is the named exception). |
| **T20** audit/log injection | Typed log and audit fields only; no free text parsed back as structure. |
| **T21** tools inside a CLI runner | `cmd/cli-runner` keeps the explicit tool allowlist with every built-in disabled; the runner holds no DB credential, mTLS material or signing key; its MCP token is single-investigation, single-cluster and read-only. |

## Agent RBAC

A change under `deploy/helm/argus-agent/templates/` keeps the identities separate:

- `clusterrole.yaml` (investigate) is read-only: no Secrets, no `pods/exec`, no `nodes/proxy`, and
  no `bind`, `escalate` or `impersonate`;
- `dryrun.yaml` is opt-in;
- `remediate-role.yaml` is opt-in and namespace-scoped by default, and is fenced by
  `validatingadmissionpolicy.yaml`'s field allowlist.

A new verb or resource is a finding to justify, not a line to approve.

## Output

Findings ranked by severity, each with the T or SR number, `file:line`, a concrete failure scenario
("a viewer with a grant scoped to cluster A can read cluster B's incidents via …"), and the minimal
fix if it is obvious. Then one line per misuse case: affected, not affected, or not applicable. If a
change moves an SR's status, update §8's status table in `lld/01-threat-model.md`. If it moves a
boundary, add a dated addendum.
