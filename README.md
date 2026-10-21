# ARGUS

**AI-assisted operations for a fleet of Kubernetes clusters.**
**Self-hosted. GitOps-first. Nothing changes without a person — unless you decide otherwise.**

[User guide](https://argus.nubestack.com/) · [Install](docs/INSTALL.md) · [Architecture](docs/ARCHITECTURE.md) · [Security model](lld/01-threat-model.md)

ARGUS watches many clusters from one hub. Agents inside each cluster detect symptoms and report them;
the hub groups them into incidents, investigates the root cause with bounded, read-only tools, and
proposes a fix you can review. When the broken object is owned by Git, the fix is a pull request.
When it is not, the fix is a typed, signed, dry-run-checked change that you approve before it runs.

**Contents** — [Why ARGUS](#why-argus) · [Quick start](#quick-start) ·
[Tour](#tour) — [Incident management](#incident-management) · [Fleet overview](#fleet-overview) ·
[Clusters and the network](#clusters-and-the-network) · [Everything else](#everything-else) ·
[How it works](#how-it-works) · [Safety model](#safety-model) · [Installation](#installation) ·
[Documentation](#documentation) · [Repository layout](#repository-layout) · [Development](#development)

[![The ARGUS fleet overview](docs/screenshots/overview-fleet.png)](docs/screenshots/overview-fleet.png)
<sub>The fleet overview. Every image here is the running product on a two-cluster test install, with
hostnames, IP addresses and repository owners replaced by placeholders.</sub>

## Quick start

With Helm 3.8+ and an ingress controller:

```bash
helm install argus-hub oci://registry-1.docker.io/nubestack/argus-hub-chart --version 0.2.0 \
  -n argus-system --create-namespace \
  --set ingress.host=argus.example.com --set ingress.clusterIssuer=letsencrypt
```

`ingress.host` is the only value an install needs (`ingress.clusterIssuer` adds a cert-manager
certificate). The hub runs with its own backed-up Postgres and already watches the cluster it is
installed in; agents connect to the same address as the UI. Sign in, add an AI provider, then
**Clusters → Enroll a cluster** prints the agent install for each other cluster, or **Fleet tokens**
enrolls a whole fleet through Argo CD or Flux.
Step by step, with screenshots: the [user guide](https://argus.nubestack.com/). The install and
upgrade reference is [docs/INSTALL.md](docs/INSTALL.md). [More installation options ↓](#installation)

* * *

## Why ARGUS

- **One pane for every cluster** — the hub never holds a kubeconfig. Agents dial out to it over an
  mTLS tunnel, so a cluster behind NAT or a firewall enrolls the same way as one next door.
- **Root cause, not a wall of alerts** — symptoms are grouped into incidents and investigated by an AI
  model through read-only tools: events, logs, owner chains, GitOps ownership. Every conclusion
  separates what was observed from what was inferred, and says "could not determine" rather than
  guess.
- **GitOps-first fixes** — if Argo CD, Flux or Fleet owns the object, the proposed fix is a pull
  request against the source repository. ARGUS never merges it.
- **The model proposes; code decides** — a fix is a closed set of typed actions, never shell text.
  Which actions are even allowed is decided by code from ownership facts *before* the model is
  asked.
- **Safe by default** — investigation is read-only, remediation is a separate, opt-in identity per
  cluster, every plan is signed and audited, and unattended execution is off until you allowlist
  namespaces for it.
- **Bring your own model** — any OpenAI-compatible API, or Claude Code / Codex through an isolated
  CLI runner.

* * *

## Tour

> Live screenshots are from a two-cluster test install. Hostnames, IP addresses and repository
> owners are replaced with `example.org`-style placeholders; everything else is real data.

### Incident management

Every incident moves through the same four phases to an outcome. Each phase answers one question —
what broke, why, what to do about it, and did it stay fixed — and the fix phase follows whichever
route the incident is on.

[![The incident lifecycle](docs/screenshots/lifecycle-phases.png)](docs/screenshots/lifecycle-phases.png)

[![Incident list](docs/screenshots/incidents.png)](docs/screenshots/incidents.png)
_Incidents — one row per problem, not per event, with who has the next move and how it will be fixed_

[![An incident waiting on a person](docs/screenshots/incident-lifecycle.png)](docs/screenshots/incident-lifecycle.png)
[![A remediated incident](docs/screenshots/incident-closed.png)](docs/screenshots/incident-closed.png)
_Lifecycle — every incident page opens on where it is, how long each step took, and whose move it is_

- After a fix runs, ARGUS watches for the symptom to come back before it closes the incident
- A symptom that returns reopens the incident, or links a new one to it, rather than starting over
- A person can resolve or dismiss an incident too, and the record says who closed it and how

[![Root cause and causal chain](docs/screenshots/incident-chain.png)](docs/screenshots/incident-chain.png)
_Why — the conclusion with its confidence, the causal chain step by step with the tools behind each
step, and what was ruled out_

- The investigation uses read-only tools only — describe, events, logs, owner chain, GitOps
  ownership, Helm status, recent changes — and every call is listed
- When the cause is not well supported, it says "could not determine" rather than guessing

[![Affected objects](docs/screenshots/graph-incident.png)](docs/screenshots/graph-incident.png)
_Affected objects — what the broken object owns, uses and is reached by, read live from the cluster_

[![A fix that ran](docs/screenshots/incident-fix.png)](docs/screenshots/incident-fix.png)
_Fix, applied — the route ARGUS chose and why, the exact typed action, who approved it, and an Undo_

[![A decision waiting](docs/screenshots/incident-approve.png)](docs/screenshots/incident-approve.png)
_Fix, waiting on you — confidence, risk and reversibility, the safety gate that held it back, and why it cannot run yet_


- The route — pull request, in place, both, or guidance — is decided by code from ownership facts
  *before* the model proposes anything, with its caveats stated ("Helm reverts it on the next
  reconcile")
- A plan is bound to the object version it was written for; if the object changes, approval is
  refused rather than applied to something else
- A high-risk change that cannot be undone is never auto-approved, whatever the confidence — a
  hard floor, not a setting

[![Approvals queue](docs/screenshots/approvals.png)](docs/screenshots/approvals.png)
_Approvals — every pending decision across the fleet: what is broken, the change, and the decision_

### Fleet overview

[![The fleet overview, live](docs/screenshots/overview.png)](docs/screenshots/overview.png)
_Overview — the same page as the top of this file, on the live two-cluster install_

- **Now**: open incidents by where they are in the loop, the queue waiting on a person with how long
  each has waited, one ring per cluster, and incidents opened per day
- **Next 90 days**: every certificate expiry and freeze window in the fleet on one runway
- **Standing**: an upgrade ladder, a posture heatmap, node capacity one hexagon per node, Helm and
  GitOps health, agent versions, and the automation guardrails
- Built for 200+ clusters: every card shows its worst eight and counts the rest, and the page reads
  checks the hub keeps fresh instead of calling every agent each time it opens

### Clusters and the network

[![Cluster overview](docs/screenshots/cluster-overview.png)](docs/screenshots/cluster-overview.png)
_Cluster — pods, workloads and nodes, resource use, what needs attention, and recent changes_

[![Network map](docs/screenshots/cluster-map.png)](docs/screenshots/cluster-map.png)
_Map — every namespace's ingress → service → workload → pod chain, unhealthy paths first, with
NetworkPolicies and disruption budgets marked; exportable as PNG_

[![Related objects](docs/screenshots/graph-related.png)](docs/screenshots/graph-related.png)
_Related — any object's relationships: what exposes, configures, protects and owns it_

[![Connectivity](docs/screenshots/connectivity.png)](docs/screenshots/connectivity.png)
_Connectivity — the traffic path from an ingress to ready pods, the NetworkPolicies on the way, and "can traffic reach it?" from outside or from a pod_


Any object opens in the same inspector, with Summary, Events, Logs, Metrics, Related, Connectivity, Changes,
Policy, Helm, GitOps, Rollout and YAML tabs as they apply.

[![Comparing two Deployments](docs/screenshots/compare.png)](docs/screenshots/compare.png)
_Compare — two objects side by side, read live, with what differs summarised before the line-by-line
diff; bookkeeping fields hidden and redacted values flagged rather than compared_

[![Timeline](docs/screenshots/cluster-timeline.png)](docs/screenshots/cluster-timeline.png)
_Timeline — changes, findings and incidents on one time axis_

[![Certificates](docs/screenshots/cluster-certificates.png)](docs/screenshots/cluster-certificates.png)
_Certificates — an expiry runway, nearest first_

[![Upgrade readiness](docs/screenshots/cluster-upgrade.png)](docs/screenshots/cluster-upgrade.png)
_Upgrade — blockers and warnings for the next Kubernetes minor, each with its fix_


Each cluster's page also has **GitOps** (Argo CD and Flux apps, with the controller's own reason
for a failing sync), **Helm** (every release and the health of what it owns), **Posture** (security,
reliability and efficiency checks mapped to NSA/CISA and CIS), **Agent** (what the agent can see,
each detector's own health, and what it may change), and **Traffic** and **Cost** once the agent is
pointed at the cluster's Prometheus.

### Everything else

- **Signals** — every finding the agents reported, whether it opened an incident, and why not;
  **Tolerations** suppress known noise by reason, with an audit trail
- **Insights** — investigations that reached a conclusion, tokens and cost per investigation, and
  what keeps recurring across the fleet
- **Search** — find any object by name, namespace, label or image on every cluster you can inspect
- **Recent changes** — everything ARGUS changed, who approved it, and an Undo; every action is
  also in a hash-chained **Audit log** that `argusctl audit verify` re-checks straight against
  Postgres
- **Automation guardrails** — unattended execution (off by default, namespace allowlist), blast-radius
  caps, maintenance and freeze windows, an auto-approval policy and a circuit breaker
- **AI tools for people** — connect your own MCP client to ARGUS with a personal token; it gets the
  same read-only tools, scoped to your permissions
- **Single sign-on and access** — OIDC directly (LDAP, Active Directory or SAML through a broker
  such as Dex), built-in roles, and grants scoped to one cluster or a cluster group
- **Notifications** — webhook destinations, routed by cluster or cluster group, severity and
  transition
- **Dark mode** — on every screen, following your system setting or your choice

* * *

## How it works

```mermaid
flowchart LR
  subgraph cluster["Each watched cluster"]
    A["argus-agent<br/>detectors · read-only tools"]
    X["remediation executor<br/>(optional, opt-in)"]
  end
  subgraph hub["ARGUS hub"]
    G["tunnel gateway"] --> O["incidents &amp; investigation"]
    O --> R["resolution route<br/>PR · in place · guidance"]
    O --> UI["web UI &amp; API"]
    DB[("Postgres")]
  end
  A -- "mTLS tunnel (agent dials out)" --> G
  R -- "approved, signed plan" --> X
  R -- "pull request" --> Git[("Git repository")]
  O <--> M["AI model<br/>API or CLI runner"]
```

| Component | Required | Purpose |
|---|---:|---|
| Hub | Yes | Web UI, API, migrations, agent tunnel, incident workflow, settings, and background jobs |
| Postgres | Yes | Users, settings, clusters, findings, incidents, analyses, plans, and the audit chain |
| Agent | Yes, per watched cluster | Detects symptoms, answers read-only investigation requests, and optionally executes approved fixes |
| AI provider | Yes | An OpenAI-compatible API, or the Claude Code / Codex CLI runner |
| CLI runner | Optional | Isolated container for Claude Code or Codex investigations |
| Git repository token | Recommended | Lets ARGUS open pull requests for GitOps-owned fixes |

Everything is published on Docker Hub under `nubestack`: the images (`argus-hub`, `argus-agent`,
`argus-cli-runner`) and the charts as OCI artifacts (`argus-hub-chart`,
`argus-agent-chart`). One version names one release of all of them, and each chart version pins its
images by digest — [what is published](docs/INSTALL.md#other-ways-to-install).

## Safety model

- Agents dial out to the hub; the hub holds no kubeconfigs
- Investigation is read-only and never reads Kubernetes Secrets
- Secret values are redacted inside the cluster, before anything leaves it
- Remediation is a separate service identity, opted into per cluster
- Fixes are typed actions checked with a server-side dry run — never shell commands
- Plans are signed, bound to the object version they were written for, single-use, and audited
- Pull requests are reviewed and merged by people, never by ARGUS
- Unattended execution is off by default and limited to allowlisted namespaces

The Kubernetes faults ARGUS is built and evaluated against are catalogued in
[`issue-catalog/`](issue-catalog/).

## Installation

| You want | Use |
|---|---|
| A Kubernetes install | [Helm](docs/INSTALL.md): `oci://registry-1.docker.io/nubestack/argus-hub-chart`, one value |
| GitOps-managed hub and agents | [Argo CD and Flux examples](deploy/examples/) |
| To add clusters | **Clusters → Enroll a cluster** (one), or **Clusters → Fleet tokens** (many) |

Pass the same `--version` everywhere: a chart version pins every image by digest, and the hub's
enroll command installs the agent chart of its own release. For production, use an external Postgres
([External Postgres](docs/INSTALL.md#external-postgres)).

After installing:

1. Sign in and change the bootstrap password.
2. Configure an AI provider in **Settings → AI providers**.
3. Register Git repositories if you want pull-request fixes.
4. Enroll clusters.
5. Start read-only: run analyses, review the plans, and enable remediation per cluster only once you
   trust them.

## Documentation

| I want to know... | Read |
|---|---|
| How to install, upgrade and back up ARGUS | [docs/INSTALL.md](docs/INSTALL.md) |
| Supported versions and known limits | [docs/SUPPORT.md](docs/SUPPORT.md) |
| What changed in each release | [CHANGELOG.md](CHANGELOG.md) |
| How to report a vulnerability | [SECURITY.md](SECURITY.md) |
| How to install and use ARGUS, step by step | [The user guide](https://argus.nubestack.com/) |
| How the system is shaped | [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) |
| How to develop and test it | [RUNBOOK.md](RUNBOOK.md) |
| Prometheus metrics the hub exposes | [docs/METRICS.md](docs/METRICS.md) |
| The API | [docs/openapi.yaml](docs/openapi.yaml) |
| Security boundaries and threat model | [lld/01-threat-model.md](lld/01-threat-model.md) |
| Architecture decisions | [lld/14-adrs.md](lld/14-adrs.md) |

## Repository layout

| Path | What it is |
|---|---|
| `cmd/hub` | Hub binary with `api`, `migrate`, and other entrypoints; embeds the web UI |
| `cmd/agent` | In-cluster agent: enrollment, detection, tunnel connection, tools, and execution |
| `cmd/argusctl` | `argusctl audit verify`: re-checks the audit log's hash chain against Postgres, independently of the hub |
| `cmd/cli-runner` | Optional isolated runner for Claude Code or Codex |
| `web/` | React UI compiled into the hub image |
| `internal/api` | HTTP API, settings, incidents, approvals, users, audit, and preflight handlers |
| `internal/agent` | Agent-side detectors, tool handlers, enrollment, and executor |
| `internal/gateway` | Agent tunnel listener, finding ingestion, storm protection, and tolerations |
| `internal/orchestrator` | Incident state machine and sweepers |
| `internal/remediation` | Typed plan schema, risk gates, autonomy gates, and plan signing |
| `internal/resolution` | Route selection: GitOps pull request, in-place fix, both, or guidance |
| `internal/gitops`, `internal/scm` | Repository ownership, pinned file reads, branches, commits, and pull requests |
| `internal/llm`, `internal/mcp` | Investigation loop and the MCP tool server |
| `internal/fleetchecks` | The Overview's stored per-cluster checks, refreshed by a hub worker |
| `internal/data`, `internal/migrations` | Postgres access and schema migrations |
| `deploy/compose` | The local development and CI stack (not an install method) |
| `deploy/helm/argus-hub` | Hub chart with optional bundled Postgres, ingress, and CLI runner |
| `deploy/helm/argus-agent` | Agent chart with ServiceAccounts, RBAC, persistence, and admission policy |
| `fixtures/`, `issue-catalog/` | Live fault fixtures and the Kubernetes failure catalogue evaluation is built from |
| `lld/` | Threat model and decision register |

## Development

```bash
go test ./...                    # Go unit tests (DB tests need ARGUS_TEST_DATABASE_URL)
cd web && npm test               # frontend unit tests
cd web && npm run build          # frontend typecheck and bundle
cd web && npm run design-lint    # the mechanically checkable design rules
```

The web UI is embedded in the hub binary, so a frontend change needs a hub image rebuild to be
served. Local setup and testing against a real cluster are in [RUNBOOK.md](RUNBOOK.md).

## License

ARGUS is licensed under the [GNU Affero General Public License v3.0](LICENSE). It includes
open-source components under their own licences, listed with their full texts in
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
