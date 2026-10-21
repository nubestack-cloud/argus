# CLAUDE.md

Orientation for working in this repo. `README.md` indexes the maintained product and development
documents. This file is only a map of the repository and its development commands.

Load the `argus-context` skill before writing or reviewing any code, schema, API, CRD, RBAC, or infra
here — it carries the architectural non-negotiables. The `argus-add-*` skills scaffold new
detectors/endpoints/MCP tools/remediation actions/UI screens in the established pattern rather than
freehand.

**Testing has four skills.** `argus-qa` runs the checks a change needs, scaled to the delta, and
reports each as ran or skipped with a reason. `argus-live-test` builds, rolls out to a test cluster and
proves the behaviour against real cluster objects. `argus-visual-test` sweeps the rendered UI with
Playwright (widths, both themes, overflow and console errors). `argus-dependency-batch` brings
dependencies forward as one soaked, reviewed batch. `argus-review` and `argus-security-review` are
the done-gate and the threat-model pass.

Verify current behaviour against the code before relying on any state claim, in a skill or here.

**Frontend work uses three skills, in this order.** `argus-add-screen` for the plumbing (routing,
RBAC, data fetching); **`argus-design-system`** for how it should look — the token rules, the ~60-class
component vocabulary, and the six screen modes, which you name *before* laying anything out; then
**`argus-design-review`** before calling it done, which audits the result and reports `file:line`
findings. The two design skills share one ruleset
(`.claude/skills/argus-design-system/reference/{tokens,components,screens,anti-patterns}.md`) so the
checker cannot drift from the generator — edit rules there, not in either `SKILL.md`. The
mechanically decidable subset of that ruleset is enforced in CI by `web/scripts/design-lint.mjs`
(`cd web && npm run design-lint`); everything needing judgement is the review skill's job. These
replaced `argus-ui-design`/`argus-ui-review` on 2026-08-25.

**This applies to every frontend change, not just to a redesign.** UI cohesion work is limited to
concrete operator workflow problems rather than broad visual churn — that bounds how much gets
rebuilt and says nothing about the standard a one-line fix is held to. A change that
fabricates a zero, hides a control the viewer lacks capability for, carries severity in colour alone,
or invents a class instead of reusing the vocabulary is a finding on any page, on any day. Scope is
how much you change; quality is how you change it.

## Layout

```
cmd/            entry points — one directory per binary (hub, agent, cli-runner, argusctl)
internal/       everything else, organized by concern (see below)
web/            the React/TS frontend
deploy/         compose (local/dev) and helm (real deploys)
docs/           product guides plus the maintained verification matrix
lld/            threat model, decision register, and an index for retired LLD citations
scripts/        smoke-test.sh, eval-harness, misc dev tooling
issue-catalog/  the k8s fault catalog detectors/eval fixtures are built from
fixtures/       live-cluster fault fixtures the verification campaigns run from
```

The root-level development doc is `RUNBOOK.md` (local development, testing, and operations);
install and upgrade guides are in `docs/`. `lld/14-adrs.md` holds both ADR and D-R decision
registers; `lld/01-threat-model.md` holds the security boundaries. Old work-item, bug, HLD, and LLD
references in comments are historical provenance (`lld/README.md`); do not add new references to them.

## The two halves of the system

**Hub (server)** — `cmd/hub/main.go` + almost everything under `internal/`: `internal/api` (HTTP
handlers — routes registered in `server.go`, auth, RLS-scoped transactions, RFC 9457 errors),
`internal/orchestrator` (the incident state machine, in `state.go`, plus its sweepers),
`internal/gateway` (the mTLS tunnel server + finding ingestion/correlation, and `promotion.go`'s
evidence boundary deciding which findings open an incident at all), `internal/resolution` (the
resolution route: pure code deciding pull-request vs. in-place vs. both vs. guidance, and which action
shapes the prompt may offer, **before** the model proposes anything — ADR-18),
`internal/gitops` + `internal/scm` (repository-change/pull-request proposals), `internal/remediation`
(typed remediation action schemas), `internal/autoanalyze`, `internal/authz`, `internal/data`
(Postgres access, RLS request-scope helpers), `internal/mcp` (the MCP server exposing the hub's tools
to the `cli` investigation backend), `internal/migrations`. The web UI is compiled **into** the hub
binary via `go:embed`, but the embedded directory is **`internal/api/static`, not `web/dist`**
(`internal/api/static.go`): the Docker build does `rm -rf internal/api/static` and copies `web/dist`
over it first, and what is checked in there is a placeholder. So a frontend-only change needs a hub
rebuild to be servable, `npm run build` alone changes nothing a browser will see, and a hub built
with a plain `go build ./cmd/hub` serves the placeholder **silently** rather than erroring — copy
the bundle across yourself if you are running one that way.

**Cluster agent (spoke)** — `cmd/agent/main.go` + `internal/agent`. Runs against/inside one Kubernetes
cluster, dials the hub over the mTLS tunnel (`internal/tunnel` is the shared wire protocol both sides
import), reports facts/findings, and executes the read-only MCP tools and typed remediation actions
(`ScaleDeployment`, `RestartPod`, `get_gitops_ownership`, `get_owner_chain`, etc. — see
`internal/agent/tools.go`).

**Other binaries**: `cmd/cli-runner` is the CLI-backed investigator the hub's MCP host talks to for
analysis. `cmd/argusctl` (+ `internal/argusctl`) has one job, `audit verify`: independently
re-verify the audit hash chain, straight against Postgres, no hub involved. Installing, upgrading and
enrolling are Helm only (the hub chart also installs its own cluster's agent, as `localAgent`).

## Running the tests

```
go test ./...                     # Go unit tests — pure logic, no DB required
cd web && npm test                # frontend unit tests (Vitest + jsdom + Testing Library)
cd web && npm run build           # the authoritative frontend typecheck — NOT `tsc --noEmit`
cd web && npm run design-lint     # the mechanically checkable half of the design system
./scripts/smoke-test.sh           # end-to-end smoke test against a running compose stack
```

Plenty of the Go suite is `*_db_test.go` and needs a real Postgres behind `ARGUS_TEST_DATABASE_URL`
(fixtures share `internal/dbtest`); those `t.Skip` cleanly without one, so a green `go test ./...` on
a machine with no database has proved less than it looks like it has. Note that `internal/dbtest`
exists because DB-test cleanup has twice destroyed real development data — use it for a new fixture
rather than hand-writing `DELETE ... WHERE tenant_id = $1`.

The smoke test is the most complete, current description of what the API actually does — more
current than any retired API draft. `scripts/eval-harness` is a
different kind of check (`go test ./scripts/eval-harness/...` covers it without a running stack): it
grades whether the investigation loop reaches the right root cause against a golden set, not API
contracts.

`RUNBOOK.md` has the full local-dev setup (containerized vs. host-run hub, enrolling a real or fake
cluster, restarting hub/agents without testing a stale build) and the rest of the testing story
(what's *not* covered yet, deploying a frontend change, testing against a real cluster).
