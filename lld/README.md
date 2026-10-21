# Design records

Only two detailed design records are maintained:

- `01-threat-model.md`: trust boundaries, threats, and security requirements.
- `14-adrs.md`: accepted architectural decisions (`ADR-*`) and remediation decisions (`D-R*`).

The former LLD-02 through LLD-13 drafts were removed on 2026-09-05. They described planned authz,
agent protocol, RBAC, data model, detection, analysis, remediation, GitOps, API, UI, deployment, and
testing designs. The implementation subsequently became the more accurate contract and the drafts
accumulated superseded and contradictory sections while remaining marked "Draft for review."

Current sources of truth:

| Area | Source |
|---|---|
| Product and runtime architecture | `docs/ARCHITECTURE.md` |
| HTTP API | Route registration and handler/request/response types under `internal/api/` |
| Agent protocol | `internal/tunnel/` and its tests |
| Authorization | `internal/authz/`, API capability checks, and their tests |
| Kubernetes RBAC | `deploy/helm/argus-agent/templates/` and chart tests |
| Data model | `internal/migrations/`, query code, and database-backed tests |
| Detection | `internal/agent/`, `internal/agent/rules/default-rules.yaml`, and tests |
| Which findings open an incident | `internal/gateway/promotion.go` (the evidence boundary), `internal/gateway/finding.go` (correlation), `internal/conditionpolarity/` + `internal/gateway/polarity_gate.go` (which way a condition's polarity runs), and tests |
| Analysis and remediation contracts | `internal/llm/`, `internal/remediation/`, `internal/resolution/` (the route, and which action shapes it permits), `internal/orchestrator/`, and tests |
| Repository/GitOps integration | `internal/gitops/`, `internal/repotools/`, `internal/scm/`, and tests |
| UI behaviour | `web/src/`, component tests, and the user documentation (https://argus.nubestack.com/) |
| Deployment and operation | `docs/INSTALL.md`, `RUNBOOK.md`, charts, and compose files |
| Verification | Test suites, and the live fault fixtures in `fixtures/` |

Old comments may still cite an LLD number and section. Treat those citations as historical
provenance; the deleted files remain available in Git history. When changing nearby code, replace a
legacy citation with the invariant or test that now makes the behaviour intentional.


## Citations to documents that are not published

ARGUS was developed against a set of working documents (a project board, `PROJECT.md`; a live
verification log, `docs/VERIFICATION.md`; feature specifications, `docs/CLUSTER_INSIGHT_SPECS.md`; and
older files they replaced: `BACKLOG.md`, `BUGS.md`, `CAPABILITIES.md`, `DESIGN.md`, `STATUS.md`,
`FAILURE_MODES.md`, `HANDOFF.md`, `WORKLOG.md` and others). They are not part of this repository, and
neither is the history they refer to.

Code comments still cite them, for example "`PROJECT.md` B163" or "`BUGS.md` 128". Read those as
provenance: the identifier names the work item a piece of code came from, and the reasoning that
matters is written beside it. They are not links to follow. New code cites the invariant or the test
that makes behaviour intentional instead.

The design documents `lld/02` to `lld/13` are retired the same way: the code and its tests are the
contract for the areas they described, listed in the table above.
