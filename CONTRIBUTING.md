# Contributing to ARGUS

Thank you for helping. This page is the path from an idea to a merged pull request. How releases are
cut is a maintainer's job and lives in [docs/RELEASING.md](docs/RELEASING.md).

## Before you start

- **A bug:** open an issue with what you ran, what you expected and what happened, plus the hub and
  agent versions and your Kubernetes distribution (RKE2, OpenShift, EKS, kind, ...). Logs help:
  `kubectl -n argus-system logs deploy/argus-hub` and `deploy/argus-agent`.
- **A security problem:** do not open an issue. Follow [SECURITY.md](SECURITY.md).
- **A feature or a large change:** open an issue first and describe the problem it solves. ARGUS has
  safety rules that shape what can be built (below), and agreeing on the approach first saves you a
  rewrite.
- **A small fix** (a typo, a clear bug with an obvious fix): go straight to a pull request.

## Set up

[RUNBOOK.md](RUNBOOK.md) has the local development setups: everything in containers, the hub on your
host for fast Go iteration, an agent against a local or real cluster, and a whole ARGUS on a
throwaway kind cluster. You need Go (the version in `go.mod`), Node 22, Docker, Helm 3.14 or later,
and for cluster work, kind or a cluster of your own.

## Branches and pull requests

1. Fork the repository (or, as a maintainer, branch in it) and branch from `main`:
   ```bash
   git checkout main && git pull
   git checkout -b fix/agent-tunnel-endpoint      # or feat/..., docs/..., chore/...
   ```
   `release/*` branch names are reserved for releases: they trigger the release gate.
2. Keep one pull request to one change. A refactor and a feature in one diff are hard to review and
   hard to revert.
3. Push, and open the pull request into `main`. Say what changed, why, and how you tested it,
   including the cluster you tested on when the change touches cluster behaviour.
4. CI must pass (below), and a maintainer reviews. Expect questions about safety for anything that
   reaches a cluster.

## The checks CI runs, and how to run them first

CI (`.github/workflows/ci.yml`) runs these on every pull request. Running them locally first is the
fastest way to a green PR.

**Go**
```bash
gofmt -l . | grep -v '^web/'      # must print nothing
go build ./...
go vet ./...
go test -race ./...
```
Many tests are `*_db_test.go` and need a real Postgres in `ARGUS_TEST_DATABASE_URL`. Without it they
skip, and a green run proves less than it looks like. CI runs them against a real database; the
`go-db` job in `ci.yml` shows the setup. If you changed SQL, a query or a migration, run them.

**Web** (`web/`)
```bash
cd web && npm ci
npm run lint
npm run design-lint     # the mechanically checkable design rules
npm run build           # the authoritative typecheck, not `tsc --noEmit` alone
npm test                # unit tests
```

**When you changed...**

| You changed | Also run or update |
|---|---|
| `docs/openapi.yaml` | `cd web && npm run generate-api-types`, and commit `web/src/api/generated.ts` |
| A migration | Every `*.up.sql` needs its `*.down.sql` |
| A chart | `helm lint deploy/helm/argus-hub` and `deploy/helm/argus-agent`; after adding a value, `scripts/gen-values-schema.py deploy/helm/argus-hub deploy/helm/argus-agent` |
| `go.mod` or `web/package-lock.json` | `scripts/third-party-notices.py` (the release refuses a stale `THIRD_PARTY_NOTICES.md`) |
| Anything that names the release version | `scripts/release/version.py check` |

A frontend change is only visible after the hub image is rebuilt, because the UI is compiled into
the hub binary. RUNBOOK.md has the procedure.

## The safety rules a change must keep

ARGUS works on people's production clusters, so these are not style preferences. A change that
breaks one will not be merged, however useful it is. The full reasoning is in
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) and the [threat model](lld/01-threat-model.md).

- The cluster agent is read-only. Changes go through the separate, opt-in remediation identity, never
  through the investigation path.
- The model proposes; code decides and executes. Model output never becomes a shell command, and
  every action is a typed, closed-schema plan that is checked before it runs.
- Secrets never reach prompts, logs, notifications or audit records. Redaction happens in the agent,
  before data leaves the cluster.
- Every API route checks authentication and capability on the server. Hiding a button is not
  authorisation.
- Database access runs inside the request's row-level-security scope.
- Errors returned to callers never carry internal error text.

## Commits

Write the subject as what the change does ("Honour ARGUS_TUNNEL_ENDPOINT on first enrollment"), and
use the body for why. Code comments say what is true now and why; the history of how it got there
belongs in the commit message.

## Licence

ARGUS is licensed under the [GNU Affero General Public License v3.0](LICENSE). By opening a pull
request you agree that your contribution is licensed under the same terms.
