---
name: argus-dependency-batch
description: Bring ARGUS's dependencies forward as one reviewed, tested batch — Go modules, the web app's npm packages, GitHub Actions, and the versions pinned in the Dockerfile and charts — taking only releases that have been public for at least 72 hours and whose changelogs were actually read against how ARGUS uses them. Use when asked to update, bump or refresh dependencies, to act on a govulncheck or npm audit finding, or to review open dependency-update pull requests.
argument-hint: [ecosystem or package to limit the batch to — defaults to all]
---

# Batch dependency updates

One batch of updates that were each soaked, read, and tested, in place of a stream of one-line bumps
nobody reviewed. The batch is **dependency-only**: an update that needs ARGUS source changes is
excluded and written up as its own follow-up.

Do not commit, push, open a pull request or close anyone else's until the owner asks. The owner
commits after reviewing. When they do ask, the batch goes on its own branch
(`deps/batch-YYYY-MM-DD`), started from current `origin/main` in a separate worktree if the
working tree has unrelated changes, which it usually does.

## The gates, which do not bend

- **72 hours since the target version was published**, measured from the registry or release
  timestamp, not from when an update was proposed. Record the screening time in UTC. No rounding
  up, and no exceptions without the owner saying so.
- **The gate applies to the resolved graph**, not the line you edited. A lockfile or `go mod tidy`
  can pull a transitive version newer than anything you asked for, and that version is held to the
  same 72 hours and the same reading.
- **Read the changelog across the whole range**, old to new, for every direct update; read the release
  metadata for every changed transitive one. Missing or vague notes mean read the compare view.
  Uncertainty raises the risk; it is not evidence of safety.
- **Primary sources only**: upstream release notes, changelogs, compare views, security advisories,
  the npm registry's `time` field, `proxy.golang.org` (`go list -m -json <mod>@<ver>` reports
  `Time`), and GitHub release or tag dates. A bot's compatibility score is a lead, not a review.
- **No install scripts from an unvetted package.** Build the npm graph with
  `npm install --package-lock-only --ignore-scripts` until the set is approved; run the real install
  and the checks afterwards.

## 1. Inventory

Take a baseline of direct and resolved versions for each ecosystem ARGUS actually has. Check the
repository rather than trusting this list:

| Ecosystem | Where | Candidates |
|---|---|---|
| Go modules | `go.mod`, `go.sum` (the Go toolchain line too) | `go list -m -u -json all` |
| npm | `web/package.json`, `web/package-lock.json` | `cd web && npm outdated` |
| GitHub Actions | `.github/workflows/*.yml` `uses:` lines | each action's releases |
| Images and CLIs pinned in `Dockerfile` | base images (`node`, `golang`, `distroless`, `debian`) and the `ARG` versions (`HELM_VERSION`, `KUBECTL_VERSION`, `CLAUDE_CLI_VERSION`, `CODEX_CLI_VERSION`) | upstream releases |
| One-off pins | `web/package.json`'s `openapi-typescript@x.y.z` in `generate-api-types` | npm |
| Known vulnerabilities | `scripts/govulncheck-gate.sh` against `scripts/govulncheck-baseline.json`; `npm audit` | the advisory itself |

The chart image digests (`deploy/helm/*/values.yaml`) are ARGUS's own images, moved by
`scripts/pin-image-digests.sh` on a release, not by this batch.

## 2. Judge each candidate by how ARGUS uses it

For each one, grep for its imports and configuration (`rg -l '<module path>' --type go`,
`rg "from '<pkg>" web/src`) and read the changelog with that usage in mind. Look for removed or
renamed APIs, changed defaults, a new minimum toolchain, migrations, behaviour changes in security,
serialization or networking, and regressions reported against the release since it shipped.

Read with extra care where ARGUS is sensitive:

- `k8s.io/*` and `sigs.k8s.io/*`: they move in lockstep, and the agent's behaviour against real
  clusters is the product;
- `pgx` and the migration tooling: RLS correctness rides on transaction semantics;
- JWT, crypto and TLS libraries: the tunnel's mTLS and the session tokens;
- the model SDKs and the CLI runner's `claude`/`codex` versions: their flags and JSON output have
  changed shape before and broken parsing silently;
- React, the router, TanStack Query, Vite and the CSS toolchain: these can change what renders.

Decide one of three: **include**, **hold for soak**, or **exclude for risk**, with the evidence in one
line. A major version is not automatically unsafe, and a patch is not automatically safe.

## 3. Apply

Change only the accepted direct versions, then let the native tooling resolve
(`go get <mod>@<ver> && go mod tidy`; `npm install <pkg>@<ver> --ignore-scripts`). Never merge a
bot's branch wholesale.

Then diff the result against the baseline and account for every movement, direct and transitive. A
version you did not ask for gets the full 72-hour and changelog treatment, or the batch is pinned so
that it does not move. Check that `git diff` touches only manifests, lockfiles, workflow `uses:`
lines and Dockerfile pins, with no source, no `internal/api/static` and no generated bundle.

If nothing survives, there is no batch. Report the holds and exclusions instead.

## 4. Test according to the risk

[`argus-qa`](../argus-qa/SKILL.md) for the touched ecosystems, at full width here rather than the
touched-packages subset. That means `go build`, `vet` and `test ./...` with the DB suite running,
plus `go mod verify` for Go, and `npm run build`, `lint`, `test` and `design-lint` for web. Add a
targeted test for any non-trivial bump: the packages importing a changed Kubernetes library against
the fake clientset, the tunnel round-trip tests for a TLS change, and a parse of real CLI output for
a runner CLI change.

A dependency batch is not visually inert when React, routing, the CSS toolchain or fonts move. Run
[`argus-visual-test`](../argus-visual-test/SKILL.md) then, or say why it was skipped. A Dockerfile
change gets an image build, and a change to anything the agent ships gets
[`argus-live-test`](../argus-live-test/SKILL.md) before it is trusted.

A failed or unavailable test excludes that update. It does not get waved through, and the
independent updates that passed stay in.

## 5. Report

- The screening time (UTC) and the 72-hour cutoff.
- **Included**: dependency, old → new, published at, age, and the risk conclusion in one line.
- **Held or excluded**: each with its concrete reason.
- Transitive movement you did not ask for, and why it is acceptable.
- The links to the release notes the material conclusions rest on.
- Every check, as [`argus-qa`](../argus-qa/SKILL.md) reports them, including the visual line.

Then stop for the owner. If they ask for a pull request, its description is this report.
