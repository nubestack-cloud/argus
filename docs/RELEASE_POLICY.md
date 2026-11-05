# Release Policy

This is the policy behind `.github/workflows/release.yml` — what a release is, what has to be true
before one ships, and how the mechanical parts (digest pinning, signing, scanning) actually get
maintained rather than going stale the moment they're written. `docs/SUPPORT.md` has the Kubernetes
version matrix and the upgrade/rollback contract; this document is about the release process itself.

## Versioning

Semantic versioning, tagged `vMAJOR.MINOR.PATCH` (optionally `-rc.N` for a release candidate tag, e.g.
`v0.3.0-rc.1`). The three published images (`nubestack/argus-hub`, `nubestack/argus-agent`,
`nubestack/argus-cli-runner`), the `argusctl` binaries, and both Helm charts are versioned
together — one tag names one release of the whole system. The charts are published as
`oci://registry-1.docker.io/nubestack/argus-hub-chart` and `.../argus-agent-chart`: Docker Hub keeps a
chart and an image of the same name in one repository, where chart tag `X.Y.Z` would overwrite image
tag `X.Y.Z`. In the repository the charts keep their directory names and the last release's version;
`scripts/release/package-charts.sh` stamps the name, the version, every image digest and the hub's
`agentChart.version` into a staged copy when a release is cut, and the charts' helpers fix the
resource names, so the rename changes nothing in a cluster.

**A published version is immutable.** Once a tag has been published, its images, charts and tag are
never rebuilt, re-pushed or moved: a change, however small, is the next patch version. Re-publishing
changes the digests people pinned and leaves the signatures and SBOMs describing artifacts that no
longer carry that version.

There is currently one supported line: the latest release. No parallel long-term-support branch is
maintained: a security fix ships in the next release of that line, not as a backport to an older
tag. `docs/SUPPORT.md` states the supported Kubernetes range.

## Branch and Tag Convention

- **Ordinary development** happens on branches merged into `main` via a normal PR — gated by
  `.github/workflows/ci.yml` (fast, hermetic: Go build/vet/test, web typecheck/lint/build/design-lint,
  migration up/down pairing, dependency scanning).
- **A release candidate** is a branch named `release/*` (cut from `main`, or for a patch release
  from the previous release's tag) opened as a PR into `main`. This is the one PR
  shape `.github/workflows/release.yml`'s `gate` job actually runs for (every other PR still triggers
  the workflow file, but the job's own `if:` skips it at zero cost — see that file's header comment).
  `gate` builds the real hub image, brings up a real hub+Postgres compose stack, stands up a real
  (if disposable) `kind` cluster, and requires both `scripts/smoke-test.sh` and the Playwright suite to
  pass against them.
- **Cutting the release** is pushing a tag matching `v*.*.*`. This re-runs `gate` (a tag can be pushed
  without ever going through a `release/*` PR) and, only if it passes, runs `publish`: multi-arch image
  builds, SBOM generation, vulnerability scanning, chart packaging, signing, and attaching everything
  to the tag's GitHub Release.

**Making "cannot merge without the end-to-end suite passing" an enforced gate** needs one
repository-admin action: turn on branch protection for `main` requiring `release.yml`'s `gate` job to
pass. Until it is on, a failing `gate` is visible on the PR but does not block the merge button.

## Cutting a Release

[RELEASING.md](RELEASING.md) is the step-by-step runbook, from one-time setup to verifying the
published release. In short:

1. Branch `release/X.Y.Z`, run `scripts/release/version.py bump X.Y.Z`, write the `## [X.Y.Z]`
   notes in `CHANGELOG.md`, and open a PR into `main`. `gate` runs on it.
2. Merge, then tag the merge commit `vX.Y.Z` and push the tag. `publish` refuses a tag that does not
   match the tree's version or has no release notes, then builds, scans, signs and publishes
   everything, and creates the GitHub Release from the changelog section.
3. Verify the release, then move the repository's image pins to it (below).

`scripts/release/version.py` holds the one list of places the version is written, and CI's
`release-version` job fails when any of them disagree.

The workflow needs the `DOCKERHUB_USERNAME` and `DOCKERHUB_TOKEN` repository secrets to publish.

## What A Release Contains

| Supply-chain property | Status | Where |
|---|---|---|
| Digest pinning (vs. `latest` chart defaults) | **Done** | `deploy/helm/argus-hub/values.yaml`, `deploy/helm/argus-agent/values.yaml` (`image.digest`, `cliRunner.image.digest`); see "Updating pinned digests" below for the maintenance side. |
| Multi-architecture images | **Done for all four images, without emulation — see `docs/SUPPORT.md`** | `Dockerfile`'s `--platform=$BUILDPLATFORM` stages; `.github/workflows/release.yml`. |
| Packaged charts | **Done** | `scripts/release/package-charts.sh` in `release.yml`'s `publish` job: packaged with digests and pushed to Docker Hub as OCI artifacts. |
| `argusctl` | **Done** | `argusctl audit verify` as Linux/macOS binaries on the GitHub Release. |
| Values validation | **Done** | Each chart's `values.schema.json`, generated from `values.yaml` by `scripts/gen-values-schema.py deploy/helm/argus-hub deploy/helm/argus-agent`; regenerate it when a value is added. |
| SBOM | **Done** | `syft`, SPDX format, one per image, attached to the GitHub Release. |
| Dependency scanning | **Done** | `govulncheck` (Go, `scripts/govulncheck-gate.sh`, baseline-gated — see below) and `npm audit` (web), both in `.github/workflows/ci.yml` on every PR. |
| Image scanning | **Done, gated on CRITICAL only today** | `trivy image` in `release.yml`; see "Known, currently-open scan findings" below for why HIGH isn't blocking yet. |
| Release signing | **Done in CI** | `cosign` keyless signing in `release.yml`: every published image and OCI chart by digest, and each packaged chart file as a `.bundle`. |
| Checksums | **Done** | One flat `SHA256SUMS` over every release file. |
| Admission-verification guidance | **Done (guidance, not a shipped controller)** | `docs/SUPPORT.md`'s "Verifying Images at Admission". |
| Release policy | **Done** | This document. |
| Supported-Kubernetes matrix | **Done** | `docs/SUPPORT.md`. |
| Upgrade/rollback contract | **Done** | `docs/SUPPORT.md` and `docs/INSTALL.md`. |
| Licence | **Done — AGPL-3.0, unmodified text** | `LICENSE`. |
| Third-party licences | **Done** | `THIRD_PARTY_NOTICES.md`, generated by `scripts/third-party-notices.py` from the Go modules and the web UI's npm packages, shipped in every image; the release workflow refuses a stale one. Regenerate it when `go.mod` or `web/package-lock.json` changes. |
| Release notes | **Per release** | `CHANGELOG.md`: the release workflow uses the tag's section as the GitHub Release notes (GitHub's generated notes when there is none). Write the section, including anything an upgrade needs, in the release PR. |
| `SECURITY.md` | **Done** | The private reporting path for vulnerabilities. |
| CI gating a release candidate on the end-to-end suite | **Workflow built; needs branch protection on `main`** | `.github/workflows/release.yml`'s `gate` job; see the note above. |

## Updating Pinned Digests

Run after every image publish:

```bash
./scripts/pin-image-digests.sh <tag>
# or, if the three images are versioned independently:
./scripts/pin-image-digests.sh --hub-tag <tag> --agent-tag <tag> --cli-runner-tag <tag>
```

This re-resolves each image's digest straight from the registry's manifest API (no image pull) and
rewrites `deploy/helm/argus-hub/values.yaml` and `deploy/helm/argus-agent/values.yaml` in place,
preserving every surrounding comment (it edits structurally, by indentation and key, not by
dumping/reloading the YAML — a dump/reload would silently discard the comments that explain the field
in the first place). It is idempotent: running it again with the same tag reproduces the same digest
and touches nothing.

The release job pins the digests it just built into the charts it publishes, so a published chart is
always pinned correctly. The repository's own `values.yaml` pins can only follow once those images
exist: commit the diff in a small pull request after the release is out
([RELEASING.md](RELEASING.md), step 11). A digest that is pinned once and never
updated again is worse than no pin at all — it looks like a supply-chain control while silently
preventing every future upgrade from ever reaching an installed chart. This script is what keeps the
pin honest.

## Known, Currently-Open Scan Findings

Stated here rather than hidden, per this project's own standing instruction not to weaken a scan to
make it pass:

- **No call-reachable Go vulnerabilities** (govulncheck, 2026-10-21, built with Go 1.26.10 as
  `go.mod` and the Dockerfile pin it; 1.26.10 fixes GO-2026-6809 in `crypto/x509`). `golang.org/x/net` is at v0.60.0 and the `golang` base image is pinned to the patch
  release that fixed the standard-library findings; `scripts/govulncheck-baseline.json` stays empty.
- **npm advisories in dev tooling only** — `vitest`'s `@vitest/mocker` and `tinypool`, `undici` and
  `source-map-js` — never present in `npm run build`'s shipped output (`npm audit --omit=dev` reports
  none, checked 2026-10-14). Reported on every CI run
  (`npm audit`, non-blocking) rather than gated, since gating on a dev-only dependency would block every
  PR over something that never ships.
- Neither the hub, agent, nor cli-runner image's OS layer (Debian, via `gcr.io/distroless/base-debian12`
  or `node:22-bookworm(-slim)`) had any CRITICAL or HIGH finding at the time this was last checked —
  the findings above are entirely in the Go binary's own dependency graph, not the base image.

None of the above is silenced by an ignore file or a scanner downgrade. They fail loudly in scan
output; they are simply not yet gating merges, for the reasons stated next to each.
