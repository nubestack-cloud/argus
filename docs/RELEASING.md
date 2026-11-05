# Releasing ARGUS

The maintainer's runbook, from an empty branch to a published, signed release. The rules behind it
(versioning, what a release contains, supply-chain properties) are in
[RELEASE_POLICY.md](RELEASE_POLICY.md); everyday development is in
[CONTRIBUTING.md](../CONTRIBUTING.md).

A release is **cut by pushing a tag**. CI does all the publishing: multi-arch images, SBOMs, scans,
charts pinned by digest, signatures and the GitHub Release. Nothing is ever built or pushed by hand.

## One-time setup

1. **Docker Hub secrets.** On hub.docker.com, **Account settings → Personal access tokens →
   Generate new token**, with Read & Write access. On GitHub, **Settings → Secrets and variables →
   Actions → New repository secret**: `DOCKERHUB_USERNAME` and `DOCKERHUB_TOKEN`. Without them the
   release builds everything but publishes nothing.
2. **Protect `main`.** **Settings → Rules → Rulesets → New branch ruleset**, targeting the default
   branch: require a pull request, block force pushes and deletion, and require the status checks
   *Release gate* and the CI jobs. A check appears in the list only after it has run once.
3. **Git over SSH**, so fetch and push work without a token:
   `git remote set-url origin git@github.com:nubestack-cloud/argus.git`.
4. **Tools for verifying a release:** Helm 3.14 or later and
   [cosign](https://github.com/sigstore/cosign/releases). `gh` (`gh auth login`) is optional; every
   `gh` step below has a web equivalent.

## Which release

| Release | Branch from | Version |
|---|---|---|
| New features (minor) | `main` | `0.3.0` |
| Fixes only (patch) | `main`, if everything on it is fit to ship; otherwise the previous release's tag (`git checkout -b release/0.3.1 v0.3.0`) plus the fixes | `0.3.1` |
| Release candidate | The release branch, before merging | `0.3.0-rc.1` (published as a pre-release) |

## Cutting the release

**1. Branch**
```bash
git checkout main && git pull
git checkout -b release/0.3.0
```

**2. Bump the version everywhere**
```bash
scripts/release/version.py bump 0.3.0
```
It rewrites every place the version is written: both charts, the version the agent reports to the
hub, the API spec, every install command, the examples. It also starts a `## [0.3.0]` section in
`CHANGELOG.md`. The image pins in the two `values.yaml` files are deliberately left alone; they move
after the release (step 10).

**3. Write the release notes** in that `CHANGELOG.md` section, replacing the placeholder comment.
They become the GitHub Release text, so write for an operator: what changed for them, grouped under
`### Added`, `### Changed`, `### Fixed`. If upgrading needs any step beyond `helm upgrade`, say so here
and in `docs/INSTALL.md` ("Upgrading"). Keep the heading exactly `## [0.3.0]`; the release job finds
the notes by it.

**4. Check**
```bash
scripts/release/version.py check
helm lint deploy/helm/argus-hub --set ingress.host=argus.example.com
helm lint deploy/helm/argus-agent --set hub.apiUrl=https://argus.example.com
```
plus the checks in [CONTRIBUTING.md](../CONTRIBUTING.md) for anything else the branch changed.

**5. Commit, push, open the pull request into `main`**
```bash
git add -A && git commit -m "Release 0.3.0"
git push -u origin release/0.3.0
gh pr create --base main --title "Release 0.3.0" --body "See CHANGELOG.md"
```
On the web: open the repository and use the **Compare & pull request** banner.

**6. Let the gate run.** A `release/*` pull request runs the release gate: it builds the hub image,
starts a real hub and Postgres, stands up a kind cluster, and runs the smoke test and the Playwright
suite against them. Follow it with `gh run watch` or on the pull request's **Checks**. If it fails,
read the log (`gh run view --log-failed`), fix on the branch, and push; it runs again.

**7. Merge** with a merge commit (`gh pr merge --merge`, or **Merge pull request** on the web).

**8. Tag the merge commit.** This is the step that publishes.
```bash
git checkout main && git pull
git tag -a v0.3.0 -m "ARGUS 0.3.0"
git push origin v0.3.0
```
Push the tag from the terminal, not by creating a release on the web: the job creates the GitHub
Release itself, from the changelog.

**9. Watch it publish** (`gh run watch`, or **Actions → Release**). The gate runs again on the tag.
Then, before building anything, the publish job refuses a tag that does not match the version in the
tree, or a release with no notes. After that it builds the images for amd64 and arm64, generates SBOMs, fails on CRITICAL scan findings, pushes the
charts pinned to the new digests, signs everything with cosign, and creates the GitHub Release.

## After the release

**10. Verify it as a user would**
```bash
helm show chart oci://registry-1.docker.io/nubestack/argus-hub-chart --version 0.3.0
cosign verify docker.io/nubestack/argus-hub:0.3.0 \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp '^https://github.com/nubestack-cloud/argus/\.github/workflows/release\.yml@refs/tags/v'
gh release view v0.3.0
```
Then install it from scratch on a throwaway kind cluster (RUNBOOK.md, "a whole ARGUS on a throwaway
`kind` cluster"), and upgrade the lab clusters with `--version 0.3.0 --reset-then-reuse-values`.

**11. Move the repository's image pins to the release**, in a small pull request:
```bash
git checkout main && git pull && git checkout -b pin-0.3.0
scripts/pin-image-digests.sh 0.3.0
git commit -am "Pin chart images to 0.3.0" && git push -u origin pin-0.3.0
```

**12. Update the user guide** (the `nubestack-cloud/docs-argus` repository): change `--version` in
its install commands to the new release, on a branch, and merge it once the release is published.
Only `main` deploys the site, so the guide never names a version that does not exist yet.

**13. Announce it**, linking the GitHub Release.

## Never

- **Re-publish a version.** Once `0.3.0` is out, its images, charts and tag are fixed. Anything that
  needs changing is `0.3.1`. Rebuilding under the same version changes the digests people pinned and
  leaves the signatures pointing at the old ones.
- **Move or delete a pushed tag.**
- **Build or push release images by hand.** Only the release job signs them and produces SBOMs.
- **Edit the version by hand.** `scripts/release/version.py bump` knows every place it is written,
  and CI fails if they disagree.

## When something goes wrong

**The publish job failed partway.** If nobody can have installed the release yet (you have not
announced it, and it failed before or during publishing), fix the cause and use **Re-run failed
jobs** on the same run. Otherwise, cut a patch release.

**A published release is broken.** Cut a patch release with the fix. Edit the broken release's
GitHub notes to start with "Superseded by X.Y.Z, which fixes ...". Do not delete it: people may have
pinned it. For a security problem, also follow [SECURITY.md](../SECURITY.md) and say in the notes
which versions are affected.
