# Supported Versions and the Upgrade Contract

Where a version has been run, this says so; where it has not, it says "expected to work". An
overstated support matrix is a defect like any other.

## Kubernetes

**Supported: Kubernetes 1.29 and newer**, for the cluster the hub runs on and for every watched
cluster.

| Version | Status | Basis |
|---|---|---|
| 1.35 | **Verified** | Runs the hub and an agent continuously: GitOps pull requests, remediation in test namespaces, the incident loop end to end |
| 1.34 | **Verified** | Watched continuously by an agent; a disposable multi-node `kind` cluster is used for remediation, admission-policy and scheduling tests |
| 1.30 – 1.33 | Expected to work | No API ARGUS depends on changed in a way that affects it, but these minors have not been run |
| 1.29 | Expected to work, read-only | See below |
| Older | Not supported | |

**Remediation needs 1.30.** The read-only agent needs nothing beyond long-GA APIs. Remediation
(`remediate.enabled`) and dry-run validation (`dryRun.enabled`) are fenced by
`ValidatingAdmissionPolicy` at `admissionregistration.k8s.io/v1`, GA in 1.30; on 1.29 the agent chart
refuses those switches with a message saying so. There is deliberately no fallback: the admission
policy is the backstop for every write ARGUS makes.

**Distributions.** The charts need no distribution-specific settings: storage, the IngressClass and
OpenShift's security policy are detected at install (docs/INSTALL.md, "Before you start"). Verified
on RKE2 and on `kind`. OpenShift is expected to work (the pods leave their user IDs to its restricted
policy, detected or `global.openshift=true`) but has not been the target of a real run yet; nor have
EKS, GKE or AKS.

A row moves to "verified" only when that version has actually been the target of a real run.

## Architectures

Every image (`argus-hub`, `argus-agent`, `argus-cli-runner`) is published for
`linux/amd64` and `linux/arm64`. The images are cross-built without emulation: the Go binaries are
cross-compiled and the CLI runner's tools are installed for the target CPU, so each architecture runs
native binaries.

## Upgrades and Rollbacks

The procedure is in [INSTALL.md](INSTALL.md#upgrading). What it relies on:

**Hub**

- `helm upgrade` with the new chart version. The `migrate` container brings the schema up to date
  before the hub starts, and the Deployment uses `strategy: Recreate`, so a partly migrated schema never
  serves traffic.
- Migrations are **forward-only** in practice: the previous hub will not start against a newer schema.
  Rolling the hub back therefore means restoring the database backup taken before the upgrade, then
  `helm rollback`. Each migration has a down file, but the hub does not run them.
- `replicaCount` is fixed at 1, because the hub holds every agent's tunnel in memory; an upgrade is a
  brief single-pod restart, and agents reconnect by themselves.
- Leave `terminationGracePeriodSeconds` to the chart, which derives it from `shutdown.*` so a restart
  never cuts a drain short.

**Agent**

- `helm upgrade`, or **Upgrade agent** from the hub. The agent's enrolled
  identity is kept in a Secret, so an upgrade or `helm rollback` does not cost the enrollment.
- What does: `helm uninstall` (a decommission, by design) and `--force` on upgrade or rollback, which
  replaces objects and with them the Secret's contents.
- Remediation is RBAC in the watched cluster: changing it takes effect when that cluster's agent chart
  is upgraded, in either direction.

**Images**

- Each chart version pins its images by tag and digest, and pulls by digest. Installing a chart
  version installs exactly the images it was released with, and a new chart version brings new ones.
- An image you pin yourself (`image.tag`, `image.digest`) is a value you set: it stays across upgrades
  until you remove it.

## Supply Chain

| | |
|---|---|
| Images | Multi-arch, pinned by digest in each chart version |
| Charts | OCI artifacts: `oci://registry-1.docker.io/nubestack/argus-hub-chart` and `argus-agent-chart` |
| SBOM | SPDX, one per image, attached to the release |
| Scanning | `govulncheck` and `npm audit` on every change; `trivy` on every image, failing on CRITICAL |
| Signing | `cosign`, keyless, on every published image and OCI chart; packaged chart files carry a `.bundle` |
| Checksums | `SHA256SUMS` over every release file (argusctl binaries, charts, SBOMs, scans) |
| Licence | AGPL-3.0 (`LICENSE`). The licences of every bundled dependency are in `THIRD_PARTY_NOTICES.md`; both are shipped in every image under `/licenses` |

## Verifying a Release

```bash
cosign verify docker.io/nubestack/argus-hub:0.2.1 \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp '^https://github.com/nubestack-cloud/argus/\.github/workflows/release\.yml@refs/tags/v'
```

The same works for `argus-agent`, `argus-cli-runner`, `argus-hub-chart` and
`argus-agent-chart`.

## Verifying Images at Admission

ARGUS does not ship an admission controller of its own. To admit only signed ARGUS images, use the one
you already run: Sigstore's `policy-controller` with a `ClusterImagePolicy` for `nubestack/argus-hub`,
`nubestack/argus-agent` and `nubestack/argus-cli-runner`, or Kyverno's `verifyImages`, given the release
workflow's keyless signing identity.

## Known Limits

**The hub is a single replica.** It holds every agent's tunnel in memory, so it cannot yet run as more
than one pod. In practice:

- an upgrade or node failure is a short outage of the hub (typically under a minute on upgrade). The
  watched clusters are unaffected: agents only observe, keep retrying, and reconnect by themselves;
- detection in the clusters continues while the hub is down, and findings are reported when agents
  reconnect;
- protect the hub's availability with the usual single-pod measures: a `PodDisruptionBudget`-aware
  maintenance process, a node with headroom, and Postgres outside the hub's node
  (`postgres.mode=external`) for production.

Multi-replica hubs, with tunnels shared across pods, are on the roadmap. Until then this is a stated
limit, not a configuration option: the chart refuses `replicaCount` other than 1.

**Bundled Postgres is one pod with no backups of its own** (take a copy off the cluster before each upgrade). For production, use a managed Postgres or
an operator such as CloudNativePG (`postgres.mode=external`; see "External Postgres" in
[INSTALL.md](INSTALL.md#external-postgres)) so the database has its own replication and point-in-time recovery.
