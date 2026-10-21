# Changelog

All notable changes to ARGUS. Versions follow [semantic versioning](https://semver.org/); each
release's upgrade steps are in [docs/INSTALL.md](docs/INSTALL.md#upgrading).

## [0.2.0]

The first public release.

### Install

- **One-value Helm install.** `helm install argus-hub oci://registry-1.docker.io/nubestack/argus-hub-chart --version 0.2.0 -n argus-system --create-namespace --set ingress.host=<host>`
  brings up the hub, its Postgres, this cluster's agent, and everything other agents need. `ingress.clusterIssuer`
  adds a cert-manager certificate in the same step.
- **Agents connect through the hub's Ingress.** The agent tunnel runs as a WebSocket at
  `/api/v1/agent/tunnel` on the same host as the UI, with its mutual-TLS session inside it, so the
  Ingress never sees agent traffic. A dedicated tunnel address (`tunnel.publicEndpoint`) is still
  supported for networks that need one, and `hub.tunnelEndpoint` moves an enrolled agent between the
  two without enrolling again.
- **Fleet tokens.** One reusable, revocable, expiring token enrolls many clusters, with an optional
  auto-accept, for GitOps rollouts. Issue and revoke them from **Clusters → Fleet tokens**.
- **Argo CD and Flux examples** for the hub and for the agent on every cluster (`deploy/examples/`).
- **Values validation.** Both charts ship a `values.schema.json`, so a misspelt key fails the install.
- **A database dump before every upgrade.** With the bundled Postgres, `helm upgrade` dumps the
  database onto its own volume first, so an upgrade can be
  [rolled back](docs/INSTALL.md#rolling-back-an-upgrade). There are no scheduled backups: for data you
  must keep, use an external Postgres with its own backups.
- **This cluster's agent is installed with the hub**, enrolled and accepted automatically through a
  single-use token the hub registers for it (listed, and revocable, under Fleet tokens).
- **Findings are kept 30 days on new installs** (Settings → General), so the database has a
  bound out of the box. Existing installs keep their setting.
- **Helm only.** Installing, upgrading and enrolling are plain `helm`; `argusctl` is reduced to
  `audit verify`, the independent audit-log check, published as binaries for Linux and macOS.
- **Signed artifacts.** Images and OCI charts are signed with Sigstore keyless signing, and every
  release carries SBOMs, vulnerability scan reports and a `SHA256SUMS` file.
- **Bundled Postgres sized for concurrent queries.** Its `/dev/shm` is a 512Mi memory-backed volume
  (`postgres.bundled.sharedMemory`) instead of the container default of 64Mi, which parallel queries
  outgrew under a burst of findings.
- **Pinned images.** Charts pull images by digest.
- **Helm is the only install method.** The Docker Compose templates are gone; Compose remains the
  development and CI stack only. ARGUS does not install a local model: embeddings for related-analysis
  retrieval are off unless you point the hub at an endpoint you run (`embeddings.ollamaUrl`).

### Upgrade notes

- Existing releases keep their object names; new installs name objects after the release.
- The hub chart installs this cluster's agent, except where one is already installed.
- `ingress.enabled` now defaults to `true` and renders only when `ingress.host` is set.
- The database volume defaults to 10Gi. The nightly backup CronJob and its volume are gone; an old
  backup volume is kept and can be deleted. Old `postgres.bundled.backup.*` keys are ignored.
- Unknown values keys are now rejected.

See [Upgrading to 0.2.0](docs/INSTALL.md#upgrading-from-a-release-before-020) for the details.

### Fixed

- **The sign-in page shows nothing about your installation.** Anyone who can reach it sees it before
  signing in, so the counters, charts and activity feed from the original designs are gone, along with
  the disabled Google / Entra ID / SAML buttons shown when no single sign-on provider is configured.
  Configured providers still appear. There are two sign-in styles, Aperture and Sentinel; an install
  that had chosen Telemetry is moved to the default.
- **Automatic investigation honours the severities you tick.** It used to investigate Medium
  incidents too whenever it ran at all, so unticking Medium did nothing.
- Saving settings on a new install that has no AI provider yet no longer fails with a server error.
- An agent whose cluster was decommissioned backs off as intended even when its first message to
  the hub fails, instead of reconnecting every few seconds.
- List filter bars no longer carry form-label margins: fields line up with the status tabs, and the
  Incidents list shows its first row 40px higher.
- Approving a fix that runs in place returns the documented response (`incidentId`, `planId`,
  `verdict`, `incidentState`, `message`), the same shape as a pull-request approval and a rejection.

### Known limits

- The hub runs as a single replica; see [docs/SUPPORT.md](docs/SUPPORT.md).
