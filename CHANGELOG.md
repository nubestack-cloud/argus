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
- **Upgrades only migrate.** `helm upgrade` runs the new release's migrations, each in one
  transaction, and does nothing else to the database. The upgrade steps start with one command that
  copies the bundled database off the cluster, which is also how an upgrade is
  [rolled back](docs/INSTALL.md#rolling-back-an-upgrade). The chart takes no backups of its own: for
  data you must keep, use an external Postgres with its own backups.
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
  backup volume is kept and can be deleted. `postgres.bundled.backup.*` keys are accepted and
  ignored.
- Unknown values keys are now rejected.

See [Upgrading to 0.2.0](docs/INSTALL.md#upgrading-from-a-release-before-020) for the details.

### Fixed

- **An incident waiting on a decision closes when what it is about is deleted.** It used to stay
  open forever if its workload, or its object when it had none (a bare Pod), was deleted while a
  plan awaited approval: the plan had nothing left to act on. A pod replaced by a rollout still
  does not close it.
- **Metrics, traffic and cost connect by themselves.** The agent chart finds a Prometheus the
  cluster already runs (Rancher monitoring, kube-prometheus-stack, a Prometheus server, a Thanos
  query, a VictoriaMetrics single node) at install and upgrade, by the same rules the Traffic tab
  uses to suggest one, and the install notes name it. `metrics.prometheusService` still chooses
  one, and `metrics.autoDetect=false` turns it off.
- **The charts install on any conformant Kubernetes without cluster-specific settings.** On
  OpenShift (detected, or `global.openshift=true`) the pods leave their user and group IDs for the
  cluster to assign, as its restricted policy requires. With no default IngressClass the hub's
  Ingress uses one of the cluster's, and with none at all the install notes say so. Remediation and
  dry runs refuse a cluster older than 1.30 with a plain message, since their admission policies
  need it; a read-only agent still installs on 1.29.
- **A refused Analyze no longer shifts the incident header.** The reason floats under the button and
  can be dismissed. With no AI provider set up it says so in plain words, with a link to set one
  up for people who can. The Overview no longer shows a setup card that could not be put away:
  choosing an AI provider is a step in the top bar's setup guide.
- **The agent can read the whole cluster by default** (`read.allApiGroups`): get, list and watch on
  every API group the cluster serves, CRDs included, plus CRDs added later that grant read to the
  built-in `view` role. Before, it read only a fixed list of kinds. Still never Secret contents,
  `pods/exec`, `attach`, `port-forward` or `*/proxy`, and never a write. A few groups whose reads
  amount to credentials or sessions are left out (`read.excludeApiGroups`); a CRD added later
  without that label becomes readable at the agent's next `helm upgrade`.
- **The install works on a cluster with no default StorageClass.** The bundled database's volume
  uses the cluster default, else one of the cluster's StorageClasses, instead of waiting forever
  for a volume nothing would create. With no StorageClass at all the database runs on a temporary
  volume, and the install notes say so. An existing database's volume is never changed.
- **A missing `ingress.clusterIssuer` stops the install** with the cluster's ClusterIssuers listed,
  instead of an Ingress whose certificate never arrives.
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
