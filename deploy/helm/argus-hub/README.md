# argus-hub-chart

The ARGUS hub: the web UI, the API, the tunnel agents connect through, and the background jobs, in
one binary. By default it also runs its own Postgres, and the agent for the
cluster it is installed in, so the hub watches that cluster from the start.

## Install

```bash
helm install argus-hub oci://registry-1.docker.io/nubestack/argus-hub-chart --version 0.2.0 \
  -n argus-system --create-namespace \
  --set ingress.host=argus.example.com \
  --set ingress.clusterIssuer=letsencrypt
```

`ingress.host` is the only value an install needs. Drop `ingress.clusterIssuer` if you do not use
cert-manager, and set `ingress.tls.enabled=true` with `ingress.tls.secretName` naming an existing
certificate Secret instead (or leave TLS off for a lab). The IngressClass and the database's
StorageClass default to the cluster's defaults, or one of its classes when none is marked default;
`ingress.className` and `postgres.bundled.persistence.storageClass` choose. On OpenShift (detected,
or `global.openshift=true`) the pods leave their user IDs for the cluster to assign.

**Gateway API instead of Ingress:** set `httpRoute.host` and `httpRoute.parentRefs` (your Gateway)
instead of `ingress.host`; the chart then creates an HTTPRoute for the UI, the API and the agent
tunnel.

The install notes print the sign-in URL and the command that reads the generated admin password.
This cluster appears in **Clusters** as `local` within a minute. Add an AI provider, then enroll other
clusters from **Clusters → Enroll a cluster**, which prints the matching `helm install` of
`argus-agent-chart`. For many clusters, issue one **fleet token** from **Clusters → Fleet tokens**
and roll the agent chart out with Argo CD or Flux (examples in `deploy/examples/`).

## How agents reach the hub

Agents always dial out to the hub; the hub never connects into a cluster. They connect to the same
URL as the UI, `https://<ingress.host>/api/v1/agent/tunnel`, as a WebSocket. Inside it runs a
mutually authenticated TLS session that the hub and agent terminate themselves, so the Ingress only
forwards opaque frames and never sees agent traffic or holds agent credentials. Any ingress
controller that supports WebSocket works without extra configuration; the chart sets long read and
send timeouts for ingress-nginx.

If agents cannot use the Ingress, set `tunnel.service.type=LoadBalancer` (or `NodePort`) and
`tunnel.publicEndpoint=<host>:<port>` to give them a dedicated TLS address instead.

## What it deploys

| Resource | When |
|---|---|
| Hub `Deployment`, API `Service`, tunnel `Service` | Always |
| `ServiceAccount` with no RBAC and no token (the hub never calls a Kubernetes API) | Always |
| `Ingress` for the UI, API and agent tunnel | `ingress.host` is set |
| `HTTPRoute` (Gateway API) for the same | `httpRoute.host` is set |
| This cluster's agent (the agent chart, as `localAgent`) and its enrollment key `Secret` | `localAgent.enabled` (the default), the hub in `argus-system`, and no agent installed here already |
| Bootstrap admin password `Secret` | Unless `bootstrap.existingSecret` |
| Postgres `StatefulSet`, PVC, `Service`, connection `Secret` | `postgres.mode=bundled` (the default) |
| CLI runner `Deployment`, `Service`, `Secret`s | A model credential is supplied, or `cliRunner.enabled=true` |
| Tunnel `LoadBalancer`/`NodePort`, or passthrough `Ingress` | `tunnel.service.type`, `tunnel.ingress.enabled` |

Migrations run in a `migrate` init container before the hub starts, on install and on every upgrade.

## Good to know

- **Values are validated.** The chart ships a `values.schema.json`; a misspelt or misplaced key fails
  the install instead of being ignored.
- **This cluster's agent** enrolls with a single-use key the chart generates, which the hub lists
  under Fleet tokens. It takes any agent-chart value under `localAgent.` (for example
  `localAgent.remediate.enabled`), upgrades with the hub, and is skipped when the cluster already
  runs an agent. `localAgent.enabled=false` turns it off.
- **Images are pinned by digest.** Each chart release pins its images by digest, so `--version` alone
  reproduces an install.
- **No backups of its own.** An upgrade only runs the new release's migrations, each in its own
  transaction. Before upgrading the bundled Postgres, take a copy off the cluster with one
  `pg_dump` command; rolling back is "restore that copy, then `helm rollback`". The install guide has
  both. For data you must keep, use `postgres.mode=external` with your database's own backups.
- **One replica.** The hub holds every agent's tunnel in memory, so `replicaCount` must be 1 and
  upgrades use `strategy: Recreate`. Agents reconnect on their own within seconds.
- **Generated Secrets survive upgrades.** The admin password, Postgres password, runner token and
  metrics token are created once and read back on every upgrade.
- **Data survives `helm uninstall`.** The Postgres StatefulSet, its PVC and the generated Secrets are
  kept (`postgres.bundled.persistence.retainOnDelete`), so a reinstall reconnects to the same data.
- **Production databases.** `postgres.mode=external` points the hub at a managed Postgres or a
  CloudNativePG cluster. Migrations run as a schema-owning role and the hub as `argus_app`, which
  cannot bypass row-level security; one Secret supplies both connection strings.
- **The CLI investigator** (`cliRunner.*`) needs a model credential. Pass it with `--set-file` or an
  existing Secret, never `--set`.
- **The database holds the hub's signing keys and CA.** Protect its volume, and any copy of it, like
  the hub's own credentials.

## Check before installing

```bash
helm template argus-hub oci://registry-1.docker.io/nubestack/argus-hub-chart --version 0.2.0 \
  -n argus-system --set ingress.host=argus.example.com \
  | kubectl apply --dry-run=server -n argus-system -f -
```

User guide (installation and use): <https://argus.nubestack.com/>. Install and upgrade reference:
[`docs/INSTALL.md`](https://github.com/nubestack-cloud/argus/blob/main/docs/INSTALL.md).
