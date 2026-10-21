# Install ARGUS

ARGUS has two parts, each a Helm chart:

- the **hub** — the web UI, the API and the database. You install it once.
- the **agent** — runs in each cluster you want to watch. The hub installs one for its own cluster
  automatically.

This page is the install and upgrade guide. For a step-by-step walkthrough with screenshots, and
for how to use ARGUS once it is running, see the **user guide at <https://argus.nubestack.com/>**.

## Before you start

You need:

- a Kubernetes cluster for the hub, version 1.29 or newer (1.30 or newer if ARGUS may change
  anything: remediation's admission policies need it). Any conformant distribution works, OpenShift
  included: the chart detects OpenShift and lets it assign the pods' user IDs;
- Helm 3.8 or newer on your machine;
- an ingress controller in that cluster (or a Gateway API Gateway: see
  [Gateway API](#gateway-api-instead-of-ingress));
- a hostname for the hub, such as `argus.example.com`, that your browser and your other clusters can
  reach. No DNS name to spare? `argus.<ingress-ip>.nip.io` points at your ingress controller's IP
  with no DNS change.
- optionally, cert-manager, to get HTTPS without handling certificates yourself.

The Ingress uses the cluster's default IngressClass, or one of its IngressClasses if none is
marked default; `ingress.className` chooses one. With no ingress controller at all, the install
notes say so and give the port-forward command.

The database needs a volume. The chart uses the cluster's default StorageClass, or one of its
StorageClasses if none is marked default. A cluster with no StorageClass at all still installs, but
the database is then temporary and loses its data whenever its pod restarts (the install notes
say so): fine for a trial, not for keeping anything.

Decide two things now, because they are hard to change later:

1. **How big the database should be.** The default is 10 GB, enough for a handful of clusters.
   Plan about 0.5–1 GB for each busy cluster you will watch. Helm cannot grow the volume after
   installing, so pick the size up front (see step 1).
2. **Where the data lives.** By default the hub runs its own database in the cluster. That is the
   simplest choice, but it has no scheduled backups. If incident history and the audit log must
   survive losing the cluster, use a managed database instead:
   [External Postgres](#external-postgres).

## Step 1: Install the hub

```bash
helm install argus-hub oci://registry-1.docker.io/nubestack/argus-hub-chart --version 0.2.0 \
  -n argus-system --create-namespace \
  --set ingress.host=argus.example.com \
  --set ingress.clusterIssuer=letsencrypt
```

| Option | What to put |
|---|---|
| `ingress.host` | **Required.** The hub's hostname |
| `ingress.clusterIssuer` | The name of a cert-manager ClusterIssuer in this cluster (`kubectl get clusterissuer`), for HTTPS. The install stops if there is none by that name. No cert-manager? Leave it out and add `--set ingress.tls.enabled=true --set ingress.tls.secretName=<your TLS Secret>` instead. **Plain HTTP, for a trial:** leave out both; the hub is then at `http://<host>`, and agents still encrypt their own connection inside it |
| `ingress.className` | Only to choose a specific ingress controller. Without it, the chart uses the default IngressClass, or one of the cluster's IngressClasses if none is the default |
| `postgres.bundled.persistence.size` | Only if you need more than 10Gi, for example `50Gi` |
| `postgres.bundled.persistence.storageClass` | Only to choose a specific StorageClass. Without it, the chart uses the cluster default, or one of the cluster's StorageClasses if there is no default |

The chart creates one Ingress for the web interface, the API and the agents' connection (a
WebSocket at `/api/v1/agent/tunnel`). The ingress controller terminates HTTPS with the certificate
cert-manager issues, or with your Secret; the agents' own mutual TLS runs inside the WebSocket, so
it is unaffected. The controller must keep those connections open: the chart sets ingress-nginx's
timeouts for you, and with any other controller, or a load balancer in front of it, allow idle
connections of at least 60 seconds (agents send a heartbeat every 30).

Wait for it to start. This takes about a minute, mostly downloading images:

```bash
kubectl -n argus-system rollout status deploy/argus-hub --timeout=5m
```

You now have the hub, its database, and an agent for this cluster. The agent connects by itself
within a minute and appears in ARGUS as `local`.

## Step 2: Sign in

Get the admin password:

```bash
kubectl -n argus-system get secret argus-hub-bootstrap -o jsonpath='{.data.password}' | base64 -d; echo
```

Open `https://argus.example.com`, sign in as `admin@localhost` with that password, and choose a new
password when asked. **Clusters** already shows `local`.

## Step 3: Connect an AI model

ARGUS uses an AI model to investigate incidents. Pick one:

**A model behind an API.** Any OpenAI-compatible endpoint works, including a model you host
yourself. Add it in **Settings → AI providers** and click **Test connection**. Nothing to install.

**Claude Code or Codex.** The hub runs these for you; it needs only their credential. Neither has to
be installed on the machine you run `helm` from.

Put the credential in a file there, without it showing on screen or in your shell history. The
command asks you to paste it, and nothing appears as you paste:

```bash
mkdir -p ~/.argus && chmod 700 ~/.argus
printf 'Paste the credential, then press Enter: '; read -rs TOKEN; echo
printf '%s' "$TOKEN" > ~/.argus/model-credential && unset TOKEN && chmod 600 ~/.argus/model-credential
```

> [!TIP]
> **How to get the credential**, on any machine with a browser:
>
> - **Claude subscription (Pro or Max):** on a machine with Claude Code
>   (`npm install -g @anthropic-ai/claude-code`), run `claude setup-token`, sign in in the browser it
>   opens, and copy the token it prints. It starts `sk-ant-oat01-`.
> - **Anthropic API key:** [console.anthropic.com](https://console.anthropic.com/) → **API keys** →
>   **Create key**. It starts `sk-ant-api03-`.
> - **Codex:** an OpenAI API key, from [platform.openai.com/api-keys](https://platform.openai.com/api-keys)
>   → **Create new secret key**. It starts `sk-`.

Then upgrade the hub with it. For a Claude subscription:

```bash
helm upgrade argus-hub oci://registry-1.docker.io/nubestack/argus-hub-chart --version 0.2.0 \
  -n argus-system --reset-then-reuse-values \
  --set-file cliRunner.modelCredential.claudeCodeOauthToken=$HOME/.argus/model-credential \
  --set cliRunner.authMode=subscription
```

For the others, swap the `--set-file` option:

| You have | Option |
|---|---|
| A Claude subscription | `cliRunner.modelCredential.claudeCodeOauthToken`, plus `--set cliRunner.authMode=subscription` |
| An Anthropic API key | `cliRunner.modelCredential.anthropicApiKey` |
| An OpenAI API key (Codex) | `cliRunner.modelCredential.openaiApiKey` |
| The credential in a Secret already | `cliRunner.modelCredential.existingSecret`, with key `CLAUDE_CODE_OAUTH_TOKEN`, `ANTHROPIC_API_KEY` or `OPENAI_API_KEY` |

Once the upgrade is done, delete the file: `rm ~/.argus/model-credential`.

Never pass a credential with plain `--set`: it would be saved in your shell history. Then in
**Settings → AI providers**, add a provider of kind **CLI**, with runner URL
`http://argus-hub-cli-runner:8090` and agent `claude` or `codex`, and click **Test connection**.

## Step 4: Add your other clusters

Each cluster runs one agent, which connects out to the hub. Nothing connects into your clusters,
and the hub never needs their kubeconfigs. Each cluster must be able to reach the hub's hostname.

**One cluster.** In ARGUS, open **Clusters → Enroll a cluster**. It shows commands with the hub's
address and a one-time token already filled in. Run them against the new cluster:

```bash
kubectl create namespace argus-system
kubectl -n argus-system create secret generic argus-enrollment-token --from-literal=token=<token>
helm install argus-agent oci://registry-1.docker.io/nubestack/argus-agent-chart --version 0.2.0 \
  -n argus-system --set namespace.create=false \
  --set hub.apiUrl=https://argus.example.com \
  --set enrollment.tokenSecretRef.name=argus-enrollment-token \
  --set displayName=prod-eu
```

When the cluster appears in **Clusters**, click **Accept**.

**Many clusters.** Open **Clusters → Fleet tokens** and issue one token for all of them. Tick
**Accept automatically** if you don't want to accept each cluster by hand. Put the token in every
cluster as the Secret `argus-system/argus-enrollment-token` (key `token`), and install the agent
chart everywhere with your GitOps tool. There are ready-made examples for an
[Argo CD ApplicationSet](../deploy/examples/argocd/agents.yaml) and [Flux](../deploy/examples/flux/agent.yaml).

ARGUS only watches at first. It changes nothing in a cluster until you
[allow remediation](#allow-remediation) there.

## Upgrading

1. Read the [changelog](../CHANGELOG.md) for every release since yours. Anything that needs your
   attention is listed there.
2. **Back up the database, off the cluster** (bundled Postgres). This file is your way back if the
   upgrade goes wrong:

   ```bash
   kubectl -n argus-system exec argus-hub-postgres-0 -- pg_dump -U postgres -Fc argus > argus-before-upgrade.dump
   ```

   Keep it somewhere safe: it holds the hub's keys as well as its data. With an external database,
   use your database's own backup or snapshot instead.
3. Upgrade the hub:

   ```bash
   helm upgrade argus-hub oci://registry-1.docker.io/nubestack/argus-hub-chart --version <new> \
     -n argus-system --reset-then-reuse-values
   kubectl -n argus-system rollout status deploy/argus-hub --timeout=10m
   ```

   The hub restarts once, for about 20 seconds, and applies the new release's database migrations
   before it serves anything; each migration is one transaction, so a failed one changes nothing.
   Agents reconnect by themselves, and the hub's own cluster's agent is upgraded with it.
4. Upgrade the agent in each of your other clusters, in any order:

   ```bash
   helm --kube-context <ctx> upgrade argus-agent oci://registry-1.docker.io/nubestack/argus-agent-chart \
     --version <new> -n argus-system --reset-then-reuse-values
   ```

   Or click **Upgrade agent** on the cluster's **Agent** tab, if that agent was installed with
   `selfUpgrade.enabled=true`.
5. Check that every cluster is `Active` in **Clusters**, and that each **Agent** tab shows the new
   version.

Two things to avoid: `--reuse-values` (it also keeps the old image versions, so nothing changes),
and `helm upgrade --force` on an agent (it deletes the agent's identity, so the cluster has to be
added again). An upgrade otherwise keeps every cluster connected.

### Rolling back an upgrade

**An agent:** `helm --kube-context <ctx> rollback argus-agent -n argus-system`.

**The hub** can only go back together with its database, because an upgrade changes the database
to the new version. Restore the copy you took before upgrading, then roll back:

```bash
P="kubectl -n argus-system exec argus-hub-postgres-0 --"
kubectl -n argus-system scale deploy/argus-hub --replicas=0
$P psql -U postgres -d postgres -c "ALTER DATABASE argus RENAME TO argus_before_rollback"
$P createdb -U postgres argus
kubectl -n argus-system exec -i argus-hub-postgres-0 -- \
  pg_restore -U postgres -d argus --exit-on-error < argus-before-upgrade.dump
helm -n argus-system rollback argus-hub
```

Then check the hub loaded its keys:
`kubectl -n argus-system logs deploy/argus-hub -c hub | grep -c "loaded the persisted"` should print
`5`. Anything recorded after the upgrade is lost. Once all is well, delete the old copy:
`$P dropdb -U postgres argus_before_rollback`.

With an external database, restore from your database's own backup instead.

### Upgrading from a release before 0.2.0

- Your existing object names and data are kept.
- If the cluster already runs an agent you installed, the hub does not add a second one.
- A dedicated tunnel address (`tunnel.publicEndpoint`) keeps working. To move agents to the
  Ingress, upgrade each with `--set hub.tunnelEndpoint=wss://<ingress.host>/api/v1/agent/tunnel`,
  then remove `tunnel.*` from the hub's settings.
- The nightly database backup is gone. Its volume (`<release>-postgres-backup`) is kept; delete it
  when you no longer need the old copies.
- Settings are now checked: a misspelt option stops the upgrade and names the option.
- Your retention settings are kept. Only new installs keep findings for 30 days by default.

---

# Reference

## Other ways to install

Helm is the way to install ARGUS. Two situations change the command.

### No ingress, just trying it

Install without any `--set` options, then
`kubectl -n argus-system port-forward svc/argus-hub 8080:8080` and open `http://localhost:8080`. The
hub watches its own cluster; other clusters cannot reach it.

### Gateway API instead of Ingress

Attach the hub to a Gateway you run, instead of setting `ingress.host`:

```bash
helm install argus-hub oci://registry-1.docker.io/nubestack/argus-hub-chart --version 0.2.0 \
  -n argus-system --create-namespace \
  --set httpRoute.host=argus.example.com \
  --set 'httpRoute.parentRefs[0].name=<gateway>' \
  --set 'httpRoute.parentRefs[0].namespace=<gateway-namespace>'
```

The chart creates an HTTPRoute for the UI, the API and the agents' tunnel. The Gateway's listener
holds the certificate for the host (`httpRoute.https=false` for plain HTTP), and it must allow
WebSocket connections to stay open: agents send a heartbeat every 30 seconds.

### All the options

Every value is documented in `helm show values oci://registry-1.docker.io/nubestack/argus-hub-chart --version 0.2.0`,
and both charts validate values against a schema. This cluster's agent takes every agent-chart value
under `localAgent.` (for example `localAgent.displayName=hub-cluster`); `localAgent.enabled=false`
turns it off.

### What is published

 Each release `X.Y.Z` publishes the hub and agent charts
(`oci://registry-1.docker.io/nubestack/argus-hub-chart`, `…/argus-agent-chart`) and the images
`nubestack/argus-hub`, `nubestack/argus-agent` and `nubestack/argus-cli-runner` for amd64 and arm64.
A chart version pins its images by digest, so `--version` installs the same bytes every time. Images
and charts are signed ([verify a release](SUPPORT.md#verifying-a-release)).

## How agents connect

Agents enroll over HTTPS at the hub's URL and then keep a WebSocket open at
`/api/v1/agent/tunnel` on the same host. Inside it runs a mutual-TLS session that only the agent and
the hub can decrypt, so the Ingress forwards opaque frames and never sees agent traffic. Any ingress
controller with WebSocket support works; a load balancer in front of it needs an idle timeout of at
least 60 seconds (agents send heartbeats every 30). This cluster's agent connects to the hub's
in-cluster Service instead.

Check that a cluster can reach the hub:

```bash
kubectl --context <ctx> run argus-probe --rm -i --restart=Never --image=busybox:1.36 -- \
  wget -qO- -T 5 https://argus.example.com/healthz
```

**A dedicated tunnel address**, for networks that cannot carry WebSockets through the Ingress: the
hub also serves the tunnel on its own TLS port (8443). Expose it with
`tunnel.service.type=LoadBalancer` (or `NodePort` with `tunnel.service.nodePort`) and set
`tunnel.publicEndpoint=<host>:<port>`. That address is written into the tunnel certificate; to move it
later, keep the old host in `tunnel.extraSANs` until every agent has moved. An enrolled agent switches
path with `--set hub.tunnelEndpoint=<address>`, without enrolling again.

**A private CA.** If the hub's certificate comes from an internal CA, give agents the CA:
`--set-file hub.caBundle=./ca.pem`, or `--set hub.caSecretRef.name=<Secret holding ca.crt>`.

## Allow remediation

Agents are read-only. Write access is Kubernetes RBAC in the watched cluster, turned on per cluster
and limited to the namespaces you list:

```bash
helm --kube-context <ctx> upgrade argus-agent oci://registry-1.docker.io/nubestack/argus-agent-chart \
  --version 0.2.0 -n argus-system --reset-then-reuse-values \
  --set remediate.enabled=true --set 'remediate.namespaces={payments,checkout}'
```

For the hub's own cluster, set the same values on the hub release with a `localAgent.` prefix
(`--set localAgent.remediate.enabled=true`).

This adds a second agent Deployment under its own identity, fenced by admission policies (Kubernetes
1.30+). `remediate.allNamespaces=true` allows every namespace, `kube-system` included.
`remediate.nodeOps.enabled=true` adds cordon and drain; `selfUpgrade.enabled=true` lets the hub
upgrade the agent. `remediate.enabled=false` makes the cluster read-only again. What remediation does
and what bounds it: [Connect a cluster](https://argus.nubestack.com/getting-started/connect-a-cluster/).

## External Postgres

Set `postgres.mode=external` and give the hub one Secret with two connection strings, because
migrations and the hub run as different roles:

| Key | Role | Must |
|---|---|---|
| `url` | exactly `argus_app` | `LOGIN`, and **not** a superuser or `BYPASSRLS`: the hub checks |
| `migrateUrl` | a schema-owning role, e.g. `argus_migrate` | create and alter objects in the database |
| `appPassword` | (with `postgres.external.appPasswordKey`) | the password in `url`; migrations set it on `argus_app` |

The database needs Postgres 16 with the **pgvector** extension. Prepare it once, as an administrator:

```sql
CREATE DATABASE argus;
CREATE ROLE argus_migrate LOGIN PASSWORD '<migrate-password>';
ALTER DATABASE argus OWNER TO argus_migrate;
CREATE ROLE argus_app;
GRANT argus_app TO argus_migrate WITH ADMIN OPTION;
ALTER ROLE argus_migrate CREATEROLE;
\c argus
CREATE EXTENSION IF NOT EXISTS vector;
```

```bash
umask 077; cat > argus-db.env   # paste the three lines, then Ctrl-D
url=postgres://argus_app:<app-password>@db.example.internal:5432/argus?sslmode=require
migrateUrl=postgres://argus_migrate:<migrate-password>@db.example.internal:5432/argus?sslmode=require
appPassword=<app-password>
```

```bash
kubectl -n argus-system create secret generic argus-db --from-env-file=argus-db.env && rm argus-db.env
helm install argus-hub oci://registry-1.docker.io/nubestack/argus-hub-chart --version 0.2.0 \
  -n argus-system --set ingress.host=argus.example.com \
  --set postgres.mode=external --set postgres.external.existingSecret=argus-db \
  --set postgres.external.appPasswordKey=appPassword
```

**CloudNativePG.** With the [CloudNativePG](https://cloudnative-pg.io/) operator installed, this
creates a replicated database prepared for ARGUS (the image must include pgvector; CloudNativePG's
standard images do, but check yours):

```yaml
apiVersion: postgresql.cnpg.io/v1
kind: Cluster
metadata:
  name: argus-db
  namespace: argus-system
spec:
  instances: 3
  imageName: ghcr.io/cloudnative-pg/postgresql:16
  storage:
    size: 20Gi
  bootstrap:
    initdb:
      database: argus
      owner: argus_migrate
      postInitApplicationSQL:
        - CREATE EXTENSION IF NOT EXISTS vector
        - CREATE ROLE argus_app
        - GRANT argus_app TO argus_migrate WITH ADMIN OPTION
        - ALTER ROLE argus_migrate CREATEROLE
  # Add spec.backup (object storage) for point-in-time recovery.
```

Build the hub's Secret from the operator's `argus-db-app` Secret, with a new password for `argus_app`:

```bash
MIGRATE_URL=$(kubectl -n argus-system get secret argus-db-app -o jsonpath='{.data.uri}' | base64 -d)
APP_PW=$(openssl rand -hex 24); umask 077
printf 'migrateUrl=%s\nurl=postgresql://argus_app:%s@argus-db-rw.argus-system.svc:5432/argus\nappPassword=%s\n' \
  "$MIGRATE_URL" "$APP_PW" "$APP_PW" > argus-db.env
kubectl -n argus-system create secret generic argus-db --from-env-file=argus-db.env && rm argus-db.env
unset MIGRATE_URL APP_PW
```

On a shared server, `postgres.pool.maxConns` caps the hub's share of `max_connections`.

## Resizing the database volume

Growing the bundled database's volume works only if its StorageClass allows expansion
(`kubectl get storageclass` shows `ALLOWVOLUMEEXPANSION true`; `local-path` does not):

```bash
kubectl -n argus-system patch pvc data-argus-hub-postgres-0 \
  -p '{"spec":{"resources":{"requests":{"storage":"100Gi"}}}}'
kubectl -n argus-system delete statefulset argus-hub-postgres --cascade=orphan   # Postgres keeps running
helm upgrade argus-hub oci://registry-1.docker.io/nubestack/argus-hub-chart --version 0.2.0 \
  -n argus-system --reset-then-reuse-values --set postgres.bundled.persistence.size=100Gi
```

Postgres's shared memory (`postgres.bundled.sharedMemory`, 512Mi) counts against its memory limit.

## Uninstall

`helm -n argus-system uninstall argus-hub` removes the hub and this cluster's agent but keeps the
database and the generated Secrets, so a reinstall finds its data again. The agent's
identity goes with it (an uninstall is a decommission), so before reinstalling, decommission the old
`local` cluster in **Clusters**; the reinstalled agent then enrolls afresh. To remove everything:

```bash
helm -n argus-system uninstall argus-hub
kubectl -n argus-system delete statefulset argus-hub-postgres
kubectl -n argus-system delete pvc data-argus-hub-postgres-0   # the data: no way back
kubectl -n argus-system delete secret --ignore-not-found argus-hub-db argus-hub-bootstrap argus-hub-cli-runner \
  argus-hub-metrics
```

An agent in another cluster: `helm -n argus-system uninstall argus-agent`, then decommission the
cluster in **Clusters**.

## Troubleshooting

**Hub stuck at `Init:0/2`, Postgres PVC `Pending`.** The StorageClass cannot create the volume:
`kubectl -n argus-system describe pvc data-argus-hub-postgres-0` says why. Fix the storage, or choose
another class: delete the StatefulSet and the empty PVC
(`kubectl -n argus-system delete statefulset argus-hub-postgres; kubectl -n argus-system delete pvc data-argus-hub-postgres-0`),
and upgrade with `--set postgres.bundled.persistence.storageClass=<class>`.

**The browser warns about the certificate.** cert-manager has not issued it yet:
`kubectl -n argus-system describe certificate argus-hub-tls` shows why. A ClusterIssuer that uses
HTTP-01 needs the hub's hostname to be reachable from the internet.

**`additional properties '<key>' not allowed`.** A values key is misspelt or misplaced; the message
names it.

**`local` does not appear in Clusters.** Read its log:
`kubectl -n argus-system logs deploy/argus-agent`. The install notes (`helm status argus-hub -n
argus-system`) say whether it was installed: it is not when the hub is outside `argus-system` or the
cluster already ran another agent.

**Another cluster never appears.** It cannot reach the hub: run the [probe](#how-agents-connect) from
that cluster and read its agent's log.

**The tunnel drops every minute.** Something in front of the Ingress cuts idle connections; raise its
idle timeout to at least 60 seconds, or use a [dedicated tunnel address](#how-agents-connect).

**`migrate` fails** (`kubectl -n argus-system logs deploy/argus-hub -c migrate`).
`extension "vector" is not available`: the Postgres has no pgvector. `password authentication failed`
after a reinstall: the data survived but the `argus-hub-db` Secret did not.

**The Ingress answers 404.** It matches only `ingress.host`. An empty `ADDRESS` in
`kubectl -n argus-system get ingress` means `ingress.className` names a class no controller watches.

**"already enrolled".** The hub identifies a cluster by its `kube-system` UID: decommission the old
record in **Clusters** and enroll again.

## Production checklist

- HTTPS on the Ingress; settings in a values file passed on every upgrade.
- External Postgres with its own backups, if incident history and the audit log must survive losing
  the cluster. With the bundled one, a copy taken off the cluster before every upgrade
  ([Upgrading](#upgrading)).
- The database volume sized for your fleet (0.5–1 GB per busy cluster) and finding retention set to
  suit.
- Model credentials by `--set-file` or `existingSecret`, never `--set`.
- `/metrics` scraped with its bearer token ([METRICS.md](METRICS.md)).
- Cost limits, storm protection and Git repository bindings set in **Settings** before relying on
  automation; remediation enabled per cluster and namespace, once you trust what ARGUS proposes.
- [Supported versions and known limits](SUPPORT.md), including the single-replica hub.
