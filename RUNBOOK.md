# Runbook

> **Deploying ARGUS for real?** Start with [`docs/INSTALL.md`](docs/INSTALL.md) — hub, Postgres,
> agents, AI providers and the settings that are off by default. This file is the *dev and operations*
> companion to it: local iteration, the test suites, upgrading a running stack, and working against a
> real cluster.

**Procedures you follow line by line.** Bringing the dev stack up, running an agent,
enrolling a real cluster, configuring what the product does at runtime, backing the hub up
and restoring it, running the test suites, deploying a change to a running stack, and
working against a real cluster. [`README.md`](README.md) is the two-minute orientation page; this is the file to
open when you are actually doing something.

Most of what follows is written down because it was got wrong first — by people and by AI
agents. The `go:embed` rebuild requirement under "Deploying a frontend change", the agent
fingerprint collision under "Testing against a real cluster", and keeping every kubeconfig
explicit, in that same section, are the three that have cost the most time. Read them before improvising.

## What gets deployed (dev/test environment), and what each piece does

`docker compose up` brings up **four** containers — deliberately minimal; see the note at the top of `docker-compose.yaml` for why `redis`/`nats`/`dex`/`minio` are commented out rather than running idle:

| Service | Role | Currently used by the app? |
|---|---|---|
| `postgres` | The system of record — users, grants, clusters, incidents, everything (`retired LLD-05`). Row-level security is enforced here, not just in application code. Image is `pgvector/pgvector:pg16` (a drop-in-compatible superset of `postgres:16`, not a different engine) so `CREATE EXTENSION vector` (migration 000082, `PROJECT.md` L2's storage half) has something to install into. | **Yes** — everything implemented so far reads/writes through it. |
| `hub-migrate` | One-shot: applies the Postgres schema migrations (`internal/migrations/`), then sets the login password on the `argus_app` role (which migrations deliberately create `NOLOGIN` — no password belongs in a migration file). Runs once, exits. | Yes — this is how the schema gets created and how `hub-api` gets a usable credential. |
| `hub-api` | The actual long-running service. **This is the whole application** — JSON HTTP API and the web UI (embedded static assets, `internal/api/static.go`), both on `:8080`. Also opens `:8443` for the agent mTLS tunnel. | Yes — this is the application. |

`redis` (locks, rate limits, spend counters), `nats` (JetStream — finding ingestion, agent tunnel queues), `dex` (SSO broker), and `minio` (evidence object storage) are all commented out — none has a Go client anywhere in this repo yet. Uncomment the one you need when the code that needs it actually exists; don't run them idle "for later."

## Local development

### Option A — fully containerized (closest to how it actually deploys)

```
docker build -t argus/hub:dev .
docker compose -f deploy/compose/docker-compose.yaml up -d
```

That's it — `hub-migrate` runs once as an init-style service (schema + `argus_app` password), `hub-api` comes up listening on `:8080` once it succeeds. Check `docker compose -f deploy/compose/docker-compose.yaml ps -a` if something didn't start; logs via `docker compose -f deploy/compose/docker-compose.yaml logs <service>`.

### Option B — running the hub on the host (faster iteration while writing Go code)

```
docker compose -f deploy/compose/docker-compose.yaml up -d postgres

export ARGUS_MIGRATE_DATABASE_URL="postgres://postgres:postgres@localhost:5432/argus?sslmode=disable"
export ARGUS_APP_PASSWORD="dev-local-password-123"   # pick any value — this is local-dev only
go run ./cmd/hub migrate   # applies migrations AND sets argus_app's password in one step

export ARGUS_DATABASE_URL="postgres://argus_app:${ARGUS_APP_PASSWORD}@localhost:5432/argus?sslmode=disable"
go run ./cmd/hub api
```

**Option B serves a blank UI unless you copy the bundle across first, and it will not tell you.**
`go:embed` reads `internal/api/static` (`internal/api/static.go`), not `web/dist` — the Dockerfile
does `rm -rf internal/api/static && COPY --from=web-build /web/dist internal/api/static` before
building, and what is checked in is a placeholder `index.html` saying the binary was built without
the UI. A host-run hub therefore serves that placeholder with a 200, no error and no warning. If you
need the real UI on Option B:

```
cd web && npm run build && cd ..
rm -rf internal/api/static && cp -r web/dist internal/api/static   # then go run ./cmd/hub api
```

Restore the placeholder before committing — `git status internal/api/static` should be clean.

(`.env.example` at the repo root documents the variable names Option B needs — copy it to `.env` and `set -a; source .env; set +a` if you'd rather not export them by hand one at a time. Nothing here reads `.env` automatically; it's a reference, not a config file the tooling loads for you.)

Either way: the bootstrap super-admin credential is printed once to stdout on first run against an empty database (HLD §5.6) — no default password ships in the Go code itself. Verify it's actually working with `curl localhost:8080/readyz` (checks the RLS preconditions in `lld/01-threat-model.md` SR-2, not just that the process is up). If you're running this way (Option B, not the compose profile), you'll need to grep the logs for it each time you wipe the database, same as before.

**Note:** the hub's runtime base image is `gcr.io/distroless/base-debian12`, not the smaller `static-debian12` variant — the latter broke container-name DNS resolution in testing here even with a fully static binary. See `PROJECT.md` §4 before "optimizing" this back to `static`.

### Option C — running the spoke agent against the compose-hosted hub

`cmd/agent` implements the spoke side of `retired LLD-03`'s enrollment handshake and tunnel (§2, §5-§8), scoped to this repo's MVP transport (`internal/tunnel`'s newline-delimited-JSON-over-mTLS, not gRPC yet). Once the hub is up (Option A or B above) and you have an enrollment token (`POST /api/v1/clusters/enrollment-tokens`, see "Accessing it" below):

```
export ARGUS_ENROLLMENT_TOKEN=<from the enrollment-token endpoint or the UI>
export ARGUS_HUB_API_URL=http://localhost:8080
go run ./cmd/agent
```

It enrolls, logs `pendingApproval` while it polls for an admin to accept the cluster, then connects the mTLS tunnel and sends a heartbeat every 30s once accepted. A successful enrollment's key/cert/CA and hub tunnel endpoint are persisted under `ARGUS_AGENT_DATA_DIR` (default `./argus-agent-data`), so restarting the same binary against the same data dir reconnects directly without needing the token again.

**Trap: `./argus-agent-data` is relative to whatever directory you happened to `go run` from.** Restart the same binary from a *different* shell/cwd and it looks for (and creates) an unrelated, empty data dir — the agent re-enrolls from scratch, indistinguishable from a genuine identity loss unless you notice the fresh `pendingApproval` log line and think to check `pwd`. Pass an absolute `ARGUS_AGENT_DATA_DIR` for anything you intend to restart more than once.

**The Helm-deployed in-cluster agent no longer has this problem by default (`PROJECT.md` B163).** `deploy/helm/argus-agent` now ships `identity.mode: secret`: the issued cert/key/CA, cluster id, plan signing key and fingerprint live in a Kubernetes Secret in the agent's own namespace (`templates/identity-secret.yaml`), which the chart creates and the agent reads and updates through a Role restricted by `resourceNames` to that one Secret. No StorageClass is involved, so it works on every cluster in a heterogeneous fleet, and it survives node loss — which a node-local `ReadWriteOnce` PVC does not. A `kubectl set env`, `kubectl rollout restart`, a `resources.limits` edit, a node drain or an eviction is now a restart, not a re-enrollment. The log line to look for is `agent: identity is stored in Secret argus-system/argus-agent-identity — it survives pod replacement`.

**What still loses the identity, and is meant to:** `helm uninstall` (a decommission — the Secret goes with the release) and `helm upgrade --force` (which replaces objects instead of patching them, discarding the Secret's contents; do not use `--force` against an enrolled agent). `identity.mode: ephemeral` also deliberately reproduces the old behaviour, and the agent logs a warning on every start in that mode.

**If you are looking at an agent deployed from an older chart, or one running `identity.mode: ephemeral`,** the original failure still applies and is worth understanding, because it is what the default now prevents. `agent-data` is an `emptyDir` — not relative-path-fragile, but Pod-lifetime-fragile: it is wiped by *any* Pod restart, not just an image/version change. A `kubectl set env`, `kubectl rollout restart`, an edit to `resources.limits`, a node drain, or simply the scheduler evicting the Pod all destroy the enrolled mTLS cert/key/CA and cluster ID exactly as completely as deleting the whole release would — with no warning, because the Pod comes back `Running` and looks healthy; the failure only shows up later as the agent stuck in `CrashLoopBackOff`/`Disconnected` trying to re-enroll with credentials it no longer has, or (if it *can* silently obtain a fresh identity) as a phantom second cluster row on the hub. Recovery needs `POST /api/v1/clusters/{id}/decommission` (clears the fingerprint-uniqueness constraint) followed by a full re-enrollment with a fresh token — restarting again does not fix it. Two ways to avoid this:
- Upgrade to a chart with `identity.mode: secret` (the default), which needs nothing from the target cluster. An agent that already has an identity in `dataDir` — from a PVC, say — keeps it: `internal/agent/identity.go` adopts what it finds there into the Secret on first start rather than re-enrolling.
- Or set `persistence.enabled: true` (`values.yaml`, added by the PROJECT.md 128 fix) on any cluster with a real StorageClass — the disposable `kind` cluster already provisions `local-path-storage`, so this costs nothing there. This backs `agent-data` with a real PersistentVolumeClaim instead of an `emptyDir`, so an ordinary Pod restart no longer loses the mounted identity (though deleting the PVC itself, or the namespace, still does; and a node-local provisioner binds the Pod to one node).
- Otherwise, treat every restart of an in-cluster agent as equivalent to a fresh install: expect to decommission and re-enroll, and don't be surprised when a "routine" `kubectl set env` turns into that.

This works even without a live target Kubernetes cluster to point it at — cluster fact-gathering (server version, node count) is best-effort and reports `Reachable: false` if there's no reachable `KUBECONFIG`/in-cluster config, which makes the enrollment/tunnel flow itself fully testable standalone.

### Option D — enrolling a real cluster (recommended for anything other than local testing)

Option C above (`go run ./cmd/agent`) was only ever meant for exercising the tunnel logic without needing a real cluster — it doesn't install any RBAC and just inherits whatever ambient credentials happen to be around. For a real cluster, use the agent chart: **Clusters → Enroll a cluster** in the UI prints the `helm install` with a fresh token (the agent runs as the read-only `argus-investigate` ServiceAccount — no Secrets, no write verbs, no ambient credentials). Run it against the cluster, then accept it in the UI.

### Option E — a whole ARGUS on a throwaway `kind` cluster

For testing the install path itself, or a disposable hub to try something against, install the hub chart; it installs that cluster's agent too. Use a dedicated kubeconfig file so the context can never be confused with a real cluster's:

```
kind create cluster --name argus-try --kubeconfig ~/.kube/kind-argus-try.yaml
helm --kubeconfig ~/.kube/kind-argus-try.yaml install argus-hub deploy/helm/argus-hub -n argus-system --create-namespace
kubectl --kubeconfig ~/.kube/kind-argus-try.yaml -n argus-system port-forward svc/argus-hub 8080:8080
# ... and when done:
kind delete cluster --name argus-try && rm ~/.kube/kind-argus-try.yaml
```

It uses the images the charts pin, pulled from Docker Hub by the kind node — not a local build. To test
a local hub or agent build this way, load the image into the node first (see "A disposable `kind`
cluster" below) and pass the chart's image values with `helm upgrade --reset-then-reuse-values` after
the install. Point it only at a cluster you own: on a cluster that already runs a hub it only
(re)enrolls, but that still installs, uninstalls and accepts agents.

### Independently verifying the audit log's hash chain (SR-15)

`internal/audit`'s `RecordEvent` chains every `audit_events` row to the one before it with a SHA-256 hash (`retired LLD-05` §7) — but a hash chain is only actually tamper-*evident* if something can independently recompute and check it. `argusctl audit verify` is that something, and it deliberately is **not** a hub API endpoint: every route the hub API serves is something a compromised hub controls, so a verification feature reachable only through the hub could be disabled by exactly the kind of compromise it exists to detect. This tool only needs a Postgres connection string; it never talks to the hub API at all.

```
argusctl audit verify --database-url "postgres://postgres:postgres@localhost:5432/argus?sslmode=disable"
# or, equivalently, with $ARGUS_MIGRATE_DATABASE_URL already set in your shell:
argusctl audit verify
```

It reads every `audit_events` row (across all tenants, in `occurred_at ASC, id ASC` order — the same partitioned table a plain `ORDER BY` over the parent already spans transparently, no per-partition looping needed), and for each row checks two independent things: (1) recomputing the row's own hash from its own stored fields and its own stored `prev_hash` reproduces its own stored `hash`, and (2) that stored `prev_hash` actually equals the immediately preceding row's stored `hash` (or the documented genesis constant, for the first row). It reports the first row where either check fails — id, timestamp, which check, expected vs. actual — and exits non-zero. Zero rows is reported as a trivially intact (empty) chain, not a failure.

**Connection requirement, and why:** `audit_events` has `FORCE ROW LEVEL SECURITY`, and this tool needs to see every tenant's rows, not one tenant's RLS-scoped view — the opposite of the hub API's own connection, which `internal/data.DB.CheckRLSPreconditions` requires to *not* be able to bypass RLS. So `audit verify` requires a connection string for a role that **does** bypass RLS (a superuser, or one with `BYPASSRLS`) — `$ARGUS_MIGRATE_DATABASE_URL` (the migration-owning connection, already a superuser in the dev/compose setup) works; `$ARGUS_DATABASE_URL` (the `argus_app` role) does not, and the tool refuses to run under it rather than silently "verifying" an empty, RLS-filtered view as if it were a genuinely clean chain. Resolution order: `--database-url`, then `$ARGUS_MIGRATE_DATABASE_URL`, then `$ARGUS_DATABASE_URL` (which will fail the bypass check and print an explanation, rather than a false result).

## Accessing it

**There's a GUI now, and it's embedded in the same container as the API** — one image, one running container, per the consolidation goal in `the retired high-level design` §4.1.1. It is no longer the login-plus-cluster-list first slice this paragraph used to describe: `web/src/components/AppShell.tsx`'s nav is the current list of screens (Overview, Clusters, Incidents, Approvals, Tolerations, Audit Log, Insights, Users, Settings), each with its own section below. Still not the full `retired LLD-11` spec — read the nav, not this sentence, for what exists.

```
docker build -t argus/hub:dev .
docker compose -f deploy/compose/docker-compose.yaml up -d
```

Open `http://localhost:8080/` (or `http://<host-ip>:8080/` if you're not on the machine running Docker) directly in a browser — that's it, no separate frontend process. Log in as `admin@localhost` / `dev-admin-password-123` (the compose profile's `ARGUS_BOOTSTRAP_PASSWORD`, fixed for local dev so it doesn't change on every volume wipe — see `docker-compose.yaml`; override it with a real shell env var before `up` if you want something else, and never reuse this value outside a throwaway dev stack), and you'll land on the fleet overview. Click "Enroll a cluster" to get a token and the ready-to-paste `helm install argus-agent deploy/helm/argus-agent --set hub.apiUrl=… --set enrollment.token=…` command (`web/src/components/EnrollTokenModal.tsx`'s `shellSnippet` — the modal renders that, and only that, whichever TTL class you pick; it has never rendered the `go run ./cmd/agent` form this line used to promise). Run it against a target cluster — or export the same token into Option C's `go run ./cmd/agent` by hand if you only want to exercise the tunnel — and watch the cluster appear as `pendingApproval`, click Accept, and watch it flip to `Active` within a few seconds as the real agent connects its mTLS tunnel and sends its first heartbeat. That loop — enroll, accept, watch it go healthy — is the current MVP end to end.

**Decommissioning a cluster** (the "Decommission" action on a cluster's detail page) only ever updates the hub's own records — it archives the cluster and, if its tunnel happens to be open right now, force-closes that connection immediately (`internal/gateway.Gateway.Disconnect`), and the hub refuses the cert if the agent tries to reconnect afterward (`lookupClusterBySerial`'s state check). What it does **not** do is remove anything from the cluster itself: the `argus-agent` process (there is no remote-uninstall mechanism, and no protocol message that means "stop trying permanently") keeps running and will keep retrying its connection forever, indistinguishable to it from an ordinary network blip. The UI's confirmation modal says this explicitly once the decommission succeeds; to actually finish the job, run this against that cluster's own kubeconfig context (matching this repo's own install convention — release name `argus-agent`, namespace `argus-system`, as the UI's enroll command installs it):

```
helm uninstall argus-agent -n argus-system --kube-context <your-context>
```

**Developing the UI itself?** `docker build` bakes a snapshot of `web/`'s built assets into the image — it won't pick up frontend edits until you rebuild. For hot-reload iteration, run the UI standalone instead: `cd web && npm install && npm run dev`, which proxies `/api` to `localhost:8080` and reflects source changes immediately.

Once an agent is enrolled and its detector reports a real Kubernetes Warning event, it shows up under **Incidents** in the nav — click through to a detail page and hit **Analyze** to run a real, bounded, evidence-gathering AI investigation against that cluster (see "AI analysis" below for what that actually does now, and how to configure a provider first; without one, Analyze returns a clear "not configured" message rather than pretending to work).

Everything the UI calls is plain JSON over HTTP on `:8080`, still fully exercised (RFC 9457 errors, auth, capability checks, the full enrollment/accept/tunnel lifecycle) in `scripts/smoke-test.sh` if you'd rather drive it from the command line — that script is the most complete, current list of what the API actually does; `retired LLD-10` describes the eventual full surface, most of which doesn't exist yet.

## What each area does, and how to configure it

The subsections below are **operational** reference: the exact env var, settings-API body, endpoint,
log line or SQL query for each area. Anything described as live-editable takes effect without a hub
restart; anything that genuinely does need one — the agent-side finding-resend cooldown under
"Detection settings" — says so.

**What each feature is and why it behaves that way is not repeated here.** That is
the [user documentation](https://argus.nubestack.com/) (behaviour, every setting, the honest limits) and
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) (the mechanisms, the state machine, the diagrams). This
file assumes you have read whichever of those you needed and now want the command.

**Running the SQL below: connect as `postgres`, never as `argus_app`.** Every table these queries touch
has `FORCE ROW LEVEL SECURITY`, and `argus_app`'s policies resolve against request-scope settings the
hub sets per transaction — a plain `psql` session has none, so the query **succeeds and returns zero
rows**. That reads as "no data" rather than as an error, which is the worst possible failure mode for a
diagnostic query. Proven on the dev stack: `SELECT count(*) FROM incidents` returns 103 as `postgres`
and `0` as `argus_app`, with no warning either way.

```
docker exec compose-postgres-1 psql -U postgres -d argus -c "<query>"
```

### Cluster node/resource status

The cluster detail page's **Nodes** section (below **Facts**) shows each node's readiness and, where available, its resource usage — closing one of the two real gaps raised in `PROJECT.md` ("Should we have cluster status, nodes, up/down, resource status?"). This uses only RBAC `argus-investigate` already had: `get`/`list` on core `nodes` (readiness, allocatable CPU/memory) and on `metrics.k8s.io`'s `pods`/`nodes` (live usage) — see `deploy/helm/argus-agent/templates/clusterrole.yaml`, unchanged by this feature.

`GET /api/v1/clusters/{id}`'s `facts.nodes` array is populated by `internal/agent.GatherFacts` and carries, per node: `name`, `ready`, `cpuAllocatable`/`memoryAllocatable` (Kubernetes `resource.Quantity` strings straight off the Node object's own `status.allocatable` — the same units `kubectl describe node` shows, e.g. `"4"`, `"16374636Ki"` — always present on any reachable cluster), and `cpuUsed`/`memoryUsed` (same Quantity-string convention, from `metrics.k8s.io`'s `NodeMetrics`). **`cpuUsed`/`memoryUsed` are omitted, not zero, on any cluster that doesn't run metrics-server** — that's the common case, not an error: the agent lists `metrics.k8s.io` best-effort and simply leaves usage fields off when that API isn't installed, exactly the same "degrade, don't fail" posture `Reachable: false` already had for a totally unreachable cluster. `facts.nodes` itself is always a real (possibly empty) JSON array, never `null` or a missing key, whether or not the cluster is reachable at all.

### Filtering incidents by state

The **Incidents** page has a state filter dropdown ("All states" plus every value `incidents.state`'s CHECK constraint allows — seventeen as of migration `000101`, since `Diagnosed`/`ExecutionUnknown`/`ValidationUnknown`/`PlanRejected`/`Expired` were each added after this line first said "twelve"; `internal/api`'s `validIncidentStates` is the list, kept honest by `TestValidIncidentStatesMatchesMigration`) — the other real gap raised in `PROJECT.md` ("Filter incidents by status"). It's backed by `GET /api/v1/incidents?state=<value>`, ANDed with the existing `?clusterId=` filter the cluster detail page already used; an unrecognized value is a `400`, and omitting `?state=` is byte-for-byte the old "every state" behavior. "All states" is the dropdown's default, so the unfiltered view stays one click away rather than curated down to some "open" subset.

### Clearing incidents raised before the promotion boundary moved

`POST /api/v1/incidents/reconcile-promotion` (`incident:triage`) closes open incidents whose *entire*
finding history is one the current evidence boundary would no longer promote. Use it after the
promotion rules tighten — migration `000092` and `internal/gateway/promotion.go` were the first such
change, and by design neither touched incidents that already existed.

**It previews by default.** A body of `{}` reports what it would close and changes nothing:

```
curl -sS -X POST "$API/api/v1/incidents/reconcile-promotion" \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" -d '{}'
```

Read the `incidents` array before applying — each entry carries the incident's state, opening reason,
how many findings it has and which reasons they were, so the verdict is checkable rather than
something to take on trust. Then:

```
curl -sS -X POST "$API/api/v1/incidents/reconcile-promotion" \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"apply": true, "note": "why you accept closing these unread"}'
```

The note is mandatory when applying, exactly as it is for dismissing one incident by hand: this
closes incidents nobody reviewed, `Dismissed` is terminal, and the reason has to be auditable
afterwards. Every closed incident id is written to `audit_events` under
`details->>'action' = 'reconcile_incident_promotion'`, and each incident gets a timeline entry keyed
`reason = "promotion_evidence_reconciliation"` — that key, not a state or a column, is how these are
told apart from a human's individual triage later:

```
SELECT incident_id FROM timeline_events WHERE payload->>'reason' = 'promotion_evidence_reconciliation';
```

Three things it deliberately does not do. It never deletes, detaches or rewrites a **finding** — the
findings are the record that the detector fired, and the response reports how many were retained so
that is checkable. It never closes an incident with **no** findings, because an empty history is not
a non-promotable one. And it **skips** incidents another writer owns (`Investigating`, `Executing`,
`AwaitingMerge`, `Validating`) rather than walking them to a closed state, reporting them as
`skippedInProgress`; re-run once they settle. One call closes at most 500 incidents (about 10 ms
each — the cost is `orchestrator.SetState`'s correlation-group recomputation, measured in
`internal/api/clusters.go`); if `truncated` is true, call it again.

### AI analysis — bring your own OpenAI-compatible endpoint

`internal/llm` talks to anything exposing an OpenAI-style `/chat/completions` endpoint — most self-hosted/open-source model servers do (Ollama, vLLM, LocalAI, llama.cpp's server, ...).

**Config is now DB-backed and live-editable, not env-var-only.** `GET`/`PUT /api/v1/admin/settings` (super-admin only — `org:settings:write`, `internal/api/settings.go`) reads/writes the single `org_settings` row (migration `000018_org_settings`) for everything except the provider itself; `internal/settings.Resolve` is called fresh on every analysis request, and its precedence rule is: **the DB row's column, if set, else the env var below, else unconfigured** — no hub restart needed to pick up a change made through the API.

**Where the provider actually lives, since it moved:** an installation can hold several providers (a metered API key, one or more CLI runners) in the `ai_providers` table (migration `000034`), one of which `org_settings.active_ai_provider_id` marks active, managed through `GET`/`POST /api/v1/admin/ai-providers`, `PUT`/`DELETE .../{id}`, `POST .../{id}/activate` and `POST .../{id}/test` (all `org:settings:write`) and through Settings' **AI providers** section. `PUT /api/v1/admin/settings`'s `llm` section is still supported and still works — it edits the **active** provider in place, and creates one named `Default` if none is active yet (`settings.UpdateActiveProvider`) — so the recipe below is unchanged, but a fleet with more than one provider configured is edited through the `ai-providers` routes, not this one.

```
ARGUS_LLM_BASE_URL=http://<your-server>/v1
ARGUS_LLM_MODEL=<model name your server serves>
ARGUS_LLM_API_KEY=<optional — many self-hosted servers don't need one>
```

These env vars are now **seed defaults**, not the only source — set them for a fresh install's out-of-the-box behavior, or leave them unset and configure everything through the web UI's Settings screen (super-admin only) or `PUT /api/v1/admin/settings` directly. `GET /api/v1/admin/settings` never returns the actual `apiKey` — only `apiKeySet: true|false` — so a client can tell whether a key is configured without ever being shown it. `PUT` distinguishes "field absent from the body" (leave the stored value unchanged) from "field present as `""`" (explicitly clear it), which is what lets the UI update `baseUrl` without needing to re-paste a secret it was never shown back.

**Analyze now runs a real, bounded, tool-calling investigation** — not a one-shot guess from raw event text. Clicking Analyze (or `POST /api/v1/incidents/{id}/analyze`) has the model decide, turn by turn, which read-only tool to call against the incident's own cluster (routed over the real mTLS tunnel to that cluster's agent, staying inside `argus-investigate`'s read-only RBAC the whole way) before it commits to a root cause. **`internal/llm/toolloop.go` is the list, not this paragraph** — it is the single source both backends' surfaces are projected from, so it cannot drift from what the model is actually offered. Today that is seven always-offered cluster tools (`get_events`, `get_logs`, `describe_resource`, `list_resources`, `get_owner_chain`, `get_gitops_ownership`, `list_nodeport_allocations`), plus four offered only when the specific incident or cluster supports them: `dry_run_patch` (only where the agent holds the opt-in `argus-dryrun` grant — the one write-capable tool, restricted to `dryRun=All`), `query_metrics` (only where `metrics.prometheusService` is configured and granted), and the two hub-side repository tools `list_repo_files`/`read_repo_file` (`internal/repotools` — these do **not** go over the tunnel, and are offered only when the incident resolves to a readable registered repository, scoped to its pinned synced commit). The loop itself is `toolloop.go`'s `Investigate`, wired in by `internal/api/analyze.go`, per `retired LLD-07` and ADR-2 (`lld/14-adrs.md`). `get_gitops_ownership` (`{gvk, namespace, name} -> {managed_by: "argocd"|"flux"|"none", app_ref?}`) checks whether Argo CD or Flux manages the object being investigated — the RBAC for it (`argoproj.io` Applications/ApplicationSets, everything under `*.toolkit.fluxcd.io`) has been in `deploy/helm/argus-agent/templates/clusterrole.yaml` since the chart was written; this is what finally reads it, closing the "kubectl fix on a GitOps-managed resource is futile" gap `the retired high-level design` §1.4 #3 calls out.

The response (and `GET /incidents/{id}`'s embedded `analysis`) is either:

- **`status: "complete"`** — `rootCause.statement` + a `confidence` (0.0–1.0), plus `causalChain` (each step's hypothesis, the tool call(s) it made, and what it found) and `ruledOut` (hypotheses considered and rejected, with why).
- **`status: "partial"`** — the model never concluded before a bound was hit (`partialReason: "iteration_limit" | "time_limit"`). `rootCause`/`confidence` are **always `null`** here — an incomplete investigation has no confidence to report, and forcing a number would be exactly the "numerology" the LLD warns against. `causalChain`/`ruledOut` are still populated with whatever real evidence was gathered before the bound hit, and `suggestedNextSteps` says what to check manually — a partial analysis is a real, useful result, not a failure response.

Both shapes also carry real token/cost accounting, populated identically whether the investigation concluded or hit a bound: `tokensBilledIn`/`tokensCacheRead`/`tokensOut` are summed across **every** model round-trip the investigation made (`retired LLD-07` §7), not just the concluding one, and `tokensCacheRead` is parsed from the standard OpenAI `prompt_tokens_details.cached_tokens` extension field when a provider reports it. `costUsd` is `0` until you configure a per-token price for your model (see "Cost tracking and a daily spend ceiling" below) — never a guessed or hardcoded per-model rate.

### Cost tracking and a daily spend ceiling

`analyses.cost_usd` used to be a hardcoded `0` everywhere, on purpose — no per-model USD pricing table existed anywhere in this codebase, and inventing one would mean putting a fabricated number in a persisted, audited table. It's now real, computed from an operator-configured price table for whichever model you set above — still an honest `0` until you configure it, never a default.

Set it via the Settings screen's **Model pricing** section, or `PUT /api/v1/admin/settings`'s `"cost"` section:

```json
{"cost": {
  "pricePerMillionInputTokens": 3.00,
  "pricePerMillionCachedTokens": 0.30,
  "pricePerMillionOutputTokens": 15.00,
  "dailySpendCeilingUsd": 25.00
}}
```

Prices are USD per **million** tokens — the same unit `the retired high-level design` §16.3's own worked cost model uses, so you can copy a number straight from your provider's published pricing page. The three price fields must be set together or left all `null` (a partial table would compute a systematically wrong cost, worse than an honest `0`) — `GET`'s `cost.pricingConfigured` tells you which state you're in. Once set, every *new* analysis gets a real `costUsd`; an analysis that ran before you configured pricing keeps its honest historical `$0.00` forever — it's never retroactively recomputed. `GET /api/v1/insights`' `costAndTokens.totalCostUsd` and the Insights page's "Total cost" tile pick this up automatically, with no query change on our end — it was always a correct `SUM(cost_usd)`, just waiting for non-zero data.

`dailySpendCeilingUsd` (`null` by default — no ceiling, today's unbounded behavior) caps how much real spend (today's `SUM(analyses.cost_usd)`, UTC calendar day) is allowed to accumulate before **`internal/autoanalyze`'s unsupervised automatic path** (the poller that investigates new incidents with no human in the loop, see "Automatic investigation" below) stops starting any further investigation — logged clearly (`autoanalyze: daily spend ceiling reached ...`) so a fleet going quiet on auto-analysis is something you can notice, not a silent no-op. It resumes on its own once spend resets (next UTC day) or you raise the ceiling — no restart needed either way. A **manual** click on "Analyze" for one specific incident is deliberately **not** blocked by this ceiling: a human explicitly asking for one investigation is a bounded, accountable action, not the kind of unattended repeated spend the ceiling exists to stop (the manual path still logs that the ceiling was breached, for the trail). If you haven't configured pricing, the ceiling check is a no-op regardless of what it's set to — cost is always `0` without a price table, so there's nothing meaningful to compare against, and pretending otherwise would look like a working control that structurally can't be one.

`GET /api/v1/spend/today` reports today's real spend and ceiling status (`{todaySpendUsd, pricingConfigured, dailySpendCeilingUsd, ceilingBreached}`) and is gated on the narrower `spend:read` capability rather than the admin-only `org:settings:write` that configures pricing/the ceiling — a resolver can see today's spend without needing full settings access. This is the first thing in this codebase that actually uses `spend:read`/`spend:manage` — both have been in `internal/authz/permissions.go`'s capability catalogue since the first authz pass, unused until now.

This is a deliberately simplified, single, org-wide ceiling, not `the retired high-level design` §16.4's full hierarchical `org ≥ tenant ≥ cluster ≥ policy` budget structure, and there's no 50/80/95% warning-notification tier or spend-rate anomaly detection yet — this codebase's confirmed single-org scope has no other use for a per-tenant/per-cluster budget today, and both are real, named gaps rather than something silently dropped.

If the target cluster has no live agent connection right now, analysis fails fast with a clear `503` rather than running a doomed investigation loop to the end of its budget. The iteration cap (default 8 model round-trips) and wall-clock cap (default 3 minutes) are judgment calls, not LLD-pinned numbers. **These two bounds are now DB-backed and live-editable too**, the same `org_settings`/`PUT /api/v1/admin/settings` path as the provider config above (`analysis.maxIterations`/`analysis.timeLimitSeconds`, both `number|null` — `null` means "not overridden, falling back to the env var or the hardcoded default," and `GET` also returns `analysis.effectiveMaxIterations`/`analysis.effectiveTimeLimitSeconds` so a caller can see the concrete number actually in force even while the raw field is `null`) — a change takes effect on the very next analysis, no hub restart needed. `ARGUS_ANALYSIS_MAX_ITERATIONS` / `ARGUS_ANALYSIS_TIME_LIMIT_SECONDS` still work exactly as before as the seed default a null DB column falls back to.

One deliberate MVP simplification worth knowing about: every tool call's result is stored inline inside `causalChain` (in the `analyses.causal_chain` column), not in the separate object-store-backed `evidence` table `retired LLD-05` sketches — that table needs a MinIO client this repo doesn't have yet (see `docker-compose.yaml`'s own header comment). At a handful of tool calls per incident this costs nothing; it's not the final design.

### Remediation: the operational specifics

What the action types are, how the gate routes an incident, and what each state means:
the user documentation's [remediation actions](https://argus.nubestack.com/reference/remediation-actions/) and [incident states](https://argus.nubestack.com/reference/incident-states/), and the state machine in
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) §5. What you need at the console:

| I want to | Do this |
|---|---|
| See the queue | `GET /api/v1/approvals` (`remediation:approve`). Sorted by severity then age. |
| See what a plan would actually do, without approving | `POST /api/v1/incidents/{id}/preflight` — the same rehearsal an approval runs, returning the field-level diff the API server itself produced. **Preview change** in the UI. |
| Approve | `POST /api/v1/incidents/{id}/approve`. Additionally needs the execution capability for that action type — the route capability is necessary but not sufficient. |
| Reject | `POST /api/v1/incidents/{id}/reject`, non-empty `reason` required. → `Dismissed`. |
| Propose the fix at source instead | `POST /api/v1/incidents/{id}/repository-change` — **a set of whole-file edits, one file or many**, each carrying the file's complete new content (2026-08-28; the old `filePath`/`fieldPath`/`newValue` single-field shape was deleted, `PROJECT.md` F22). Needs `repo:write` + `remediation:approve` + `remediation:execute:pr`. Check the handler for the current field names before scripting against it — this row is a pointer, not a schema. |
| Change the autonomy policy | `PUT /api/v1/admin/settings`, `autonomy` section (migration `000028`). `GET` returns `effective*` so you can see what is actually in force. Live — no restart. |
| See what actually executed | `SELECT * FROM remediation_executions ORDER BY executed_at DESC` — outcome, error, the `resourceVersion` precondition used, and whether it was unattended. |
| See why an approval was refused | The 4xx body carries the real reason. A guardrail refusal is a `409` with its own problem `type`, so the UI can offer the matching confirmation rather than string-matching a message. |

**Two guardrails refuse an approval and ask for confirmation**, each with a **single-use token bound to
that specific refusal**: scaling a workload currently at zero, and patching an object a GitOps
controller owns. Confirming is a second, deliberate approve call carrying that token; the confirmation
is recorded in the audit trail, and — importantly for debugging — the audit records the *redeemed*
value, not what the client claimed, so a stale or absent token reads as `false` however the request was
formed.

**The hard safety floor cannot be configured away.** A high-risk, irreversible plan always needs a
human; that check runs before any policy field is consulted.
`TestResolveAutonomyPolicyCannotWeakenSafetyFloor` proves it by resolving the most permissive policy
this settings path can express and confirming such a plan still comes back `NeedsApproval`.

### Unattended execution — the operational specifics

What it is, the four bounds, and what enabling it accepts:
[Unattended execution](https://argus.nubestack.com/automation/unattended-execution/). Off by default (migration `000046`).

```json
{"autonomy": {"unattendedExecutionEnabled": true,
              "maxUnattendedPerCluster": 3, "maxUnattendedFleetWide": 10,
              "unattendedWindowSeconds": 3600}}
```

**Where to look when something changed and nobody knows why** — this is the reason this subsection
exists at all:

- **Startup**: `api: UNATTENDED EXECUTION IS ENABLED — …` with the resolved caps, or
  `api: unattended execution disabled — every remediation requires a human approval`. Whether this is
  on is visible in the first place an operator looks.
- **Per execution**: `unattended: incident … executed without human approval, now Validating`.
- **Per refusal**: `unattended: incident … not executed: <reason>` — including the blast-radius
  message with the real counts, so a cap that tripped says which one and why.
- **In the database**: `SELECT * FROM remediation_executions WHERE unattended ORDER BY executed_at DESC`.
  The decision behind each one is in `remediation_approval_decisions` with `actor_id IS NULL`,
  `unattended = true`, and the gate's verdict plus the blast-radius numbers as its `reason`.
- **In the audit log**: `actor_auth_method = 'policy'`, no actor, no source IP — because no request
  reached the hub and recording one would be a fiction.

A `0` in any cap is **rejected** with an explanation rather than read as "unconfigured"; so is a
per-cluster cap above the fleet-wide one, which could never take effect.

### Automatic investigation — the operational specifics

What it is and what bounds its cost: [Automatic investigation](https://argus.nubestack.com/automation/automatic-investigation/). Off by default.

```json
{"automation": {"autoAnalysisEnabled": true, "autoAnalysisSeverities": ["high", "critical"]}}
```

Four things that surprise people, all of them deliberate:

- **`autoAnalysisEnabled: true` with an empty severity list analyses nothing**, not everything. A blank
  checklist reads as "nothing chosen yet", and the safe reading of that is to do nothing.
- **The list is a checklist, not a floor.** `["medium"]` alone is valid, with the *more* severe
  `high`/`critical` untouched — a selection no "at or above this threshold" setting could express.
- **`medium` is added to any non-empty selection you make** (`autoanalyze.widenForCostGatedMedium`,
  `PROJECT.md` T1, 2026-09-04), so a checklist of `["high", "critical"]` will in fact also investigate
  `medium` incidents. It is reached only after the sweep's daily-spend-ceiling check has already
  cleared, which is the intended control on the extra volume — not the severities picker. Two things
  it never does: it never touches `low`, and it never widens an **empty** selection (the previous
  bullet's "nothing chosen" state still means nothing). It also never writes back to `org_settings`,
  so `GET /api/v1/admin/settings` keeps showing what you actually ticked, which is exactly why this
  surprises people.
- **Each incident is automatically attempted at most once, ever** — whether that attempt concluded, came
  back partial, or failed outright because no AI provider was configured. Nothing clears the flag. A
  person can always still run `POST /api/v1/incidents/{id}/analyze` manually, which is what makes that
  simple rule a reasonable trade rather than a trap.

Both fields are re-read every poll tick (15s, `autoanalyze.DefaultPollInterval`), so a settings change
takes effect within one tick. An incident is skipped — not burned — if its cluster has no live tunnel,
and retried on a later tick once it reconnects.

**The stale-object sweeper shares this poller and is NOT gated on the setting above.** It runs every
10 minutes regardless, closing incidents whose object the cluster reports as definitively gone
(`autoanalyze: incident … resolved from <state> — <object> no longer exists (nothing to act on)`).
See [The incident lifecycle](https://argus.nubestack.com/incidents/lifecycle/) for why, and what it deliberately will not close.

### Notifications — a webhook per new incident

`internal/notify` is a deliberately small first slice of `the retired high-level design` §13 (alerting and notifications): no digests, no per-tenant routing rules, no per-user preferences, no interactive Slack callbacks/approval buttons — just "a new incident happened, POST it to a webhook."

**Config is now DB-backed and live-editable too**, via the same `org_settings` row and the same `GET`/`PUT /api/v1/admin/settings` API as the AI provider above — set/change the webhook URL live, no restart needed:

```
ARGUS_NOTIFY_WEBHOOK_URL=https://hooks.slack.com/services/...   # or any plain webhook receiver
```

— now a seed default, per `internal/settings.Resolve`'s same DB-overrides-env precedence rule. Treat this URL as a secret, not just a plain endpoint: a Slack incoming-webhook URL embeds a bearer-equivalent token in its path, so `GET /api/v1/admin/settings` returns only `webhookConfigured: true|false`, never the URL itself.

Nothing configured (neither the DB row nor the env var) means each sweep tick is simply a no-op — no crash, no error, just no notifications, and the poller itself always runs regardless (whether it has anything to do is now resolved per tick, not decided once at startup). When configured, a background poller (`internal/notify.WebhookNotifier`, the same architectural shape as `internal/gateway/health.go`'s `HealthMonitor`) checks every 30s (`notify.DefaultNotifyCheckInterval`) for incidents with `notified_at IS NULL`, POSTs a `{"text": "..."}` body (Slack's incoming-webhook shape — plain enough for a generic receiver too) describing each one (cluster id, fingerprint, severity, first seen), and marks it notified only on a 2xx response. A failed POST leaves `notified_at` NULL so the next sweep retries it — a webhook outage or typo'd URL never permanently drops a notification, and never stops the poller from moving on to other incidents in the same batch.

### Data retention and partitioning

`findings`, `incidents`, and `audit_events` were always declared `PARTITION BY RANGE` (`internal/migrations/000004`/`000005`/`000008`), but until now nothing ever actually created a dated partition — every row of all three, since this project began, landed in that table's `_default` catch-all partition, silently defeating the entire point of partitioning (flat query performance as history grows, and cheap, instant retention via `DROP TABLE` instead of a slow row-by-row `DELETE`). `internal/partition.Maintainer` fixes this: a daily background job (same architectural shape as `internal/gateway/health.go`'s `HealthMonitor` and `internal/notify.WebhookNotifier`, wired into `cmd/hub/main.go`'s `runAPI`) that:

1. **Ensures the current month's and next month's partition exist** for each of the three tables — `CREATE TABLE IF NOT EXISTS ... PARTITION OF ... FOR VALUES FROM (...) TO (...)`, so a burst of inserts around a month boundary never has to wait on a just-in-time create. Because it also covers the *current* month, the very first run after upgrading onto this is a genuine catch-up, not just "starts working from tomorrow" — see `retired LLD-12` §9's reasoning for why monthly, not daily or weekly, is the right period at this project's realistic scale.
2. **Drops whole partitions past a configured retention window — only where one is explicitly set.** Retention is per data type, configured in days via `PUT /api/v1/admin/settings`'s `retention` section (`auditRetentionDays`/`incidentRetentionDays`/`findingRetentionDays`, migration `000021_retention_settings`) and — this is the important safety property — **every one of the three defaults to `null`, meaning "keep forever," and this platform never silently starts deleting anything just because it was upgraded.** An operator has to explicitly opt in to a retention window (e.g. "keep audit logs for one year" → `auditRetentionDays: 365`) before this job ever drops so much as one partition of that table.

**Explicitly out of scope for this job:** migrating the years of historical rows already sitting in each table's `_default` partition into real dated partitions. That's a real, separate, live-data migration concern (moving rows on a table with `FORCE ROW LEVEL SECURITY`, at whatever size `_default` has grown to) — flagged in `PROJECT.md`, not silently attempted here. This job only affects new writes going forward and never touches `_default`'s existing rows.

**How much storage does this actually need?** `the retired high-level design` §17.5 already covers a 1,000-cluster deployment; `retired LLD-12` §9 is the honest, explicitly-assumption-stated equivalent for the much more common 5–20–100-cluster range — short answer, at that scale storage is not the constraint (a few hundred MB even after a full year of history at every default), and partitioning's real payoff there is query-plan stability and cheap retention, not disk savings.

### Detection settings — per-detector enable/disable and storm protection

`retired LLD-06` specs a much fuller detection layer — a `RemediationPolicy` CRD, a cluster-side controller, occurrence-aggregation dedup, and cross-policy precedence resolution — none of which exists here; that's real, separate, cluster-side controller infrastructure, a bigger lift than what this section covers. What *does* exist now, closing the concrete pain point the two hardcoded detectors caused (PROJECT.md's Phase 1 row flagged this repeatedly), is a first, deliberately-scoped, **hub-side** slice: two new `PUT /api/v1/admin/settings` `detection`-section controls, both enforced inside `internal/gateway/finding.go`'s `handleFinding`, both fully live the moment they're saved — no agent or hub restart.

- **Per-detector enable/disable** (`disabledDetectorIds: string[]` — three detector IDs exist: `k8s-warning-events`, `k8s-pod-conditions` and `k8s-sweep`, the last of which carries the declarative rule engine *and* every kind-agnostic predicate (`internal/agent/generic_predicates.go` — six today: conditions, `generation`-vs-`observedGeneration` lag, `deletionTimestamp`/stuck-finalizer age, dangling reference, peer outlier, admission-policy type checking), so disabling it is much broader than the other two; an independent per-rule `disabledRuleIds` exists for that reason, `PROJECT.md` 111): **this is a hub-side filter, not a switch the agent sees.** There is no hub-to-agent config-push mechanism in `internal/tunnel`'s protocol today (`internal/tunnel/protocol.go`: `ClientMessage` carries `Heartbeat`/`InventoryDelta`/`Finding`/`ToolResult` agent→hub, `ServerMessage` carries `Ack`/`Error`/`ToolRequest` hub→agent — still nothing shaped like a config push in either direction), so "disabling a detector" can only mean the hub drops what it already received before it's ever recorded or becomes an incident — the agent itself keeps running that detector and keeps sending its findings exactly as before. Genuinely live, though: re-resolved fresh on every `Finding` the hub receives.
- **Storm protection** (`stormProtectionMaxNewIncidents`/`stormProtectionWindowSeconds`, both `number|null`, set together or cleared together): caps how many brand-new (never-before-seen-fingerprint) incidents a single cluster may open within a rolling window — a real ceiling on a flood of *distinct* new problems, not the same-fingerprint dedup `handleFinding`'s correlation rule already did. Once a cluster hits the ceiling, a finding that would have opened yet another new incident is still recorded (its `findings.incident_id` is left `NULL` — "arrived, not correlated," never silently dropped), but no new incident is created for the rest of the window; an already-open incident sharing that finding's fingerprint keeps updating completely normally the whole time, since only *new*-incident creation is throttled. Every suppression is logged (`log.Printf`) and recorded as a real `audit_events` row (`internal/audit`, `event: "storm_protection_suppressed_new_incident"`) — visible, never silent. Both fields default to `null` ("no ceiling," today's unchanged behavior) — opt-in, the same safety posture retention's `null`-means-forever default already established, rather than a new default that could silently start suppressing incidents on an unrelated upgrade.

**What still needs an agent restart, and why:** the third hardcoded knob this task closes — `findingResendCooldown`, the per-fingerprint resend-dedup window (`internal/agent/detector.go`, default 5 minutes) — is deliberately **not** part of `PUT /api/v1/admin/settings`. It's enforced entirely inside the agent's own process, which has no path to receive a hub-pushed config change (the same protocol gap above); exposing it as a hub "live-editable" setting would be a control that silently did nothing until the agent's next restart, which is exactly the kind of overclaiming this project's honesty norms (see PROJECT.md's many "not done, deliberately" notes) exist to avoid. Instead it's a real, working, but agent-side, restart-required environment variable: `ARGUS_FINDING_RESEND_COOLDOWN_SECONDS` (positive integer seconds; unset/invalid falls back to the 5-minute default), read once by `cmd/agent/main.go` at startup.

Migration `000026_detection_settings` adds `disabled_detector_ids`/`storm_protection_max_new_incidents`/`storm_protection_window_seconds` to `org_settings`; `internal/settings.Config`/`Resolve`/`Update` follow the exact same DB-row-first, no-env-var-tier pattern the retention/automation fields already use. The web UI's Settings screen has a **Detectors** section (`SettingsPage.tsx`'s `SETTINGS_SECTIONS` — a grouped list down the left, not tabs across the top) exposing all of this, including an explanatory note for the cooldown env var above (a read-only note, not a form field — it isn't live, so it doesn't get a live-looking control).

**Dry-run against history** (`POST /api/v1/detection/dry-run`, same `org:settings:write` capability as the section above): `retired LLD-11` §3 names a `PolicyEditor` component with a "dry-run-against-history" feature for `RemediationPolicy` authoring — no `RemediationPolicy` exists yet, so this endpoint applies the same idea to the two real controls above instead. The request body is a *candidate* `detection` section — identical shape to the `PUT` above, never saved — replayed against a bounded window (`?days=`, default 7, max 90) of real `findings`/`incidents` history. It calls `internal/gateway`'s exported `IsDetectorDisabled`/`StormProtectionConfigured`/`StormProtectionWindowStart`/`StormProtectionShouldSuppress` — the exact functions `handleFinding` uses on the live path, not a second, independently-written copy that could silently drift — and reports, per cluster/detector: how many recorded findings would now be filtered by the candidate's `disabledDetectorIds`, and of the new-incident decisions still eligible for storm protection, how many that were actually created would now be suppressed (or vice versa) under the candidate's ceiling. Pure simulation: it never writes to `org_settings` or anywhere else, and never contacts a live cluster. The Settings screen's **Detectors** section gets a "Preview against history" button that sends whatever is currently entered in the form — before it's saved — and renders the result inline.

### User and grant management

The **Users** screen (`/users`, `UsersPage.tsx` — gated by `user:read`, granted to `super-admin`/`tenant-admin` only) is the admin console for creating users and assigning/revoking role grants; `internal/api/users.go` backs it with `GET`/`POST /api/v1/users` and `POST`/`DELETE /api/v1/users/{id}/grants(/{grantId})`, all gated by `user:read`/`user:manage` (`internal/authz/permissions.go`'s catalogue already declared both, nothing implemented them until now).

Creating a user generates a one-time, high-entropy temporary password shown exactly once in the response (never logged, never returned again by `GET /users`) — the same "shown once" discipline `POST /clusters/enrollment-tokens` already uses for its own secret — with `mustChangePassword` forced `true`, reusing the existing local-login/forced-change mechanism rather than an email-invite flow. A grant assigns a role — one of the 4 builtin roles (`super-admin`/`tenant-admin`/`resolver`/`viewer`) **or a custom role**, since custom-role authoring now exists (`internal/api/custom_roles.go`, `GET`/`POST /api/v1/custom-roles` and `PUT`/`DELETE .../{id}`; `authz.ResolveRoleCapabilities` tries a custom role after a builtin one). There is still no *second* assignment mechanism and no ad hoc capability-set grant: a custom role is granted through this same `POST /users/{id}/grants`, and a grant row only ever stores a `role_id`. Scope is `AllClusters`, a single already-enrolled cluster, **or `ClusterGroup`** — that scope type used to be rejected here precisely because there was no membership to resolve it against, and there now is (`internal/api/cluster_groups.go`, `GET`/`POST /api/v1/cluster-groups` plus `POST`/`DELETE .../{id}/clusters`, resolved by `authz.AccessibleClusterIDs`). A typo'd or deleted `clusterGroupId` is rejected, not silently accepted (`clusterGroupExists`). Revoking a grant sets `revoked_at`, leaving the account itself intact with zero effective permissions; **disabling the account** (below) is the separate primitive for ending the account's own ability to be used at all.

**Disabling/enabling a user** — there is still no hard-delete endpoint, and won't be: a real `DELETE FROM users` would orphan every `audit_events.actor_id` and `grants.principal_id`/`granted_by` row pointing at that user, which is actively harmful for a product whose audit trail is supposed to be a permanent record. `users.disabled_at` (already in the schema, already read by `handleLogin`'s `WHERE ... disabled_at IS NULL` login check) is the soft-disable field this closes the loop on — until now nothing ever set it:

- **`POST /api/v1/users/{id}/disable`** (`user:manage`): sets `disabled_at = now()` and — the same session-ending mechanism `reset-password` above uses — revokes every refresh token the target holds and bumps their `token_generation`, so an already-issued, not-yet-expired access token stops working on its very next request and every login attempt with their (still-correct) password is rejected immediately, not just at natural token expiry. Rejected with `409` against an already-disabled user. A super-admin may not disable **themselves** if doing so would leave zero other active, non-disabled super-admins able to administer the system (checked only for that exact case — disabling anyone else, or a non-super-admin disabling themselves, needs no such check); rejected with `409` (`https://argus.io/errors/last-super-admin`).
- **`POST /api/v1/users/{id}/enable`** (`user:manage`): clears `disabled_at` back to `NULL`. Doesn't touch sessions — there's nothing live left to revoke (disabling already ended every session), and re-enabling isn't the security-sensitive direction disabling is. Rejected with `409` against an already-enabled user.
- **`DELETE /api/v1/users/{id}`** (`user:remove`, super-admin only): removes the user from active management/authentication without hard-deleting their historical identity. It sets `deleted_at`, also disables the account, revokes active role grants and refresh tokens, bumps `token_generation`, and hides the user from `GET /api/v1/users`. Self-removal and removing the last active super-admin are rejected with `409`.

These lifecycle actions are on `UsersPage.tsx`: each row shows an Active/Disabled status badge, a "Disable"/"Enable" action gated on `user:manage`, and a stronger "Remove user" action gated on `user:remove` (disabled-not-hidden) — destructive actions sit behind a confirm step.

**Changing/resetting a password** — until now, `mustChangePassword` nagged every affected user (`AppShell.tsx`'s banner) with no way to act on it, and there was no admin reset-password action either. Two endpoints close that:

- **`PUT /api/v1/users/me/password`** (any authenticated user, no capability needed): `{currentPassword, newPassword}`. `currentPassword` is verified against the caller's own stored hash first — deliberately true even when that "current" password is a just-issued temporary one, since skipping the check there would let anyone who ever saw the temporary password set their own new one even after the real owner already changed it. `newPassword` needs to be at least `authz.MinPasswordLength` (12) characters — a length floor, not a character-class rules engine. On success it updates the hash, clears `mustChangePassword`, and returns a fresh access/refresh token pair (same shape as login) — the caller swaps these in and keeps working with no forced logout, while **every other outstanding session for that user (every other refresh token, and every access token via a bumped `token_generation`) is ended immediately.**
- **`POST /api/v1/users/{id}/reset-password`** (`user:manage`): generates a fresh high-entropy temporary password with the exact same `generateTemporaryPassword` `handleCreateUser` already uses, forces `mustChangePassword` back to `true`, and — the actual point of a reset — ends every session the target currently holds (their refresh tokens revoked, their `token_generation` bumped so any live access token stops working on its very next request, not just at its natural 15-minute expiry). Returns the new temporary password exactly once, in the same one-shot shape `handleCreateUser`'s own response already uses.

Both are on `UsersPage.tsx`: the account-area "Change password" button and the `mustChangePassword` banner's own new action both open the same `ChangePasswordModal`; each user row gets a "Reset password" action gated on `user:manage` (disabled-not-hidden) behind a confirm step, revealing the new temporary password through the same one-time-reveal pattern `CreateUserModal`'s result panel already established. Neither endpoint ever logs, audits, or returns the old or new password anywhere but that one response — `audit.RecordEvent` records only that a change/reset happened and by whom (`action: "change_password"` / `"reset_password"`).

A stateless JWT access token can't normally be revoked mid-lifetime without a server-side blocklist; rather than add one, `users.token_generation` (migration `000023`) is a monotonic counter embedded in every access token's `gen` claim at issuance — `requireAuth` rejects any token whose `gen` doesn't match the user's current value. A password change/reset bumps it, which is what makes "immediately," not "within 15 minutes," actually true.

### Audit log

The **Audit log** screen (`/audit-log`, `AuditLogPage.tsx` — gated by `audit:read`, `super-admin` only, deliberately excluded even from `tenant-admin` per `internal/authz/permissions.go`'s explicit comment) is the first way to actually *read* the hash-chained `audit_events` table from the UI, short of `psql` or the standalone `argusctl audit verify` tool (below) — those two remain a genuinely separate, additive capability, not something this screen replaces: `argusctl audit verify` proves the chain hasn't been tampered with and deliberately runs outside the hub for that reason, while this screen just lists/reads rows through the hub's normal capability-gated request path, the same as every other "list X" screen.

`internal/api/audit.go` backs it with `GET /api/v1/audit-events` (filterable by `actor` — a substring match on the actor's email/display name, or an exact `actor_id`; `capability` — exact match, this schema's existing name for "the action taken"; `since`/`until` — RFC 3339, inclusive; and paginated via `limit`/`cursor`, a keyset scheme rather than `limit`/`offset` because this table, unlike the small `users` list above, is append-only and can grow unbounded) and `GET /api/v1/audit-events/{id}` for one row's full record (structured `details`/`scope` JSON plus its own `prevHash`/`hash`, so an admin can eyeball one row's chain linkage inline). List rows carry a short `detailsSummary` string rather than the raw `details` blob — its shape varies per write path (a settings PUT records different fields than a cluster accept), so the full structured version is only in the detail endpoint, mirroring the `Incident`/`IncidentDetail` split elsewhere in this API. This is read-only by design — no edit or delete of any kind exists anywhere in this path, since the entire point of a hash chain is that it's append-only and tamper-evident.

### Reading the hub's logs, and reconstructing one investigation

The hub logs **one JSON object per line** through `log/slog` (`internal/logging`). Two environment
variables control it, both set in `deploy/compose/docker-compose.yaml` and
`deploy/helm/argus-hub/values.yaml`:

| Variable | Values | Default | What it changes |
|---|---|---|---|
| `ARGUS_LOG_LEVEL` | `debug` / `info` / `warn` / `error` | `info` | `debug` adds one line per model round trip and one per tunnel tool call |
| `ARGUS_LOG_FORMAT` | `json` / `text` | `json` | `text` for a human tailing a local hub; a support bundle is only useful as `json` |

An unrecognised value for either is ignored and the default used — a typo in a log setting never
stops a hub from starting.

Four attributes are fixed and mean the same thing everywhere they appear: `incident_id`,
`cluster_id`, `actor_id`, `request_id`. `component` names the subsystem (`api`, `gateway`,
`autoanalyze`, `orchestrator`, `llm`, ...).

**`request_id` is the correlation id**, and it is the one thing to ask a reporter for. Every response
carries it in the `X-Request-Id` header, and every RFC 9457 error body carries it as a `requestId`
member, so "quote the requestId from the error you saw" is a complete question. It is minted per HTTP
request and per background unit of work (one sweep tick; one *investigation* for the auto-analysis
poller, since a tick investigates a whole wave of fleet-correlated siblings at once and a tick-level
id would interleave their trails).

To reconstruct one investigation end to end, with the hub at `ARGUS_LOG_LEVEL=debug`:

```bash
# The operator quotes req_01m39anw81gznqe0qm0advyw1b from the UI or an error body.
docker compose -f deploy/compose/docker-compose.yaml logs hub-api \
  | grep req_01m39anw81gznqe0qm0advyw1b
```

which yields the whole trail in order — every model round trip with its token counts, every tool call
over the tunnel with its outcome and duration, the analysis that was written, and the request's own
completion with its status and latency (a `202`, logged as soon as the run is claimed — the
investigation then runs in the background under the same request id):

```
INFO  api      http request           {"method":"POST","route":"POST /api/v1/incidents/{id}/analyze","status":202,...}
DEBUG gateway  tunnel tool call       {"cluster_id":"cl_...","tool":"get_events","outcome":"success","duration_ms":2}
DEBUG llm      model round trip       {"model":"...","round":2,"tool_calls_requested":1,"tokens_in":50,...}
INFO  api      investigation complete {"incident_id":"inc_...","analysis_id":"an_...","iterations":4,...}
```

Going the other way — from a stored analysis back to its run — `analyses.request_id` (migration
`000117`) holds the same id, so `SELECT request_id FROM analyses WHERE id = 'an_...'` gives you the
string to grep for. It is `NULL` for any analysis written before that migration; that absence means
"predates request correlation", never "the trail is missing".

Two things worth knowing before you go looking:

- **Not every call site is converted yet.** A line carrying `"unstructured": true` came through the
  standard-library `log` bridge: it is still JSON, still levelled, still redacted, but it has no
  fields and *no `request_id`*, so it will not appear in the grep above. `internal/api`'s auth,
  user-management and admin-CRUD handlers are the bulk of what is still in that state.
- **Log output is redacted.** `internal/redact`'s pattern layer runs over every message and every
  attribute value on the way out (`internal/logging`'s handler), so a credential the hub formatted
  into an error string does not reach the bundle. It is a pattern filter and cannot tell
  documentation from a real header, so an instructional line containing something that *looks* like
  a credential will come out with `[REDACTED]` in it. That is the filter working.

### Insights

`GET /api/v1/insights` (gated by **both** `incident:read` and `analysis:read` — the response genuinely reads both capabilities' tables) is a single, read-only, fleet-wide reporting endpoint — `the retired high-level design` §15.1's "Insights" screen, the last of its ten named screens that had no UI at all before this. Everything it returns is real SQL aggregation (`GROUP BY`/`COUNT`/`SUM`/`AVG`, computed by Postgres, never a full-table fetch summed in Go) over `incidents`/`findings`/`analyses`:

- **Recurring issue classes** — incidents grouped by their exact `fingerprint` (namespace/kind/object name/reason, all hashed together — see `internal/agent/detector.go`'s `computeFingerprint`) across the whole visible history, ranked by how many distinct incidents and clusters share one signature. A fingerprint spanning more than one cluster is genuinely "the same problem, more than one cluster" — the fleet-wide pattern a single cluster's own incident list can't show.
- **Top noisy namespaces** — `findings` grouped by namespace, ranked by raw finding volume.
- **Investigation outcomes** — what fraction of every `analyses` row ever written reached a confident conclusion (`complete`) versus hit an iteration/time bound first (`partial`), plus the average number of tool-calling iterations a real investigation takes.
- **Cost and tokens per investigation** — real averages over `tokens_billed_in`/`tokens_cache_read`/`tokens_out`, a 14-day daily trend, and a `totalCostUsd` that's a real, non-zero dollar figure once you've configured per-token pricing (see "Cost tracking and a daily spend ceiling" above) — `0` and honest until then, with a `costTrackingNote` saying so, never a fabricated number.

**Deliberately not built, and said so in the response itself** (`notBuilt: [...]`), rather than faked: a confidence **calibration curve** and per-issue-class **autonomy readiness**, both from `the retired high-level design` §15.1's fuller vision for this screen. Both need real data this codebase doesn't have yet — shadow-mode calibration history for the first, real human approve/reject decisions for the second (the approval queue itself only just exists) — building either from what's on hand today would mean charting self-reported model confidence as if it were a verified probability, exactly what this project's calibration design (D10) says never to ship.

The **Insights** page (`InsightsPage.tsx`) renders all of the above using this app's existing hand-rolled-SVG/CSS chart conventions (`OverviewPage.tsx`'s stat tiles and day-bucketed bar chart, plus a new horizontal ranked-bar list for noisy namespaces) — no charting library. **It is wired into the nav** — `/insights`, routed in `web/src/App.tsx` and listed in `AppShell.tsx`'s `RECORD_NAV_ITEMS` alongside Audit Log, the "looking back, not working" group rather than the day-to-day one. (This line said "not yet wired into the nav" long after it was.)

### Exercising federated login locally (`PROJECT.md` S2)

The SSO implementation has **not** been run against a live identity provider — everything so far is
unit tests plus a discovery probe. This is the cheapest way to actually close that gap, and it is
what a live verification of S2 would need to do.

Run Dex as the provider. It is the same broker a customer with LDAP or SAML would put in front of
ARGUS, so exercising it here exercises the real path rather than a special case:

```bash
cat > /tmp/dex.yaml <<'EOF'
issuer: http://localhost:5556/dex
storage: {type: memory}
web: {http: 0.0.0.0:5556}
staticClients:
  - id: argus
    secret: argus-dev-secret
    redirectURIs: ['http://localhost:8080/api/v1/auth/sso/callback']
    name: ARGUS
enablePasswordDB: true
staticPasswords:
  # password: "password" (bcrypt)
  - email: sre@example.com
    hash: '$2a$10$2b2cU8CPhOTaGrs1HRQuAueS7JTT5ZHsHSzYiFPm1leZck7Mc8T4W'
    username: sre
    userID: 08a8684b-db88-4b73-90a9-3cd1661f5466
EOF
docker run --rm -p 5556:5556 -v /tmp/dex.yaml:/etc/dex/config.yaml \
  ghcr.io/dexidp/dex:v2.41.1 dex serve /etc/dex/config.yaml
```

Then register it. `identity:manage` is super-admin only, so use the bootstrap account's token:

```bash
curl -sS -X POST localhost:8080/api/v1/admin/identity-providers \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' -d '{
    "displayName": "Dex (local)",
    "issuer": "http://localhost:5556/dex",
    "clientId": "argus",
    "clientSecret": "argus-dev-secret",
    "redirectUri": "http://localhost:8080/api/v1/auth/sso/callback",
    "groupsClaim": "groups",
    "enabled": true
  }'
```

Two things that will bite, both checked and reported by the API rather than left to fail later: the
issuer must **not** have a trailing slash (it is compared byte-for-byte against Dex's own discovery
document), and `enabled: true` triggers a discovery probe — so if Dex is not up yet, the save is
refused.

Map a group to a role, then sign in at `/login` and use the new button:

```bash
curl -sS -X POST localhost:8080/api/v1/admin/identity-providers/$IDP_ID/group-mappings \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"groupName": "platform-sre", "roleId": "resolver"}'
```

**What a real verification has to check, beyond "the login worked":**

- A federated user row appears with `idp_issuer`/`idp_subject` set and `password_hash` NULL.
- Their grant has `source = 'idp_sync'` and `granted_by` naming the mapping id.
- Removing the group at the provider and signing in again **revokes** that grant, while a
  `source = 'manual'` grant on the same user survives untouched. This is the half that makes group
  mapping worth having, and the half a happy-path test misses.
- A password login by a non-super-admin is refused with `sso-required` while the bootstrap
  super-admin's password still works — the break-glass rule.
- Replaying the callback URL a second time fails: the handoff code is single-use.

Note the frontend is embedded via `go:embed`, so the login button will not appear until the hub is
rebuilt — `npm run build` alone changes nothing a browser sees.

## Backup, restore, and disaster recovery

ARGUS does not ship a backup tool of its own — Postgres already has one. The one convenience is the
hub chart's optional `postgres.bundled.backup` (off by default): a CronJob that runs plain `pg_dump -Fc`
and `pg_dumpall --roles-only` against the *bundled* Postgres into a PVC, keeping the newest
`retention` of each. It is a floor for a bundled install, not the production path — same cluster,
usually the same storage, no WAL archiving, so a restore loses everything since the last run.
External/managed Postgres with its own backup policy is the production path
(`docs/INSTALL.md`, "Storage"). What this section owns is the part that
is *specific to ARGUS*: what else besides the database has to come back with it, and **exactly what
stops working when you restore from a point before the hub's current key material** — because the hub
keeps its signing keys, its CA and its secret-encryption key *in the database itself*
(`signing_keys`, `internal/migrations/000016_signing_keys.up.sql`), so "restore the database" and
"roll the hub's entire cryptographic identity back in time" are the same operation, whether or not
you meant them to be.

### The five things in `signing_keys`, and what each one holds up

Every row is written once, on the first `hub api` start that finds it missing, by
`internal/data.LoadOrCreateSigningKey`. None of them is ever rotated by any code path in this repo.

| `purpose` | What it is | What depends on it |
|---|---|---|
| `jwt` | ES256 private key | Access-token signatures (`internal/authz/jwt.go`). 15-minute TTL, so the blast radius is one token lifetime. |
| `enrollment` | HMAC-SHA256 key | Enrollment-token signatures (`internal/authz/enrollment.go`). |
| `dev_ca_root` | EC private key **plus the exact certificate bytes** | The gateway's own TLS server cert, every enrolled cluster's leaf cert, and the `ClientCAs` pool the mTLS handshake checks against (`internal/gateway/devca.go`). |
| `plan_signing_key_root` | HMAC root key | Every per-cluster remediation plan signing key, `HKDF(root, clusterID)` (`internal/remediation.DeriveClusterSigningKey`), handed to an agent once at enroll time and kept by the agent from then on. |
| `secret_kek_local_v1` | AES-256 KEK | Wraps the per-secret DEK for every envelope-encrypted secret — today the Git provider token (`internal/secretbox`). |

Two things are deliberately **not** in that list, and knowing so saves a wrong diagnosis later:
refresh tokens are opaque random strings hashed into `refresh_tokens`, not signed by anything; and the
`audit_events` hash chain is keyless SHA-256 (`internal/audit.ComputeHash`). Neither is affected by key
material at all. Both are still affected by a restore, for a different reason — see below.

### What to back up

**1. The database.** Everything the hub knows is in Postgres — including all five keys above. There is
no hub-side state outside it: the web UI is compiled into the binary with `go:embed`, the hub chart
mounts no volume into the hub Pod at all (the only claim it can create belongs to the bundled
Postgres StatefulSet — `deploy/helm/argus-hub/templates/postgres.yaml`), and the only compose volume
is `argus-postgres-data`.

```
pg_dump -U postgres -d argus -Fc -f argus-$(date +%F).dump
```

**2. The Postgres *roles*, separately.** `argus_app` is a cluster-global object, so a per-database
dump does not contain it, and the dump's `GRANT ... TO argus_app` statements fail without it. Restoring
a database-only dump into a fresh Postgres gives you a `pg_restore` that exits non-zero with one error
per grant — while restoring every table and every row perfectly, so the data looks fine and the hub
cannot read any of it.

```
pg_dumpall -U postgres --roles-only -f argus-roles-$(date +%F).sql
```

**`hub migrate` does not repair this.** Migration `000009` is what creates `argus_app` and grants it
everything, and it is already recorded as applied in the restored database, so `hub migrate` prints
`already up to date, nothing to do`, sets the role's login password from `ARGUS_APP_PASSWORD`, and
leaves the grants missing. The hub then dies on its first query with
`bootstrap: check existing organisations: ERROR: permission denied for table organisations (SQLSTATE 42501)`.
Restore the roles, or re-issue the grants by hand; do not expect the migrator to notice.

**3. The deployment inputs, which are not hub state but which a restore needs anyway.**
`ARGUS_APP_PASSWORD` (must match the password in the restored role, or re-set it with `hub migrate`),
`ARGUS_BOOTSTRAP_PASSWORD` (only ever consulted when no super-admin exists — against a restored
database, bootstrap is a no-op and the *old* admin password is the one that works),
`ARGUS_TUNNEL_PUBLIC_ENDPOINT` / `ARGUS_TUNNEL_SANS`, `ARGUS_METRICS_TOKEN`, the CLI-runner shared
token and any model credentials. Helm values or the compose env file, backed up wherever you keep those.

**4. Per-cluster agent identity, which is not yours to back up and not in this dump.** Each agent keeps
its private key, its issued leaf certificate, the CA it pinned, the hub endpoint, its plan signing key,
its cluster id and its fingerprint in the `argus-agent-identity` Secret in `argus-system` **in its own
cluster** (`internal/agent/identity.go`, `deploy/helm/argus-agent/templates/identity-secret.yaml`). The
hub's copy of the *public* half is in the database (`clusters.issued_cert_pem`, `clusters.cert_serial`);
the agent's private key exists nowhere else in the world. A hub backup does not protect it, and a hub
restore does not restore it — which is precisely why the mismatch cases below are the interesting ones.

If you run the bundled Postgres from the hub chart, note `postgres.bundled.persistence.enabled`
(default `true`): turned off, the StatefulSet's data is an `emptyDir` and a pod restart destroys the
database *and every key in it*, which is not a restore scenario but produces the same consequences.

### Restoring

Order matters: roles into the *cluster* first, then the database, then start the hub.

```
psql -U postgres -d postgres -f argus-roles-YYYY-MM-DD.sql     # 1. roles, before anything references them
createdb -U postgres argus                                      # 2. an empty target
pg_restore -U postgres -d argus argus-YYYY-MM-DD.dump           # 3. expect exit 0 and zero errors
argusctl audit verify --database-url "postgres://postgres:...@host:5432/argus?sslmode=disable"
```

Then start the hub and **read its first five log lines**, which are the one cheap signal that the
restore brought the key material with it:

```
loaded the persisted JWT signing key
loaded the persisted enrollment token signing key
loaded the persisted dev CA root
loaded the persisted remediation plan signing root key
loaded the persisted secret-encryption key
```

If any of those says `generated and persisted a new ...` instead, `signing_keys` did not come back —
the hub has just minted a brand-new cryptographic identity, and every consequence in the next section
has happened to your live fleet rather than to a backup.

### The bundled Postgres's pre-upgrade dump (Helm)

The hub chart takes no scheduled backups. Before every `helm upgrade` a hook Job, scheduled onto the
Postgres pod's node, writes a verified `pg_dump -Fc` to `backups/argus-<UTC timestamp>.dump` on the
database's own volume (beside `pgdata/`) and keeps the newest `postgres.bundled.backup.keep` (2).
**Every dump holds all five keys above.** Restoring it to roll an upgrade back is `docs/INSTALL.md`
("Rolling back an upgrade"); the consequences below apply to it like to any restore.

### What breaks on a restore from before the current key material

Not "some things may break." These, specifically.

**Access tokens: only the ones signed by the restored `jwt` key verify.** Any access token minted
between the backup point and the restore is rejected — `401` on every route, immediately. Tokens minted
before the backup point keep working for the remainder of their 15-minute `AccessTokenTTL`. This is the
smallest of the consequences and self-healing.

**Sessions are *not* terminated, and that is the surprise.** Refresh tokens are opaque random strings;
only their SHA-256 is stored, and no key signs them (`internal/authz/session.go`). So a browser holding
a refresh token from before the backup point silently exchanges it for a fresh access token and the user
never notices a key change happened. Three consequences follow from the same fact:

- A refresh token issued *after* the backup point has no row to match and fails with
  `refresh token not recognized` (`401`). Those users must log in again.
- **A refresh token that was already rotated and revoked after the backup point comes back
  unrevoked**, and is accepted again. `revoked_at`, `replaced_by` and the whole reuse-detection state
  are ordinary rows in `refresh_tokens`, so a restore rewinds them with everything else. If a stolen
  refresh token was detected and its family killed in the window you are rolling back over, that kill
  is undone. **After any restore, revoke sessions explicitly rather than assuming the rollback is
  security-neutral.**
- `token_generation` (the counter a password change bumps to kill outstanding access tokens,
  `internal/authz/jwt.go`) is a `users` column, so a post-backup password change is also rolled back —
  along with the password itself.

**Agent certificates: it depends entirely on which side of the backup point each cluster enrolled.**

- *Enrolled before the backup point:* it reconnects with nothing to do. The restored `dev_ca_root` is
  byte-for-byte the certificate the agent pinned at enrollment — `NewPersistentDevCA` deliberately
  reloads the original certificate bytes rather than re-deriving an equivalent one from the same key
  (`internal/gateway/devca.go` says why) — and `clusters.cert_serial` is in the dump, so
  `lookupClusterBySerial` finds the cluster and the mTLS tunnel comes straight back up.
- *Enrolled after the backup point (or after any key change):* it is dead, twice over, and either
  failure alone is fatal. Its leaf was signed by a CA key the restored hub no longer has, so the
  handshake fails signature verification; and even if it did not, the `clusters` row carrying its
  `cert_serial` no longer exists, so `lookupClusterBySerial` returns no match and the gateway closes
  the connection.
- **The agent will not fix itself.** `internal/agent/client.go` enrolls only when it finds *no*
  persisted identity; a rejected tunnel is an ordinary retry-forever condition, indistinguishable to
  the agent from a network blip. Recovery is manual, per affected cluster: delete the identity, issue
  a fresh enrollment token, restart the agent, and accept the cluster again in the hub.

  ```
  kubectl --context <ctx> -n argus-system delete secret argus-agent-identity
  kubectl --context <ctx> -n argus-system rollout restart deploy/argus-agent
  ```

- **The per-cluster remediation plan signing key goes with it.** It is
  `HKDF(plan_signing_key_root, clusterID)`, issued once at enroll and stored by the agent
  (`internal/remediation/sign.go`). If the root changed, an agent that kept its old derived key refuses
  every signed plan; the same re-enrollment is the repair, and until it happens the agent logs that
  `scale_deployment`/`restart_pod` will be refused.

**Enrollment tokens issued after the backup point are void, and they fail on the row, not the
signature.** `RedeemEnrollmentToken` looks the `token_id` up in `enrollment_tokens` *before* it checks
the HMAC, so a post-backup token produces `token_id ... not found` in the hub log and a `400
Enrollment token could not be redeemed` to the agent — the same generic message every other rejection
reason gets, deliberately, since the endpoint is unauthenticated. A token issued before the backup
point and still inside its TTL redeems normally. Reissue anything from the lost window; do not debug it.

**The audit hash chain stays intact and `argusctl audit verify` passes — which is exactly why it is
not a restore check.** No key is an input to it: `internal/audit.ComputeHash` is a keyless SHA-256 over
each row's own fields plus the previous row's stored hash. A restore truncates the chain back to a
prefix of itself, and a prefix of a valid chain is a valid chain, so verification is clean before and
after and the lost rows leave no trace in the table at all — the restored rows' `prev_hash` values link
across the gap perfectly, and the next event the hub writes chains onto the restored tip as if nothing
were missing. **`audit verify` proves no row was altered. It can never prove no row was lost.** If the
audit log matters for the window you are rolling back over, the only thing that recovers it is the
pre-restore database itself, so *rename* the damaged database rather than dropping it, and reconcile
`count(*)` and `max(occurred_at)` across the two before you discard anything.

**Envelope-encrypted secrets survive a whole-database restore and are destroyed by a partial one.**
Ciphertext and the KEK that opens it live in the same database, so restoring the entire dump keeps them
consistent and the Git provider token still opens. Restoring `signing_keys` *alone* into a current
database — the tempting "just get my old keys back so sessions survive" move — leaves every secret
sealed since the backup point wrapped under a KEK that is no longer there, and `internal/secretbox`'s
`Open` fails them as authentication errors that look exactly like data corruption. **Never restore
`signing_keys` on its own**, in either direction.

Finally, the ordinary data consequences, which are not key-related but are what an operator is usually
asked about first: incidents, analyses, approvals, executions, pull-request records, grants, users,
detection settings and provider settings all revert to the backup point, and any repository change
ARGUS proposed in the lost window still exists in the Git provider — the hub's memory of having
proposed it does not — no `pull_requests` row means nothing left for `internal/orchestrator`'s merge
watcher to follow, so those pull requests need closing or re-linking by hand.

## Testing

**Unit tests** (pure logic, no database required — password hashing, JWT signing/verification including the SR-18 algorithm-pinning checks, enrollment-token validation rules):

```
go test ./...
```

**Frontend tests** (`web/`, Vitest + jsdom + Testing Library — BACKLOG P3):

```
cd web && npm test          # or: npm run test:watch
```

**This suite does NOT run in CI, and this line used to claim it did.** `.github/workflows/ci.yml`'s
`web` job is `npm ci` → `typecheck` → `lint` → `design-lint` → `build` — there is no `npm test` step in
it or in any other workflow (`e2e.yml` runs `npm run test:e2e`, a different suite; `grep -rn "npm test"
.github/workflows/` returns nothing). So a broken Vitest test blocks nothing until someone runs it by
hand. Run it before calling frontend work done, and treat wiring it into `ci.yml` as outstanding.

What it started as was **UI-critical logic, not markup**: the formatters an operator reads
numbers off, the pagination clamp (a list shrinking under a parked page number is routine here, because
these lists refetch whenever the hub publishes an incident or cluster event), the detection-latency derivation — anchored to the values
measured on real clusters in `docs/VERIFICATION.md` §6 rather than to the formula restated — and the
three-state remediation-authority card, where collapsing "unknown" into "not granted" would tell an
operator remediation is unavailable when nobody could ask. It has since grown component coverage of the
big pages too (`web/src` holds 23 test files, including `IncidentsPage`, `IncidentDetailPage`,
`SettingsPage`, `UsersPage`, `InsightsPage`, `ApprovalsPage`, `ClustersPage`, `ClusterDetailPage`,
`OverviewPage`, `AuditLogPage`, `LoginPage`, `TolerationsPage`, plus route-level rendering in
`App.test.tsx`).

Each of those was verified by mutation: break the clamp, render a reported zero as `0s`, drop the
sweep-boundary rounding, make an unanswered authority check render as a denial — all four are caught. A
test nobody has seen fail is not yet evidence of anything.

**Browser end-to-end tests** (`web/e2e/`, Playwright + Chromium — BACKLOG P3, committed 2026-08-26).
Different from the Vitest suite above on purpose: that suite mocks every `api/client` call and checks
component logic in jsdom; this one drives a real Chromium against a REAL running hub+Postgres (this
same "Local development" section's Option A/B), so it needs a stack already up before you run it:

```
docker build -t argus/hub:dev .                                  # if you haven't already
docker compose -f deploy/compose/docker-compose.yaml up -d       # if not already running
cd web && npx playwright install --with-deps chromium            # once per machine
npm run test:e2e
```

`playwright.config.ts`'s `globalSetup` seeds a known fixture through the real `POST /api/v1/demo-data`
endpoint and `globalTeardown` clears it afterward — nothing to seed by hand. **That endpoint exists only
when `ARGUS_ENABLE_DEMO_DATA=true`**, which `deploy/compose/docker-compose.yaml` sets and no real
deployment should (PROJECT.md D14 — it writes fabricated analyses, approval decisions attributed to the
caller by name, executions and metered spend into the same tables real rows live in, excluded from no
count anywhere). If the whole suite fails at `globalSetup` with a 404, that flag is off on the stack you
pointed it at. There is no longer any UI that reaches it: sample data was removed from Settings and from
the onboarding wizard, and the honest answer to an empty install is to enrol a cluster — a throwaway test
cluster included. It logs in as the compose profile's bootstrap admin
(`admin@localhost` / `dev-admin-password-123`, same as "Accessing it" above); override with
`ARGUS_E2E_EMAIL`/`ARGUS_E2E_PASSWORD` if your stack's bootstrap credential differs. Point it at a
different hub (e.g. `npm run dev`'s Vite server, for fast iteration on the specs themselves without a
container rebuild) with `PLAYWRIGHT_BASE_URL=http://localhost:5173`.

Covers what `PROJECT.md`/`retired LLD-13` name as the UI-critical flows, deliberately kept small rather
than re-testing everything the Vitest suite already covers at the component level: login (valid/invalid
credentials, sign-out, the already-authenticated `/login` redirect, an unauthenticated visit to a
protected route bouncing back), the incident list, an incident's six lifecycle stages
(Detection/Analysis/Recommendation/Approve/Apply/Validate) rendering from real analysis/plan data, and the
approval queue's real pending-plan diff view. Runs against whatever `baseURL` you point it at — nothing
here starts or stops the stack for you, so a dev stack left running keeps running after the suite exits.
Wired into CI as its own `.github/workflows/e2e.yml`, on demand (`workflow_dispatch`) rather than
per-PR, since it needs the Docker+Postgres stack `ci.yml`'s own hermetic design deliberately avoids.

**End-to-end smoke test** against a running stack — the exact sequence used to verify every increment while building it, saved as a script instead of re-typed manually each time:

```
docker build -t argus/hub:dev .
docker compose -f deploy/compose/docker-compose.yaml up -d
./scripts/smoke-test.sh
```

Covers: health/readiness, login (including wrong-password rejection), the first auth-required route, cluster-enrollment-token issuance and its validation rules, **capability denial for a role that lacks it** (creates a throwaway viewer user via `hub hash-password` + a direct SQL insert, confirms it gets `403` on an onboard-only route while still able to read its own permissions, then cleans up), refresh-token rotation with reuse-detection, the full cluster enrollment/accept/certificate-issuance lifecycle plus tunnel-delivered finding ingestion and incident correlation, org settings, the audit log API, user/grant management (`POST /api/v1/users` with a server-generated temporary password that actually authenticates and forces a password change, granting/revoking an additional role and confirming `GET /users/me/effective-permissions` reflects it, and capability denial for both `user:read` and `user:manage`), **password self-service change and admin reset** (§10a: wrong-current-password and below-minimum-length rejection; a successful self-service change returns a fresh token pair with no forced logout while the OLD access token AND refresh token both stop working immediately; an admin reset ends a target's already-issued session the same way and forces `mustChangePassword` back on; neither endpoint's response, nor its audit event, ever carries a password), and — most recently — **user disable/enable** (§10b: an already-issued session dies immediately on disable — same live-token/live-refresh-token proof §10a's reset case uses — a subsequent login with the correct password is rejected, re-enabling restores it, both actions 409 on their own already-applied state or 404 on an unknown user, both 403 without `user:manage`, and the last-remaining-super-admin self-disable guardrail actually blocks that one specific case — proven by first draining it to exactly one active super-admin, then confirming that account's own session still works after the blocked attempt — while a tenant-admin's self-disable, or a super-admin's self-disable while another active super-admin still exists, both go through with no such check). Exits non-zero if anything fails; §10a is 19 assertions and §10b is 18 more, and §10+§10a+§10b together pass clean, reverified against a fully clean, isolated volume — see `PROJECT.md`'s latest numbered section for the whole suite's current pass/fail total, which moves round to round as parallel work lands. A later `## 14` section covers `GET /api/v1/insights`: inserts a small, uniquely-prefixed fixture set directly via `psql` (no create API exists for `incidents`/`findings`/`analyses`) spanning two clusters, three fingerprints (one recurring across both), three namespaces, and a mix of complete/partial analyses across different days, then asserts the real aggregation against baseline-plus-delta math rather than assuming the shared `analyses` table starts empty.

If the stack has been running a while, `hub-api`'s bootstrap password won't be in the logs anymore (it only prints once) — pass it explicitly: `ARGUS_ADMIN_PASSWORD=... ./scripts/smoke-test.sh`.

**Golden-set eval harness** — a different kind of check than the above: `scripts/smoke-test.sh` asserts deterministic API contracts; `scripts/eval-harness` asks "did the investigation loop reach the right conclusion," which needs a known-correct answer to grade against, not just a status code. Kept as its own script for exactly that reason, per `retired LLD-07` §6:

```
docker compose -f deploy/compose/docker-compose.yaml up -d   # if not already running
go run ./scripts/eval-harness -personality good
go run ./scripts/eval-harness -personality bad
```

Each run enrolls a real throwaway cluster, dials the real mTLS tunnel with a fake "cluster" (`scripts/eval-harness/fakeagent.go`) that answers tool calls from a golden case's own fixture instead of "not found," points the hub's AI settings at an in-process fake reasoning model (`-personality good` reasons plausibly; `-personality bad` concludes off the first event alone with no corroboration), then drives every case in `scripts/eval/golden/*.json` through the real `POST /incidents/{id}/analyze` and scores the result on root-cause correctness and tool-call efficiency (independently, per §6). Point `-llm-base-url`/`-llm-model`/`-llm-api-key` at a real configured provider instead to grade a real model rather than the fake reasoner. See `PROJECT.md`'s eval-harness section for the exact golden-set format, the scoring approach, and a captured good-vs-bad run showing the two personalities score 100%/100% vs 25%/0%. `go test ./scripts/eval-harness/...` covers the same distinguishing behavior without needing a running stack. Deliberately **not** a CI regression gate and **not** a confidence-calibration curve — see `PROJECT.md` for why both are out of scope for this first version.

**What's not covered yet.** The three frontend gaps this paragraph used to list — component coverage of
the big pages, route-level rendering, and a browser-driven end-to-end flow — are all closed (see the two
frontend subsections above); what remains is that the Vitest suite runs **only by hand**, since nothing
in `ci.yml` invokes it. Still genuinely absent: no `envtest`/fake-cluster suite, no
chaos/failure-injection tests, and no CI wiring for either of those two — `retired LLD-13` specs the full
target test strategy (including the SR-1…SR-21 traceability matrix), but only a slice of it exists as
actual runnable tests so far. See `PROJECT.md` §4.

## Deploying a frontend change to the running stack

The web UI is **embedded into the hub binary** with `go:embed` (`internal/api/static.go`), so
the compose stack serves whatever bundle was built into the image — not whatever is in `web/dist`,
and not a dev server. `npm run build` passing proves the bundle compiles; it says nothing about
what the running stack serves.

To actually deploy a frontend change:

```
docker build -t argus/hub:dev .
docker compose -f deploy/compose/docker-compose.yaml up -d --force-recreate hub-api
```

**That recreate is now a drain, not a kill (`PROJECT.md` B162).** On `SIGTERM` the hub takes
itself out of readiness, finishes in-flight HTTP requests, sends every browser WebSocket feed a
1001 "going away" close frame, stops its background sweepers, and only then closes the agent
tunnels (`cmd/hub/main.go`'s `drainHub`). So a recreate can now take a few seconds rather than
being instant, and `stop_grace_period: 60s` in the compose file is what stops Docker
SIGKILLing it partway through — Docker's default is 10s. Budget it with
`ARGUS_SHUTDOWN_READINESS_DELAY_SECONDS` (default 3) and `ARGUS_SHUTDOWN_GRACE_SECONDS`
(default 15); `deploy/helm/argus-hub` derives `terminationGracePeriodSeconds` from the same two
values so they cannot drift apart. Agents reconnect on their own backoff, so no re-enrollment
is involved.

To confirm which build is live, grep the served bundle for a string you just added:

```
BUNDLE=$(curl -s localhost:8080/ | grep -o 'index-[A-Za-z0-9_-]*\.js' | head -1)
curl -s "localhost:8080/assets/$BUNDLE" | grep -c "some new string"
```

`npm run dev` (vite on :5173, proxying `/api` to the container) is fine and fast for iterating —
but a feature verified only there is **not** verified for the deployed product. This was learned
the hard way: a whole Settings area was verified on :5173, reported as done, and was genuinely
absent from :8080 because the image predated it.

## Testing against a real cluster

Treat a shared cluster the way you would production: investigation reads, and the read of a real
object is the point, but anything that changes the cluster (installing or removing an agent, creating
test objects, executing a remediation) needs the cluster owner's agreement first. Keep every
kubeconfig in its own file and pass `KUBECONFIG` or `--context` explicitly on every command, so a
command never lands on whatever context happens to be current.

### Shipping an agent change to a cluster that already runs one

The chart's default `identity.mode: secret` keeps the enrolled identity in a Secret, so a new image
and a restart keep the enrollment:

```
docker build --target agent -t <registry>/argus-agent:<tag> .
docker push <registry>/argus-agent:<tag>
helm --kube-context <ctx> upgrade argus-agent deploy/helm/argus-agent -n argus-system --reset-then-reuse-values \
  --set image.repository=<registry>/argus-agent --set image.tag=<tag> --set image.digest="" --set image.pullPolicy=Always
```

Confirm the Secret exists first (`kubectl -n argus-system get secret argus-agent-identity`): a release
installed from an old chart, or running `identity.mode: ephemeral`, has none, and a restart then costs
the enrollment (see Option C).

### Running a development agent beside the installed one

To try an agent change without touching the installed agent, run the new binary on your machine
against the same cluster, enrolled as a separate cluster entry:

```
go build -o /tmp/argus-agent-test ./cmd/agent
mkdir -p /tmp/argus-agent-test-data
# A distinct fingerprint is REQUIRED: the real one is sha256(kube-system namespace UID), so a
# second agent on the same cluster would be refused as a duplicate. The agent reads this file
# before computing one.
head -c 32 /dev/urandom | xxd -p | tr -d '\n' > /tmp/argus-agent-test-data/fingerprint.txt

TOK=$(curl -s -X POST localhost:8080/api/v1/clusters/enrollment-tokens \
  -H "Authorization: Bearer $ADMIN_JWT" -H 'Content-Type: application/json' \
  -d '{"ttlClass":"B","maxRedemptions":1,"scopeHint":{}}' | jq -r .token)

setsid env KUBECONFIG=<kubeconfig> \
  ARGUS_ENROLLMENT_TOKEN="$TOK" \
  ARGUS_HUB_API_URL=http://localhost:8080 \
  ARGUS_CLUSTER_DISPLAY_NAME="dev-agent" \
  ARGUS_AGENT_DATA_DIR=/tmp/argus-agent-test-data \
  /tmp/argus-agent-test > /tmp/argus-agent-test.log 2>&1 < /dev/null &
```

Accept it (`POST /api/v1/clusters/{id}/accept`); it goes `Active` within about 30 seconds while the
installed agent keeps running. Afterwards, `POST /api/v1/clusters/{id}/decommission` and stop the
process. Three traps:

- `pkill -f argus-agent-test` matches the shell running it and kills the whole command line: use a
  bracket pattern (`pkill -f "argus-agent-tes[t]"`) and build in a separate step.
- Start it with `setsid … < /dev/null &`, not a bare `&`, or it dies with the shell and the cluster
  shows `Disconnected` mid-test.
- `cp` onto a running binary does not replace the running process: build to a new path.

## A disposable `kind` cluster

For anything that would be irresponsible on a shared cluster (node-pressure faults, unsafe admission
policies, real remediation execution), use a `kind` cluster nobody else depends on, with one
control-plane and two worker nodes:

```
printf 'kind: Cluster\napiVersion: kind.x-k8s.io/v1alpha4\nnodes:\n- role: control-plane\n- role: worker\n- role: worker\n' > /tmp/kind-argus.yaml
kind create cluster --name argus-disposable --config /tmp/kind-argus.yaml --kubeconfig ~/.kube/kind-argus-disposable.yaml
```

**Loading a local image.** Where `kind load docker-image` fails (it writes a temporary tar file of its
own), load straight into each node's containerd:

```
docker build --target agent -t argus/agent:dev .
for n in argus-disposable-control-plane argus-disposable-worker argus-disposable-worker2; do
  docker save argus/agent:dev | docker exec -i "$n" ctr -n k8s.io images import -
done
```

**Enrolling an agent with remediation on.** Install the chart directly, with the opt-in write paths:

```
TOKEN=$(curl -s -X POST localhost:8080/api/v1/clusters/enrollment-tokens \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H 'Content-Type: application/json' -d '{"ttlClass":"B"}' | jq -r .token)

helm install argus-agent deploy/helm/argus-agent \
  --kube-context kind-argus-disposable --kubeconfig ~/.kube/kind-argus-disposable.yaml \
  --namespace argus-system --create-namespace \
  --set hub.apiUrl=http://<kind-network-gateway>:8080 \
  --set enrollment.token="$TOKEN" --set displayName=argus-disposable \
  --set remediate.enabled=true --set remediate.namespaces[0]=default \
  --set policyController.enabled=true --set dryRun.enabled=true
```

`hub.apiUrl` cannot be `host.docker.internal` here: that name resolves for a Compose container, not
for a pod on the `kind` network. Use that network's gateway, from
`docker network inspect kind --format '{{(index .IPAM.Config 1).Gateway}}'` (often `172.19.0.1`).

The fingerprint survives `helm uninstall`, because the cluster is the same, so decommission the
previous cluster entry before enrolling again or the enrollment is refused `409 already-enrolled`.
Delete the cluster with `kind delete cluster --name argus-disposable` once it has served its purpose.

## A GitOps test environment

The pull-request route is tested end to end against a real repository and a real Argo CD syncing it:

| | |
|---|---|
| Repository | A private GitHub repository holding the fixtures below |
| Cluster | A test cluster running Argo CD, with an `Application` per fixture |
| Token | A fine-grained personal access token, kept in a file with mode `600` |

The live tests read the repository from `ARGUS_GITOPS_REPO=owner/name` and the token from
`ARGUS_GITOPS_TOKEN`, and skip without them.

**The token.** ARGUS refuses a classic PAT (`internal/scm/tokenshape.go`), whose scope cannot be
sized. Create a fine-grained token limited to the one repository:

| Setting | Value | Why |
|---|---|---|
| Repository access | Only the test repository | Sizes the exposure |
| Contents | Read and write | Read files at the synced commit; commit the edit |
| Pull requests | Read and write | Open the pull request |
| Metadata | Read-only | Required by GitHub |
| Everything else | No access | Including Actions, Secrets, Administration and Workflows |
| Expiration | 7–14 days | Exercises the expiry warning too |

Never pass the token on a command line or paste it anywhere; inside ARGUS it is stored
envelope-encrypted. ARGUS never writes `.github/workflows/**`, and a token without Workflows access
makes that a second guarantee.

**Fixtures.** Each covers one edit shape, because the pull-request verifier's claims (only the
intended field changed, no comment moved, the document count is unchanged) mean something only
against files that have something to lose:

| Fixture | Exercises |
|---|---|
| A Deployment file with two documents and comments throughout | Changing a scalar while proving only one document moved |
| A Deployment that is OOMKilled under load | A fix that is one number |
| A Deployment with no `resources` and no `imagePullSecrets` | Creating a scalar, and a list with its first entry |
| An empty flow collection (`resources: {}`) | Expansion into a block mapping; a populated flow collection is refused |
| A Helm chart whose `values.yaml` holds the memory limit | Mapping a live field back to the values key a template consumes |

**Rules.** Unattended execution stays off, nothing is merged automatically, and nothing is created in
the GitHub account beyond commits, one branch per incident and pull requests in that repository.
Rendering a Helm values change needs the Application's `spec.source.helm.valueFiles`; without them
ARGUS reports the render as `Degraded` rather than rendering against chart defaults.
