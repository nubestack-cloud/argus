# ARGUS Metrics Reference

The hub exposes a Prometheus-format metrics endpoint at `GET /metrics`, on the same address and port
as the rest of the API.

This page is for writing alert rules against ARGUS's own health, not for the product's business data
(incident detail, remediation history, audit trail) — use the API or UI for that.

## Authentication

`GET /metrics` **requires** a bearer token. There is no unauthenticated mode, and no separate "require
a token" switch — the `ARGUS_METRICS_TOKEN` environment variable on the hub is both the switch and
the secret:

- **Set.** A request must send `Authorization: Bearer <the same value>` or get `401 Unauthorized` with
  a `WWW-Authenticate: Bearer` header. Compared in constant time.
- **Unset.** The endpoint is **disabled**. Every scrape gets `503 Service Unavailable` with a problem
  body naming the missing variable, and no metric data is served to anyone — authenticated or not. It
  does **not** fall back to serving openly.

The hub states which of the two it is in, once, in its own startup log, so you can tell without
curling the endpoint:

```
api: ARGUS_METRICS_TOKEN is set — GET /metrics requires `Authorization: Bearer <token>` ...
api: ARGUS_METRICS_TOKEN is not set — GET /metrics is DISABLED and will answer every scrape with 503 ...
```

`503` rather than `401` for the unconfigured case is deliberate: nothing you can put in your
`scrape_config` will satisfy a hub that has no secret configured, so the response points at the hub's
environment rather than at your scraper.

**This changed.** The endpoint previously served openly when the variable was unset. If you are
upgrading a hub that relied on that, set a token and add it to your scrape config, or your scrapes
will start failing — a Helm install does this for you (below); a hub run any other way does not.

### Why a token is required

No metric on this page ever carries a cluster name, namespace, or object name (see "What every metric
answers," below, for the full label-safety argument) — but several of them are still real operational
signal on their own: `argus_clusters_by_state` (fleet size and health), `argus_incidents_by_state`
(incident volume), `argus_tunnel_connections_active` (effectively a live heartbeat), and
`argus_analysis_cost_usd_total` (accumulated spend). ARGUS does not reveal a count or a heartbeat to
an anonymous visitor anywhere else in the product, and a scrape target is not an exception. In an install
with no proxy in front of the API port, "anonymous visitor" may be
more of the network than you expect.

### Configuring a token with Helm

A Helm install needs nothing from you: leave `api.metricsToken` empty and the chart generates a token,
stores it in a Secret, wires it into the hub's `ARGUS_METRICS_TOKEN`, and preserves it across
upgrades so it cannot silently rotate under a working Prometheus config. Read it back with:

```
kubectl -n <namespace> get secret <release>-argus-hub-metrics \
  -o jsonpath='{.data.token}' | base64 -d ; echo
```

To pick the value yourself instead:

```
helm upgrade --install argus-hub ./deploy/helm/argus-hub \
  --set api.metricsToken="$(openssl rand -hex 32)"
```

An explicit `api.metricsToken` always wins over the generated one. Either way, put the **same value**
in your Prometheus config:

```yaml
scrape_configs:
  - job_name: argus-hub
    authorization:
      credentials: "the token you read back, or the one you passed to --set"
    static_configs:
      - targets: ["argus-hub.example.com:8080"]
```

(Or `bearer_token_file` if you'd rather mount the token as a file than inline it in Prometheus's own
config — either is standard Prometheus `scrape_config` syntax, not anything ARGUS-specific.)

If you manage the Secret yourself, set `api.metricsTokenExistingSecret` to its name (and
`api.metricsTokenKey` if the key inside it isn't `token`) — the chart then creates and generates
nothing, and it is on you to make sure that Secret holds a non-empty token.

### Configuring a token outside Helm

A hub run without the Helm chart (for example the development stack) gets no generated token: set `ARGUS_METRICS_TOKEN` on the
hub yourself, to any value you like, and use the same value in your scrape config. Until you do, the
hub's `/metrics` answers 503.

## Deploying with Helm

The hub's Kubernetes Service carries the classic scrape annotations by default
(`prometheus.io/scrape`, `prometheus.io/port`, `prometheus.io/path`), so a Prometheus configured with
`kubernetes_sd_configs` + the usual `prometheus.io/*` relabeling picks the hub up automatically. Set
`api.service.metricsScrapeAnnotations` to `false` if your scrape setup discovers targets a different
way and would rather these were absent. No Prometheus Operator `ServiceMonitor` is provided — this
deployment doesn't assume the Operator is installed; if yours is, point a `ServiceMonitor` at the
same Service and port instead.

Those annotations say **where** to scrape, not **how** to authenticate. Discovery alone will get you a
401 — the job that scrapes the hub still needs the credential from "Authentication," above.

## What every metric answers

Every label on every metric below is a small, fixed set of values ARGUS itself defines — a lifecycle
state, an action type, an outcome, a registered API route pattern, a tool name, or a cluster ID —
**never a cluster display name, namespace, object name, fingerprint or user identity.** That part is
absolute and is not negotiable for any future metric.

Two labels are worth reading carefully because they look like exceptions and are not:

- **`cluster_id`** appears on the two per-cluster series (`argus_cluster_state`,
  `argus_cluster_last_heartbeat_timestamp_seconds`) and nowhere else. It is an ARGUS-minted opaque
  identifier (`cl_01j...`), not a name you chose, and it is one series per cluster — a few hundred
  for a large fleet, which is not a cardinality problem. It exists so you can be paged about a
  *named* cluster; "something in the fleet is Disconnected" is not an actionable alert at 3am.
  Nothing else gains a per-cluster label, because on a metric that already has two or three labels of
  its own that would multiply into the cardinality problem this rule exists to prevent.
- **`route`** is the *registered route pattern* (`GET /api/v1/incidents/{id}`), never the request
  path. An incident ID in a URL therefore cannot reach a label, and a scanner hitting random URLs
  cannot mint series — everything unmatched lands in a single `route="unmatched"` bucket.

Cluster-specific detail beyond state and liveness is still fully available through the API and UI; it
just isn't multiplied into this scrape target.

A metric that has never fired even once since the hub started is simply **absent** from the scrape,
not present with a value of `0`. Prometheus's `absent()` function is the right tool for "has this
event happened at all" — don't write an alert that assumes a metric reads `0` before it has ever been
observed.

### Finding ingestion

`argus_findings_processed_total{outcome="..."}` — a counter, incremented once per Finding the hub
receives from an agent over the tunnel. `outcome` says what happened to it: `opened_new_incident`,
`updated_existing_incident`, `reopened_after_recurrence`, `reopened_after_expiry`,
`suppressed_toleration`, `suppressed_storm_protection`, `retained_unpromoted` (recorded as evidence,
didn't rise to an incident), `dropped_detector_disabled`, `dropped_rule_disabled`,
`dropped_polarity_healthy`, or `error`.

A useful alert: a rising rate of `error`, or of `suppressed_storm_protection` (which means a cluster is
producing more brand-new incidents than its configured ceiling allows, faster than operators can be
expected to notice from the incident list alone).

`argus_finding_processing_inflight` — a gauge: findings the hub has accepted and not finished
processing, including those waiting for one of the eight processing slots. A value that keeps climbing
past eight means ingestion is falling behind the agents; alert on it staying high for several minutes.

### Incidents by state

`argus_incidents_by_state{state="..."}` — a gauge, one series per incident lifecycle state (`Detected`,
`Investigating`, `AwaitingApproval`, `Executing`, `Validating`, `Resolved`, and so on). Refreshed
periodically rather than on every scrape, so scraping this endpoint frequently does not add load to
Postgres.

A useful alert: `AwaitingApproval` or `NeedsHumanInvestigation` staying above zero for longer than your
team's expected response time — that's a queue with nobody looking at it.

### Cluster / tunnel state

`argus_clusters_by_state{state="..."}` — a gauge, one series per cluster connection/lifecycle state
(`Active`, `Degraded`, `Disconnected`, `PendingApproval`, `Provisioning`, `IncompatibleVersion`,
`Rejected`, `Archived`).

`argus_tunnel_connections_active` — a gauge with no labels: how many agent tunnel connections this hub
process currently holds open, in real time.

A useful alert: `Disconnected` above zero for a cluster you expect to always be connected, or
`argus_tunnel_connections_active` dropping sharply without a matching drop in `Active` clusters (which
would point at the tunnel listener itself, not at the clusters).

### Analysis latency and cost

`argus_analysis_duration_seconds{trigger="manual"|"auto",outcome="success"|"error"}` — a histogram of
how long one AI investigation took, split by whether a person clicked Analyze or the unattended
poller triggered it.

`argus_analysis_cost_usd_total{trigger="manual"|"auto",cost_basis="metered"|"subscription"|"unknown"}`
— a counter of recorded investigation spend in US dollars. **Only `cost_basis="metered"` is real,
measured spend.** `subscription` means the run was billed against a flat-rate subscription rather than
per-call, and its dollar figure is notional, not a bill you'll actually see — sum `metered` alone if
you're tracking real cost against a budget.

A useful alert: `rate(argus_analysis_cost_usd_total{cost_basis="metered"}[1h])` crossing whatever your
own budget threshold is.

### Notification delivery

`argus_notify_delivery_total{outcome="success"|"failure"}` — a counter of outbound webhook delivery
attempts for incident notifications.

A useful alert: any sustained rate of `failure` — it means people are not being told about incidents
that ARGUS itself already knows about.

### Remediation execution outcomes

`argus_remediation_execution_total{action_type="...",kind="forward"|"undo",outcome="succeeded"|"failed"|"unknown"}`
— a counter of every remediation change ARGUS actually applied to (or undid on) a cluster.
`action_type` is one of ARGUS's typed remediation actions (`ScaleDeployment`, `RestartPod`,
`PatchResourceLimits`, `RevertContainerImage`, `OpenPR`, and the others); `kind` distinguishes a
forward change from rolling one back.

A useful alert: any `failed` or `unknown` outcome at all — each one means a change ARGUS made to a
live cluster did not cleanly confirm, and is worth a human look regardless of volume.

### Per-cluster state and liveness

`argus_cluster_state{cluster_id="cl_..."}` — a gauge, **one series per cluster**, whose *value* is a
severity-ordered code for that cluster's lifecycle state:

| Value | State |
|---|---|
| 0 | `Active` |
| 1 | `PendingApproval` |
| 2 | `Provisioning` |
| 3 | `Archived` |
| 4 | `Degraded` |
| 5 | `IncompatibleVersion` |
| 6 | `Rejected` |
| 7 | `Disconnected` |

The state is the value rather than a second label so that a cluster has exactly one series (not one
per state, seven of which would be stale), and so the alert you actually want is a threshold:
`argus_cluster_state >= 4`. A cluster that is deleted **loses its series** rather than freezing at its
last value, so an alert cannot keep firing about a cluster that no longer exists.

`argus_cluster_last_heartbeat_timestamp_seconds{cluster_id="cl_..."}` — a gauge holding the Unix time
of that cluster's last agent heartbeat, or its enrolment time if it has never checked in. Alert on its
**age**, not its value: `time() - argus_cluster_last_heartbeat_timestamp_seconds > 90`. This is the
continuous signal underneath the step function above, so you can page before the health sweep has
finished deciding a cluster is Degraded.

### HTTP requests

`argus_http_request_duration_seconds{method="...",route="..."}` — a histogram of hub request latency
by method and registered route pattern.

`argus_http_requests_total{method="...",route="...",status="..."}` — a counter of completed requests,
additionally labelled by response status code.

They are deliberately two metrics rather than one histogram also labelled by status: the API has
around two hundred route patterns, and a histogram multiplied by status would be tens of thousands of
exposition lines per scrape. Rate comes off either; error rate off the counter; p99 off the histogram.

A useful alert: a rising rate of `status=~"5.."` on any route, or p99 latency on
`POST /api/v1/incidents/{id}/analyze` approaching your configured analysis time limit.

### Database connection pool

`argus_db_pool_connections{state="total"|"idle"|"acquired"|"constructing"}` and
`argus_db_pool_max_connections` — gauges describing pool occupancy.

`argus_db_pool_acquire_total`, `argus_db_pool_empty_acquire_total`,
`argus_db_pool_canceled_acquire_total`, `argus_db_pool_acquire_wait_seconds_total` — counters.

The pair that matters is `argus_db_pool_empty_acquire_total` (an acquire that had to *wait* for a free
connection) and `argus_db_pool_acquire_wait_seconds_total`. Pool exhaustion presents everywhere else
in the system as unexplained latency with no error; these are the only signals that name the cause.

A useful alert: `rate(argus_db_pool_empty_acquire_total[5m]) > 0` sustained — raise
`ARGUS_DB_MAX_CONNS`.

### Background sweeper health

`argus_sweeper_run_duration_seconds{sweeper="...",outcome="success"|"error"}` — a histogram of how long
one run of each background sweeper took.

`argus_sweeper_last_success_timestamp_seconds{sweeper="..."}` — the Unix time each sweeper last
completed a run **without error**. A sweeper that fails every tick does not refresh it.

`sweeper` is a short fixed name: `validation`, `self_healing`, `merge`, `approval`, `cluster_health`,
`auto_analysis`, `stale_object`, `notify`, `partition`, `orphan_reap`, `knowledge_backfill`,
`execution_reconcile`, `unattended_execution`.

A stalled sweeper is close to invisible otherwise — nothing crashes, nothing errors, incidents simply
stop progressing. Alert on the **age** of the last success:
`time() - argus_sweeper_last_success_timestamp_seconds{sweeper="validation"} > 600`.

### Tool calls over the agent tunnel

`argus_tool_call_duration_seconds{tool="...",outcome="..."}` and
`argus_tool_calls_total{tool="...",outcome="..."}` — every diagnostic or remediation tool call the hub
dispatches to an agent, by tool name and outcome (`success`, `error`, `timeout`, `not_connected`).

`timeout` and `not_connected` are kept apart from `error` on purpose: a timeout leaves a *mutation*
indeterminate, and `not_connected` says nothing about the cluster's health, only that this hub replica
does not hold its tunnel session.

A useful alert: a rising rate of `outcome="timeout"` — investigations are burning their time budget on
calls the agent never answered.

### Go runtime

`argus_go_goroutines`, `argus_go_heap_alloc_bytes`, `argus_go_heap_inuse_bytes`,
`argus_go_memstats_sys_bytes`, `argus_go_gc_cycles_total` — enough to answer the two questions worth
alerting on: is the hub leaking goroutines, and is it leaking heap. Sampled on a bounded interval
rather than at scrape time, because reading the heap stats briefly stops the world and a scrape
interval is yours to choose, not the hub's.

A useful alert: `argus_go_goroutines` growing monotonically over hours, or
`argus_go_heap_inuse_bytes` approaching the pod's memory limit.

### Collector health

`argus_metrics_collector_last_success_timestamp_seconds{collector="..."}` and
`argus_metrics_collector_failures_total{collector="..."}` — the two gauges/counters above
(`argus_incidents_by_state`, `argus_clusters_by_state`) are refreshed periodically rather than computed
on every scrape; these two series say when that refresh last actually succeeded and how many times it
has failed. If a state or cluster gauge looks suspiciously unchanging, check these before trusting its
last value as current.
