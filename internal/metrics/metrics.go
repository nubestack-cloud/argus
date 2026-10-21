package metrics

import (
	"log/slog"

	"argus/internal/logging"
	"time"
)

// All five log sites in this package are programmer errors on a defensive
// branch — a label-count mismatch, a negative counter Add, a collector that
// failed — never per-observation output, so the cost of a logger here is
// paid only when something is already wrong. They use the non-Context
// variants deliberately: a metric can be recorded from anywhere, including
// a background refresher with no request behind it, and inventing a
// context to satisfy the idiom would attach a request id that is not real.
var logger = logging.For("metrics")

// This file is the one place every metric name/help/label set this hub
// exports is declared — a call site elsewhere imports this package and
// calls one of these vars, never constructs its own Counter/Gauge/
// Histogram. That keeps every metric name and its label cardinality
// reviewable in one file, rather than scattered across the packages that
// happen to observe each event.
//
// # Label-safety argument, made once here, per PROJECT.md T11's own
// requirement ("decide deliberately what is a label and what is not")
//
// **The privacy half is absolute and has never moved.** No label in this
// file is ever a namespace, an object name, a fingerprint, a cluster
// display name, a repository path, a user email, or any other value that
// names a specific customer object or person. Every label below is one of:
// a fixed lifecycle-state name (orchestrator.State*, a small closed enum
// this codebase's own CHECK constraints already pin), a
// remediation.ActionType (11 fixed values), a short outcome/kind/trigger/
// basis string this package's own call sites choose from a closed Go
// switch, a registered HTTP route PATTERN (never a request path — see
// HTTPRequestsTotal), a tool name from the fixed investigation surface, or
// an ARGUS-minted cluster ID.
//
// **The cardinality half was NARROWED on 2026-09-23, and this paragraph is
// the current rule — do not read the argument it replaced as still
// standing.** T11 originally banned a per-cluster label outright, on the
// grounds that a 200+ cluster fleet multiplies every series. The owner
// reversed that for cluster identity specifically (PROJECT.md T24): 200
// clusters is a few hundred series, which is not a cardinality problem,
// and the blanket ban left an operator unable to be paged for a NAMED
// cluster — "something in the fleet is Disconnected" is not an alert
// anyone can act on at 3am. So:
//
//   - cluster_id IS a permitted label, on cluster state and cluster health
//     only (ClusterState, ClusterLastHeartbeatTimestampSeconds below). It
//     is an ARGUS-minted opaque ULID (cl_01j...), not a customer-chosen
//     name, so it carries no information about the customer's estate
//     beyond "a cluster exists"; the display name stays in Postgres, where
//     the UI joins it.
//   - Nothing else gains one. A per-cluster label on findings, incidents,
//     executions or analyses would multiply against those metrics' own
//     labels (outcome x action_type x kind x cluster) and IS the
//     cardinality problem the original argument described. Cluster-scoped
//     detail for those belongs in Postgres, which can already answer it.
//   - A per-cluster series must be REMOVED when its cluster is, or the
//     scrape accumulates one series per cluster that ever existed — see
//     Gauge.ReplaceSeries and internal/gateway's refreshClusterStateMetrics.
//
// So this endpoint now answers fleet-wide "can this be alerted on" AND
// "which cluster", but still never "which object".
var (
	// FindingsProcessedTotal counts every Finding the gateway's tunnel
	// listener received, by how handleFinding (internal/gateway/finding.go)
	// disposed of it — a closed, reviewed set of outcomes, not an
	// open-ended one: "dropped_detector_disabled", "dropped_rule_disabled",
	// "dropped_polarity_healthy" (BACKLOG.md E11/E12's condition-polarity
	// gate confidently resolving a condition as healthy),
	// "retained_unpromoted" (recorded as evidence but not promoted to fault —
	// PROJECT.md B173), "suppressed_toleration", "suppressed_storm_protection",
	// "opened_new_incident", "updated_existing_incident",
	// "reopened_after_recurrence", "reopened_after_expiry", and "error" (the
	// call returned an error — see internal/gateway's processFindingAsync,
	// which closes the tunnel connection on this outcome, so a rising rate
	// here is itself a sign of connection churn worth alerting on).
	FindingsProcessedTotal = NewCounter(
		"argus_findings_processed_total",
		"Findings received over the agent tunnel, labeled by how handleFinding disposed of them.",
		"outcome",
	)

	// IncidentsByState reports currently-open-ish incident counts per
	// lifecycle state (orchestrator.State*), refreshed on a bounded interval
	// — see internal/orchestrator.RefreshIncidentStateMetrics — rather than
	// computed per scrape. Every known state is set to its real count
	// (including a true zero) on every successful refresh; a refresh
	// failure leaves the gauge at its last known values rather than
	// resetting anything to 0 — see Gauge's own doc comment and
	// CollectorFailuresTotal below.
	IncidentsByState = NewGauge(
		"argus_incidents_by_state",
		"Open ARGUS incidents grouped by lifecycle state. Refreshed periodically, not per scrape; absent until the first successful refresh, never a fabricated zero on a failed one.",
		"state",
	)

	// ClustersByState mirrors IncidentsByState for cluster connection/
	// lifecycle state (PendingApproval/Provisioning/Active/Degraded/
	// Disconnected/IncompatibleVersion/Rejected/Archived — migration
	// 000002's CHECK constraint), refreshed on internal/gateway's own
	// health-monitor sweep tick (every DefaultHealthCheckInterval, 20s) —
	// piggybacked onto a query that ticker already runs, rather than a new
	// one.
	ClustersByState = NewGauge(
		"argus_clusters_by_state",
		"Enrolled clusters grouped by connection/lifecycle state — this is the tunnel/connected-cluster state metric. Refreshed on the health monitor's own sweep tick, not per scrape.",
		"state",
	)

	// TunnelConnectionsActive is the number of mTLS tunnel connections the
	// gateway currently holds open — an exact, in-memory, real-time count
	// (internal/gateway's connsMu-guarded registry), never DB-derived, so
	// there is no "collection failure" case for it: Inc/Dec happen exactly
	// where a connection registers/unregisters. Distinct from
	// ClustersByState{state="Active"}: this counts live TCP/TLS sessions
	// this specific hub process holds, which — once the multi-replica half
	// of T11 lands — will differ from "how many clusters are Active" by
	// definition (a cluster is Active fleet-wide; its tunnel session is
	// pinned to one hub replica).
	TunnelConnectionsActive = NewGauge(
		"argus_tunnel_connections_active",
		"mTLS tunnel connections currently held open by this hub process.",
	)

	// FindingProcessingInflight is PROJECT.md T11's queue-depth metric: how
	// many Findings the gateway has accepted off the tunnel and not yet
	// finished processing — from the instant processFindingAsync's
	// goroutine is spawned until it returns, which INCLUDES time spent
	// waiting for a free findingSem slot (see
	// internal/gateway.maxConcurrentFindingProcessing), not only time spent
	// actively holding one. Deliberately uncapped at findingSem's own small
	// size (8): a value stuck at 8 while this gauge keeps climbing is
	// exactly the BUGS.md 131 storm shape this metric exists to make
	// visible — capping it at the semaphore's size would hide that. An
	// in-memory, exact, real-time count.
	FindingProcessingInflight = NewGauge(
		"argus_finding_processing_inflight",
		"Findings the gateway has accepted and not yet finished processing — the finding-ingestion queue depth, including any currently waiting for a free processing slot.",
	)

	// AnalysisDurationSeconds is the wall-clock duration of one AI
	// investigation call (internal/llm.Router.Investigate), observed at its
	// two call sites (internal/api's manual POST /analyze and
	// internal/autoanalyze's unattended poller) rather than inside
	// internal/llm itself, which is outside this task's declared scope.
	// trigger is "manual" or "auto"; outcome is "success" or "error" — both
	// closed two-value enums.
	AnalysisDurationSeconds = NewHistogram(
		"argus_analysis_duration_seconds",
		"Wall-clock duration of one AI investigation call.",
		// Investigations are seconds-to-minutes, not sub-second — bounds
		// chosen to resolve that range, not copied from a generic HTTP
		// latency default. autoanalyze's own AnalysisTimeLimitSeconds
		// default and BACKLOG.md's measured "30-90s and unbounded above"
		// note (autoanalyze.go) put most real observations inside this
		// range, with 600s (10m) as a generous top bucket for an
		// unusually slow or nearly-timed-out run.
		[]float64{1, 2, 5, 10, 20, 30, 45, 60, 90, 120, 180, 300, 600},
		"trigger", "outcome",
	)

	// AnalysisCostUSDTotal accumulates PersistAnalysis's own returned
	// costUSD (internal/api/analyze.go), which is already the single place
	// this codebase computes real vs. notional cost
	// (lld/07-analysis-contracts.md §10.5) — this metric adds no second
	// cost calculation. cost_basis is llm.CostBasisMetered/Subscription/
	// Unknown, the exact three-value enum PersistAnalysis's own result
	// already carries — never rendered or summed as if a subscription's
	// notional figure were real metered spend without that label
	// distinguishing them (see argus-context's lesson 9: "never render an
	// unavailable cost as $0.00").
	AnalysisCostUSDTotal = NewCounter(
		"argus_analysis_cost_usd_total",
		"Cumulative recorded AI-investigation cost in US dollars, by trigger and cost basis (metered vs. subscription-notional vs. unknown — never summed together without this label).",
		"trigger", "cost_basis",
	)

	// NotifyDeliveryTotal counts outbound incident-notification webhook
	// attempts (internal/notify), by outcome — this is PROJECT.md T11's
	// "notification delivery failures" metric. Both of internal/notify's
	// queues (the original per-incident queue and BACKLOG.md N1's widened
	// transition queue) share this one metric, since both go through the
	// identical claim/deliver/record shape and "did the last delivery
	// attempt succeed" is the same question for either.
	NotifyDeliveryTotal = NewCounter(
		"argus_notify_delivery_total",
		"Outbound incident-notification webhook delivery attempts, by outcome.",
		"outcome",
	)

	// RemediationExecutionTotal is PROJECT.md T11's "execution outcomes"
	// metric — every remediation_executions row this hub writes, at its one
	// chokepoint (internal/api's recordExecutionOutcome — see that
	// function's own doc comment on why it is the one place this row is
	// ever written). action_type is a remediation.ActionType (11 fixed
	// values, "unknown" for the rare orphaned-Executing recovery case that
	// genuinely has no attempt record to read one from — see
	// settleOrphanExecuting's own doc comment for why "unknown" there is
	// honest, not a fabricated default); kind is "forward" or "undo";
	// outcome is remediation_executions.outcome's own three-value CHECK
	// ("succeeded"/"failed"/"unknown").
	RemediationExecutionTotal = NewCounter(
		"argus_remediation_execution_total",
		"Remediation executions recorded (forward changes and undos), by action type, kind, and outcome.",
		"action_type", "kind", "outcome",
	)

	// CollectorLastSuccessTimestampSeconds and CollectorFailuresTotal are
	// this package's own meta-metrics: they exist so a periodically-
	// refreshed gauge going stale (IncidentsByState, ClustersByState) is
	// itself something an alert rule can catch, rather than a silent, calm-
	// looking last-known-good value with no signal that collection stopped
	// working. collector is a short fixed name ("incident_state",
	// "cluster_state") chosen at each refresh function's own call site.
	CollectorLastSuccessTimestampSeconds = NewGauge(
		"argus_metrics_collector_last_success_timestamp_seconds",
		"Unix time of the last successful periodic metrics collection, by collector. Cross-check a periodically-refreshed gauge's staleness against this before reading its last value as current.",
		"collector",
	)
	CollectorFailuresTotal = NewCounter(
		"argus_metrics_collector_failures_total",
		"Count of failed periodic metrics-collection attempts, by collector.",
		"collector",
	)

	// ------------------------------------------------------------------
	// PROJECT.md T24. Everything above answers "something in the fleet is
	// wrong"; everything below answers "what, and where" — the HTTP
	// surface, the connection pool, the background sweepers, the tool
	// calls an investigation makes, this process's own runtime, and
	// per-cluster state.
	// ------------------------------------------------------------------

	// HTTPRequestDurationSeconds and HTTPRequestsTotal are deliberately two
	// metrics rather than one histogram labeled by status as well.
	//
	// The API has ~200 registered route patterns. A single histogram
	// labeled method x route x status would be (routes x statuses) series,
	// each costing 12+ exposition lines (one per bucket, plus _sum and
	// _count) — tens of thousands of lines on every scrape, for a hub whose
	// entire metrics endpoint is otherwise a few hundred. Splitting them
	// costs one extra metric name and buys latency at ~200 series and
	// status at one cheap line per (route, status) actually observed.
	// "Rate by route" comes off either one; "error rate by route" comes off
	// the counter; "p99 by route" comes off the histogram.
	//
	// **route is the registered PATTERN, never the request path.** It comes
	// from net/http's own ServeMux match ("GET /api/v1/incidents/{id}"), so
	// an incident id, a cluster id, a filename or a query string cannot
	// reach a label no matter what a caller sends — and the label set is
	// bounded by the route table in internal/api/server.go rather than by
	// traffic. A request matching nothing is recorded as "unmatched", which
	// is also what stops a scanner hitting random URLs from minting series.
	HTTPRequestDurationSeconds = NewHistogram(
		"argus_http_request_duration_seconds",
		"Wall-clock duration of one hub HTTP request, by method and registered route pattern.",
		// Sub-millisecond to a minute. The bottom of the range is real —
		// /healthz and a cached GET are hundreds of microseconds — and the
		// top has to accommodate POST /incidents/{id}/analyze, which runs a
		// whole investigation inside the request and is bounded by
		// ARGUS_ANALYSIS_TIME_LIMIT_SECONDS rather than by any HTTP
		// timeout (cmd/hub sets no WriteTimeout, deliberately). A request
		// slower than the top bucket still lands in +Inf and in _sum, so
		// the mean stays honest even where the quantile saturates.
		[]float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60},
		"method", "route",
	)
	HTTPRequestsTotal = NewCounter(
		"argus_http_requests_total",
		"Hub HTTP requests completed, by method, registered route pattern, and response status code.",
		"method", "route", "status",
	)

	// DBPoolConnections and the pool counters below are PROJECT.md P15's
	// other half: P15 tuned the pool and added data.DB.Stat, and said in
	// that method's own doc comment that T24 is where it becomes a metric.
	// This is that. The whole point is the pair (EmptyAcquireTotal,
	// AcquireWaitSecondsTotal): pool exhaustion presents as unexplained
	// latency everywhere else in the system, and these two are the only
	// signals that name the cause.
	//
	// state is total/idle/acquired/constructing — pgxpool.Stat's own four
	// connection counts, a closed set fixed by that library's API.
	DBPoolConnections = NewGauge(
		"argus_db_pool_connections",
		"Postgres connection-pool connections held by this hub process, by state (total/idle/acquired/constructing).",
		"state",
	)
	DBPoolMaxConnections = NewGauge(
		"argus_db_pool_max_connections",
		"Configured maximum size of this hub process's Postgres connection pool (data.PoolConfig.MaxConns).",
	)
	DBPoolAcquireTotal = NewCounter(
		"argus_db_pool_acquire_total",
		"Connection acquisitions from the Postgres pool.",
	)
	DBPoolEmptyAcquireTotal = NewCounter(
		"argus_db_pool_empty_acquire_total",
		"Connection acquisitions that had to WAIT for a connection to come free. Non-zero and rising is the signal that MaxConns is too low for the deployment.",
	)
	DBPoolCanceledAcquireTotal = NewCounter(
		"argus_db_pool_canceled_acquire_total",
		"Connection acquisitions abandoned because the caller's context was cancelled before a connection came free.",
	)
	DBPoolAcquireWaitSecondsTotal = NewCounter(
		"argus_db_pool_acquire_wait_seconds_total",
		"Cumulative time callers have spent waiting to acquire a pooled connection. Divide its rate by argus_db_pool_acquire_total's to get mean wait per acquire.",
	)

	// SweeperRunDurationSeconds and SweeperLastSuccessTimestampSeconds are
	// the per-sweeper half of T24. CollectorLastSuccessTimestampSeconds
	// above already does this for the two METRICS collectors; these do it
	// for the background workers that actually run the product — the
	// validation, merge, approval, health, auto-analysis, notification,
	// partition, orphan-reap, execution-reconcile and unattended-execution
	// sweeps.
	//
	// A stalled sweeper is close to invisible today: nothing crashes,
	// nothing errors, incidents simply stop progressing. The last-success
	// gauge is what makes "the validation sweeper has not completed a run
	// in 20 minutes" an alert rule instead of a discovery. sweeper is a
	// short fixed name chosen at each Run loop's own call site, from the
	// same closed set cmd/hub/main.go's startWorker calls name.
	SweeperRunDurationSeconds = NewHistogram(
		"argus_sweeper_run_duration_seconds",
		"Wall-clock duration of one background sweeper run, by sweeper and outcome.",
		// Sweeps are milliseconds when there is nothing to do and can run
		// to minutes when a tick picks up an investigation; 600s matches
		// AnalysisDurationSeconds' own top bucket for that reason.
		[]float64{0.01, 0.05, 0.1, 0.5, 1, 5, 10, 30, 60, 120, 300, 600},
		"sweeper", "outcome",
	)
	SweeperLastSuccessTimestampSeconds = NewGauge(
		"argus_sweeper_last_success_timestamp_seconds",
		"Unix time of the last run of each background sweeper that completed without error. Alert on its AGE, not its value.",
		"sweeper",
	)

	// ToolCallDurationSeconds and ToolCallsTotal cover every tool call the
	// hub dispatches over the agent tunnel — gateway.CallTool is the single
	// chokepoint both investigation backends and every hub-side call site
	// funnel through, so instrumenting it there covers the api backend's
	// loop, the cli backend's MCP callbacks, and the routing/verification
	// calls internal/api makes on its own account, without any of them
	// having to remember to measure.
	//
	// tool is the tool NAME, from the fixed investigation/remediation
	// surface (get_events, describe_resource, scale_deployment, ...). It is
	// passed through SafeToolLabel, which admits only a short identifier
	// shape: the name reaching CallTool is server-side-allowlisted before
	// dispatch, but a metric label is the wrong place to depend on that
	// being true somewhere else.
	//
	// No cluster_id label here, per the narrowed rule above: tool x outcome
	// x cluster is exactly the multiplication that rule still excludes.
	ToolCallDurationSeconds = NewHistogram(
		"argus_tool_call_duration_seconds",
		"Wall-clock duration of one tool call dispatched over the agent tunnel, by tool and outcome.",
		// The hub's own tunnel tool-call timeout is the natural top of this
		// range; buckets resolve the sub-second majority and the timeout
		// cliff, which is what distinguishes "the cluster is slow" from
		// "the agent never answered".
		[]float64{0.05, 0.1, 0.25, 0.5, 1, 2, 5, 10, 20, 30, 60},
		"tool", "outcome",
	)
	ToolCallsTotal = NewCounter(
		"argus_tool_calls_total",
		"Tool calls dispatched over the agent tunnel, by tool and outcome (success/error/not_connected/timeout).",
		"tool", "outcome",
	)

	// ClusterState is the per-cluster gauge the owner's 2026-09-23 call
	// added (see the narrowed cardinality rule in this file's header).
	//
	// **One series per cluster, and the VALUE encodes the state** — rather
	// than the obvious state-as-a-label shape, which would be
	// clusters x states series and, worse, would leave a cluster's previous
	// state sitting at 1 unless every state were rewritten on every
	// refresh. One series per cluster is what "a few hundred series" in the
	// owner's decision means, and it makes the alert an operator actually
	// wants trivial: argus_cluster_state{cluster_id="cl_x"} >= 4.
	//
	// The codes are ordered by severity, deliberately, so a threshold
	// comparison is meaningful:
	//
	//	0 = Active
	//	1 = PendingApproval
	//	2 = Provisioning
	//	3 = Archived
	//	4 = Degraded
	//	5 = IncompatibleVersion
	//	6 = Rejected
	//	7 = Disconnected
	//
	// ClusterStateCode below is the single mapping; the names are migration
	// 000002's own CHECK constraint values. An unrecognised state is not
	// mapped to a number at all (the cluster is omitted from the refresh
	// rather than reported as some default), because a new lifecycle state
	// silently landing in an existing severity bucket is how an alert ends
	// up lying.
	ClusterState = NewGauge(
		"argus_cluster_state",
		"Per-cluster lifecycle state as a severity-ordered code (0=Active 1=PendingApproval 2=Provisioning 3=Archived 4=Degraded 5=IncompatibleVersion 6=Rejected 7=Disconnected). One series per cluster; a cluster that no longer exists loses its series rather than freezing at its last value.",
		"cluster_id",
	)

	// ClusterLastHeartbeatTimestampSeconds is the health half of the same
	// owner call. State is a step function the health monitor moves on
	// fixed thresholds; this is the continuous signal underneath it, so an
	// operator can page on "cluster X has been quiet for 90 seconds"
	// without waiting for the sweep that would eventually call it Degraded.
	// Falls back to the cluster's created_at where it has never checked in,
	// matching the COALESCE the health monitor's own demotion queries use —
	// a never-connected cluster reads as maximally stale, which is true.
	ClusterLastHeartbeatTimestampSeconds = NewGauge(
		"argus_cluster_last_heartbeat_timestamp_seconds",
		"Unix time of each cluster's last agent heartbeat (its enrolment time if it has never checked in). Alert on its AGE.",
		"cluster_id",
	)

	// Go runtime metrics. T24: "nothing can observe the hub leaking
	// goroutines or heap." No new dependency — runtime.NumGoroutine and
	// runtime.ReadMemStats into this registry, refreshed on the process
	// collector's own tick (see collectors.go) rather than at scrape time,
	// because ReadMemStats stops the world briefly and a scrape interval is
	// not this process's to choose.
	//
	// A deliberately small set. The full runtime/metrics surface is ~100
	// metrics; these five are the ones that answer the two questions worth
	// alerting on — "is it leaking goroutines" and "is it leaking heap" —
	// plus enough GC signal to tell a leak from a busy period.
	GoGoroutines = NewGauge(
		"argus_go_goroutines",
		"Goroutines currently running in this hub process.",
	)
	GoHeapAllocBytes = NewGauge(
		"argus_go_heap_alloc_bytes",
		"Bytes of allocated heap objects in this hub process (runtime.MemStats.HeapAlloc).",
	)
	GoHeapInuseBytes = NewGauge(
		"argus_go_heap_inuse_bytes",
		"Bytes in in-use heap spans in this hub process (runtime.MemStats.HeapInuse).",
	)
	GoMemstatsSysBytes = NewGauge(
		"argus_go_memstats_sys_bytes",
		"Total bytes of memory obtained from the OS by this hub process (runtime.MemStats.Sys).",
	)
	GoGCCyclesTotal = NewCounter(
		"argus_go_gc_cycles_total",
		"Completed GC cycles in this hub process.",
	)
)

// RecordCollectionSuccess and RecordCollectionFailure are the two outcomes
// every periodic DB-backed refresh function in this codebase (see
// CollectorLastSuccessTimestampSeconds' own doc comment) reports through —
// named, rather than left as two inline metric calls at each call site, so
// every refresher reports the identical shape.

func RecordCollectionSuccess(collector string) {
	CollectorLastSuccessTimestampSeconds.Set(float64(time.Now().Unix()), collector)
}

func RecordCollectionFailure(collector string, err error) {
	CollectorFailuresTotal.Inc(collector)
	logger.Warn("collector refresh failed", slog.String("collector", collector), logging.Err(err))
}
