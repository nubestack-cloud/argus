package agent

// This file implements the spoke agent's third Detection Controller: a
// periodic "sweep" — a plain List against several resource types on a
// fixed interval, rather than a live watch — for problems that are real
// and sustained but don't reliably announce themselves as either a
// Warning-type Event (detector.go) or a Pod status transition
// (pod_conditions_detector.go): a Deployment/StatefulSet/DaemonSet stuck
// short of its desired replica count, a PersistentVolumeClaim wedged in
// Pending, a Job that ran to completion and failed, a Node that's NotReady
// or reporting sustained Memory/Disk/PID pressure, a HorizontalPodAutoscaler
// that can't scale its target, and a Service whose selector currently
// matches no ready endpoint at all.
//
// This is lld/06-detection-framework.md §5's "Sweep" detector class, real
// for the first time — that document names this exact scope ("replicas
// mismatched >N minutes, Pending >N minutes, unbound PVCs, failed Jobs,
// NotReady nodes") as spec'd-but-unimplemented; it does NOT implement §3's
// fuller shared-watch Detector-plugin architecture (a controller that fans
// one watch out to many Evaluate() calls) — this stays a plain, independent
// per-check List loop, deliberately matching detector.go/
// pod_conditions_detector.go's existing "MVP scope-down, not the final
// design" posture rather than introducing a different architecture for
// just this file.
//
// Runs under the same read-only argus-investigate RBAC as every other
// detector in this package — every resource type checked here
// (deployments/statefulsets/daemonsets, persistentvolumeclaims, jobs,
// nodes, horizontalpodautoscalers, services, endpointslices) is already
// get/list/watch-granted; no RBAC change was needed to add this file.
// Deliberately does NOT check for expiring TLS certificates, even though
// that's a real, common, and well-known failure mode
// lld/06-detection-framework.md §5 also names — that would require reading
// Secrets, which argus-investigate's own ClusterRole explicitly and
// permanently excludes (deploy/helm/argus-agent/templates/clusterrole.yaml's
// own "never granted" list) on the reasoning that list/watch on Secrets
// exposes values too, not just existence. Closing that specific gap would
// need a real, separate RBAC/design discussion, not a quiet addition here.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	appsv1 "k8s.io/api/apps/v1"
	autoscalingv2 "k8s.io/api/autoscaling/v2"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"

	"argus/internal/logging"
	"argus/internal/objdiff"
	"argus/internal/tunnel"
)

const (
	// sweepDetectorID/Version identify this detector's Findings on the
	// wire, distinct from detector.go's/pod_conditions_detector.go's own
	// DetectorID/Version pairs.
	sweepDetectorID      = "k8s-sweep"
	sweepDetectorVersion = "v1"

	// DefaultSweepInterval is how often runSweepDetector re-runs every
	// check below. lld/06-detection-framework.md §5 names "every 5
	// minutes, default" explicitly — matched here rather than picked
	// independently.
	DefaultSweepInterval = 5 * time.Minute

	// sweepFailedJobMaxAge bounds how far back checkFailedJobs will report a
	// failure. Without it, this check re-reported every failed Job in the
	// cluster on every sweep, forever — and because the hub only correlates a
	// recurring Finding into an incident that is NOT already Resolved/Dismissed
	// (internal/gateway/finding.go), each re-report after an operator resolved
	// the incident opened a **brand-new** one. A Job that failed on Monday and
	// still exists (no TTL controller by default) therefore produced a fresh,
	// unresolvable incident every 5 minutes indefinitely, plus a fresh paid
	// investigation each time if auto-analysis covered its severity.
	//
	// One hour is long enough that a sweep cannot miss a failure (12 sweeps at
	// the default interval) and short enough that old, already-triaged
	// wreckage stops generating incidents. This is a report-window, not a
	// sustain-threshold: a failed Job is terminal, so there is nothing to wait
	// out — the question is only whether the failure is still news.
	sweepFailedJobMaxAge = time.Hour

	// defaultSweepSustainedThreshold is the DEFAULT for how long a condition must
	// have persisted before this file reports it. Both it and DefaultSweepInterval
	// are overridable per agent (ARGUS_SWEEP_SUSTAINED_THRESHOLD_SECONDS /
	// ARGUS_SWEEP_INTERVAL_SECONDS, plumbed through agent.Config exactly like
	// FindingResendCooldown) because "how long must this be broken before you
	// tell me" is a genuine operator policy call, not a property of the code:
	// a latency-sensitive platform team wants minutes, a noisy dev cluster
	// wants longer, and neither should need a rebuild to say so. The threshold
	// is passed down as an explicit parameter rather than read from a mutable
	// package variable, so no sweep can observe a half-applied change and the
	// tests can drive it directly.
	//
	// A threshold is needed at all because every check below is something
	// that's briefly, normally true during an ordinary rollout/scheduling cycle
	// (a Deployment is unavailable for a few seconds during almost every
	// deploy; a PVC is Pending for a moment while its provisioner
	// catches up), so firing on the very first sweep that observes it
	// would be far too noisy to be useful. A judgment call, not a spec'd
	// value — matching pod_conditions_detector.go's own
	// podPendingTimeoutThreshold precedent for exactly this kind of
	// constant (a stated heuristic, explicitly not derived from
	// anything) — revisit if real operation shows it's too slow or too
	// chatty. Deliberately longer than that constant's 5 minutes: a sweep
	// only samples every DefaultSweepInterval, so a shorter threshold
	// would just mean "sometimes fires on the very first sample," which
	// defeats the point of having a threshold at all.
	defaultSweepSustainedThreshold = 10 * time.Minute

	// minSweepCheckerTimeout/maxSweepCheckerTimeout bound the per-checker
	// deadline sweepCheckerTimeout derives from the sweep interval
	// (PROJECT.md P19). See that function for the reasoning; these are the
	// two ends it clamps to.
	minSweepCheckerTimeout = 5 * time.Second
	maxSweepCheckerTimeout = 30 * time.Second

	reasonDeploymentReplicasUnavailable    = "DeploymentReplicasUnavailable"
	reasonStatefulSetReplicasUnavailable   = "StatefulSetReplicasUnavailable"
	reasonDaemonSetReplicasUnavailable     = "DaemonSetReplicasUnavailable"
	reasonDeploymentReplicaFailure         = "DeploymentReplicaFailure"
	reasonReplicaSetReplicaFailure         = "ReplicaSetReplicaFailure"
	reasonPVCPendingTimeout                = "PVCPendingTimeout"
	reasonJobFailed                        = "JobFailed"
	reasonNodeNotReady                     = "NodeNotReady"
	reasonNodeMemoryPressure               = "NodeMemoryPressure"
	reasonNodeDiskPressure                 = "NodeDiskPressure"
	reasonNodePIDPressure                  = "NodePIDPressure"
	reasonHPAScalingBlocked                = "HPAScalingBlocked"
	reasonHPAMetricsUnavailable            = "HPAMetricsUnavailable"
	reasonServiceNoEndpoints               = "ServiceNoEndpoints"
	reasonServiceTargetPortUnresolved      = "ServiceTargetPortUnresolved"
	reasonWebhookBackingServiceUnreachable = "WebhookBackingServiceUnreachable"
	reasonIngressBackendMissing            = "IngressBackendServiceMissing"
	// reasonIngressBackendPortMismatch is BACKLOG.md AN1 (issue-catalog
	// ING-005) — see checkIngressBackendMissing's doc comment for why this is
	// a distinct Reason from reasonIngressBackendMissing rather than folded
	// into the same candidate.
	reasonIngressBackendPortMismatch = "IngressBackendPortMismatch"
	// reasonIngressHostPathCollision is BACKLOG.md AX1 (issue-catalog
	// ING-009) — see checkIngressHostPathCollision's doc comment.
	reasonIngressHostPathCollision = "IngressHostPathCollision"
	// RETENTION ANSWERED 2026-09-18: this rule was kept conditional on whether the
	// target fleet still runs Kubernetes versions where the API server does not
	// default PVC retention (pre-1.31). docs/SUPPORT.md now declares a support floor
	// of 1.29, so those versions ARE in scope and this rule stays.
	// reasonOrphanedPVC is BACKLOG.md AK1 (issue-catalog STS-008) — see
	// checkOrphanedPVC's doc comment.
	reasonOrphanedPVC = "PersistentVolumeClaimOrphaned"
	// reasonFieldOwnershipConflict is BACKLOG.md E10's "two owners of one
	// field" predicate shape (issue-catalog DEPL-012) — see
	// checkFieldOwnershipConflict's doc comment.
	reasonFieldOwnershipConflict = "FieldOwnershipConflict"
)

// argusRemediateFieldManager is the field manager name ARGUS's own in-place
// patches carry (internal/api/remediation_exec.go's argusFieldManager
// constant, duplicated here rather than imported: the agent package is the
// spoke-side binary and does not, and should not, import the hub-side
// internal/api package). A field ARGUS itself last wrote is not a
// contention worth reporting — it is exactly what is expected right after
// an ARGUS-executed remediation — so checkFieldOwnershipConflict excludes it
// before counting distinct managers, matching objdiff.DescribeContention's
// own ignore-list convention at its other call site.
const argusRemediateFieldManager = "argus-remediate"

// sweepCandidate is one detected condition, before fingerprinting/cooldown
// is applied — the shape every checker function below returns, so
// runOneSweep's dedup-and-send logic is written exactly once rather than
// once per checker.
type sweepCandidate struct {
	GVK             string
	Namespace       string
	Name            string
	UID             string
	ResourceVersion string
	Reason          string
	Message         string
	Severity        string
	Class           string
	Confidence      string
	Impact          string
	// SustainedFrom is when this condition demonstrably became true, when the
	// cluster itself tells us (a condition's LastTransitionTime, a PVC's
	// creation). Zero means "unknown" — and for those checks runOneSweep
	// applies its own observed-since gate instead (see sustainedLongEnough).
	//
	// This field exists because three checks used to compare against the
	// *object's* age, which is not the same thing at all: for any object older
	// than the threshold that comparison is trivially satisfied, so a
	// transient state fired on the very first sweep that saw it. A StatefulSet
	// created last month going 2/3-ready during a normal rolling update was
	// reported immediately as a "high" severity problem.
	SustainedFrom time.Time
	OccurredAt    time.Time
	// RuleID mirrors tunnel.Finding's own field of the same name — set only
	// by evaluateRule (BACKLOG.md E9/V3), left at its zero value ("") by
	// every hand-written checker in this file. See tunnel.Finding.RuleID's
	// doc comment for why this exists and why Reason alone was not enough.
	RuleID string
	// WorkloadGVK/WorkloadName mirror tunnel.Finding's own fields of the same
	// name — set only by checkPodPendingTimeout (the one sweep checker that
	// looks at Pods), left at their zero value by every other checker, which
	// don't apply to replica-level correlation (BACKLOG.md's A3).
	WorkloadGVK  string
	WorkloadName string
	// PodPriority mirrors tunnel.Finding's own field of the same name — set
	// only by checkPodPendingTimeout (the same one checker that sets
	// WorkloadGVK/WorkloadName above, and for the same reason: it is the
	// one sweep checker holding a full *corev1.Pod object rather than an
	// unstructured one), left nil by every other checker. See that field's
	// own doc comment for the absent-vs-zero contract.
	PodPriority *int32
	// RelatedWorkloadGVK/RelatedWorkloadName mirror tunnel.Finding's own
	// fields of the same name (BACKLOG.md's A3b) — set only by
	// checkPVCPending and checkServiceNoEndpoints, the two checkers whose
	// object is causally linked to a workload it does NOT own or belong to
	// (a PVC's mounting Pod, a Service's selected Pod), via
	// internal/agent/objectref.go's resolveRelatedWorkloadFor* helpers.
	// Deliberately distinct from WorkloadGVK/WorkloadName above — see that
	// pair's doc comment, and tunnel.Finding's, for why this must not reuse
	// them.
	RelatedWorkloadGVK  string
	RelatedWorkloadName string

	// References mirrors tunnel.Finding's own field of the same name
	// (PROJECT.md B153) — set for every candidate checkGenericObjectHealth's
	// dispatcher produces (not just checkGenericDanglingReference's own),
	// by that dispatcher's own shared post-processing step, never by an
	// individual predicate directly.
	References []tunnel.ObjectReference

	// ConditionType/ConditionObservedValue/ConditionSampleCount/
	// ConditionMajorityValue/ConditionMajorityFraction mirror tunnel.Finding's
	// own fields of the same name (BACKLOG.md E11 piece 3) — set only by
	// generic_predicates.go's checkGenericConditions, left at their zero
	// value by every other checker. See tunnel.Finding's own doc comment for
	// why the hub, not this agent, makes the final fire-or-drop polarity
	// call.
	ConditionType             string
	ConditionObservedValue    string
	ConditionSampleCount      int
	ConditionMajorityValue    string
	ConditionMajorityFraction float64

	// ConditionParentPath mirrors tunnel.Finding's own field of the same name
	// (PROJECT.md B154) — set only by checkGenericConditions when the
	// condition it flagged was found nested under status (a Gateway
	// listener, an HTTPRoute parent), empty for the conventional top-level
	// status.conditions[] case.
	ConditionParentPath string
}

// runSweepDetector is the third Detection Controller: same overall
// lifecycle shape as watchWarningEvents/watchPodConditions (started once
// from Run as its own goroutine; only starts if a live cluster config
// resolves at all; never blocks or panics when no cluster is reachable;
// fully independent of tunnel connection state) — but ticks on a plain
// interval rather than watching, since what it's checking (a sustained
// condition, not a discrete event) doesn't fit the watch model the other two
// detectors use.
//
// Builds both a typed clientset (for sweepCheckers) and a dynamic client (for
// dynamicSweepCheckers — CRD-backed checks like checkArgoSyncFailed, which
// need dynamic.Interface because Argo's Application has no typed client)
// from the same *rest.Config, the same pattern facts.go's gatherNodeUsage
// uses for metrics.k8s.io. Unlike newClientset() (which builds only the
// typed client, and is still what every other detector in this package
// uses), this needs both, so it resolves the config itself rather than
// going through that helper.
func runSweepDetector(ctx context.Context, findingCh chan<- tunnel.Finding, cooldown, interval, sustainedThreshold time.Duration, rules []Rule) {
	cfg, err := loadKubeConfig()
	if err != nil {
		logger.WarnContext(ctx, "sweep detector: no reachable cluster config; detector will not start", logging.Err(err))
		sweepRunState.recordError(err, time.Now())
		return
	}
	clientset, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		logger.WarnContext(ctx, "sweep detector: no reachable cluster config; detector will not start", logging.Err(err))
		sweepRunState.recordError(err, time.Now())
		return
	}

	// dyn stays nil (the interface's zero value, not a non-nil interface
	// wrapping a nil pointer — hence the if/else rather than a bare
	// `dyn, err := ...; if err != nil { dyn = nil }`) when it can't be built,
	// which every dynamic-checker call site treats as "skip CRD-backed
	// checks," the same soft-degrade posture as a cluster with no
	// metrics-server. In practice this branch is not expected to fire: a
	// dynamic client is built from the same rest.Config the typed clientset
	// above already accepted, so there is nothing left for it to reject.
	var dyn dynamic.Interface
	if dc, err := dynamic.NewForConfig(cfg); err != nil {
		logger.WarnContext(ctx, "sweep detector: could not build dynamic client; CRD-backed checks (e.g. Argo CD sync failures) will not run", logging.Err(err))
	} else {
		dyn = dc
	}

	// BACKLOG.md E11 piece 1, wired in as a measured rollout: from here on,
	// the generic kind-agnostic predicates (generic_predicates.go) also
	// sweep whatever ServerPreferredResources ∩ this identity's own RBAC
	// discovers beyond supportedGVKs' fixed set — see
	// enableDiscoveredWatchSet's own doc comment for exactly what this does
	// and does not widen. Uses the same clientset already built above; no
	// second credential, no new RBAC grant needed for THIS call (only for
	// whatever a newly-discovered kind's own get/list/watch requires, which
	// is by definition already granted or that kind would not be in the
	// discovered set at all).
	enableDiscoveredWatchSet(clientset)

	// PROJECT.md P18: arm the memory guard from this pod's own cgroup limit,
	// once, here — the same "a package var only this file's own logic
	// consults" wiring enableDiscoveredWatchSet just above uses, and for the
	// same reason (see sweep_memory.go's own doc comment on
	// sweepMemoryGuardInstance). A process with no container limit gets no
	// guard, which is every `go test` and every host-run agent.
	enableSweepMemoryGuard()

	// One deadline per checker, derived from this agent's configured
	// interval (PROJECT.md P19) — computed once here rather than per pass,
	// since the interval cannot change without restarting this goroutine.
	checkerTimeout := sweepCheckerTimeout(interval)

	logger.InfoContext(ctx, "sweep detector: starting; checking for problems that don't reliably surface as a Warning Event or a Pod status transition",
		slog.Duration("interval", interval), slog.Duration("sustained_threshold", sustainedThreshold), slog.Duration("checker_timeout", checkerTimeout), slog.Int("rule_count", len(rules)))

	// lastSent is this detector's own resend-dedup cooldown map — same
	// convention (and same reasoning for not sharing it with the other two
	// detectors' own maps) as pod_conditions_detector.go's watchPodConditions.
	lastSent := make(map[string]time.Time)

	// firstObserved is when this detector first *saw* a given problem, for the
	// checks where the cluster gives no authoritative "since when" (see
	// sweepCandidate.SustainedFrom). Entries are pruned every sweep to only
	// what is still true, so a problem that clears and later recurs starts its
	// clock over instead of inheriting a stale one.
	firstObserved := make(map[string]time.Time)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			// One pass, one health verdict — see recordSweepPassOutcome
			// (detector_status.go) for what the three outcomes of a pass
			// mean and why a timeout is not one of the failures.
			now := time.Now()
			timedOut, err := runOneSweep(ctx, clientset, dyn, findingCh, lastSent, firstObserved, cooldown, sustainedThreshold, checkerTimeout, rules)
			recordSweepPassOutcome(&sweepRunState, timedOut, err, checkerTimeout, now)
		}
	}
}

// sweepChecker is one check's shape: given a clientset and "now", list
// whatever it needs and return every currently-detected candidate. Errors
// are returned (not swallowed) so runOneSweep can log which specific check
// failed — one check's API error (e.g. a resource type the caller genuinely
// has no RBAC for, on some non-default cluster configuration) must never
// abort every other check in the same sweep.
type sweepChecker struct {
	name string
	fn   func(ctx context.Context, snap *sweepSnapshot, now time.Time, sustainedThreshold time.Duration) ([]sweepCandidate, error)
}

var sweepCheckers = []sweepChecker{
	{"pod pending timeout", checkPodPendingTimeout},
	{"deployment replicas", checkDeploymentReplicas},
	{"replica failure condition", checkReplicaFailure},
	{"statefulset replicas", checkStatefulSetReplicas},
	{"daemonset replicas", checkDaemonSetReplicas},
	{"pvc pending", checkPVCPending},
	{"orphaned pvc", checkOrphanedPVC},
	{"failed jobs", checkFailedJobs},
	{"node not ready", checkNodeNotReady},
	{"node pressure conditions", checkNodePressureConditions},
	{"hpa scaling blocked", checkHPAScalingBlocked},
	{"service no endpoints", checkServiceNoEndpoints},
	{"service targetPort unresolved", checkServiceTargetPortUnresolved},
	{"webhook backing service unreachable", checkWebhookBackingServiceUnreachable},
	{"ingress backend missing", checkIngressBackendMissing},
	{"ingress host+path collision", checkIngressHostPathCollision},
	{"hpa/gitops field ownership conflict", checkFieldOwnershipConflict},
}

// errSweepCheckerTimeout is the sentinel runOneSweep classifies a checker's
// failure by, so a checker that ran out of time is reported as exactly that
// — against its own name — rather than being mixed into the aggregate error
// that decides whether this detector looks alive at all (PROJECT.md P19).
var errSweepCheckerTimeout = errors.New("sweep checker timed out")

// sweepCheckerTimeout is how long any one checker gets before the sweep
// gives up on it and moves to the next, derived from the configured sweep
// interval.
//
// # Why there has to be one at all
//
// Until PROJECT.md P19 every checker ran on the agent's lifetime context, so
// a single API server that accepts the connection and then stops answering
// hung the whole pass forever: the 16 checkers behind the stuck one never
// ran, no Finding from any of them was ever sent, runOneSweep never
// returned, and the detector's run-health record froze at whatever it said
// before — an agent that looks merely quiet while it is in fact doing
// nothing at all. facts.go's factsTimeout exists for precisely this failure
// shape on the facts path; this is the same reasoning applied to the sweep.
//
// # Why it is not factsTimeout's 5 seconds
//
// factsTimeout bounds a node list and a version check on the connect path.
// A sweep checker's first read can legitimately be a cluster-wide list of
// every Pod on a large cluster, which takes seconds on any fleet worth
// running this on. Five seconds there would not bound a hang, it would
// manufacture one. A tenth of the sweep interval (30s at the 5-minute
// default) is long enough that no healthy list is cut short and short
// enough that a genuinely wedged read cannot eat the pass.
//
// # The clamp
//
// The interval is operator-tunable (ARGUS_SWEEP_INTERVAL_SECONDS), so the
// timeout is derived from it rather than fixed: an operator who sweeps every
// 30 seconds should not be handing each checker a 30-second budget. The
// bounds keep the derivation sane at both extremes — never under
// minSweepCheckerTimeout, which no cluster-wide list on a real cluster could
// meet, and never over maxSweepCheckerTimeout, past which a hung checker is
// costing more than any slow one could be worth.
//
// Worst case a pass takes len(sweepCheckers) x this, which at the defaults
// (17 x 30s) exceeds the 5-minute interval. That is deliberate and safe: the
// sweep loop is a single goroutine on a ticker, so a long pass makes the
// next tick late rather than piling passes up, and a pass where every
// checker hangs is a cluster-wide API server outage, not a tuning problem.
func sweepCheckerTimeout(interval time.Duration) time.Duration {
	timeout := interval / 10
	if timeout < minSweepCheckerTimeout {
		return minSweepCheckerTimeout
	}
	if timeout > maxSweepCheckerTimeout {
		return maxSweepCheckerTimeout
	}
	return timeout
}

// runSweepChecker runs one checker under its own deadline and reports a
// deadline hit as errSweepCheckerTimeout rather than as whatever the API
// client happened to return.
//
// The parent context is checked too: when the agent itself is shutting down,
// every in-flight checker fails with a cancellation that is not a timeout
// and must not be recorded as one.
//
// The shared snapshot means a checker can inherit a deadline error from a
// list an EARLIER checker paid for and lost (sweep_snapshot.go caches
// failures on purpose). That is why the classification looks at the error as
// well as at this checker's own context: the second reader of a kind whose
// list timed out is reported as a timeout too, which is true — it did not
// get the data, and for the same reason.
func runSweepChecker(ctx context.Context, c sweepChecker, snap *sweepSnapshot, now time.Time, sustainedThreshold, timeout time.Duration) ([]sweepCandidate, error) {
	checkCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	candidates, err := c.fn(checkCtx, snap, now, sustainedThreshold)
	if err == nil || ctx.Err() != nil {
		return candidates, err
	}
	if checkCtx.Err() != nil || errors.Is(err, context.DeadlineExceeded) {
		return nil, fmt.Errorf("%w after %s: %v", errSweepCheckerTimeout, timeout, err)
	}
	return candidates, err
}

// runDynamicSweepChecker is runSweepChecker's counterpart for the CRD-backed
// checkers, which take a dynamic.Interface instead of the snapshot. Same
// deadline, no timeout classification — see runOneSweep's dynamic loop for
// why a timeout there is not separable from the ordinary "this cluster does
// not run that controller" case.
func runDynamicSweepChecker(ctx context.Context, c dynamicSweepChecker, dyn dynamic.Interface, now time.Time, sustainedThreshold, timeout time.Duration) ([]sweepCandidate, error) {
	checkCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	return c.fn(checkCtx, dyn, now, sustainedThreshold)
}

// runOneSweep runs every checker in sweepCheckers — and, when dyn is
// non-nil, every checker in dynamicSweepCheckers too — and sends a (deduped)
// Finding for each candidate any of them returns.
//
// dyn is nil whenever runSweepDetector couldn't build a dynamic client (see
// its own doc comment) and in every existing test that predates
// dynamicSweepCheckers; either way, a nil dyn just means "skip the
// CRD-backed checks," never a panic — nothing here dereferences it, since
// dynamicSweepChecker.fn is only ever called with it when it's set.
//
// All four sources of candidates in a pass (the typed sweepCheckers, the
// CRD-backed dynamicSweepCheckers, generic_predicates.go's kind-agnostic
// predicates, and the declarative rules — BACKLOG.md E9,
// internal/agent/rules.go) feed the SAME stillTrue/firstObserved/lastSent
// maps through the same recordSweepCandidates helper, not independent copies
// of the fingerprint/gate/send logic: any one checker's fingerprint has to
// participate in the one stillTrue set this sweep builds, or the pruning
// pass below would delete its firstObserved entry the moment an earlier loop
// finished, before a later one ever got a chance to re-add it.
// Returns an aggregate error (errors.Join, nil when nothing failed) covering
// ONLY the fixed, always-present sweepCheckers loop — PROJECT.md T13's own
// run-health signal for the sweep detector as a whole (see
// runSweepDetector's call site). Deliberately excludes dynamicSweepCheckers
// and the declarative rules loop: those are CRD-backed (Argo CD, Flux,
// Velero, cert-manager) and fail exactly the same way whether the CRD was
// never installed on this cluster or RBAC denies it — a distinction this
// function cannot make without the topology-discovery machinery T13
// explicitly rules out of scope — so counting them here would report a
// perfectly normal "this cluster doesn't run Argo CD" as a sweep detector
// failure.
//
// Also returns the names of any checkers that ran out of time (PROJECT.md
// P19), as a SEPARATE value rather than as entries in that aggregate error.
// The two say different things and an operator needs to tell them apart: an
// aggregate error means a check could not be performed at all — RBAC denies
// the read, the resource does not exist — and is a standing fault. A
// timeout means the check was performed and the cluster did not answer in
// time, which on a large cluster is a capacity signal about one specific
// read, not a broken detector. Folding the second into the first would
// reduce both to "the sweep failed", with no indication which check hung —
// which is exactly the state P19 exists to end.
func runOneSweep(ctx context.Context, clientset kubernetes.Interface, dyn dynamic.Interface, findingCh chan<- tunnel.Finding,
	lastSent, firstObserved map[string]time.Time, cooldown, sustainedThreshold, checkerTimeout time.Duration, rules []Rule) ([]string, error) {
	now := time.Now()

	// stillTrue collects every fingerprint seen this sweep, so firstObserved can
	// be pruned to exactly what is still a problem. Without pruning, a
	// StatefulSet that was briefly degraded months ago would keep its original
	// first-observation forever and the next brief blip would report instantly.
	stillTrue := make(map[string]struct{})

	// PROJECT.md P18: price this cluster before reading it. One Limit: 1
	// request, once per pass, is what lets every Pod-enumerating read below
	// be refused BEFORE it allocates rather than after — see
	// sweepMemoryGuard.sizeCluster. A no-op on an agent with no container
	// memory limit, which is every unit test.
	sweepMemoryGuardInstance.sizeCluster(ctx, dyn)

	// The typed half runs inside its own function, and that is load-bearing
	// rather than tidiness — see runTypedSweepCheckers for why the typed
	// snapshot's lifetime is now enforced by scope.
	timedOut, checkErrs := runTypedSweepCheckers(ctx, clientset, findingCh, lastSent, firstObserved, stillTrue, now, cooldown, sustainedThreshold, checkerTimeout)

	// PROJECT.md P18: the typed snapshot is out of scope as of the line
	// above, so every budget decision from here on is about a heap that no
	// longer holds it. Re-arm the forced collection that makes the guard's
	// live-heap reading exact — see beginDynamicHalf for what happens when
	// the two halves have to share one.
	sweepMemoryGuardInstance.beginDynamicHalf()

	if dyn != nil {
		for _, c := range dynamicSweepCheckers {
			// Bounded the same way the typed checkers are (PROJECT.md P19) —
			// a CRD-backed check hanging would strand every rule behind it
			// just as surely. Not collected into timedOut: a
			// dynamicSweepChecker's failures are deliberately not part of
			// this detector's run-health signal at all (see this function's
			// doc comment), and a timeout is no more distinguishable from
			// "this cluster does not run Argo CD" than any other failure here.
			candidates, err := runDynamicSweepChecker(ctx, c, dyn, now, sustainedThreshold, checkerTimeout)
			if errors.Is(err, errSweepMemoryBudget) {
				// PROJECT.md P18: this checker's read did not fit in what is
				// left of this agent's memory limit. Skipped, like the typed
				// half's refusals and the rules loop's below, rather than
				// ending the dynamic half — one CRD-backed checker being
				// unaffordable says nothing about checkArgoSyncFailed's
				// handful of Application objects.
				//
				// Recorded on this detector's own run state rather than
				// returned: the typed half above DID complete, and marking
				// the whole pass failed would misreport a partial sweep as a
				// dead detector. recordSuccess (called by the caller, after
				// this returns) deliberately does not clear an error, so both
				// facts survive — "this pass ran, and here is what it could
				// not afford".
				logger.WarnContext(ctx, "sweep detector: dynamic checker skipped", logging.Err(err))
				sweepRunState.recordError(err, now)
				continue
			}
			if err != nil {
				logger.WarnContext(ctx, "sweep detector: check failed", slog.String("checker", c.name), logging.Err(err))
				continue
			}
			recordSweepCandidates(candidates, now, stillTrue, firstObserved, sustainedThreshold, findingCh, lastSent, cooldown)
		}

		// PROJECT.md P28: the generic kind-agnostic predicates and all of
		// the declarative rules, over ONE list per kind — see
		// runUnstructuredSweepHalf, which owns that snapshot's scope the way
		// runTypedSweepCheckers owns the typed one's.
		runUnstructuredSweepHalf(ctx, clientset, dyn, rules, findingCh, lastSent, firstObserved,
			stillTrue, now, cooldown, sustainedThreshold, checkerTimeout)
	}

	for fp := range firstObserved {
		if _, ok := stillTrue[fp]; !ok {
			delete(firstObserved, fp)
		}
	}

	return timedOut, errors.Join(checkErrs...)
}

// runUnstructuredSweepHalf runs everything in a pass that reads unstructured
// objects — generic_predicates.go's six kind-agnostic predicates and all of
// rules/default-rules.yaml's declarative rules — against ONE snapshot it
// creates and owns (PROJECT.md P28).
//
// # What this collapsed
//
// The predicates already listed every watched kind once and shared it. The
// rules did not: each of the 37 issued its own cluster-wide list of a kind
// the predicate pass had just read, including two full unstructured Pod
// lists and six Deployment lists. Measured on sweep_listcount_test.go's
// one-object-per-kind fixture: 85 dynamic lists per pass before, 48 after,
// with the rules' contribution going from 37 to zero. Nothing about a rule's
// semantics changed — a rule sees the same objects, a few milliseconds
// earlier, from the same watch-cache read (sweepListOptions) it would have
// issued itself.
//
// # Why this is a function and not a block inside runOneSweep
//
// Identical reasoning to runTypedSweepCheckers, one half later: the
// unstructured snapshot is the largest allocation a pass makes (measured at
// roughly four times the typed half on the same cluster), so it must be
// unreachable the moment this half is done rather than for as long as
// someone remembers to nil it. Being out of scope is a property a later edit
// cannot accidentally remove.
//
// # The memory guard still prices every read, including the rules'
//
// It prices them in ONE place now instead of 38. Before P28, a rule's list
// went through admitUnstructuredList per rule; now the snapshot's build does
// that per KIND (inside listWatchedKindObjects) and the whole half is
// admitted up front against the last pass' measured size
// (admitUnstructuredHalf). A rule reading from the snapshot issues no read,
// so there is nothing left to price — what it reads was already paid for and
// already refused if it did not fit.
//
// When the half cannot be afforded at all, the rules fall back to listing
// their own kinds one at a time, priced exactly as they were before this
// change. That fallback is the reason the degraded behaviour P18 measured
// still holds. Verified in a container against a 2,015-pod cluster
// (2026-09-25): at 320Mi the shared snapshot is built and nothing is
// refused; at 256Mi the snapshot is refused, the rules fall back and run,
// and the pass survives at 242Mi of the 256Mi limit with the reason on the
// detector status.
func runUnstructuredSweepHalf(ctx context.Context, clientset kubernetes.Interface, dyn dynamic.Interface, rules []Rule,
	findingCh chan<- tunnel.Finding, lastSent, firstObserved map[string]time.Time, stillTrue map[string]struct{},
	now time.Time, cooldown, sustainedThreshold, checkerTimeout time.Duration) {

	// PROJECT.md P18. This is the largest single allocation any sweep pass
	// makes, and it is all-or-nothing by construction: the predicates CANNOT
	// run on a partial map, because checkGenericDanglingReference reads
	// absence as a fact about the cluster. So the whole snapshot is admitted
	// or refused as a unit, and a refusal produces no candidates at all.
	liveBefore := liveHeapBytes()
	snap, err := buildUnstructuredSweepSnapshot(ctx, dyn, checkerTimeout)
	if err != nil {
		// Recorded on this detector's own run state rather than returned:
		// the typed half DID complete, and marking the whole pass failed
		// would misreport a partial sweep as a dead detector. recordSuccess
		// (called by the caller, after this returns) deliberately does not
		// clear an error, so both facts survive — "this pass ran, and here
		// is what it could not afford".
		logger.WarnContext(ctx, "sweep detector: unstructured snapshot build failed", logging.Err(err))
		sweepRunState.recordError(err, now)
		// The rules can still be attempted one kind at a time — see this
		// function's doc comment.
		runRulesWithOwnLists(ctx, clientset, dyn, rules, findingCh, lastSent, firstObserved,
			stillTrue, now, cooldown, sustainedThreshold, checkerTimeout)
		return
	}
	// Measured at the end of this half, with the snapshot still reachable —
	// recordUnstructuredHalf forces a collection to get an exact live
	// figure, and without the KeepAlive that collection would be free to
	// reclaim the very map it is trying to weigh, recording a projection far
	// smaller than the truth and admitting the pass that kills the agent.
	defer func() {
		sweepMemoryGuardInstance.recordUnstructuredHalf(liveBefore)
		runtime.KeepAlive(snap)
	}()

	// PROJECT.md E11. Published from the ONE place that has the finished
	// read record — this half owns the shared snapshot, and the facts
	// gatherer runs on a different goroutine at a different cadence. Recorded
	// before the predicates run rather than after, because the record is
	// complete the moment the snapshot is built and nothing below can change
	// it; doing it here means a panic in a predicate cannot lose the
	// coverage figure for the whole pass.
	recordSweepCoverage(snap.coverage(now))

	recordSweepCandidates(checkGenericObjectHealth(snap, now, sustainedThreshold),
		now, stillTrue, firstObserved, sustainedThreshold, findingCh, lastSent, cooldown)

	recordSweepCandidates(staleSchedulesInSnapshot(snap, now),
		now, stillTrue, firstObserved, sustainedThreshold, findingCh, lastSent, cooldown)

	runRulesFromSnapshot(ctx, snap, rules, findingCh, lastSent, firstObserved,
		stillTrue, now, cooldown, sustainedThreshold)
}

// buildUnstructuredSweepSnapshot is the admitted, deadline-bounded build of
// one pass' shared unstructured view. Every error it returns means the same
// thing to a caller — there is no snapshot this pass — which is why it
// collapses the guard's refusal and the listing's own refusal into one
// return rather than making the caller tell them apart.
func buildUnstructuredSweepSnapshot(ctx context.Context, dyn dynamic.Interface, checkerTimeout time.Duration) (*unstructuredSnapshot, error) {
	// PROJECT.md P17(c): the half is admitted whole, paginated, or refused,
	// in that order — see sweep_pagination.go. The plan applies to every
	// kind inside it, so a half that had to be downgraded pages ALL of its
	// kinds rather than picking some, which is what keeps the bound on the
	// half rather than on one lucky kind within it.
	plan, err := sweepMemoryGuardInstance.planUnstructuredHalf()
	if err != nil {
		return nil, err
	}
	// Bounded like every other check in a pass (PROJECT.md P19): this is ~47
	// cluster-wide lists in a row, and an API server that stops answering
	// part-way through must not strand the rules behind it forever.
	//
	// ONE deadline for the whole build, not one per kind, which is what the
	// generic predicates already had (runDynamicSweepChecker wrapped their
	// single listing call the same way). The rules now inherit it, and that
	// is a real trade worth naming: on an API server slow enough to burn
	// this budget part-way through, every kind after the slow one is
	// recorded unreadable and the rules over those kinds are skipped, where
	// before each rule got its own fresh deadline. Skipped-and-reported is
	// the right side of that trade — a rule that would have timed out
	// anyway now says so instead of silently finding nothing — and keeping
	// the bound is what stops one hung kind from costing a whole pass.
	buildCtx, cancel := context.WithTimeout(ctx, checkerTimeout)
	defer cancel()
	return listWatchedKindObjects(buildCtx, dyn, plan)
}

// runRulesFromSnapshot evaluates every declarative rule against objects the
// pass has already read. No API call is issued here at all.
//
// A rule whose kind was not read is SKIPPED, not evaluated against an empty
// list (PROJECT.md B185's reasoning applied to the rules layer): a rule that
// sees nothing reports nothing, which is indistinguishable from "this rule
// checked and found the cluster healthy". How loudly that is reported
// depends on what the snapshot recorded:
//
//   - kindNotServed — no CRD installed. Silent, exactly as evaluateRule's
//     own meta.IsNoMatchError tolerance has always been: a cluster that does
//     not run Velero is not a cluster with a broken Velero rule.
//   - anything else (RBAC denied it, the memory guard refused it, the list
//     failed) — reported once per pass on the detector's run state, naming
//     the rules that did not run and why. An operator can act on "the
//     ClusterRole is missing this kind"; they cannot act on silence.
func runRulesFromSnapshot(ctx context.Context, snap *unstructuredSnapshot, rules []Rule,
	findingCh chan<- tunnel.Finding, lastSent, firstObserved map[string]time.Time, stillTrue map[string]struct{},
	now time.Time, cooldown, sustainedThreshold time.Duration) {

	// One pod source for the whole loop, so the namespace index the
	// selector-shaped comparators need is built at most once per pass rather
	// than once per rule.
	pods := &snapshotPodSource{snap: snap}

	var skipped []string
	var skipReason string
	for _, r := range rules {
		gvk, err := parseGVKString(r.GVK)
		if err != nil {
			logger.WarnContext(ctx, "sweep detector: rule GVK parse failed", slog.String("rule_id", r.ID), logging.Err(err))
			continue
		}
		if !snap.readable(gvk.Kind) {
			if snap.readState(gvk.Kind) != kindNotServed {
				skipped = append(skipped, r.ID)
				skipReason = snap.unreadableReason(gvk.Kind)
			}
			continue
		}
		candidates, err := evaluateRuleObjects(ctx, pods, r, snap.objectsOfGVK(gvk), now)
		if err != nil {
			logger.WarnContext(ctx, "sweep detector: rule check failed", slog.String("rule_id", r.ID), logging.Err(err))
			continue
		}
		recordSweepCandidates(candidates, now, stillTrue, firstObserved, sustainedThreshold, findingCh, lastSent, cooldown)
	}
	if len(skipped) > 0 {
		skipErr := fmt.Errorf("%d of %d declarative rule(s) did not run this pass (%s): %s",
			len(skipped), len(rules), strings.Join(skipped, ", "), skipReason)
		logger.WarnContext(ctx, "sweep detector: rules skipped this pass", logging.Err(skipErr))
		sweepRunState.recordError(skipErr, now)
	}
}

// runRulesWithOwnLists is the pre-P28 rule loop, kept as the fallback for a
// pass whose shared snapshot could not be built (almost always: the memory
// guard refused it). Each rule lists its own GVK, priced one at a time by
// the same guard, so a cluster too large for the whole-cluster unstructured
// pass still gets whatever rules it can afford — which is the degraded
// behaviour P18 measured and sized the chart default against.
func runRulesWithOwnLists(ctx context.Context, clientset kubernetes.Interface, dyn dynamic.Interface, rules []Rule,
	findingCh chan<- tunnel.Finding, lastSent, firstObserved map[string]time.Time, stillTrue map[string]struct{},
	now time.Time, cooldown, sustainedThreshold, checkerTimeout time.Duration) {

	var refusedRules []string
	var ruleRefusal error
	for _, r := range rules {
		// The same budget check the typed lists get (PROJECT.md P18).
		// Skipped one at a time rather than ending the loop: a rule over
		// Pods being unaffordable says nothing about a rule over
		// PodDisruptionBudgets. Reported once, after the loop, so one
		// unaffordable kind cannot fill the log with 30 copies of the same
		// sentence.
		plan, err := sweepMemoryGuardInstance.planUnstructuredList(gvkKindSuffix(r.GVK), "declarative rule "+r.ID)
		if err != nil {
			refusedRules = append(refusedRules, r.ID)
			ruleRefusal = err
			continue
		}
		ruleCtx, cancel := context.WithTimeout(ctx, checkerTimeout)
		candidates, err := evaluateRule(ruleCtx, dyn, clientset, r, now, plan)
		cancel()
		if errors.Is(err, errSweepMemoryBudget) {
			// A paginated rule read that ran out of budget part-way through
			// (PROJECT.md P17(c)). Recorded with the rules refused BEFORE
			// they were issued rather than logged as a generic check
			// failure: to an operator these are the same event — this rule
			// did not run, and the agent's memory limit is why — and only
			// the refusal path puts the reason on the detector status.
			refusedRules = append(refusedRules, r.ID)
			ruleRefusal = err
			continue
		}
		if err != nil {
			logger.WarnContext(ctx, "sweep detector: rule check failed", slog.String("rule_id", r.ID), logging.Err(err))
			continue
		}
		recordSweepCandidates(candidates, now, stillTrue, firstObserved, sustainedThreshold, findingCh, lastSent, cooldown)
	}
	if len(refusedRules) > 0 {
		refusal := fmt.Errorf("%d of %d declarative rule(s) skipped this pass (%s): %w",
			len(refusedRules), len(rules), strings.Join(refusedRules, ", "), ruleRefusal)
		logger.WarnContext(ctx, "sweep detector: rules skipped this pass", logging.Err(refusal))
		sweepRunState.recordError(refusal, now)
	}
}

// runTypedSweepCheckers runs the fixed, always-present typed half of one
// pass — sweepCheckers — against a snapshot it creates and owns.
//
// # Why this is a function and not a block inside runOneSweep
//
// The typed snapshot (PROJECT.md P17(a)) holds all 14 cluster-wide typed
// lists at once, dominated by the Pod list. generic_predicates.go's
// listWatchedKindObjects, which runs in the dynamic half straight after
// this, holds every watched kind as unstructured map trees — measured at
// roughly four times the typed half's retained size on the same cluster
// (sweep_memory_live_test.go). If the typed snapshot were still reachable
// while that ran, a pass' peak would be the SUM of the two, which is the
// shape most likely to be OOMKilled mid-sweep (PROJECT.md P18).
//
// That used to be prevented by a `snap = nil` line between the two halves.
// It worked, and it was one line away from not working: nothing stopped a
// later edit from reading the snapshot below it, moving it, or deleting it
// as dead code — and nothing would have failed, because the symptom is an
// OOMKill on somebody else's large cluster weeks later. Putting the typed
// half in its own function means the snapshot is unreachable after it
// returns because it is out of scope, which is not a property a future edit
// can accidentally remove. TestTypedSweepSnapshotIsReleasedBeforeTheDynamicHalf
// pins the behaviour; this shape is what makes it true.
//
// Returns the same two values runOneSweep returns for this half: the
// checkers that ran out of time (named, never aggregated — PROJECT.md P19)
// and the checkers that failed.
func runTypedSweepCheckers(ctx context.Context, clientset kubernetes.Interface, findingCh chan<- tunnel.Finding,
	lastSent, firstObserved map[string]time.Time, stillTrue map[string]struct{}, now time.Time,
	cooldown, sustainedThreshold, checkerTimeout time.Duration) ([]string, []error) {

	// One shared, list-once view of the cluster for every checker in this
	// pass (PROJECT.md P17(a)) — see sweep_snapshot.go for what that removes
	// and why it is behaviour-preserving. Built per pass and discarded with
	// it; nothing here caches across sweeps.
	snap := newSweepSnapshot(clientset)

	var checkErrs []error
	var timedOut []string
	var refusedCheckers []string
	var lastRefusal error
	for _, c := range sweepCheckers {
		candidates, err := runSweepChecker(ctx, c, snap, now, sustainedThreshold, checkerTimeout)
		if errors.Is(err, errSweepCheckerTimeout) {
			// Named, not aggregated — see runOneSweep's own doc comment.
			logger.WarnContext(ctx, "sweep detector: check timed out", slog.String("checker", c.name), logging.Err(err))
			timedOut = append(timedOut, c.name)
			continue
		}
		if errors.Is(err, errSweepMemoryBudget) {
			// PROJECT.md P18: the guard refused one of this checker's lists
			// because the read would not fit in what is left of this agent's
			// memory limit. Skipped, not fatal to the half: the projection
			// is per kind, so "the Pod list does not fit" says nothing about
			// the Deployment list, and abandoning the other 16 checkers
			// would give up detection this agent can still afford.
			//
			// Collected and reported once after the loop — a cluster whose
			// Pod list is unaffordable has several checkers that want it,
			// and one log line per checker would bury the reason in
			// repetition.
			refusedCheckers = append(refusedCheckers, c.name)
			lastRefusal = err
			continue
		}
		if err != nil {
			logger.WarnContext(ctx, "sweep detector: check failed", slog.String("checker", c.name), logging.Err(err))
			checkErrs = append(checkErrs, fmt.Errorf("%s: %w", c.name, err))
			continue
		}
		recordSweepCandidates(candidates, now, stillTrue, firstObserved, sustainedThreshold, findingCh, lastSent, cooldown)
	}
	if len(refusedCheckers) > 0 {
		// Into the aggregate error, unlike the dynamic half's refusal: these
		// are the always-present checks, and some of them not running is
		// exactly what this detector's run-health signal exists to say.
		refusal := fmt.Errorf("%d of %d always-present check(s) skipped this pass (%s): %w",
			len(refusedCheckers), len(sweepCheckers), strings.Join(refusedCheckers, ", "), lastRefusal)
		logger.WarnContext(ctx, "sweep detector: always-present checks skipped this pass", logging.Err(refusal))
		checkErrs = append(checkErrs, refusal)
	}
	return timedOut, checkErrs
}

// recordSweepCandidates is runOneSweep's per-checker inner loop, factored out
// so the typed (sweepCheckers) and dynamic (dynamicSweepCheckers) call sites
// share one copy of the fingerprint/sustain-gate/send sequence instead of
// two that could silently drift apart.
func recordSweepCandidates(candidates []sweepCandidate, now time.Time, stillTrue map[string]struct{},
	firstObserved map[string]time.Time, sustainedThreshold time.Duration,
	findingCh chan<- tunnel.Finding, lastSent map[string]time.Time, cooldown time.Duration) {
	for _, cand := range candidates {
		fp := candidateFingerprint(cand)
		stillTrue[fp] = struct{}{}
		if !sustainedLongEnough(cand, fp, now, firstObserved, sustainedThreshold) {
			continue
		}
		sendSweepFinding(cand, fp, now, findingCh, lastSent, cooldown)
	}
}

// sustainedLongEnough decides whether a candidate has persisted long enough to
// report, and is the fix for a real flaw: three checks used to compare
// defaultSweepSustainedThreshold against the *object's* creation timestamp, which is
// trivially satisfied by any object older than the threshold — so a normal
// rolling update of a month-old StatefulSet was reported instantly as a "high"
// severity problem, and the doc comments claiming a sustained-problem proxy
// were simply wrong.
//
// Two cases:
//
//   - The cluster tells us when the condition became true (a condition's
//     LastTransitionTime, a PVC's creation while still Pending). The checker
//     sets SustainedFrom and has already applied the threshold itself; trust it.
//   - It doesn't. Then the only honest measure is how long *this detector* has
//     observed the problem, which is what firstObserved tracks. The cost is
//     that a fresh agent process re-starts every clock, delaying the first
//     report by up to the threshold after a restart — acceptable, and far
//     better than reporting transients as sustained failures.
func sustainedLongEnough(c sweepCandidate, fp string, now time.Time, firstObserved map[string]time.Time, sustainedThreshold time.Duration) bool {
	if !c.SustainedFrom.IsZero() {
		return true
	}
	seen, ok := firstObserved[fp]
	if !ok {
		firstObserved[fp] = now
		return false
	}
	return now.Sub(seen) >= sustainedThreshold
}

// candidateFingerprint is the same fingerprint sendSweepFinding computes, split
// out so runOneSweep can key its observation map on it without computing it
// twice or letting the two drift apart.
func candidateFingerprint(c sweepCandidate) string {
	kind := c.GVK
	if idx := strings.LastIndex(c.GVK, "/"); idx >= 0 {
		kind = c.GVK[idx+1:]
	}
	return computeFingerprint(c.Namespace, kind, c.Name, c.Reason)
}

// checkDeploymentReplicas flags a Deployment whose Available condition has
// been False for at least defaultSweepSustainedThreshold. Deployment is the one
// workload kind in this file with a reliable, timestamped Available
// condition the controller itself maintains — StatefulSet/DaemonSet don't
// have an equivalent in practice (see their own checkers below for the
// fallback this uses instead). A Deployment deliberately scaled to zero
// replicas is not a problem and is skipped.
func checkDeploymentReplicas(ctx context.Context, snap *sweepSnapshot, now time.Time, sustainedThreshold time.Duration) ([]sweepCandidate, error) {
	list, err := snap.deployments(ctx)
	if err != nil {
		return nil, err
	}
	var out []sweepCandidate
	for _, d := range list.Items {
		desired := int32(1)
		if d.Spec.Replicas != nil {
			desired = *d.Spec.Replicas
		}
		if desired == 0 {
			continue
		}

		available := deploymentCondition(d.Status.Conditions, appsv1.DeploymentAvailable)
		if available == nil || available.Status == corev1.ConditionTrue {
			continue
		}
		if available.LastTransitionTime.IsZero() || now.Sub(available.LastTransitionTime.Time) < sustainedThreshold {
			continue
		}

		out = append(out, sweepCandidate{
			GVK: "apps/v1/Deployment", Namespace: d.Namespace, Name: d.Name, UID: string(d.UID), ResourceVersion: d.ResourceVersion,
			Reason: reasonDeploymentReplicasUnavailable,
			Message: fmt.Sprintf("Deployment has %d/%d replicas ready and has been Available=False for %s (%s: %s)",
				d.Status.ReadyReplicas, desired, now.Sub(available.LastTransitionTime.Time).Round(time.Second), available.Reason, available.Message),
			Severity:      "high",
			SustainedFrom: available.LastTransitionTime.Time,
			OccurredAt:    available.LastTransitionTime.Time,
		})
	}
	return out, nil
}

// checkReplicaFailure flags a Deployment or ReplicaSet carrying
// ReplicaFailure=True: the workload controller recording, on the object itself
// and with a transition time, that it could not create — or delete — a Pod.
// k8s.io/api/apps/v1 names the causes on the constant itself, "insufficient
// quota, limit ranges, pod security policy, node selectors, etc. or deleted due
// to kubelet being down or finalizers are failing", which is one check covering
// a whole family of admission-time blocks.
//
// # Why the two existing paths do not cover this
//
// The Warning Event carrying the same text (FailedCreate on the ReplicaSet) is
// detector.go's job and it genuinely works — while the controller is still
// retrying. Once it stops, that Event's LastTimestamp stops advancing and
// staleEventThreshold (15 minutes) discards it as history, deliberately and
// correctly. The condition is the durable half of the same fact: the ReplicaSet
// controller sets it when a create/delete call is refused and clears it on the
// next sync that succeeds, so it is True for exactly as long as the fault lasts.
// For this family of causes it is the only signal that outlives the retries.
//
// checkDeploymentReplicas overlaps less than it looks, too. It reads the
// Available condition, which stays True for a scale-up blocked while minimum
// availability holds — a 3→4 scale-up against an exhausted quota with
// maxUnavailable: 1. Today that fault is reported by NOTHING in this agent:
// Available is True, the pod-conditions watch has no Pod to watch (it was never
// created), and the Event ages out. The workload keeps serving with no headroom
// left, which is then discovered during the traffic spike the scale-up was for.
//
// # Severity: "high"
//
// "medium" (checkHPAScalingBlocked's level) was the alternative, and would be
// the honest reading of that same minimum-availability-holds case: the workload
// is serving, only its headroom is gone. Rejected for two reasons. The condition
// does not distinguish that case from a workload with zero pods and no way to
// create one — both read ReplicaFailure=True — and severity in this file is a
// property of the reason, not recomputed per object. And "medium" sits below the
// default auto-analysis severities (high, critical), so it would reproduce the
// exact silence this check exists to end: nobody is watching a medium.
//
// "critical" was rejected as well: this file keeps that for
// cluster-infrastructure blast radius (checkNodeNotReady — a NotReady node takes
// every workload on it with it). One workload that cannot create pods is serious
// and human-fixable, not that.
//
// # Overlap 1, same object and two conditions: left to fire, deliberately
//
// A Deployment that is both below minimum availability AND blocked from creating
// pods produces this candidate and checkDeploymentReplicas'. Both are allowed,
// because the hub correlates by OBJECT (internal/gateway/finding.go's
// objectCorrelationKey — gvk|namespace|object_name), so the two land on ONE
// incident for that Deployment and severity escalation does the rest. BACKLOG.md
// A1 is about one fault opening several incidents; within one object it cannot.
//
// Suppressing the Available finding was the alternative — checkHPAScalingBlocked
// does exactly that between its own two conditions — and it is wrong here:
// ReplicaFailure also covers FailedDelete, which says nothing about why a
// workload is unavailable, so the rule would sometimes hide a real outage behind
// an unrelated stuck deletion. Instead the message carries the ready/desired
// counts and the Available state, so this finding stands on its own and a reader
// of the shared incident can tell the impact from the cause.
//
// # Overlap 2, two objects and one fault: suppressed here, because the hub can't
//
// The Deployment controller copies its ReplicaSet's ReplicaFailure condition up
// onto the Deployment — reason, message and transition time intact
// (pkg/controller/deployment's getReplicaFailures, via
// ReplicaSetToDeploymentCondition). One refused create is therefore visible on
// two objects with two different object keys, and object correlation cannot
// merge those: two incidents for one fault, which IS A1. So a ReplicaSet is
// skipped when the Deployment that owns it carries the condition too.
//
// Carrying the owning Deployment in WorkloadGVK/WorkloadName instead, and
// letting the hub's workload tier fold the two together, was rejected: those
// fields are reserved for pod-sibling correlation (see sweepCandidate and
// BACKLOG.md A3), and making a ReplicaSet finding correlate with that
// Deployment's POD findings changes grouping far beyond this check. Suppressing
// at the source needs no hub change and cannot mis-group anything.
//
// ReplicaSets are still checked rather than dropped, for the two cases where
// nothing else carries the signal at all: a bare ReplicaSet with no Deployment
// above it (hand-written manifests, and some operators create ReplicaSets
// directly), and a Deployment whose status is not being updated — a wedged or
// absent deployment controller, which is precisely when "trust the Deployment to
// mirror it" is the wrong assumption. That is why the suppression key is "the
// owner carries the condition", not "the owner exists". A healthy mirror inherits
// the ReplicaSet's own LastTransitionTime, so it is in place long before the
// sustain threshold and the ordinary case leaks no duplicates.
//
// No report window like sweepFailedJobMaxAge, and none is needed: a failed Job is
// terminal wreckage that stays on the cluster forever, whereas this condition is
// removed by the controller when the failure clears — so a ReplicaFailure still
// being reported on the tenth sweep is still true on the tenth sweep.
//
// Costs one extra List (replicasets) per sweep, inside RBAC that already grants
// it (deploy/helm/argus-agent/templates/clusterrole.yaml lists replicasets among
// the apps resources) — nothing to widen, no chart rollout to wait for. Not
// live-tested: inducing this needs a real quota or admission rejection on a
// cluster, so what the tests pin is this logic, not Kubernetes' behaviour.
func checkReplicaFailure(ctx context.Context, snap *sweepSnapshot, now time.Time, sustainedThreshold time.Duration) ([]sweepCandidate, error) {
	deployments, err := snap.deployments(ctx)
	if err != nil {
		return nil, err
	}
	replicaSets, err := snap.replicaSets(ctx)
	if err != nil {
		return nil, err
	}

	var out []sweepCandidate

	// Every Deployment carrying the condition, whether or not it is sustained
	// long enough to REPORT yet. The ReplicaSet rule below has to key on "the
	// fault is visible on the owner", not "the owner reported it this sweep":
	// keying on the report would let the ReplicaSet fire during the sustain
	// window and the Deployment fire after it — two incidents for one fault,
	// produced by the very code meant to prevent that.
	ownerCarriesCondition := make(map[string]bool)

	for _, d := range deployments.Items {
		cond := deploymentCondition(d.Status.Conditions, appsv1.DeploymentReplicaFailure)
		if cond == nil || cond.Status != corev1.ConditionTrue {
			continue
		}
		ownerCarriesCondition[d.Namespace+"/"+d.Name] = true

		sustainedFrom, report := conditionSustainedFrom(cond.LastTransitionTime, now, sustainedThreshold)
		if !report {
			continue
		}

		// No desired == 0 skip, unlike checkDeploymentReplicas. Available=False
		// on a Deployment somebody scaled to zero is expected and boring;
		// ReplicaFailure=True on one is not, because this condition exists only
		// because an API call was actually refused — and FailedDelete at zero
		// replicas ("the pods will not go away") is a real fault, not a state
		// somebody chose.
		desired := int32(1)
		if d.Spec.Replicas != nil {
			desired = *d.Spec.Replicas
		}

		out = append(out, sweepCandidate{
			GVK: "apps/v1/Deployment", Namespace: d.Namespace, Name: d.Name, UID: string(d.UID), ResourceVersion: d.ResourceVersion,
			Reason: reasonDeploymentReplicaFailure,
			Message: replicaFailureMessage("Deployment", now, sustainedFrom, cond.Reason, cond.Message,
				fmt.Sprintf("%d/%d replicas ready, %s", d.Status.ReadyReplicas, desired, availableConditionState(d.Status.Conditions))),
			Severity:      "high",
			SustainedFrom: sustainedFrom,
			OccurredAt:    firstNonZeroTime(sustainedFrom, now),
		})
	}

	for _, rs := range replicaSets.Items {
		cond := replicaSetCondition(rs.Status.Conditions, appsv1.ReplicaSetReplicaFailure)
		if cond == nil || cond.Status != corev1.ConditionTrue {
			continue
		}
		owner := controllerDeploymentName(rs.OwnerReferences)
		if owner != "" && ownerCarriesCondition[rs.Namespace+"/"+owner] {
			continue
		}
		sustainedFrom, report := conditionSustainedFrom(cond.LastTransitionTime, now, sustainedThreshold)
		if !report {
			continue
		}
		desired := int32(1)
		if rs.Spec.Replicas != nil {
			desired = *rs.Spec.Replicas
		}
		state := fmt.Sprintf("%d/%d replicas ready", rs.Status.ReadyReplicas, desired)
		if owner != "" {
			// Named because it changes where an operator looks, and because it
			// states the odd part out loud: the Deployment above this ReplicaSet
			// is not reporting a condition its own controller should have copied
			// upward, so the Deployment's status is stale too.
			state += fmt.Sprintf(", owned by Deployment %s whose own status does not carry this condition", owner)
		}

		out = append(out, sweepCandidate{
			GVK: "apps/v1/ReplicaSet", Namespace: rs.Namespace, Name: rs.Name, UID: string(rs.UID), ResourceVersion: rs.ResourceVersion,
			Reason:        reasonReplicaSetReplicaFailure,
			Message:       replicaFailureMessage("ReplicaSet", now, sustainedFrom, cond.Reason, cond.Message, state),
			Severity:      "high",
			SustainedFrom: sustainedFrom,
			OccurredAt:    firstNonZeroTime(sustainedFrom, now),
		})
	}

	return out, nil
}

// replicaFailureMessage phrases a ReplicaFailure finding, with the condition's
// own Reason and Message quoted verbatim and given the most room on purpose:
// that text is the only part of this finding that names the actual cause — the
// ResourceQuota that is full, the webhook that refused, the Pod Security level
// that was violated, the node selector nothing matches — and it is the whole
// difference between "pods are not being created" and something an operator can
// act on without opening a terminal.
//
// The duration is dropped when the condition carried no transition time, rather
// than printed as a number derived from nothing — the same rule
// nodeNotReadyMessage follows for the same reason.
func replicaFailureMessage(kind string, now, sustainedFrom time.Time, reason, message, state string) string {
	if sustainedFrom.IsZero() {
		return fmt.Sprintf("%s cannot create or delete pods to reach its desired replica count: %s: %s — %s (ReplicaFailure=True, no transition time reported)",
			kind, reason, message, state)
	}
	return fmt.Sprintf("%s cannot create or delete pods to reach its desired replica count: %s: %s — %s (ReplicaFailure=True for %s)",
		kind, reason, message, state, now.Sub(sustainedFrom).Round(time.Second))
}

// conditionSustainedFrom applies this file's standard rule to one condition's
// LastTransitionTime: when the cluster gives us one it IS the sustain clock, and
// the threshold is applied right here (report=false until it is crossed); when it
// does not, the zero time returned leaves sustainedLongEnough to gate on how long
// this detector has actually observed the problem instead.
//
// Split out rather than repeated inline because the zero-timestamp case is the
// one every earlier version of this file got wrong in a different way:
// checkNodeNotReady had a branch that could never fire (0 >= 10m), and three
// checks substituted the object's own age for a sustain clock.
func conditionSustainedFrom(lastTransition metav1.Time, now time.Time, sustainedThreshold time.Duration) (time.Time, bool) {
	if lastTransition.IsZero() {
		return time.Time{}, true
	}
	if now.Sub(lastTransition.Time) < sustainedThreshold {
		return time.Time{}, false
	}
	return lastTransition.Time, true
}

// controllerDeploymentName returns the name of the apps/v1 Deployment that
// CONTROLS this object, or "" when none does.
//
// Filters on Controller==true, unlike resolveWorkloadFromOwnerRefs' deliberate
// refs[0]: that function uses its answer to GROUP findings, where a near-miss
// costs a little grouping quality, while this one uses it to SUPPRESS one — so a
// merely-decorative ownerReference (an operator's own bookkeeping link) must not
// be able to silence a real fault. The API group is checked for the same reason:
// a CRD that happens to be Kind: Deployment must not either.
func controllerDeploymentName(refs []metav1.OwnerReference) string {
	for _, ref := range refs {
		if ref.Kind == "Deployment" && strings.HasPrefix(ref.APIVersion, "apps/") && ref.Controller != nil && *ref.Controller {
			return ref.Name
		}
	}
	return ""
}

// deploymentCondition returns the named condition from a Deployment's status, or
// nil when the controller has not written it. Takes the condition slice rather
// than the Deployment so the pointer returned is into the list's own backing
// array and stays valid past the end of a range iteration.
func deploymentCondition(conds []appsv1.DeploymentCondition, t appsv1.DeploymentConditionType) *appsv1.DeploymentCondition {
	for i := range conds {
		if conds[i].Type == t {
			return &conds[i]
		}
	}
	return nil
}

// replicaSetCondition is deploymentCondition for a ReplicaSet — separate only
// because appsv1 declares the two condition structs as distinct types with
// identical fields, and this package has no generic-over-conditions helper worth
// introducing for two call sites.
func replicaSetCondition(conds []appsv1.ReplicaSetCondition, t appsv1.ReplicaSetConditionType) *appsv1.ReplicaSetCondition {
	for i := range conds {
		if conds[i].Type == t {
			return &conds[i]
		}
	}
	return nil
}

// availableConditionState renders a Deployment's Available condition for an
// operator-facing message. Spelled out rather than left implicit because it is
// the difference between "this is an outage" and "this is a blocked scale-up
// nothing else in this agent reports" — and because this finding may share an
// incident with checkDeploymentReplicas', where a reader needs to tell the
// impact from the cause.
func availableConditionState(conds []appsv1.DeploymentCondition) string {
	c := deploymentCondition(conds, appsv1.DeploymentAvailable)
	if c == nil {
		return "Available=<unreported>"
	}
	return fmt.Sprintf("Available=%s", c.Status)
}

// checkStatefulSetReplicas flags a StatefulSet short of its desired ready
// replica count. Unlike Deployment, StatefulSet's controller doesn't
// reliably populate a timestamped Available-style condition in practice —
// this uses the object's own age as the sustained-problem proxy instead
// (a StatefulSet that's existed longer than the threshold and still isn't
// fully ready is stuck, not mid-rollout), an explicit, named
// simplification rather than a silently different algorithm from the
// Deployment checker.
func checkStatefulSetReplicas(ctx context.Context, snap *sweepSnapshot, now time.Time, sustainedThreshold time.Duration) ([]sweepCandidate, error) {
	list, err := snap.statefulSets(ctx)
	if err != nil {
		return nil, err
	}
	var out []sweepCandidate
	for _, s := range list.Items {
		desired := int32(1)
		if s.Spec.Replicas != nil {
			desired = *s.Spec.Replicas
		}
		if desired == 0 || s.Status.ReadyReplicas >= desired {
			continue
		}
		// No object-age check: StatefulSet exposes no timestamped condition
		// saying when it became under-replicated, and the object's own age is
		// not a substitute (see sustainedLongEnough). SustainedFrom is left
		// zero so runOneSweep gates on how long this detector has actually
		// observed the shortfall.
		out = append(out, sweepCandidate{
			GVK: "apps/v1/StatefulSet", Namespace: s.Namespace, Name: s.Name, UID: string(s.UID), ResourceVersion: s.ResourceVersion,
			Reason:     reasonStatefulSetReplicasUnavailable,
			Message:    fmt.Sprintf("StatefulSet has %d/%d replicas ready", s.Status.ReadyReplicas, desired),
			Severity:   "high",
			OccurredAt: now,
		})
	}
	return out, nil
}

// checkDaemonSetReplicas flags a DaemonSet short of its desired scheduled
// node count — same age-as-sustained-proxy simplification as
// checkStatefulSetReplicas, for the same reason (no reliable timestamped
// condition to key off instead).
func checkDaemonSetReplicas(ctx context.Context, snap *sweepSnapshot, now time.Time, sustainedThreshold time.Duration) ([]sweepCandidate, error) {
	list, err := snap.daemonSets(ctx)
	if err != nil {
		return nil, err
	}
	var out []sweepCandidate
	for _, d := range list.Items {
		if d.Status.DesiredNumberScheduled == 0 || d.Status.NumberReady >= d.Status.DesiredNumberScheduled {
			continue
		}
		// Same as StatefulSet: no authoritative timestamp, so no object-age
		// proxy — runOneSweep gates on observed duration instead.
		out = append(out, sweepCandidate{
			GVK: "apps/v1/DaemonSet", Namespace: d.Namespace, Name: d.Name, UID: string(d.UID), ResourceVersion: d.ResourceVersion,
			Reason:     reasonDaemonSetReplicasUnavailable,
			Message:    fmt.Sprintf("DaemonSet has %d/%d desired pods ready", d.Status.NumberReady, d.Status.DesiredNumberScheduled),
			Severity:   "high",
			OccurredAt: now,
		})
	}
	return out, nil
}

// checkPVCPending flags a PersistentVolumeClaim that's sat in phase Pending
// for at least defaultSweepSustainedThreshold — a common, easy-to-miss stuck state
// (no available PV matching its StorageClass/size, a provisioner that's
// stopped working) that throws no Warning Event of its own once the
// initial provisioning attempt's events age out.
func checkPVCPending(ctx context.Context, snap *sweepSnapshot, now time.Time, sustainedThreshold time.Duration) ([]sweepCandidate, error) {
	list, err := snap.persistentVolumeClaims(ctx)
	if err != nil {
		return nil, err
	}
	var out []sweepCandidate
	for _, pvc := range list.Items {
		if pvc.Status.Phase != corev1.ClaimPending {
			continue
		}
		if pvc.CreationTimestamp.IsZero() || now.Sub(pvc.CreationTimestamp.Time) < sustainedThreshold {
			continue
		}

		// BACKLOG.md A3b, the volume-reference half: which Pod(s) in this
		// same namespace mount this PVC, and what workload (if any) owns
		// them — resolved only for a PVC already past the sustain
		// threshold, i.e. only for the (typically small) set of PVCs this
		// check is about to report anyway, never for every PVC in the
		// cluster. See internal/agent/objectref.go's doc comment for the
		// full cost argument and internal/objectgroup for what this enables
		// hub-side.
		relatedGVK, relatedName, _ := resolveRelatedWorkloadForPVC(ctx, snap.clientset, pvc.Namespace, pvc.Name)
		class, impact := tunnel.FindingClassRisk, tunnel.FindingImpactPotential
		if relatedGVK != "" && relatedName != "" {
			class, impact = tunnel.FindingClassFault, tunnel.FindingImpactDegraded
		}

		out = append(out, sweepCandidate{
			GVK: "v1/PersistentVolumeClaim", Namespace: pvc.Namespace, Name: pvc.Name, UID: string(pvc.UID), ResourceVersion: pvc.ResourceVersion,
			Reason: reasonPVCPendingTimeout,
			Message: fmt.Sprintf("PersistentVolumeClaim has been Pending for %s%s", now.Sub(pvc.CreationTimestamp.Time).Round(time.Second),
				relatedWorkloadDescription(relatedGVK, relatedName)),
			// Authoritative: a PVC that is still Pending has been Pending since
			// it was created, so its creation time really is when this
			// condition began — unlike a workload's age.
			Severity:            "high",
			Class:               class,
			Confidence:          tunnel.FindingConfidenceVerified,
			Impact:              impact,
			SustainedFrom:       pvc.CreationTimestamp.Time,
			OccurredAt:          pvc.CreationTimestamp.Time,
			RelatedWorkloadGVK:  relatedGVK,
			RelatedWorkloadName: relatedName,
		})
	}
	return out, nil
}

// checkOrphanedPVC flags a `Bound` PersistentVolumeClaim created from a
// StatefulSet's `volumeClaimTemplate` whose ordinal is now out of range of
// that StatefulSet's current `spec.replicas`, and which no Pod currently
// references — BACKLOG.md AK1, issue-catalog STS-008.
//
// # Why checkPVCPending does not already cover this
//
// That check tests the OPPOSITE phase (`Pending`) — a claim stuck waiting to
// be provisioned. This is a claim that provisioned successfully, is `Bound`,
// and is simply no longer wanted: scaling a StatefulSet down deletes ordinals
// at or above the new replica count, but — this cluster's real 1.35 default,
// `persistentVolumeClaimRetentionPolicy.whenScaled: Retain` — leaves their
// per-ordinal PVCs behind holding real storage quota forever. Nothing about
// a `Bound` claim with no error, no event, and no Pod looks broken from any
// angle a dashboard shows; that is exactly why FAILURE_MODES.md's own row
// for this (StatefulSet, "Orphaned per-ordinal PVCs after scale-down") named
// it "Not checked" until this change.
//
// # Why the naming match is provable, not guessed
//
// A `volumeClaimTemplate` claim's name is API contract, not convention:
// `<template-name>-<statefulset-name>-<ordinal>`
// (see FAILURE_MODES.md's own note and CAPABILITIES.md §3's real 156-day
// orphan, found only because it happened to ALSO be Pending). So a `Bound`
// PVC whose parsed ordinal is `>= spec.replicas` of the StatefulSet named
// inside it, AND that no live Pod mounts, is orphaned by arithmetic — the
// same "certain rather than inferred" bar checkIngressBackendMissing's own
// doc comment holds itself to.
//
// parseStatefulSetPVCTemplateName does the actual name parsing, tried against
// every StatefulSet in the PVC's own namespace (a claim's name alone doesn't
// say which StatefulSet it belongs to when a namespace has more than one) —
// see that function's doc comment for why the match is unambiguous in
// practice.
//
// # Cost
//
// One extra List each of StatefulSets, PersistentVolumeClaims, and Pods
// (cluster-wide) per sweep, inside RBAC already granted for every other check
// in this file (persistentvolumeclaims and statefulsets are already listed by
// checkPVCPending/checkStatefulSetReplicas; pods by checkPodPendingTimeout).
// The Pod list is read once, up front, into a set — not re-listed per
// candidate PVC — because unlike resolveRelatedWorkloadForPVC's use (called
// only for a PVC ALREADY flagged, to enrich its message), whether a Pod
// references this claim is part of THIS check's match condition itself, so
// it cannot be deferred to "only for already-flagged candidates" the way that
// helper's own doc comment describes.
//
// # Severity: "low"
//
// This wastes storage quota, and possibly money, forever — but nothing is
// currently failing or blocked, unlike reasonPVCPendingTimeout's "high" (pods
// cannot start). Matches this file's other standing-hygiene-not-active-fault
// findings (deployment-revision-history-limit-zero, pod-evicted-not-cleaned-up
// in default-rules.yaml, both "low" for the same reason).
func checkOrphanedPVC(ctx context.Context, snap *sweepSnapshot, now time.Time, sustainedThreshold time.Duration) ([]sweepCandidate, error) {
	stsList, err := snap.statefulSets(ctx)
	if err != nil {
		return nil, err
	}
	if len(stsList.Items) == 0 {
		// Nothing that could own a volumeClaimTemplate PVC at all.
		return nil, nil
	}
	pvcList, err := snap.persistentVolumeClaims(ctx)
	if err != nil {
		return nil, err
	}
	podList, err := snap.pods(ctx)
	if err != nil {
		return nil, err
	}

	// referencedClaims is built once, up front — see the doc comment above
	// for why this cannot be deferred to only already-flagged candidates the
	// way resolveRelatedWorkloadForPVC's callers do.
	referencedClaims := make(map[string]bool, len(podList.Items))
	for i := range podList.Items {
		pod := &podList.Items[i]
		for _, vol := range pod.Spec.Volumes {
			if vol.PersistentVolumeClaim != nil {
				referencedClaims[pod.Namespace+"/"+vol.PersistentVolumeClaim.ClaimName] = true
			}
		}
	}

	stsByNamespace := make(map[string][]appsv1.StatefulSet)
	for _, s := range stsList.Items {
		stsByNamespace[s.Namespace] = append(stsByNamespace[s.Namespace], s)
	}

	var out []sweepCandidate
	for _, pvc := range pvcList.Items {
		if pvc.Status.Phase != corev1.ClaimBound {
			continue
		}
		for _, sts := range stsByNamespace[pvc.Namespace] {
			ordinal, ok := parseStatefulSetPVCTemplateName(pvc.Name, sts.Name)
			if !ok {
				continue
			}
			desired := int32(1)
			if sts.Spec.Replicas != nil {
				desired = *sts.Spec.Replicas
			}
			if ordinal < int(desired) {
				// In range — this ordinal is (or should be) a live member of
				// the StatefulSet today, not orphaned.
				continue
			}
			if referencedClaims[pvc.Namespace+"/"+pvc.Name] {
				// A Pod still mounts it — e.g. a StatefulSet mid-scale-up
				// whose Pod for this ordinal hasn't been (re)created yet from
				// a pre-existing claim. Not orphaned while something still
				// depends on it.
				continue
			}
			out = append(out, sweepCandidate{
				GVK: "v1/PersistentVolumeClaim", Namespace: pvc.Namespace, Name: pvc.Name, UID: string(pvc.UID), ResourceVersion: pvc.ResourceVersion,
				Reason: reasonOrphanedPVC,
				Message: fmt.Sprintf("PersistentVolumeClaim was created from StatefulSet %s/%s's volumeClaimTemplate for ordinal %d, but spec.replicas is now %d and no Pod currently references this claim — it is retaining storage that will never be reclaimed on its own (the common default persistentVolumeClaimRetentionPolicy.whenScaled: Retain)",
					sts.Namespace, sts.Name, ordinal, desired),
				Severity:   "low",
				Class:      tunnel.FindingClassRisk,
				Confidence: tunnel.FindingConfidenceVerified,
				Impact:     tunnel.FindingImpactPotential,
				// Neither the PVC's nor the StatefulSet's own age says when
				// the scale-down that orphaned this claim happened — gated on
				// observed duration instead, same reasoning as
				// checkServiceNoEndpoints.
				OccurredAt: now,
				// The StatefulSet this claim was made FOR, not one it
				// currently belongs to (nothing currently references it) —
				// the same "causally linked to a workload it does NOT own or
				// belong to" case RelatedWorkloadGVK/Name exists for (see
				// sweepCandidate's own doc comment), reused here for the same
				// reason: WorkloadGVK/WorkloadName is reserved for
				// checkPodPendingTimeout's pod-to-owner correlation.
				RelatedWorkloadGVK:  "apps/v1/StatefulSet",
				RelatedWorkloadName: sts.Name,
			})
			// One StatefulSet match is enough per PVC — a name cannot
			// simultaneously belong to two StatefulSets in the same
			// namespace by this convention (see
			// parseStatefulSetPVCTemplateName's doc comment).
			break
		}
	}
	return out, nil
}

// parseStatefulSetPVCTemplateName parses pvcName against the
// volumeClaimTemplate naming CONTRACT — not a convention — for stsName:
// "<template-name>-<stsName>-<ordinal>". Returns the parsed ordinal and
// ok=true only when pvcName ends with "-<stsName>-" followed by one or more
// digits and something non-empty (the template name) precedes it.
//
// Matched against the LAST occurrence of "-<stsName>-" in pvcName, not the
// first: a template name that itself contains stsName as a substring (e.g.
// StatefulSet "web" and volumeClaimTemplate "web-data", giving PVC name
// "web-data-web-0") must still resolve the split point closest to the
// ordinal, which the rightmost occurrence always is.
func parseStatefulSetPVCTemplateName(pvcName, stsName string) (ordinal int, ok bool) {
	marker := "-" + stsName + "-"
	idx := strings.LastIndex(pvcName, marker)
	if idx <= 0 {
		// idx == 0 would mean an empty template name ("" + "-sts-0"), which
		// volumeClaimTemplate naming never produces — the template name is
		// always a real, non-empty prefix.
		return 0, false
	}
	tail := pvcName[idx+len(marker):]
	if tail == "" {
		return 0, false
	}
	n, err := strconv.Atoi(tail)
	if err != nil || n < 0 {
		return 0, false
	}
	return n, true
}

// checkFailedJobs flags a Job whose JobFailed condition is True — already a
// terminal, unambiguous outcome, so this doesn't apply
// defaultSweepSustainedThreshold the way the other checks do (there's no "briefly,
// normally True during a rollout" case to wait out for a Job that has
// already finished failing).
func checkFailedJobs(ctx context.Context, snap *sweepSnapshot, now time.Time, sustainedThreshold time.Duration) ([]sweepCandidate, error) {
	list, err := snap.jobs(ctx)
	if err != nil {
		return nil, err
	}
	var out []sweepCandidate
	for _, j := range list.Items {
		var failed *batchv1.JobCondition
		for i := range j.Status.Conditions {
			if j.Status.Conditions[i].Type == batchv1.JobFailed && j.Status.Conditions[i].Status == corev1.ConditionTrue {
				failed = &j.Status.Conditions[i]
				break
			}
		}
		if failed == nil {
			continue
		}

		// A failure with no timestamp is reported once (we cannot tell how old
		// it is, and refusing would mean never reporting it); one with a
		// timestamp is only reported while it is still recent — see
		// sweepFailedJobMaxAge for why an unbounded window was actively harmful.
		occurredAt := now
		if !failed.LastTransitionTime.IsZero() {
			occurredAt = failed.LastTransitionTime.Time
			if now.Sub(occurredAt) > sweepFailedJobMaxAge {
				continue
			}
		}
		c := sweepCandidate{
			GVK: "batch/v1/Job", Namespace: j.Namespace, Name: j.Name, UID: string(j.UID), ResourceVersion: j.ResourceVersion,
			Reason:  reasonJobFailed,
			Message: fmt.Sprintf("Job failed: %s: %s", failed.Reason, failed.Message),
			// Terminal and authoritative: no sustain wait applies.
			Severity:      "high",
			SustainedFrom: occurredAt,
			OccurredAt:    occurredAt,
		}
		// A CronJob's run belongs to the CronJob: every failing run is the
		// same fault, and without the workload each one opened its own
		// incident (loop campaign 2026-10-13, S09). Same resolution the
		// event detector uses (workload.go).
		if owner := metav1.GetControllerOf(&j); owner != nil && owner.Kind == "CronJob" {
			c.WorkloadGVK = formatGVK(schema.FromAPIVersionAndKind(owner.APIVersion, owner.Kind))
			c.WorkloadName = owner.Name
		}
		out = append(out, c)
	}
	return out, nil
}

// checkNodeNotReady flags a Node whose Ready condition is not True for at
// least defaultSweepSustainedThreshold — a fleet-wide, potentially very
// high-blast-radius problem (everything scheduled to that node), hence
// "critical" rather than this file's usual "high". A Node reporting no
// Ready condition at all is treated the same as NotReady (that's itself
// abnormal — every real kubelet reports one), using "now" as its
// transition time since there's nothing else to measure from.
func checkNodeNotReady(ctx context.Context, snap *sweepSnapshot, now time.Time, sustainedThreshold time.Duration) ([]sweepCandidate, error) {
	list, err := snap.nodes(ctx)
	if err != nil {
		return nil, err
	}
	var out []sweepCandidate
	for _, n := range list.Items {
		var ready *corev1.NodeCondition
		for i := range n.Status.Conditions {
			if n.Status.Conditions[i].Type == corev1.NodeReady {
				ready = &n.Status.Conditions[i]
				break
			}
		}
		if ready != nil && ready.Status == corev1.ConditionTrue {
			continue
		}

		// A Node reporting no Ready condition at all is abnormal in itself
		// (every real kubelet reports one) and is treated as NotReady — but the
		// previous version of this code could never actually report it: it set
		// transitionedAt = now and then required now-transitionedAt >=
		// threshold, i.e. 0 >= 10m, so the branch was dead on every sweep while
		// its own doc comment claimed otherwise. Now it leaves SustainedFrom
		// zero and lets runOneSweep gate on observed duration, which is the
		// honest measure when the node tells us nothing.
		var sustainedFrom time.Time
		reason, message := "NoReadyCondition", "Node has never reported a Ready condition"
		if ready != nil {
			reason, message = ready.Reason, ready.Message
			if !ready.LastTransitionTime.IsZero() {
				sustainedFrom = ready.LastTransitionTime.Time
				if now.Sub(sustainedFrom) < sustainedThreshold {
					continue
				}
			}
		}

		out = append(out, sweepCandidate{
			GVK: "v1/Node", Namespace: "", Name: n.Name, UID: string(n.UID), ResourceVersion: n.ResourceVersion,
			Reason:        reasonNodeNotReady,
			Message:       nodeNotReadyMessage(now, sustainedFrom, reason, message),
			Severity:      "critical",
			SustainedFrom: sustainedFrom,
			OccurredAt:    firstNonZeroTime(sustainedFrom, now),
		})
	}
	return out, nil
}

// checkNodePressureConditions flags a Node reporting MemoryPressure,
// DiskPressure, or PIDPressure as True for at least defaultSweepSustainedThreshold.
// Unlike NodeReady, these three conditions are inverted — True means a real,
// active problem (the kubelet is evicting pods to relieve memory/disk
// pressure, or refusing to admit new processes under PID pressure), not
// health — and each is checked independently since a node can be under one
// kind of pressure without the others. Severity "high" rather than
// checkNodeNotReady's "critical": a node under pressure is still scheduling
// and running most workloads, a narrower blast radius than a fully NotReady
// node.
func checkNodePressureConditions(ctx context.Context, snap *sweepSnapshot, now time.Time, sustainedThreshold time.Duration) ([]sweepCandidate, error) {
	list, err := snap.nodes(ctx)
	if err != nil {
		return nil, err
	}

	pressureConditions := []struct {
		conditionType corev1.NodeConditionType
		reason        string
	}{
		{corev1.NodeMemoryPressure, reasonNodeMemoryPressure},
		{corev1.NodeDiskPressure, reasonNodeDiskPressure},
		{corev1.NodePIDPressure, reasonNodePIDPressure},
	}

	var out []sweepCandidate
	for _, n := range list.Items {
		for _, pc := range pressureConditions {
			var cond *corev1.NodeCondition
			for i := range n.Status.Conditions {
				if n.Status.Conditions[i].Type == pc.conditionType {
					cond = &n.Status.Conditions[i]
					break
				}
			}
			if cond == nil || cond.Status != corev1.ConditionTrue {
				continue
			}
			if cond.LastTransitionTime.IsZero() || now.Sub(cond.LastTransitionTime.Time) < sustainedThreshold {
				continue
			}

			out = append(out, sweepCandidate{
				GVK: "v1/Node", Namespace: "", Name: n.Name, UID: string(n.UID), ResourceVersion: n.ResourceVersion,
				Reason: pc.reason,
				Message: fmt.Sprintf("Node has reported %s=True for %s (%s: %s)",
					pc.conditionType, now.Sub(cond.LastTransitionTime.Time).Round(time.Second), cond.Reason, cond.Message),
				Severity:      "high",
				SustainedFrom: cond.LastTransitionTime.Time,
				OccurredAt:    cond.LastTransitionTime.Time,
			})
		}
	}
	return out, nil
}

// nodeNotReadyMessage phrases the finding differently depending on whether the
// node told us when it went NotReady — reporting a duration we don't actually
// know would be a fabricated number in an operator-facing message.
func nodeNotReadyMessage(now, sustainedFrom time.Time, reason, message string) string {
	if sustainedFrom.IsZero() {
		return fmt.Sprintf("Node is NotReady with no transition time reported (%s: %s)", reason, message)
	}
	return fmt.Sprintf("Node has been NotReady for %s (%s: %s)",
		now.Sub(sustainedFrom).Round(time.Second), reason, message)
}

// firstNonZeroTime returns a if set, else b — used for OccurredAt, which must
// always carry a real timestamp even when the cluster gave us none.
func firstNonZeroTime(a, b time.Time) time.Time {
	if !a.IsZero() {
		return a
	}
	return b
}

// checkHPAScalingBlocked flags a HorizontalPodAutoscaler that has not been
// doing its job for at least the sustained threshold — an easy-to-miss signal
// that throws no Warning Event of its own once the original attempt's events
// age out.
//
// TWO conditions, not one, because checking only AbleToScale missed the more
// common failure entirely. An HPA scaling on CPU utilisation against a
// container that declares no CPU request reports:
//
//	AbleToScale=True    reason=SucceededGetScale
//	ScalingActive=False reason=FailedGetResourceMetric
//
// AbleToScale means "I can read and write the target's scale subresource" —
// still perfectly true here. ScalingActive means "I can actually compute a
// desired replica count and act on it," which is the part that is broken:
// utilisation is a percentage OF the request, so with no request the metric is
// undefined and the autoscaler is inert. It looks configured in `kubectl get
// hpa` (beyond a quiet `<unknown>/70%`), it raises no event, and it does
// nothing at all — which is discovered during the traffic spike it was
// supposed to absorb. Verified live on a real cluster: the original
// AbleToScale-only check did not fire for that HPA at all.
//
// Reported as two distinct reasons rather than one, because they need
// different responses: a blocked HPA has lost its target, an inert one is
// misconfigured but pointed at the right thing.
//
// ScalingActive=False with reason ScalingDisabled is deliberately EXCLUDED:
// that is what the API server reports for an intentionally disabled
// autoscaler (a target scaled to zero, minReplicas=0), which is a choice
// somebody made, not a fault.
func checkHPAScalingBlocked(ctx context.Context, snap *sweepSnapshot, now time.Time, sustainedThreshold time.Duration) ([]sweepCandidate, error) {
	list, err := snap.horizontalPodAutoscalers(ctx)
	if err != nil {
		return nil, err
	}
	var out []sweepCandidate
	for _, hpa := range list.Items {
		// hpaCondition finds one condition by type, or nil. Declared per-HPA
		// rather than as a package helper because it closes over this HPA's
		// own condition slice, and taking a pointer into a loop variable's
		// field is exactly the aliasing bug that convention avoids.
		hpaCondition := func(t autoscalingv2.HorizontalPodAutoscalerConditionType) *autoscalingv2.HorizontalPodAutoscalerCondition {
			for i := range hpa.Status.Conditions {
				if hpa.Status.Conditions[i].Type == t {
					return &hpa.Status.Conditions[i]
				}
			}
			return nil
		}

		// Checked in severity order, and only ONE candidate is emitted per
		// HPA: a target it cannot reach at all subsumes an inert metric, and
		// reporting both would be two incidents for one broken autoscaler —
		// the duplication problem this codebase is already trying to reduce
		// (see BACKLOG.md A1).
		if c := hpaCondition(autoscalingv2.AbleToScale); c != nil && c.Status == corev1.ConditionFalse {
			if !c.LastTransitionTime.IsZero() && now.Sub(c.LastTransitionTime.Time) >= sustainedThreshold {
				out = append(out, hpaCandidate(hpa, reasonHPAScalingBlocked,
					fmt.Sprintf("HorizontalPodAutoscaler cannot scale its target: %s: %s", c.Reason, c.Message), c))
			}
			continue
		}

		if c := hpaCondition(autoscalingv2.ScalingActive); c != nil && c.Status == corev1.ConditionFalse {
			// See the doc comment: a deliberately disabled autoscaler is not a
			// fault.
			if c.Reason == "ScalingDisabled" {
				continue
			}
			if !c.LastTransitionTime.IsZero() && now.Sub(c.LastTransitionTime.Time) >= sustainedThreshold {
				out = append(out, hpaCandidate(hpa, reasonHPAMetricsUnavailable,
					fmt.Sprintf("HorizontalPodAutoscaler is not autoscaling — it can reach its target but cannot compute a desired replica count: %s: %s", c.Reason, c.Message), c))
			}
		}
	}
	return out, nil
}

// hpaCandidate builds the sweepCandidate both HPA checks above share, so the
// GVK string, severity and the SustainedFrom/OccurredAt pair are written once
// and cannot drift between the two reasons.
func hpaCandidate(hpa autoscalingv2.HorizontalPodAutoscaler, reason, message string,
	cond *autoscalingv2.HorizontalPodAutoscalerCondition) sweepCandidate {
	return sweepCandidate{
		GVK: "autoscaling/v2/HorizontalPodAutoscaler", Namespace: hpa.Namespace, Name: hpa.Name,
		UID: string(hpa.UID), ResourceVersion: hpa.ResourceVersion,
		Reason:        reason,
		Message:       message,
		Severity:      "medium",
		SustainedFrom: cond.LastTransitionTime.Time,
		OccurredAt:    cond.LastTransitionTime.Time,
	}
}

// checkServiceNoEndpoints flags a selector-based Service with zero ready
// endpoints across every EndpointSlice that belongs to it — "nothing
// behind this Service can currently receive traffic," a real, common
// failure (every backing Pod crashed, a label selector typo, a readiness
// probe that never passes) that throws no Warning Event of its own at all;
// the Service object itself just quietly serves nothing. Skips
// ExternalName Services (no selector/endpoints ever apply) and any Service
// with no selector at all (headless/manually-managed-Endpoints services —
// "no endpoints" isn't necessarily a problem for those, and this file has
// no reliable way to tell a deliberate empty Endpoints object from a
// broken one in that case).
func checkServiceNoEndpoints(ctx context.Context, snap *sweepSnapshot, now time.Time, sustainedThreshold time.Duration) ([]sweepCandidate, error) {
	services, err := snap.services(ctx)
	if err != nil {
		return nil, err
	}
	slices, err := snap.endpointSlices(ctx)
	if err != nil {
		return nil, err
	}

	readyByService := make(map[string]bool, len(slices.Items))
	for _, s := range slices.Items {
		svcName := s.Labels["kubernetes.io/service-name"]
		if svcName == "" {
			continue
		}
		key := s.Namespace + "/" + svcName
		if readyByService[key] {
			continue
		}
		for _, ep := range s.Endpoints {
			if ep.Conditions.Ready == nil || *ep.Conditions.Ready {
				readyByService[key] = true
				break
			}
		}
	}

	var out []sweepCandidate
	for _, svc := range services.Items {
		if len(svc.Spec.Selector) == 0 || svc.Spec.Type == corev1.ServiceTypeExternalName {
			continue
		}
		if readyByService[svc.Namespace+"/"+svc.Name] {
			continue
		}

		// BACKLOG.md A3b, the selector-based half: which Pod(s) in this same
		// namespace this Service's own selector matches, and what workload
		// (if any) owns them — resolved only for a Service already flagged
		// as lacking ready endpoints, never for every Service in the
		// cluster, and via a server-side label-selector List rather than a
		// client-side scan. See internal/agent/objectref.go's doc comment
		// for the full cost argument and internal/objectgroup for what this
		// enables hub-side.
		relatedGVK, relatedName, _ := resolveRelatedWorkloadForSelector(ctx, snap.clientset, svc.Namespace, svc.Spec.Selector)

		out = append(out, sweepCandidate{
			GVK: "v1/Service", Namespace: svc.Namespace, Name: svc.Name, UID: string(svc.UID), ResourceVersion: svc.ResourceVersion,
			Reason: reasonServiceNoEndpoints,
			Message: "Service has a selector but no ready endpoints — nothing behind it can currently receive traffic" +
				relatedWorkloadDescription(relatedGVK, relatedName),
			// No authoritative timestamp (EndpointSlices carry no "empty
			// since"), and the Service's own age is meaningless here — a
			// year-old Service whose one backend is mid-restart is not a
			// sustained outage. Gated on observed duration instead.
			Severity:            "high",
			Class:               tunnel.FindingClassRisk,
			Confidence:          tunnel.FindingConfidenceVerified,
			Impact:              tunnel.FindingImpactPotential,
			OccurredAt:          now,
			RelatedWorkloadGVK:  relatedGVK,
			RelatedWorkloadName: relatedName,
		})
	}
	return out, nil
}

// checkServiceTargetPortUnresolved flags a Service whose port asked for a
// NAMED targetPort that no backing container declares — "this Service has
// healthy-looking endpoints and still blackholes every request."
//
// # Why checkServiceNoEndpoints does not already cover this
//
// That check asks whether anything is behind the Service, and here something
// is: the pod is running, ready, selected, and listed in the EndpointSlice.
// What is missing is the PORT. Verified live on rke2 (WORKLOG §178) against a
// pod declaring only containerPort 8080:
//
//	SLICE                    SVC                PORTS    ADDRS          READY
//	portmatch-named-9kdfs    portmatch-named    <none>   [10.42.1.24]   true
//	portmatch-numeric-k7rwz  portmatch-numeric  9090     [10.42.1.24]   true
//	portmatch-ok-8xb86       portmatch-ok       8080     [10.42.1.24]   true
//
// The named case does NOT drop the endpoint as one might expect — the endpoint
// stays ready and the slice's `ports` is written as NULL (not as an entry with a
// nil port, which is what a first implementation here assumed; the assumption
// passed its own unit test and then found nothing on a live cluster). So every
// existing signal
// says healthy: no Warning Event (nothing failed), no Pod status transition
// (the pod is fine), ready endpoints (so checkServiceNoEndpoints skips it).
// The Service is completely broken and nothing in this agent noticed.
//
// # The signal, and why it carries no guesswork
//
// A nil port in an EndpointSlice is kube-controller-manager reporting that IT
// could not resolve the name — not an inference of ours. That makes this a
// fact read off the cluster, in the spirit of detector.go's reviewed severity
// table rather than a heuristic.
//
// # Why the NUMERIC mismatch above is deliberately NOT flagged
//
// portmatch-numeric is equally broken and equally invisible, and it is the more
// common typo — but "targetPort 9090 is not in the container's declared ports"
// does not prove breakage. containerPort declarations are informational in
// Kubernetes: a container may listen on a port it never declares, and plenty
// do. Flagging that would mean paging a human, and spending real analysis
// money, on a workload that is fine. This detector reports only what the
// cluster itself has already declared unresolvable; the numeric case is
// recorded as a known non-detection in docs/FAILURE_MODES.md instead of
// guessed at here.
func checkServiceTargetPortUnresolved(ctx context.Context, snap *sweepSnapshot, now time.Time, sustainedThreshold time.Duration) ([]sweepCandidate, error) {
	services, err := snap.services(ctx)
	if err != nil {
		return nil, err
	}
	slices, err := snap.endpointSlices(ctx)
	if err != nil {
		return nil, err
	}

	// Per Service: the set of port NAMES the slices resolved, and whether any
	// endpoint is ready.
	type portState struct {
		resolved map[string]bool
		anyReady bool
	}
	byService := make(map[string]*portState, len(slices.Items))
	for _, sl := range slices.Items {
		svcName := sl.Labels["kubernetes.io/service-name"]
		if svcName == "" {
			continue
		}
		key := sl.Namespace + "/" + svcName
		st := byService[key]
		if st == nil {
			st = &portState{resolved: map[string]bool{}}
			byService[key] = st
		}
		for _, ep := range sl.Endpoints {
			if ep.Conditions.Ready == nil || *ep.Conditions.Ready {
				st.anyReady = true
				break
			}
		}
		for _, p := range sl.Ports {
			// A nil Port is the same "did not resolve" statement as the name
			// being absent from the list entirely; either way it contributes
			// nothing to the resolved set.
			if p.Port == nil {
				continue
			}
			// EndpointPort.Name mirrors the SERVICE port's name (empty for a
			// single unnamed port), which is what lets an unresolved entry be
			// attributed back to the right ServicePort below.
			name := ""
			if p.Name != nil {
				name = *p.Name
			}
			st.resolved[name] = true
		}
	}

	var out []sweepCandidate
	for _, svc := range services.Items {
		if len(svc.Spec.Selector) == 0 || svc.Spec.Type == corev1.ServiceTypeExternalName {
			continue
		}
		st := byService[svc.Namespace+"/"+svc.Name]
		// No slices, or nothing ready behind it: that is
		// checkServiceNoEndpoints' finding, and emitting a second one here
		// would be two incidents for one broken Service.
		if st == nil || !st.anyReady {
			continue
		}
		// No separate "the slices may not be written yet" guard: the
		// endpointslice controller computes endpoints and ports in the same
		// object write, so a slice that already carries a READY endpoint has
		// necessarily had this Service's ports resolved too. An empty resolved
		// set on such a slice is the controller's answer, not a race.
		var broken []string
		for _, sp := range svc.Spec.Ports {
			// Only a named targetPort can fail to resolve. A numeric one is
			// used verbatim (see the doc comment), and an omitted targetPort
			// defaults to the Service port, which always resolves.
			if sp.TargetPort.Type != intstr.String || sp.TargetPort.StrVal == "" {
				continue
			}
			if st.resolved[sp.Name] {
				continue
			}
			label := sp.Name
			if label == "" {
				label = fmt.Sprintf("port %d", sp.Port)
			}
			broken = append(broken, fmt.Sprintf("%s -> %q", label, sp.TargetPort.StrVal))
		}
		if len(broken) == 0 {
			continue
		}
		out = append(out, sweepCandidate{
			GVK: "v1/Service", Namespace: svc.Namespace, Name: svc.Name, UID: string(svc.UID), ResourceVersion: svc.ResourceVersion,
			Reason: reasonServiceTargetPortUnresolved,
			Message: fmt.Sprintf("Service has ready endpoints but Kubernetes could not resolve its named targetPort (%s) on any backing container — requests to this Service are silently dropped",
				strings.Join(broken, ", ")),
			// "high", matching checkServiceNoEndpoints: the user-visible
			// effect is identical (no traffic is served), and this variant is
			// harder for a human to spot precisely because the Service looks
			// healthy from every angle a dashboard shows.
			Severity: "high",
			// Same reasoning as checkServiceNoEndpoints: EndpointSlices carry
			// no "unresolved since", and the Service's own age says nothing
			// about how long this has been true. Gated on observed duration by
			// sustainedLongEnough instead.
			OccurredAt: now,
		})
	}
	return out, nil
}

// checkWebhookBackingServiceUnreachable is PROJECT.md B149's webhook half:
// a ValidatingWebhookConfiguration or MutatingWebhookConfiguration whose
// `clientConfig.service` names a Service with zero ready endpoints. This is
// deliberately generic across every registered webhook of both kinds, not a
// detector for one named webhook — exactly the shape the direction asks for
// ("mechanisms not per-case hardcoding").
//
// # Why this is the high-blast-radius half of B149, not the CEL half
//
// checkGenericAdmissionPolicyTypeChecking (this file's sibling) already
// covers a ValidatingAdmissionPolicy's own statically-detectable CEL errors.
// That is a narrower problem: one policy, matched objects only. A webhook
// with an unreachable backing service is categorically worse — every write
// to every kind and namespace that webhook's `rules` match fails outright
// (a default `failurePolicy: Fail`) or silently skips validation/mutation
// (`failurePolicy: Ignore`), and nothing about the failure names the webhook
// as the cause: an operator sees a wall of unrelated "admission webhook ...
// denied the request" or "... failed calling webhook" errors on completely
// different objects, with no Kubernetes-native signal pointing back at the
// one broken Service behind it.
//
// # Why Service/EndpointSlice, not calling the webhook itself
//
// This agent's identity is read-only (argus-context's non-negotiable 1) and
// has no business synthesizing an AdmissionReview request just to see what
// comes back — that would also only prove reachability from this agent's
// own pod, not from the API server, which is the caller that actually
// matters. "Does the backing Service have any ready endpoint" is the same
// generically-true precondition checkServiceNoEndpoints already asks for an
// ordinary Service, reused here rather than re-implemented, because a
// webhook backing Service with zero ready endpoints cannot possibly answer
// the API server either way — TCP has nothing to connect to.
//
// # What this deliberately does NOT cover
//
//   - `clientConfig.url` (an out-of-cluster or non-Service endpoint):
//     skipped. There is no Service/EndpointSlice to check reachability
//     against, and probing an arbitrary URL from a read-only cluster agent
//     is a different, riskier mechanism this task does not build.
//   - A backing Service with a ready endpoint that nonetheless returns
//     malformed responses, wrong TLS, or times out under real load: also
//     not caught. "Has a ready endpoint" is necessary, not sufficient, for
//     "actually answers admission review calls correctly" — the same
//     honest scope boundary checkServiceNoEndpoints itself draws for an
//     ordinary Service.
//   - Runtime-only CEL evaluation errors in a ValidatingAdmissionPolicy
//     against one specific object: that is checkGenericAdmissionPolicyTypeChecking's
//     own documented, separate scope boundary, unchanged by this check.
//
// Left unclassified (no Class/Confidence/Impact set on the candidate) like
// checkGenericObservedGenerationLag/checkGenericStuckFinalizer/
// checkGenericAdmissionPolicyTypeChecking: normalizeFindingEvidence's
// default for an unset tuple is Fault/Verified/Degraded, which promotes.
// This is deliberately NOT in the Class=Anomaly family (checkGenericConditions/
// checkGenericDanglingReference/checkGenericPeerOutlier, B153's own subject) —
// there is no legitimate "deliberately broken webhook" state the way a
// Service can legitimately have no selector-based endpoints; a registered
// webhook whose backing Service cannot be reached is confidently, always a
// fault.
func checkWebhookBackingServiceUnreachable(ctx context.Context, snap *sweepSnapshot, now time.Time, sustainedThreshold time.Duration) ([]sweepCandidate, error) {
	validating, err := snap.validatingWebhookConfigurations(ctx)
	if err != nil {
		return nil, err
	}
	mutating, err := snap.mutatingWebhookConfigurations(ctx)
	if err != nil {
		return nil, err
	}

	type webhookRef struct {
		configGVK, configName, webhookName, namespace, serviceName, failurePolicy string
	}
	var refs []webhookRef
	for _, cfg := range validating.Items {
		for _, wh := range cfg.Webhooks {
			if wh.ClientConfig.Service == nil {
				continue
			}
			refs = append(refs, webhookRef{
				configGVK: "admissionregistration.k8s.io/v1/ValidatingWebhookConfiguration", configName: cfg.Name, webhookName: wh.Name,
				namespace: wh.ClientConfig.Service.Namespace, serviceName: wh.ClientConfig.Service.Name,
				failurePolicy: string(derefFailurePolicy(wh.FailurePolicy)),
			})
		}
	}
	for _, cfg := range mutating.Items {
		for _, wh := range cfg.Webhooks {
			if wh.ClientConfig.Service == nil {
				continue
			}
			refs = append(refs, webhookRef{
				configGVK: "admissionregistration.k8s.io/v1/MutatingWebhookConfiguration", configName: cfg.Name, webhookName: wh.Name,
				namespace: wh.ClientConfig.Service.Namespace, serviceName: wh.ClientConfig.Service.Name,
				failurePolicy: string(derefFailurePolicy(wh.FailurePolicy)),
			})
		}
	}
	if len(refs) == 0 {
		return nil, nil
	}

	// One targeted EndpointSlice List per DISTINCT backing service, by the
	// same label EndpointSlices always carry back to their owning Service
	// (kubernetes.io/service-name) — cheap, since a cluster registers far
	// fewer webhooks than it runs Services, unlike checkServiceNoEndpoints's
	// own bulk-list-everything approach, which would be the wrong shape
	// here for a handful of lookups.
	readyCache := map[string]bool{}
	serviceExistsCache := map[string]bool{}
	var out []sweepCandidate
	for _, ref := range refs {
		cacheKey := ref.namespace + "/" + ref.serviceName
		ready, cached := readyCache[cacheKey]
		if !cached {
			var err error
			ready, err = anyReadyEndpointForService(ctx, snap, ref.namespace, ref.serviceName)
			if err != nil {
				return nil, err
			}
			readyCache[cacheKey] = ready
		}
		if ready {
			continue
		}
		exists, cachedExists := serviceExistsCache[cacheKey]
		if !cachedExists {
			// From the sweep's one Service list, not a per-webhook Get
			// (PROJECT.md P17(a)). This also removes a way the message could
			// be wrong: a transient Get error used to read as "the Service
			// itself does not exist", because the old code inferred absence
			// from any error at all. A list failure now propagates as an
			// error instead of being narrated as a missing Service.
			services, err := snap.services(ctx)
			if err != nil {
				return nil, err
			}
			for i := range services.Items {
				if services.Items[i].Namespace == ref.namespace && services.Items[i].Name == ref.serviceName {
					exists = true
					break
				}
			}
			serviceExistsCache[cacheKey] = exists
		}
		absence := "no ready endpoints"
		if !exists {
			absence = "the Service itself does not exist"
		}
		out = append(out, sweepCandidate{
			GVK: ref.configGVK, Namespace: "", Name: ref.configName,
			Reason: reasonWebhookBackingServiceUnreachable,
			Message: fmt.Sprintf("webhook %q's backing Service %s/%s has %s — every write matching this webhook's rules currently %s (failurePolicy=%s)",
				ref.webhookName, ref.namespace, ref.serviceName, absence,
				webhookBlockOrSkipVerb(ref.failurePolicy), orDefaultFailurePolicy(ref.failurePolicy)),
			Severity:   "critical",
			OccurredAt: now,
		})
	}
	return out, nil
}

// derefFailurePolicy returns admissionregistrationv1.Ignore's zero-value
// stand-in ("" — meaning the API server's own default of Fail applies) when
// nil, rather than panicking on a nil pointer dereference. Kept as its own
// tiny function so every call site reads the same way.
func derefFailurePolicy(p *admissionregistrationv1.FailurePolicyType) admissionregistrationv1.FailurePolicyType {
	if p == nil {
		return ""
	}
	return *p
}

// orDefaultFailurePolicy names what the API server actually does when
// FailurePolicy is unset: defaults to Fail per the admissionregistration.k8s.io/v1
// API's own documented default, so the message names the real behavior
// rather than an empty string.
func orDefaultFailurePolicy(p string) string {
	if p == "" {
		return string(admissionregistrationv1.Fail)
	}
	return p
}

// webhookBlockOrSkipVerb names the user-visible consequence for the message
// text: Fail blocks every matching write outright, Ignore silently admits
// them unvalidated/unmutated — very different failure shapes worth naming
// distinctly rather than one blended "this is broken" sentence.
func webhookBlockOrSkipVerb(failurePolicy string) string {
	if orDefaultFailurePolicy(failurePolicy) == string(admissionregistrationv1.Ignore) {
		return "skips this webhook (failurePolicy: Ignore silently admits without it)"
	}
	return "fails outright"
}

// anyReadyEndpointForService reports whether at least one EndpointSlice
// belonging to namespace/name has at least one Ready (or unspecified-Ready,
// matching checkServiceNoEndpoints's own "Ready == nil means ready" reading
// of the API's own documented default) endpoint. A Service with no
// EndpointSlices at all (never created, or the Service itself does not
// exist) correctly reads as "not ready" — the caller distinguishes "no
// Service" from "Service but no ready endpoint" separately, for the message
// text only; both are equally unreachable.
func anyReadyEndpointForService(ctx context.Context, snap *sweepSnapshot, namespace, name string) (bool, error) {
	// Answered from the sweep's one cluster-wide EndpointSlice list rather
	// than a fresh namespace-scoped, label-selected List per webhook backing
	// Service (PROJECT.md P17(a)): checkServiceNoEndpoints has already paid
	// for that list this pass, and a cluster with several webhook
	// configurations used to issue one extra List per distinct backing
	// Service on top of it. The filter below is exactly what the server-side
	// selector did — EndpointSlice's kubernetes.io/service-name is a plain
	// equality label — so this selects the same slices.
	slices, err := snap.endpointSlices(ctx)
	if err != nil {
		return false, err
	}
	for _, s := range slices.Items {
		if s.Namespace != namespace || s.Labels["kubernetes.io/service-name"] != name {
			continue
		}
		for _, ep := range s.Endpoints {
			if ep.Conditions.Ready == nil || *ep.Conditions.Ready {
				return true, nil
			}
		}
	}
	return false, nil
}

// deploymentByNamespacedName finds one Deployment in an already-listed
// DeploymentList, returning nil when the list does not contain it — the
// snapshot-served replacement for a per-object Get, with the same
// "not there" outcome a NotFound produced. A linear scan: the one caller
// looks up at most one Deployment per distinct HPA scale target, and
// building an index for that would cost more than it saves on any cluster
// where the HPA count is not itself the problem.
func deploymentByNamespacedName(list *appsv1.DeploymentList, namespace, name string) *appsv1.Deployment {
	for i := range list.Items {
		if list.Items[i].Namespace == namespace && list.Items[i].Name == name {
			return &list.Items[i]
		}
	}
	return nil
}

// checkIngressBackendMissing flags an Ingress whose backend is broken in
// either of two provable ways: it routes to a Service which does not exist in
// its namespace at all (reasonIngressBackendMissing), or it routes to a
// Service that DOES exist but whose port does not match anything the Service
// actually declares (reasonIngressBackendPortMismatch, BACKLOG.md AN1 /
// issue-catalog ING-005). Either way, every request to that path fails at the
// ingress controller, and nothing in Kubernetes complains.
//
// Certain rather than inferred, which is what makes both halves safe to
// report: a Service is either in the API or it is not, and its
// `spec.ports` either contains a port matching the backend's requested name/
// number or it does not — no heuristic in either case. Nobody points an
// Ingress at a Service (or a Service port) on purpose and leaves it wrong —
// this is a typo, a rename, or a Service whose ports changed out from under a
// chart that still references the old one.
//
// Both backend positions are checked, because either one breaks traffic and the
// second is the easier to forget: every rule's per-path backend, and the
// Ingress-wide `defaultBackend`. Backends that reference a `resource` rather
// than a `service` are skipped — those point at a cluster-scoped custom object
// this check cannot resolve and has no business guessing about.
//
// # Why the port half is a SEPARATE Reason, not folded into the missing-service
// # candidate
//
// The two are different faults with different fixes (the Service doesn't
// exist at all, vs. it exists but this Ingress asks for the wrong port on it),
// and — same reasoning checkReplicaFailure's own doc comment gives for firing
// alongside checkDeploymentReplicas rather than suppressing one — the hub
// correlates by OBJECT (gvk|namespace|name), so both candidates land on ONE
// incident for this Ingress when both are true; nothing is lost by keeping
// them distinct, and a reader can tell "totally absent" from "present but
// misconfigured" without parsing one blended sentence.
//
// One candidate PER REASON per Ingress, listing every broken backend under
// that reason, rather than one per path: an Ingress with a dozen paths
// pointing at one deleted Service (or one wrong port) is one fault each, and
// the alternative is twelve incidents for it (BACKLOG.md A1).
//
// # Why the port comparator checks name OR number, matching the API itself
//
// `networking.k8s.io/v1.ServiceBackendPort` validation requires exactly one of
// `name`/`number` to be set (never both, never neither) — see
// ingressBackendPortMatches — mirroring how a real Ingress backend can
// reference a Service port either way.
//
// Not covered here, deliberately: `spec.ingressClassName` naming an
// IngressClass that does not exist, which silently leaves the Ingress unclaimed
// by every controller. It is equally provable and equally invisible, but the
// agent's ClusterRole grants no access to `ingressclasses`
// (deploy/helm/argus-agent/templates/clusterrole.yaml), so adding the check
// means widening RBAC — and until every deployed agent has the newer chart, the
// check would fail on every sweep and log a permission error every 30 seconds.
// Worth doing as its own change, with the chart, rather than smuggled in here.
func checkIngressBackendMissing(ctx context.Context, snap *sweepSnapshot, now time.Time, sustainedThreshold time.Duration) ([]sweepCandidate, error) {
	ingresses, err := snap.ingresses(ctx)
	if err != nil {
		return nil, err
	}
	if len(ingresses.Items) == 0 {
		// Most clusters have few or no Ingresses; skip the Services list
		// entirely rather than paying for it on every sweep.
		return nil, nil
	}
	services, err := snap.services(ctx)
	if err != nil {
		return nil, err
	}
	// svcPorts, not just an existence set: AN1 needs each existing Service's
	// actual Spec.Ports to compare a backend's requested port against, reusing
	// this SAME already-fetched Service list rather than a second List call
	// (BACKLOG.md's own framing of this item).
	svcPorts := make(map[string][]corev1.ServicePort, len(services.Items))
	for _, svc := range services.Items {
		svcPorts[svc.Namespace+"/"+svc.Name] = svc.Spec.Ports
	}

	var out []sweepCandidate
	for _, ing := range ingresses.Items {
		// Sets, not slices: one deleted Service (or one wrong port)
		// referenced from eight paths should read as one missing name/port
		// mismatch, not the same one repeated eight times.
		missing := map[string]bool{}
		portMismatches := map[string]string{}
		note := func(backend *networkingv1.IngressBackend) {
			if backend == nil || backend.Service == nil || backend.Service.Name == "" {
				return
			}
			key := ing.Namespace + "/" + backend.Service.Name
			ports, ok := svcPorts[key]
			if !ok {
				missing[backend.Service.Name] = true
				return
			}
			if !ingressBackendPortMatches(backend.Service.Port, ports) {
				desc := formatIngressBackendPort(backend.Service.Port)
				// Keyed by service+port descriptor, so the same broken
				// reference named on several paths collapses to one entry —
				// same reasoning as the `missing` set above.
				portMismatches[backend.Service.Name+"|"+desc] = fmt.Sprintf(
					"Service %s (requested port %s, but Service's actual ports are: %s)",
					backend.Service.Name, desc, formatServicePorts(ports))
			}
		}
		note(ing.Spec.DefaultBackend)
		for _, rule := range ing.Spec.Rules {
			if rule.HTTP == nil {
				continue
			}
			for i := range rule.HTTP.Paths {
				note(&rule.HTTP.Paths[i].Backend)
			}
		}

		if len(missing) > 0 {
			names := make([]string, 0, len(missing))
			for n := range missing {
				names = append(names, n)
			}
			// Sorted so the message — and therefore the fingerprint's
			// message, and what an operator reads twice — is stable across
			// sweeps rather than reordered by map iteration.
			sort.Strings(names)
			out = append(out, sweepCandidate{
				GVK: "networking.k8s.io/v1/Ingress", Namespace: ing.Namespace, Name: ing.Name,
				UID: string(ing.UID), ResourceVersion: ing.ResourceVersion,
				Reason: reasonIngressBackendMissing,
				Message: fmt.Sprintf("Ingress routes to Service(s) that do not exist in namespace %s: %s — requests to those paths cannot reach a backend",
					ing.Namespace, strings.Join(names, ", ")),
				Severity: "high",
				// The Ingress's own age says nothing: a year-old Ingress whose
				// Service was deleted a minute ago is a fresh fault, and a
				// just-created Ingress may be waiting for its Service to appear
				// from the same chart. Gated on observed duration instead, which
				// is also what stops a normal apply-ordering race from reporting.
				OccurredAt: now,
			})
		}

		if len(portMismatches) > 0 {
			descs := make([]string, 0, len(portMismatches))
			for _, d := range portMismatches {
				descs = append(descs, d)
			}
			sort.Strings(descs)
			out = append(out, sweepCandidate{
				GVK: "networking.k8s.io/v1/Ingress", Namespace: ing.Namespace, Name: ing.Name,
				UID: string(ing.UID), ResourceVersion: ing.ResourceVersion,
				Reason: reasonIngressBackendPortMismatch,
				Message: fmt.Sprintf("Ingress in namespace %s routes to a port that does not exist on its target Service: %s — requests to those paths cannot reach a backend even though the Service itself exists",
					ing.Namespace, strings.Join(descs, "; ")),
				Severity: "high",
				// Same reasoning as the missing-service candidate above: age
				// of neither object says anything about when the port
				// mismatch began (a Service's ports can change independently
				// of the Ingress at any time), so this is gated on observed
				// duration instead.
				OccurredAt: now,
			})
		}
	}
	return out, nil
}

// ingressBackendPortMatches reports whether port — an Ingress backend's
// requested Service port, referenced by exactly one of Name or Number per
// networking.k8s.io/v1's own validation — matches any port actually declared
// on the target Service.
//
// A backend with NEITHER Name nor Number set (Number==0 and Name=="") cannot
// occur on an object the API server accepted (one of the two is required),
// but is treated as "matches" rather than flagged here regardless: this
// checker reports only what it can prove, and there is nothing to compare
// against for a backend port this checker cannot even identify.
func ingressBackendPortMatches(port networkingv1.ServiceBackendPort, svcPorts []corev1.ServicePort) bool {
	if port.Name != "" {
		for _, sp := range svcPorts {
			if sp.Name == port.Name {
				return true
			}
		}
		return false
	}
	if port.Number == 0 {
		return true
	}
	for _, sp := range svcPorts {
		if sp.Port == port.Number {
			return true
		}
	}
	return false
}

// formatIngressBackendPort renders a backend port for an operator-facing
// message, naming which of the two reference styles (by name or by number)
// was actually used — the same distinction ingressBackendPortMatches itself
// branches on.
func formatIngressBackendPort(port networkingv1.ServiceBackendPort) string {
	if port.Name != "" {
		return fmt.Sprintf("%q (by name)", port.Name)
	}
	return fmt.Sprintf("%d (by number)", port.Number)
}

// formatServicePorts renders a Service's actual spec.Ports for the same
// message, so a reader sees exactly what WOULD have matched without a second
// lookup.
func formatServicePorts(ports []corev1.ServicePort) string {
	if len(ports) == 0 {
		return "(none)"
	}
	parts := make([]string, 0, len(ports))
	for _, p := range ports {
		if p.Name != "" {
			parts = append(parts, fmt.Sprintf("%s (%d)", p.Name, p.Port))
		} else {
			parts = append(parts, fmt.Sprintf("%d", p.Port))
		}
	}
	return strings.Join(parts, ", ")
}

// checkIngressHostPathCollision flags two (or more) DIFFERENT Ingress objects
// that declare the same `host` with overlapping `path`/`pathType` rules —
// BACKLOG.md AX1, issue-catalog ING-009. ingress-nginx (and every other
// controller in practice) resolves this by silently picking one and shadowing
// the other; there is nothing invalid about either Ingress object on its own,
// so neither admission nor any single-object check (including
// checkIngressBackendMissing above) can ever see it — this is the one check
// in this file that is explicitly cross-Ingress rather than per-object.
//
// # Scope: cluster-wide, matching checkIngressBackendMissing's own
//
// Two Ingresses colliding on `host` are very often in DIFFERENT namespaces
// (that's the actual live-confirmed shape in CAPABILITIES.md §6bo — a
// forgotten shared-domain Ingress left behind in another team's namespace) —
// a per-namespace scope would miss the exact case this check exists for. The
// same List already used for checkIngressBackendMissing's own cluster-wide
// scope is reused here as a separate call (each sweepChecker lists what it
// needs independently, same as checkServiceNoEndpoints/
// checkServiceTargetPortUnresolved's independent Service+EndpointSlice
// lists), so this needs no new RBAC.
//
// # What counts as "overlapping", and why it's a segment-prefix test
//
// Two Exact paths overlap only when they are identical strings — Exact
// routing does not do prefix matching, so "/foo" and "/foo/bar" as two Exact
// rules genuinely do not collide. Everything else (Prefix, or the
// ImplementationSpecific default, treated the same conservative way as Prefix
// since ingress-nginx's actual default behaviour for it IS prefix-like)
// overlaps when one path's segments are a prefix of the other's — "/foo"
// (Prefix) collides with "/foo/bar" (any type) but not with "/foobar" (not a
// segment boundary), matching how ingress-nginx itself decides which rule a
// request path matches. See pathsOverlap.
//
// # One candidate per Ingress, not per collision or per pair
//
// A single Ingress can collide with more than one other Ingress (or with
// several rules on the same other Ingress); this reports ONE candidate per
// involved Ingress, naming every host/partner combination found, rather than
// one per pairwise collision — same "one fault, one candidate" reasoning as
// checkIngressBackendMissing's own doc comment (BACKLOG.md A1). Both
// Ingresses in a colliding pair get their own candidate (symmetric), so
// whichever one an operator is looking at names the other.
//
// # Why DIFFERENT `spec.ingressClassName` values are never flagged
//
// This is the reason FAILURE_MODES.md's own Ingress section originally
// rejected this check outright: two Ingresses CAN legitimately share a host
// and path when two DIFFERENT controllers each own one of them (a common
// internal/external-facing split, e.g. `ingressClassName: nginx-internal` vs.
// `nginx-external`) — that is a normal, supported, multi-controller
// deployment, not a fault, and flagging it would page a human about a
// configuration that is working as intended. This check is only safe to ship
// because it can read `spec.ingressClassName` for free (no RBAC beyond what
// checkIngressBackendMissing already uses) and skips a pair where BOTH
// Ingresses name an EXPLICIT class and those classes differ — see
// ingressClassesCanCollide. It still flags the case BACKLOG.md AX1/
// issue-catalog ING-009 actually asks for and CAPABILITIES.md §6bo actually
// reproduced: two Ingresses with no class named at all (both resolve to the
// SAME cluster default) or both naming the SAME class — the case where one
// controller genuinely has to arbitrate between them.
func checkIngressHostPathCollision(ctx context.Context, snap *sweepSnapshot, now time.Time, sustainedThreshold time.Duration) ([]sweepCandidate, error) {
	ingresses, err := snap.ingresses(ctx)
	if err != nil {
		return nil, err
	}
	if len(ingresses.Items) < 2 {
		// Nothing to collide with.
		return nil, nil
	}

	type pathEntry struct {
		ingressKey   string // namespace/name
		ingressClass string
		path         string
		pathType     networkingv1.PathType
	}
	byHost := make(map[string][]pathEntry)
	ingressByKey := make(map[string]*networkingv1.Ingress, len(ingresses.Items))
	for i := range ingresses.Items {
		ing := &ingresses.Items[i]
		key := ing.Namespace + "/" + ing.Name
		ingressByKey[key] = ing
		class := ""
		if ing.Spec.IngressClassName != nil {
			class = *ing.Spec.IngressClassName
		}
		for _, rule := range ing.Spec.Rules {
			if rule.Host == "" || rule.HTTP == nil {
				continue
			}
			for _, p := range rule.HTTP.Paths {
				pt := networkingv1.PathTypeImplementationSpecific
				if p.PathType != nil {
					pt = *p.PathType
				}
				byHost[rule.Host] = append(byHost[rule.Host], pathEntry{ingressKey: key, ingressClass: class, path: p.Path, pathType: pt})
			}
		}
	}

	// collisions[ingressKey][host] = set of colliding partner ingressKeys —
	// nested so one candidate's message can group by host (a single Ingress
	// may collide on one host and not another) without re-deriving that
	// grouping from a flat list.
	collisions := make(map[string]map[string]map[string]bool)
	addCollision := func(key, host, partnerKey string) {
		if collisions[key] == nil {
			collisions[key] = make(map[string]map[string]bool)
		}
		if collisions[key][host] == nil {
			collisions[key][host] = make(map[string]bool)
		}
		collisions[key][host][partnerKey] = true
	}

	for host, entries := range byHost {
		for i := 0; i < len(entries); i++ {
			for j := i + 1; j < len(entries); j++ {
				a, b := entries[i], entries[j]
				if a.ingressKey == b.ingressKey {
					// Two paths on the SAME Ingress object are that object's
					// own business, not a cross-Ingress collision this check
					// is about.
					continue
				}
				if !ingressClassesCanCollide(a.ingressClass, b.ingressClass) {
					// Two EXPLICIT, DIFFERENT classes: a supported
					// multi-controller split, not a fault — see this
					// function's own doc comment.
					continue
				}
				if !pathsOverlap(a.path, a.pathType, b.path, b.pathType) {
					continue
				}
				addCollision(a.ingressKey, host, b.ingressKey)
				addCollision(b.ingressKey, host, a.ingressKey)
			}
		}
	}

	// Deterministic iteration order: map iteration order is randomized, and
	// this candidate list must not reorder between sweeps (candidateFingerprint
	// doesn't depend on message content, but the message an operator reads
	// twice should be stable regardless).
	keys := make([]string, 0, len(collisions))
	for k := range collisions {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var out []sweepCandidate
	for _, key := range keys {
		ing := ingressByKey[key]
		if ing == nil {
			continue
		}
		hosts := make([]string, 0, len(collisions[key]))
		for h := range collisions[key] {
			hosts = append(hosts, h)
		}
		sort.Strings(hosts)

		var parts []string
		for _, h := range hosts {
			partners := make([]string, 0, len(collisions[key][h]))
			for p := range collisions[key][h] {
				partners = append(partners, p)
			}
			sort.Strings(partners)
			parts = append(parts, fmt.Sprintf("host %q also claimed by Ingress(es) %s", h, strings.Join(partners, ", ")))
		}

		out = append(out, sweepCandidate{
			GVK: "networking.k8s.io/v1/Ingress", Namespace: ing.Namespace, Name: ing.Name,
			UID: string(ing.UID), ResourceVersion: ing.ResourceVersion,
			Reason: reasonIngressHostPathCollision,
			Message: fmt.Sprintf("Ingress declares the SAME host and path as a DIFFERENT Ingress object: %s — nothing in the Ingress spec breaks that tie, so the controller chooses arbitrarily (ingress-nginx picks whichever object is older and logs a warning); neither object is individually invalid. Nested paths on a shared host are NOT reported: longest match resolves those deterministically",
				strings.Join(parts, "; ")),
			Severity: "high",
			// Neither Ingress's age says when the collision began (either
			// side could have been created first, and either could have been
			// edited most recently to introduce the overlap) — gated on
			// observed duration instead, same reasoning as every other
			// Ingress/Service check in this file with no authoritative
			// timestamp to read.
			OccurredAt: now,
		})
	}
	return out, nil
}

// ingressClassesCanCollide reports whether two Ingresses naming classA/classB
// could actually be arbitrated by the SAME controller — see
// checkIngressHostPathCollision's own doc comment for why this exists at all.
// An empty class means "no `spec.ingressClassName` set", which resolves to
// whatever IngressClass in the cluster carries the default annotation — the
// SAME one for every such Ingress — so it can always collide with another
// empty class, or with an explicit one (that explicit class might BE the
// cluster's default; this checker cannot read IngressClass objects to know
// for certain, so it stays on the side of flagging rather than silently
// missing the case FAILURE_MODES.md's row worried about the least: two
// otherwise-identical Ingresses that both simply left the field unset).
// Only two EXPLICIT, DIFFERENT class names are treated as certainly separate
// controllers.
func ingressClassesCanCollide(classA, classB string) bool {
	if classA == "" || classB == "" {
		return true
	}
	return classA == classB
}

// pathsOverlap decides whether two Ingress path rules would collide at the
// ingress controller — see checkIngressHostPathCollision's doc comment for
// the reasoning. Exact-vs-Exact requires an identical path; any other
// combination (Prefix, or the ImplementationSpecific default, both treated
// the same conservative way) overlaps when one path's segments are a prefix
// of the other's.
// pathsOverlap reports whether two paths on the same host, declared by two
// DIFFERENT Ingress objects, are genuinely ambiguous — meaning no rule decides
// which one serves a request that matches both.
//
// # Why this is narrower than "one path contains the other"
//
// It used to return true whenever either path was a segment-prefix of the
// other, and that produced a false positive on the single most common Ingress
// layout there is: a root application on "/" plus sibling applications on
// sub-paths. Measured on one real cluster on 2026-09-09, that shape accounted
// for **every** shared-host case — one host carried "/" plus fifteen distinct
// sub-paths, another "/" plus three — and had produced 18 incidents and 288
// findings, all of them wrong. The message asserted "the ingress controller
// will silently pick one and shadow the other", which is simply not what
// happens.
//
// Nested paths are resolved DETERMINISTICALLY, by both the API and every real
// controller:
//
//   - The Ingress spec: where two paths are equally matched, an Exact path type
//     takes precedence over Prefix.
//   - ingress-nginx orders paths by descending length before emitting location
//     blocks, so "/softpack" is matched ahead of "/". Traefik and HAProxy
//     resolve longest-match the same way.
//
// So "/" and "/softpack" coexist by design. Reporting that as a fault told an
// operator their working configuration was broken, which is worse than
// reporting nothing.
//
// What IS ambiguous is two different Ingress objects declaring the SAME path on
// the same host. Nothing in the spec breaks that tie; ingress-nginx picks by
// oldest CreationTimestamp and logs a warning, which is exactly the "silently
// picks one" behaviour the original message described — it was the right
// warning attached to the wrong predicate.
//
// # ImplementationSpecific is deliberately excluded
//
// Its matching semantics are, by definition, the controller's own — commonly a
// regex, which ingress-nginx applies first-match rather than longest-match. A
// claim about shadowing between two ImplementationSpecific paths would be a
// guess about software ARGUS cannot see, so this returns false for them rather
// than inventing a verdict. That is a stated boundary, not an oversight: the
// cost is that a genuine regex collision goes unreported, and the alternative
// is asserting a fault that may not exist.
func pathsOverlap(pathA string, typeA networkingv1.PathType, pathB string, typeB networkingv1.PathType) bool {
	if typeA == networkingv1.PathTypeImplementationSpecific || typeB == networkingv1.PathTypeImplementationSpecific {
		return false
	}

	normA, normB := normaliseIngressPath(pathA), normaliseIngressPath(pathB)
	if normA != normB {
		// Distinct paths, including the nested case. Longest match decides.
		return false
	}

	// Identical paths. Exact-versus-Prefix on the same path is NOT ambiguous —
	// the spec gives Exact precedence — so only a matching pair of types
	// leaves the controller with an arbitrary choice to make.
	return typeA == typeB
}

// normaliseIngressPath makes two spellings of the same path compare equal.
// Only the trailing slash is significant here: "/app" and "/app/" select the
// same prefix, and an Ingress author may write either.
func normaliseIngressPath(p string) string {
	if p == "" {
		return "/"
	}
	if p == "/" {
		return "/"
	}
	return strings.TrimSuffix(p, "/")
}

// sendSweepFinding computes c's fingerprint, applies the resend-dedup
// cooldown, and sends the resulting Finding non-blockingly — same
// fingerprint/cooldown/send shape as detector.go's handleWatchedEvent and
// pod_conditions_detector.go's sendPodFinding. kind is taken from the tail
// of GVK (after the last "/") rather than threaded through as a separate
// field, matching internal/agent/tools.go's parseGVKString convention for
// the same wire shape elsewhere in this package.
func sendSweepFinding(c sweepCandidate, fp string, now time.Time, findingCh chan<- tunnel.Finding, lastSent map[string]time.Time, cooldown time.Duration) {
	if !shouldSend(fp, now, lastSent, cooldown) {
		return
	}

	class := c.Class
	if class == "" {
		class = tunnel.FindingClassFault
	}
	confidence := c.Confidence
	if confidence == "" {
		confidence = tunnel.FindingConfidenceVerified
	}
	impact := c.Impact
	if impact == "" {
		impact = tunnel.FindingImpactDegraded
	}

	f := tunnel.Finding{
		DetectorID:          sweepDetectorID,
		DetectorVersion:     sweepDetectorVersion,
		Fingerprint:         fp,
		GVK:                 c.GVK,
		Namespace:           c.Namespace,
		ObjectName:          c.Name,
		ObjectUID:           c.UID,
		ResourceVersion:     c.ResourceVersion,
		Reason:              c.Reason,
		Message:             c.Message,
		OccurrenceCount:     1,
		Severity:            c.Severity,
		Class:               class,
		Confidence:          confidence,
		Impact:              impact,
		OccurredAt:          c.OccurredAt,
		WorkloadGVK:         c.WorkloadGVK,
		WorkloadName:        c.WorkloadName,
		PodPriority:         c.PodPriority,
		RelatedWorkloadGVK:  c.RelatedWorkloadGVK,
		RelatedWorkloadName: c.RelatedWorkloadName,
		RuleID:              c.RuleID,

		ConditionType:             c.ConditionType,
		ConditionObservedValue:    c.ConditionObservedValue,
		ConditionSampleCount:      c.ConditionSampleCount,
		ConditionMajorityValue:    c.ConditionMajorityValue,
		ConditionMajorityFraction: c.ConditionMajorityFraction,
		ConditionParentPath:       c.ConditionParentPath,
		References:                c.References,
	}

	// PROJECT.md B176: lastSent is stamped ONLY on a delivered finding. It
	// used to be stamped above, before the send was even attempted, so an
	// overflowed finding entered the 5-minute resend cooldown as though it
	// had gone out and the next sweep suppressed it as a duplicate — a
	// transient overflow became indefinite silence about that object.
	if emitFinding(f, findingCh) {
		lastSent[fp] = now
	}
}

// checkPodPendingTimeout is a periodic BACKSTOP for
// pod_conditions_detector.go's own watch-based Pending-timeout check
// (reasonPendingTimeout there), added after that watch-based check was found
// live to sometimes never fire at all.
//
// # WHY A WATCH-BASED CHECK CAN MISS THIS ENTIRELY, NOT JUST SLOWLY
//
// pod_conditions_detector.go's checkPendingTimeout only runs inside
// handleWatchedPod, itself only invoked when the API server delivers an
// ADDED/MODIFIED event for that Pod. A Pod that is genuinely, permanently
// unschedulable (e.g. a resource request no node can ever satisfy) gets
// re-attempted by the scheduler repeatedly, but if each retry produces the
// EXACT SAME PodScheduled=False condition (same reason, same message), the
// scheduler has nothing new to write and does not repatch the Pod object —
// it only re-emits the Event, which lands on a completely different
// watch (detector.go's Warning-events watch, as FailedScheduling) and is
// itself subject to the SAME resend cooldown as any other repeated event.
//
// Verified live: a Pod requesting more CPU/memory than any node in a real
// 5-node cluster could ever satisfy sat Pending for over 6 minutes —
// comfortably past podPendingTimeoutThreshold — with ZERO PendingTimeout
// finding. Its PodScheduled condition's LastTransitionTime never advanced
// past the Pod's own creation instant: the object had received exactly one
// watch delivery (its own creation) in its entire life. checkPendingTimeout
// was therefore evaluated exactly once, at pendingFor≈0, and never again —
// not "detected slowly", genuinely never.
//
// This is precisely the gap sweep_detector.go's own package comment
// describes as its reason to exist: "problems that don't reliably surface as
// ... a Pod status transition." A sustained-condition check that depends on
// receiving a status transition to re-evaluate is not actually a
// sustained-condition check for an object whose status stops transitioning —
// which is exactly the pathological, permanently-stuck case a timeout exists
// to catch.
//
// SAME reason/fingerprint as the watch-based check, deliberately: both paths
// call computeFingerprint("", "Pod", name, reasonPendingTimeout) by construction
// (candidateFingerprint below derives it from GVK+Name+Reason exactly like
// sendPodFinding does), so whichever one fires first — the fast watch path for
// the common case where status genuinely changes, or this slower periodic
// backstop for the pathological case where it doesn't — lands on the SAME
// incident rather than opening a second one for the same Pod.
//
// Uses CreationTimestamp, not SustainedFrom: unlike most sweep checks, a
// Pod's own age IS the right measure here (that's what the pinned
// implementation in pod_conditions_detector.go already measures), so no
// separate observed-since bookkeeping is needed — runOneSweep's
// sustainedLongEnough gate is still applied on top via SustainedFrom, giving
// this check the same "don't fire on the very first sweep after the
// threshold is nominally crossed" debounce every other sweep check gets.
func checkPodPendingTimeout(ctx context.Context, snap *sweepSnapshot, now time.Time, sustainedThreshold time.Duration) ([]sweepCandidate, error) {
	list, err := snap.pods(ctx)
	if err != nil {
		return nil, err
	}
	var out []sweepCandidate
	for _, pod := range list.Items {
		if pod.Status.Phase != corev1.PodPending {
			continue
		}
		if pod.CreationTimestamp.IsZero() {
			continue
		}
		pendingFor := now.Sub(pod.CreationTimestamp.Time)
		if pendingFor < sustainedThreshold {
			continue
		}
		workloadGVK, workloadName, _ := resolveWorkloadFromOwnerRefs(ctx, snap.clientset, pod.Namespace, pod.GetOwnerReferences())
		out = append(out, sweepCandidate{
			GVK: "v1/Pod", Namespace: pod.Namespace, Name: pod.Name, UID: string(pod.UID), ResourceVersion: pod.ResourceVersion,
			Reason:        reasonPendingTimeout,
			Message:       fmt.Sprintf("pod has been Pending for %s (created at %s) — the periodic sweep backstop caught this because the pod's status has not transitioned since creation, so the watch-based check never got a second look", pendingFor.Round(time.Second), pod.CreationTimestamp.Time.Format(time.RFC3339)),
			Severity:      severityForReason(reasonPendingTimeout),
			SustainedFrom: pod.CreationTimestamp.Time,
			OccurredAt:    now,
			WorkloadGVK:   workloadGVK,
			WorkloadName:  workloadName,
			PodPriority:   pod.Spec.Priority,
		})
	}
	return out, nil
}

// minFieldOwnershipFlips is how many times spec.replicas' current field
// manager must have CHANGED IDENTITY, across successive sweeps, before
// checkFieldOwnershipConflict reports a conflict — see
// fieldOwnershipObservation's doc comment for why this checker needs a flip
// COUNT at all rather than a single comparison. 2 is the smallest number
// that distinguishes "a one-time, unremarkable handover" (A owned it, then B
// took over and kept it — one flip, e.g. the object was just created by
// GitOps and an HPA claimed it once afterward) from "these two are actually
// fighting" (A, then B, then A again — proof B's claim didn't stick, which
// is what "conflict" actually means here).
const minFieldOwnershipFlips = 2

// fieldOwnershipObservation is what checkFieldOwnershipConflict remembers,
// ACROSS SWEEPS, about one Deployment's spec.replicas field-manager history.
//
// # Why this checker needs memory at all, unlike every other checker in this file
//
// The first version of this check compared managers within a SINGLE
// managedFields snapshot (matching how objdiff.OwnersOf is used at its other
// call site, internal/api/remediation_exec.go's fieldContentionDetail) —
// looking for two managers claiming spec.replicas at once. Live
// verification against a real Argo CD + HPA fixture on the rke2 cluster
// (BACKLOG.md E10) proved that premise wrong: Kubernetes' own managedFields
// bookkeeping makes ownership of one field EXCLUSIVE at every instant. The
// moment the HPA controller's `scale` subresource write lands, spec.replicas
// is reassigned away from whichever manager held it before (argocd-controller,
// in the live fixture) — that manager's OWN managedFieldsEntry for the object
// survives (it still claims other fields, like spec.template/spec.selector),
// but its claim on THIS ONE leaf is gone, replaced outright, never shared.
// ~30 samples at 1-second resolution, across both classic Argo sync and true
// Server-Side-Apply, showed zero co-occurrence: exactly one manager owned
// spec.replicas at every single sample. So a single List/Get, timed however
// well, can never observe "two owners of one field" for this exact fault —
// the conflict is only visible by comparing the SAME field's owner ACROSS
// TIME and noticing it keeps changing back and forth, which a field with one
// legitimate, stable owner never does.
type fieldOwnershipObservation struct {
	// Managers is every distinct manager observed claiming spec.replicas for
	// this object so far, while it has continuously been both HPA-targeted
	// and GitOps-owned. Cleared (the whole entry deleted, see
	// checkFieldOwnershipConflict's pruning pass) the moment either
	// condition stops holding, so history doesn't survive an HPA/GitOps
	// binding being removed and reattached to an unrelated later conflict.
	Managers map[string]bool
	// LastManager is the owner observed on the most recent sweep, compared
	// against the next sweep's owner to detect a flip.
	LastManager string
	// Flips counts how many times LastManager has changed. See
	// minFieldOwnershipFlips for why 1 is not enough on its own.
	Flips int
}

// fieldOwnershipHistory is checkFieldOwnershipConflict's own cross-sweep
// memory (see fieldOwnershipObservation's doc comment for why this one
// checker, uniquely in this file, cannot decide anything from a single
// snapshot). Keyed by "namespace/deploymentName".
//
// Package-level rather than threaded through sweepChecker.fn's parameters
// (the shape every other checker in sweepCheckers shares) because adding a
// checker-specific parameter would mean changing that one shared function
// signature — and therefore every other checker's declaration — for a need
// only this checker has. Safe without a mutex: every sweepChecker.fn call
// happens sequentially from runOneSweep's single ticker goroutine, the same
// no-lock assumption runSweepDetector's own lastSent/firstObserved maps
// already rely on one level up. Tests that call checkFieldOwnershipConflict
// directly must call resetFieldOwnershipHistoryForTest between cases so one
// test's accumulated flip history cannot leak into another's.
var fieldOwnershipHistory = map[string]*fieldOwnershipObservation{}

// resetFieldOwnershipHistoryForTest clears fieldOwnershipHistory. Test-only
// (see fieldOwnershipHistory's own doc comment); not gated behind a build
// tag because nothing outside this package can reach it, matching this
// file's existing convention of test-only helpers living alongside the code
// they reset (compare sweepCheckers itself, saved/restored by
// TestRunOneSweep_OneCheckFailingDoesNotBlockOthers rather than hidden
// behind a tag).
func resetFieldOwnershipHistoryForTest() {
	fieldOwnershipHistory = map[string]*fieldOwnershipObservation{}
}

// checkFieldOwnershipConflict flags a Deployment whose `spec.replicas`
// field-manager identity keeps flipping back and forth between a
// HorizontalPodAutoscaler (via its own `scaleTargetRef`) and a GitOps
// reconciler (Argo CD or Flux) — BACKLOG.md E10's "two owners of one field"
// predicate shape, issue-catalog DEPL-012. See fieldOwnershipObservation's
// doc comment for why this is a flip count over time rather than a
// same-instant comparison.
//
// # Why nothing already sees this
//
// Every other check in this file (and every rule in default-rules.yaml)
// answers "what does THIS object's status say", one object at a time.
// DEPL-012 has no such symptom: both writers believe they are doing the
// right thing, the Deployment's own `status` never enters a failure state
// (`Available=True` throughout — each write is individually valid, just
// disagreeing about the *value*), and no Warning Event fires because
// nothing errors. The only place the conflict is visible at all is
// `metadata.managedFields` — which manager currently claims which field —
// and that requires `internal/objdiff.OwnersOf`, a comparison this file had
// never called before this check (E10's review found it built for
// remediation's `PatchField` guardrail and "not wired to detection").
//
// # Why this is HPA-and-GitOps specifically, not "any two managers ever"
//
// A Deployment can perfectly legitimately have `spec.replicas` change hands
// ONCE (created by GitOps, then a human does a one-off `kubectl scale`) —
// that is not a fault, which is exactly why minFieldOwnershipFlips requires
// more than one change. What makes DEPL-012 a real, ongoing fault is that
// BOTH sides reassert on a recurring cycle: an HPA recomputes and rewrites
// spec.replicas on every metrics tick, while Argo/Flux revert it to the
// manifest value on every sync — so the object churns forever, which shows
// up as repeated flips, not a single handover. That is why this check also
// requires an HPA whose `scaleTargetRef` actually names this Deployment AND
// a GitOps controller recognized by ownershipFromMetadata's strong signals
// (Argo's self-referencing tracking-id, or a Flux annotation) — restricted
// to "argocd"/"flux" specifically, not "fleet"/"helm" too, because those are
// the two DESIGN.md §11.2 documents as continuously-reconciling (a plain
// `helm install` release does not revert a live edit on its own; nothing
// here claims it does) — the flip-history mechanism alone, with neither
// precondition, would just as happily "detect" any Deployment whose
// spec.replicas some human manually toggled twice by hand, which is not
// this predicate's job and not something this checker has any business
// reporting on.
//
// # Field-specific, not object-level — the whole point of this predicate shape
//
// A Deployment can be GitOps-managed and HPA-targeted at once with NO
// conflict at all, when the manifest simply omits `replicas` (the common,
// correct pattern for an HPA-scaled workload) — Argo/Flux then own
// everything else but never touch `spec.replicas` at all, so OwnersOf never
// reports them as a candidate owner of that path, LastManager never changes
// away from the HPA's own manager, and Flips stays 0 forever. This check
// would be worthless — and wrong far more often than right — if it fired on
// "GitOps-managed AND HPA-targeted" alone; it only fires once the SAME
// field's owner has genuinely and repeatedly changed identity.
//
// # Why a typed Deployment's ManagedFields needs converting first
//
// objdiff deliberately has no Kubernetes imports (fieldowner.go's own doc
// comment) and works from a plain `map[string]any`, matching what the
// dynamic client's `unstructured.Unstructured.Object` already looks like.
// This file's sweepCheckers use the typed `kubernetes.Interface` clientset
// instead (appsv1.Deployment, whose ManagedFields is a typed
// `[]metav1.ManagedFieldsEntry`), so managedFieldsToOwnershipObject converts
// once, per Deployment, rather than adding a Kubernetes dependency to
// objdiff or moving this check to the dynamic-client checker list for no
// other reason.
//
// # Cost and RBAC
//
// Nothing of its own: both the HorizontalPodAutoscaler list and the
// Deployment list it resolves scale targets against are the sweep's one
// shared per-pass snapshot (checkHPAScalingBlocked and
// checkDeploymentReplicas are the other readers) — no new resource type, no
// new verb, so no chart/RBAC change is needed.
//
// # Severity: "medium"
//
// Matches hpaCandidate's own "medium" for HPAScalingBlocked/
// HPAMetricsUnavailable — the same family (an HPA not doing its actual job)
// rather than checkOrphanedPVC's "low" (nothing is currently failing) or
// checkIngressHostPathCollision's "high" (traffic is silently misrouted
// right now). Here nothing is down, but autoscaling itself is defeated:
// under real load the HPA raises replicas and the next GitOps sync reverts
// them, so the one moment autoscaling exists to handle is exactly when it
// silently doesn't work — a real, recurring functional problem, not
// (currently) an outage.
func checkFieldOwnershipConflict(ctx context.Context, snap *sweepSnapshot, now time.Time, sustainedThreshold time.Duration) ([]sweepCandidate, error) {
	deployments, err := snap.deployments(ctx)
	if err != nil {
		return nil, err
	}
	hpas, err := snap.horizontalPodAutoscalers(ctx)
	if err != nil {
		return nil, err
	}
	if len(hpas.Items) == 0 {
		return nil, nil
	}

	// checkedTargets dedupes the Deployment Get call when more than one HPA
	// names the same scaleTargetRef (already a fault checkHPAScalingBlocked's
	// AmbiguousSelector branch would separately catch, but nothing here
	// assumes it can't happen).
	checkedTargets := make(map[string]bool)
	// inScope collects every object key confirmed HPA-targeted AND
	// GitOps-owned THIS sweep, so the pruning pass below can forget anything
	// that has stopped being both, rather than keeping a stale flip count
	// forever (see fieldOwnershipHistory's own doc comment).
	inScope := make(map[string]bool)

	var out []sweepCandidate
	for _, hpa := range hpas.Items {
		ref := hpa.Spec.ScaleTargetRef
		// Scope: DEPL-012's own shape is a Deployment. ref.APIVersion is
		// conventionally "apps/v1" but is not always set by every manifest
		// generator, so only the group prefix is checked, not the exact
		// string.
		if ref.Kind != "Deployment" || (ref.APIVersion != "" && !strings.HasPrefix(ref.APIVersion, "apps/")) {
			continue
		}
		key := hpa.Namespace + "/" + ref.Name
		if checkedTargets[key] {
			continue
		}
		checkedTargets[key] = true

		// Resolved out of the sweep's one Deployment list rather than a Get
		// per distinct scale target (PROJECT.md P17(a)) — on a cluster with
		// hundreds of HPAs that was hundreds of extra requests every pass,
		// for objects the sweep had already listed. A List carries
		// metadata.managedFields, which is the only part of the object this
		// check reads, so nothing is lost.
		dep := deploymentByNamespacedName(deployments, hpa.Namespace, ref.Name)
		if dep == nil {
			// A dangling scaleTargetRef is a real problem, but a
			// different shape (nothing to compare managedFields
			// against) — not this check's job.
			continue
		}

		self := objectIdentity{Kind: "Deployment", Group: "apps", Namespace: dep.Namespace, Name: dep.Name}
		ownership := ownershipFromMetadata(dep.Labels, dep.Annotations, self, nil)
		if ownership == nil || (ownership.ManagedBy != "argocd" && ownership.ManagedBy != "flux") {
			// No reconciling GitOps controller in the picture — an HPA that
			// is the only writer of spec.replicas is exactly the healthy
			// case, and a plain Helm release/Fleet bundle's ownership signal
			// alone does not establish the recurring-reassertion behavior
			// this check is about (see doc comment above).
			continue
		}
		inScope[key] = true

		obj := managedFieldsToOwnershipObject(dep.ManagedFields)
		owners := objdiff.OwnersOf(obj, "spec.replicas")
		current := currentFieldManager(owners, argusRemediateFieldManager)
		if current == "" {
			// Nobody (other than possibly ARGUS itself) currently claims
			// this field at all — nothing to compare against yet.
			continue
		}

		obs := fieldOwnershipHistory[key]
		if obs == nil {
			obs = &fieldOwnershipObservation{Managers: map[string]bool{}}
			fieldOwnershipHistory[key] = obs
		}
		obs.Managers[current] = true
		if obs.LastManager != "" && obs.LastManager != current {
			obs.Flips++
		}
		obs.LastManager = current

		if obs.Flips < minFieldOwnershipFlips {
			// Not yet proven to be a genuine back-and-forth — could still be
			// a single, unremarkable handover. See minFieldOwnershipFlips's
			// own doc comment.
			continue
		}

		managers := make([]string, 0, len(obs.Managers))
		for m := range obs.Managers {
			managers = append(managers, m)
		}
		sort.Strings(managers)

		appDesc := ownership.ManagedBy
		if ownership.AppRef != nil && ownership.AppRef.Name != "" {
			appDesc = fmt.Sprintf("%s (%s %s)", ownership.ManagedBy, ownership.AppRef.Kind, ownership.AppRef.Name)
		}

		out = append(out, sweepCandidate{
			GVK: "apps/v1/Deployment", Namespace: dep.Namespace, Name: dep.Name,
			UID: string(dep.UID), ResourceVersion: dep.ResourceVersion,
			Reason: reasonFieldOwnershipConflict,
			Message: fmt.Sprintf("Deployment's spec.replicas has changed field-manager ownership %d times across sweeps, alternating between %s: HorizontalPodAutoscaler %s/%s scales it live via the scale subresource, while it is also GitOps-managed by %s, which reasserts spec.replicas from its manifest on every sync — the two disagree about the desired replica count, each write is individually valid, and neither side's claim ever sticks, producing a continuous reconcile loop rather than a stable value",
				obs.Flips, strings.Join(managers, ", "), hpa.Namespace, hpa.Name, appDesc),
			Severity: "medium",
			// Neither object's age says when the two managers started
			// disagreeing, and unlike most of this file's other candidates
			// this one is inherently gated on repeated OBSERVATION over time
			// already (obs.Flips), not a single timestamp — OccurredAt is
			// simply "now", same reasoning as checkIngressHostPathCollision's
			// own standing-conflict candidates.
			OccurredAt:          now,
			RelatedWorkloadGVK:  "autoscaling/v2/HorizontalPodAutoscaler",
			RelatedWorkloadName: hpa.Name,
		})
	}

	for key := range fieldOwnershipHistory {
		if !inScope[key] {
			delete(fieldOwnershipHistory, key)
		}
	}

	return out, nil
}

// managedFieldsToOwnershipObject converts a typed ObjectMeta's ManagedFields
// into the `map[string]any` shape internal/objdiff.OwnersOf expects — see
// checkFieldOwnershipConflict's own doc comment for why this conversion is
// needed at all rather than calling OwnersOf directly on a typed object.
func managedFieldsToOwnershipObject(fields []metav1.ManagedFieldsEntry) map[string]any {
	entries := make([]any, 0, len(fields))
	for _, f := range fields {
		entry := map[string]any{
			"manager":   f.Manager,
			"operation": string(f.Operation),
		}
		if f.FieldsV1 != nil && len(f.FieldsV1.Raw) > 0 {
			var fieldsV1 map[string]any
			if err := json.Unmarshal(f.FieldsV1.Raw, &fieldsV1); err == nil {
				entry["fieldsV1"] = fieldsV1
			}
			// A FieldsV1 that fails to unmarshal is left with no "fieldsV1"
			// key at all, which OwnersOf's own `entry["fieldsV1"].(map[string]any)`
			// type-assert treats as "does not claim anything" — the same
			// fail-closed posture objdiff.claims already documents for a
			// malformed set (a false positive here would refuse, or in this
			// checker's case falsely report, a claim that isn't real).
		}
		entries = append(entries, entry)
	}
	return map[string]any{
		"metadata": map[string]any{
			"managedFields": entries,
		},
	}
}

// currentFieldManager returns the single most-specific manager OwnersOf
// reported for a field, skipping any name in ignore (see
// argusRemediateFieldManager's doc comment for why ARGUS's own manager is
// skipped), or "" when nothing else claims it. OwnersOf itself already
// orders exact claims before containment and is stable-sorted (see its own
// doc comment), so the first non-ignored entry here is deterministic.
//
// Live verification (checkFieldOwnershipConflict's doc comment) found that
// real managedFields data for this exact contention pattern never contains
// more than one non-ARGUS claimant at a time — this returns one manager, not
// a set, because that is genuinely what a single snapshot can ever show for
// this predicate; the SET of managers seen is instead accumulated by the
// caller across sweeps (fieldOwnershipObservation.Managers).
func currentFieldManager(owners []objdiff.FieldOwner, ignore ...string) string {
	skip := make(map[string]bool, len(ignore))
	for _, m := range ignore {
		skip[m] = true
	}
	for _, o := range owners {
		if skip[o.Manager] {
			continue
		}
		return o.Manager
	}
	return ""
}
