package agent

// detector_status.go gives each of ARGUS's three built-in detectors
// (detector.go's warning-events watch, pod_conditions_detector.go's pod
// watch, sweep_detector.go's periodic sweep) a small, mutex-protected record
// of its own run health — PROJECT.md T13: today a quiet cluster is
// ambiguous (healthy? disconnected? a detector silently RBAC-denied?), and
// nothing this agent already reports distinguishes those cases. This file
// deliberately reuses two mechanisms this package already has rather than
// inventing new ones:
//
//   - each detector's own watch/sweep loop already knows exactly when it
//     last opened/ran successfully and exactly what error ended its last
//     attempt — recorded here via detectorRunState, written only by that
//     detector's own goroutine;
//   - discovery.go's DiscoverWatchSet / generic_predicates.go's
//     discoveredWatchSetCache (BACKLOG.md E11: ServerPreferredResources()
//     intersected with a SelfSubjectRulesReview) already answers "does this
//     identity's RBAC currently grant get+list+watch on resource X" — no
//     new SelfSubjectAccessReview is issued by this file.
//
// Absent/zero-value discipline (matching tunnel.ClusterRemediation.Checked's
// own documented contract exactly, per this file's own reasoning): a
// detectorRunState that has never recorded a success or an error is not a
// claim that its detector is failing — it is "this agent has not completed
// a run of it yet". tunnel.ClusterFacts.Detectors itself is nil for any
// agent build that predates this field.

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"argus/internal/tunnel"
)

// detectorRunState is one detector's own mutable run-health record, written
// only by that detector's own goroutine and read only by snapshot (called
// from factsWithDetection on every fact-gathering pass — on connect, and
// then every client.go's factsRefreshInterval for as long as the tunnel
// stays up). The mutex exists purely for that single-writer/single-reader
// split.
//
// That cadence is the whole reason this record is worth keeping. Until
// PROJECT.md B177 the gathering pass ran only on connect, so what a detector
// recorded after its session opened — including its very first successful
// sweep — never reached the hub at all, and a working detector reported a
// zero LastSuccessAt for the life of the session.
type detectorRunState struct {
	mu            sync.Mutex
	lastSuccessAt time.Time
	lastErr       string
	lastErrAt     time.Time
	// timedOutChecks is the ONLY field here whose contract is "the pass
	// that just ended" rather than "ever" — see recordCheckerTimeout.
	timedOutChecks []string
}

// recordSuccess marks this detector as having just completed a run — a
// watch's successful open (or an ongoing open watch's own heartbeat tick,
// see detectorSuccessHeartbeatInterval below), or a sweep pass in which no
// checker FAILED — at instant now.
//
// "No checker failed" deliberately includes a pass in which a checker timed
// out (PROJECT.md P19's residual): that pass ran, and everything it got an
// answer from was fine. What it did not get an answer from is recorded
// separately by recordCheckerTimeout, which is why this can now advance
// where it previously could not. Deliberately does NOT touch
// timedOutChecks — that field is assigned exactly once per pass by
// recordCheckerTimeout, and clearing it here would make the order of two
// calls describing the same pass decide the answer.
//
// Deliberately does NOT clear lastErr/lastErrAt: an operator needs "this
// failed at T, and has since recovered" to stay visible rather than being
// silently erased the moment things start working again. A consumer tells
// the two apart by comparing ErrorAt against LastSuccessAt (see
// tunnel.DetectorStatus's own doc comment).
func (s *detectorRunState) recordSuccess(now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastSuccessAt = now
}

// recordError marks this detector's most recent attempt as having failed
// with err at instant now. A nil err is a no-op (never clears anything) —
// callers pass exactly what their own attempt returned, including nil for
// "this attempt was fine", and nil already has no news to report here.
func (s *detectorRunState) recordError(err error, now time.Time) {
	if err == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastErr = err.Error()
	s.lastErrAt = now
}

// sweepCheckerTimeoutPrefix is the stable marker recordCheckerTimeout puts
// in front of the checker names it records, so a consumer of
// tunnel.DetectorStatus.Error can tell a timed-out check from a failed one
// without parsing free text (PROJECT.md P19).
const sweepCheckerTimeoutPrefix = "sweep checker timeout: "

// recordCheckerTimeout records that named sweep checker(s) ran out of time
// at instant now, rather than failed.
//
// This is deliberately a different entry point from recordError even though
// both land in the same two wire fields. An operator looking at a detector
// that reports "the sweep failed" has no idea whether one check is slow or
// the whole detector is dead, and before PROJECT.md P19 there was no way to
// tell: a slow List did not even fail, it hung, and the record simply
// stopped moving. Naming the checkers, behind a stable prefix, makes the two
// distinguishable on the surface the hub already receives.
//
// Called once per sweep pass, ALWAYS — including with an empty names, which
// is how a clean pass clears what the previous one reported. That is what
// makes tunnel.DetectorStatus.TimedOutChecks answerable as "is a check
// hanging right now" rather than as history, and it is the opposite
// contract to Error/ErrorAt, which this also writes and which are never
// cleared. Both are written, deliberately: the named-field answer is for a
// hub that understands TimedOutChecks, and the prefixed Error text is what a
// hub that predates it has always had — dropping the second to add the first
// would take a working signal away from an unrebuilt hub.
//
// This does NOT advance LastSuccessAt. The sweep loop advances it separately
// once it knows no checker actually FAILED (see runSweepDetector's switch),
// which is the change P19's residual asked for: before TimedOutChecks
// existed, one field had to carry both facts and the only safe reading of it
// was the strict one, so a single slow List froze the timestamp for as long
// as it stayed slow.
func (s *detectorRunState) recordCheckerTimeout(names []string, timeout time.Duration, now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	// Assigned, never merged: this describes one pass. Copied rather than
	// retained so a caller's slice (runOneSweep's own accumulator) can never
	// be mutated out from under a concurrent snapshot.
	s.timedOutChecks = append([]string(nil), names...)
	if len(names) == 0 {
		return
	}
	// Says how many checks were NOT blocked, not how many succeeded: this
	// record cannot see whether one of them also failed, and claiming
	// otherwise would be the kind of fabricated count the rest of this
	// codebase refuses to render.
	s.lastErr = fmt.Sprintf("%s%s (no response within %s; the other %d of %d checks in this pass still ran)",
		sweepCheckerTimeoutPrefix, strings.Join(names, ", "), timeout, len(sweepCheckers)-len(names), len(sweepCheckers))
	s.lastErrAt = now
}

// recordSweepPassOutcome is the sweep detector's entire run-health verdict
// for one pass, in one place, because the three outcomes of a pass are easy
// to conflate and PROJECT.md P19's residual is precisely what conflating two
// of them cost:
//
//   - PROJECT.md T13's original signal: a pass in which no checker FAILED is
//     this detector's "run completed successfully", and advances
//     LastSuccessAt. A failing checker is a standing fault (RBAC denies the
//     read, the resource does not exist), records this pass' error, and does
//     NOT advance it — see runOneSweep's own doc comment for why a failure is
//     deliberately all-or-nothing at the detector level rather than tracked
//     per checker.
//   - A checker that ran out of time is a THIRD outcome, not a failure. The
//     check was performed and the cluster did not answer in time, which on a
//     large cluster is a capacity signal about one specific read. It names
//     the checkers on DetectorStatus.TimedOutChecks and, for a hub that
//     predates that field, behind the stable sweepCheckerTimeoutPrefix in
//     Error — so an operator can tell "the service no endpoints check did
//     not answer in 30s" from "the sweep failed" either way. It still
//     advances LastSuccessAt, which it did not before TimedOutChecks existed
//     to say what was missing: freezing that timestamp behind one hung List
//     made a healthy, actively-reporting detector read hub-side as one that
//     had not run since.
//
// recordCheckerTimeout is called unconditionally, even when nothing timed
// out, because TimedOutChecks describes THIS pass and a clean pass has to
// clear what the previous one named. recordError is called after it so a
// hard failure wins the single Error field when a pass produced both: a read
// that is denied outright is the more actionable of the two, and the timed
// out checkers are still named in their own field regardless.
func recordSweepPassOutcome(state *detectorRunState, timedOut []string, err error, checkerTimeout time.Duration, now time.Time) {
	state.recordCheckerTimeout(timedOut, checkerTimeout, now)
	if err != nil {
		state.recordError(err, now)
		return
	}
	state.recordSuccess(now)
}

// snapshot reads this detector's own run-health record. DeniedReads is left
// unset here — the caller (snapshotClusterDetectors) fills it in from the
// discovered-watch-set check, which is keyed by detector ID rather than by
// detectorRunState instance.
func (s *detectorRunState) snapshot() tunnel.DetectorStatus {
	s.mu.Lock()
	defer s.mu.Unlock()
	return tunnel.DetectorStatus{
		LastSuccessAt:  s.lastSuccessAt,
		Error:          s.lastErr,
		ErrorAt:        s.lastErrAt,
		TimedOutChecks: append([]string(nil), s.timedOutChecks...),
	}
}

// Package-level, one instance per built-in detector — the same
// "background goroutine writes, factsWithDetection reads" split
// generic_predicates.go's discoveredWatchSetCache already establishes (see
// that file's own doc comment). Each detector's own goroutine is the only
// writer of its own instance:
//   - warningEventsRunState: detector.go's watchWarningEvents/runWarningEventWatch
//   - podConditionsRunState: pod_conditions_detector.go's watchPodConditions/runPodConditionsWatch
//   - sweepRunState: sweep_detector.go's runSweepDetector
var (
	warningEventsRunState detectorRunState
	podConditionsRunState detectorRunState
	sweepRunState         detectorRunState
)

// detectorSuccessHeartbeatInterval is how often a watch-based detector
// (warning-events, pod-conditions) re-affirms LastSuccessAt while its watch
// stays open with no new delivery to react to.
//
// Without this, a detector's own LastSuccessAt would only ever advance on a
// watch (re)open or an actual event delivery — which starves exactly the
// case this feature exists to surface: a perfectly healthy but genuinely
// quiet cluster (no Warning events, no Pod churn) would show a LastSuccessAt
// that gets staler and staler even though the watch is connected and
// working right now, making "healthy but quiet" indistinguishable from "not
// observed" on a long enough timeline — the exact ambiguity PROJECT.md T13
// exists to remove. One minute is short enough that this heartbeat, not
// event volume, is always the freshest signal of "still connected right
// now".
const detectorSuccessHeartbeatInterval = time.Minute

// detectorRequiredRead is one read a built-in detector needs, named the way
// an operator would recognise it ("events", "jobs") alongside the
// group/resource DiscoverWatchSet's own output is keyed by.
type detectorRequiredRead struct {
	label    string
	group    string
	resource string
}

// requiredDetectorReads is the fixed set of reads each built-in detector
// actually performs, taken straight from this package's own source
// (detector.go/pod_conditions_detector.go's newClientset() + Watch() calls;
// sweep_detector.go's sweepCheckers, grepped rather than guessed) — matching
// PROJECT.md T13's own instruction to enumerate the real, shipped catalogue
// rather than invent an extensible registry. Deliberately limited to
// resources that exist on every stock Kubernetes cluster: sweep_detector.go
// also has CRD-backed dynamicSweepCheckers (Argo CD, Flux, Velero,
// cert-manager Applications/Kustomizations/Backups/Certificates) that are
// legitimately absent on a cluster that never installed those controllers,
// and telling "RBAC denies this" apart from "this CRD was never installed"
// would need the topology-discovery machinery T13 explicitly rules out of
// scope — so those are not claimed as "required" here at all, rather than
// guessed at.
var requiredDetectorReads = map[string][]detectorRequiredRead{
	warningEventsDetectorID: {
		{label: "events", group: "", resource: "events"},
	},
	podConditionsDetectorID: {
		{label: "pods", group: "", resource: "pods"},
	},
	sweepDetectorID: {
		{label: "pods", group: "", resource: "pods"},
		{label: "deployments", group: "apps", resource: "deployments"},
		{label: "statefulsets", group: "apps", resource: "statefulsets"},
		{label: "daemonsets", group: "apps", resource: "daemonsets"},
		{label: "replicasets", group: "apps", resource: "replicasets"},
		{label: "jobs", group: "batch", resource: "jobs"},
		{label: "nodes", group: "", resource: "nodes"},
		{label: "persistentvolumeclaims", group: "", resource: "persistentvolumeclaims"},
		{label: "services", group: "", resource: "services"},
		{label: "endpointslices", group: "discovery.k8s.io", resource: "endpointslices"},
		{label: "horizontalpodautoscalers", group: "autoscaling", resource: "horizontalpodautoscalers"},
		{label: "ingresses", group: "networking.k8s.io", resource: "ingresses"},
		{label: "validatingwebhookconfigurations", group: "admissionregistration.k8s.io", resource: "validatingwebhookconfigurations"},
		{label: "mutatingwebhookconfigurations", group: "admissionregistration.k8s.io", resource: "mutatingwebhookconfigurations"},
	},
}

// detectorDeniedReads answers "which of detectorID's own required reads
// does this agent's RBAC currently NOT grant", sourced from
// generic_predicates.go's discoveredWatchSetCache — the exact same
// ServerPreferredResources ∩ SelfSubjectRulesReview mechanism
// enableDiscoveredWatchSet already wires up for the sweep detector's
// kind-agnostic predicates, reused rather than re-asked.
//
// Returns nil (never an empty non-nil slice) whenever the check itself
// could not be run — discoveredWatchSetCache not yet populated (this
// agent's sweep detector goroutine has not called enableDiscoveredWatchSet
// yet, or has but its first Get has not completed), or a refresh failing
// with no prior cached set — matching DeniedReads' own documented "absent
// means either nothing denied or nothing checked" contract. This is
// deliberately fail-quiet: a transient discovery hiccup must not flip every
// detector to "permission blocked" on the wire.
func detectorDeniedReads(ctx context.Context, detectorID string) []string {
	reads := requiredDetectorReads[detectorID]
	if len(reads) == 0 {
		return nil
	}
	cache := discoveredWatchSetCache.Load()
	if cache == nil {
		return nil
	}
	watchSet, err := cache.Get(ctx)
	if err != nil {
		return nil
	}

	granted := make(map[string]bool, len(watchSet))
	for _, dr := range watchSet {
		granted[dr.GVR.Group+"/"+dr.GVR.Resource] = true
	}

	var denied []string
	for _, r := range reads {
		if !granted[r.group+"/"+r.resource] {
			denied = append(denied, r.label)
		}
	}
	return denied
}

// snapshotClusterDetectors builds the wire-shape tunnel.ClusterDetectors
// from the three package-level detectorRunState instances plus each
// detector's own denied-reads check. Called once per fact-gathering pass
// from factsWithDetection (client.go), bounded by factsTimeout the same way
// every other capability check GatherFacts triggers already is.
func snapshotClusterDetectors(ctx context.Context) *tunnel.ClusterDetectors {
	ctx, cancel := context.WithTimeout(ctx, factsTimeout)
	defer cancel()

	withDenied := func(state *detectorRunState, detectorID string) tunnel.DetectorStatus {
		status := state.snapshot()
		status.DeniedReads = detectorDeniedReads(ctx, detectorID)
		return status
	}

	return &tunnel.ClusterDetectors{
		WarningEvents: withDenied(&warningEventsRunState, warningEventsDetectorID),
		PodConditions: withDenied(&podConditionsRunState, podConditionsDetectorID),
		Sweep:         withDenied(&sweepRunState, sweepDetectorID),
	}
}
