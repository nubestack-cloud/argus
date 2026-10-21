package agent

// PROJECT.md T13: unit coverage for detector_status.go's own run-health
// bookkeeping (detectorRunState, detectorDeniedReads, snapshotClusterDetectors),
// plus integration-style coverage proving the three real detector loops
// (detector.go/pod_conditions_detector.go/sweep_detector.go) actually call
// into it — a unit test on detectorRunState alone would prove the mechanism
// works in isolation without proving anything wired it up.

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"argus/internal/tunnel"

	authorizationv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	k8sfake "k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

// resetDetectorRunStates is called at the start of every test in this file
// that touches the package-level warningEventsRunState/podConditionsRunState/
// sweepRunState instances — these are written by background goroutines in
// the real agent, so tests that exercise them directly must not depend on
// whatever an earlier test left behind.
func resetDetectorRunStates() {
	warningEventsRunState = detectorRunState{}
	podConditionsRunState = detectorRunState{}
	sweepRunState = detectorRunState{}
}

func TestDetectorRunStateNeverRunIsAllZero(t *testing.T) {
	var s detectorRunState
	got := s.snapshot()
	if !got.LastSuccessAt.IsZero() || got.Error != "" || !got.ErrorAt.IsZero() {
		t.Fatalf("a detectorRunState that never recorded anything must snapshot as all-zero (unknown, not failing or healthy), got %+v", got)
	}
}

func TestDetectorRunStateRecordSuccessThenError(t *testing.T) {
	var s detectorRunState
	t1 := time.Now()
	s.recordSuccess(t1)

	t2 := t1.Add(time.Minute)
	s.recordError(errors.New("watch closed"), t2)

	got := s.snapshot()
	if !got.LastSuccessAt.Equal(t1) {
		t.Fatalf("LastSuccessAt = %v, want %v", got.LastSuccessAt, t1)
	}
	if got.Error != "watch closed" || !got.ErrorAt.Equal(t2) {
		t.Fatalf("Error/ErrorAt = %q/%v, want %q/%v", got.Error, got.ErrorAt, "watch closed", t2)
	}
}

// TestDetectorRunStateErrorDoesNotEraseEarlierSuccess is the trap this
// codebase has been bitten by twice before, applied to this new mechanism:
// a later failure must not erase the evidence that this detector was
// working a moment ago (tunnel.DetectorStatus's own doc comment says exactly
// this — a consumer tells "recovered" from "still broken" by comparing
// ErrorAt against LastSuccessAt, which is only possible if both survive).
func TestDetectorRunStateErrorDoesNotEraseEarlierSuccess(t *testing.T) {
	var s detectorRunState
	success := time.Now()
	s.recordSuccess(success)
	s.recordError(errors.New("transient"), success.Add(time.Second))

	got := s.snapshot()
	if got.LastSuccessAt.IsZero() {
		t.Fatal("recordError must not clear a previously recorded LastSuccessAt")
	}
}

// TestDetectorRunStateSuccessDoesNotEraseEarlierError is the same guarantee
// in the other direction: a later success must not silently erase a real,
// still-worth-knowing-about earlier error.
func TestDetectorRunStateSuccessDoesNotEraseEarlierError(t *testing.T) {
	var s detectorRunState
	failAt := time.Now()
	s.recordError(errors.New("permission denied"), failAt)
	s.recordSuccess(failAt.Add(time.Minute))

	got := s.snapshot()
	if got.Error == "" {
		t.Fatal("recordSuccess must not clear a previously recorded Error")
	}
}

func TestDetectorRunStateRecordErrorNilIsNoOp(t *testing.T) {
	var s detectorRunState
	s.recordError(nil, time.Now())
	got := s.snapshot()
	if got.Error != "" || !got.ErrorAt.IsZero() {
		t.Fatalf("recordError(nil, ...) must be a no-op, got %+v", got)
	}
}

// TestDetectorDeniedReadsNilCacheReturnsNil covers the case
// snapshotClusterDetectors relies on for every agent build up until sweep's
// own goroutine has called enableDiscoveredWatchSet at least once: the
// discovery mechanism hasn't produced anything to check against yet, so the
// honest answer is "not checked", not "nothing denied" and not "everything
// denied".
func TestDetectorDeniedReadsNilCacheReturnsNil(t *testing.T) {
	discoveredWatchSetCache.Store(nil)
	got := detectorDeniedReads(context.Background(), warningEventsDetectorID)
	if got != nil {
		t.Fatalf("expected nil with no discovered watch set cache, got %v", got)
	}
}

// TestDetectorDeniedReadsAllGranted is the sweep detector's required-reads
// list checked against a discovered watch set that grants every single one
// — the "healthy" case, DeniedReads must come back empty.
func TestDetectorDeniedReadsAllGranted(t *testing.T) {
	var rules []authorizationv1.ResourceRule
	for _, r := range requiredDetectorReads[sweepDetectorID] {
		rules = append(rules, fullRule(r.group, r.resource))
	}
	disc := &fakeDiscoverer{lists: sweepRequiredResourceLists()}
	discoveredWatchSetCache.Store(NewWatchSetCache(disc, &fakeRulesReviewer{rules: rules}, time.Hour))
	t.Cleanup(func() { discoveredWatchSetCache.Store(nil) })

	got := detectorDeniedReads(context.Background(), sweepDetectorID)
	if len(got) != 0 {
		t.Fatalf("expected no denied reads when RBAC grants everything sweep needs, got %v", got)
	}
}

// TestDetectorDeniedReadsNamesEveryMissingOne is PROJECT.md T13's own
// acceptance criterion for the sweep detector specifically: RBAC denies
// "jobs" and "nodes" (leaving everything else granted) must name exactly
// those two, not a generic "something is denied", and must not falsely
// flag anything that IS actually granted.
func TestDetectorDeniedReadsNamesEveryMissingOne(t *testing.T) {
	var rules []authorizationv1.ResourceRule
	for _, r := range requiredDetectorReads[sweepDetectorID] {
		if r.label == "jobs" || r.label == "nodes" {
			continue // deliberately NOT granted
		}
		rules = append(rules, fullRule(r.group, r.resource))
	}
	disc := &fakeDiscoverer{lists: sweepRequiredResourceLists()}
	discoveredWatchSetCache.Store(NewWatchSetCache(disc, &fakeRulesReviewer{rules: rules}, time.Hour))
	t.Cleanup(func() { discoveredWatchSetCache.Store(nil) })

	got := detectorDeniedReads(context.Background(), sweepDetectorID)
	want := map[string]bool{"jobs": true, "nodes": true}
	if len(got) != len(want) {
		t.Fatalf("denied reads = %v, want exactly %v", got, want)
	}
	for _, label := range got {
		if !want[label] {
			t.Errorf("denied reads incorrectly named %q, which was actually granted", label)
		}
	}
}

// TestDetectorDeniedReadsWarningEventsAndPodConditions covers the other two
// catalogue entries' own single-resource requirement, independently of
// sweep's — RBAC here grants pods but denies events.
func TestDetectorDeniedReadsWarningEventsAndPodConditions(t *testing.T) {
	disc := &fakeDiscoverer{lists: []*metav1.APIResourceList{
		{
			GroupVersion: "v1",
			APIResources: []metav1.APIResource{
				{Name: "pods", Namespaced: true, Kind: "Pod", Verbs: metav1.Verbs{"get", "list", "watch"}},
				{Name: "events", Namespaced: true, Kind: "Event", Verbs: metav1.Verbs{"get", "list", "watch"}},
			},
		},
	}}
	discoveredWatchSetCache.Store(NewWatchSetCache(disc, &fakeRulesReviewer{rules: []authorizationv1.ResourceRule{fullRule("", "pods")}}, time.Hour))
	t.Cleanup(func() { discoveredWatchSetCache.Store(nil) })

	if got := detectorDeniedReads(context.Background(), podConditionsDetectorID); len(got) != 0 {
		t.Fatalf("pod-conditions: expected no denied reads (pods is granted), got %v", got)
	}
	if got := detectorDeniedReads(context.Background(), warningEventsDetectorID); len(got) != 1 || got[0] != "events" {
		t.Fatalf("warning-events: expected [events] denied, got %v", got)
	}
}

// sweepRequiredResourceLists builds a discovery response advertising every
// resource requiredDetectorReads[sweepDetectorID] names, each with the
// get/list/watch verbs DiscoverWatchSet requires the API server to
// advertise — the RBAC side is what each test varies via fakeRulesReviewer.
func sweepRequiredResourceLists() []*metav1.APIResourceList {
	byGroup := map[string][]metav1.APIResource{}
	for _, r := range requiredDetectorReads[sweepDetectorID] {
		byGroup[r.group] = append(byGroup[r.group], metav1.APIResource{
			Name:       r.resource,
			Namespaced: true,
			Kind:       r.label,
			Verbs:      metav1.Verbs{"get", "list", "watch"},
		})
	}
	var lists []*metav1.APIResourceList
	for group, resources := range byGroup {
		gv := "v1"
		if group != "" {
			gv = group + "/v1"
		}
		lists = append(lists, &metav1.APIResourceList{GroupVersion: gv, APIResources: resources})
	}
	return lists
}

// TestSnapshotClusterDetectorsAlwaysPopulatesAllThree is the fixed-catalogue
// guarantee tunnel.ClusterDetectors' own doc comment states: every build
// that reports ClusterDetectors at all reports one DetectorStatus per
// catalogue entry, never a partial report.
func TestSnapshotClusterDetectorsAlwaysPopulatesAllThree(t *testing.T) {
	resetDetectorRunStates()
	discoveredWatchSetCache.Store(nil)
	t.Cleanup(func() { discoveredWatchSetCache.Store(nil) })

	got := snapshotClusterDetectors(context.Background())
	if got == nil {
		t.Fatal("snapshotClusterDetectors returned nil")
	}
	// All three should be the all-zero "never observed" value here (nothing
	// has run yet), never a fabricated success or failure.
	for name, s := range map[string]tunnel.DetectorStatus{
		"warningEvents": got.WarningEvents,
		"podConditions": got.PodConditions,
		"sweep":         got.Sweep,
	} {
		if !s.LastSuccessAt.IsZero() || s.Error != "" {
			t.Errorf("%s: expected the untouched all-zero value before any detector has run, got %+v", name, s)
		}
	}
}

// TestSnapshotClusterDetectorsCarriesRunStateAndDeniedReads is the
// integration point between the two halves of this file: a detector that
// has recorded a real success/error, combined with a real denied-reads
// check, must show up together in one DetectorStatus.
func TestSnapshotClusterDetectorsCarriesRunStateAndDeniedReads(t *testing.T) {
	resetDetectorRunStates()

	success := time.Now()
	warningEventsRunState.recordSuccess(success)

	disc := &fakeDiscoverer{lists: []*metav1.APIResourceList{
		{GroupVersion: "v1", APIResources: []metav1.APIResource{
			{Name: "pods", Namespaced: true, Kind: "Pod", Verbs: metav1.Verbs{"get", "list", "watch"}},
		}},
	}}
	// Grants pods, not events — so warning-events (which needs events)
	// comes back denied even though it just recorded a clean success: the
	// two facts are independent and both must be visible at once.
	discoveredWatchSetCache.Store(NewWatchSetCache(disc, &fakeRulesReviewer{rules: []authorizationv1.ResourceRule{fullRule("", "pods")}}, time.Hour))
	t.Cleanup(func() { discoveredWatchSetCache.Store(nil) })

	got := snapshotClusterDetectors(context.Background())
	if !got.WarningEvents.LastSuccessAt.Equal(success) {
		t.Fatalf("WarningEvents.LastSuccessAt = %v, want %v", got.WarningEvents.LastSuccessAt, success)
	}
	if len(got.WarningEvents.DeniedReads) != 1 || got.WarningEvents.DeniedReads[0] != "events" {
		t.Fatalf("WarningEvents.DeniedReads = %v, want [events]", got.WarningEvents.DeniedReads)
	}
}

// --- Integration coverage: the real detector loops actually call into this
// mechanism, not just a hand-written unit test of detectorRunState in
// isolation. ---

// TestRunWarningEventWatchRecordsSuccessOnOpen proves detector.go's own
// watch loop — not a test double standing in for it — records a success the
// moment its Watch() call opens, which is what lets a healthy-but-quiet
// cluster (this fake clientset never delivers anything) be told apart from
// one whose detector never started at all.
func TestRunWarningEventWatchRecordsSuccessOnOpen(t *testing.T) {
	resetDetectorRunStates()
	clientset := k8sfake.NewSimpleClientset()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		_, _ = runWarningEventWatch(ctx, clientset, make(chan tunnel.Finding, 1), map[string]time.Time{}, defaultFindingResendCooldown, "")
		close(done)
	}()

	// runWarningEventWatch records success synchronously right after Watch()
	// opens, before it ever reaches its select loop — no sleep/poll needed,
	// just enough scheduling for the goroutine above to run.
	deadline := time.Now().Add(2 * time.Second)
	for warningEventsRunState.snapshot().LastSuccessAt.IsZero() {
		if time.Now().After(deadline) {
			t.Fatal("runWarningEventWatch never recorded a success after its watch opened")
		}
		time.Sleep(time.Millisecond)
	}

	cancel()
	<-done
}

// TestRecordWarningEventWatchOutcomeRecordsRealFailure proves the real
// production wiring end to end for the failure path: an actually-forbidden
// Watch() call, run through the real runWarningEventWatch against a fake
// clientset, fed through the real recordWarningEventWatchOutcome — the same
// two calls watchWarningEvents' own retry loop makes — lands in
// warningEventsRunState as a real error, not "not yet observed".
func TestRecordWarningEventWatchOutcomeRecordsRealFailure(t *testing.T) {
	resetDetectorRunStates()
	clientset := k8sfake.NewSimpleClientset()
	clientset.PrependWatchReactor("events", func(k8stesting.Action) (bool, watch.Interface, error) {
		return true, nil, errors.New("events is forbidden: User cannot watch resource")
	})

	_, err := runWarningEventWatch(context.Background(), clientset, make(chan tunnel.Finding, 1), map[string]time.Time{}, defaultFindingResendCooldown, "")
	if err == nil {
		t.Fatal("expected runWarningEventWatch to return an error when Watch() is forbidden")
	}
	recordWarningEventWatchOutcome(context.Background(), err)

	got := warningEventsRunState.snapshot()
	if got.Error == "" {
		t.Fatal("expected a forbidden Watch() call to be recorded as this detector's error")
	}
}

// TestRecordWarningEventWatchOutcomeIgnoresShutdown proves the other half:
// when ctx is what ended the watch (ordinary agent shutdown, or a tunnel
// reconnect tearing this goroutine down), that must never be recorded as a
// detector error — an operator reading detector status must not see a
// permanent-looking "Error" every time this agent restarts.
func TestRecordWarningEventWatchOutcomeIgnoresShutdown(t *testing.T) {
	resetDetectorRunStates()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	recordWarningEventWatchOutcome(ctx, ctx.Err())

	got := warningEventsRunState.snapshot()
	if got.Error != "" {
		t.Fatalf("a context-cancelled shutdown must not be recorded as a detector error, got %q", got.Error)
	}
}

// TestRecordPodConditionsWatchOutcomeRecordsRealFailure /
// TestRecordPodConditionsWatchOutcomeIgnoresShutdown are
// pod_conditions_detector.go's identical pair, proving the second
// detector's wiring independently of the first's.
func TestRecordPodConditionsWatchOutcomeRecordsRealFailure(t *testing.T) {
	resetDetectorRunStates()
	clientset := k8sfake.NewSimpleClientset()
	clientset.PrependWatchReactor("pods", func(k8stesting.Action) (bool, watch.Interface, error) {
		return true, nil, errors.New("pods is forbidden: User cannot watch resource")
	})

	err := runPodConditionsWatch(context.Background(), clientset, make(chan tunnel.Finding, 1), map[string]time.Time{}, defaultFindingResendCooldown)
	if err == nil {
		t.Fatal("expected runPodConditionsWatch to return an error when Watch() is forbidden")
	}
	recordPodConditionsWatchOutcome(context.Background(), err)

	got := podConditionsRunState.snapshot()
	if got.Error == "" {
		t.Fatal("expected a forbidden Watch() call to be recorded as this detector's error")
	}
}

func TestRecordPodConditionsWatchOutcomeIgnoresShutdown(t *testing.T) {
	resetDetectorRunStates()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	recordPodConditionsWatchOutcome(ctx, ctx.Err())

	got := podConditionsRunState.snapshot()
	if got.Error != "" {
		t.Fatalf("a context-cancelled shutdown must not be recorded as a detector error, got %q", got.Error)
	}
}

// TestRunOneSweepReturnsNilOnACleanPass proves runOneSweep — the real
// function runSweepDetector's ticker loop calls to decide whether to record
// a success or an error (PROJECT.md T13) — returns nil when every typed
// checker succeeds, which is exactly what lets sweepRunState.recordSuccess
// fire on a healthy pass.
func TestRunOneSweepReturnsNilOnACleanPass(t *testing.T) {
	clientset := k8sfake.NewSimpleClientset()
	_, err := runOneSweep(context.Background(), clientset, nil, make(chan tunnel.Finding, 1),
		map[string]time.Time{}, map[string]time.Time{}, defaultFindingResendCooldown, defaultSweepSustainedThreshold, defaultTestCheckerTimeout, nil)
	if err != nil {
		t.Fatalf("expected a clean sweep pass to return nil, got %v", err)
	}
}

// TestRunOneSweepReturnsErrorNamingTheFailingCheck proves the failure half:
// one typed checker (nodes) failing — the RBAC-denied shape this feature
// exists to surface — makes runOneSweep return a non-nil error that names
// which check failed, which is what ends up as this detector's own Error on
// the wire (via sweepRunState.recordError in runSweepDetector's ticker
// loop).
func TestRunOneSweepReturnsErrorNamingTheFailingCheck(t *testing.T) {
	clientset := k8sfake.NewSimpleClientset()
	clientset.PrependReactor("list", "nodes", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, errors.New("nodes is forbidden: User cannot list resource")
	})

	_, err := runOneSweep(context.Background(), clientset, nil, make(chan tunnel.Finding, 1),
		map[string]time.Time{}, map[string]time.Time{}, defaultFindingResendCooldown, defaultSweepSustainedThreshold, defaultTestCheckerTimeout, nil)
	if err == nil {
		t.Fatal("expected runOneSweep to return an error when the nodes list is forbidden")
	}
	if !strings.Contains(err.Error(), "node not ready") {
		t.Fatalf("expected the aggregate error to name the failing check (%q), got %q", "node not ready", err.Error())
	}
}

// TestWatchSetRefreshOutpacesTheFactsThatCarryIt pins PROJECT.md B177's fix.
//
// DeniedReads is read out of discoveredWatchSetCache during the facts gather
// (detectorDeniedReads), so if that cache's TTL is longer than the gather's
// own interval, an operator reading the detection-coverage table is looking
// at a denial that could be a whole TTL older than the timestamp beside it —
// and nothing on the screen says so. Keeping the TTL strictly shorter makes
// every gather re-read, which collapses the two stalenesses into the one the
// screen already shows.
//
// This is a relationship, not a value: either constant may move, but the
// inequality is what the fix is.
func TestWatchSetRefreshOutpacesTheFactsThatCarryIt(t *testing.T) {
	if DefaultWatchSetRefreshInterval >= factsRefreshInterval {
		t.Fatalf("the watch-set TTL (%s) is not shorter than the facts refresh interval (%s) that carries DeniedReads to the hub — a revoked permission is then stale by up to %s more than the screen admits (PROJECT.md B177)",
			DefaultWatchSetRefreshInterval, factsRefreshInterval, DefaultWatchSetRefreshInterval)
	}
}
