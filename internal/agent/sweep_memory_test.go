package agent

// Unit tests for PROJECT.md P18's memory guard. The numbers that JUSTIFY the
// guard's constants are measured against a real cluster
// (sweep_memory_live_test.go); what is tested here is the decision logic
// around them, which has to hold on a machine with no cluster and no cgroup
// limit at all.

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sruntime "k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	dynfake "k8s.io/client-go/dynamic/fake"
	k8sfake "k8s.io/client-go/kubernetes/fake"

	"argus/internal/tunnel"
)

func TestContainerMemoryLimitReadsTheFirstFiniteValue(t *testing.T) {
	dir := t.TempDir()
	write := func(name, contents string) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
			t.Fatalf("writing %s: %v", name, err)
		}
		return path
	}

	cases := []struct {
		name  string
		files []string
		want  uint64
		ok    bool
	}{
		{"cgroup v2 limit", []string{write("v2", "536870912\n")}, 536870912, true},
		{"cgroup v2 unlimited", []string{write("max", "max\n")}, 0, false},
		// cgroup v1 spells "no limit" as a number near 2^63, which must not
		// be mistaken for an 8-exabyte container.
		{"cgroup v1 unlimited sentinel", []string{write("v1max", "9223372036854771712\n")}, 0, false},
		{"no cgroup files at all", []string{filepath.Join(dir, "missing")}, 0, false},
		{"unreadable path falls through to the next", []string{filepath.Join(dir, "missing"), write("v2b", "268435456")}, 268435456, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			prev := cgroupMemoryLimitPaths
			cgroupMemoryLimitPaths = tc.files
			t.Cleanup(func() { cgroupMemoryLimitPaths = prev })

			got, ok := containerMemoryLimit()
			if ok != tc.ok || got != tc.want {
				t.Fatalf("containerMemoryLimit() = (%d, %v), want (%d, %v)", got, ok, tc.want, tc.ok)
			}
		})
	}
}

// TestNilGuardAdmitsEverything pins the property every existing call site
// depends on: an agent with no container memory limit (every unit test, every
// host-run agent, RUNBOOK.md's host-run setup) behaves exactly as it did
// before this guard existed.
func TestNilGuardAdmitsEverything(t *testing.T) {
	var g *sweepMemoryGuard
	// Every planner returns the zero plan — the unpaginated watch-cache read
	// (PROJECT.md P17(b)) — so an unguarded agent also never gives up the
	// watch cache, which is the other half of "behaves exactly as before".
	for _, tc := range []struct {
		name string
		plan func() (sweepReadPlan, error)
	}{
		{"typed list", func() (sweepReadPlan, error) { return g.planTypedList("Pod") }},
		{"unstructured half", g.planUnstructuredHalf},
		{"unstructured list", func() (sweepReadPlan, error) { return g.planUnstructuredList("Pod", "a rule") }},
	} {
		plan, err := tc.plan()
		if err != nil {
			t.Fatalf("nil guard refused %s: %v", tc.name, err)
		}
		if plan.paginate {
			t.Errorf("nil guard paginated %s — an agent with no memory limit has no reason to give up the watch cache", tc.name)
		}
	}
	if err := g.admitUnstructuredKindInHalf("Pod", "a kind inside the half"); err != nil {
		t.Fatalf("nil guard refused a kind inside the half: %v", err)
	}
	// And the same for a guard that exists but found no limit to guard.
	unlimited := &sweepMemoryGuard{podCount: 100000}
	plan, err := unlimited.planTypedList("Pod")
	if err != nil {
		t.Fatalf("guard with no limit refused a typed list: %v", err)
	}
	if plan.paginate {
		t.Error("guard with no limit paginated a typed list")
	}
}

func TestGuardRefusesAReadItCannotAfford(t *testing.T) {
	g := &sweepMemoryGuard{limit: 256 << 20, budget: 230 << 20, podCount: 5000}

	// 5,000 pods x 50KiB x 2 objects/pod is 488Mi of objects before any
	// headroom at all — past a 230Mi budget even paginated, so this is
	// refused outright rather than downgraded (PROJECT.md P17(c)).
	_, err := g.planUnstructuredHalf()
	if !errors.Is(err, errSweepMemoryBudget) {
		t.Fatalf("expected a memory-budget refusal, got %v", err)
	}
	// The message is what an operator sees on the cluster's detector status,
	// so it has to carry the three facts they need: what was skipped, how big
	// this agent's limit is, and what to do about it.
	for _, want := range []string{"generic kind-agnostic predicate pass", "256Mi", "values.yaml"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("refusal message does not mention %q: %s", want, err)
		}
	}
	if g.refusals != 1 {
		t.Errorf("refusals = %d, want 1", g.refusals)
	}

	// The same guard on a cluster a hundredth the size admits it, whole.
	g.podCount = 50
	plan, err := g.planUnstructuredHalf()
	if err != nil {
		t.Fatalf("expected a 50-pod cluster to be admitted under a 230Mi budget, got %v", err)
	}
	if plan.paginate {
		t.Error("a 50-pod cluster was paginated under a 230Mi budget — pagination is the escalation, not the default")
	}
}

// TestGuardProjectsOnlyFromPods is the honest limit of the projection: the
// guard prices what it can count and does not invent a number for anything
// else (see projectFor).
func TestGuardProjectsOnlyFromPods(t *testing.T) {
	g := &sweepMemoryGuard{limit: 1 << 30, budget: 900 << 20, podCount: 4000}
	if got := g.projectFor("Pod", unstructuredLiveBytesPerObject); got != 4000*unstructuredLiveBytesPerObject {
		t.Errorf("Pod projection = %d, want %d", got, 4000*unstructuredLiveBytesPerObject)
	}
	if got := g.projectFor("ConfigMap", unstructuredLiveBytesPerObject); got != 0 {
		t.Errorf("ConfigMap projection = %d, want 0 (uncountable kinds project nothing)", got)
	}
	// An unsized pass (the probe failed) projects nothing at all rather than
	// guessing, and falls back to the incremental checks.
	g.podCount = 0
	if got := g.projectFor("Pod", unstructuredLiveBytesPerObject); got != 0 {
		t.Errorf("projection with no pod count = %d, want 0", got)
	}
}

func TestSizeClusterCountsPodsAndResetsPerPassState(t *testing.T) {
	scheme := k8sruntime.NewScheme()
	gvr := schema.GroupVersionResource{Group: "", Version: "v1", Resource: "pods"}
	dyn := dynfake.NewSimpleDynamicClientWithCustomListKinds(scheme, map[schema.GroupVersionResource]string{gvr: "PodList"},
		newGenericObj("v1", "Pod", "default", "p1", "uid-1"),
		newGenericObj("v1", "Pod", "default", "p2", "uid-2"),
	)

	g := &sweepMemoryGuard{limit: 1 << 30, budget: 900 << 20, forcedGCThisPass: true, podCount: 99}
	g.sizeCluster(context.Background(), dyn)

	// The fake dynamic client ignores Limit and returns everything, so this
	// asserts the plumbing (count = items + remainingItemCount), not the API
	// server's pagination behaviour — that is what the live test measures.
	if g.podCount != 2 {
		t.Errorf("podCount = %d, want 2", g.podCount)
	}
	if g.forcedGCThisPass {
		t.Error("sizeCluster must reset the per-pass forced-GC flag, or a long-lived agent pays for at most one confirming collection ever")
	}

	// A guard with no limit never probes at all — one request per pass is
	// cheap, but not on an agent that has nothing to guard.
	unguarded := &sweepMemoryGuard{podCount: 7}
	unguarded.sizeCluster(context.Background(), dyn)
	if unguarded.podCount != 7 {
		t.Errorf("an unlimited guard probed the cluster anyway: podCount = %d", unguarded.podCount)
	}
}

// TestRefusedTypedListIsNotCached pins sweep_snapshot.go's deliberate
// asymmetry: a List that FAILED is cached (so a pass never pays twice for a
// failing API call), but a list that was REFUSED is not, because a refusal
// costs no API call and the room it was refused for may have been freed by
// the time a cheaper checker asks.
func TestRefusedTypedListIsNotCached(t *testing.T) {
	clientset := k8sfake.NewSimpleClientset(&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "p", Namespace: "default"}})
	prev := sweepMemoryGuardInstance
	t.Cleanup(func() { sweepMemoryGuardInstance = prev })

	// budget of 1 byte: everything is unaffordable.
	sweepMemoryGuardInstance = &sweepMemoryGuard{limit: 1 << 20, budget: 1}
	if _, err := newSweepSnapshot(clientset).pods(context.Background()); !errors.Is(err, errSweepMemoryBudget) {
		t.Fatalf("expected the Pod list to be refused, got %v", err)
	}
	if len(clientset.Actions()) != 0 {
		t.Fatalf("a refused list still went to the API server: %v", clientset.Actions())
	}

	snap := newSweepSnapshot(clientset)
	if _, err := snap.pods(context.Background()); !errors.Is(err, errSweepMemoryBudget) {
		t.Fatalf("expected refusal, got %v", err)
	}
	// Room appears (a GC, or an earlier half being dropped) and the same
	// snapshot must now be able to serve the list.
	sweepMemoryGuardInstance = &sweepMemoryGuard{limit: 1 << 30, budget: 1 << 30}
	list, err := snap.pods(context.Background())
	if err != nil {
		t.Fatalf("expected the list to be served once there was room, got %v", err)
	}
	if len(list.Items) != 1 {
		t.Fatalf("expected 1 pod, got %d", len(list.Items))
	}
}

// TestGenericPredicatePassRefusesWholeOrNothing is the false-positive
// guarantee: the kind-agnostic predicates read absence as a fact about the
// cluster, so a memory refusal must produce NO SNAPSHOT rather than a
// partial one the predicates would then read absence off.
//
// Since PROJECT.md P28 the refusal is decided one level up, when the shared
// snapshot is built — which is also what stops the declarative rules
// evaluating against a partial view, since they read the same snapshot.
func TestGenericPredicatePassRefusesWholeOrNothing(t *testing.T) {
	scheme := k8sruntime.NewScheme()
	gvr := schema.GroupVersionResource{Group: "", Version: "v1", Resource: "pods"}
	dyn := dynfake.NewSimpleDynamicClientWithCustomListKinds(scheme, map[schema.GroupVersionResource]string{gvr: "PodList"},
		newGenericObj("v1", "Pod", "default", "p1", "uid-1"))

	prev := sweepMemoryGuardInstance
	t.Cleanup(func() { sweepMemoryGuardInstance = prev })
	sweepMemoryGuardInstance = &sweepMemoryGuard{limit: 1 << 20, budget: 1}

	snap, err := buildUnstructuredSweepSnapshot(context.Background(), dyn, time.Minute)
	if !errors.Is(err, errSweepMemoryBudget) {
		t.Fatalf("expected a memory-budget refusal, got %v", err)
	}
	if snap != nil {
		t.Fatalf("a refused pass produced a snapshot with %d kind(s) in it; it must produce none", len(snap.objects))
	}
}

// TestRefusedKindIsRecordedAsUnreadable is the other half of the same
// guarantee, one level down: when the guard refuses a kind PART-WAY through
// building the snapshot, the build stops and returns nothing — the partial
// map is not handed to predicates that would read its gaps as facts
// (PROJECT.md P18), and it is not handed to the rules either (P28).
func TestRefusedKindIsRecordedAsUnreadable(t *testing.T) {
	scheme := k8sruntime.NewScheme()
	gvr := schema.GroupVersionResource{Group: "", Version: "v1", Resource: "pods"}
	dyn := dynfake.NewSimpleDynamicClientWithCustomListKinds(scheme, map[schema.GroupVersionResource]string{gvr: "PodList"},
		newGenericObj("v1", "Pod", "default", "p1", "uid-1"))

	prev := sweepMemoryGuardInstance
	t.Cleanup(func() { sweepMemoryGuardInstance = prev })
	sweepMemoryGuardInstance = &sweepMemoryGuard{limit: 1 << 20, budget: 1}

	snap, err := listWatchedKindObjects(context.Background(), dyn, sweepReadPlan{})
	if !errors.Is(err, errSweepMemoryBudget) {
		t.Fatalf("expected the per-kind refusal to stop the build, got %v", err)
	}
	if snap != nil {
		t.Fatal("a stopped build must return no snapshot at all, so the partial map becomes garbage immediately")
	}
}

// TestTypedSweepSnapshotIsReleasedBeforeTheDynamicHalf is the behavioural
// half of runTypedSweepCheckers' existence (the structural half is that the
// snapshot is out of scope once it returns).
//
// Measures rather than asserting on code shape: build a fixture whose typed
// Pod list is worth several megabytes, find out what one copy of it costs,
// then run a real pass and read the live heap from inside a dynamic checker.
// If the typed snapshot were still reachable there — which is exactly what a
// future edit that moved, reused or "cleaned up" the typed half would cause
// — the live heap would still be carrying that whole copy.
func TestTypedSweepSnapshotIsReleasedBeforeTheDynamicHalf(t *testing.T) {
	if testing.Short() {
		t.Skip("allocates tens of megabytes to make the difference measurable")
	}
	const pods = 4000
	objs := make([]k8sruntime.Object, 0, pods)
	padding := strings.Repeat("x", 1024)
	for i := 0; i < pods; i++ {
		objs = append(objs, &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:              fmt.Sprintf("pod-%05d", i),
				Namespace:         "default",
				CreationTimestamp: metav1.NewTime(time.Now()),
				Annotations:       map[string]string{"argus.io/padding": padding},
			},
			Status: corev1.PodStatus{Phase: corev1.PodRunning},
		})
	}
	clientset := k8sfake.NewSimpleClientset(objs...)

	// What does one copy of that list cost? (The fake clientset deep-copies
	// on List, the same way a real decode allocates a fresh one.)
	runtime.GC()
	base := liveHeapBytes()
	list, err := clientset.CoreV1().Pods(metav1.NamespaceAll).List(context.Background(), metav1.ListOptions{})
	if err != nil {
		t.Fatalf("listing the fixture: %v", err)
	}
	runtime.GC()
	copyCost := saturatingSubUint(liveHeapBytes(), base)
	runtime.KeepAlive(list)
	list = nil
	if copyCost < 4<<20 {
		t.Skipf("fixture too small to measure: one list copy is %d bytes, and this test needs a multi-megabyte list to tell the two cases apart", copyCost)
	}

	var liveInDynamicHalf uint64
	prevDynamic := dynamicSweepCheckers
	dynamicSweepCheckers = []dynamicSweepChecker{{
		name: "P18 live-heap probe",
		fn: func(ctx context.Context, dyn dynamic.Interface, now time.Time, sustained time.Duration) ([]sweepCandidate, error) {
			runtime.GC()
			liveInDynamicHalf = liveHeapBytes()
			return nil, nil
		},
	}}
	t.Cleanup(func() { dynamicSweepCheckers = prevDynamic })

	// A non-nil dynamic client is all runOneSweep needs to reach the dynamic
	// half; the probe above is the only checker that will run against it.
	dyn := dynfake.NewSimpleDynamicClient(k8sruntime.NewScheme())

	findingCh := make(chan tunnel.Finding, 4096)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for range findingCh {
		}
	}()

	runtime.GC()
	before := liveHeapBytes()
	if _, err := runOneSweep(context.Background(), clientset, dyn, findingCh, map[string]time.Time{}, map[string]time.Time{},
		defaultFindingResendCooldown, defaultSweepSustainedThreshold, time.Minute, nil); err != nil {
		t.Logf("sweep reported: %v (irrelevant to what this test measures)", err)
	}
	close(findingCh)
	<-done

	if liveInDynamicHalf == 0 {
		t.Fatal("the dynamic half never ran, so this test measured nothing")
	}
	if ceiling := before + copyCost/2; liveInDynamicHalf > ceiling {
		t.Fatalf("live heap during the dynamic half was %d bytes, more than half a %d-byte typed list copy above the %d-byte baseline — the typed snapshot is still reachable, and a pass' peak is now the SUM of both halves (PROJECT.md P18)",
			liveInDynamicHalf, copyCost, before)
	}
}

func saturatingSubUint(a, b uint64) uint64 {
	if a < b {
		return 0
	}
	return a - b
}

// TestRefusedSnapshotStillPricesEveryRule is the guarantee PROJECT.md P28
// must not break: when the shared unstructured snapshot cannot be afforded,
// the declarative rules do not silently disappear with it. They fall back to
// listing their own kinds, and every one of those reads is priced by the
// same guard — one refusal per rule, not one refusal for the whole set.
//
// Counted through the guard's own refusal tally rather than through the
// fake client's actions, because the point is precisely that these reads
// were DECLINED before they reached a client.
func TestRefusedSnapshotStillPricesEveryRule(t *testing.T) {
	prevGuard := sweepMemoryGuardInstance
	// Reset rather than saved and restored: detectorRunState carries a
	// mutex, so a copy of it is a vet error — the same reason
	// detector_status_test.go assigns a fresh zero value too.
	t.Cleanup(func() { sweepMemoryGuardInstance, sweepRunState = prevGuard, detectorRunState{} })
	sweepRunState = detectorRunState{}
	// A budget of one byte: the shared snapshot is unaffordable, and so is
	// every individual rule list behind it.
	sweepMemoryGuardInstance = &sweepMemoryGuard{limit: 1 << 20, budget: 1}

	rules := []Rule{
		{ID: "rule-a", GVK: "apps/v1/Deployment", Reason: "R", Severity: "low", Message: "m",
			Condition: RuleCondition{Field: "spec.replicas", Comparator: "eq", Value: "0"}},
		{ID: "rule-b", GVK: "v1/Pod", Reason: "R", Severity: "low", Message: "m",
			Condition: RuleCondition{Field: "spec.nodeName", Comparator: "notPresent"}},
	}

	clientset := k8sfake.NewSimpleClientset()
	dyn := dynfake.NewSimpleDynamicClient(k8sruntime.NewScheme())
	findingCh := make(chan tunnel.Finding, 16)

	runUnstructuredSweepHalf(context.Background(), clientset, dyn, rules, findingCh,
		map[string]time.Time{}, map[string]time.Time{}, map[string]struct{}{}, time.Now(),
		defaultFindingResendCooldown, defaultSweepSustainedThreshold, time.Minute)

	// One for the whole-half admission, one per rule that was then priced
	// individually on the fallback path.
	if got, want := sweepMemoryGuardInstance.refusals, uint64(1+len(rules)); got != want {
		t.Fatalf("guard refused %d read(s), want %d (the half, plus one per rule) — a rule that is never priced is a rule the guard has stopped protecting", got, want)
	}
	if status := sweepRunState.snapshot().Error; !strings.Contains(status, "declarative rule") {
		t.Fatalf("the detector status must say the rules did not run and why, got %q", status)
	}
}

// TestRuleOverAnUnreadableKindIsSkippedNotEvaluated is PROJECT.md B185 at
// the rules layer: a rule whose kind this pass could not read must be
// skipped and reported, never evaluated against an empty list. A rule that
// silently matches nothing is indistinguishable from a rule that checked and
// found the cluster healthy, which is the same false reassurance the
// dangling-reference predicate was giving.
func TestRuleOverAnUnreadableKindIsSkippedNotEvaluated(t *testing.T) {
	t.Cleanup(func() { sweepRunState = detectorRunState{} })
	sweepRunState = detectorRunState{}

	snap := newUnstructuredSnapshot()
	snap.record("Deployment", kindReadResult{state: kindForbidden, reason: "RBAC denies this agent list on Deployment"})
	snap.record("Backup", kindReadResult{state: kindNotServed, reason: "this cluster's API server does not serve Backup at all"})

	rules := []Rule{
		{ID: "denied-kind", GVK: "apps/v1/Deployment", Reason: "R", Severity: "low", Message: "m",
			Condition: RuleCondition{Field: "spec.replicas", Comparator: "eq", Value: "0"}},
		{ID: "absent-crd", GVK: "velero.io/v1/Backup", Reason: "R", Severity: "low", Message: "m",
			Condition: RuleCondition{Field: "status.phase", Comparator: "eq", Value: "Failed"}},
	}

	findingCh := make(chan tunnel.Finding, 16)
	runRulesFromSnapshot(context.Background(), snap, rules, findingCh,
		map[string]time.Time{}, map[string]time.Time{}, map[string]struct{}{}, time.Now(),
		defaultFindingResendCooldown, defaultSweepSustainedThreshold)

	if len(findingCh) != 0 {
		t.Fatalf("a rule over an unreadable kind must produce nothing, got %d finding(s)", len(findingCh))
	}
	status := sweepRunState.snapshot().Error
	if !strings.Contains(status, "denied-kind") {
		t.Fatalf("a rule skipped because RBAC denies its kind must be named on the detector status — an operator can act on that; got %q", status)
	}
	if strings.Contains(status, "absent-crd") {
		t.Fatalf("a rule over a CRD this cluster does not install is not a problem and must stay silent, got %q", status)
	}
}

// --- PROJECT.md B187: the recalibrated factors, and the read that used to
// slip past them ---

// TestB187SingleListIsPricedAtItsMeasuredCost reproduces, in arithmetic, the
// exact admission B187 reports as fatal: a 200Mi agent on a 2,030-pod
// cluster, in the declarative-rule fallback loop, being handed a cluster-wide
// unstructured Pod list.
//
// Under the single 1.4x factor that used to price every read, that list was
// projected at 99Mi x 1.4 = 139Mi against a 180Mi budget and ADMITTED. Its
// real cost, measured in a container at that limit, is ~245Mi, and the agent
// was OOMKilled mid-decode — which is worse than a refusal by the whole
// margin sweep_memory.go's opening comment describes, because the kernel
// also takes the dedup state with it.
func TestB187SingleListIsPricedAtItsMeasuredCost(t *testing.T) {
	const (
		limit  = 200 << 20
		budget = 180 << 20
		pods   = 2030
	)
	g := &sweepMemoryGuard{limit: limit, budget: budget, podCount: pods}

	projected := g.projectFor("Pod", unstructuredLiveBytesPerObject)
	if whole := uint64(float64(projected) * singleListDecodeHeadroomFactor); whole <= budget {
		t.Fatalf("a whole cluster-wide unstructured Pod list on a %d-pod cluster is priced at %s, which still fits a %s budget — this is B187 exactly, and the agent dies rather than refusing",
			pods, mib(whole), mib(budget))
	}

	// What the guard does about it now is NOT simply to refuse: the objects
	// themselves (99Mi) do fit, so the read is downgraded to pages rather
	// than dropped (PROJECT.md P17(c)).
	plan, err := g.planUnstructuredList("Pod", "declarative rule pod-evicted-not-cleaned-up")
	if err != nil {
		t.Fatalf("a read whose objects fit must be paginated, not refused: %v", err)
	}
	if !plan.paginate {
		t.Fatal("the fallback loop's Pod list was admitted whole at a 200Mi limit — that is the read that OOMKills the agent")
	}
	if g.paginated != 1 {
		t.Errorf("paginated = %d, want 1", g.paginated)
	}

	// And a cluster big enough that even the objects do not fit is still
	// refused outright, because pagination cannot shrink what a read must
	// hold all at once.
	g.podCount = 20000
	if _, err := g.planUnstructuredList("Pod", "declarative rule pod-evicted-not-cleaned-up"); !errors.Is(err, errSweepMemoryBudget) {
		t.Fatalf("20,000 pods' worth of objects cannot fit a 180Mi budget in any shape, want a refusal, got %v", err)
	}
}

// TestB187ManyKindPassIsNotPricedAsOneList is the other half of the
// recalibration, and the reason there are two constants rather than one.
//
// Pricing listWatchedKindObjects' 21-list read at the single-list rate would
// refuse, at a 320Mi limit on the same 2,030-pod cluster, a pass that
// measurably completes at a 266-270Mi peak. Over-refusal is a real failure:
// it silently narrows what the cluster is swept for, and the operator's only
// symptom is a quieter detector.
func TestB187ManyKindPassIsNotPricedAsOneList(t *testing.T) {
	g := &sweepMemoryGuard{limit: 320 << 20, budget: 288 << 20, podCount: 2030}

	plan, err := g.planUnstructuredHalf()
	if err != nil {
		t.Fatalf("the many-kind pass measurably completes at a 320Mi limit on this cluster and must not be refused: %v", err)
	}
	if plan.paginate {
		t.Error("the many-kind pass was paginated at a limit where it completes whole — pagination costs API-server requests and is the escalation, not the default")
	}

	// The single-list rate would have refused it. Pinned so that collapsing
	// the two constants back into one cannot pass this suite.
	projected := g.projectFor("Pod", unstructuredLiveBytesPerObject*unstructuredObjectsPerPod)
	if asOneList := uint64(float64(projected) * singleListDecodeHeadroomFactor); asOneList <= g.budget {
		t.Fatal("the two headroom factors no longer disagree on this read — one of them has drifted, and the measurement behind them is in sweep_memory.go")
	}
}

// TestPagedHeadroomFactorShrinksWithTheRead pins the property that makes
// pagination a bound rather than a better guess: the larger the collection,
// the closer its headroom gets to holding the objects and nothing else.
func TestPagedHeadroomFactorShrinksWithTheRead(t *testing.T) {
	small := pagedHeadroomFactor(sweepPageSize*2*unstructuredLiveBytesPerObject, unstructuredLiveBytesPerObject)
	large := pagedHeadroomFactor(sweepPageSize*50*unstructuredLiveBytesPerObject, unstructuredLiveBytesPerObject)
	if !(large < small) {
		t.Fatalf("paged headroom did not shrink with the read: %.2f at 50 pages vs %.2f at 2", large, small)
	}
	if large >= singleListDecodeHeadroomFactor || small >= singleListDecodeHeadroomFactor {
		t.Fatalf("a paginated read must be cheaper than the same read whole: %.2f/%.2f vs %.2f", small, large, singleListDecodeHeadroomFactor)
	}
	// A collection smaller than one page is not a paginated read at all and
	// must not be priced as if it were.
	if got := pagedHeadroomFactor(10*unstructuredLiveBytesPerObject, unstructuredLiveBytesPerObject); got != singleListDecodeHeadroomFactor {
		t.Errorf("a sub-page collection was priced at %.2f, want the full %.2f", got, singleListDecodeHeadroomFactor)
	}
}

// TestOneUnaffordableReadIsOneRefusal guards the counter an operator reads to
// tell a one-off from a standing fault. planRead asks the budget question up
// to three times about the same read (whole, in pages, and to build the
// message); only the read is refused, not each shape of it.
func TestOneUnaffordableReadIsOneRefusal(t *testing.T) {
	g := &sweepMemoryGuard{limit: 64 << 20, budget: 57 << 20, podCount: 20000}
	if _, err := g.planUnstructuredList("Pod", "declarative rule x"); !errors.Is(err, errSweepMemoryBudget) {
		t.Fatalf("want a refusal, got %v", err)
	}
	if g.refusals != 1 {
		t.Fatalf("refusals = %d after one unaffordable read, want 1", g.refusals)
	}
}

// TestGuardPricesAnyKindAfterOnePass is the generalisation P17(c) needed: the
// Limit: 1 probe can only afford to count one kind per pass, so before this
// the guard could price Pods and nothing else — and a cluster whose heaviest
// kind is not Pods got no projection, and therefore neither pagination nor a
// refusal, however large it grew.
func TestGuardPricesAnyKindAfterOnePass(t *testing.T) {
	g := &sweepMemoryGuard{limit: 256 << 20, budget: 230 << 20}

	// Pass 1: nothing has been counted, so nothing but Pods can be priced
	// and Pods have no probe either.
	if got := g.projectFor("Service", unstructuredLiveBytesPerObject); got != 0 {
		t.Errorf("an unseen kind projected %d, want 0 — the guard must not invent a count", got)
	}

	// The pass reads it, and the count is fed back.
	g.recordKindCount("Service", 40000)
	if got := g.projectFor("Service", unstructuredLiveBytesPerObject); got != 40000*unstructuredLiveBytesPerObject {
		t.Fatalf("Service projection = %d, want %d", got, 40000*unstructuredLiveBytesPerObject)
	}
	// And that is now enough to refuse it, which is the whole point.
	if _, err := g.planUnstructuredList("Service", "declarative rule x"); !errors.Is(err, errSweepMemoryBudget) {
		t.Fatalf("40,000 Services cannot fit a 230Mi budget in any shape, want a refusal, got %v", err)
	}

	// The Pod probe still wins when it is larger than the remembered count,
	// because it is the only input refreshed within the current pass — a
	// cluster that doubled since the last pass is exactly the case a stale
	// count would get wrong.
	g.recordKindCount("Pod", 10)
	g.podCount = 5000
	if got := g.projectFor("Pod", typedLiveBytesPerObject); got != 5000*typedLiveBytesPerObject {
		t.Errorf("Pod projection = %d, want the fresher probe's %d", got, 5000*typedLiveBytesPerObject)
	}
	// ...and the remembered count wins when IT is larger, for the same
	// reason in the other direction.
	g.recordKindCount("Pod", 9000)
	if got := g.projectFor("Pod", typedLiveBytesPerObject); got != 9000*typedLiveBytesPerObject {
		t.Errorf("Pod projection = %d, want the larger remembered %d", got, 9000*typedLiveBytesPerObject)
	}

	// A guard with no limit records nothing, so no unit test and no host-run
	// agent accumulates state it will never consult.
	unlimited := &sweepMemoryGuard{}
	unlimited.recordKindCount("Service", 40000)
	if unlimited.lastKindCounts != nil {
		t.Error("a guard with no memory limit recorded kind counts it can never use")
	}
}

// TestSweepMemoryBudgetReservesAnAbsoluteFloor pins the other half of
// PROJECT.md B187's fix. At a 200Mi container limit the old
// fraction-only reserve left 20Mi for a process that needs 28Mi outside its
// heap, so the budget the guard measured against — and told the Go runtime
// to hold to — was one the runtime could not possibly honour, and the agent
// was killed while every individual read looked affordable.
func TestSweepMemoryBudgetReservesAnAbsoluteFloor(t *testing.T) {
	// Asserted as the RESERVE (limit minus budget) rather than as byte
	// counts, because the reserve is the quantity with a meaning: it is what
	// the process needs and the heap may not have.
	cases := []struct {
		limit   uint64
		reserve uint64
		why     string
	}{
		{200 << 20, minNonHeapReserve, "the absolute floor governs, not the 10% that would leave 20Mi for a process needing 28Mi"},
		{320 << 20, minNonHeapReserve, "the two rules meet exactly here, so nothing the headroom factors were calibrated at moves"},
	}
	for _, tc := range cases {
		if got := tc.limit - sweepMemoryBudget(tc.limit); got != tc.reserve {
			t.Errorf("sweepMemoryBudget(%s) reserved %s, want %s — %s", mib(tc.limit), mib(got), mib(tc.reserve), tc.why)
		}
	}
	// Above the crossover the fraction governs and nothing changes: the
	// reserve is a tenth of the limit, which is already more than the floor.
	for _, limit := range []uint64{512 << 20, 1 << 30} {
		reserve := limit - sweepMemoryBudget(limit)
		if reserve <= minNonHeapReserve {
			t.Errorf("at a %s limit the reserve is %s, which the absolute floor should no longer be setting", mib(limit), mib(reserve))
		}
		if want := uint64(float64(limit) * (1 - goSoftMemoryLimitFraction)); reserve != want {
			t.Errorf("at a %s limit the reserve is %s, want the unchanged %s", mib(limit), mib(reserve), mib(want))
		}
	}
	// A limit below the reserve disables the guard rather than going
	// negative. An agent with less memory than its own runtime needs has a
	// problem this guard cannot solve.
	if got := sweepMemoryBudget(16 << 20); got != 0 {
		t.Errorf("sweepMemoryBudget(16Mi) = %s, want 0", mib(got))
	}
}

// TestEachHalfOfAPassGetsItsOwnForcedCollection guards the subtlety in
// beginDynamicHalf: the typed half runs first and its first budget check
// spends the pass' one forced collection, which would leave the dynamic half
// — the larger and more consequential read of the two — deciding against a
// live-heap reading taken while the typed snapshot was still held.
func TestEachHalfOfAPassGetsItsOwnForcedCollection(t *testing.T) {
	g := &sweepMemoryGuard{limit: 320 << 20, budget: sweepMemoryBudget(320 << 20)}
	g.sizeCluster(context.Background(), nil) // resets the per-pass state

	// The typed half's first refusal-shaped check spends the collection.
	g.fits(1<<62, 1)
	if !g.forcedGCThisPass {
		t.Fatal("a check that could not be satisfied cheaply did not force a collection")
	}
	g.beginDynamicHalf()
	if g.forcedGCThisPass {
		t.Fatal("the dynamic half did not get its own forced collection — it would price the largest read in the pass against a heap that still counts the typed snapshot")
	}
	// And a new pass re-arms it as before.
	g.fits(1<<62, 1)
	g.sizeCluster(context.Background(), nil)
	if g.forcedGCThisPass {
		t.Fatal("a new pass did not reset the forced-collection budget")
	}
}
