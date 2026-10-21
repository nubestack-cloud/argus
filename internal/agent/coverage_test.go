package agent

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"argus/internal/tunnel"

	authorizationv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// coverage_test.go covers PROJECT.md E11's coverage-loss signal: the 216→44
// drop that nothing could report before, and the discipline that keeps it
// from lying in either direction.

// TestDiscoverWatchSetReportsTheCoverageItAlreadyComputed is the central
// claim. The intersection has always counted what RBAC excluded — it logged
// the number and threw it away. This proves the number now comes back as
// data, and that the denominator is the whole candidate set rather than
// whatever happened to survive.
func TestDiscoverWatchSetReportsTheCoverageItAlreadyComputed(t *testing.T) {
	disc := &fakeDiscoverer{lists: []*metav1.APIResourceList{
		{GroupVersion: "v1", APIResources: []metav1.APIResource{
			{Name: "pods", Kind: "Pod", Namespaced: true, Verbs: metav1.Verbs{"get", "list", "watch"}},
			{Name: "secrets", Kind: "Secret", Namespaced: true, Verbs: metav1.Verbs{"get", "list", "watch"}},
		}},
		{GroupVersion: "velero.io/v1", APIResources: []metav1.APIResource{
			{Name: "backups", Kind: "Backup", Namespaced: true, Verbs: metav1.Verbs{"get", "list", "watch"}},
		}},
	}}
	// Grants pods only. secrets and velero.io/backups are served but denied.
	rules := &fakeRulesReviewer{rules: []authorizationv1.ResourceRule{
		{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"get", "list", "watch"}},
	}}

	set, cov, err := DiscoverWatchSet(context.Background(), disc, rules)
	if err != nil {
		t.Fatalf("DiscoverWatchSet returned error: %v", err)
	}
	if len(set) != 1 {
		t.Fatalf("watch set has %d kinds, want 1", len(set))
	}
	if cov.Served != 3 {
		t.Errorf("Served = %d, want 3 — the denominator is every resource the API server advertises with get+list+watch, which is what a cluster-admin-bound agent would resolve", cov.Served)
	}
	if cov.Readable != 1 {
		t.Errorf("Readable = %d, want 1", cov.Readable)
	}
	want := []string{"/secrets", "velero.io/backups"}
	if len(cov.Denied) != len(want) {
		t.Fatalf("Denied = %v, want %v", cov.Denied, want)
	}
	for i := range want {
		if cov.Denied[i] != want[i] {
			t.Errorf("Denied[%d] = %q, want %q — the sample is sorted so an operator comparing two snapshots sees a real change, not a different arbitrary slice of a map", i, cov.Denied[i], want[i])
		}
	}
	if cov.DeniedTruncated {
		t.Error("DeniedTruncated is true with 2 denied resources and a bound of 40")
	}
}

// TestCoverageDeniedSampleIsBoundedAndSaysSo proves the sample cannot grow
// with the problem it reports. This payload is re-sent every two minutes for
// the life of every agent, so an unbounded list is not a cosmetic concern.
func TestCoverageDeniedSampleIsBoundedAndSaysSo(t *testing.T) {
	var resources []metav1.APIResource
	for i := 0; i < maxDeniedSample*3; i++ {
		resources = append(resources, metav1.APIResource{
			Name: "kind" + string(rune('a'+i%26)) + string(rune('a'+i/26)) + "s",
			Kind: "K", Namespaced: true, Verbs: metav1.Verbs{"get", "list", "watch"},
		})
	}
	disc := &fakeDiscoverer{lists: []*metav1.APIResourceList{{GroupVersion: "example.com/v1", APIResources: resources}}}
	rules := &fakeRulesReviewer{} // grants nothing

	_, cov, err := DiscoverWatchSet(context.Background(), disc, rules)
	if err != nil {
		t.Fatalf("DiscoverWatchSet returned error: %v", err)
	}
	if cov.Readable != 0 {
		t.Errorf("Readable = %d, want 0", cov.Readable)
	}
	if cov.Served != len(resources) {
		t.Errorf("Served = %d, want %d — the count must be exact even though the sample is not", cov.Served, len(resources))
	}
	if len(cov.Denied) != maxDeniedSample {
		t.Errorf("Denied has %d entries, want it capped at %d", len(cov.Denied), maxDeniedSample)
	}
	if !cov.DeniedTruncated {
		t.Error("DeniedTruncated is false on a capped sample — a consumer would read the sample as the complete list")
	}
}

// TestSnapshotClusterCoverageReportsUnknownRatherThanZero is the
// zero-value discipline this codebase already applies to costs and counts
// (never render an unavailable figure as 0), applied to coverage. An agent
// that cannot compute coverage must not report "0 of 0", which reads as
// "this agent sees nothing".
func TestSnapshotClusterCoverageReportsUnknownRatherThanZero(t *testing.T) {
	prev := discoveredWatchSetCache.Load()
	discoveredWatchSetCache.Store(nil)
	t.Cleanup(func() { discoveredWatchSetCache.Store(prev) })

	cov := snapshotClusterCoverage(context.Background())
	if cov == nil {
		t.Fatal("snapshotClusterCoverage returned nil — an agent that cannot compute coverage still has something to say, and omitting the field means 'too old to know'")
	}
	if cov.Checked {
		t.Error("Checked is true with no discovery cache wired up")
	}
	if cov.KindsServed != 0 || cov.KindsReadable != 0 {
		t.Error("an unchecked coverage reported non-zero counts")
	}
	if cov.Error == "" {
		t.Error("Checked is false with no Error — a consumer has no way to tell why")
	}
}

// TestSnapshotClusterCoverageCarriesBothMeasurements proves the two halves
// are independent: the grant-shaped intersection and the sweep's own
// positive read record answer different questions, and reporting only one is
// showing half the answer.
func TestSnapshotClusterCoverageCarriesBothMeasurements(t *testing.T) {
	disc := &fakeDiscoverer{lists: []*metav1.APIResourceList{
		{GroupVersion: "v1", APIResources: []metav1.APIResource{
			{Name: "pods", Kind: "Pod", Namespaced: true, Verbs: metav1.Verbs{"get", "list", "watch"}},
			{Name: "nodes", Kind: "Node", Verbs: metav1.Verbs{"get", "list", "watch"}},
		}},
	}}
	rules := &fakeRulesReviewer{rules: []authorizationv1.ResourceRule{
		{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"get", "list", "watch"}},
	}}
	prev := discoveredWatchSetCache.Load()
	discoveredWatchSetCache.Store(NewWatchSetCache(disc, rules, time.Minute))
	t.Cleanup(func() { discoveredWatchSetCache.Store(prev) })

	// A sweep pass that read one kind, was denied another, and declined a
	// third for memory — three outcomes a grant alone cannot distinguish.
	snap := newUnstructuredSnapshot()
	snap.record("Pod", kindReadResult{state: kindReadOK})
	snap.record("Node", kindReadResult{state: kindForbidden, reason: "RBAC denies list on Node"})
	snap.record("ConfigMap", kindReadResult{state: kindNotAffordable, reason: "the memory guard declined this read"})
	snap.record("Backup", kindReadResult{state: kindNotServed, reason: "no CRD"})
	recordSweepCoverage(snap.coverage(time.Now()))
	t.Cleanup(func() {
		lastSweepCoverage.mu.Lock()
		lastSweepCoverage.cov = nil
		lastSweepCoverage.mu.Unlock()
	})

	cov := snapshotClusterCoverage(context.Background())
	if !cov.Checked {
		t.Fatalf("Checked is false: %s", cov.Error)
	}
	if cov.KindsServed != 2 || cov.KindsReadable != 1 {
		t.Errorf("grant-shaped coverage = %d readable of %d served, want 1 of 2", cov.KindsReadable, cov.KindsServed)
	}
	if cov.LastSweep == nil {
		t.Fatal("LastSweep is nil — the grant half alone cannot report a kind the memory guard declined, which is exactly what the sweep record is for")
	}
	ls := cov.LastSweep
	if ls.KindsRead != 1 || ls.KindsForbidden != 1 || ls.KindsNotAffordable != 1 || ls.KindsNotServed != 1 {
		t.Errorf("sweep coverage = read %d, forbidden %d, notAffordable %d, notServed %d; want 1 each",
			ls.KindsRead, ls.KindsForbidden, ls.KindsNotAffordable, ls.KindsNotServed)
	}
	if ls.At.IsZero() {
		t.Error("LastSweep.At is zero — a nil LastSweep is how 'no pass yet' is reported, so a zero timestamp here is a fabricated fact")
	}
}

// TestCoverageRidesTheFactsPath proves the signal actually reaches the wire.
// A field computed correctly and never attached to the payload is the
// failure mode this codebase has shipped twice (see CLAUDE.md's lessons).
func TestCoverageRidesTheFactsPath(t *testing.T) {
	facts := factsWithDetection(Config{})
	if facts.Coverage == nil {
		t.Fatal("ClusterFacts.Coverage is nil — the coverage signal never reaches the hub, which is the whole point of computing it")
	}
	msg := inventoryMessage(facts)
	if msg.InventoryDelta == nil || msg.InventoryDelta.Facts.Coverage == nil {
		t.Fatal("the inventory message the tunnel actually carries has no coverage on it")
	}
}

// TestSweepCoverageCountsAnUnclassifiedOutcomeAsFailed pins the direction
// this signal must err in. A read outcome nobody classified is still an
// unread kind; counting it as read would overstate coverage, which is the
// one mistake this whole mechanism exists to prevent.
func TestSweepCoverageCountsAnUnclassifiedOutcomeAsFailed(t *testing.T) {
	snap := newUnstructuredSnapshot()
	snap.record("Thing", kindReadResult{state: kindReadFailed, reason: "transient API error"})
	cov := snap.coverage(time.Now())
	if cov == nil {
		t.Fatal("coverage returned nil for a snapshot with a recorded read")
	}
	if cov.KindsRead != 0 || cov.KindsFailed != 1 {
		t.Errorf("read %d / failed %d, want 0 / 1", cov.KindsRead, cov.KindsFailed)
	}
}

// TestEmptySnapshotReportsNoCoverageRatherThanZeroCoverage keeps "no pass
// has run" distinguishable from "a pass read nothing" — the same absent-vs-
// zero discipline tunnel.ClusterCoverage documents.
func TestEmptySnapshotReportsNoCoverageRatherThanZeroCoverage(t *testing.T) {
	if cov := newUnstructuredSnapshot().coverage(time.Now()); cov != nil {
		t.Errorf("an empty snapshot produced %+v, want nil — a zeroed SweepCoverage would claim a pass ran and read nothing", cov)
	}
}

// TestClusterCoverageWireShapeOmitsNothingLoadBearing guards the JSON a hub
// and a UI read. Checked and the two counts must always be present (so a
// consumer can tell "checked, and it is genuinely 0" from "not reported"),
// while the optional halves must stay omitted when empty.
func TestClusterCoverageWireShapeOmitsNothingLoadBearing(t *testing.T) {
	for _, field := range []string{`"checked"`, `"kindsServed"`, `"kindsReadable"`} {
		if !strings.Contains(coverageJSON(t, &tunnel.ClusterCoverage{}), field) {
			t.Errorf("a zero ClusterCoverage omits %s — a consumer could not distinguish it from an agent that never reported one", field)
		}
	}
	if strings.Contains(coverageJSON(t, &tunnel.ClusterCoverage{}), `"lastSweep"`) {
		t.Error("a ClusterCoverage with no sweep record still emits lastSweep")
	}
}

// coverageJSON marshals one ClusterCoverage the way the tunnel does.
func coverageJSON(t *testing.T, c *tunnel.ClusterCoverage) string {
	t.Helper()
	b, err := json.Marshal(c)
	if err != nil {
		t.Fatalf("marshal ClusterCoverage: %v", err)
	}
	return string(b)
}
