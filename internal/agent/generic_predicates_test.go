package agent

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"argus/internal/tunnel"

	authorizationv1 "k8s.io/api/authorization/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	dynfake "k8s.io/client-go/dynamic/fake"
	k8stesting "k8s.io/client-go/testing"
)

// newGenericObj builds a minimal unstructured object for these pure-logic
// tests — no live cluster, no dynamic client, matching this package's own
// convention (fieldOwnershipFixture, sweep_detector_test.go) of testing a
// checker's decision logic against hand-built inputs rather than a fake
// clientset wherever the function under test doesn't itself need one.
func newGenericObj(apiVersion, kind, namespace, name, uid string) *unstructured.Unstructured {
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": apiVersion,
		"kind":       kind,
		"metadata": map[string]any{
			"namespace":       namespace,
			"name":            name,
			"uid":             uid,
			"resourceVersion": "1",
		},
	}}
}

func setCondition(o *unstructured.Unstructured, condType, status string, lastTransition time.Time) {
	conds, _, _ := unstructured.NestedSlice(o.Object, "status", "conditions")
	// reason/message are always set, even though most tests using this
	// helper don't care about their content: looksLikeConditionArray
	// (PROJECT.md B154) requires at least one of them present as part of
	// the condition-array shape signature, matching every real
	// metav1.Condition-shaped array this predicate now finds at any depth
	// under status, not just the conventional top-level one.
	cond := map[string]any{"type": condType, "status": status, "reason": "TestReason", "message": "test condition"}
	if !lastTransition.IsZero() {
		cond["lastTransitionTime"] = lastTransition.UTC().Format(time.RFC3339)
	}
	conds = append(conds, cond)
	_ = unstructured.SetNestedSlice(o.Object, conds, "status", "conditions")
}

func setGeneration(o *unstructured.Unstructured, gen int64) {
	_ = unstructured.SetNestedField(o.Object, gen, "metadata", "generation")
}

func setObservedGeneration(o *unstructured.Unstructured, gen int64) {
	_ = unstructured.SetNestedField(o.Object, gen, "status", "observedGeneration")
}

func setDeletionTimestamp(o *unstructured.Unstructured, ts time.Time) {
	o.SetDeletionTimestamp(&metav1.Time{Time: ts})
}

func setFinalizers(o *unstructured.Unstructured, finalizers ...string) {
	o.SetFinalizers(finalizers)
}

func setPodPhase(o *unstructured.Unstructured, phase string) {
	_ = unstructured.SetNestedField(o.Object, phase, "status", "phase")
}

func setControllerOwner(o *unstructured.Unstructured, uid string) {
	yes := true
	o.SetOwnerReferences([]metav1.OwnerReference{{
		APIVersion: "apps/v1", Kind: "ReplicaSet", Name: "owner", UID: types.UID(uid), Controller: &yes,
	}})
}

func setSpecRef(o *unstructured.Unstructured, path []string, kind, name, namespace string) {
	ref := map[string]any{"kind": kind, "name": name}
	if namespace != "" {
		ref["namespace"] = namespace
	}
	_ = unstructured.SetNestedMap(o.Object, ref, path...)
}

// --- Severity assignment (BACKLOG.md T1, 2026-09-04) ---

func TestBlastRadiusSeverity(t *testing.T) {
	cases := []struct {
		affectedCount int
		totalCount    int
		want          string
	}{
		{0, 30, "low"},   // defensive: should never happen, but must not panic or escalate
		{1, 1000, "low"}, // "one pod of twenty" — isolated, regardless of population
		{1, 4, "low"},

		// Below minGenericPolaritySamples: too small a population to trust a
		// proportion, capped at "medium" even though affectedCount == total.
		{2, 4, "medium"},
		{4, 4, "medium"},

		// The live-fixture regression this fix exists for (BUGS.md,
		// 2026-09-04): 5 of 30 (16.7%) is a small minority of a real
		// population — the old affectedCount-only version reported "high"
		// for exactly this case.
		{5, 30, "medium"},

		// Large absolute count, tiny proportion of a much larger fleet:
		// must NOT be "high" just because the count crosses the old flat-5
		// threshold.
		{5, 1000, "low"},      // 0.5%
		{150, 1000, "medium"}, // 15%

		// Small population, large proportion: proportion can promote to
		// "high" even with a small absolute count — the flip side of the
		// same fix (predicate 5's smaller sibling groups).
		{2, 5, "high"}, // 40%, at the high-fraction boundary
		{3, 7, "high"}, // 43%
		{4, 5, "high"},

		// Genuinely large, evenly split populations still reach "high".
		{20, 40, "high"},
	}
	for _, c := range cases {
		if got := blastRadiusSeverity(c.affectedCount, c.totalCount); got != c.want {
			t.Errorf("blastRadiusSeverity(%d, %d) = %q, want %q", c.affectedCount, c.totalCount, got, c.want)
		}
	}
}

func TestObservedGenerationLagSeverity(t *testing.T) {
	cases := []struct {
		lag  int64
		want string
	}{
		{1, "low"},
		{2, "medium"},
		{3, "medium"},
		{4, "high"},
		{100, "high"},
	}
	for _, c := range cases {
		if got := observedGenerationLagSeverity(c.lag); got != c.want {
			t.Errorf("observedGenerationLagSeverity(%d) = %q, want %q", c.lag, got, c.want)
		}
	}
}

func TestStuckFinalizerSeverity(t *testing.T) {
	threshold := 10 * time.Minute
	cases := []struct {
		age  time.Duration
		want string
	}{
		{threshold, "medium"}, // just past the report floor
		{2 * threshold, "medium"},
		{3*threshold - time.Second, "medium"},
		{3 * threshold, "high"},
		{24 * threshold, "high"},
	}
	for _, c := range cases {
		if got := stuckFinalizerSeverity(c.age, threshold); got != c.want {
			t.Errorf("stuckFinalizerSeverity(%v, %v) = %q, want %q", c.age, threshold, got, c.want)
		}
	}
}

// --- Predicate 1: conditions + Mechanism 1 polarity inference ---

func TestCheckGenericConditions_MajorityInference_FlagsMinority(t *testing.T) {
	now := time.Now()
	old := now.Add(-time.Hour)
	threshold := 10 * time.Minute

	objs := make([]*unstructured.Unstructured, 0, 5)
	for i := 0; i < 4; i++ {
		o := newGenericObj("widgets.example.io/v1", "Widget", "ns", "healthy-"+string(rune('a'+i)), "uid-"+string(rune('a'+i)))
		setCondition(o, "Ready", "True", old)
		objs = append(objs, o)
	}
	broken := newGenericObj("widgets.example.io/v1", "Widget", "ns", "broken", "uid-broken")
	setCondition(broken, "Ready", "False", old)
	objs = append(objs, broken)

	out := checkGenericConditions(map[string][]*unstructured.Unstructured{"Widget": objs}, now, threshold)
	if len(out) != 1 {
		t.Fatalf("expected exactly 1 candidate (the minority reading), got %d: %+v", len(out), out)
	}
	c := out[0]
	if c.Name != "broken" {
		t.Fatalf("expected the flagged object to be 'broken', got %q", c.Name)
	}
	if c.Reason != genericConditionAnomalyReasonPrefix+"Ready" {
		t.Fatalf("unexpected Reason: %q", c.Reason)
	}
	if c.ConditionSampleCount != 5 {
		t.Fatalf("expected sample count 5, got %d", c.ConditionSampleCount)
	}
	if c.ConditionMajorityValue != "True" {
		t.Fatalf("expected inferred majority value True, got %q", c.ConditionMajorityValue)
	}
	if c.ConditionMajorityFraction < 0.79 || c.ConditionMajorityFraction > 0.81 {
		t.Fatalf("expected majority fraction ~0.8, got %f", c.ConditionMajorityFraction)
	}
	// This is the load-bearing property: nothing here ever compared "False"
	// against a hardcoded "bad" literal — the minority reading was caught
	// purely because it disagreed with its peers.
	if c.ConditionObservedValue != "False" {
		t.Fatalf("expected observed value False, got %q", c.ConditionObservedValue)
	}
	// BACKLOG.md T1: a lone minority-of-1 is the "one pod of twenty" case —
	// low blast radius, not a flat "medium".
	if c.Severity != "low" {
		t.Fatalf("expected a lone outlier to carry severity 'low', got %q", c.Severity)
	}
	if c.Class != tunnel.FindingClassAnomaly || c.Confidence != tunnel.FindingConfidenceUnverified || c.Impact != tunnel.FindingImpactNone {
		t.Fatalf("generic condition evidence = %s/%s/%s, want anomaly/unverified/none", c.Class, c.Confidence, c.Impact)
	}
}

// TestCheckGenericConditions_LargeMinority_SeverityCappedByStructuralCeiling
// pins a real live-fixture finding (rke2, 2026-09-04, BUGS.md — a 30-object
// CRD population, 5 anomalous/25 healthy): the pre-fix, affectedCount-only
// blastRadiusSeverity reported "high" for this, but 5-of-25 is a 20%
// minority — a small proportion, not "every replica." Worse, 20% is
// approximately the LARGEST minority checkGenericConditions' own confident-
// majority branch can ever produce (majorityFraction must clear
// genericPolarityMajorityFraction, 0.8, so the minority is always < 20%) —
// meaning the old code's "high" fired on ~every confidently-flagged minority
// this predicate could ever report, not just the rare large ones. Renamed
// from ...SeverityEscalates (its pre-fix name) because "escalates" was true
// only relative to the single-outlier case, never relative to the total
// population — the property this test now actually pins is the reverse: a
// proportion this small stays at "medium" even at 5 raw affected peers.
func TestCheckGenericConditions_LargeMinority_SeverityCappedByStructuralCeiling(t *testing.T) {
	now := time.Now()
	old := now.Add(-time.Hour)
	threshold := 10 * time.Minute

	var objs []*unstructured.Unstructured
	// 16 healthy, 5 broken — 16/21 ≈ 76%... below the 0.8 floor, so widen the
	// healthy majority to clear it convincingly while still leaving the
	// minority at exactly minGenericPolaritySamples (5), the threshold this
	// test exists to pin.
	for i := 0; i < 20; i++ {
		o := newGenericObj("v1", "Widget", "ns", "healthy-"+string(rune('a'+i)), "uid-h"+string(rune('a'+i)))
		setCondition(o, "Ready", "True", old)
		objs = append(objs, o)
	}
	for i := 0; i < 5; i++ {
		o := newGenericObj("v1", "Widget", "ns", "broken-"+string(rune('a'+i)), "uid-b"+string(rune('a'+i)))
		setCondition(o, "Ready", "False", old)
		objs = append(objs, o)
	}
	// 20/25 = 80% majority, exactly clearing genericPolarityMajorityFraction;
	// the 5-object, 20%-of-25 minority is this test's case.

	out := checkGenericConditions(map[string][]*unstructured.Unstructured{"Widget": objs}, now, threshold)
	if len(out) != 5 {
		t.Fatalf("expected all 5 minority objects flagged, got %d: %+v", len(out), out)
	}
	for _, c := range out {
		if c.Severity != "medium" {
			t.Errorf("object %s: expected severity 'medium' for a 20%% minority (5 of 25) — proportion-based, not the old raw-count 'high' — got %q", c.Name, c.Severity)
		}
	}
}

// TestCheckGenericConditions_TerminalPhasePod_NeverFlagged pins BUGS.md 137's
// actual mechanism (checkGenericConditions' cluster-wide majority/minority
// tally, not checkGenericPeerOutlier's same-owner one): a completed Job
// pod's Ready=False must never be tallied at all against a cluster where
// most Pods are long-running and Ready=True — not counted as a minority
// against them, and not counted as part of the population they're measured
// against either. Before this fix, a completed pod was a permanent
// "minority of one" the moment it finished, forever (observed live: three
// real incidents, one 79 days old, with 643/736/741 occurrences).
func TestCheckGenericConditions_TerminalPhasePod_NeverFlagged(t *testing.T) {
	now := time.Now()
	old := now.Add(-time.Hour)
	threshold := 10 * time.Minute

	var objs []*unstructured.Unstructured
	for i := 0; i < 10; i++ {
		o := newGenericObj("v1", "Pod", "ns", "running-"+string(rune('a'+i)), "ur"+string(rune('a'+i)))
		setPodPhase(o, "Running")
		setCondition(o, "Ready", "True", old)
		objs = append(objs, o)
	}
	completed := newGenericObj("v1", "Pod", "ns", "cronjob-completed", "uc")
	setPodPhase(completed, "Succeeded")
	setCondition(completed, "Ready", "False", old)
	objs = append(objs, completed)

	out := checkGenericConditions(map[string][]*unstructured.Unstructured{"Pod": objs}, now, threshold)
	if len(out) != 0 {
		t.Fatalf("expected the terminal-phase pod not to be flagged, got %d candidate(s): %+v", len(out), out)
	}
}

// TestCheckGenericConditions_NeverReachesHigh_StructuralCeiling documents,
// rather than merely asserts, why checkGenericConditions' confident-majority
// branch cannot itself produce "high" under the fixed, proportion-based
// blastRadiusSeverity: the branch only flags a minority once the majority
// clears genericPolarityMajorityFraction (0.8), which caps the minority
// below 20% — under blastRadiusHighFraction (0.40). "high" from this
// predicate would require a contradiction (a minority large enough to be
// "high" but small enough to leave an 80%-confident majority), so it never
// fires here even at fleet scale — matching this file's own design note that
// this predicate's ceiling for a confidently-inferred minority is "medium,"
// not "high" (checkGenericPeerOutlier's 50%-majority guard is the path that
// can actually reach "high").
func TestCheckGenericConditions_NeverReachesHigh_StructuralCeiling(t *testing.T) {
	now := time.Now()
	old := now.Add(-time.Hour)
	threshold := 10 * time.Minute

	var objs []*unstructured.Unstructured
	// 400 healthy, 99 broken: 400/499 ≈ 80.2%, just clearing the confidence
	// floor with the largest minority (99, ≈19.8%) this branch can produce
	// at this scale — large in absolute terms, still capped below the 40%
	// high-fraction threshold.
	for i := 0; i < 400; i++ {
		o := newGenericObj("v1", "Widget", "ns", fmt.Sprintf("healthy-%d", i), fmt.Sprintf("uid-h%d", i))
		setCondition(o, "Ready", "True", old)
		objs = append(objs, o)
	}
	for i := 0; i < 99; i++ {
		o := newGenericObj("v1", "Widget", "ns", fmt.Sprintf("broken-%d", i), fmt.Sprintf("uid-b%d", i))
		setCondition(o, "Ready", "False", old)
		objs = append(objs, o)
	}

	out := checkGenericConditions(map[string][]*unstructured.Unstructured{"Widget": objs}, now, threshold)
	if len(out) != 99 {
		t.Fatalf("expected all 99 minority objects flagged, got %d", len(out))
	}
	for _, c := range out {
		if c.Severity == "high" {
			t.Errorf("object %s: got severity 'high' — should be structurally unreachable via this predicate's confident-majority branch", c.Name)
		}
	}
}

// TestCheckGenericConditions_InsufficientSample_SeverityIsLow pins the
// fail-open branch's own severity floor: a lone, low-population instance
// (nothing to compare it against locally) must not be escalated beyond
// "low" — this heuristic has no real basis for a stronger claim, and the
// hub's own polarity gate carries the real verdict for populations this
// small.
func TestCheckGenericConditions_InsufficientSample_SeverityIsLow(t *testing.T) {
	now := time.Now()
	old := now.Add(-time.Hour)
	threshold := 10 * time.Minute

	o := newGenericObj("certificates.example.io/v1", "Certificate", "ns", "solo", "uid-solo")
	setCondition(o, "Ready", "True", old)

	out := checkGenericConditions(map[string][]*unstructured.Unstructured{"Certificate": {o}}, now, threshold)
	if len(out) != 1 {
		t.Fatalf("expected 1 candidate, got %d", len(out))
	}
	if out[0].Severity != "low" {
		t.Fatalf("expected severity 'low' for a single-instance, low-population forward, got %q", out[0].Severity)
	}
}

func TestCheckGenericConditions_InvertedPolarity_MinorityIsTrue(t *testing.T) {
	// The mirror image of the test above, proving this mechanism is
	// polarity-invariant: here the MAJORITY reads False and the single
	// outlier reads True (e.g. MemoryPressure, where True is the problem) —
	// the exact case a hardcoded "False is bad" table gets backwards.
	now := time.Now()
	old := now.Add(-time.Hour)
	threshold := 10 * time.Minute

	objs := make([]*unstructured.Unstructured, 0, 5)
	for i := 0; i < 4; i++ {
		o := newGenericObj("v1", "Node", "", "node-"+string(rune('a'+i)), "uid-"+string(rune('a'+i)))
		setCondition(o, "MemoryPressure", "False", old)
		objs = append(objs, o)
	}
	pressured := newGenericObj("v1", "Node", "", "node-pressured", "uid-pressured")
	setCondition(pressured, "MemoryPressure", "True", old)
	objs = append(objs, pressured)

	out := checkGenericConditions(map[string][]*unstructured.Unstructured{"Node": objs}, now, threshold)
	if len(out) != 1 {
		t.Fatalf("expected exactly 1 candidate, got %d: %+v", len(out), out)
	}
	if out[0].Name != "node-pressured" || out[0].ConditionObservedValue != "True" || out[0].ConditionMajorityValue != "False" {
		t.Fatalf("expected node-pressured (True) flagged against a False majority, got %+v", out[0])
	}
}

func TestCheckGenericConditions_InsufficientSample_ForwardsUnconditionally(t *testing.T) {
	now := time.Now()
	old := now.Add(-time.Hour)
	threshold := 10 * time.Minute

	o := newGenericObj("certificates.example.io/v1", "Certificate", "ns", "solo", "uid-solo")
	setCondition(o, "Ready", "True", old)

	out := checkGenericConditions(map[string][]*unstructured.Unstructured{"Certificate": {o}}, now, threshold)
	if len(out) != 1 {
		t.Fatalf("expected the single instance to be forwarded regardless of its value (no local majority possible), got %d candidates", len(out))
	}
	if out[0].ConditionMajorityValue != "" {
		t.Fatalf("expected no majority value to be claimed below the sample floor, got %q", out[0].ConditionMajorityValue)
	}
	if out[0].ConditionSampleCount != 1 {
		t.Fatalf("expected sample count 1, got %d", out[0].ConditionSampleCount)
	}
}

func TestCheckGenericConditions_NoConfidentMajority_Skipped(t *testing.T) {
	now := time.Now()
	old := now.Add(-time.Hour)
	threshold := 10 * time.Minute

	var objs []*unstructured.Unstructured
	for i := 0; i < 3; i++ {
		o := newGenericObj("v1", "Widget", "ns", "true-"+string(rune('a'+i)), "u")
		setCondition(o, "Ready", "True", old)
		objs = append(objs, o)
	}
	for i := 0; i < 2; i++ {
		o := newGenericObj("v1", "Widget", "ns", "false-"+string(rune('a'+i)), "u")
		setCondition(o, "Ready", "False", old)
		objs = append(objs, o)
	}
	// 3/5 = 60%, below genericPolarityMajorityFraction (0.8) — genuinely
	// ambiguous, and this mechanism should decline to guess rather than
	// forward all five every sweep.
	out := checkGenericConditions(map[string][]*unstructured.Unstructured{"Widget": objs}, now, threshold)
	if len(out) != 0 {
		t.Fatalf("expected no candidates for a population with no confident majority, got %d: %+v", len(out), out)
	}
}

func TestCheckGenericConditions_AllHealthy_NoCandidates(t *testing.T) {
	now := time.Now()
	old := now.Add(-time.Hour)
	threshold := 10 * time.Minute

	var objs []*unstructured.Unstructured
	for i := 0; i < 5; i++ {
		o := newGenericObj("v1", "Widget", "ns", "healthy-"+string(rune('a'+i)), "u")
		setCondition(o, "Ready", "True", old)
		objs = append(objs, o)
	}
	out := checkGenericConditions(map[string][]*unstructured.Unstructured{"Widget": objs}, now, threshold)
	if len(out) != 0 {
		t.Fatalf("expected no candidates when every peer agrees, got %d: %+v", len(out), out)
	}
}

func TestCheckGenericConditions_NotYetSustained_Skipped(t *testing.T) {
	now := time.Now()
	old := now.Add(-time.Hour)
	recent := now.Add(-time.Second)
	threshold := 10 * time.Minute

	var objs []*unstructured.Unstructured
	for i := 0; i < 4; i++ {
		o := newGenericObj("v1", "Widget", "ns", "healthy-"+string(rune('a'+i)), "u")
		setCondition(o, "Ready", "True", old)
		objs = append(objs, o)
	}
	broken := newGenericObj("v1", "Widget", "ns", "just-broke", "u")
	setCondition(broken, "Ready", "False", recent)
	objs = append(objs, broken)

	out := checkGenericConditions(map[string][]*unstructured.Unstructured{"Widget": objs}, now, threshold)
	if len(out) != 0 {
		t.Fatalf("expected the freshly-transitioned minority reading to be gated by the sustained threshold, got %d: %+v", len(out), out)
	}
}

// --- PROJECT.md B154: conditions found by shape, at any depth under status,
// not just the conventional top-level status.conditions[] ---

// setNestedCondition builds one condition-shaped map — the same four fields
// (type/status/reason/message) plus lastTransitionTime that looksLikeConditionArray
// requires — for use inside a hand-built nested status shape these tests
// construct directly, since setCondition only ever targets the top-level
// status.conditions[] path.
func setNestedCondition(condType, status string, lastTransition time.Time) map[string]any {
	return map[string]any{
		"type": condType, "status": status,
		"reason": "TestReason", "message": "test condition",
		"lastTransitionTime": lastTransition.UTC().Format(time.RFC3339),
	}
}

// TestCheckGenericConditions_GatewayShape_FindsPerListenerConditions
// reproduces the exact live shape PROJECT.md B154 was filed against: a
// Gateway API Gateway keeps its real per-listener diagnosis under
// status.listeners[].conditions, not at the top level. Before this fix,
// checkGenericConditions read only status.conditions and never saw
// Conflicted=True at all (proven by a stash round-trip against the
// pre-fix code — see the commit this test landed in).
func TestCheckGenericConditions_GatewayShape_FindsPerListenerConditions(t *testing.T) {
	now := time.Now()
	old := now.Add(-time.Hour)
	threshold := 10 * time.Minute

	gw := newGenericObj("gateway.networking.k8s.io/v1", "Gateway", "gwapi-verify", "gw-faults", "uid-gw")
	_ = unstructured.SetNestedSlice(gw.Object, []any{
		setNestedCondition("Accepted", "False", old),
		setNestedCondition("Programmed", "False", old),
	}, "status", "conditions")
	_ = unstructured.SetNestedSlice(gw.Object, []any{
		map[string]any{
			"name": "plain",
			"conditions": []any{
				setNestedCondition("Accepted", "False", old),
				setNestedCondition("Conflicted", "True", old),
				setNestedCondition("Programmed", "False", old),
			},
		},
		map[string]any{
			"name": "secure",
			"conditions": []any{
				setNestedCondition("Accepted", "False", old),
				setNestedCondition("Conflicted", "True", old),
				setNestedCondition("Programmed", "False", old),
			},
		},
		map[string]any{
			"name": "badcert",
			"conditions": []any{
				setNestedCondition("Accepted", "False", old),
				setNestedCondition("ResolvedRefs", "False", old),
				setNestedCondition("Programmed", "False", old),
			},
		},
	}, "status", "listeners")

	out := checkGenericConditions(map[string][]*unstructured.Unstructured{"Gateway": {gw}}, now, threshold)

	var sawConflicted, sawResolvedRefs int
	for _, c := range out {
		if c.ConditionType == "Conflicted" {
			sawConflicted++
			if c.ConditionObservedValue != "True" {
				t.Fatalf("expected Conflicted observed value True, got %q", c.ConditionObservedValue)
			}
			if c.ConditionParentPath == "" || !strings.Contains(c.ConditionParentPath, "plain") && !strings.Contains(c.ConditionParentPath, "secure") {
				t.Fatalf("expected ConditionParentPath to name the listener (plain/secure), got %q", c.ConditionParentPath)
			}
			if !strings.Contains(c.Message, "plain") && !strings.Contains(c.Message, "secure") {
				t.Fatalf("expected the message alone (no struct field needed) to name the listener, got %q", c.Message)
			}
		}
		if c.ConditionType == "ResolvedRefs" {
			sawResolvedRefs++
			if !strings.Contains(c.ConditionParentPath, "badcert") {
				t.Fatalf("expected ResolvedRefs' ConditionParentPath to name the badcert listener, got %q", c.ConditionParentPath)
			}
		}
	}
	if sawConflicted != 2 {
		t.Fatalf("expected both listeners (plain, secure) to report Conflicted=True — this is the condition B154 was filed because it was entirely invisible; got %d Conflicted candidates out of %d total: %+v", sawConflicted, len(out), out)
	}
	if sawResolvedRefs != 1 {
		t.Fatalf("expected the badcert listener's ResolvedRefs=False to be visible too, got %d: %+v", sawResolvedRefs, out)
	}
}

// TestCheckGenericConditions_HTTPRouteShape_FindsPerParentConditions
// reproduces HTTPRoute's own shape from the same fixture: it has NO
// top-level status.conditions at all, only status.parents[].conditions,
// where the parent's own name lives one level further down, under its own
// parentRef — proving containerName's fallback (not just a direct "name"
// field) actually fires.
func TestCheckGenericConditions_HTTPRouteShape_FindsPerParentConditions(t *testing.T) {
	now := time.Now()
	old := now.Add(-time.Hour)
	threshold := 10 * time.Minute

	route := newGenericObj("gateway.networking.k8s.io/v1", "HTTPRoute", "gwapi-verify", "route-dangling-backend", "uid-route")
	_ = unstructured.SetNestedSlice(route.Object, []any{
		map[string]any{
			"controllerName": "gateway.nginx.org/nginx-gateway-controller",
			"parentRef": map[string]any{
				"group": "gateway.networking.k8s.io", "kind": "Gateway",
				"name": "gw-listener-conflict", "namespace": "gwapi-verify",
			},
			"conditions": []any{
				setNestedCondition("Accepted", "False", old),
				setNestedCondition("ResolvedRefs", "False", old),
			},
		},
	}, "status", "parents")

	out := checkGenericConditions(map[string][]*unstructured.Unstructured{"HTTPRoute": {route}}, now, threshold)

	var sawResolvedRefs bool
	for _, c := range out {
		if c.ConditionType == "ResolvedRefs" {
			sawResolvedRefs = true
			if !strings.Contains(c.ConditionParentPath, "gw-listener-conflict") {
				t.Fatalf("expected ConditionParentPath to name the parent via its nested parentRef.name, got %q", c.ConditionParentPath)
			}
		}
	}
	if !sawResolvedRefs {
		t.Fatalf("expected HTTPRoute's per-parent ResolvedRefs=False to be visible — before B154, HTTPRoute had no top-level status.conditions at all and produced zero findings; got %d candidates: %+v", len(out), out)
	}
}

// --- Predicate 2: generation vs observedGeneration ---

func TestCheckGenericObservedGenerationLag_FlagsGap(t *testing.T) {
	now := time.Now()
	o := newGenericObj("v1", "Ingress", "ns", "stale", "u")
	setGeneration(o, 3)
	setObservedGeneration(o, 1)

	out := checkGenericObservedGenerationLag(map[string][]*unstructured.Unstructured{"Ingress": {o}}, now)
	if len(out) != 1 {
		t.Fatalf("expected 1 candidate, got %d", len(out))
	}
	if out[0].Reason != reasonGenericObservedGenerationStale {
		t.Fatalf("unexpected reason %q", out[0].Reason)
	}
	// BACKLOG.md T1: lag of 2 (3-1) is the "several edits piled up" tier.
	if out[0].Severity != "medium" {
		t.Fatalf("expected severity 'medium' for a lag of 2, got %q", out[0].Severity)
	}
}

// TestCheckGenericObservedGenerationLag_SeverityScalesWithLag pins the
// low/high ends of the same signal the test above pins the middle of
// (BACKLOG.md T1): a single unacknowledged edit is the weakest, most
// transient-looking signal this predicate can report, and a large pile-up is
// the strongest.
func TestCheckGenericObservedGenerationLag_SeverityScalesWithLag(t *testing.T) {
	now := time.Now()

	single := newGenericObj("v1", "Ingress", "ns", "single-behind", "u")
	setGeneration(single, 2)
	setObservedGeneration(single, 1)

	pileup := newGenericObj("v1", "Ingress", "ns", "way-behind", "u2")
	setGeneration(pileup, 10)
	setObservedGeneration(pileup, 1)

	out := checkGenericObservedGenerationLag(map[string][]*unstructured.Unstructured{"Ingress": {single, pileup}}, now)
	if len(out) != 2 {
		t.Fatalf("expected 2 candidates, got %d", len(out))
	}
	got := map[string]string{}
	for _, c := range out {
		got[c.Name] = c.Severity
	}
	if got["single-behind"] != "low" {
		t.Errorf("expected 'single-behind' (lag 1) to be severity 'low', got %q", got["single-behind"])
	}
	if got["way-behind"] != "high" {
		t.Errorf("expected 'way-behind' (lag 9) to be severity 'high', got %q", got["way-behind"])
	}
}

func TestCheckGenericObservedGenerationLag_Converged_NoCandidate(t *testing.T) {
	now := time.Now()
	o := newGenericObj("v1", "Ingress", "ns", "converged", "u")
	setGeneration(o, 3)
	setObservedGeneration(o, 3)

	out := checkGenericObservedGenerationLag(map[string][]*unstructured.Unstructured{"Ingress": {o}}, now)
	if len(out) != 0 {
		t.Fatalf("expected no candidate for a converged object, got %d", len(out))
	}
}

func TestCheckGenericObservedGenerationLag_NoObservedGenerationField_NoCandidate(t *testing.T) {
	now := time.Now()
	o := newGenericObj("v1", "Widget", "ns", "no-status-field", "u")
	setGeneration(o, 3)
	// status.observedGeneration deliberately never set.

	out := checkGenericObservedGenerationLag(map[string][]*unstructured.Unstructured{"Widget": {o}}, now)
	if len(out) != 0 {
		t.Fatalf("expected no candidate when the kind never publishes observedGeneration, got %d", len(out))
	}
}

// --- Predicate 3: stuck finalizer ---

func TestCheckGenericStuckFinalizer_FlagsOldDeletion(t *testing.T) {
	now := time.Now()
	threshold := 10 * time.Minute
	o := newGenericObj("v1", "ConfigMap", "ns", "stuck", "u")
	setDeletionTimestamp(o, now.Add(-time.Hour))
	setFinalizers(o, "example.io/block")

	out := checkGenericStuckFinalizer(map[string][]*unstructured.Unstructured{"ConfigMap": {o}}, now, threshold)
	if len(out) != 1 {
		t.Fatalf("expected 1 candidate, got %d", len(out))
	}
	if out[0].SustainedFrom.IsZero() {
		t.Fatalf("expected SustainedFrom to carry the real deletionTimestamp")
	}
	// BACKLOG.md T1: 1 hour is well past 3x the 10-minute threshold —
	// unambiguously stuck, not just past the report floor.
	if out[0].Severity != "high" {
		t.Fatalf("expected severity 'high' for a deletion blocked 6x past threshold, got %q", out[0].Severity)
	}
}

// TestCheckGenericStuckFinalizer_JustPastThreshold_SeverityIsMedium pins the
// other end of stuckFinalizerSeverity's own scale (BACKLOG.md T1): a
// deletion blocked only just long enough to be reported at all is "confirmed
// stuck, not yet clearly abandoned" — medium, not high.
func TestCheckGenericStuckFinalizer_JustPastThreshold_SeverityIsMedium(t *testing.T) {
	now := time.Now()
	threshold := 10 * time.Minute
	o := newGenericObj("v1", "ConfigMap", "ns", "just-stuck", "u")
	setDeletionTimestamp(o, now.Add(-threshold))
	setFinalizers(o, "example.io/block")

	out := checkGenericStuckFinalizer(map[string][]*unstructured.Unstructured{"ConfigMap": {o}}, now, threshold)
	if len(out) != 1 {
		t.Fatalf("expected 1 candidate, got %d", len(out))
	}
	if out[0].Severity != "medium" {
		t.Fatalf("expected severity 'medium' for a deletion just past the report threshold, got %q", out[0].Severity)
	}
}

func TestCheckGenericStuckFinalizer_RecentDeletion_NoCandidate(t *testing.T) {
	now := time.Now()
	threshold := 10 * time.Minute
	o := newGenericObj("v1", "ConfigMap", "ns", "just-deleted", "u")
	setDeletionTimestamp(o, now.Add(-time.Second))
	setFinalizers(o, "example.io/block")

	out := checkGenericStuckFinalizer(map[string][]*unstructured.Unstructured{"ConfigMap": {o}}, now, threshold)
	if len(out) != 0 {
		t.Fatalf("expected no candidate for a deletion well inside the sustained window, got %d", len(out))
	}
}

func TestCheckGenericStuckFinalizer_NoDeletionTimestamp_NoCandidate(t *testing.T) {
	now := time.Now()
	o := newGenericObj("v1", "ConfigMap", "ns", "alive", "u")

	out := checkGenericStuckFinalizer(map[string][]*unstructured.Unstructured{"ConfigMap": {o}}, now, 10*time.Minute)
	if len(out) != 0 {
		t.Fatalf("expected no candidate for a live object, got %d", len(out))
	}
}

// readSnapshotOf wraps a hand-built "Kind -> objects" fixture in the
// per-pass snapshot the predicates now take, marking every kind in it as
// successfully read. That is the right default for a fixture: the objects
// are there because the test put them there, which is exactly what a
// completed List means. A test about a kind that could NOT be read builds
// its snapshot explicitly instead (see the B185 cases).
func readSnapshotOf(objectsByKind map[string][]*unstructured.Unstructured) *unstructuredSnapshot {
	snap := newUnstructuredSnapshot()
	for kind, objs := range objectsByKind {
		snap.record(kind, kindReadResult{state: kindReadOK})
		snap.add(kind, objs)
	}
	return snap
}

// --- Predicate 4: dangling reference ---

func TestCheckGenericDanglingReference_FlagsMissingTarget(t *testing.T) {
	now := time.Now()
	hpa := newGenericObj("autoscaling/v2", "HorizontalPodAutoscaler", "ns", "hpa1", "u")
	setSpecRef(hpa, []string{"spec", "scaleTargetRef"}, "Deployment", "does-not-exist", "")

	objectsByKind := map[string][]*unstructured.Unstructured{
		"HorizontalPodAutoscaler": {hpa},
		"Deployment":              {newGenericObj("apps/v1", "Deployment", "ns", "some-other-deployment", "u")},
	}
	out := checkGenericDanglingReference(readSnapshotOf(objectsByKind), now)
	if len(out) != 1 {
		t.Fatalf("expected 1 dangling-reference candidate, got %d: %+v", len(out), out)
	}
	if out[0].Reason != genericDanglingReferenceReasonPrefix+"Deployment" {
		t.Fatalf("unexpected reason %q", out[0].Reason)
	}
	// BACKLOG.md T1: this predicate is a deliberate, reasoned constant (see
	// checkGenericDanglingReference's own doc comment) — pin the value so a
	// future change to it is a conscious edit, not a silent drift.
	if out[0].Severity != "medium" {
		t.Fatalf("expected the reasoned constant severity 'medium', got %q", out[0].Severity)
	}
	if out[0].Class != tunnel.FindingClassAnomaly || out[0].Confidence != tunnel.FindingConfidenceUnverified || out[0].Impact != tunnel.FindingImpactNone {
		t.Fatalf("generic reference evidence = %s/%s/%s, want anomaly/unverified/none", out[0].Class, out[0].Confidence, out[0].Impact)
	}
}

func TestCheckGenericDanglingReference_ExistingTarget_NoCandidate(t *testing.T) {
	now := time.Now()
	hpa := newGenericObj("autoscaling/v2", "HorizontalPodAutoscaler", "ns", "hpa1", "u")
	setSpecRef(hpa, []string{"spec", "scaleTargetRef"}, "Deployment", "real-deployment", "")

	objectsByKind := map[string][]*unstructured.Unstructured{
		"HorizontalPodAutoscaler": {hpa},
		"Deployment":              {newGenericObj("apps/v1", "Deployment", "ns", "real-deployment", "u")},
	}
	out := checkGenericDanglingReference(readSnapshotOf(objectsByKind), now)
	if len(out) != 0 {
		t.Fatalf("expected no candidate when the referenced object exists, got %d: %+v", len(out), out)
	}
}

// TestCheckGenericDanglingReference_TopLevelField_RoleBindingSubjects is
// PROJECT.md B148's regression test: found live 2026-09-06 (breadth-campaign
// RBAC-004 fixture) — a RoleBinding naming a nonexistent ServiceAccount in
// its subjects never opened an incident, because subjects/roleRef sit at
// the object's TOP LEVEL (siblings of apiVersion/kind/metadata), not nested
// under a spec or a status the old spec/status-only scan could see.
func TestCheckGenericDanglingReference_TopLevelField_RoleBindingSubjects(t *testing.T) {
	now := time.Now()
	rb := newGenericObj("rbac.authorization.k8s.io/v1", "RoleBinding", "ns", "rb1", "u")
	rb.Object["subjects"] = []any{
		map[string]any{"kind": "ServiceAccount", "name": "does-not-exist", "namespace": "ns"},
	}
	rb.Object["roleRef"] = map[string]any{"kind": "Role", "name": "some-role", "apiGroup": "rbac.authorization.k8s.io"}

	objectsByKind := map[string][]*unstructured.Unstructured{
		"RoleBinding":    {rb},
		"Role":           {newGenericObj("rbac.authorization.k8s.io/v1", "Role", "ns", "some-role", "u")}, // roleRef resolves — only subjects should dangle
		"ServiceAccount": {newGenericObj("v1", "ServiceAccount", "ns", "some-other-sa", "u")},
	}
	out := checkGenericDanglingReference(readSnapshotOf(objectsByKind), now)
	if len(out) != 1 {
		t.Fatalf("expected 1 dangling-reference candidate for the RoleBinding's top-level subjects field, got %d: %+v", len(out), out)
	}
	if out[0].Reason != genericDanglingReferenceReasonPrefix+"ServiceAccount" {
		t.Fatalf("unexpected reason %q", out[0].Reason)
	}
}

// TestCheckGenericDanglingReference_OwnerReferencesNeverFlagged confirms the
// one deliberate exclusion in B148's fix: metadata (and so
// metadata.ownerReferences, which also carries a kind+name pair
// findObjectReferences would otherwise match) is never scanned. Owner
// reference garbage collection is a different Kubernetes mechanism with
// different semantics — a stale ownerReference can be a deliberate, correct
// state (an object orphaned on purpose), not a fault this predicate exists
// to flag.
func TestCheckGenericDanglingReference_OwnerReferencesNeverFlagged(t *testing.T) {
	now := time.Now()
	obj := newGenericObj("v1", "ConfigMap", "ns", "cm1", "u")
	obj.Object["metadata"].(map[string]any)["ownerReferences"] = []any{
		map[string]any{"kind": "Deployment", "name": "does-not-exist", "uid": "gone"},
	}

	objectsByKind := map[string][]*unstructured.Unstructured{"ConfigMap": {obj}}
	out := checkGenericDanglingReference(readSnapshotOf(objectsByKind), now)
	if len(out) != 0 {
		t.Fatalf("expected no candidate from a dangling ownerReference (metadata is deliberately excluded), got %d: %+v", len(out), out)
	}
}

// TestCheckGenericAdmissionPolicyTypeChecking_FlagsAWarning is PROJECT.md
// B149's regression test, built from the real status shape confirmed live
// 2026-09-06 against this project's own rke2 test cluster
// (`kubectl get --raw` against a real ValidatingAdmissionPolicy whose CEL
// expression referenced a field that does not exist on its matched kind).
func TestCheckGenericAdmissionPolicyTypeChecking_FlagsAWarning(t *testing.T) {
	now := time.Now()
	vap := newGenericObj("admissionregistration.k8s.io/v1", "ValidatingAdmissionPolicy", "", "b149-probe", "u")
	if err := unstructured.SetNestedSlice(vap.Object, []any{
		map[string]any{
			"fieldRef": "spec.validations[0].expression",
			"warning":  "/v1, Kind=ConfigMap: ERROR: <input>:1:7: undefined field 'spec'",
		},
	}, "status", "typeChecking", "expressionWarnings"); err != nil {
		t.Fatalf("build fixture: %v", err)
	}

	out := checkGenericAdmissionPolicyTypeChecking(map[string][]*unstructured.Unstructured{"ValidatingAdmissionPolicy": {vap}}, now)
	if len(out) != 1 {
		t.Fatalf("expected 1 candidate, got %d: %+v", len(out), out)
	}
	if out[0].Reason != reasonGenericAdmissionPolicyTypeCheckWarning {
		t.Errorf("Reason = %q, want %q", out[0].Reason, reasonGenericAdmissionPolicyTypeCheckWarning)
	}
	if out[0].Severity != "high" {
		t.Errorf("Severity = %q, want high (B149: unbounded future blast radius)", out[0].Severity)
	}
	if !strings.Contains(out[0].Message, "undefined field 'spec'") {
		t.Errorf("Message = %q, want it to quote the real type-checking warning", out[0].Message)
	}
}

// TestCheckGenericAdmissionPolicyTypeChecking_NoWarnings_NoCandidate confirms
// a healthy policy (no expressionWarnings at all, the common case) produces
// no candidate.
func TestCheckGenericAdmissionPolicyTypeChecking_NoWarnings_NoCandidate(t *testing.T) {
	now := time.Now()
	vap := newGenericObj("admissionregistration.k8s.io/v1", "ValidatingAdmissionPolicy", "", "healthy-policy", "u")
	_ = unstructured.SetNestedField(vap.Object, int64(1), "status", "observedGeneration")

	out := checkGenericAdmissionPolicyTypeChecking(map[string][]*unstructured.Unstructured{"ValidatingAdmissionPolicy": {vap}}, now)
	if len(out) != 0 {
		t.Fatalf("expected no candidate for a policy with no type-checking warnings, got %d: %+v", len(out), out)
	}
}

// TestCheckGenericAdmissionPolicyTypeChecking_IgnoresOtherKinds confirms this
// predicate only ever looks at objectsByKind["ValidatingAdmissionPolicy"] —
// an unrelated kind sitting in the same sweep must never be mistaken for one.
func TestCheckGenericAdmissionPolicyTypeChecking_IgnoresOtherKinds(t *testing.T) {
	now := time.Now()
	out := checkGenericAdmissionPolicyTypeChecking(map[string][]*unstructured.Unstructured{
		"ConfigMap": {newGenericObj("v1", "ConfigMap", "ns", "cm1", "u")},
	}, now)
	if len(out) != 0 {
		t.Fatalf("expected no candidate from an unrelated kind, got %d: %+v", len(out), out)
	}
}

func TestCheckGenericDanglingReference_UnknownTargetKind_SilentNotFlagged(t *testing.T) {
	now := time.Now()
	obj := newGenericObj("v1", "Widget", "ns", "w1", "u")
	setSpecRef(obj, []string{"spec", "somethingRef"}, "TotallyUnwatchedKind", "whatever", "")

	objectsByKind := map[string][]*unstructured.Unstructured{"Widget": {obj}}
	out := checkGenericDanglingReference(readSnapshotOf(objectsByKind), now)
	if len(out) != 0 {
		t.Fatalf("expected no claim about a kind this agent cannot verify, got %d: %+v", len(out), out)
	}
}

func TestCheckGenericDanglingReference_CrossNamespaceRef_Respected(t *testing.T) {
	now := time.Now()
	obj := newGenericObj("v1", "RoleBinding", "ns-a", "rb1", "u")
	// References a ServiceAccount explicitly in a DIFFERENT namespace, inside
	// a list-shaped "subjects" field — findObjectReferences walks arbitrary
	// nesting including slices, so this exercises that path too.
	_ = unstructured.SetNestedSlice(obj.Object, []any{map[string]any{"kind": "ServiceAccount", "name": "sa1", "namespace": "ns-b"}}, "spec", "subjects")

	objectsByKind := map[string][]*unstructured.Unstructured{
		"RoleBinding":    {obj},
		"ServiceAccount": {newGenericObj("v1", "ServiceAccount", "ns-b", "sa1", "u")},
	}
	out := checkGenericDanglingReference(readSnapshotOf(objectsByKind), now)
	if len(out) != 0 {
		t.Fatalf("expected the cross-namespace reference to resolve against ns-b, not the referrer's own namespace, got %d: %+v", len(out), out)
	}
}

// --- Predicate 5: peer-relative outlier ---

func TestCheckGenericPeerOutlier_FlagsMinorityShape(t *testing.T) {
	now := time.Now()
	old := now.Add(-time.Hour)
	var objs []*unstructured.Unstructured
	for i := 0; i < 4; i++ {
		o := newGenericObj("v1", "Pod", "ns", "pod-"+string(rune('a'+i)), "u"+string(rune('a'+i)))
		setControllerOwner(o, "owner-1")
		setCondition(o, "Ready", "True", old)
		objs = append(objs, o)
	}
	oddOne := newGenericObj("v1", "Pod", "ns", "pod-odd", "u-odd")
	setControllerOwner(oddOne, "owner-1")
	setCondition(oddOne, "Ready", "False", old)
	objs = append(objs, oddOne)

	out := checkGenericPeerOutlier(map[string][]*unstructured.Unstructured{"Pod": objs}, now)
	if len(out) != 1 {
		t.Fatalf("expected 1 outlier candidate, got %d: %+v", len(out), out)
	}
	if out[0].Name != "pod-odd" {
		t.Fatalf("expected pod-odd to be flagged, got %q", out[0].Name)
	}
	// BACKLOG.md T1: a lone outlier among 5 siblings is the "one pod of
	// twenty" case — low, not the old flat "low"-for-everything either, but
	// the same VALUE this specific shape should still produce.
	if out[0].Severity != "low" {
		t.Fatalf("expected severity 'low' for a lone outlier, got %q", out[0].Severity)
	}
	if out[0].Class != tunnel.FindingClassAnomaly || out[0].Confidence != tunnel.FindingConfidenceInferred || out[0].Impact != tunnel.FindingImpactNone {
		t.Fatalf("generic peer evidence = %s/%s/%s, want anomaly/inferred/none", out[0].Class, out[0].Confidence, out[0].Impact)
	}
}

// TestCheckGenericPeerOutlier_SharedMinorityShape_SeverityEscalates is the
// high-blast-radius counterpart: when several siblings share the SAME
// off-majority shape at once, severity must escalate with them (BACKLOG.md
// T1), not stay pinned at the lone-outlier value.
func TestCheckGenericPeerOutlier_SharedMinorityShape_SeverityEscalates(t *testing.T) {
	now := time.Now()
	old := now.Add(-time.Hour)
	var objs []*unstructured.Unstructured
	// 6 majority + 5 sharing one divergent shape = 11 siblings, majority
	// 6/11 > half, minority-shape count 5 matches minGenericPolaritySamples.
	for i := 0; i < 6; i++ {
		o := newGenericObj("v1", "Pod", "ns", "healthy-"+string(rune('a'+i)), "uh"+string(rune('a'+i)))
		setControllerOwner(o, "owner-1")
		setCondition(o, "Ready", "True", old)
		objs = append(objs, o)
	}
	for i := 0; i < 5; i++ {
		o := newGenericObj("v1", "Pod", "ns", "degraded-"+string(rune('a'+i)), "ud"+string(rune('a'+i)))
		setControllerOwner(o, "owner-1")
		setCondition(o, "Ready", "False", old)
		objs = append(objs, o)
	}

	out := checkGenericPeerOutlier(map[string][]*unstructured.Unstructured{"Pod": objs}, now)
	if len(out) != 5 {
		t.Fatalf("expected all 5 minority-shape siblings flagged, got %d: %+v", len(out), out)
	}
	for _, c := range out {
		if c.Severity != "high" {
			t.Errorf("object %s: expected severity 'high' when 5 siblings share the same minority shape, got %q", c.Name, c.Severity)
		}
	}
}

func TestCheckGenericPeerOutlier_NoMajority_NoCandidate(t *testing.T) {
	now := time.Now()
	old := now.Add(-time.Hour)
	shapes := []string{"True", "False", "Unknown"}
	var objs []*unstructured.Unstructured
	for i, s := range shapes {
		o := newGenericObj("v1", "Pod", "ns", "pod-"+string(rune('a'+i)), "u")
		setControllerOwner(o, "owner-1")
		setCondition(o, "Ready", s, old)
		objs = append(objs, o)
	}
	out := checkGenericPeerOutlier(map[string][]*unstructured.Unstructured{"Pod": objs}, now)
	if len(out) != 0 {
		t.Fatalf("expected no candidate when no shape has a genuine majority, got %d: %+v", len(out), out)
	}
}

func TestCheckGenericPeerOutlier_BelowMinGroupSize_NoCandidate(t *testing.T) {
	now := time.Now()
	old := now.Add(-time.Hour)
	a := newGenericObj("v1", "Pod", "ns", "pod-a", "u")
	setControllerOwner(a, "owner-1")
	setCondition(a, "Ready", "True", old)
	b := newGenericObj("v1", "Pod", "ns", "pod-b", "u")
	setControllerOwner(b, "owner-1")
	setCondition(b, "Ready", "False", old)

	out := checkGenericPeerOutlier(map[string][]*unstructured.Unstructured{"Pod": {a, b}}, now)
	if len(out) != 0 {
		t.Fatalf("expected no candidate below minPeerGroupSize, got %d: %+v", len(out), out)
	}
}

func TestCheckGenericPeerOutlier_NoOwner_NotGrouped(t *testing.T) {
	now := time.Now()
	old := now.Add(-time.Hour)
	var objs []*unstructured.Unstructured
	for i := 0; i < 5; i++ {
		o := newGenericObj("v1", "Pod", "ns", "standalone-"+string(rune('a'+i)), "u")
		setCondition(o, "Ready", "True", old)
		objs = append(objs, o)
	}
	out := checkGenericPeerOutlier(map[string][]*unstructured.Unstructured{"Pod": objs}, now)
	if len(out) != 0 {
		t.Fatalf("expected no grouping at all for objects with no controlling owner, got %d: %+v", len(out), out)
	}
}

// TestCheckGenericPeerOutlier_TerminalPhasePod_NotFlagged pins BUGS.md 137:
// a completed Job pod's Ready=False (the correct, permanent reading for
// phase Succeeded) must not be flagged as an outlier against its
// still-running siblings, and must not be counted in their population
// either — a real Succeeded pod is not "wrong" relative to them, it is a
// different, incomparable population.
func TestCheckGenericPeerOutlier_TerminalPhasePod_NotFlagged(t *testing.T) {
	now := time.Now()
	old := now.Add(-time.Hour)
	var objs []*unstructured.Unstructured
	for i := 0; i < 4; i++ {
		o := newGenericObj("v1", "Pod", "ns", "running-"+string(rune('a'+i)), "ur"+string(rune('a'+i)))
		setControllerOwner(o, "owner-1")
		setPodPhase(o, "Running")
		setCondition(o, "Ready", "True", old)
		objs = append(objs, o)
	}
	completed := newGenericObj("v1", "Pod", "ns", "job-completed", "uc")
	setControllerOwner(completed, "owner-1")
	setPodPhase(completed, "Succeeded")
	setCondition(completed, "Ready", "False", old)
	objs = append(objs, completed)

	out := checkGenericPeerOutlier(map[string][]*unstructured.Unstructured{"Pod": objs}, now)
	if len(out) != 0 {
		t.Fatalf("expected the terminal-phase pod not to be flagged, got %d candidate(s): %+v", len(out), out)
	}
}

// --- listWatchedKindObjects / buildExistenceIndex / kindIsNamespaced ---

func TestKindIsNamespaced_KnownAndUnknownKinds(t *testing.T) {
	if ns, known := kindIsNamespaced("Deployment"); !known || !ns {
		t.Fatalf("expected Deployment to be known and namespaced, got known=%v namespaced=%v", known, ns)
	}
	if ns, known := kindIsNamespaced("Node"); !known || ns {
		t.Fatalf("expected Node to be known and cluster-scoped, got known=%v namespaced=%v", known, ns)
	}
	if _, known := kindIsNamespaced("NoSuchKindAnywhere"); known {
		t.Fatalf("expected an unwatched kind to be reported unknown")
	}
}

func TestExistenceIndex(t *testing.T) {
	snap := readSnapshotOf(map[string][]*unstructured.Unstructured{
		"Deployment": {newGenericObj("apps/v1", "Deployment", "ns", "d1", "u")},
	})
	idx := snap.existenceIndex()
	if !idx["Deployment"]["ns/d1"] {
		t.Fatalf("expected ns/d1 to be indexed")
	}
	if idx["Deployment"]["ns/d2"] {
		t.Fatalf("did not expect a false positive for a name never listed")
	}
}

// TestExistenceIndexOmitsAKindThatWasNotRead is the index half of PROJECT.md
// B185: a kind this pass could not read has NO entry, which is what makes
// "this object is not there" a different lookup from "I could not look".
func TestExistenceIndexOmitsAKindThatWasNotRead(t *testing.T) {
	snap := newUnstructuredSnapshot()
	snap.record("Deployment", kindReadResult{state: kindReadOK})
	snap.add("Deployment", []*unstructured.Unstructured{newGenericObj("apps/v1", "Deployment", "ns", "d1", "u")})
	snap.record("Secret", kindReadResult{state: kindNotListed, reason: "never listed"})

	idx := snap.existenceIndex()
	if _, ok := idx["Deployment"]; !ok {
		t.Fatal("a kind that was read must be indexed")
	}
	if _, ok := idx["Secret"]; ok {
		t.Fatal("a kind that was never read must have no existence index at all")
	}
}

// TestListWatchedKindObjects_DiscoveredKindIsUnionedIn is BACKLOG.md E11
// piece 1's own wiring, exercised end to end through listWatchedKindObjects:
// a kind NOT in supportedGVKs, but present in a WatchSetCache's discovered
// set, must be listed and folded into the same objectsByKind map every
// existing predicate already reads — and a kind that IS in BOTH must never
// be listed twice.
func TestListWatchedKindObjects_DiscoveredKindIsUnionedIn(t *testing.T) {
	t.Cleanup(func() { discoveredWatchSetCache.Store(nil) })

	widgetGVR := schema.GroupVersionResource{Group: "example.com", Version: "v1", Resource: "widgets"}
	podGVR := schema.GroupVersionResource{Group: "", Version: "v1", Resource: "pods"}

	widget := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "example.com/v1", "kind": "Widget",
		"metadata": map[string]any{"name": "w1", "namespace": "default", "uid": "uid-w1"},
	}}
	pod := newGenericObj("v1", "Pod", "default", "p1", "uid-p1")

	scheme := runtime.NewScheme()
	gvrToKind := map[schema.GroupVersionResource]string{
		widgetGVR: "WidgetList",
		podGVR:    "PodList",
	}
	dyn := dynfake.NewSimpleDynamicClientWithCustomListKinds(scheme, gvrToKind, widget, pod)

	disc := &fakeDiscoverer{lists: []*metav1.APIResourceList{podsResourceList(), widgetsResourceList()}}
	rules := &fakeRulesReviewer{rules: []authorizationv1.ResourceRule{fullRule("", "pods"), fullRule("example.com", "widgets")}}
	discoveredWatchSetCache.Store(NewWatchSetCache(disc, rules, time.Hour))

	out, err := listWatchedKindObjects(context.Background(), dyn, sweepReadPlan{})
	if err != nil {
		t.Fatalf("listWatchedKindObjects: %v", err)
	}

	if got := len(out.objectsOf("Widget")); got != 1 {
		t.Fatalf("expected Widget (discovered, not in supportedGVKs) to be listed once, got %d: %+v", got, out.objectsOf("Widget"))
	}
	if got := len(out.objectsOf("Pod")); got != 1 {
		t.Fatalf("expected Pod (in supportedGVKs AND the discovered set) to be listed exactly once, not double-listed, got %d", got)
	}
	if !out.readable("Widget") || !out.readable("Pod") {
		t.Fatalf("expected both kinds to be recorded as read this pass")
	}
}

// TestListWatchedKindObjects_NilDiscoveredWatchSetIsANoOp confirms the
// pre-E11-piece-1 default (discoveredWatchSetCache never set) behaves
// exactly as before this change — no discovered kind appears, and
// supportedGVKs kinds are listed exactly as they always were.
func TestListWatchedKindObjects_NilDiscoveredWatchSetIsANoOp(t *testing.T) {
	discoveredWatchSetCache.Store(nil) // the real, pre-wiring default; explicit for clarity

	podGVR := schema.GroupVersionResource{Group: "", Version: "v1", Resource: "pods"}
	pod := newGenericObj("v1", "Pod", "default", "p1", "uid-p1")
	scheme := runtime.NewScheme()
	dyn := dynfake.NewSimpleDynamicClientWithCustomListKinds(scheme, map[schema.GroupVersionResource]string{podGVR: "PodList"}, pod)

	out, err := listWatchedKindObjects(context.Background(), dyn, sweepReadPlan{})
	if err != nil {
		t.Fatalf("listWatchedKindObjects: %v", err)
	}

	if got := out.objectsOf("Widget"); got != nil {
		t.Fatalf("expected no Widget entry with discoveredWatchSetCache nil, got %+v", got)
	}
	if got := len(out.objectsOf("Pod")); got != 1 {
		t.Fatalf("expected supportedGVKs' own Pod listing to be unaffected, got %d", got)
	}
}

// TestAttachOutboundReferences_PopulatesForEveryCandidateRegardlessOfPredicate
// is PROJECT.md B153's addendum: References must be attached to EVERY
// candidate checkGenericObjectHealth's dispatcher produces, not only ones
// checkGenericDanglingReference itself emits — a Fault-classed candidate
// from a totally different predicate, on an object that happens to also
// carry an outbound reference, needs it too (the hub's own
// reference-direction impact check reads it from THAT finding).
func TestAttachOutboundReferences_PopulatesForEveryCandidateRegardlessOfPredicate(t *testing.T) {
	route := newGenericObj("gateway.networking.k8s.io/v1", "HTTPRoute", "prod", "my-route", "u")
	route.Object["spec"] = map[string]any{
		"parentRefs": []any{
			map[string]any{"kind": "Gateway", "name": "my-gateway"}, // namespace omitted deliberately
		},
	}
	objectsByKind := map[string][]*unstructured.Unstructured{"HTTPRoute": {route}}

	// A candidate from an unrelated predicate (simulated directly — not
	// actually checkGenericDanglingReference's own output), on the SAME
	// object, must still get References attached.
	candidates := []sweepCandidate{
		{GVK: "gateway.networking.k8s.io/v1/HTTPRoute", Namespace: "prod", Name: "my-route", Reason: "SomeOtherFault"},
	}
	attachOutboundReferences(candidates, objectsByKind)

	if len(candidates[0].References) != 1 {
		t.Fatalf("References = %+v, want exactly 1 (the parentRef)", candidates[0].References)
	}
	got := candidates[0].References[0]
	if got.Kind != "Gateway" || got.Name != "my-gateway" {
		t.Errorf("reference = %+v, want Kind=Gateway Name=my-gateway", got)
	}
	// The namespace-defaulting rule: parentRefs omitted namespace, so it
	// must default to the REFERRING object's own namespace (Gateway API's
	// own convention for parentRefs, mirrored from
	// checkGenericDanglingReference's identical rule for existence-checking).
	if got.Namespace != "prod" {
		t.Errorf("reference.Namespace = %q, want %q (defaulted from the HTTPRoute's own namespace)", got.Namespace, "prod")
	}
}

// TestAttachOutboundReferences_NoReferencesLeavesFieldEmpty confirms an
// object with nothing reference-shaped in its top-level fields gets no
// References at all (nil, not an empty-but-present slice) — the honest
// default migration 000100's own comment argues for (NULL, not `[]`).
func TestAttachOutboundReferences_NoReferencesLeavesFieldEmpty(t *testing.T) {
	pod := newGenericObj("v1", "Pod", "default", "plain-pod", "u")
	objectsByKind := map[string][]*unstructured.Unstructured{"Pod": {pod}}
	candidates := []sweepCandidate{{GVK: "v1/Pod", Namespace: "default", Name: "plain-pod", Reason: "CrashLoopBackOff"}}

	attachOutboundReferences(candidates, objectsByKind)

	if len(candidates[0].References) != 0 {
		t.Errorf("References = %+v, want none", candidates[0].References)
	}
}

// --- PROJECT.md B185: an unreadable kind is not an empty kind ---

// b185Fixture is one HorizontalPodAutoscaler whose scaleTargetRef names a
// Deployment that this pass will not find, and a dynamic client that can
// answer a List for both kinds. Everything about the two cases below is
// identical except WHY the Deployment is not in the snapshot.
func b185Fixture(t *testing.T) (*unstructured.Unstructured, map[schema.GroupVersionResource]string) {
	t.Helper()
	hpa := newGenericObj("autoscaling/v2", "HorizontalPodAutoscaler", "ns", "hpa1", "uid-hpa")
	setSpecRef(hpa, []string{"spec", "scaleTargetRef"}, "Deployment", "target-that-is-not-listed", "")
	return hpa, map[schema.GroupVersionResource]string{
		{Group: "autoscaling", Version: "v2", Resource: "horizontalpodautoscalers"}: "HorizontalPodAutoscalerList",
		{Group: "apps", Version: "v1", Resource: "deployments"}:                     "DeploymentList",
	}
}

// TestDanglingReference_EmptyKindStillReportsADanglingReference is the
// control for the test below it. Without this, "no finding" would be
// indistinguishable from "this predicate stopped working".
func TestDanglingReference_EmptyKindStillReportsADanglingReference(t *testing.T) {
	hpa, listKinds := b185Fixture(t)
	dyn := dynfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), listKinds, hpa)

	snap, err := listWatchedKindObjects(context.Background(), dyn, sweepReadPlan{})
	if err != nil {
		t.Fatalf("listWatchedKindObjects: %v", err)
	}
	if !snap.readable("Deployment") {
		t.Fatalf("Deployment should have been read successfully (and found empty): %s", snap.unreadableReason("Deployment"))
	}
	out := checkGenericDanglingReference(snap, time.Now())
	if len(out) != 1 {
		t.Fatalf("a reference into a kind this pass READ and found empty is genuinely dangling; got %d candidate(s): %+v", len(out), out)
	}
}

// TestDanglingReference_RBACDeniedKindIsNotDangling is PROJECT.md B185
// itself. Same cluster, same reference, same predicate — the only change is
// that the agent may not list Deployments. Before the snapshot carried a
// read record, that produced exactly the finding above: a fabricated
// "references a Deployment that does not currently exist" about a Deployment
// that is merely invisible, and one per reference into the denied kind
// across the whole cluster.
func TestDanglingReference_RBACDeniedKindIsNotDangling(t *testing.T) {
	hpa, listKinds := b185Fixture(t)
	dyn := dynfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), listKinds, hpa)
	dyn.PrependReactor("list", "deployments", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewForbidden(schema.GroupResource{Group: "apps", Resource: "deployments"},
			"", fmt.Errorf(`deployments.apps is forbidden: User "system:serviceaccount:argus:argus-investigate" cannot list resource "deployments"`))
	})

	snap, err := listWatchedKindObjects(context.Background(), dyn, sweepReadPlan{})
	if err != nil {
		t.Fatalf("listWatchedKindObjects: %v", err)
	}
	if snap.readable("Deployment") {
		t.Fatal("a kind RBAC denied must not be recorded as read")
	}
	if reason := snap.unreadableReason("Deployment"); !strings.Contains(reason, "RBAC") {
		t.Fatalf("the recorded reason must say what an operator has to fix, got %q", reason)
	}
	if got := snap.readState("Deployment"); got != kindForbidden {
		t.Fatalf("readState = %v, want kindForbidden — a denied kind must be distinguishable from one the cluster does not serve", got)
	}

	out := checkGenericDanglingReference(snap, time.Now())
	if len(out) != 0 {
		t.Fatalf("a reference into a kind this agent may not READ must produce no dangling-reference finding; got %d: %+v", len(out), out)
	}
}

// TestDanglingReference_SecretReferenceIsNotDangling is the case
// genericPredicateExcludedKinds used to be believed to cover and did not.
// Secret is never listed, so it never had an existence index, so every
// explicit kind+name reference to one was reported as broken. It is now
// covered by the same general mechanism as every other unreadable kind,
// rather than by a second hand-maintained list.
func TestDanglingReference_SecretReferenceIsNotDangling(t *testing.T) {
	obj := newGenericObj("v1", "ConfigMap", "ns", "cm1", "uid-cm")
	setSpecRef(obj, []string{"spec", "credentialsRef"}, "Secret", "db-password", "")

	snap := newUnstructuredSnapshot()
	snap.record("ConfigMap", kindReadResult{state: kindReadOK})
	snap.add("ConfigMap", []*unstructured.Unstructured{obj})
	snap.record("Secret", kindReadResult{state: kindNotListed, reason: "Secret is deliberately never listed by this agent"})

	if out := checkGenericDanglingReference(snap, time.Now()); len(out) != 0 {
		t.Fatalf("a reference to a Secret must produce no dangling-reference finding — this agent never lists Secrets and so cannot know; got %d: %+v", len(out), out)
	}
}

// TestSnapshotDistinguishesEveryWayAKindCanBeMissing pins the distinction
// the whole record exists to make, at the level it is made.
func TestSnapshotDistinguishesEveryWayAKindCanBeMissing(t *testing.T) {
	snap := newUnstructuredSnapshot()
	snap.record("Deployment", kindReadResult{state: kindReadOK})
	snap.record("Backup", kindReadResult{state: kindNotServed, reason: "no CRD"})
	snap.record("Node", kindReadResult{state: kindForbidden, reason: "RBAC denies list on Node"})

	if !snap.readable("Deployment") {
		t.Error("a kind that was read and found empty is readable")
	}
	if snap.readable("Backup") || snap.readable("Node") {
		t.Error("a kind that was not read must never report as readable")
	}
	if snap.readState("Backup") == snap.readState("Node") {
		t.Error("a CRD nobody installed and a kind RBAC denies are different operator situations and must stay distinguishable")
	}
	// A kind nothing ever attempted is unknown, not empty — the safe answer
	// for a predicate that reads absence as fact.
	if snap.readable("NeverHeardOfIt") {
		t.Error("an unattempted kind must not report as readable")
	}
	if snap.unreadableReason("Deployment") != "" {
		t.Error("a readable kind has no unreadable reason")
	}
}
