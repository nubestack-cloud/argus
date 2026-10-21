package importance

import (
	"fmt"
	"math"
	"strings"
	"testing"
)

func confPtr(v float64) *float64 { return &v }
func priPtr(v int32) *int32      { return &v }

func TestScore_IsomorphicToItsOwnWeights(t *testing.T) {
	f := Factors{BlastRadius: 3, AgeHours: 10, OccurrenceRate: 2, Confidence: confPtr(0.8)}
	want := WeightBlastRadius*3 + WeightAgeHours*10 + WeightOccurrenceRate*2 + WeightConfidence*0.8
	if got := Score(f); got != want {
		t.Fatalf("Score(%+v) = %v, want %v", f, got, want)
	}
}

func TestScore_NoAnalysisYetContributesNothing(t *testing.T) {
	withNil := Score(Factors{BlastRadius: 1, AgeHours: 5, OccurrenceRate: 1, Confidence: nil})
	withZero := Score(Factors{BlastRadius: 1, AgeHours: 5, OccurrenceRate: 1, Confidence: confPtr(0)})
	if withNil != withZero {
		t.Fatalf("nil confidence scored %v, explicit 0 confidence scored %v — want equal (both mean 'no confirmed evidence')", withNil, withZero)
	}
}

// A widely-shared fault, long open, recurring often, confidently diagnosed
// must outrank an isolated, fresh, one-off, unanalyzed incident — the
// direct case T1 exists to make possible without a per-kind table.
func TestScore_OrdersTheObviousCase(t *testing.T) {
	important := Score(Factors{BlastRadius: 12, AgeHours: 120, OccurrenceRate: 4, Confidence: confPtr(0.95)})
	unimportant := Score(Factors{BlastRadius: 1, AgeHours: 1, OccurrenceRate: 0, Confidence: nil})
	if important <= unimportant {
		t.Fatalf("important score %v, unimportant score %v — want important > unimportant", important, unimportant)
	}
}

func TestSQLExpr_UsesTheSameWeightsAsScore(t *testing.T) {
	expr := SQLExpr("br", "age", "rate", "conf")
	for _, want := range []string{"br", "age", "rate", "conf", "BIGINT"} {
		if !strings.Contains(expr, want) {
			t.Errorf("SQLExpr output missing %q; got: %s", want, expr)
		}
	}
	// The weights themselves must appear literally — this is what keeps the
	// SQL expression and Score from silently drifting apart on the actual
	// numbers (this package's own doc comment on why there is only one
	// source of truth for them).
	for _, weight := range []float64{WeightBlastRadius, WeightAgeHours, WeightOccurrenceRate, WeightConfidence} {
		marker := formatWeight(weight)
		if !strings.Contains(expr, marker) {
			t.Errorf("SQLExpr output missing weight literal %q (from %v); got: %s", marker, weight, expr)
		}
	}
}

// formatWeight mirrors SQLExpr's own %g formatting exactly, so this test
// fails if that verb ever changes without this test noticing.
func formatWeight(w float64) string {
	return fmt.Sprintf("%g", w)
}

func TestExplain_OmitsFactorsThatContributedNothing(t *testing.T) {
	reasons := Explain(Factors{BlastRadius: 1, AgeHours: 0, OccurrenceRate: 0, Confidence: nil})
	if reasons != nil {
		t.Fatalf("Explain(all-silent factors) = %v, want nil", reasons)
	}
}

func TestExplain_RanksByActualContributionNotFieldOrder(t *testing.T) {
	// Confidence (weight 20/point) at 0.95 contributes 19 — more than
	// AgeHours=10 (weight 0.5/hour, contributes 5) — so confidence's own
	// sentence must be listed FIRST even though AgeHours is checked before
	// Confidence inside Explain's own body. This is the actual regression
	// Explain exists to prevent: ranking by check order (or struct field
	// order) would be a plausible-looking guess, not the real breakdown
	// Score used.
	reasons := Explain(Factors{BlastRadius: 1, AgeHours: 10, OccurrenceRate: 0, Confidence: confPtr(0.95)})
	if len(reasons) != 2 {
		t.Fatalf("Explain = %v, want exactly 2 reasons", reasons)
	}
	if !strings.Contains(reasons[0], "confident") {
		t.Fatalf("reasons[0] = %q, want the confidence sentence ranked first (it contributed more: 19 vs 5)", reasons[0])
	}
	if !strings.Contains(reasons[1], "open for") {
		t.Fatalf("reasons[1] = %q, want the age sentence ranked second", reasons[1])
	}
}

func TestExplain_StatesAgeInDaysOnceItCrossesADay(t *testing.T) {
	reasons := Explain(Factors{BlastRadius: 1, AgeHours: 49, OccurrenceRate: 0, Confidence: nil})
	if len(reasons) != 1 || !strings.Contains(reasons[0], "day") {
		t.Fatalf("reasons = %v, want a day-scale phrase for a 49-hour-old incident", reasons)
	}
}

// TestScore_HighWorkloadPriorityOutranksLowPriority is this task's first
// required proof: two otherwise-identical incidents, differing only in the
// resolved spec.priority of the Pod that opened them, must rank the
// higher-priority one above the lower-priority one.
func TestScore_HighWorkloadPriorityOutranksLowPriority(t *testing.T) {
	base := Factors{BlastRadius: 1, AgeHours: 5, OccurrenceRate: 0, Confidence: nil}
	highPriority := base
	highPriority.WorkloadCriticality = priPtr(10000)
	lowPriority := base
	lowPriority.WorkloadCriticality = priPtr(1)

	if got, want := Score(highPriority), Score(lowPriority); got <= want {
		t.Fatalf("Score(high priority)=%v, Score(low priority)=%v — want high > low", got, want)
	}
}

// TestScore_AbsentWorkloadCriticalityContributesNothing is this task's
// second required proof: the ONE representation the wire uses for "unknown"
// — nil — must contribute nothing, whether the cause is a non-Pod incident,
// an older agent that never sent tunnel.Finding.PodPriority, or a real Pod
// whose own spec.priority the API server never resolved. All three are
// indistinguishable as nil by the time Factors reaches this package, so one
// case stands in for all three: nil must score identically to the pre-this-
// feature 3-factor formula, never a fabricated low-criticality zero folded
// in as if it meant something.
func TestScore_AbsentWorkloadCriticalityContributesNothing(t *testing.T) {
	f := Factors{BlastRadius: 3, AgeHours: 10, OccurrenceRate: 2, Confidence: confPtr(0.8), WorkloadCriticality: nil}
	preExistingFormula := WeightBlastRadius*3 + WeightAgeHours*10 + WeightOccurrenceRate*2 + WeightConfidence*0.8
	if got := Score(f); got != preExistingFormula {
		t.Fatalf("Score with nil WorkloadCriticality = %v, want %v (the unchanged 3-factor formula — nil must add nothing)", got, preExistingFormula)
	}

	// And nil must equal an explicit 0 too, the same "absence == a
	// contribution of zero, by construction" property TestScore_
	// NoAnalysisYetContributesNothing already established for Confidence.
	withZero := Score(Factors{BlastRadius: 3, AgeHours: 10, OccurrenceRate: 2, Confidence: confPtr(0.8), WorkloadCriticality: priPtr(0)})
	if got := Score(f); got != withZero {
		t.Fatalf("nil WorkloadCriticality scored %v, explicit priority-0 scored %v — want equal", got, withZero)
	}
}

func TestExplain_OmitsWorkloadCriticalityWhenNilOrZero(t *testing.T) {
	nilCase := Explain(Factors{BlastRadius: 1, AgeHours: 0, OccurrenceRate: 0, Confidence: nil, WorkloadCriticality: nil})
	if nilCase != nil {
		t.Fatalf("Explain(nil WorkloadCriticality, all else silent) = %v, want nil", nilCase)
	}
	zeroCase := Explain(Factors{BlastRadius: 1, AgeHours: 0, OccurrenceRate: 0, Confidence: nil, WorkloadCriticality: priPtr(0)})
	if zeroCase != nil {
		t.Fatalf("Explain(priority=0, all else silent) = %v, want nil — a default-priority Pod is not itself a reason", zeroCase)
	}
}

// TestExplain_RanksWorkloadCriticalityByActualContribution extends the
// existing field-order regression test to the new factor: a very high
// resolved priority (a system-critical Pod) must outrank a merely-open-for-
// a-while incident in Explain's own ordering, even though AgeHours is
// checked first inside Explain's body.
func TestExplain_RanksWorkloadCriticalityByActualContribution(t *testing.T) {
	// WeightWorkloadCriticality (2.0) * log1p(10000) ≈ 2 * 9.21 ≈ 18.4,
	// comfortably ahead of WeightAgeHours (0.5) * 10 = 5.
	reasons := Explain(Factors{BlastRadius: 1, AgeHours: 10, OccurrenceRate: 0, Confidence: nil, WorkloadCriticality: priPtr(10000)})
	if len(reasons) != 2 {
		t.Fatalf("Explain = %v, want exactly 2 reasons", reasons)
	}
	if !strings.Contains(reasons[0], "priority") {
		t.Fatalf("reasons[0] = %q, want the workload-criticality sentence ranked first (it contributed more: ~18.4 vs 5)", reasons[0])
	}
	if !strings.Contains(reasons[1], "open for") {
		t.Fatalf("reasons[1] = %q, want the age sentence ranked second", reasons[1])
	}
}

func TestSQLExprWithCriticality_UsesTheSameWeightsAsScore(t *testing.T) {
	expr := SQLExprWithCriticality("br", "age", "rate", "conf", "prio")
	for _, want := range []string{"br", "age", "rate", "conf", "prio", "BIGINT"} {
		if !strings.Contains(expr, want) {
			t.Errorf("SQLExprWithCriticality output missing %q; got: %s", want, expr)
		}
	}
	for _, weight := range []float64{WeightBlastRadius, WeightAgeHours, WeightOccurrenceRate, WeightConfidence, WeightWorkloadCriticality} {
		marker := formatWeight(weight)
		if !strings.Contains(expr, marker) {
			t.Errorf("SQLExprWithCriticality output missing weight literal %q (from %v); got: %s", marker, weight, expr)
		}
	}
}

// TestSQLExpr_IsSQLExprWithCriticalityPassingNull locks in that the
// 4-argument SQLExpr today's incidents.go still calls is not a second,
// independently-maintained formula — it is SQLExprWithCriticality itself,
// called with the literal SQL NULL for the fifth argument. If these two
// ever compute the numbers differently, this is the test that catches it.
func TestSQLExpr_IsSQLExprWithCriticalityPassingNull(t *testing.T) {
	got := SQLExpr("br", "age", "rate", "conf")
	want := SQLExprWithCriticality("br", "age", "rate", "conf", "NULL")
	if got != want {
		t.Fatalf("SQLExpr(...) = %q,\nSQLExprWithCriticality(..., \"NULL\") = %q — want identical", got, want)
	}
}

// TestScore_WorkloadCriticalityIsBoundedNotLinear is the regression test
// for the live-cluster finding that killed the first (raw-linear) version
// of this factor: a real kind cluster's ONLY PriorityClasses were
// Kubernetes' own two built-ins (system-node-critical/
// system-cluster-critical, both ~2e9) — no operator had ever defined a
// custom one — so raw-linear scoring made every kube-system Pod's incident
// outscore every real application incident by six orders of magnitude,
// which is not a criticality signal, just Kubernetes' own plumbing
// permanently burying the operator's actual queue.
//
// The bounded (log1p) form must NOT reproduce that: an otherwise-ordinary
// incident on a merely-system-critical Pod must NOT outrank a
// widely-shared, long-open, frequently-recurring, confidently-diagnosed
// incident on a Pod with no special priority at all — the exact ordering
// the raw-linear version got backwards.
func TestScore_WorkloadCriticalityIsBoundedNotLinear(t *testing.T) {
	merelySystemCritical := Score(Factors{
		BlastRadius: 1, AgeHours: 1, OccurrenceRate: 0, Confidence: nil,
		WorkloadCriticality: priPtr(2000001000), // system-node-critical
	})
	realApplicationIncident := Score(Factors{
		BlastRadius: 12, AgeHours: 120, OccurrenceRate: 4, Confidence: confPtr(0.95),
		WorkloadCriticality: priPtr(1000), // an ordinary custom PriorityClass
	})
	if merelySystemCritical >= realApplicationIncident {
		t.Fatalf("merely-system-critical incident scored %v, real application incident scored %v — want the application incident to outrank a trivial incident that only happens to be on a system Pod (this is exactly what raw-linear scoring got backwards)", merelySystemCritical, realApplicationIncident)
	}

	// And the system-critical Pod's OWN contribution must still land in
	// roughly the same range as the other three factors' typical maximums
	// (tens, not tens of millions) — this is the quantitative form of the
	// package's own "none of the four factors can dominate by construction"
	// rule, which the raw-linear version violated outright.
	contribution := workloadCriticalityContribution(priPtr(2000001000))
	if contribution > 100 {
		t.Fatalf("system-critical contribution = %v, want it bounded to roughly the same order of magnitude as WeightConfidence's own max (20) — not tens of millions", contribution)
	}
}

// TestWorkloadCriticalityContribution_ClampsNegativePriority guards against
// math.Log1p's own documented behavior (NaN below -1, -Inf at exactly -1):
// a negative priority (a real, if rare, "less than default" PriorityClass)
// must contribute a clean 0, never poison Score with NaN/-Inf.
func TestWorkloadCriticalityContribution_ClampsNegativePriority(t *testing.T) {
	for _, p := range []int32{-1, -100, -2000000000} {
		got := workloadCriticalityContribution(priPtr(p))
		if got != 0 {
			t.Errorf("workloadCriticalityContribution(%d) = %v, want 0 (clamped, not NaN/-Inf)", p, got)
		}
	}
	f := Factors{BlastRadius: 1, AgeHours: 1, OccurrenceRate: 0, WorkloadCriticality: priPtr(-100)}
	if score := Score(f); math.IsNaN(score) || math.IsInf(score, 0) {
		t.Fatalf("Score with negative priority = %v, want a finite number", score)
	}
}

// TestExplain_Priority0IsDistinctFromNilButBothOmitted is the explicit
// "do not collapse them" check: priority 0 (a REAL resolved value — the
// globally-default PriorityClass) and nil (no signal at all) are different
// facts about an incident, even though both happen to contribute 0 to the
// score and so are both, correctly, omitted from Explain — the same
// "silent about an axis nothing stood out on" reading every other factor
// here already gets for its own zero-contribution case.
func TestExplain_Priority0IsDistinctFromNilButBothOmitted(t *testing.T) {
	nilCrit := priPtr(0) // a distinct pointer from a real nil
	if nilCrit == nil {
		t.Fatal("priPtr(0) must not be nil — priority 0 is a real value")
	}
	withZero := Explain(Factors{WorkloadCriticality: priPtr(0)})
	withNil := Explain(Factors{WorkloadCriticality: nil})
	if withZero != nil || withNil != nil {
		t.Fatalf("Explain(priority=0) = %v, Explain(priority=nil) = %v, want both nil (no reason, not a wrong reason)", withZero, withNil)
	}
	// But at the Factors/Score level they remain genuinely different
	// pointers/values, never coerced into one representation.
	f0 := Factors{WorkloadCriticality: priPtr(0)}
	fNil := Factors{WorkloadCriticality: nil}
	if f0.WorkloadCriticality == nil {
		t.Fatal("a Factors literal built with priPtr(0) must keep a non-nil pointer")
	}
	if fNil.WorkloadCriticality != nil {
		t.Fatal("a Factors literal built with no WorkloadCriticality must stay nil")
	}
}
