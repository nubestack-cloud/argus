package gateway

import (
	"context"
	"strings"
	"testing"

	"argus/internal/data"
	"argus/internal/llm"
	"argus/internal/tunnel"
)

// fakeCompleter is a minimal llm.Completer stand-in. This package's tests
// use it (rather than a real *llm.Provider/*llm.Router) precisely to prove
// applyConditionPolarityGate/llmAsker depend only on the Completer
// interface — BACKLOG.md P13: before it, Gateway.LLM was concretely typed
// *llm.Provider, so this gate's Mechanism 2 could only ever be exercised
// against the api backend's HTTP path, which is not what an operator
// running a cli-kind provider (the common case) actually has configured.
type fakeCompleter struct {
	text, model string
	err         error
}

func (f fakeCompleter) Complete(_ context.Context, _, _ string) (llm.Result, error) {
	if f.err != nil {
		return llm.Result{}, f.err
	}
	return llm.Result{Text: f.text, Model: f.model}, nil
}

// cleanupPolarityGateRow deletes any row this test may have written for
// (kind, conditionType) — condition_polarity has no TTL/invalidation an
// individual test can rely on to reset itself (see that package's own doc
// comment), so tests do it themselves, matching
// internal/conditionpolarity/polarity_db_test.go's own convention.
func cleanupPolarityGateRow(t *testing.T, kind, conditionType string) {
	t.Helper()
	pool := testPool(t)
	if _, err := pool.Exec(context.Background(), `DELETE FROM condition_polarity WHERE kind = $1 AND condition_type = $2`, kind, conditionType); err != nil {
		t.Fatalf("cleanup condition_polarity row for %s/%s: %v", kind, conditionType, err)
	}
}

func TestApplyConditionPolarityGate_NonMatchingReason_UntouchedAndProceeds(t *testing.T) {
	pool := testPool(t)
	g := &Gateway{db: &data.DB{Pool: pool}}
	f := &tunnel.Finding{Reason: "OOMKilled", Severity: "high", Message: "container was OOMKilled"}

	if proceed := g.applyConditionPolarityGate(context.Background(), f); !proceed {
		t.Fatal("expected a Finding whose Reason does not carry the GenericConditionAnomaly prefix to proceed untouched")
	}
	if f.Severity != "high" || f.Message != "container was OOMKilled" {
		t.Fatalf("expected f to be completely untouched, got Severity=%q Message=%q", f.Severity, f.Message)
	}
}

// TestApplyConditionPolarityGate_UnresolvableNoModelNoSample is BACKLOG.md
// E12's own headline acceptance shape at the gate level: the exact failure
// mode that used to silently drop a Finding (no model configured, and too
// few live samples to infer locally) must now proceed, floored to low
// severity and marked, never dropped.
func TestApplyConditionPolarityGate_UnresolvableNoModelNoSample(t *testing.T) {
	kind, condType := "E12GateTestWidget", "Ready"
	cleanupPolarityGateRow(t, kind, condType)
	t.Cleanup(func() { cleanupPolarityGateRow(t, kind, condType) })

	pool := testPool(t)
	g := &Gateway{db: &data.DB{Pool: pool}} // g.LLM is nil: no model configured
	f := &tunnel.Finding{
		Reason:                 "GenericConditionAnomaly:" + condType,
		GVK:                    "example.com/v1/" + kind,
		Severity:               "high",
		Message:                "Ready reads False, differing from this object's peers",
		ConditionType:          condType,
		ConditionObservedValue: "False",
		ConditionSampleCount:   1, // far below minStatisticalSampleCount
	}

	if proceed := g.applyConditionPolarityGate(context.Background(), f); !proceed {
		t.Fatal("BACKLOG.md E12: an unresolvable polarity must proceed (fail open), never drop")
	}
	if f.Severity != "low" {
		t.Fatalf("expected severity floored to low, got %q", f.Severity)
	}
	if !strings.HasPrefix(f.Message, polarityUnverifiedMarker) {
		t.Fatalf("expected Message to start with the polarity-unverified marker, got %q", f.Message)
	}
	if !strings.Contains(f.Message, "Ready reads False, differing from this object's peers") {
		t.Fatalf("expected the original Message to still be present (appended after the marker), got %q", f.Message)
	}
}

// TestApplyConditionPolarityGate_ModelConfigured_UsesCompleter is BACKLOG.md
// P13's regression lock: with too few live samples to infer statistically
// (forcing Mechanism 2), a Gateway.LLM that is ANY llm.Completer — not
// specifically a *llm.Provider — is asked, its answer is trusted, and it is
// persisted with source="model" and the real model name. Before P13 this
// path was only ever exercisable through *llm.Provider.Complete; this test
// proves the gate now works against the interface, matching what
// cmd/hub/main.go actually wires (the *llm.Router, which dispatches to
// whichever provider kind — api or cli — Settings has active).
func TestApplyConditionPolarityGate_ModelConfigured_UsesCompleter(t *testing.T) {
	kind, condType := "P13GateTestNode", "DiskPressure"
	cleanupPolarityGateRow(t, kind, condType)
	t.Cleanup(func() { cleanupPolarityGateRow(t, kind, condType) })

	pool := testPool(t)
	g := &Gateway{db: &data.DB{Pool: pool}, LLM: fakeCompleter{text: "False", model: "fake-model-x"}}
	f := &tunnel.Finding{
		Reason:                 "GenericConditionAnomaly:" + condType,
		GVK:                    "v1/" + kind,
		Severity:               "high",
		Message:                "orig",
		ConditionType:          condType,
		ConditionObservedValue: "True", // the model says False is the bad value, so True is healthy
		ConditionSampleCount:   1,      // far below minStatisticalSampleCount, forcing Mechanism 2
	}

	if proceed := g.applyConditionPolarityGate(context.Background(), f); proceed {
		t.Fatal("expected the model's answer (False is the bad value, so True is healthy) to resolve this Finding as healthy and drop it")
	}

	var badValue, source, modelName string
	err := pool.QueryRow(context.Background(),
		`SELECT bad_value, source, model_name FROM condition_polarity WHERE kind = $1 AND condition_type = $2`,
		kind, condType,
	).Scan(&badValue, &source, &modelName)
	if err != nil {
		t.Fatalf("expected a persisted verdict: %v", err)
	}
	if badValue != "False" || source != "model" || modelName != "fake-model-x" {
		t.Fatalf("got bad_value=%q source=%q model_name=%q, want False/model/fake-model-x", badValue, source, modelName)
	}
}

func TestApplyConditionPolarityGate_MalformedFinding_UnverifiedNotDropped(t *testing.T) {
	pool := testPool(t)
	g := &Gateway{db: &data.DB{Pool: pool}}
	f := &tunnel.Finding{
		Reason:   "GenericConditionAnomaly:Ready",
		GVK:      "v1/Pod",
		Severity: "medium",
		Message:  "orig",
		// ConditionType/ConditionObservedValue deliberately left empty.
	}

	if proceed := g.applyConditionPolarityGate(context.Background(), f); !proceed {
		t.Fatal("expected a malformed Finding to proceed unverified, not drop")
	}
	if f.Severity != "low" || !strings.HasPrefix(f.Message, polarityUnverifiedMarker) {
		t.Fatalf("expected floored severity + marker for a malformed Finding, got Severity=%q Message=%q", f.Severity, f.Message)
	}
}

func TestApplyConditionPolarityGate_UnparseableGVK_UnverifiedNotDropped(t *testing.T) {
	pool := testPool(t)
	g := &Gateway{db: &data.DB{Pool: pool}}
	f := &tunnel.Finding{
		Reason:                 "GenericConditionAnomaly:Ready",
		GVK:                    "", // nothing to parse a Kind out of
		Severity:               "medium",
		Message:                "orig",
		ConditionType:          "Ready",
		ConditionObservedValue: "False",
	}

	if proceed := g.applyConditionPolarityGate(context.Background(), f); !proceed {
		t.Fatal("expected an unparseable GVK to proceed unverified, not drop")
	}
	if f.Severity != "low" || !strings.HasPrefix(f.Message, polarityUnverifiedMarker) {
		t.Fatalf("expected floored severity + marker, got Severity=%q Message=%q", f.Severity, f.Message)
	}
}

// TestApplyConditionPolarityGate_ConfidentlyHealthy_Drops is the one
// remaining legitimate drop path: a verdict that IS actually resolved (here,
// a confident statistical read) saying the observed value is the healthy
// one must still drop, exactly as before E12 — E12 narrows what counts as
// "resolved," it does not remove the drop-on-genuinely-healthy case.
func TestApplyConditionPolarityGate_ConfidentlyHealthy_Drops(t *testing.T) {
	kind, condType := "E12GateTestDeployment", "Available"
	cleanupPolarityGateRow(t, kind, condType)
	t.Cleanup(func() { cleanupPolarityGateRow(t, kind, condType) })

	pool := testPool(t)
	g := &Gateway{db: &data.DB{Pool: pool}}
	f := &tunnel.Finding{
		Reason:                    "GenericConditionAnomaly:" + condType,
		GVK:                       "apps/v1/" + kind,
		Severity:                  "high",
		Message:                   "orig",
		ConditionType:             condType,
		ConditionObservedValue:    "True", // the reading this Finding is ABOUT
		ConditionSampleCount:      10,
		ConditionMajorityValue:    "True", // True is confidently the majority => True is healthy
		ConditionMajorityFraction: 0.9,
	}

	if proceed := g.applyConditionPolarityGate(context.Background(), f); proceed {
		t.Fatal("expected a confidently-resolved-healthy verdict to still drop")
	}
}

// TestApplyConditionPolarityGate_UncorroboratedModelVerdict_RealFaultSurfaces
// is BACKLOG.md E11's own named-but-open gap (see the E11 entry's "A wrong
// cached polarity verdict still has no correction path an operator would
// find"): a WRONG model-sourced verdict, cached for a Kind that never has
// minStatisticalSampleCount live instances at once, must NOT be trusted as
// authoritative for a silent drop forever just because E12's TTL/confident-
// override paths can never fire for it.
//
// Reproduction: seed a wrong verdict exactly as a weak model asked once
// would (mirrors conditionpolarity's own
// TestResolve_ConfidentContradictingSample_OverridesCachedModelVerdict
// seeding step, and this package's TestApplyConditionPolarityGate_
// ModelConfigured_UsesCompleter for how to drive the gate itself) — the
// model says "True" is the bad value for Ready, when in reality "False" is
// the real problem indicator. Then a SECOND Finding arrives reporting the
// REAL fault (Ready=False) with, again, too few live peers to ever build a
// confident sample (SampleCount=1, exactly the structural case this Kind is
// stuck in). Before the fix in this commit, the gate resolves the second
// call to the stale, wrong, cached verdict and silently drops a genuine
// anomaly — this test pins that this no longer happens.
func TestApplyConditionPolarityGate_UncorroboratedModelVerdict_RealFaultSurfaces(t *testing.T) {
	kind, condType := "E11GateTestRareCRD", "Ready"
	cleanupPolarityGateRow(t, kind, condType)
	t.Cleanup(func() { cleanupPolarityGateRow(t, kind, condType) })

	pool := testPool(t)

	// Step 1: seed the wrong model verdict. A weak model is asked once,
	// with too few live peers (SampleCount=1) to check its answer against
	// anything — exactly how a real wrong guess gets cached in the first
	// place.
	seedG := &Gateway{db: &data.DB{Pool: pool}, LLM: fakeCompleter{text: "True", model: "weak-model"}}
	seedF := &tunnel.Finding{
		Reason:                 "GenericConditionAnomaly:" + condType,
		GVK:                    "example.com/v1/" + kind,
		Severity:               "high",
		Message:                "Ready reads False",
		ConditionType:          condType,
		ConditionObservedValue: "False",
		ConditionSampleCount:   1,
	}
	if proceed := seedG.applyConditionPolarityGate(context.Background(), seedF); proceed {
		t.Fatal("seed: expected the (wrong) model verdict to resolve this first Finding as healthy and drop it, exactly as the model's one-time guess says")
	}

	var badValue, source string
	if err := pool.QueryRow(context.Background(),
		`SELECT bad_value, source FROM condition_polarity WHERE kind = $1 AND condition_type = $2`,
		kind, condType,
	).Scan(&badValue, &source); err != nil {
		t.Fatalf("expected a persisted seed verdict: %v", err)
	}
	if badValue != "True" || source != "model" {
		t.Fatalf("seed: got bad_value=%q source=%q, want True/model", badValue, source)
	}

	// Step 2: the REAL fault recurs. Still only 1 live instance — this
	// Kind/condition pair structurally never clears minStatisticalSampleCount,
	// so E12's confident-override path can never fire for it, and the
	// cached guess is nowhere near its 7-day TTL yet. No model configured
	// on THIS call either, to prove the fix does not depend on a model
	// being reachable right now.
	g := &Gateway{db: &data.DB{Pool: pool}} // g.LLM is nil
	f := &tunnel.Finding{
		Reason:                 "GenericConditionAnomaly:" + condType,
		GVK:                    "example.com/v1/" + kind,
		Severity:               "high",
		Message:                "Ready reads False, differing from this object's peers",
		ConditionType:          condType,
		ConditionObservedValue: "False", // the REAL fault
		ConditionSampleCount:   1,       // still far below minStatisticalSampleCount
	}

	if proceed := g.applyConditionPolarityGate(context.Background(), f); !proceed {
		t.Fatal("a real fault must not be silently dropped on the strength of a never-corroborated model guess — it should surface unverified instead")
	}
	if f.Severity != "low" {
		t.Fatalf("expected severity floored to low, got %q", f.Severity)
	}
	if !strings.HasPrefix(f.Message, polarityUnverifiedMarker) {
		t.Fatalf("expected the polarity-unverified marker, got %q", f.Message)
	}
	if !strings.Contains(f.Message, "never been corroborated") {
		t.Fatalf("expected a marker distinguishing this from the generic unresolvable case, got %q", f.Message)
	}
}

// TestApplyConditionPolarityGate_CorroboratedModelVerdict_StillDrops is the
// regression guard for the fix above: a Kind that DOES have plenty of live
// instances, and whose cached model verdict HAS at some point been checked
// against a confident live sample (and agreed), must keep dropping exactly
// as before — even on a LATER call where, that one time, the sample happens
// to be thin. This is what distinguishes the historical "ever corroborated"
// design from a bare per-call confidence check, which would spuriously
// flag this common case as unverified too.
func TestApplyConditionPolarityGate_CorroboratedModelVerdict_StillDrops(t *testing.T) {
	kind, condType := "E11GateTestPopulousCRD", "Ready"
	cleanupPolarityGateRow(t, kind, condType)
	t.Cleanup(func() { cleanupPolarityGateRow(t, kind, condType) })

	pool := testPool(t)

	// Seed a model verdict, again from too few live peers.
	seedG := &Gateway{db: &data.DB{Pool: pool}, LLM: fakeCompleter{text: "False", model: "some-model"}}
	seedF := &tunnel.Finding{
		Reason:                 "GenericConditionAnomaly:" + condType,
		GVK:                    "example.com/v1/" + kind,
		Severity:               "high",
		Message:                "orig",
		ConditionType:          condType,
		ConditionObservedValue: "True",
		ConditionSampleCount:   1,
	}
	if proceed := seedG.applyConditionPolarityGate(context.Background(), seedF); proceed {
		t.Fatal("seed: expected the model verdict (False is bad) to resolve True as healthy and drop it")
	}

	// This Kind is actually populous: a later Finding arrives with a
	// confident live sample that AGREES with the cached guess. The seed
	// verdict says bad_value=False (True is the healthy reading), so an
	// AGREEING sample must report True as the confident majority —
	// otherValue("True") == "False" == the cached bad_value — which is
	// what makes Resolve take the "agree, mark corroborated" branch rather
	// than the "disagree, override to statistical" branch (a genuinely
	// different code path this test must exercise, not just happen to
	// pass via).
	confirmG := &Gateway{db: &data.DB{Pool: pool}}
	confirmF := &tunnel.Finding{
		Reason:                    "GenericConditionAnomaly:" + condType,
		GVK:                       "example.com/v1/" + kind,
		Severity:                  "high",
		Message:                   "orig",
		ConditionType:             condType,
		ConditionObservedValue:    "True", // the majority/healthy reading
		ConditionSampleCount:      10,
		ConditionMajorityValue:    "True",
		ConditionMajorityFraction: 0.9,
	}
	if proceed := confirmG.applyConditionPolarityGate(context.Background(), confirmF); proceed {
		t.Fatal("expected the confirming, confidently-healthy sample to drop, same as any other confidently-resolved-healthy case")
	}

	// Confirm the row is still source="model" (the agree branch must NOT
	// rewrite it wholesale the way the disagree/override branch does) and
	// is now ever_confirmed=true — the actual mechanism this test exists
	// to pin, not just the fire/drop outcome, which the override branch
	// could otherwise satisfy by coincidence.
	var source string
	var everConfirmed bool
	if err := pool.QueryRow(context.Background(),
		`SELECT source, ever_confirmed FROM condition_polarity WHERE kind = $1 AND condition_type = $2`,
		kind, condType,
	).Scan(&source, &everConfirmed); err != nil {
		t.Fatalf("expected a persisted row: %v", err)
	}
	if source != "model" || !everConfirmed {
		t.Fatalf("expected the agreeing sample to leave source=model but flip ever_confirmed=true, got source=%q ever_confirmed=%v", source, everConfirmed)
	}

	// Now a LATER Finding for the same pair arrives with, once again, too
	// few live peers to be confident. Because this pair HAS been
	// corroborated before, this must NOT be newly marked unverified — the
	// cached verdict is trusted exactly as E12 already intended for a
	// well-evidenced model verdict.
	laterG := &Gateway{db: &data.DB{Pool: pool}}
	laterF := &tunnel.Finding{
		Reason:                 "GenericConditionAnomaly:" + condType,
		GVK:                    "example.com/v1/" + kind,
		Severity:               "high",
		Message:                "orig",
		ConditionType:          condType,
		ConditionObservedValue: "False", // the anomalous reading per the (corroborated) verdict's bad_value
		ConditionSampleCount:   1,       // thin this time, but that must not matter now
	}
	if proceed := laterG.applyConditionPolarityGate(context.Background(), laterF); !proceed {
		t.Fatal("expected a real anomaly per an already-corroborated verdict to proceed")
	}
	if laterF.Severity != "high" || laterF.Message != "orig" {
		t.Fatalf("expected an already-corroborated verdict's anomaly to proceed UNMARKED, got Severity=%q Message=%q", laterF.Severity, laterF.Message)
	}
}

// TestApplyConditionPolarityGate_ConfidentlyAnomalous_ProceedsUnmarked
// confirms E12 did not turn this gate into a pass-through: a genuinely
// confirmed anomaly still proceeds normally, with NO marker and its
// original severity untouched.
func TestApplyConditionPolarityGate_ConfidentlyAnomalous_ProceedsUnmarked(t *testing.T) {
	kind, condType := "E12GateTestNode", "MemoryPressure"
	cleanupPolarityGateRow(t, kind, condType)
	t.Cleanup(func() { cleanupPolarityGateRow(t, kind, condType) })

	pool := testPool(t)
	g := &Gateway{db: &data.DB{Pool: pool}}
	f := &tunnel.Finding{
		Reason:                    "GenericConditionAnomaly:" + condType,
		GVK:                       "v1/" + kind,
		Severity:                  "high",
		Message:                   "orig",
		ConditionType:             condType,
		ConditionObservedValue:    "True", // the minority/anomalous reading
		ConditionSampleCount:      10,
		ConditionMajorityValue:    "False", // False is the confident majority => True is the anomaly
		ConditionMajorityFraction: 0.9,
	}

	if proceed := g.applyConditionPolarityGate(context.Background(), f); !proceed {
		t.Fatal("expected a confidently-resolved anomaly to proceed")
	}
	if f.Severity != "high" || f.Message != "orig" {
		t.Fatalf("expected a real anomaly to proceed UNMODIFIED, got Severity=%q Message=%q", f.Severity, f.Message)
	}
}
