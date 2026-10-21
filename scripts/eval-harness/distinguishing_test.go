// distinguishing_test.go is the fast, network-free regression test for this
// harness's own central claim: that the scoring tells a good investigation
// apart from a bad one, rather than only proving the wire plumbing works.
//
// It runs the real offline path (offline.go's RunCaseOffline — the real
// system prompt, the real tool schemas, the checked-in corpus) against both
// deterministic stand-ins, and asserts the two are distinguishable. The
// expensive, more faithful version of this proof is `-mode stack` against a
// running hub; this exists so the proof has an always-on guard that needs no
// docker compose to catch a regression in the reasoner, the scorer, the
// corpus or the prompt.
package main

import (
	"testing"
)

func simulateInvestigation(personality string, gc GoldenCase) (AnalyzeResponse, error) {
	return RunCaseOffline(gc, OfflineOptions{Personality: personality})
}

func loadWholeCorpus(t *testing.T) []GoldenCase {
	t.Helper()
	cases, err := LoadGoldenCaseDirs([]string{"../eval/golden", "../eval/generated"})
	if err != nil {
		t.Fatalf("%v", err)
	}
	return cases
}

// TestStandInBaselineIsExactlyTheNightlyFloors is what makes floors of 1.0
// legitimate rather than optimistic. The deterministic stand-in follows the
// real system prompt and nothing else, so its score is a fact, not a target:
// every case it is evaluated on it passes, and every case it cannot be
// evaluated on is reported as not evaluated rather than counted as a zero.
//
// If this test fails, either the prompt stopped saying something a correct
// investigation needs, a fixture became unachievable by following the prompt,
// or the skip rule changed — all three are exactly what the nightly is for,
// and all three should be looked at rather than have the floor lowered.
func TestStandInBaselineIsExactlyTheNightlyFloors(t *testing.T) {
	cases := loadWholeCorpus(t)
	results, err := RunCorpusOffline(cases, OfflineOptions{Personality: "good"})
	if err != nil {
		t.Fatalf("%v", err)
	}
	for _, r := range results {
		if !r.Skipped && !r.CorrectnessPass {
			t.Errorf("case %s (%s): expected the good stand-in to pass, got: %s", r.Case.ID, r.Case.Provenance, r.CorrectnessDetail)
		}
	}
	s := Aggregate(results)
	if s.RootCauseRate() < DefaultMinRootCauseRate {
		t.Errorf("root-cause match rate %.3f is below the nightly floor %.3f (%d/%d)", s.RootCauseRate(), DefaultMinRootCauseRate, s.RootCauseMatched, s.RootCauseTotal)
	}
	if s.HonestNegativeRate() < DefaultMinHonestNegativeRate {
		t.Errorf("honest-negative rate %.3f is below the nightly floor %.3f (%d/%d)", s.HonestNegativeRate(), DefaultMinHonestNegativeRate, s.HonestNegativeHit, s.HonestNegativeN)
	}
}

// TestKnowledgeRequiringCasesAreSkippedForTheStandInAndRunForAModel pins the
// skip rule in both directions. A corpus that quietly dropped cases would
// overstate its coverage; one that scored the stand-in on cases it cannot
// possibly answer would pin the gate to the floor, where no regression could
// move it. Neither is acceptable, so both halves are asserted.
func TestKnowledgeRequiringCasesAreSkippedForTheStandInAndRunForAModel(t *testing.T) {
	cases := loadWholeCorpus(t)

	needsKnowledge := 0
	for _, gc := range cases {
		if gc.RequiresWorldKnowledge() {
			needsKnowledge++
			if SkipReasonFor(gc, false) == "" {
				t.Errorf("case %s needs world knowledge but would be scored against the knowledge-free stand-in", gc.ID)
			}
			if SkipReasonFor(gc, true) != "" {
				t.Errorf("case %s would be skipped even with a real model configured — a model is exactly the subject it is for", gc.ID)
			}
			continue
		}
		if SkipReasonFor(gc, false) != "" {
			t.Errorf("case %s does not need world knowledge and must be graded against every subject", gc.ID)
		}
	}
	if needsKnowledge == 0 {
		t.Fatal("no case in the corpus requires world knowledge — the catalogue-generated cases are supposed to, so either the corpus or the derivation broke")
	}

	// Every hand-written definite case puts its own answer in its evidence,
	// which is what lets a stand-in that only follows instructions be graded
	// at all.
	for _, gc := range cases {
		if gc.Provenance == "hand-written" && gc.RequiresWorldKnowledge() {
			t.Errorf("hand-written case %s hides its answer from its own evidence — that makes it a knowledge test, and the hand-written corpus is the part that has to grade every subject", gc.ID)
		}
	}
}

// TestBadStandInFailsAtLeastTheCasesItShould is the "distinguishes good from
// bad" assertion. The bad stand-in concludes off the first get_events result
// alone, never corroborates, and never admits uncertainty — so it must fail
// the red-herring case (it takes the decoy at face value) and the
// insufficient-evidence case (it fabricates confidence). Those two failures
// are the whole point of the harness existing.
func TestBadStandInFailsAtLeastTheCasesItShould(t *testing.T) {
	mustFail := map[string]bool{
		"checkout-api-dependency-red-herring": true,
		"unexplained-pending-pod":             true,
	}

	anyFailed := false
	for _, gc := range loadWholeCorpus(t) {
		resp, err := simulateInvestigation("bad", gc)
		if err != nil {
			t.Fatalf("%v", err)
		}
		cr := ScoreCase(gc, resp)
		if !cr.CorrectnessPass {
			anyFailed = true
		}
		if mustFail[gc.ID] && cr.CorrectnessPass {
			t.Errorf("case %s: expected the bad stand-in to FAIL (that is what this case is for), but it passed: %s", gc.ID, cr.CorrectnessDetail)
		}
	}
	if !anyFailed {
		t.Fatalf("expected at least one case to catch the bad stand-in — the scoring is not distinguishing anything if it never does")
	}
}

// TestBothScoresAreReportedSeparately pins the property the two-score design
// exists for: a subject that guesses on everything must not be able to buy a
// collapsed honest-negative rate with a decent root-cause rate. The bad
// stand-in is exactly that subject, and the assertion is that its two scores
// are visibly different numbers rather than one blended one.
func TestBothScoresAreReportedSeparately(t *testing.T) {
	cases := loadWholeCorpus(t)

	var badResults []CaseResult
	for _, gc := range cases {
		resp, err := simulateInvestigation("bad", gc)
		if err != nil {
			t.Fatalf("%v", err)
		}
		badResults = append(badResults, ScoreCase(gc, resp))
	}
	bad := Aggregate(badResults)

	if bad.HonestNegativeN == 0 {
		t.Fatal("the corpus has no honest-negative cases — the second score has nothing to measure")
	}
	if bad.RootCauseTotal == 0 {
		t.Fatal("the corpus has no root-cause cases — the first score has nothing to measure")
	}
	if bad.HonestNegativeRate() != 0 {
		t.Errorf("the bad stand-in never declines, so its honest-negative rate must be 0, got %.2f (%d/%d)",
			bad.HonestNegativeRate(), bad.HonestNegativeHit, bad.HonestNegativeN)
	}
	if bad.RootCauseRate() <= bad.HonestNegativeRate() {
		t.Errorf("expected the bad stand-in to score higher on root-cause match (%.2f) than on honest negatives (%.2f) — "+
			"that gap is exactly what a single blended score would hide",
			bad.RootCauseRate(), bad.HonestNegativeRate())
	}
}

// TestBadStandInIsLessEfficientOnTheObviousCase is the complementary
// dimension, demonstrated rather than asserted in a comment: even on a case
// both stand-ins get factually right, the bad one shows up worse on tool-call
// efficiency.
func TestBadStandInIsLessEfficientOnTheObviousCase(t *testing.T) {
	for _, gc := range loadWholeCorpus(t) {
		if gc.ID != "crashloop-oom-clear" {
			continue
		}
		goodResp, err := simulateInvestigation("good", gc)
		if err != nil {
			t.Fatalf("%v", err)
		}
		badResp, err := simulateInvestigation("bad", gc)
		if err != nil {
			t.Fatalf("%v", err)
		}
		goodCR := ScoreCase(gc, goodResp)
		badCR := ScoreCase(gc, badResp)
		if !goodCR.CorrectnessPass || !badCR.CorrectnessPass {
			t.Fatalf("expected both stand-ins to get the obvious case right (good=%v bad=%v)", goodCR.CorrectnessPass, badCR.CorrectnessPass)
		}
		if !goodCR.EfficiencyPass {
			t.Errorf("expected the good stand-in to be within the reasonable iteration band: %s", goodCR.EfficiencyDetail)
		}
		if badCR.EfficiencyPass {
			t.Errorf("expected the bad stand-in to be flagged as under-investigating, but efficiency passed: %s", badCR.EfficiencyDetail)
		}
		return
	}
	t.Fatalf("golden case \"crashloop-oom-clear\" not found")
}
