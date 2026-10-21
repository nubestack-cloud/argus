// score.go grades one run of the corpus.
//
// # Two scores, never one
//
// The headline is deliberately TWO numbers that are never averaged:
//
//	root-cause match rate  — of the cases whose correct answer is a named
//	                         root cause, how many did the investigation name
//	                         correctly?
//	honest-negative rate   — of the cases whose correct answer is "could not
//	                         determine", how many did it decline on, instead
//	                         of inventing a cause?
//
// Averaging them would hide the failure that matters most. A product that
// confidently invents a root cause is worse than one that declines: the
// invented cause is acted on, and the decline is escalated to a human. A
// single blended number lets a collapse in the second score be paid for with
// a rise in the first — a model that guesses on everything would score
// BETTER on a blend than one that knows when to stop. That is the exact
// trade this product's evidence discipline exists to refuse
// (lld/07-analysis-contracts.md §4's "numerology" warning; ARCHITECTURE's
// observed fact / inference / ruled-out split), so the report refuses it too.
//
// Tool-call efficiency is reported as a third, separate, non-gating number,
// for the same "tracked independently rather than blended" reason.
//
// # What is NOT scored
//
// Causal-chain quality and cost are the other two dimensions the retired
// analysis contract named. Cost has no per-model pricing table to grade
// against here, and causal-chain quality is structurally guaranteed by
// internal/llm/toolloop.go's own shape — a CausalStep can only ever be built
// from a real tool call and its real result — so grading it again would
// re-derive a property the types already enforce rather than add a check.
package main

import (
	"fmt"
	"sort"
	"strings"

	"argus/scripts/eval/casefmt"
)

// AnalyzeResponse is the slice of the analyze response this harness scores —
// deliberately not the full internal/api struct, since this package should
// not depend on hub internals any more than a real HTTP client would.
type AnalyzeResponse struct {
	Status     string
	RootCause  string // "" if nil
	Confidence *float64
	Iterations int
	// Route/ActionType (PG9, 2026-10-13 parity review) are the real
	// orchestrator's own resolution route and the proposed plan's
	// actionType — "" when the subject does not compute one (the offline
	// deterministic stand-in never does) or when the investigation
	// genuinely proposed no plan.
	Route      string
	ActionType string
}

// CaseResult is one case's scored outcome, or the record of why it was not
// evaluated against this subject.
type CaseResult struct {
	Case              GoldenCase
	Response          AnalyzeResponse
	CorrectnessPass   bool
	CorrectnessDetail string
	EfficiencyPass    bool
	EfficiencyDetail  string

	// Skipped marks a case this subject cannot be graded on at all — see
	// casefmt.Case.RequiresWorldKnowledge. A skipped case is counted in
	// neither score's numerator nor its denominator, and is listed on its own
	// in the report with SkipReason, because a number that silently drops
	// cases is a number that overstates its own coverage.
	Skipped    bool
	SkipReason string
}

// SkipCase records a case the subject cannot be graded on.
func SkipCase(gc GoldenCase, reason string) CaseResult {
	return CaseResult{Case: gc, Skipped: true, SkipReason: reason}
}

// SkipReasonFor applies the one rule that decides whether a case is gradable
// against the subject running, and returns why when it is not. Shared by both
// run modes so the corpus cannot mean two different things depending on how
// it was run.
func SkipReasonFor(gc GoldenCase, subjectHasWorldKnowledge bool) string {
	if subjectHasWorldKnowledge || !gc.RequiresWorldKnowledge() {
		return ""
	}
	return "needs world knowledge (its answer is not anywhere in its own evidence) and the subject is the deterministic stand-in, which has none — configure a model backend to evaluate this case"
}

// Scores is one run's two headline numbers plus the non-gating third,
// each with the denominator it was computed over. The denominators travel
// with the numbers on purpose: "100% honest-negative rate" means something
// very different over 7 cases than over 1, and a report that prints only the
// percentage invites exactly that misreading.
type Scores struct {
	RootCauseMatched  int
	RootCauseTotal    int
	HonestNegativeHit int
	HonestNegativeN   int
	EfficiencyInBand  int
	EfficiencyTotal   int
	// NotEvaluated counts cases this subject could not be graded on. It is
	// reported next to the scores rather than folded into them.
	NotEvaluated int
}

func (s Scores) RootCauseRate() float64      { return rate(s.RootCauseMatched, s.RootCauseTotal) }
func (s Scores) HonestNegativeRate() float64 { return rate(s.HonestNegativeHit, s.HonestNegativeN) }
func (s Scores) EfficiencyRate() float64     { return rate(s.EfficiencyInBand, s.EfficiencyTotal) }

func rate(n, total int) float64 {
	if total == 0 {
		return 0
	}
	return float64(n) / float64(total)
}

// ScoreCase applies both dimensions to one case's analyze response.
func ScoreCase(gc GoldenCase, resp AnalyzeResponse) CaseResult {
	cr := CaseResult{Case: gc, Response: resp}
	cr.CorrectnessPass, cr.CorrectnessDetail = scoreCorrectness(gc.Expected, resp)
	cr.EfficiencyPass, cr.EfficiencyDetail = scoreEfficiency(gc.Expected, resp)
	return cr
}

// Aggregate splits results into the two corpora by the case's own expected
// type and counts each separately.
func Aggregate(results []CaseResult) Scores {
	var s Scores
	for _, r := range results {
		if r.Skipped {
			s.NotEvaluated++
			continue
		}
		switch r.Case.Expected.Type {
		case casefmt.ExpectInsufficient:
			s.HonestNegativeN++
			if r.CorrectnessPass {
				s.HonestNegativeHit++
			}
		default:
			s.RootCauseTotal++
			if r.CorrectnessPass {
				s.RootCauseMatched++
			}
		}
		s.EfficiencyTotal++
		if r.EfficiencyPass {
			s.EfficiencyInBand++
		}
	}
	return s
}

// scoreCorrectness grades one case against its known-correct answer: a direct
// textual check rather than an LLM-judge pass. A keyword check is less
// flexible than a judge, but it is exactly as trustworthy as the person (or,
// for the generated corpus, the derivation) that produced the expected set —
// which is the right property for a regression gate, where a judge model's
// own drift would show up indistinguishably from the product's.
// fixReachedCheck is PG9's addition (2026-10-13 parity review) to the end of
// every ExpectDefinite success path: naming the right root cause is
// necessary but, for a case that sets RequiredRoute/RequiredActionType, not
// sufficient — the investigation also has to have reached the fix those
// fields name, through the ordinary route/permitted-action-type mechanism
// (internal/resolution), not a hardcoded per-pattern shortcut this harness
// would have no way to tell apart from the real thing anyway.
//
// Gated on resp.Route != "" — route is always resolvable in principle, but
// this harness only actually computes and reports it for a run capable of
// producing one (a real model, offline or stack; never the deterministic
// stand-in, which is instructions-only and has no plan concept at all —
// see RunCaseOffline/decideNext). An empty Route is therefore this run's own
// honest signal "I did not attempt orchestration," not a route that happens
// to be blank, and is read as "not applicable" rather than a failure — the
// same reasoning that keeps a case requiring RequiredRoute/RequiredActionType
// gradeable for root cause under EVERY subject (TestKnowledgeRequiringCases...
// pins exactly that), while the fix dimension only ever engages for a
// subject that could have gotten it right.
func fixReachedCheck(exp ExpectedOutcome, resp AnalyzeResponse, baseDetail string) (bool, string) {
	if exp.RequiredRoute == "" && exp.RequiredActionType == "" {
		return true, baseDetail
	}
	if resp.Route == "" {
		return true, baseDetail + " (route/action-type not checked: this subject does not compute one)"
	}
	if exp.RequiredRoute != "" && resp.Route != exp.RequiredRoute {
		return false, fmt.Sprintf("root cause was right (%s), but reached route %q, want %q", baseDetail, resp.Route, exp.RequiredRoute)
	}
	if exp.RequiredActionType != "" && resp.ActionType != exp.RequiredActionType {
		return false, fmt.Sprintf("root cause was right (%s), but reached action type %q, want %q", baseDetail, resp.ActionType, exp.RequiredActionType)
	}
	return true, baseDetail
}

func scoreCorrectness(exp ExpectedOutcome, resp AnalyzeResponse) (pass bool, detail string) {
	switch exp.Type {
	case casefmt.ExpectInsufficient:
		maxConf := exp.MaxConfidenceForInsufficient
		if maxConf == 0 {
			maxConf = 0.4
		}
		if resp.Status == "partial" {
			return true, "correctly returned a partial (bound-hit) result rather than guessing"
		}
		if resp.Status == "complete" {
			if resp.Confidence != nil && *resp.Confidence <= maxConf {
				return true, fmt.Sprintf("correctly concluded with low confidence (%.2f <= %.2f) rather than fabricating certainty", *resp.Confidence, maxConf)
			}
			gotConf := "nil"
			if resp.Confidence != nil {
				gotConf = fmt.Sprintf("%.2f", *resp.Confidence)
			}
			return false, fmt.Sprintf("FABRICATED CONFIDENCE: evidence was insufficient but the analysis concluded \"complete\" at confidence %s (> %.2f)", gotConf, maxConf)
		}
		return false, fmt.Sprintf("unexpected status %q", resp.Status)

	case casefmt.ExpectDefinite:
		if resp.Status != "complete" {
			return false, fmt.Sprintf("expected a definite conclusion but got status %q", resp.Status)
		}
		minConf := exp.MinConfidence
		if minConf == 0 {
			minConf = 0.5
		}
		if resp.Confidence == nil || *resp.Confidence < minConf {
			gotConf := "nil"
			if resp.Confidence != nil {
				gotConf = fmt.Sprintf("%.2f", *resp.Confidence)
			}
			return false, fmt.Sprintf("confidence %s is below the %.2f minimum for a definite case", gotConf, minConf)
		}
		lower := strings.ToLower(resp.RootCause)

		var missing []string
		for _, kw := range exp.RequiredKeywords {
			if !strings.Contains(lower, strings.ToLower(kw)) {
				missing = append(missing, kw)
			}
		}
		if len(missing) > 0 {
			return false, fmt.Sprintf("missing required keyword(s) %v in statement %q", missing, truncate(resp.RootCause, 200))
		}

		// anyOf: the statement has to commit to one of the candidate root
		// causes. This is what grades a catalogue-generated case — the
		// catalogue's own root_causes list is already an "any one of these is
		// right" set, so this check is the mapping of that list onto a score,
		// not a looser version of the required-keyword check.
		if len(exp.AnyOfKeywords) > 0 {
			hit := ""
			for _, kw := range exp.AnyOfKeywords {
				if strings.Contains(lower, strings.ToLower(kw)) {
					hit = kw
					break
				}
			}
			if hit == "" {
				return false, fmt.Sprintf("named NO candidate root cause: none of %v appears in statement %q", exp.AnyOfKeywords, truncate(resp.RootCause, 200))
			}
			var present []string
			for _, kw := range exp.ForbiddenKeywords {
				if strings.Contains(lower, strings.ToLower(kw)) {
					present = append(present, kw)
				}
			}
			if len(present) > 0 {
				return false, fmt.Sprintf("FELL FOR THE RED HERRING: forbidden keyword(s) %v present in statement %q", present, truncate(resp.RootCause, 200))
			}
			return fixReachedCheck(exp, resp, fmt.Sprintf("named candidate root cause %q (of %v) at confidence %.2f", hit, exp.AnyOfKeywords, *resp.Confidence))
		}

		var present []string
		for _, kw := range exp.ForbiddenKeywords {
			if strings.Contains(lower, strings.ToLower(kw)) {
				present = append(present, kw)
			}
		}
		if len(present) > 0 {
			return false, fmt.Sprintf("FELL FOR THE RED HERRING: forbidden keyword(s) %v present in statement %q", present, truncate(resp.RootCause, 200))
		}
		return fixReachedCheck(exp, resp, fmt.Sprintf("statement contains all required keywords %v and none forbidden, at confidence %.2f", exp.RequiredKeywords, *resp.Confidence))

	default:
		return false, fmt.Sprintf("golden case has an unrecognized expected.type %q", exp.Type)
	}
}

// scoreEfficiency is iterations used vs. the case's own reasonable band.
// Never folded into the case's pass/fail: it is reported for every case
// regardless of whether correctness passed, and nothing gates on it.
func scoreEfficiency(exp ExpectedOutcome, resp AnalyzeResponse) (pass bool, detail string) {
	switch {
	case resp.Iterations < exp.MinIterations:
		return false, fmt.Sprintf("%d iterations is BELOW the reasonable minimum of %d — likely concluded without gathering enough evidence", resp.Iterations, exp.MinIterations)
	case resp.Iterations > exp.MaxIterations:
		return false, fmt.Sprintf("%d iterations is ABOVE the reasonable maximum of %d — likely churned without converging", resp.Iterations, exp.MaxIterations)
	default:
		return true, fmt.Sprintf("%d iterations is within the reasonable [%d, %d] band", resp.Iterations, exp.MinIterations, exp.MaxIterations)
	}
}

// Report renders the per-case table, the two headline scores, and — whenever
// the run included a catalogue-generated case — the limitation banner.
//
// subject is what actually produced these answers (a real model and its name,
// or the deterministic stand-in). It is printed at the top and the bottom of
// every report, because a score with no subject attached is a number someone
// will quote later without knowing what it measured.
func Report(results []CaseResult, subject string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "\n=== eval-harness report ===\nsubject: %s\n\n", subject)

	var skipped []CaseResult
	for _, r := range results {
		if r.Skipped {
			skipped = append(skipped, r)
			continue
		}
		status := "FAIL"
		if r.CorrectnessPass {
			status = "PASS"
		}
		effStatus := "FAIL"
		if r.EfficiencyPass {
			effStatus = "PASS"
		}
		kind := "root-cause match"
		if r.Case.Expected.Type == casefmt.ExpectInsufficient {
			kind = "honest negative"
		}
		fmt.Fprintf(&b, "[%s] %-34s (%s, %s)\n", status, r.Case.ID, kind, r.Case.Provenance)
		fmt.Fprintf(&b, "       %s\n", r.CorrectnessDetail)
		fmt.Fprintf(&b, "       efficiency [%s]: %s\n", effStatus, r.EfficiencyDetail)
		fmt.Fprintf(&b, "       (status=%s iterations=%d rootCause=%q)\n\n", r.Response.Status, r.Response.Iterations, truncate(r.Response.RootCause, 160))
	}

	if len(skipped) > 0 {
		fmt.Fprintf(&b, "--- %d case(s) NOT EVALUATED against this subject ---\n", len(skipped))
		for _, r := range skipped {
			fmt.Fprintf(&b, "[ -- ] %-34s %s\n", r.Case.ID, r.SkipReason)
		}
		b.WriteString("These are counted in neither score, in neither numerator nor denominator.\n\n")
	}

	s := Aggregate(results)
	fmt.Fprintf(&b, "--- scores (subject: %s) ---\n", subject)
	fmt.Fprintf(&b, "root-cause match rate:  %d/%d (%.0f%%)\n", s.RootCauseMatched, s.RootCauseTotal, 100*s.RootCauseRate())
	fmt.Fprintf(&b, "honest-negative rate:   %d/%d (%.0f%%)\n", s.HonestNegativeHit, s.HonestNegativeN, 100*s.HonestNegativeRate())
	fmt.Fprintf(&b, "tool-call efficiency:   %d/%d (%.0f%%)   [reported, never gating]\n", s.EfficiencyInBand, s.EfficiencyTotal, 100*s.EfficiencyRate())
	if s.NotEvaluated > 0 {
		fmt.Fprintf(&b, "not evaluated:          %d case(s)\n", s.NotEvaluated)
	}
	b.WriteString("\nThe first two are reported separately and are never averaged: a run that\n")
	b.WriteString("invents a root cause rather than declining is worse than one that declines,\n")
	b.WriteString("and a blended number would let the second be paid for with the first.\n")

	if banner := LimitationBanner(results); banner != "" {
		b.WriteString(banner)
	}
	return b.String()
}

// LimitationBanner reprints, once per run, the limitation carried by the
// generated cases in it, along with how much of each score came from them.
// The sentence lives in the case files; this is the second place a reader
// meets it, and it is deliberately printed at the BOTTOM of the report, right
// under the numbers, rather than at the top where a scrollback would lose it.
func LimitationBanner(results []CaseResult) string {
	byLimitation := map[string]int{}
	synthesizedDefinite, synthesizedInsufficient := 0, 0
	for _, r := range results {
		if !r.Case.Synthesized() {
			continue
		}
		byLimitation[r.Case.Limitation]++
		if r.Case.Expected.Type == casefmt.ExpectInsufficient {
			synthesizedInsufficient++
		} else {
			synthesizedDefinite++
		}
	}
	if len(byLimitation) == 0 {
		return ""
	}
	limitations := make([]string, 0, len(byLimitation))
	for l := range byLimitation {
		limitations = append(limitations, l)
	}
	sort.Strings(limitations)

	var b strings.Builder
	b.WriteString("\n--- what these numbers do NOT cover ---\n")
	fmt.Fprintf(&b, "%d of the root-cause cases and %d of the honest-negative cases above are\n", synthesizedDefinite, synthesizedInsufficient)
	fmt.Fprintf(&b, "%s cases. For those:\n\n", casefmt.ProvenanceCatalog)
	for _, l := range limitations {
		b.WriteString("  " + wrap(l, 76, "  ") + "\n")
	}
	return b.String()
}

// AllCorrect reports whether every case passed correctness — kept for the
// harness's own exit code. The floors in main.go are what the nightly
// actually gates on.
func AllCorrect(results []CaseResult) bool {
	for _, r := range results {
		if !r.CorrectnessPass {
			return false
		}
	}
	return true
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

func wrap(s string, width int, indent string) string {
	var b strings.Builder
	col := 0
	for i, w := range strings.Fields(s) {
		if col > 0 && col+1+len(w) > width {
			b.WriteString("\n" + indent)
			col = 0
		} else if i > 0 {
			b.WriteString(" ")
			col++
		}
		b.WriteString(w)
		col += len(w)
	}
	return b.String()
}

// SubsetBanner is printed whenever a run scored fewer cases than the corpus
// holds, and it names every case that ran.
//
// The scores above it are then unambiguously scores over THAT list, not over
// "the eval corpus" — which matters most in exactly the situation the subset
// exists for. A real-model run is paid for per case, so the cheap run is the
// one most likely to be quoted, and a percentage with a hidden denominator is
// the easiest number in this repo to misread.
func SubsetBanner(ran []GoldenCase, corpusSize int, requested string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "\n--- THIS RUN SCORED A SUBSET: %d of the %d case(s) in the corpus ---\n", len(ran), corpusSize)
	b.WriteString("The two rates above are over this list only, and are NOT the corpus's scores:\n")
	for _, gc := range ran {
		kind := "root-cause"
		if gc.Expected.Type == casefmt.ExpectInsufficient {
			kind = "honest-negative"
		}
		fmt.Fprintf(&b, "  %-36s (%s, %s)\n", gc.ID, kind, gc.Provenance)
	}
	fmt.Fprintf(&b, "Selected with -case-ids %s\n", requested)
	return b.String()
}

// CaseStabilityReport names the cases whose verdict was not the same in
// every pass.
//
// This is the part of a variance measurement a gating decision actually
// turns on. A mean that moves three points between passes is ambiguous — it
// could be one borderline case flipping, or the whole corpus drifting — and
// those two shapes have opposite implications: the first can be gated on
// after excluding or rewriting one case, the second cannot be gated on at
// all. The aggregate spread cannot tell them apart; this can.
//
// It also reports the flipped cases' differing statements, because "the
// model reached the same conclusion and the keyword check disagreed" and
// "the model reached a different conclusion" are different problems, and
// only one of them is the model's.
func CaseStabilityReport(runs [][]CaseResult) string {
	if len(runs) < 2 {
		return ""
	}
	type outcome struct {
		passes     int
		total      int
		kind       string
		statements []string
	}
	order := []string{}
	byID := map[string]*outcome{}
	for _, results := range runs {
		for _, r := range results {
			if r.Skipped {
				continue
			}
			o, ok := byID[r.Case.ID]
			if !ok {
				kind := "root-cause"
				if r.Case.Expected.Type == casefmt.ExpectInsufficient {
					kind = "honest-negative"
				}
				o = &outcome{kind: kind}
				byID[r.Case.ID] = o
				order = append(order, r.Case.ID)
			}
			o.total++
			if r.CorrectnessPass {
				o.passes++
			}
			o.statements = append(o.statements, fmt.Sprintf("[%s] %s", passWord(r.CorrectnessPass), r.CorrectnessDetail))
		}
	}

	var unstable []string
	for _, id := range order {
		o := byID[id]
		if o.passes != 0 && o.passes != o.total {
			unstable = append(unstable, id)
		}
	}

	var b strings.Builder
	b.WriteString("\n--- per-case stability across the runs above ---\n")
	if len(unstable) == 0 {
		fmt.Fprintf(&b, "Every one of the %d scored case(s) returned the SAME verdict in all %d runs.\n", len(order), len(runs))
		b.WriteString("The spread reported above therefore comes from nothing but the cases that were\nnot evaluated, if any — no case changed its mind.\n")
		return b.String()
	}
	fmt.Fprintf(&b, "%d of %d scored case(s) did NOT return the same verdict in all %d runs:\n\n", len(unstable), len(order), len(runs))
	for _, id := range unstable {
		o := byID[id]
		fmt.Fprintf(&b, "  %s (%s) — passed %d of %d runs\n", id, o.kind, o.passes, o.total)
		for i, st := range o.statements {
			fmt.Fprintf(&b, "    run %d: %s\n", i+1, truncate(st, 150))
		}
		b.WriteString("\n")
	}
	b.WriteString("A case in this list is where a gate on the mean would be flaky. Read each one\nbefore raising a floor: a case that flips because the MODEL changed its mind is\na real instability, and one that flips because a keyword check straddles two\nequally correct phrasings is a fault in the case.\n")
	return b.String()
}

func passWord(ok bool) string {
	if ok {
		return "PASS"
	}
	return "FAIL"
}
