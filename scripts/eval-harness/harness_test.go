// harness_test.go covers the pure, DB-free/network-free logic in this
// package — golden-case loading and tool-response matching, the good/bad
// reasoner's category detection and turn-taking, and the two scoring
// dimensions — the same "DB-touching behavior is verified live instead"
// split this repo's other packages already follow (see
// internal/api/incidents_test.go's own precedent, cited in WORKLOG.md §49).
// The actual real-stack run (real hub, real tunnel, real bounded
// investigation loop) is this harness's own main() — verified live per
// STATUS.md's new eval-harness section, not here.
package main

import (
	"encoding/json"
	"strings"
	"testing"

	"argus/internal/llm"
	"argus/internal/resolution"
)

// realSystemPrompt is the production prompt, built for the in-place route
// with no optional tools — the same call internal/api/analyze.go makes. The
// reasoner tests below drive the stand-in with this rather than a placeholder
// string, because the stand-in's behaviour is now derived FROM the prompt:
// handing it "..." would test a subject that had been told nothing.
func realSystemPrompt() string {
	return llm.SystemPrompt(resolution.RouteInPlace, false, false, false)
}

// TestPromptContractIsDetectedInTheRealSystemPrompt is the guard on the
// phrases reasoner.go keys its behaviour off. Those phrases live in
// internal/llm.SystemPrompt; if one is reworded there, the stand-in silently
// loses a behaviour and the nightly goes red for what is really a rename.
// Failing here instead turns that into a compile-and-test-time problem with
// an obvious fix, rather than a mysterious overnight score drop.
//
// It is deliberately NOT a test that the prompt must contain particular
// words — the prompt's authors are free to reword it. It is a test that this
// file has been updated when they do.
func TestPromptContractIsDetectedInTheRealSystemPrompt(t *testing.T) {
	c := promptContractOf(realSystemPrompt())
	if !c.RequiresVerification {
		t.Errorf("the real system prompt no longer contains %q — update phraseVerification in reasoner.go to whatever instruction replaced it", phraseVerification)
	}
	if !c.RequiresOwnershipCheck {
		t.Errorf("the real system prompt no longer contains %q — update phraseOwnershipCheck in reasoner.go", phraseOwnershipCheck)
	}
	if !c.RequiresHonestUncertainty {
		t.Errorf("the real system prompt no longer contains %q — update phraseHonestUncertainty in reasoner.go", phraseHonestUncertainty)
	}
}

// TestDegradedPromptCollapsesTheHonestNegativeRate is the harness's proof
// that it detects the regression it exists for, run as a unit test rather
// than described in a document: strip the honest-uncertainty instruction out
// of the real prompt, and the honest-negative rate goes to zero while the
// root-cause rate does not move. That asymmetry is the whole argument for
// reporting the two separately — a blended score would show a partial dip
// and could be dismissed as noise.
func TestDegradedPromptCollapsesTheHonestNegativeRate(t *testing.T) {
	full := realSystemPrompt()
	i := strings.Index(full, phraseHonestUncertainty)
	if i < 0 {
		t.Fatalf("cannot degrade a prompt that does not contain %q", phraseHonestUncertainty)
	}
	degraded := strings.ReplaceAll(full, phraseHonestUncertainty, "")

	if c := promptContractOf(degraded); c.RequiresHonestUncertainty {
		t.Fatal("degrading the prompt did not remove the honest-uncertainty instruction")
	}
	if c := promptContractOf(degraded); !c.RequiresVerification || !c.RequiresOwnershipCheck {
		t.Fatal("degrading one instruction removed others — the proof would not isolate the cause")
	}

	cases, err := LoadGoldenCaseDirs([]string{"../eval/golden", "../eval/generated"})
	if err != nil {
		t.Fatalf("%v", err)
	}

	score := func(prompt string) Scores {
		var results []CaseResult
		for _, gc := range cases {
			if reason := SkipReasonFor(gc, false); reason != "" {
				results = append(results, SkipCase(gc, reason))
				continue
			}
			resp, err := runWithSystemPrompt(gc, prompt)
			if err != nil {
				t.Fatalf("case %s: %v", gc.ID, err)
			}
			results = append(results, ScoreCase(gc, resp))
		}
		return Aggregate(results)
	}

	before := score(full)
	after := score(degraded)

	if before.HonestNegativeRate() != 1.0 {
		t.Fatalf("baseline honest-negative rate should be 1.000, got %.3f", before.HonestNegativeRate())
	}
	if after.HonestNegativeRate() != 0.0 {
		t.Errorf("a prompt with no honest-uncertainty instruction should score 0.000 on honest negatives, got %.3f (%d/%d)",
			after.HonestNegativeRate(), after.HonestNegativeHit, after.HonestNegativeN)
	}
	if after.RootCauseRate() != before.RootCauseRate() {
		t.Errorf("degrading only the honest-uncertainty instruction moved the root-cause rate too (%.3f -> %.3f) — the two scores are supposed to isolate different failures",
			before.RootCauseRate(), after.RootCauseRate())
	}
}

func runWithSystemPrompt(gc GoldenCase, prompt string) (AnalyzeResponse, error) {
	return RunCaseOffline(gc, OfflineOptions{Personality: "good", SystemPromptOverride: prompt})
}

func TestLoadGoldenCasesFromRealDir(t *testing.T) {
	cases, err := LoadGoldenCases("../eval/golden")
	if err != nil {
		t.Fatalf("LoadGoldenCases: %v", err)
	}
	if len(cases) < 3 {
		t.Fatalf("expected at least 3 golden cases in the checked-in set, got %d", len(cases))
	}
	seen := map[string]bool{}
	for _, gc := range cases {
		if seen[gc.ID] {
			t.Errorf("duplicate golden case id %q", gc.ID)
		}
		seen[gc.ID] = true
		if gc.Expected.Type != "definite" && gc.Expected.Type != "insufficient" {
			t.Errorf("case %s: bad expected.type %q", gc.ID, gc.Expected.Type)
		}
	}
}

func TestToolResponseMatchPicksMostSpecificEntry(t *testing.T) {
	gc := GoldenCase{
		ToolResponses: map[string][]ToolResponseEntry{
			"get_logs": {
				{Match: map[string]string{"previous": "true"}, Data: json.RawMessage(`{"lines":["specific"]}`)},
				{Match: map[string]string{}, Data: json.RawMessage(`{"lines":["default"]}`)},
			},
		},
	}

	data, errMsg := gc.ToolResponse("get_logs", json.RawMessage(`{"namespace":"prod","pod":"x","previous":true}`))
	if errMsg != "" {
		t.Fatalf("unexpected error %q", errMsg)
	}
	if string(data) != `{"lines":["specific"]}` {
		t.Errorf("expected the previous=true-matched entry, got %s", data)
	}

	data, _ = gc.ToolResponse("get_logs", json.RawMessage(`{"namespace":"prod","pod":"x"}`))
	if string(data) != `{"lines":["default"]}` {
		t.Errorf("expected the fallback (empty-match) entry when nothing else matches, got %s", data)
	}
}

func TestToolResponseSynthesizesDefaultForUnmentionedTool(t *testing.T) {
	gc := GoldenCase{ToolResponses: map[string][]ToolResponseEntry{}}
	data, errMsg := gc.ToolResponse("get_owner_chain", json.RawMessage(`{}`))
	if errMsg != "" {
		t.Fatalf("unexpected error %q", errMsg)
	}
	if string(data) != "[]" {
		t.Errorf("expected a synthesized empty array for get_owner_chain, got %s", data)
	}
}

// --- reasoner ---

func strp(s string) *string { return &s }

func userMsg(prompt string) wireMessage { return wireMessage{Role: "user", Content: strp(prompt)} }

func toolResultMsg(content string) wireMessage {
	return wireMessage{Role: "tool", Content: strp(content)}
}

const clearOOMPrompt = `Cluster: eval
Incident fingerprint: eval-1, severity: critical, seen 6 time(s)

Findings:
- [critical] v1/Pod/prod/payments-api-7f8b9c9c8d-x2kq1 reason="OOMKilled" message="Container payments-api was OOMKilled" (detector=pod-status, x6)
`

func TestGoodReasonerReachesCorrectCategoryOnClearOOM(t *testing.T) {
	messages := []wireMessage{
		{Role: "system", Content: strp(realSystemPrompt())},
		userMsg(clearOOMPrompt),
	}
	// round 0: expect a get_events tool call
	turn := decideNext("good", messages)
	if len(turn.ToolCalls) != 1 || turn.ToolCalls[0].Function.Name != "get_events" {
		t.Fatalf("round 0: expected a get_events tool call, got %+v", turn.ToolCalls)
	}
	messages = append(messages, turn, toolResultMsg(`[{"reason":"OOMKilled","message":"OOMKilled after exceeding its memory limit"}]`))

	// round 1: category is "oom" -> expect get_logs
	turn = decideNext("good", messages)
	if len(turn.ToolCalls) != 1 || turn.ToolCalls[0].Function.Name != "get_logs" {
		t.Fatalf("round 1: expected a get_logs tool call for an OOM signal, got %+v", turn.ToolCalls)
	}
	messages = append(messages, turn, toolResultMsg(`{"lines":["Killed process 1 (payments-api) - OOM killed"]}`))

	// round 2: expect get_gitops_ownership
	turn = decideNext("good", messages)
	if len(turn.ToolCalls) != 1 || turn.ToolCalls[0].Function.Name != "get_gitops_ownership" {
		t.Fatalf("round 2: expected a get_gitops_ownership tool call, got %+v", turn.ToolCalls)
	}
	messages = append(messages, turn, toolResultMsg(`{"managed_by":"none"}`))

	// round 3: expect a conclusion mentioning oomkilled/memory
	turn = decideNext("good", messages)
	if len(turn.ToolCalls) != 0 {
		t.Fatalf("round 3: expected a conclusion (no tool calls), got %+v", turn.ToolCalls)
	}
	var final struct {
		RootCause  struct{ Statement string } `json:"rootCause"`
		Confidence float64
	}
	if err := json.Unmarshal([]byte(*turn.Content), &final); err != nil {
		t.Fatalf("conclusion did not parse as the pinned final-JSON shape: %v (content: %s)", err, *turn.Content)
	}
	if final.Confidence < 0.5 {
		t.Errorf("expected a confident conclusion on a clear case, got confidence %v", final.Confidence)
	}
}

func TestBadReasonerConcludesAfterOneToolCallRegardlessOfSignal(t *testing.T) {
	messages := []wireMessage{
		{Role: "system", Content: strp(realSystemPrompt())},
		userMsg(clearOOMPrompt),
	}
	turn := decideNext("bad", messages)
	if len(turn.ToolCalls) != 1 {
		t.Fatalf("round 0: expected exactly one tool call, got %d", len(turn.ToolCalls))
	}
	messages = append(messages, turn, toolResultMsg(`[{"reason":"OOMKilled"}]`))

	turn = decideNext("bad", messages)
	if len(turn.ToolCalls) != 0 {
		t.Fatalf("round 1: bad personality should conclude immediately, got tool calls %+v", turn.ToolCalls)
	}
}

// --- scoring ---

func TestScoreCorrectnessDefiniteCase(t *testing.T) {
	exp := ExpectedOutcome{Type: "definite", RequiredKeywords: []string{"oomkilled", "memory"}, ForbiddenKeywords: []string{"unhealthy"}}

	pass, _ := scoreCorrectness(exp, AnalyzeResponse{Status: "complete", RootCause: "OOMKilled: exceeded memory limit", Confidence: f64p(0.8)})
	if !pass {
		t.Errorf("expected pass when all required keywords present and none forbidden")
	}

	pass, _ = scoreCorrectness(exp, AnalyzeResponse{Status: "complete", RootCause: "Unhealthy readiness probe", Confidence: f64p(0.9)})
	if pass {
		t.Errorf("expected fail when a forbidden keyword is present")
	}

	pass, _ = scoreCorrectness(exp, AnalyzeResponse{Status: "complete", RootCause: "some other thing", Confidence: f64p(0.9)})
	if pass {
		t.Errorf("expected fail when required keywords are missing")
	}
}

func TestScoreCorrectnessInsufficientCaseCatchesFabricatedConfidence(t *testing.T) {
	exp := ExpectedOutcome{Type: "insufficient", MaxConfidenceForInsufficient: 0.4}

	pass, _ := scoreCorrectness(exp, AnalyzeResponse{Status: "complete", RootCause: "could not determine", Confidence: f64p(0.2)})
	if !pass {
		t.Errorf("expected pass for an honest low-confidence conclusion")
	}

	pass, detail := scoreCorrectness(exp, AnalyzeResponse{Status: "complete", RootCause: "a confident guess", Confidence: f64p(0.85)})
	if pass {
		t.Errorf("expected fail for a confident conclusion when evidence was insufficient, got detail %q", detail)
	}

	pass, _ = scoreCorrectness(exp, AnalyzeResponse{Status: "partial"})
	if !pass {
		t.Errorf("expected a partial result to pass an insufficient-evidence case")
	}
}

func TestScoreEfficiencyBand(t *testing.T) {
	exp := ExpectedOutcome{MinIterations: 3, MaxIterations: 5}
	if pass, _ := scoreEfficiency(exp, AnalyzeResponse{Iterations: 4}); !pass {
		t.Errorf("4 should be within [3,5]")
	}
	if pass, _ := scoreEfficiency(exp, AnalyzeResponse{Iterations: 2}); pass {
		t.Errorf("2 should be below the minimum")
	}
	if pass, _ := scoreEfficiency(exp, AnalyzeResponse{Iterations: 8}); pass {
		t.Errorf("8 should be above the maximum")
	}
}

func f64p(v float64) *float64 { return &v }

// TestStackModeRefusesToMislabelACLIHubsAnswers is the guard on the one
// output this program must never produce: a real, billed model's answers
// printed under the deterministic stand-in's name.
//
// A hub whose active provider is kind=cli accepts the harness's PUT of a
// base URL, keeps its kind, and goes on using its runner — so without this
// check a `-mode stack` run against such a hub reports the wrong subject
// over real numbers. The error message names the way out, because the
// situation is a legitimate one to be in (see -stack-use-configured-provider).
func TestStackModeRefusesToMislabelACLIHubsAnswers(t *testing.T) {
	cli := llmSettingsView{ProviderKind: "cli", CLIRunnerURL: "http://argus-runner:8090", CLIAgent: "claude", CLIBackendAvailable: true}
	err := verifyProviderWriteLanded(cli, "http://host.docker.internal:41234")
	if err == nil {
		t.Fatal("a cli-kind hub silently discarded the harness's base URL and the harness accepted it — the run would have been scored against a model the report never names")
	}
	if !strings.Contains(err.Error(), "-stack-use-configured-provider") {
		t.Errorf("the refusal does not name the flag that measures such a hub deliberately: %v", err)
	}

	// The api case still has to pass, and still has to catch a base URL the
	// hub did not actually store.
	api := llmSettingsView{ProviderKind: "api", BaseURL: "http://host.docker.internal:41234"}
	if err := verifyProviderWriteLanded(api, "http://host.docker.internal:41234"); err != nil {
		t.Errorf("an api hub that stored exactly what was set was refused: %v", err)
	}
	if err := verifyProviderWriteLanded(api, "http://somewhere-else"); err == nil {
		t.Error("a hub reporting a different base URL than was set was accepted")
	}
}

// TestConfiguredProviderIsReportedAsARealModelMeasurement covers the other
// half: when the harness deliberately measures the hub's own provider, the
// run must be marked as measuring a real model (so the "nothing was
// measured" banner stays off), and a cli provider the hub cannot actually
// serve must be refused BEFORE a corpus of analyze calls is paid for.
func TestConfiguredProviderIsReportedAsARealModelMeasurement(t *testing.T) {
	subj, err := describeConfiguredProvider(llmSettingsView{
		ProviderKind: "cli", CLIRunnerURL: "http://argus-runner:8090", CLIAgent: "claude", CLIBackendAvailable: true,
	})
	if err != nil {
		t.Fatalf("a usable cli provider was refused: %v", err)
	}
	if !subj.MeasuresRealModel {
		t.Error("a run against a real CLI-driven model was not marked as measuring a real model — the report would claim nothing was measured")
	}
	if !strings.Contains(subj.Description, "claude") || !strings.Contains(subj.Description, "argus-runner") {
		t.Errorf("the subject line does not name what answered: %q", subj.Description)
	}
	if !strings.Contains(subj.Caveats, "efficiency") {
		t.Error("the cli subject carries no caveat about the tool-call efficiency number, which counts different things than an api-backend iteration")
	}

	if _, err := describeConfiguredProvider(llmSettingsView{
		ProviderKind: "cli", CLIRunnerURL: "http://argus-runner:8090", CLIAgent: "claude", CLIBackendAvailable: false,
	}); err == nil {
		t.Error("a hub with no MCP listener was accepted; every analyze call would have failed after a full enrollment")
	}
}

// TestSelectCasesRejectsAnUnknownID: a subset run is the expensive run, so
// its denominator is the number most likely to be quoted. A typo'd ID that
// silently shrank the corpus would be invisible in the output.
func TestSelectCasesRejectsAnUnknownID(t *testing.T) {
	cases, err := LoadGoldenCases("../eval/golden")
	if err != nil {
		t.Fatalf("load golden cases: %v", err)
	}
	got, err := SelectCases(cases, "crashloop-oom-clear, unexplained-pending-pod")
	if err != nil {
		t.Fatalf("selecting two real cases failed: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("selected %d case(s), want 2", len(got))
	}
	if _, err := SelectCases(cases, "crashloop-oom-clear,no-such-case"); err == nil {
		t.Error("an unknown case ID was silently dropped instead of failing the run")
	}
}
