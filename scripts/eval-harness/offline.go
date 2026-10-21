// offline.go runs the corpus with no hub, no Postgres, no tunnel and no
// cluster — and it is what the nightly regression gate executes.
//
// # Why there are two run modes at all
//
// main.go's original mode drives the REAL production path end to end: a real
// hub, a real POST /incidents/{id}/analyze, the real internal/llm loop, over
// a real mTLS tunnel to a fake agent answering from a fixture. That is the
// more faithful thing to run and it stays. It also needs a built image, a
// running compose stack and a configured model provider before it can
// produce a single number, which makes it the wrong thing to hang a NIGHTLY
// on: a gate that cannot run is a gate that does not exist.
//
// This mode trades some of that fidelity for the ability to actually run:
//
//	REAL here:   internal/llm.SystemPrompt — the exact production prompt,
//	             built for the same route the incident would resolve to;
//	             internal/llm.InvestigationToolSchemas — the exact tool
//	             surface both backends expose, not a re-declared copy;
//	             the fixture corpus and the scoring.
//	NOT real:    the turn loop itself. internal/llm's own investigate() is
//	             unexported and reaches settings.Resolve for a database, so
//	             this file drives the same OpenAI chat-completions wire shape
//	             directly. It is a faithful re-implementation of the loop's
//	             SHAPE, not the loop.
//
// That boundary is why a prompt edit, a tool-schema change or a model swap
// all move this score — those are the three regressions E19 exists to catch —
// while a bug in toolloop.go's own control flow would not. The stack mode
// catches that second class; this one runs every night.
//
// # The deterministic stand-in
//
// With no model backend configured, the subject is reasoner.go's stand-in,
// which obeys exactly the instructions the system prompt it is handed
// actually contains (see promptContractOf). That makes the score a measure of
// the PROMPT rather than of a model: remove the instruction that tells the
// investigation to say "could not determine", and the honest-negative rate
// goes to zero, deterministically, in CI, with no API key anywhere. It is a
// prompt-contract check, and it is not a substitute for measuring a real
// model — the report says which of the two produced its numbers, every time.
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"argus/internal/llm"
	"argus/internal/resolution"
)

// OfflineOptions configures one offline run.
type OfflineOptions struct {
	// LLMBaseURL/LLMModel/LLMAPIKey point at a real OpenAI-compatible
	// provider. When LLMBaseURL is empty the deterministic stand-in runs
	// instead and Personality selects which one.
	LLMBaseURL  string
	LLMModel    string
	LLMAPIKey   string
	Personality string

	MaxIterations int
	HTTPTimeout   time.Duration

	// SystemPromptOverride replaces internal/llm.SystemPrompt for this run.
	// It exists for one job: proving that a degraded prompt actually moves
	// the score, without editing internal/llm and rebuilding anything. The
	// nightly never sets it; a run that does says so in its subject line.
	SystemPromptOverride string
}

// Subject describes, in one line, what produced a run's answers. Printed at
// the top and bottom of every report: a score with no subject attached is a
// number someone will quote later without knowing what it measured.
func (o OfflineOptions) Subject() string {
	if o.SystemPromptOverride != "" {
		return "OVERRIDDEN SYSTEM PROMPT — this run did not use internal/llm.SystemPrompt, so its scores are not comparable to any other run's. " + o.subjectModel()
	}
	return o.subjectModel()
}

func (o OfflineOptions) subjectModel() string {
	if o.LLMBaseURL != "" {
		return fmt.Sprintf("REAL MODEL %q at %s, driven through internal/llm.SystemPrompt and internal/llm.InvestigationToolSchemas", o.LLMModel, o.LLMBaseURL)
	}
	return fmt.Sprintf(
		"DETERMINISTIC STAND-IN (personality=%s) obeying the real internal/llm.SystemPrompt — this measures whether the PROMPT still carries the instructions a correct investigation needs, NOT how well any model reasons. No diagnostic accuracy of a real model is measured by this run.",
		o.Personality)
}

// MeasuresRealModel reports whether this run's numbers came from a model.
// The nightly prints a different summary in each case, because "the prompt
// still says the right things" and "the product still diagnoses correctly"
// are different claims and only one of them is a claim about accuracy.
func (o OfflineOptions) MeasuresRealModel() bool { return o.LLMBaseURL != "" }

// routeFor picks the resolution route the incident would have resolved to,
// so the system prompt this case sees is the one it would really see.
// internal/resolution.RouteFor takes ownership FACTS, which for a fixture
// live in its own get_gitops_ownership answer — so that answer is read here
// rather than a route being hardcoded. A GitOps-managed object routes to the
// pull-request channel; anything else to in-place.
func routeFor(gc GoldenCase) resolution.Route {
	data, _ := gc.ToolResponse("get_gitops_ownership", json.RawMessage(`{}`))
	var owner struct {
		ManagedBy string `json:"managed_by"`
	}
	_ = json.Unmarshal(data, &owner)
	switch owner.ManagedBy {
	case "argocd", "flux", "fleet":
		return resolution.RoutePullRequest
	default:
		return resolution.RouteInPlace
	}
}

// UserPromptFor builds the incident's user prompt in exactly the shape
// internal/api/analyze.go + internal/llm.BuildFindingsPrompt produce for a
// real incident with one finding. Kept here (rather than calling
// BuildFindingsPrompt, which needs a pgx.Tx) so the offline mode needs no
// database; the format string is the one thing this file mirrors by hand, and
// reasoner.go's own finding-line parser is pinned to the same shape.
func UserPromptFor(gc GoldenCase) string {
	f := gc.Finding
	return fmt.Sprintf(`Cluster: eval
Incident fingerprint: eval-%s, severity: %s, seen %d time(s)

Findings:
- [%s] v1/Pod/%s/%s reason=%q message=%q (detector=%s, x%d)
`, gc.ID, f.Severity, f.OccurrenceCount,
		f.Severity, f.Namespace, f.ObjectName, f.Reason, f.Message, f.DetectorID, f.OccurrenceCount)
}

// offlineToolNames are the tools a fixture can actually answer: the seven
// read-only cluster tools that reach an agent over the tunnel.
// InvestigationToolSchemas also registers dry_run_patch, query_metrics and
// the two repository tools, all of which are gated per-investigation on
// cluster/repository facts a fixture does not have — so they are filtered out
// here by name rather than by re-declaring the list that is kept.
var offlineExcludedTools = map[string]bool{
	"dry_run_patch":   true,
	"query_metrics":   true,
	"list_repo_files": true,
	"read_repo_file":  true,
}

func offlineToolDefs() []toolWireDef {
	var out []toolWireDef
	for _, ts := range llm.InvestigationToolSchemas() {
		if offlineExcludedTools[ts.Name] {
			continue
		}
		out = append(out, toolWireDef{
			Type: "function",
			Function: toolWireFunction{
				Name:        ts.Name,
				Description: ts.Description,
				Parameters:  ts.InputSchema,
			},
		})
	}
	return out
}

type toolWireFunction struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	Parameters  json.RawMessage `json:"parameters"`
}

type toolWireDef struct {
	Type     string           `json:"type"`
	Function toolWireFunction `json:"function"`
}

// RunCaseOffline drives one case to a conclusion or a bound.
func RunCaseOffline(gc GoldenCase, opt OfflineOptions) (AnalyzeResponse, error) {
	maxIter := opt.MaxIterations
	if maxIter <= 0 {
		maxIter = llm.DefaultMaxIterations
	}

	system := opt.SystemPromptOverride
	if system == "" {
		system = llm.SystemPrompt(routeFor(gc), false, false, false)
	}
	messages := []wireMessage{
		{Role: "system", Content: &system},
		{Role: "user", Content: strPtr(UserPromptFor(gc))},
	}

	for iterations := 1; iterations <= maxIter; iterations++ {
		var turn wireMessage
		if opt.MeasuresRealModel() {
			var err error
			turn, err = callRealModel(messages, opt)
			if err != nil {
				return AnalyzeResponse{}, fmt.Errorf("case %s, iteration %d: %w", gc.ID, iterations, err)
			}
		} else {
			turn = decideNext(opt.Personality, messages)
		}

		if len(turn.ToolCalls) == 0 {
			content := ""
			if turn.Content != nil {
				content = *turn.Content
			}
			statement, confidence, actionType, err := parseConclusion(content)
			if err != nil {
				// A concluding message that does not parse is exactly what
				// internal/llm reports as a partial with reason
				// "malformed_final_answer": a real, fixable integration
				// failure, not a diagnosis. Scored as a partial so it cannot
				// masquerade as either a correct answer or a correct decline.
				return AnalyzeResponse{Status: "partial", Iterations: iterations}, nil
			}
			// Route/ActionType (PG9, 2026-10-13 parity review) are reported
			// only when a real model answered this turn. The deterministic
			// stand-in's own final answer never carries a proposedPlan at
			// all (decideNext has no plan concept, only a root-cause
			// statement), so reporting a Route for it would be reporting
			// something that run never actually reasoned about — see
			// fixReachedCheck's own doc comment for why resp.Route == ""
			// is exactly the signal that keeps this honest rather than a
			// gap to fill in.
			out := AnalyzeResponse{Status: "complete", RootCause: statement, Confidence: &confidence, Iterations: iterations}
			if opt.MeasuresRealModel() {
				out.Route, out.ActionType = string(routeFor(gc)), actionType
			}
			return out, nil
		}

		messages = append(messages, turn)
		for _, tc := range turn.ToolCalls {
			data, errMsg := gc.ToolResponse(tc.Function.Name, json.RawMessage(tc.Function.Arguments))
			content := string(data)
			if errMsg != "" {
				b, _ := json.Marshal(map[string]string{"error": errMsg})
				content = string(b)
			}
			messages = append(messages, wireMessage{Role: "tool", Content: &content, ToolCallID: tc.ID})
		}
	}

	return AnalyzeResponse{Status: "partial", Iterations: maxIter}, nil
}

// RunCorpusOffline runs every case once and scores it.
func RunCorpusOffline(cases []GoldenCase, opt OfflineOptions) ([]CaseResult, error) {
	results := make([]CaseResult, 0, len(cases))
	for i := range cases {
		if reason := SkipReasonFor(cases[i], opt.MeasuresRealModel()); reason != "" {
			results = append(results, SkipCase(cases[i], reason))
			continue
		}
		resp, err := RunCaseOffline(cases[i], opt)
		if err != nil {
			return nil, err
		}
		results = append(results, ScoreCase(cases[i], resp))
	}
	return results, nil
}

// parseConclusion reads the pinned final-answer shape. Tolerant of a markdown
// fence the way internal/llm's own parse is, and of a statement-only object
// with no confidence (scored as 0, which fails a definite case's minimum —
// the honest reading of "the model did not commit to one").
func parseConclusion(content string) (statement string, confidence float64, actionType string, err error) {
	trimmed := strings.TrimSpace(content)
	if strings.HasPrefix(trimmed, "```") {
		if i := strings.Index(trimmed, "\n"); i >= 0 {
			trimmed = trimmed[i+1:]
		}
		trimmed = strings.TrimSuffix(strings.TrimSpace(trimmed), "```")
	}
	// A model that prefixed prose before the object: take the outermost
	// braces, the same salvage internal/llm's stripJSONFence performs.
	if i := strings.Index(trimmed, "{"); i > 0 {
		if j := strings.LastIndex(trimmed, "}"); j > i {
			trimmed = trimmed[i : j+1]
		}
	}
	var final struct {
		RootCause struct {
			Statement string `json:"statement"`
		} `json:"rootCause"`
		Confidence float64 `json:"confidence"`
		// ProposedPlan (PG9, 2026-10-13 parity review): only actionType is
		// read — this harness grades WHICH fix was reached, never applies
		// one, so the rest of the plan's shape is not this parser's concern.
		ProposedPlan *struct {
			ActionType string `json:"actionType"`
		} `json:"proposedPlan"`
	}
	if err := json.Unmarshal([]byte(trimmed), &final); err != nil {
		return "", 0, "", fmt.Errorf("final answer did not parse: %w", err)
	}
	if final.RootCause.Statement == "" {
		return "", 0, "", fmt.Errorf("final answer carried no rootCause.statement")
	}
	if final.ProposedPlan != nil {
		actionType = final.ProposedPlan.ActionType
	}
	return final.RootCause.Statement, final.Confidence, actionType, nil
}

// callRealModel does one chat-completions round trip against a real provider.
func callRealModel(messages []wireMessage, opt OfflineOptions) (wireMessage, error) {
	timeout := opt.HTTPTimeout
	if timeout <= 0 {
		timeout = 2 * time.Minute
	}
	body, err := json.Marshal(struct {
		Model    string        `json:"model"`
		Messages []wireMessage `json:"messages"`
		Tools    []toolWireDef `json:"tools"`
	}{Model: opt.LLMModel, Messages: messages, Tools: offlineToolDefs()})
	if err != nil {
		return wireMessage{}, err
	}

	url := strings.TrimRight(opt.LLMBaseURL, "/") + "/chat/completions"
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return wireMessage{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	if opt.LLMAPIKey != "" {
		// Never logged anywhere in this package.
		req.Header.Set("Authorization", "Bearer "+opt.LLMAPIKey)
	}

	resp, err := (&http.Client{Timeout: timeout}).Do(req)
	if err != nil {
		return wireMessage{}, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return wireMessage{}, err
	}
	if resp.StatusCode != http.StatusOK {
		return wireMessage{}, fmt.Errorf("provider returned HTTP %d: %s", resp.StatusCode, truncate(string(raw), 300))
	}
	var parsed wireChatResponse
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return wireMessage{}, fmt.Errorf("provider response did not parse: %w", err)
	}
	if len(parsed.Choices) == 0 {
		return wireMessage{}, fmt.Errorf("provider returned no choices")
	}
	return parsed.Choices[0].Message, nil
}

func strPtr(s string) *string { return &s }
