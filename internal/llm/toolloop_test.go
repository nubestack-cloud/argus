package llm

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync"
	"testing"
	"time"

	"argus/internal/remediation"
	"argus/internal/resolution"
	"argus/internal/settings"
	"strings"
)

// --- test helpers: a fake OpenAI-tool-calling-compatible server ---

// scriptedTurn is one canned assistant response for the fake server to
// return. len(ToolCalls) == 0 means "final answer, no tool calls" — the
// model concluding. PromptTokens/CompletionTokens/CacheReadTokens let a test
// script per-turn usage explicitly (e.g. to prove accumulation sums every
// round rather than reporting only the last one); a zero value falls back to
// this file's long-standing default usage (100 prompt / 10 completion / 0
// cached) so every pre-existing test that doesn't set them keeps behaving
// exactly as before.
type scriptedTurn struct {
	Content          string
	ToolCalls        []toolCall
	Delay            time.Duration
	PromptTokens     int
	CompletionTokens int
	CacheReadTokens  int
}

// newFakeLLMServer starts an httptest.Server speaking this file's
// loopChatRequest/loopChatResponse wire shape. It returns script[i] for the
// i-th request received (0-indexed), clamped to the last scripted turn if
// more requests arrive than the script has entries — which is exactly what
// the iteration-limit and time-limit tests below want: a fake model that
// just keeps requesting another tool call forever. captured records every
// decoded request so tests can assert on message history (e.g. that a tool
// result actually made it back onto the wire as a role:"tool" message).
func newFakeLLMServer(t *testing.T, script []scriptedTurn) (*httptest.Server, *capturedRequests) {
	t.Helper()
	captured := &capturedRequests{}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req loopChatRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("fake LLM server: decode request: %v", err)
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		captured.add(req)

		idx := captured.count() - 1
		if idx >= len(script) {
			idx = len(script) - 1
		}
		turn := script[idx]
		if turn.Delay > 0 {
			time.Sleep(turn.Delay)
		}

		content := turn.Content
		resp := loopChatResponse{Model: "fake-model"}
		promptTokens, completionTokens := 100, 10
		if turn.PromptTokens != 0 {
			promptTokens = turn.PromptTokens
		}
		if turn.CompletionTokens != 0 {
			completionTokens = turn.CompletionTokens
		}
		resp.Usage.PromptTokens = promptTokens
		resp.Usage.CompletionTokens = completionTokens
		if turn.CacheReadTokens != 0 {
			resp.Usage.PromptTokensDetails = &struct {
				CachedTokens int `json:"cached_tokens"`
			}{CachedTokens: turn.CacheReadTokens}
		}
		resp.Choices = make([]struct {
			Message struct {
				Role      string     `json:"role"`
				Content   *string    `json:"content"`
				ToolCalls []toolCall `json:"tool_calls"`
			} `json:"message"`
			FinishReason string `json:"finish_reason"`
		}, 1)
		resp.Choices[0].Message.Role = "assistant"
		resp.Choices[0].Message.Content = &content
		resp.Choices[0].Message.ToolCalls = turn.ToolCalls

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	t.Cleanup(srv.Close)
	return srv, captured
}

// capturedRequests is a concurrency-safe log of every request the fake
// server decoded, in arrival order.
type capturedRequests struct {
	mu  sync.Mutex
	all []loopChatRequest
}

func (c *capturedRequests) add(req loopChatRequest) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.all = append(c.all, req)
}

func (c *capturedRequests) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.all)
}

func (c *capturedRequests) at(i int) loopChatRequest {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.all[i]
}

// tc builds one toolCall the fake server can hand back, JSON-encoding args
// into the Arguments *string* field exactly like a real provider would.
func tc(t *testing.T, id, name string, args any) toolCall {
	t.Helper()
	b, err := json.Marshal(args)
	if err != nil {
		t.Fatalf("tc: marshal args: %v", err)
	}
	return toolCall{ID: id, Type: "function", Function: toolCallFunction{Name: name, Arguments: string(b)}}
}

// fakeToolCallback records every invocation and returns scripted
// results/errors keyed by call order, standing in for gw.CallTool without
// any tunnel/gateway/agent involved.
type fakeToolCallback struct {
	mu      sync.Mutex
	calls   []recordedCall
	results map[int]json.RawMessage // by call index (0-based)
	errs    map[int]error
}

type recordedCall struct {
	Tool string
	Args json.RawMessage
}

func (f *fakeToolCallback) callback() ToolCallback {
	return func(ctx context.Context, tool string, args json.RawMessage) (json.RawMessage, error) {
		f.mu.Lock()
		idx := len(f.calls)
		f.calls = append(f.calls, recordedCall{Tool: tool, Args: args})
		f.mu.Unlock()

		if err, ok := f.errs[idx]; ok {
			return nil, err
		}
		if result, ok := f.results[idx]; ok {
			return result, nil
		}
		return json.RawMessage(`{}`), nil
	}
}

// --- tests ---

// TestInvestigateCompletesAfterMultipleToolCalls is the primary "prove the
// round trip" test: a scripted 3-tool-call investigation (get_events ->
// get_logs -> get_owner_chain) followed by a well-formed final JSON
// conclusion, confirming the full causal chain, tool-call records, and
// final root cause/confidence/ruledOut all come out shaped exactly per the
// pinned API contract.
func TestInvestigateCompletesAfterMultipleToolCalls(t *testing.T) {
	script := []scriptedTurn{
		{
			Content:   "HYPOTHESIS: check for recent warning events on the pod",
			ToolCalls: []toolCall{tc(t, "call_1", "get_events", map[string]string{"namespace": "default", "involvedObjectName": "web-0"})},
		},
		{
			Content:   "FINDING: no relevant events found\nHYPOTHESIS: check the pod's own logs for a crash reason",
			ToolCalls: []toolCall{tc(t, "call_2", "get_logs", map[string]string{"namespace": "default", "pod": "web-0"})},
		},
		{
			Content:   "FINDING: logs show an OOM kill message\nHYPOTHESIS: confirm via the owning ReplicaSet/Deployment's resource limits",
			ToolCalls: []toolCall{tc(t, "call_3", "get_owner_chain", map[string]string{"gvk": "v1/Pod", "namespace": "default", "name": "web-0", "direction": "up"})},
		},
		{
			Content: `{"rootCause": {"statement": "web-0 was OOMKilled due to an undersized memory limit"}, "confidence": 0.82, "ruledOut": [{"hypothesis": "disk pressure eviction", "reason": "no DiskPressure events found"}]}`,
		},
	}
	srv, captured := newFakeLLMServer(t, script)

	fake := &fakeToolCallback{
		results: map[int]json.RawMessage{
			0: json.RawMessage(`{"items":[]}`),
			1: json.RawMessage(`{"lines":["OOMKilled: container exceeded memory limit"]}`),
			2: json.RawMessage(`[{"gvk":"apps/v1/ReplicaSet","namespace":"default","name":"web","resolved":true}]`),
		},
	}

	result, err := investigate(t.Context(), srv.Client(), srv.URL, "", "fake-model",
		"system prompt", "user prompt", fake.callback(), 8, time.Minute, toolAvailability{dryRun: false})
	if err != nil {
		t.Fatalf("investigate: %v", err)
	}

	if result.Status != "complete" {
		t.Fatalf("Status = %q, want %q", result.Status, "complete")
	}
	if result.Iterations != 4 {
		t.Errorf("Iterations = %d, want 4 (one model call per scripted turn)", result.Iterations)
	}
	if result.RootCause == nil || result.RootCause.Statement != "web-0 was OOMKilled due to an undersized memory limit" {
		t.Errorf("RootCause = %+v, want the scripted statement", result.RootCause)
	}
	if result.Confidence == nil || *result.Confidence != 0.82 {
		t.Errorf("Confidence = %v, want 0.82", result.Confidence)
	}
	if len(result.RuledOut) != 1 || result.RuledOut[0].Hypothesis != "disk pressure eviction" {
		t.Errorf("RuledOut = %+v, want the one scripted entry", result.RuledOut)
	}

	if len(result.CausalChain) != 3 {
		t.Fatalf("len(CausalChain) = %d, want 3", len(result.CausalChain))
	}
	step0 := result.CausalChain[0]
	if step0.Step != 1 {
		t.Errorf("CausalChain[0].Step = %d, want 1", step0.Step)
	}
	if step0.Hypothesis != "check for recent warning events on the pod" {
		t.Errorf("CausalChain[0].Hypothesis = %q, want the parsed HYPOTHESIS: line", step0.Hypothesis)
	}
	if step0.Finding != "no relevant events found" {
		t.Errorf("CausalChain[0].Finding = %q, want the NEXT turn's parsed FINDING: line", step0.Finding)
	}
	if len(step0.ToolCalls) != 1 || step0.ToolCalls[0].Tool != "get_events" {
		t.Fatalf("CausalChain[0].ToolCalls = %+v, want exactly one get_events call", step0.ToolCalls)
	}
	if step0.ToolCalls[0].Error != nil {
		t.Errorf("CausalChain[0].ToolCalls[0].Error = %v, want nil", *step0.ToolCalls[0].Error)
	}
	if string(step0.ToolCalls[0].Result) != `{"items":[]}` {
		t.Errorf("CausalChain[0].ToolCalls[0].Result = %s, want the scripted tool result verbatim", step0.ToolCalls[0].Result)
	}

	step2 := result.CausalChain[2]
	if step2.Finding != "" {
		t.Errorf("CausalChain[2] (the last step before the pure-JSON conclusion) .Finding = %q, want empty — "+
			"documented simplification: the final turn is pure JSON, not a FINDING: wrap-up", step2.Finding)
	}

	// Confirm the tool callback actually saw all 3 calls, in order, with the
	// right tool name and args — not just that the causal chain claims so.
	if len(fake.calls) != 3 {
		t.Fatalf("fake tool callback invoked %d times, want 3", len(fake.calls))
	}
	if fake.calls[1].Tool != "get_logs" {
		t.Errorf("fake.calls[1].Tool = %q, want get_logs", fake.calls[1].Tool)
	}
	var logsArgs struct {
		Pod string `json:"pod"`
	}
	if err := json.Unmarshal(fake.calls[1].Args, &logsArgs); err != nil || logsArgs.Pod != "web-0" {
		t.Errorf("fake.calls[1].Args = %s, want pod=web-0", fake.calls[1].Args)
	}

	// Confirm the tool result actually made it back onto the wire as a
	// role:"tool" message before the next model call, not just recorded
	// locally in the causal chain — the whole point of using tool-role
	// messages rather than splicing evidence into the system/user prompt.
	if captured.count() < 2 {
		t.Fatalf("fake LLM server saw %d requests, want at least 2", captured.count())
	}
	secondReq := captured.at(1)
	lastMsg := secondReq.Messages[len(secondReq.Messages)-1]
	if lastMsg.Role != "tool" || lastMsg.Content == nil || *lastMsg.Content != `{"items":[]}` {
		t.Errorf("second request's last message = %+v, want a role:tool message carrying the first tool result", lastMsg)
	}
}

// TestInvestigateHitsIterationLimit scripts a model that always requests
// another tool call and never concludes, confirming the loop stops exactly
// at maxIterations (never issuing one more model call past the bound — the
// "checked before, not after" requirement) and returns a well-formed
// PartialAnalysis: status partial, iteration_limit, RootCause/Confidence
// nil, and a non-empty causal chain/suggestedNextSteps.
func TestInvestigateHitsIterationLimit(t *testing.T) {
	script := []scriptedTurn{
		{
			Content:   "HYPOTHESIS: keep looking\nFINDING: nothing conclusive yet",
			ToolCalls: []toolCall{tc(t, "call", "get_events", map[string]string{"namespace": "default"})},
		},
	}
	srv, captured := newFakeLLMServer(t, script)
	fake := &fakeToolCallback{}

	const maxIter = 3
	result, err := investigate(t.Context(), srv.Client(), srv.URL, "", "fake-model",
		"system", "user", fake.callback(), maxIter, time.Minute, toolAvailability{dryRun: false})
	if err != nil {
		t.Fatalf("investigate: %v", err)
	}

	if result.Status != "partial" {
		t.Fatalf("Status = %q, want partial", result.Status)
	}
	if result.PartialReason != "iteration_limit" {
		t.Errorf("PartialReason = %q, want iteration_limit", result.PartialReason)
	}
	if result.RootCause != nil {
		t.Errorf("RootCause = %+v, want nil on a partial result", result.RootCause)
	}
	if result.Confidence != nil {
		t.Errorf("Confidence = %v, want nil (never a number) on a partial result", *result.Confidence)
	}
	if result.Iterations != maxIter {
		t.Errorf("Iterations = %d, want exactly maxIterations (%d)", result.Iterations, maxIter)
	}
	if len(result.CausalChain) != maxIter {
		t.Errorf("len(CausalChain) = %d, want %d", len(result.CausalChain), maxIter)
	}
	if len(result.SuggestedNextSteps) == 0 {
		t.Error("SuggestedNextSteps is empty, want at least one suggestion on a partial result")
	}
	if result.RuledOut == nil {
		t.Error("RuledOut = nil, want a non-nil (possibly empty) slice")
	}

	// The bound must be checked BEFORE issuing the next round, not after —
	// exactly maxIterations model calls, never maxIterations+1.
	if captured.count() != maxIter {
		t.Errorf("fake LLM server received %d requests, want exactly %d (bound checked before, not after)", captured.count(), maxIter)
	}
}

// TestInvestigateHitsTimeLimit confirms the wall-clock bound is independent
// of (and can bind before) the iteration cap: a generous maxIterations with
// a tiny time budget and an artificially slow fake model must stop on
// time_limit, not iteration_limit, once the deadline has passed.
func TestInvestigateHitsTimeLimit(t *testing.T) {
	script := []scriptedTurn{
		{
			Content:   "HYPOTHESIS: still checking",
			ToolCalls: []toolCall{tc(t, "call", "get_events", map[string]string{})},
			Delay:     40 * time.Millisecond,
		},
	}
	srv, captured := newFakeLLMServer(t, script)
	fake := &fakeToolCallback{}

	result, err := investigate(t.Context(), srv.Client(), srv.URL, "", "fake-model",
		"system", "user", fake.callback(), 1000, 30*time.Millisecond, toolAvailability{dryRun: false})
	if err != nil {
		t.Fatalf("investigate: %v", err)
	}

	if result.Status != "partial" || result.PartialReason != "time_limit" {
		t.Fatalf("Status/PartialReason = %q/%q, want partial/time_limit", result.Status, result.PartialReason)
	}
	if captured.count() == 0 {
		t.Fatal("expected at least one round to complete before the deadline was checked")
	}
	if captured.count() >= 1000 {
		t.Errorf("fake LLM server received %d requests — the 1000-iteration cap should never have been reached under a 30ms time budget", captured.count())
	}
}

// TestInvestigateRecordsToolCallErrorsAndContinues confirms a failing tool
// call (e.g. the agent's own "resource not found"/"no reachable cluster"
// errors) is recorded on the causal chain, fed back to the model as a
// normal tool-result message (not silently dropped, not aborting the whole
// investigation), and the loop can still reach a normal conclusion
// afterward — a bounded investigation must be able to tolerate a probe that
// finds nothing and adapt, not treat every tool-level error as fatal.
func TestInvestigateRecordsToolCallErrorsAndContinues(t *testing.T) {
	script := []scriptedTurn{
		{
			Content:   "HYPOTHESIS: check the pod's logs",
			ToolCalls: []toolCall{tc(t, "call_1", "get_logs", map[string]string{"namespace": "default", "pod": "ghost"})},
		},
		{
			Content: `{"rootCause": {"statement": "could not determine — the target pod no longer exists"}, "confidence": 0.1, "ruledOut": []}`,
		},
	}
	srv, captured := newFakeLLMServer(t, script)
	fake := &fakeToolCallback{errs: map[int]error{0: errors.New("resource not found")}}

	result, err := investigate(t.Context(), srv.Client(), srv.URL, "", "fake-model",
		"system", "user", fake.callback(), 8, time.Minute, toolAvailability{dryRun: false})
	if err != nil {
		t.Fatalf("investigate: %v", err)
	}

	if result.Status != "complete" {
		t.Fatalf("Status = %q, want complete (a tool-level error is evidence, not a fatal abort)", result.Status)
	}
	if len(result.CausalChain) != 1 || len(result.CausalChain[0].ToolCalls) != 1 {
		t.Fatalf("CausalChain = %+v, want exactly one step with one tool call", result.CausalChain)
	}
	rec := result.CausalChain[0].ToolCalls[0]
	if rec.Error == nil || *rec.Error != "resource not found" {
		t.Errorf("ToolCalls[0].Error = %v, want \"resource not found\"", rec.Error)
	}
	if rec.Result != nil {
		t.Errorf("ToolCalls[0].Result = %s, want nil/omitted when Error is set", rec.Result)
	}

	secondReq := captured.at(1)
	lastMsg := secondReq.Messages[len(secondReq.Messages)-1]
	if lastMsg.Role != "tool" || lastMsg.Content == nil {
		t.Fatalf("second request's last message = %+v, want a role:tool message", lastMsg)
	}
	var errPayload struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal([]byte(*lastMsg.Content), &errPayload); err != nil || errPayload.Error != "resource not found" {
		t.Errorf("tool-result message content = %q, want a JSON {\"error\":\"resource not found\"} payload", *lastMsg.Content)
	}
}

// TestInvestigateFallsBackWhenFinalContentIsNotJSON confirms a model that
// ignores the instructed final-JSON shape doesn't crash the request or
// silently fabricate a confident-looking number — it falls back to the raw
// text as the statement with a deliberately low, documented confidence.
// TestInvestigateReportsAnUnparseableFinalAnswerAsPartial replaces an earlier test
// that asserted the opposite (BACKLOG C2, WORKLOG §158). That test locked in a
// Status of "complete", the raw prose promoted to a root-cause statement, and a
// confidence of 0.3 — a number the model never committed to.
//
// It was the exact "answer-shaped non-answer" that parseFinalAnalysis' own doc
// comment, twenty lines above the branch, refuses on the neighbouring path. It also
// disagreed with cli_investigator.go, which has always reported this same failure
// as partial. And a fabricated confidence is actively harmful now that feedback is
// collected against it: a calibration curve would carry a point claiming the model
// was 30% sure of a sentence it never said.
//
// The incident's resulting state is unchanged — orchestrator.Advance routes both a
// partial result and a nil-plan result to NeedsHumanInvestigation — so this is an
// honesty fix, not a behaviour change.
func TestInvestigateReportsAnUnparseableFinalAnswerAsPartial(t *testing.T) {
	const prose = "I think it's probably a networking issue, not totally sure though."
	script := []scriptedTurn{{Content: prose}}
	srv, _ := newFakeLLMServer(t, script)
	fake := &fakeToolCallback{}

	result, err := investigate(t.Context(), srv.Client(), srv.URL, "", "fake-model",
		"system", "user", fake.callback(), 8, time.Minute, toolAvailability{dryRun: false})
	if err != nil {
		t.Fatalf("investigate: %v", err)
	}
	if result.Status != "partial" {
		t.Fatalf("Status = %q, want partial — an unreadable final answer is not a conclusion", result.Status)
	}
	if result.PartialReason != "malformed_final_answer" {
		t.Errorf("PartialReason = %q, want malformed_final_answer — the same value cli_investigator.go reports for the same failure, and the one the frontend already has a sentence for", result.PartialReason)
	}
	if result.Confidence != nil {
		t.Errorf("Confidence = %v, want nil — any number here is invented, and an invented confidence poisons calibration", *result.Confidence)
	}
	if result.RootCause != nil {
		t.Errorf("RootCause = %+v, want nil — the prose is evidence about a failed run, not a root cause", result.RootCause)
	}
	// The prose must still be KEPT, just in the field that describes what it is.
	// Losing it was the original problem C2 names: "a real investigation failed
	// this way and its answer was simply gone".
	if result.RawFinalAnswer != prose {
		t.Errorf("RawFinalAnswer = %q, want the model's actual text — discarding it makes a prompt problem indistinguishable from a harness problem", result.RawFinalAnswer)
	}
	if result.ParseError == "" {
		t.Error("ParseError is empty, want the reason the answer could not be read; migration 000054's CHECK requires it alongside RawFinalAnswer")
	}
}

// TestInvestigateToleratesAOneSentencePrefixBeforeFencedJSON is PROJECT.md
// B152's own regression test: a real, complete, well-evidenced final answer
// discarded as "malformed_final_answer" purely because the model prefixed
// one plain sentence before its fenced JSON conclusion — the exact live
// shape found in the breadth campaign (fixtures BATCH-010/OPER-010). Before
// this fix, investigate() called parseFinalAnalysis directly, which only
// tolerates a bare (optionally fenced) JSON object spanning the WHOLE
// message; a leading "FINDING: ..." sentence made the whole-string parse
// fail with "invalid character 'F' looking for beginning of value", exactly
// like this test's own content, and the real diagnosis in raw_final_answer
// was thrown away even though it was fully correct. The fix routes through
// extractFinalAnalysis instead — already built and used by the cli backend
// for the identical reason — which retries via a brace-balanced scan before
// giving up.
func TestInvestigateToleratesAOneSentencePrefixBeforeFencedJSON(t *testing.T) {
	const content = "FINDING: the Deployment is crash-looping due to a missing ConfigMap key.\n\n```json\n" +
		`{"rootCause": {"statement": "missing ConfigMap key LOG_LEVEL", "isFault": true}, "confidence": 0.9, "ruledOut": []}` +
		"\n```"
	script := []scriptedTurn{{Content: content}}
	srv, _ := newFakeLLMServer(t, script)
	fake := &fakeToolCallback{}

	result, err := investigate(t.Context(), srv.Client(), srv.URL, "", "fake-model",
		"system", "user", fake.callback(), 8, time.Minute, toolAvailability{dryRun: false})
	if err != nil {
		t.Fatalf("investigate: %v", err)
	}
	if result.Status != "complete" {
		t.Fatalf("Status = %q, want complete — a one-sentence prefix before well-formed JSON is not the same failure as a model abandoning the JSON contract entirely (PartialReason=%q, ParseError=%q)",
			result.Status, result.PartialReason, result.ParseError)
	}
	if result.RootCause == nil || result.RootCause.Statement != "missing ConfigMap key LOG_LEVEL" {
		t.Fatalf("RootCause = %+v, want the real diagnosis recovered from the fenced JSON despite the leading sentence", result.RootCause)
	}
	if result.Confidence == nil || *result.Confidence != 0.9 {
		t.Fatalf("Confidence = %v, want the model's real 0.9, not a fabricated or missing value", result.Confidence)
	}
}

// TestInvestigateAccumulatesTokenUsageAcrossAllRounds is the primary
// regression test for the token/cost accounting gap this task closes: a
// multi-turn investigation makes several LLM calls, not one, so
// Investigation.TokensIn/TokensCacheRead/TokensOut must be the SUM of every
// round's usage, not just the concluding round's — internal/api/analyze.go
// persists these directly into analyses.tokens_billed_in/tokens_cache_read/
// tokens_out. Scripts 3 tool-calling rounds + 1 concluding round, each with a
// deliberately distinct usage figure, so a bug that reported only the last
// round's numbers (100/20/5, this test's 4th-turn figures) would be caught
// immediately rather than accidentally passing because every round happened
// to use the same numbers.
func TestInvestigateAccumulatesTokenUsageAcrossAllRounds(t *testing.T) {
	script := []scriptedTurn{
		{
			Content:          "HYPOTHESIS: check recent events",
			ToolCalls:        []toolCall{tc(t, "call_1", "get_events", map[string]string{"namespace": "default"})},
			PromptTokens:     200,
			CompletionTokens: 15,
			CacheReadTokens:  0, // first round: nothing cached yet
		},
		{
			Content:          "FINDING: nothing conclusive\nHYPOTHESIS: check the owner chain",
			ToolCalls:        []toolCall{tc(t, "call_2", "get_owner_chain", map[string]string{"gvk": "v1/Pod", "namespace": "default", "name": "web-0", "direction": "up"})},
			PromptTokens:     260,
			CompletionTokens: 12,
			CacheReadTokens:  180, // the stable system/user prefix is now cache-hit
		},
		{
			Content:          "FINDING: owner chain resolved\nHYPOTHESIS: check the pod's logs",
			ToolCalls:        []toolCall{tc(t, "call_3", "get_logs", map[string]string{"namespace": "default", "pod": "web-0"})},
			PromptTokens:     310,
			CompletionTokens: 18,
			CacheReadTokens:  240,
		},
		{
			Content:          `{"rootCause": {"statement": "web-0 crashed"}, "confidence": 0.7, "ruledOut": []}`,
			PromptTokens:     100,
			CompletionTokens: 20,
			CacheReadTokens:  5,
		},
	}
	srv, _ := newFakeLLMServer(t, script)
	fake := &fakeToolCallback{}

	result, err := investigate(t.Context(), srv.Client(), srv.URL, "", "fake-model",
		"system prompt", "user prompt", fake.callback(), 8, time.Minute, toolAvailability{dryRun: false})
	if err != nil {
		t.Fatalf("investigate: %v", err)
	}
	if result.Status != "complete" {
		t.Fatalf("Status = %q, want complete", result.Status)
	}

	wantIn := 200 + 260 + 310 + 100
	wantCacheRead := 0 + 180 + 240 + 5
	wantOut := 15 + 12 + 18 + 20
	if result.TokensIn != wantIn {
		t.Errorf("TokensIn = %d, want %d (sum of all 4 rounds, not just the last round's %d)", result.TokensIn, wantIn, 100)
	}
	if result.TokensCacheRead != wantCacheRead {
		t.Errorf("TokensCacheRead = %d, want %d (sum of all 4 rounds, not just the last round's %d)", result.TokensCacheRead, wantCacheRead, 5)
	}
	if result.TokensOut != wantOut {
		t.Errorf("TokensOut = %d, want %d (sum of all 4 rounds, not just the last round's %d)", result.TokensOut, wantOut, 20)
	}
}

// TestInvestigatePartialResultStillReportsRealAccumulatedUsage confirms a
// bound-hit (partial) investigation's token accounting is exactly as real as
// a complete one's — it made just as many real, billed LLM calls, so
// PartialAnalysis must never zero out its usage just because it never
// reached a conclusion.
func TestInvestigatePartialResultStillReportsRealAccumulatedUsage(t *testing.T) {
	script := []scriptedTurn{
		{
			Content:          "HYPOTHESIS: keep looking\nFINDING: nothing conclusive yet",
			ToolCalls:        []toolCall{tc(t, "call", "get_events", map[string]string{"namespace": "default"})},
			PromptTokens:     150,
			CompletionTokens: 8,
			CacheReadTokens:  50,
		},
	}
	srv, captured := newFakeLLMServer(t, script)
	fake := &fakeToolCallback{}

	const maxIter = 4
	result, err := investigate(t.Context(), srv.Client(), srv.URL, "", "fake-model",
		"system", "user", fake.callback(), maxIter, time.Minute, toolAvailability{dryRun: false})
	if err != nil {
		t.Fatalf("investigate: %v", err)
	}
	if result.Status != "partial" {
		t.Fatalf("Status = %q, want partial", result.Status)
	}
	if captured.count() != maxIter {
		t.Fatalf("fake LLM server received %d requests, want exactly %d", captured.count(), maxIter)
	}

	wantIn := 150 * maxIter
	wantCacheRead := 50 * maxIter
	wantOut := 8 * maxIter
	if result.TokensIn != wantIn {
		t.Errorf("TokensIn = %d, want %d (summed across all %d rounds actually made)", result.TokensIn, wantIn, maxIter)
	}
	if result.TokensCacheRead != wantCacheRead {
		t.Errorf("TokensCacheRead = %d, want %d", result.TokensCacheRead, wantCacheRead)
	}
	if result.TokensOut != wantOut {
		t.Errorf("TokensOut = %d, want %d", result.TokensOut, wantOut)
	}
	if result.TokensIn == 0 || result.TokensOut == 0 {
		t.Error("a partial result must still report real, non-zero accumulated usage — a bound-hit investigation still made real, billed LLM calls")
	}
}

// TestResolveBoundsDefaultsAndOverrides confirms resolveBounds' now-narrower
// job: apply DefaultMaxIterations/DefaultTimeLimit exactly when
// settings.Config's two fields are nil (env-var/DB precedence itself is
// settings.Resolve's job now, covered by internal/settings/settings_test.go,
// not re-tested here), and use the resolved Config value as-is otherwise —
// no more env var reads, no more "invalid value" tolerance in this function,
// since a non-positive/unparseable input is now filtered out one layer down
// by settings.resolve's firstNonNilPositiveInt before this function ever
// sees it.
func TestResolveBoundsDefaultsAndOverrides(t *testing.T) {
	t.Run("defaults when Config's bounds are nil", func(t *testing.T) {
		maxIter, timeLimit := resolveBounds(settings.Config{})
		if maxIter != DefaultMaxIterations || timeLimit != DefaultTimeLimit {
			t.Errorf("got (%d, %s), want defaults (%d, %s)", maxIter, timeLimit, DefaultMaxIterations, DefaultTimeLimit)
		}
	})

	t.Run("a resolved Config value overrides the defaults", func(t *testing.T) {
		iters, secs := 20, 600
		maxIter, timeLimit := resolveBounds(settings.Config{AnalysisMaxIterations: &iters, AnalysisTimeLimitSeconds: &secs})
		if maxIter != 20 || timeLimit != 600*time.Second {
			t.Errorf("got (%d, %s), want (20, 600s)", maxIter, timeLimit)
		}
	})

	t.Run("only one of the two bounds resolved leaves the other at its default", func(t *testing.T) {
		iters := 3
		maxIter, timeLimit := resolveBounds(settings.Config{AnalysisMaxIterations: &iters})
		if maxIter != 3 || timeLimit != DefaultTimeLimit {
			t.Errorf("got (%d, %s), want (3, %s)", maxIter, timeLimit, DefaultTimeLimit)
		}
	})
}

// TestParseTurnTextIgnoresMissingMarkers confirms the FINDING:/HYPOTHESIS:
// parsing is genuinely best-effort — a turn that uses neither marker yields
// empty strings rather than misparsing arbitrary prose as one or the other.
func TestParseTurnTextIgnoresMissingMarkers(t *testing.T) {
	finding, hypothesis := parseTurnText("just some prose with no markers at all")
	if finding != "" || hypothesis != "" {
		t.Errorf("got (%q, %q), want (\"\", \"\") for unmarked content", finding, hypothesis)
	}

	finding, hypothesis = parseTurnText("FINDING: the pod is missing\nHYPOTHESIS: check its owner")
	if finding != "the pod is missing" || hypothesis != "check its owner" {
		t.Errorf("got (%q, %q), want (\"the pod is missing\", \"check its owner\")", finding, hypothesis)
	}
}

// --- proposedPlan parsing (parseProposedPlan / Investigate wiring) ---

// TestParseProposedPlan_AbsentOrNull confirms "no plan proposed" (the
// normal, expected case per this task's brief) is read the same way
// whether the key is omitted entirely or explicitly JSON null.
func TestParseProposedPlan_AbsentOrNull(t *testing.T) {
	if p := parseProposedPlan(nil); p != nil {
		t.Errorf("nil raw: got %+v, want nil", p)
	}
	if p := parseProposedPlan(json.RawMessage(`null`)); p != nil {
		t.Errorf("JSON null: got %+v, want nil", p)
	}
	if p := parseProposedPlan(json.RawMessage(`{}`)); p != nil {
		t.Errorf("empty object: got %+v, want nil (indistinguishable from omitted)", p)
	}
}

// TestParseProposedPlan_WellFormed confirms each of the three ActionTypes
// round-trips through the wire shape SystemPrompt documents into the exact
// typed remediation.ActionParams struct internal/remediation expects.
func TestParseProposedPlan_WellFormed(t *testing.T) {
	t.Run("ScaleDeployment", func(t *testing.T) {
		raw := json.RawMessage(`{"actionType":"ScaleDeployment","targetGvk":"apps/v1/Deployment","targetNamespace":"payments","targetName":"checkout-worker","params":{"replicas":4},"reversible":true,"riskLevel":"low"}`)
		plan := parseProposedPlan(raw)
		if plan == nil {
			t.Fatal("got nil, want a parsed plan")
		}
		if err := plan.Validate(); err != nil {
			t.Errorf("Validate() = %v, want nil (well-formed plan)", err)
		}
		params, ok := plan.Params.(remediation.ScaleDeploymentParams)
		if !ok || params.Replicas != 4 {
			t.Errorf("Params = %+v, want ScaleDeploymentParams{Replicas: 4}", plan.Params)
		}
		if plan.TargetNamespace != "payments" || plan.TargetName != "checkout-worker" || !plan.Reversible || plan.RiskLevel != remediation.RiskLow {
			t.Errorf("plan = %+v, fields don't match the wire input", plan)
		}
	})

	t.Run("RestartPod", func(t *testing.T) {
		raw := json.RawMessage(`{"actionType":"RestartPod","targetGvk":"v1/Pod","targetNamespace":"payments","targetName":"checkout-worker-abc","params":{},"reversible":false,"riskLevel":"medium"}`)
		plan := parseProposedPlan(raw)
		if plan == nil {
			t.Fatal("got nil, want a parsed plan")
		}
		if err := plan.Validate(); err != nil {
			t.Errorf("Validate() = %v, want nil", err)
		}
		if _, ok := plan.Params.(remediation.RestartPodParams); !ok {
			t.Errorf("Params = %+v, want RestartPodParams{}", plan.Params)
		}
	})

	t.Run("DeleteResource", func(t *testing.T) {
		raw := json.RawMessage(`{"actionType":"DeleteResource","targetGvk":"v1/PersistentVolumeClaim","targetNamespace":"apps","targetName":"data-sts8-victim-1","params":{},"reversible":false,"riskLevel":"high"}`)
		plan := parseProposedPlan(raw)
		if plan == nil {
			t.Fatal("got nil, want a parsed plan")
		}
		if err := plan.Validate(); err != nil {
			t.Errorf("Validate() = %v, want nil", err)
		}
		if _, ok := plan.Params.(remediation.DeleteResourceParams); !ok {
			t.Errorf("Params = %+v, want DeleteResourceParams{}", plan.Params)
		}
		if plan.TargetGVK != "v1/PersistentVolumeClaim" || plan.Reversible || plan.RiskLevel != remediation.RiskHigh {
			t.Errorf("plan = %+v, fields don't match the wire input", plan)
		}
	})

	t.Run("OpenPR", func(t *testing.T) {
		// Two files, one of them a chart TEMPLATE — the shape the retired
		// single-field grammar could not express at all, and the reason this
		// wire shape changed.
		raw := json.RawMessage(`{"actionType":"OpenPR","targetGvk":"apps/v1/Deployment","targetNamespace":"payments","targetName":"checkout-worker","params":{"repository":"org/repo","files":[{"path":"charts/checkout/values.yaml","content":"image:\n  tag: 1.2.3\n"},{"path":"charts/checkout/templates/deployment.yaml","content":"image: {{ .Values.image.tag }}\n"}]},"reversible":true,"riskLevel":"medium"}`)
		plan := parseProposedPlan(raw)
		if plan == nil {
			t.Fatal("got nil, want a parsed plan")
		}
		if err := plan.Validate(); err != nil {
			t.Errorf("Validate() = %v, want nil", err)
		}
		params, ok := plan.Params.(remediation.OpenPRParams)
		if !ok {
			t.Fatalf("Params = %+v, want OpenPRParams", plan.Params)
		}
		if params.Repository != "org/repo" || len(params.Files) != 2 {
			t.Fatalf("Params = %+v, want the repository and both files", params)
		}
		if params.Files[0].Path != "charts/checkout/values.yaml" || !strings.Contains(params.Files[0].Content, "tag: 1.2.3") {
			t.Errorf("Files[0] = %+v, want the values file with its whole content", params.Files[0])
		}
		if !strings.Contains(params.Files[1].Content, "{{ .Values.image.tag }}") {
			t.Errorf("Files[1] = %+v, want the template's content carried verbatim, template markers included", params.Files[1])
		}
	})

	// BACKLOG.md "still open" #2: AB1's finding named the correct fix as
	// "delete one whole HPA manifest from the repo" — the model now has a
	// distinct "delete" field to ask for exactly that.
	t.Run("OpenPR with a delete", func(t *testing.T) {
		raw := json.RawMessage(`{"actionType":"OpenPR","targetGvk":"autoscaling/v2/HorizontalPodAutoscaler","targetNamespace":"payments","targetName":"checkout-worker","params":{"repository":"org/repo","files":[{"path":"envs/prod/hpa-a.yaml","delete":true}]},"reversible":true,"riskLevel":"low"}`)
		plan := parseProposedPlan(raw)
		if plan == nil {
			t.Fatal("got nil, want a parsed plan")
		}
		if err := plan.Validate(); err != nil {
			t.Errorf("Validate() = %v, want nil (a delete needs no content)", err)
		}
		params, ok := plan.Params.(remediation.OpenPRParams)
		if !ok {
			t.Fatalf("Params = %+v, want OpenPRParams", plan.Params)
		}
		if len(params.Files) != 1 || !params.Files[0].Delete || params.Files[0].Content != "" {
			t.Errorf("Files = %+v, want exactly one file marked Delete with no content", params.Files)
		}
	})
}

// TestParseProposedPlan_StructurallyInvalidStillReturned confirms this
// function does NOT reject a malformed plan itself — an unrecognized
// actionType is handed back as a non-nil plan whose Validate() fails, since
// internal/remediation.Evaluate (called downstream, by internal/orchestrator)
// is the single authoritative place that turns "invalid plan" into a
// Blocked decision. If this function silently discarded it instead, that
// downstream Blocked-with-a-precise-reason behavior would never fire.
func TestParseProposedPlan_StructurallyInvalidStillReturned(t *testing.T) {
	raw := json.RawMessage(`{"actionType":"DeleteNamespace","targetGvk":"v1/Namespace","targetName":"payments","reversible":false,"riskLevel":"high"}`)
	plan := parseProposedPlan(raw)
	if plan == nil {
		t.Fatal("got nil, want a non-nil (structurally invalid) plan")
	}
	if err := plan.Validate(); err == nil {
		t.Error("Validate() = nil, want an error (unrecognized action type)")
	}
}

// TestInvestigateParsesProposedPlanFromFinalMessage is the end-to-end case:
// a scripted model concludes with a proposedPlan in its final JSON, and
// Investigate's result carries it through as a real, typed
// remediation.RemediationPlan.
func TestInvestigateParsesProposedPlanFromFinalMessage(t *testing.T) {
	script := []scriptedTurn{
		{
			Content: `{"rootCause": {"statement": "checkout-worker is under-provisioned for current load"}, "confidence": 0.88, "ruledOut": [], "proposedPlan": {"actionType": "ScaleDeployment", "targetGvk": "apps/v1/Deployment", "targetNamespace": "payments", "targetName": "checkout-worker", "params": {"replicas": 4}, "reversible": true, "riskLevel": "low"}}`,
		},
	}
	srv, _ := newFakeLLMServer(t, script)
	fake := &fakeToolCallback{results: map[int]json.RawMessage{}}

	result, err := investigate(t.Context(), srv.Client(), srv.URL, "", "fake-model",
		"system prompt", "user prompt", fake.callback(), 8, time.Minute, toolAvailability{dryRun: false})
	if err != nil {
		t.Fatalf("investigate: %v", err)
	}
	if result.ProposedPlan == nil {
		t.Fatal("ProposedPlan is nil, want the scripted plan")
	}
	if err := result.ProposedPlan.Validate(); err != nil {
		t.Errorf("ProposedPlan.Validate() = %v, want nil", err)
	}
	if result.ProposedPlan.ActionType != remediation.ActionScaleDeployment {
		t.Errorf("ActionType = %q, want ScaleDeployment", result.ProposedPlan.ActionType)
	}
	params, ok := result.ProposedPlan.Params.(remediation.ScaleDeploymentParams)
	if !ok || params.Replicas != 4 {
		t.Errorf("Params = %+v, want ScaleDeploymentParams{Replicas: 4}", result.ProposedPlan.Params)
	}
}

// TestInvestigateNoProposedPlanIsNormal confirms a conclusion with no
// proposedPlan at all (the field omitted) is a completely normal, non-error
// result — ProposedPlan is simply nil.
func TestInvestigateNoProposedPlanIsNormal(t *testing.T) {
	script := []scriptedTurn{
		{Content: `{"rootCause": {"statement": "a misconfigured ConfigMap value, no clean automated fix"}, "confidence": 0.6, "ruledOut": []}`},
	}
	srv, _ := newFakeLLMServer(t, script)
	fake := &fakeToolCallback{results: map[int]json.RawMessage{}}

	result, err := investigate(t.Context(), srv.Client(), srv.URL, "", "fake-model",
		"system prompt", "user prompt", fake.callback(), 8, time.Minute, toolAvailability{dryRun: false})
	if err != nil {
		t.Fatalf("investigate: %v", err)
	}
	if result.Status != "complete" {
		t.Fatalf("Status = %q, want complete", result.Status)
	}
	if result.ProposedPlan != nil {
		t.Errorf("ProposedPlan = %+v, want nil", result.ProposedPlan)
	}
}

// TestInvestigatePartialNeverCarriesAProposedPlan confirms a bound-hit
// investigation's ProposedPlan is always nil, even though it never ran the
// final-message parsing path that could populate one — a structural
// property of partialInvestigation, checked directly here rather than only
// implicitly by every other partial-result test.
func TestInvestigatePartialNeverCarriesAProposedPlan(t *testing.T) {
	script := []scriptedTurn{
		{Content: "HYPOTHESIS: probe", ToolCalls: []toolCall{tc(t, "call_1", "get_events", map[string]string{"namespace": "default"})}},
	}
	srv, _ := newFakeLLMServer(t, script)
	fake := &fakeToolCallback{results: map[int]json.RawMessage{0: json.RawMessage(`{}`)}}

	result, err := investigate(t.Context(), srv.Client(), srv.URL, "", "fake-model",
		"system prompt", "user prompt", fake.callback(), 2, time.Minute, toolAvailability{dryRun: false})
	if err != nil {
		t.Fatalf("investigate: %v", err)
	}
	if result.Status != "partial" {
		t.Fatalf("Status = %q, want partial", result.Status)
	}
	if result.ProposedPlan != nil {
		t.Errorf("ProposedPlan = %+v, want nil for a partial result", result.ProposedPlan)
	}
}

// TestParseProposedPlanPatchResourceLimits covers the last mile of the
// PatchResourceLimits action: without this wiring the whole action was
// unreachable — the plan schema, risk floor, gate rule, agent tool and
// admission policy all existed, and the model had no way to ask for any of it.
func TestParseProposedPlanPatchResourceLimits(t *testing.T) {
	raw := json.RawMessage(`{
	  "actionType": "PatchResourceLimits",
	  "targetGvk": "apps/v1/Deployment",
	  "targetNamespace": "apps",
	  "targetName": "cache-warmer",
	  "params": {"container": "worker", "memoryLimit": "256Mi", "memoryRequest": "128Mi"},
	  "reversible": true,
	  "riskLevel": "medium"
	}`)
	plan := parseProposedPlan(raw)
	if plan == nil {
		t.Fatal("expected a parsed plan")
	}
	if plan.ActionType != remediation.ActionPatchResourceLimits {
		t.Errorf("ActionType = %q", plan.ActionType)
	}
	params, ok := plan.Params.(remediation.PatchResourceLimitsParams)
	if !ok {
		t.Fatalf("Params is %T, want PatchResourceLimitsParams", plan.Params)
	}
	if params.Container != "worker" || params.MemoryLimit != "256Mi" || params.MemoryRequest != "128Mi" {
		t.Errorf("params round-tripped wrong: %+v", params)
	}
	// Quantities stay verbatim strings: normalising here would put a third
	// opinion about valid values beside the schema's and the agent's.
	if params.CPULimit != "" || params.CPURequest != "" {
		t.Errorf("omitted fields must stay empty, got cpuLimit=%q cpuRequest=%q", params.CPULimit, params.CPURequest)
	}
}

// TestSystemPromptOffersPatchResourceLimits guards against the action silently
// dropping out of the prompt again — the failure mode is invisible, because
// everything still compiles and the model simply never proposes it.
func TestSystemPromptOffersPatchResourceLimits(t *testing.T) {
	prompt := SystemPrompt(resolution.RouteInPlace, false, false, false)
	for _, want := range []string{
		"PatchResourceLimits",
		"only be RAISED", // the in-place-lowering refusal must reach the model
		"QoS class",      // and the do-not-introduce-a-new-limit rule
	} {
		if !strings.Contains(prompt, want) {
			t.Errorf("system prompt is missing %q", want)
		}
	}
}

// TestParseProposedPlanAnnotateLabelCreate is B142's regression test: without
// a case in parseProposedPlan's switch, Params stayed nil for all three of
// these action types regardless of what the model sent, and
// RemediationPlan.Validate rejected every one of them before their own
// type-specific checks (the (GVK, key) allowlist, CreateResource's
// ConfigMap-only GVK scope) ever ran — reproduced live 2026-09-06 re-running
// SCHED-054 (docs/VERIFICATION.md).
func TestParseProposedPlanAnnotateLabelCreate(t *testing.T) {
	for _, tc := range []struct {
		name       string
		actionType remediation.ActionType
		paramsJSON string
		want       remediation.ActionParams
	}{
		{
			name:       "AnnotateResource",
			actionType: remediation.ActionAnnotateResource,
			paramsJSON: `{"key": "argus.io/incident-id", "value": "inc_01example"}`,
			want:       remediation.AnnotateResourceParams{Key: "argus.io/incident-id", Value: "inc_01example"},
		},
		{
			name:       "LabelResource",
			actionType: remediation.ActionLabelResource,
			paramsJSON: `{"key": "argus.io/managed-by", "value": "argus"}`,
			want:       remediation.LabelResourceParams{Key: "argus.io/managed-by", Value: "argus"},
		},
		{
			name:       "CreateResource",
			actionType: remediation.ActionCreateResource,
			paramsJSON: `{"data": {"MODE": "ready"}}`,
			want:       remediation.CreateResourceParams{Data: map[string]string{"MODE": "ready"}},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := json.RawMessage(fmt.Sprintf(`{
			  "actionType": %q,
			  "targetGvk": "v1/ConfigMap",
			  "targetNamespace": "apps",
			  "targetName": "sidecar-config",
			  "params": %s,
			  "reversible": false,
			  "riskLevel": "medium"
			}`, tc.actionType, tc.paramsJSON))
			plan := parseProposedPlan(raw)
			if plan == nil {
				t.Fatal("expected a parsed plan")
			}
			if plan.ActionType != tc.actionType {
				t.Errorf("ActionType = %q, want %q", plan.ActionType, tc.actionType)
			}
			if plan.Params == nil {
				t.Fatalf("Params is nil — this is exactly B142: the plan will be rejected by RemediationPlan.Validate before %s's own type-specific checks ever run", tc.actionType)
			}
			if !reflect.DeepEqual(plan.Params, tc.want) {
				t.Errorf("Params = %#v, want %#v", plan.Params, tc.want)
			}
		})
	}
}

// TestParseProposedPlanRevertContainerImage covers the last mile of the
// RevertContainerImage action: without this wiring the whole action is
// unreachable — plan schema, risk floor, gate rule, agent tool and admission
// policy all exist, and the model has no way to ask for any of it.
func TestParseProposedPlanRevertContainerImage(t *testing.T) {
	raw := json.RawMessage(`{
	  "actionType": "RevertContainerImage",
	  "targetGvk": "apps/v1/Deployment",
	  "targetNamespace": "payments",
	  "targetName": "checkout-api",
	  "params": {"container": "api"},
	  "reversible": true,
	  "riskLevel": "medium"
	}`)
	plan := parseProposedPlan(raw)
	if plan == nil {
		t.Fatal("expected a parsed plan")
	}
	if plan.ActionType != remediation.ActionRevertContainerImage {
		t.Errorf("ActionType = %q", plan.ActionType)
	}
	params, ok := plan.Params.(remediation.RevertContainerImageParams)
	if !ok {
		t.Fatalf("Params is %T, want RevertContainerImageParams", plan.Params)
	}
	if params.Container != "api" {
		t.Errorf("params round-tripped wrong: %+v", params)
	}
}

// TestParseProposedPlanRevertContainerImageIgnoresAModelSuppliedImage is the
// wiring half of this action's central guarantee. A model that volunteers an
// image — the single most dangerous field it could volunteer, since an image is
// code — must have it dropped, not validated and not carried. The plan that
// comes out is exactly the plan the model was allowed to ask for: a container
// name.
func TestParseProposedPlanRevertContainerImageIgnoresAModelSuppliedImage(t *testing.T) {
	raw := json.RawMessage(`{
	  "actionType": "RevertContainerImage",
	  "targetGvk": "apps/v1/Deployment",
	  "targetNamespace": "payments",
	  "targetName": "checkout-api",
	  "params": {"container": "api", "image": "evil.example.com/backdoor:latest"},
	  "reversible": true,
	  "riskLevel": "medium"
	}`)
	plan := parseProposedPlan(raw)
	if plan == nil {
		t.Fatal("expected a parsed plan")
	}
	params, ok := plan.Params.(remediation.RevertContainerImageParams)
	if !ok {
		t.Fatalf("Params is %T, want RevertContainerImageParams", plan.Params)
	}
	if params.Container != "api" {
		t.Errorf("Container = %q, want %q", params.Container, "api")
	}
	// There is no field the image could have landed in, and this is the
	// assertion that says so — re-marshaling the params must not mention it.
	marshaled, err := json.Marshal(params)
	if err != nil {
		t.Fatalf("marshal params: %v", err)
	}
	if strings.Contains(string(marshaled), "evil.example.com") || strings.Contains(string(marshaled), "image") {
		t.Errorf("parsed params = %s, want the model-supplied image to have been dropped entirely", marshaled)
	}
}

// TestSystemPromptOffersRevertContainerImage guards against the action silently
// dropping out of the prompt — the failure mode is invisible, because
// everything still compiles and the model simply never proposes it. The three
// substrings beyond the action's name are the load-bearing instructions: that
// the model names only a container, that it never names an image, and the
// discriminator against PatchResourceLimits (the action whose symptoms overlap
// most).
func TestSystemPromptOffersRevertContainerImage(t *testing.T) {
	prompt := SystemPrompt(resolution.RouteInPlace, false, false, false)
	for _, want := range []string{
		"RevertContainerImage",
		`"params": {"container": "<name>"}`,
		"Never name an image",
		"bad release",
	} {
		if !strings.Contains(prompt, want) {
			t.Errorf("system prompt is missing %q", want)
		}
	}
}

// TestSystemPromptOffersDeleteResource is TestSystemPromptOffersRevertContainerImage's
// counterpart for BUGS.md 118 part (b): the prompt names DeleteResource on
// an in-place route, offers all three allowlisted kinds, and states the
// PersistentVolumeClaim-specific scoping (orphaned, unmounted) in prose —
// soft guidance, not the actual enforcement (see internal/agent/
// deleteresource.go and internal/execution for that), but
// still worth pinning so a future edit cannot silently drop it.
func TestSystemPromptOffersDeleteResource(t *testing.T) {
	prompt := SystemPrompt(resolution.RouteInPlace, false, false, false)
	for _, want := range []string{
		"DeleteResource",
		"v1/PersistentVolumeClaim",
		"batch/v1/Job",
		"genuinely orphaned",
		"managed_by: none",
		"no Pod anywhere still mounts it",
		"reversible to false",
	} {
		if !strings.Contains(prompt, want) {
			t.Errorf("system prompt is missing %q", want)
		}
	}
}

// TestSystemPromptOffersDeleteResourceOnPairedRouteToo pins that
// DeleteResource is offered on RoutePaired the same as every other in-place
// action type — resolution.PermittedActionTypes' own inPlace list is shared
// between RouteInPlace and RoutePaired, and this is the prompt-side
// confirmation that sharing actually reaches the text a model sees.
func TestSystemPromptOffersDeleteResourceOnPairedRouteToo(t *testing.T) {
	prompt := SystemPrompt(resolution.RoutePaired, false, false, false)
	if !strings.Contains(prompt, "DeleteResource") {
		t.Error("system prompt for RoutePaired is missing DeleteResource")
	}
}

// TestSystemPromptOffersDeleteResourceOnPullRequestRouteToo pins the
// deliberately different case: DeleteResource is ALSO offered on
// RoutePullRequest, unlike every one of its in-place siblings (ScaleDeployment
// etc., which resolution.PermittedActionTypes correctly keeps off this
// route). See that function's own doc comment for why — BUGS.md 118's
// orphaned PVC is never itself GitOps-tracked, so whatever route the
// INCIDENT resolves to (typically pullRequest, once part (a)'s
// related-workload fallback adopts the owning StatefulSet's ownership) says
// nothing about whether deleting the PVC beside it is safe; that question
// is re-verified independently, live, downstream. Without this, the
// fallback BUGS.md 118 part (b) exists to offer would be unreachable for
// the exact fixture shape the whole entry is about.
func TestSystemPromptOffersDeleteResourceOnPullRequestRouteToo(t *testing.T) {
	prompt := SystemPrompt(resolution.RoutePullRequest, false, false, false)
	if !strings.Contains(prompt, "DeleteResource") {
		t.Error("system prompt for RoutePullRequest is missing DeleteResource")
	}
	// And its in-place siblings must still be ABSENT on this route — this
	// test would pass for the wrong reason if actionBlocks' whole in-place
	// section leaked onto pullRequest.
	for _, sibling := range []string{"ScaleDeployment", "RestartPod", "RevertContainerImage", "AnnotateResource", "LabelResource", "CreateResource"} {
		if strings.Contains(prompt, sibling) {
			t.Errorf("system prompt for RoutePullRequest unexpectedly offers %q — only OpenPR and DeleteResource belong on this route", sibling)
		}
	}
}

// TestSystemPromptOffersAnnotateLabelCreateOnInPlaceRoutes is PROJECT.md
// B130/F9's own prompt-visibility half: a verb can be correctly gated in
// resolution.PermittedActionTypes and still never reach the model if
// toolloop.go's action-block builder has no case for it (exactly what
// "dormant" meant before this fix — the routing list already omitted them,
// but even adding them there would have done nothing without this half
// too). Checks the real rendered prompt text, not the route package alone.
func TestSystemPromptOffersAnnotateLabelCreateOnInPlaceRoutes(t *testing.T) {
	for _, route := range []resolution.Route{resolution.RouteInPlace, resolution.RoutePaired} {
		prompt := SystemPrompt(route, false, false, false)
		for _, verb := range []string{"AnnotateResource", "LabelResource", "CreateResource"} {
			if !strings.Contains(prompt, verb) {
				t.Errorf("system prompt for %s is missing %q", route, verb)
			}
		}
	}
}

// TestSystemPromptOffersOpenPRAsWholeFiles asserts the three properties that
// make offering OpenPR to a model both useful and safe, after the single-field
// grammar was removed on 2026-08-28.
//
// It replaces TestSystemPromptOffersOpenPRWithoutAFilePath, which pinned the
// opposite of two of them: that the model may not name a file, and that a plan
// changes exactly one field. Both were consequences of a mechanism that no
// longer exists — ARGUS could only edit one scalar in one plain-YAML file, so a
// model-supplied path was an invented fact with nothing to check it and a
// multi-field change was unexecutable. A repository change is now whole files,
// the model must name them (it cannot state a whole-file change otherwise), and
// what makes that safe is that every path is CHECKED — confined to the synced
// directory and refused against the denylist in internal/gitops, before
// anything is read or written.
func TestSystemPromptOffersOpenPRAsWholeFiles(t *testing.T) {
	prompt := SystemPrompt(resolution.RoutePullRequest, false, false, false)

	if !strings.Contains(prompt, `"actionType": "OpenPR"`) {
		t.Error("the prompt no longer offers OpenPR, so no analysis can propose a repository fix and the whole pull-request route is human-driven again")
	}

	// 1. The unit is a whole file, and the prompt must show the shape — a model
	//    that emits a fieldPath produces params that decode to nothing.
	for _, want := range []string{`"files"`, `"path"`, `"content"`, "COMPLETE new content"} {
		if !strings.Contains(prompt, want) {
			t.Errorf("the prompt does not describe the whole-file params shape (missing %q)", want)
		}
	}
	if strings.Contains(prompt, `"fieldPath"`) {
		t.Error("the prompt still shows a fieldPath key in the OpenPR params, which the wire shape no longer has — the model would be writing a field that silently does nothing")
	}

	// 2. Templated sources are IN SCOPE now. The old prompt told the model that
	//    anything containing {{ }} was refused outright, which is what confined
	//    the pull-request route to plain manifests.
	if !strings.Contains(prompt, "Helm chart template") {
		t.Error("the prompt does not tell the model it may edit a chart template, so it will keep declining the fixes this rewrite exists to enable")
	}

	// 3. Paths are checked, not trusted, and the prompt says so — a model that
	//    is not told will keep proposing paths that are refused for a reason it
	//    was never given.
	if !strings.Contains(prompt, "forbidden-path") {
		t.Error("the prompt does not tell the model that a forbidden path is refused outright")
	}
	if !strings.Contains(prompt, "Preserve everything you are not changing") {
		t.Error("the prompt does not tell the model to preserve the rest of the file, so it will produce reviewer-hostile diffs that rewrite whole files")
	}
}

// TestSystemPromptOffersOpenPRNewFileViaListing is B141's prompt-side
// regression test: the model must be told it CAN propose a genuinely new
// file (establishing absence with list_repo_files first), not the honest but
// incomplete "a new file cannot be proposed" wording this prompt carried
// while the underlying refusal was unfixed.
func TestSystemPromptOffersOpenPRNewFileViaListing(t *testing.T) {
	prompt := SystemPrompt(resolution.RoutePullRequest, false, false, false)

	if !strings.Contains(prompt, "list_repo_files") {
		t.Error("the prompt does not tell the model to establish a new file's absence with list_repo_files")
	}
	if !strings.Contains(prompt, "NEW file") {
		t.Error("the prompt does not describe the new-file case at all")
	}
	if strings.Contains(prompt, "so do not propose adding a brand-new file") {
		t.Error("the prompt still carries the pre-B141 wording telling the model a new file can never be proposed — that is no longer true")
	}
}

// TestSystemPromptPermitsLargeStructuralRewritesOnPullRequestRoute is
// BUGS.md 116's fix: on a cleanly pullRequest-routed incident with fully
// resolved ownership and a successful repository read, the model reached
// confidence 1.00, correctly named a Deployment->Job `kind` change as the
// fix in its rootCause prose — and never called OpenPR, landing on
// NeedsHumanInvestigation/plan: null instead. The SAME session proved the
// model isn't categorically unwilling to swap a `kind` (it did so
// unprompted for a 2-line RoleBinding->ClusterRoleBinding change); what it
// declined was a larger rewrite with real, un-obvious design choices. This
// pins that the prompt now explicitly permits exactly that larger case,
// naming the Deployment->Job field restructuring as its own example, and
// separately warns against the specific known-invalid trap this bug's own
// evidence caught live via kubectl apply --dry-run=server: a Deployment's
// restartPolicy only ever accepts "Always".
func TestSystemPromptPermitsLargeStructuralRewritesOnPullRequestRoute(t *testing.T) {
	prompt := SystemPrompt(resolution.RoutePullRequest, false, true, false)

	if !strings.Contains(prompt, "kind` change") {
		t.Error("the prompt does not explicitly permit a full kind change as an acceptable OpenPR")
	}
	if !strings.Contains(prompt, "completions") || !strings.Contains(prompt, "parallelism") {
		t.Error("the prompt does not name the Deployment->Job field restructuring (spec.completions/spec.parallelism) as a concrete example of a permitted large rewrite")
	}
	if !strings.Contains(prompt, "Do not withhold a plan merely because the rewrite is large") {
		t.Error("the prompt does not tell the model that rewrite size alone is not a reason to withhold a plan")
	}
	if !strings.Contains(prompt, "restartPolicy") || !strings.Contains(prompt, "Always") {
		t.Error("the prompt does not warn that a Deployment's restartPolicy only ever accepts Always")
	}
	if !strings.Contains(prompt, "OnFailure") {
		t.Error("the prompt does not name OnFailure as the specific invalid value the model previously suggested for a Deployment")
	}
}

// TestSystemPromptOffersFileDeletion is BACKLOG.md "still open" #2: AB1's
// finding named the correct fix for two overlapping HPAs as "delete one whole
// HPA manifest from the repo", and until this the model had no way to ask
// for that. The prompt must describe the "delete" field and must NOT tell
// the model that empty content means delete — that convention was
// deliberately rejected (see remediation.ProposedFile's doc comment) because
// empty content refusing outright is load-bearing elsewhere.
func TestSystemPromptOffersFileDeletion(t *testing.T) {
	prompt := SystemPrompt(resolution.RoutePullRequest, false, false, false)
	if !strings.Contains(prompt, `"delete": true`) {
		t.Error("the prompt does not describe how to propose deleting a file")
	}
	if !strings.Contains(prompt, "remove a file entirely") {
		t.Error("the prompt does not explain WHEN a delete is the right fix")
	}
	if !strings.Contains(prompt, "do not need to have read its whole content to delete it") {
		t.Error("the prompt does not tell the model a delete needs confirmed existence, not a full content read")
	}
}

// TestSystemPromptGuidesCrossNamespaceServiceSelectorCheck is BACKLOG.md
// "still open" #12 / AQ1: list_resources was never code-restricted to the
// incident's own namespace, but nothing told the model that naming a
// DIFFERENT, specific namespace was ever a reasonable move — so it never did,
// and confidently reported (CAPABILITIES.md's SVC-002 fixture) that a
// selector-matched workload "does not exist" anywhere, when it was running
// the whole time in a different namespace. This pins the fix: the prompt
// must name the failure shape (a Service whose selector matches nothing) and
// tell the model it may re-check a different, explicitly named namespace —
// while still ruling out an unbounded "search everywhere" reading.
func TestSystemPromptGuidesCrossNamespaceServiceSelectorCheck(t *testing.T) {
	prompt := SystemPrompt(resolution.RouteInPlace, false, false, false)
	if !strings.Contains(prompt, "list_resources again against any other specific, named namespace") {
		t.Error("the prompt does not tell the model it may re-check a different, explicitly named namespace for a Service selector match")
	}
	if !strings.Contains(prompt, "one namespace per call") {
		t.Error("the prompt does not say the cross-namespace check stays one named namespace per call")
	}
	if strings.Contains(prompt, "all namespaces at once") || strings.Contains(prompt, "search every namespace") {
		t.Error("the prompt must not describe an unbounded cross-namespace search")
	}
}

// TestSystemPromptTellsModelToReadPrecomputedRelativeTime is BACKLOG.md C9 /
// BUGS.md 105: a real, freshly-issued cert-manager Certificate whose
// status.renewalTime was ~41 minutes in the FUTURE got investigated and
// confidently (0.75) reported as having "passed over 30 minutes ago" — the
// model doing its own date arithmetic on two raw RFC3339 strings and getting
// the sign backwards. internal/agent/relative_time.go now precomputes a
// signed secondsUntil/secondsSince alongside any such field; this pins that
// the system prompt actually tells the model to read that number instead of
// re-deriving it, following the same "be concrete" pattern F21's
// suggestedNextSteps and C10's causal chain guidance already use elsewhere in
// this same function.
func TestSystemPromptTellsModelToReadPrecomputedRelativeTime(t *testing.T) {
	prompt := SystemPrompt(resolution.RouteInPlace, false, false, false)

	if !strings.Contains(prompt, "SecondsUntil") || !strings.Contains(prompt, "SecondsSince") {
		t.Fatalf("the prompt does not name the SecondsUntil/SecondsSince fields tool results may now carry")
	}
	if !strings.Contains(prompt, "renewalTime") {
		t.Error("the prompt does not name renewalTime as an example of a field this covers")
	}
	if !strings.Contains(prompt, "read it directly rather than comparing the raw timestamp") {
		t.Error("the prompt does not instruct the model to read the precomputed value instead of doing its own comparison")
	}
	if !strings.Contains(prompt, "Do not do your own date arithmetic on two ISO-8601 strings") {
		t.Error("the prompt does not explicitly tell the model not to do its own date arithmetic when a precomputed field is present")
	}
	// The concrete failure mode this guidance exists to prevent, stated in the
	// prompt itself so the model has a negative example, not just an abstract
	// rule — matching this codebase's existing "be concrete" prompt style.
	if !strings.Contains(prompt, "41 minutes in the future") || !strings.Contains(prompt, "passed over 30 minutes ago") {
		t.Error("the prompt does not cite the concrete BUGS.md 105 failure mode as a negative example")
	}
}

// TestSystemPromptRepoToolGuidanceMatchesWhatTheModelCanDo pins the one
// conditional sentence in the OpenPR block. An investigation WITH the
// repository tools is told to read every file it proposes; one without is told
// to propose nothing it cannot already account for — because a whole-file
// proposal built on a guess silently discards everything else the file holds,
// which is a far worse failure than the single-field grammar could produce.
func TestSystemPromptRepoToolGuidanceMatchesWhatTheModelCanDo(t *testing.T) {
	withRepo := SystemPrompt(resolution.RoutePullRequest, false, true, false)
	if !strings.Contains(withRepo, "read_repo_file") {
		t.Error("an investigation with repository tools is not told to read the files it proposes to change")
	}

	withoutRepo := SystemPrompt(resolution.RoutePullRequest, false, false, false)
	if strings.Contains(withoutRepo, "Read every file you propose to change first") {
		t.Error("an investigation with NO repository tools is told to use a tool it does not have")
	}
	if !strings.Contains(withoutRepo, "no tool for reading this repository") {
		t.Error("an investigation with no repository tools is not warned against proposing content it has not seen")
	}
}

// TestSystemPromptGuidanceRouteAsksForConcreteSteps is BACKLOG.md F22 piece 5:
// the no-repo route used to ask the model for suggestedNextSteps as general
// "manual steps" prose. That produced usable-sounding paragraphs an operator
// still had to translate into an actual command themselves. This pins that the
// guidance-route prompt now names kubectl explicitly, tells the model to fill
// in the real object/namespace rather than a placeholder, names the
// field-path-and-value alternative for a non-command fix, and asks for one
// entry per affected resource.
//
// UPDATED 2026-08-30. This test used to assert the opposite of its second half:
// that the concrete-step rules must NOT appear on a route with an action
// available, "where suggestedNextSteps is never asked for at all". That was the
// contract, and it left a real hole — "a channel exists" and "the model can
// express this fix as a plan" are different claims. ARGUS's action types set ONE
// field, so on a pullRequest route a fix that removes a list entry yields no
// plan, and, never having been asked, no steps either: a confident root cause
// and nothing to act on. Observed on a live incident (missing imagePullSecret,
// GitOps-managed Deployment).
//
// So the steps are now asked for on EVERY route, with the same rules, and this
// test pins that — plus the one thing that must still not leak: guidance's
// "no in-cluster action is available" framing, which is false on a route that
// has one.
func TestSystemPromptAsksEveryRouteForConcreteSteps(t *testing.T) {
	for _, route := range []resolution.Route{
		resolution.RouteGuidance,
		resolution.RoutePullRequest,
		resolution.RouteInPlace,
		resolution.RoutePaired,
	} {
		prompt := SystemPrompt(route, false, false, false)

		if !strings.Contains(prompt, "suggestedNextSteps") {
			t.Errorf("route %v's prompt never asks for suggestedNextSteps", route)
		}
		if !strings.Contains(prompt, "kubectl") {
			t.Errorf("route %v's prompt does not mention kubectl as the shape a command step should take", route)
		}
		if !strings.Contains(prompt, "placeholder") {
			t.Errorf("route %v's prompt does not warn against leaving a placeholder like <namespace> or <name> in a step", route)
		}
		if !strings.Contains(prompt, "field path") {
			t.Errorf("route %v's prompt does not name the field-path-and-value alternative for a non-command fix", route)
		}
		if !strings.Contains(prompt, "One entry per affected resource") {
			t.Errorf("route %v's prompt does not ask for one suggestedNextSteps entry per affected resource", route)
		}

		// The SCHEMA has to name it too. A field the prose requires but the
		// answer shape never shows is one a model routinely omits, which is how
		// this would silently regress to null again.
		if !strings.Contains(schemaTailForRoute(route, false), "suggestedNextSteps") {
			t.Errorf("route %v's schema tail does not name suggestedNextSteps, so the model has no slot to put it in", route)
		}
	}

	// Guidance's own framing is route-specific and must not leak: telling the
	// model no in-cluster action exists, on a route where one does, would make
	// it suppress the plan it is being asked for in the same prompt.
	for _, route := range []resolution.Route{resolution.RoutePullRequest, resolution.RouteInPlace, resolution.RoutePaired} {
		other := SystemPrompt(route, false, false, false)
		if strings.Contains(other, "No in-cluster action is available") {
			t.Errorf("route %v's prompt leaked guidance's no-action-available framing", route)
		}
		if strings.Contains(other, "there is nothing to propose") {
			t.Errorf("route %v's prompt tells the model there is nothing to propose", route)
		}
	}
}

// TestSystemPromptRequiresARunnableCommandWhenNoPlanIsProposed is BACKLOG.md
// F27's own strengthening of the guidance TestSystemPromptAsksEveryRouteForConcreteSteps
// above already pins: asking for suggestedNextSteps at all (F21) is
// necessary but not sufficient — F27 measured that only 20 of 163 existing
// entries carried a real command, the rest being field-path or prose advice
// with nothing an operator could copy and run.
//
// A live incident later showed the opposite failure mode this rule must
// also guard against: a guidance-route analysis with a correct, fully
// reasoned conclusion but an EMPTY suggestedNextSteps, because an earlier
// version of this rule forbade prose outright and gave the model no path to
// state a conclusion ("already fixed by a replacement object", "create a
// Secret with this name") that genuinely cannot be expressed as a command.
// So the rule now prefers a command whenever one fits, allows concrete
// prose when it does not, and forbids only the one thing that actually
// leaves an operator stuck: an empty list. This pins that balance on every
// route (guidance never has a plan at all; the other three may or may not),
// so it cannot silently regress to either extreme.
func TestSystemPromptRequiresARunnableCommandWhenNoPlanIsProposed(t *testing.T) {
	for _, route := range []resolution.Route{
		resolution.RouteGuidance,
		resolution.RoutePullRequest,
		resolution.RouteInPlace,
		resolution.RoutePaired,
	} {
		prompt := SystemPrompt(route, false, false, false)
		if !strings.Contains(prompt, "a real, directly runnable command whenever the fix can genuinely be expressed as one") {
			t.Errorf("route %v's prompt does not prefer a real, directly runnable command when no plan is proposed", route)
		}
		if !strings.Contains(prompt, "not only the field-path variant") {
			t.Errorf("route %v's prompt does not say a field-path-only entry is insufficient for the null-plan case", route)
		}
		if !strings.Contains(prompt, "An empty suggestedNextSteps is only ever correct when there is truly nothing left to tell the operator") {
			t.Errorf("route %v's prompt does not forbid an empty suggestedNextSteps as a way to dodge the command/prose requirement", route)
		}
	}
}

// TestSystemPromptGivesWorkedExamplesForAnnotateLabelAndCreateCommands is
// BUGS.md 130's guidance-defect fix, on its own merits regardless of the F9
// wiring decision it precedes. A live measurement against this dev stack's
// real analyses found only 3 of 21 "complete" suggestedNextSteps carried a
// real command at all, and the prompt's runnable-command bullet (stepRules)
// carried exactly one worked example — scale — for the model to copy the
// SHAPE of; annotate/label/create had no worked syntax at all, only the
// abstract instruction to "write the EXACT kubectl command". Following
// BUGS.md 116's precedent for this exact failure class (a model not
// reliably following an abstract instruction is fixed by a concrete worked
// example, not by rewording the instruction again), this pins that the
// prompt now shows the model the exact command SYNTAX for the three F9-
// adjacent shapes — kubectl annotate KEY=VALUE, kubectl label KEY=VALUE,
// kubectl create configmap --from-literal=KEY=VALUE — on every route, the
// same way the scale example always has been.
func TestSystemPromptGivesWorkedExamplesForAnnotateLabelAndCreateCommands(t *testing.T) {
	for _, route := range []resolution.Route{
		resolution.RouteGuidance,
		resolution.RoutePullRequest,
		resolution.RouteInPlace,
		resolution.RoutePaired,
	} {
		prompt := SystemPrompt(route, false, false, false)

		if !strings.Contains(prompt, "kubectl -n payments-prod annotate") {
			t.Errorf("route %v's prompt does not give a worked kubectl annotate example", route)
		}
		if !strings.Contains(prompt, "argus.io/reviewed=true") {
			t.Errorf("route %v's annotate example is not a filled-in KEY=VALUE pair", route)
		}
		if !strings.Contains(prompt, "kubectl -n payments-prod label") {
			t.Errorf("route %v's prompt does not give a worked kubectl label example", route)
		}
		if !strings.Contains(prompt, "tier=frontend") {
			t.Errorf("route %v's label example is not a filled-in KEY=VALUE pair", route)
		}
		if !strings.Contains(prompt, "kubectl -n payments-prod create configmap") {
			t.Errorf("route %v's prompt does not give a worked kubectl create configmap example", route)
		}
		if !strings.Contains(prompt, "--from-literal=") {
			t.Errorf("route %v's create configmap example does not show the --from-literal=KEY=VALUE flag shape", route)
		}
		// The worked examples must not collapse into a single generic
		// instruction — each must be presented as its own distinct shape,
		// or a model skimming the prompt could still default to only ever
		// producing the scale example it sees first.
		if !strings.Contains(prompt, "do not default to a scale/restart example when the real fix is one of the others") {
			t.Errorf("route %v's prompt does not warn against defaulting to the scale example for a different fix shape", route)
		}
	}
}

// TestInvestigateRefusesToolsItNeverOffered is the api backend's equivalent of
// internal/mcp's grant allowlist, and it exists because a security review found
// the check missing here.
//
// The tool NAME arrives inside the model's response, and until this check
// existed it was forwarded to the agent verbatim — whose Execute switch also
// contains the four remediation tools. Not exploitable (those verify an HMAC the
// model has no key for), but the isolation rested entirely on that signature
// while the agent chart's own comment stated the property as "the tool loop
// never advertises the execution tools". Non-advertisement is not enforcement,
// and a tool name the model chose is a scope claim by the model.
// TestInvestigateAssignsEvidenceIDToEachDispatchedToolCall is BACKLOG.md B2's
// coverage of the new field: every tool call that actually reached callTool
// — whether it succeeded or came back an error — gets its own, distinct,
// domain.PrefixEvidence-shaped id, which internal/api.persistEvidence turns
// into an `evidence` row. Two calls in the SAME turn (rather than two
// separate turns) is deliberate: it is the case most likely to break if a
// future edit hoisted the id generation out of the per-call loop.
func TestInvestigateAssignsEvidenceIDToEachDispatchedToolCall(t *testing.T) {
	script := []scriptedTurn{
		{
			Content: "HYPOTHESIS: check events and logs",
			ToolCalls: []toolCall{
				tc(t, "call_1", "get_events", map[string]string{"namespace": "default"}),
				tc(t, "call_2", "get_logs", map[string]string{"namespace": "default", "pod": "ghost"}),
			},
		},
		{Content: `{"rootCause": {"statement": "found it"}, "confidence": 0.9, "ruledOut": []}`},
	}
	srv, _ := newFakeLLMServer(t, script)
	fake := &fakeToolCallback{errs: map[int]error{1: errors.New("pod not found")}}

	result, err := investigate(t.Context(), srv.Client(), srv.URL, "", "fake-model",
		"system", "user", fake.callback(), 8, time.Minute, toolAvailability{dryRun: false})
	if err != nil {
		t.Fatalf("investigate: %v", err)
	}
	if len(result.CausalChain) != 1 || len(result.CausalChain[0].ToolCalls) != 2 {
		t.Fatalf("CausalChain = %+v, want one step with two tool calls", result.CausalChain)
	}

	recs := result.CausalChain[0].ToolCalls
	if recs[0].EvidenceID == "" {
		t.Error("successful tool call got no EvidenceID")
	}
	if recs[1].EvidenceID == "" {
		t.Error("failed (but dispatched) tool call got no EvidenceID — a tool error is still evidence gathered, matching RecordFunc's own 'a call that failed was still a question asked'")
	}
	if recs[0].EvidenceID != "" && recs[0].EvidenceID == recs[1].EvidenceID {
		t.Errorf("both tool calls got the SAME EvidenceID %q — each dispatched call needs its own row", recs[0].EvidenceID)
	}
	for _, rec := range recs {
		if rec.EvidenceID != "" && !strings.HasPrefix(rec.EvidenceID, "ev_") {
			t.Errorf("EvidenceID = %q, want the domain.PrefixEvidence (%q) convention", rec.EvidenceID, "ev_")
		}
	}
}

// TestInvestigateAssignsNoEvidenceIDToARefusedTool pins the other half of
// EvidenceID's contract: a tool call refused by isOfferedTool BEFORE it ever
// reaches callTool must not get one, because nothing was actually dispatched
// to a cluster — there is nothing for persistEvidence to write a row about,
// and generating an id anyway would make an authorization refusal look like
// gathered evidence.
func TestInvestigateAssignsNoEvidenceIDToARefusedTool(t *testing.T) {
	script := []scriptedTurn{
		{
			Content:   "HYPOTHESIS: try to scale it",
			ToolCalls: []toolCall{tc(t, "call_1", "scale_deployment", map[string]string{"name": "x"})},
		},
		{Content: `{"rootCause": {"statement": "could not act, no write tools available"}, "confidence": 0.2, "ruledOut": []}`},
	}
	srv, _ := newFakeLLMServer(t, script)
	fake := &fakeToolCallback{}

	result, err := investigate(t.Context(), srv.Client(), srv.URL, "", "fake-model",
		"system", "user", fake.callback(), 8, time.Minute, toolAvailability{dryRun: false})
	if err != nil {
		t.Fatalf("investigate: %v", err)
	}
	if len(fake.calls) != 0 {
		t.Fatalf("callTool was invoked %d times, want 0 — a refused tool must never reach it", len(fake.calls))
	}
	if len(result.CausalChain) != 1 || len(result.CausalChain[0].ToolCalls) != 1 {
		t.Fatalf("CausalChain = %+v, want one step with one (refused) tool call recorded", result.CausalChain)
	}
	if rec := result.CausalChain[0].ToolCalls[0]; rec.EvidenceID != "" {
		t.Errorf("EvidenceID = %q for a refused tool call, want empty — nothing was dispatched, so there is nothing to persist an evidence row for", rec.EvidenceID)
	}
}

func TestInvestigateRefusesToolsItNeverOffered(t *testing.T) {
	for _, name := range []string{
		// The five that actually mutate a customer cluster (real writes, no
		// dry-run restriction — must never be offered regardless of
		// dryRunAvailable).
		"scale_deployment", "restart_pod", "patch_resource_limits", "revert_container_image", "patch_field",
		// And anything else invented out of thin air.
		"delete_everything", "exec", "",
	} {
		if isOfferedTool(name, toolAvailability{dryRun: false}) {
			t.Errorf("isOfferedTool(%q, toolAvailability{dryRun: false}) = true — the investigation loop must never dispatch it", name)
		}
		if isOfferedTool(name, toolAvailability{dryRun: true}) {
			t.Errorf("isOfferedTool(%q, toolAvailability{dryRun: true}) = true — dryRunAvailable must never widen the surface to a real, unrestricted-write tool", name)
		}
	}

	// Every read-only tool the loop advertises must remain callable
	// regardless of dryRunAvailable, or the check silently breaks
	// investigation instead of securing it.
	for _, def := range toolDefinitions {
		if !isOfferedTool(def.Function.Name, toolAvailability{dryRun: false}) {
			t.Errorf("isOfferedTool(%q, toolAvailability{dryRun: false}) = false for a tool this loop always offers", def.Function.Name)
		}
		if !isOfferedTool(def.Function.Name, toolAvailability{dryRun: true}) {
			t.Errorf("isOfferedTool(%q, toolAvailability{dryRun: true}) = false for a tool this loop always offers", def.Function.Name)
		}
	}
	if len(toolDefinitions) == 0 {
		t.Fatal("no tools offered at all — isOfferedTool would vacuously refuse everything")
	}
}

// TestDryRunPatchOfferedOnlyWhenAvailable is BACKLOG.md C4's gating
// contract, checked at exactly the boundary isOfferedTool/
// offeredToolDefinitions enforce: dry_run_patch is callable if and only if
// this investigation's dryRunAvailable is true, never as a side effect of
// anything else.
func TestDryRunPatchOfferedOnlyWhenAvailable(t *testing.T) {
	if isOfferedTool("dry_run_patch", toolAvailability{dryRun: false}) {
		t.Error("isOfferedTool(\"dry_run_patch\", toolAvailability{dryRun: false}) = true — must not be callable on a cluster that never reported the argus-dryrun grant")
	}
	if !isOfferedTool("dry_run_patch", toolAvailability{dryRun: true}) {
		t.Error("isOfferedTool(\"dry_run_patch\", toolAvailability{dryRun: true}) = false — must be callable once the cluster reported the grant")
	}

	withoutDryRun := offeredToolDefinitions(toolAvailability{dryRun: false})
	for _, def := range withoutDryRun {
		if def.Function.Name == "dry_run_patch" {
			t.Error("offeredToolDefinitions(toolAvailability{dryRun: false}) advertises dry_run_patch — a cluster without the grant must never even be told the tool exists")
		}
	}
	if len(withoutDryRun) != len(toolDefinitions) {
		t.Errorf("offeredToolDefinitions(toolAvailability{dryRun: false}) returned %d tools, want exactly the fixed %d read-only tools", len(withoutDryRun), len(toolDefinitions))
	}

	withDryRun := offeredToolDefinitions(toolAvailability{dryRun: true})
	if len(withDryRun) != len(toolDefinitions)+1 {
		t.Errorf("offeredToolDefinitions(toolAvailability{dryRun: true}) returned %d tools, want %d (the fixed six plus dry_run_patch)", len(withDryRun), len(toolDefinitions)+1)
	}
	found := false
	for _, def := range withDryRun {
		if def.Function.Name == "dry_run_patch" {
			found = true
		}
	}
	if !found {
		t.Error("offeredToolDefinitions(toolAvailability{dryRun: true}) does not include dry_run_patch")
	}
}

// TestQueryMetricsOfferedOnlyWhenAvailable is BACKLOG.md C4's other gating
// contract, the exact mirror of TestDryRunPatchOfferedOnlyWhenAvailable
// above: query_metrics is callable if and only if this investigation's
// metricsAvailable is true, never as a side effect of anything else
// (dryRun in particular — the two are independent gates, per
// toolAvailability's own doc comment).
func TestQueryMetricsOfferedOnlyWhenAvailable(t *testing.T) {
	if isOfferedTool("query_metrics", toolAvailability{metrics: false}) {
		t.Error("isOfferedTool(\"query_metrics\", toolAvailability{metrics: false}) = true — must not be callable on a cluster that never reported the metrics grant")
	}
	if !isOfferedTool("query_metrics", toolAvailability{metrics: true}) {
		t.Error("isOfferedTool(\"query_metrics\", toolAvailability{metrics: true}) = false — must be callable once the cluster reported the grant")
	}
	// dryRun must not accidentally widen or narrow query_metrics' own gate.
	if isOfferedTool("query_metrics", toolAvailability{dryRun: true, metrics: false}) {
		t.Error("isOfferedTool(\"query_metrics\", toolAvailability{dryRun: true, metrics: false}) = true — dryRunAvailable must never widen query_metrics' own, independent gate")
	}

	withoutMetrics := offeredToolDefinitions(toolAvailability{metrics: false})
	for _, def := range withoutMetrics {
		if def.Function.Name == "query_metrics" {
			t.Error("offeredToolDefinitions(toolAvailability{metrics: false}) advertises query_metrics — a cluster without the grant must never even be told the tool exists")
		}
	}
	if len(withoutMetrics) != len(toolDefinitions) {
		t.Errorf("offeredToolDefinitions(toolAvailability{metrics: false}) returned %d tools, want exactly the fixed %d read-only tools", len(withoutMetrics), len(toolDefinitions))
	}

	withMetrics := offeredToolDefinitions(toolAvailability{metrics: true})
	if len(withMetrics) != len(toolDefinitions)+1 {
		t.Errorf("offeredToolDefinitions(toolAvailability{metrics: true}) returned %d tools, want %d (the fixed tools plus query_metrics)", len(withMetrics), len(toolDefinitions)+1)
	}
	foundMetrics := false
	for _, def := range withMetrics {
		if def.Function.Name == "query_metrics" {
			foundMetrics = true
		}
	}
	if !foundMetrics {
		t.Error("offeredToolDefinitions(toolAvailability{metrics: true}) does not include query_metrics")
	}

	// The two gates must be independent: both on offers both extra tools.
	withBoth := offeredToolDefinitions(toolAvailability{dryRun: true, metrics: true})
	if len(withBoth) != len(toolDefinitions)+2 {
		t.Errorf("offeredToolDefinitions(toolAvailability{dryRun: true, metrics: true}) returned %d tools, want %d (the fixed tools plus dry_run_patch plus query_metrics)", len(withBoth), len(toolDefinitions)+2)
	}
}

// TestOfferedToolsAreAllReadOnly pins the property the allowlist protects: the
// offered surface must contain nothing that writes. If a future action is added
// to toolDefinitions by mistake, the allowlist above would faithfully permit it.
func TestOfferedToolsAreAllReadOnly(t *testing.T) {
	for _, def := range toolDefinitions {
		for _, verb := range []string{"scale_", "restart_", "patch_", "revert_", "delete_", "create_", "apply_"} {
			if strings.HasPrefix(def.Function.Name, verb) {
				t.Errorf("tool %q is offered to the model but its name says it mutates — the investigation surface must stay read-only", def.Function.Name)
			}
		}
	}
}

// --- BACKLOG.md C10: the api backend's own causal chain is hub-observed ---

// TestInvestigateStampsHubObservedProvenance pins that every Investigation the
// api backend's own loop returns — complete, partial (a bound hit), and
// partial (a malformed final answer) — is stamped
// CausalChainProvenanceHubObserved, never left blank and never
// CausalChainProvenanceSelfReported. This is what lets the UI tell this
// backend's real, turn-by-turn-observed chain apart from the cli backend's
// self-reported one without inspecting anything else about the result.
func TestInvestigateStampsHubObservedProvenance(t *testing.T) {
	t.Run("complete", func(t *testing.T) {
		script := []scriptedTurn{
			{Content: `{"rootCause": {"statement": "x"}, "confidence": 0.5, "ruledOut": []}`},
		}
		srv, _ := newFakeLLMServer(t, script)
		fake := &fakeToolCallback{results: map[int]json.RawMessage{}}
		result, err := investigate(t.Context(), srv.Client(), srv.URL, "", "fake-model",
			"system prompt", "user prompt", fake.callback(), 8, time.Minute, toolAvailability{})
		if err != nil {
			t.Fatalf("investigate: %v", err)
		}
		if result.CausalChainProvenance != CausalChainProvenanceHubObserved {
			t.Errorf("CausalChainProvenance = %q, want %q", result.CausalChainProvenance, CausalChainProvenanceHubObserved)
		}
	})

	t.Run("partial iteration limit", func(t *testing.T) {
		script := []scriptedTurn{
			{Content: "HYPOTHESIS: probe", ToolCalls: []toolCall{tc(t, "call_1", "get_events", map[string]string{"namespace": "default"})}},
		}
		srv, _ := newFakeLLMServer(t, script)
		fake := &fakeToolCallback{results: map[int]json.RawMessage{}}
		result, err := investigate(t.Context(), srv.Client(), srv.URL, "", "fake-model",
			"system prompt", "user prompt", fake.callback(), 1, time.Minute, toolAvailability{})
		if err != nil {
			t.Fatalf("investigate: %v", err)
		}
		if result.Status != "partial" {
			t.Fatalf("Status = %q, want partial", result.Status)
		}
		if result.CausalChainProvenance != CausalChainProvenanceHubObserved {
			t.Errorf("CausalChainProvenance = %q, want %q", result.CausalChainProvenance, CausalChainProvenanceHubObserved)
		}
	})

	t.Run("malformed final answer", func(t *testing.T) {
		script := []scriptedTurn{
			{Content: "not JSON at all"},
		}
		srv, _ := newFakeLLMServer(t, script)
		fake := &fakeToolCallback{results: map[int]json.RawMessage{}}
		result, err := investigate(t.Context(), srv.Client(), srv.URL, "", "fake-model",
			"system prompt", "user prompt", fake.callback(), 8, time.Minute, toolAvailability{})
		if err != nil {
			t.Fatalf("investigate: %v", err)
		}
		if result.PartialReason != "malformed_final_answer" {
			t.Fatalf("PartialReason = %q, want malformed_final_answer", result.PartialReason)
		}
		if result.CausalChainProvenance != CausalChainProvenanceHubObserved {
			t.Errorf("CausalChainProvenance = %q, want %q", result.CausalChainProvenance, CausalChainProvenanceHubObserved)
		}
	})
}

// TestFinalAnalysisWireCausalChainRoundTrips pins BACKLOG.md C10's widened
// wire contract: a causalChain array in the model's final-answer JSON
// survives parseFinalAnalysis into finalAnalysis.CausalChain, entry for
// entry, hypothesis/toolCalls/finding all intact. This is the "marshal/
// unmarshal round-trips" test the task asks for — the api backend never asks
// a model for this key (see causalChainStepWire's own doc comment), but
// parseFinalAnalysis is shared code, and the cli backend's honesty depends on
// this parse being complete and not silently dropping an entry.
func TestFinalAnalysisWireCausalChainRoundTrips(t *testing.T) {
	wire := finalAnalysisWire{
		RootCause: struct {
			Statement string `json:"statement"`
			IsFault   *bool  `json:"isFault,omitempty"`
		}{Statement: "checkout-worker OOMKilled under load"},
		Confidence: 0.9,
		CausalChain: []causalChainStepWire{
			{
				Hypothesis: "container is exceeding its memory limit",
				ToolCalls:  []string{"get_events", "describe_resource"},
				Finding:    "OOMKilled 4 times in 25 minutes",
			},
			{
				Hypothesis: "a competing process is not the cause",
				ToolCalls:  []string{"get_logs"},
				Finding:    "no other process visible in the container",
			},
		},
	}
	raw, err := json.Marshal(wire)
	if err != nil {
		t.Fatalf("marshal finalAnalysisWire: %v", err)
	}

	final, err := parseFinalAnalysis(string(raw))
	if err != nil {
		t.Fatalf("parseFinalAnalysis: %v", err)
	}
	if len(final.CausalChain) != 2 {
		t.Fatalf("CausalChain has %d entries, want 2 (raw: %s)", len(final.CausalChain), raw)
	}
	if final.CausalChain[0].Hypothesis != "container is exceeding its memory limit" {
		t.Errorf("step 0 Hypothesis = %q", final.CausalChain[0].Hypothesis)
	}
	if len(final.CausalChain[0].ToolCalls) != 2 || final.CausalChain[0].ToolCalls[0] != "get_events" || final.CausalChain[0].ToolCalls[1] != "describe_resource" {
		t.Errorf("step 0 ToolCalls = %v, want [get_events describe_resource]", final.CausalChain[0].ToolCalls)
	}
	if final.CausalChain[0].Finding != "OOMKilled 4 times in 25 minutes" {
		t.Errorf("step 0 Finding = %q", final.CausalChain[0].Finding)
	}
	if final.CausalChain[1].Hypothesis != "a competing process is not the cause" {
		t.Errorf("step 1 Hypothesis = %q", final.CausalChain[1].Hypothesis)
	}
}

// TestParseFinalAnalysis_IsFault pins BUGS.md 136's wire contract:
// rootCause.isFault survives parseFinalAnalysis intact in all three states
// (explicit true, explicit false, and absent), since orchestrator.Advance's
// suppression logic depends on telling "the model said false" apart from
// "the model was never asked."
func TestParseFinalAnalysis_IsFault(t *testing.T) {
	t.Run("explicit false", func(t *testing.T) {
		final, err := parseFinalAnalysis(`{"rootCause": {"statement": "completed Job pod, working as intended", "isFault": false}, "confidence": 0.95, "ruledOut": []}`)
		if err != nil {
			t.Fatalf("parseFinalAnalysis: %v", err)
		}
		if final.RootCause.IsFault == nil || *final.RootCause.IsFault != false {
			t.Fatalf("IsFault = %v, want a non-nil false", final.RootCause.IsFault)
		}
	})
	t.Run("explicit true", func(t *testing.T) {
		final, err := parseFinalAnalysis(`{"rootCause": {"statement": "OOMKilled", "isFault": true}, "confidence": 0.9, "ruledOut": []}`)
		if err != nil {
			t.Fatalf("parseFinalAnalysis: %v", err)
		}
		if final.RootCause.IsFault == nil || *final.RootCause.IsFault != true {
			t.Fatalf("IsFault = %v, want a non-nil true", final.RootCause.IsFault)
		}
	})
	t.Run("absent — never asked, must not default to false", func(t *testing.T) {
		final, err := parseFinalAnalysis(`{"rootCause": {"statement": "OOMKilled"}, "confidence": 0.9, "ruledOut": []}`)
		if err != nil {
			t.Fatalf("parseFinalAnalysis: %v", err)
		}
		if final.RootCause.IsFault != nil {
			t.Fatalf("IsFault = %v, want nil when the key was never in the wire JSON", *final.RootCause.IsFault)
		}
	})
}
