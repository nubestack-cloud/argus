package llm

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"argus/internal/resolution"
)

// prompt_prefix_test.go is PROJECT.md E18's real deliverable: the assertion
// that the investigation loop's request prefix does not vary between turns.
//
// A cache breakpoint placed on a prefix that changes every turn buys nothing
// AND hides that it bought nothing — the request looks cache-aware and the
// hit rate is zero. So the invariant is tested on the WIRE BYTES, not on the
// Go values that produce them: what a provider's cache matches on is the
// bytes, and a marshaling change (a field reordered, a content shape altered,
// a map iterated) that left the values equal but the bytes different would be
// invisible to a value-level assertion and fatal to the caching.

// --- helpers: a fake server that keeps the raw request bodies ---

// rawBodies is a concurrency-safe log of the exact bytes of every request
// body the fake server received, in arrival order. Deliberately not decoded:
// decoding and re-encoding would normalize away precisely the differences
// these tests exist to catch.
type rawBodies struct {
	mu  sync.Mutex
	all [][]byte
}

func (r *rawBodies) add(b []byte) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.all = append(r.all, b)
}

func (r *rawBodies) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.all)
}

func (r *rawBodies) at(i int) []byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.all[i]
}

// rawRequest is the wire request parsed only as far as it has to be: every
// field that must not vary is kept as the raw bytes it arrived as.
type rawRequest struct {
	Model      json.RawMessage   `json:"model"`
	Tools      json.RawMessage   `json:"tools"`
	ToolChoice json.RawMessage   `json:"tool_choice"`
	Messages   []json.RawMessage `json:"messages"`
}

func parseRaw(t *testing.T, body []byte) rawRequest {
	t.Helper()
	var out rawRequest
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("parse captured request body: %v\nbody: %s", err, body)
	}
	return out
}

// newRawCapturingLLMServer is newFakeLLMServer's sibling: same scripted-turn
// contract, but it records raw bodies rather than decoded loopChatRequests,
// and it lets a test control the cached_tokens it reports per request through
// cachedTokensFor (nil means "report none").
//
// It exists rather than extending newFakeLLMServer because that server
// decodes into loopChatRequest, whose Content is a *string — a request
// carrying cache_control content parts would fail to decode there, and the
// point of these tests is to look at what is actually sent.
func newRawCapturingLLMServer(t *testing.T, script []scriptedTurn, cachedTokensFor func(body []byte) int) (*httptest.Server, *rawBodies) {
	t.Helper()
	bodies := &rawBodies{}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("fake LLM server: read body: %v", err)
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		bodies.add(body)

		idx := bodies.count() - 1
		if idx >= len(script) {
			idx = len(script) - 1
		}
		turn := script[idx]

		usage := map[string]any{"prompt_tokens": 100, "completion_tokens": 10}
		if cachedTokensFor != nil {
			usage["prompt_tokens_details"] = map[string]any{"cached_tokens": cachedTokensFor(body)}
		}
		resp := map[string]any{
			"model": "fake-model",
			"choices": []any{map[string]any{
				"message":       map[string]any{"role": "assistant", "content": turn.Content, "tool_calls": turn.ToolCalls},
				"finish_reason": "stop",
			}},
			"usage": usage,
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	t.Cleanup(srv.Close)
	return srv, bodies
}

// threeToolCallScript is a scripted investigation that makes the loop take
// four round trips: three tool-calling turns and a concluding one. Four is
// the point — one turn proves nothing about a prefix that varies BETWEEN
// turns.
func threeToolCallScript(t *testing.T) []scriptedTurn {
	t.Helper()
	return []scriptedTurn{
		{
			Content:   "HYPOTHESIS: check recent events",
			ToolCalls: []toolCall{tc(t, "call_1", "get_events", map[string]string{"namespace": "default", "involvedObjectName": "web-0"})},
		},
		{
			Content:   "FINDING: nothing in events\nHYPOTHESIS: read the logs",
			ToolCalls: []toolCall{tc(t, "call_2", "get_logs", map[string]string{"namespace": "default", "pod": "web-0"})},
		},
		{
			Content:   "FINDING: OOMKilled in the log tail\nHYPOTHESIS: confirm the owning workload's limits",
			ToolCalls: []toolCall{tc(t, "call_3", "describe_resource", map[string]string{"gvk": "apps/v1/Deployment", "namespace": "default", "name": "web"})},
		},
		{
			Content: `{"rootCause": {"statement": "web-0 was OOMKilled against an undersized memory limit"}, "confidence": 0.8, "ruledOut": []}`,
		},
	}
}

// --- the invariant ---

// TestInvestigatePrefixIsByteIdenticalAcrossTurns is the test E18 asks for:
// it fails if the prefix — the model, the tool definitions, tool_choice, and
// the two leading messages — differs in any byte between one turn and the
// next of a single investigation.
//
// It also asserts the other half of the same property, which is easy to leave
// unstated: the message history is APPEND-ONLY. A provider matches a cached
// prefix from the start of the request, so a loop that rewrote, summarized or
// re-ordered an earlier turn would invalidate the cache from the point of the
// rewrite onward even with the system prompt held perfectly still.
func TestInvestigatePrefixIsByteIdenticalAcrossTurns(t *testing.T) {
	srv, bodies := newRawCapturingLLMServer(t, threeToolCallScript(t), nil)
	fake := &fakeToolCallback{}

	system := SystemPrompt(resolution.RouteInPlace, true, true, true)
	user := "incident inc_01: pod default/web-0 is CrashLoopBackOff"

	result, err := investigate(t.Context(), srv.Client(), srv.URL, "", "fake-model",
		system, user, fake.callback(), 8, time.Minute,
		toolAvailability{dryRun: true, metrics: true, repo: true})
	if err != nil {
		t.Fatalf("investigate: %v", err)
	}
	if result.Status != "complete" {
		t.Fatalf("investigate status = %q, want complete (script ends in a valid final answer)", result.Status)
	}
	if bodies.count() < 4 {
		t.Fatalf("fake provider saw %d requests, want 4 — the invariant is about what varies BETWEEN turns, so one turn cannot prove it", bodies.count())
	}

	first := parseRaw(t, bodies.at(0))
	if len(first.Messages) != 2 {
		t.Fatalf("turn 1 sent %d messages, want exactly 2 (system + user) — the prefix must be the whole of the first request", len(first.Messages))
	}

	for i := 1; i < bodies.count(); i++ {
		turn := parseRaw(t, bodies.at(i))

		if !bytes.Equal(first.Model, turn.Model) {
			t.Errorf("turn %d model = %s, turn 1 sent %s — a model change between turns invalidates the whole cached prefix", i+1, turn.Model, first.Model)
		}
		if !bytes.Equal(first.ToolChoice, turn.ToolChoice) {
			t.Errorf("turn %d tool_choice = %s, turn 1 sent %s", i+1, turn.ToolChoice, first.ToolChoice)
		}
		if !bytes.Equal(first.Tools, turn.Tools) {
			t.Errorf("turn %d tool definitions differ from turn 1's byte-for-byte — the tool schemas are part of the cached prefix and must be built once per investigation, not re-derived per turn.\nturn 1: %s\nturn %d: %s", i+1, first.Tools, i+1, turn.Tools)
		}
		if len(turn.Messages) < 2 {
			t.Fatalf("turn %d sent %d messages, want at least the 2 prefix messages", i+1, len(turn.Messages))
		}
		for j := 0; j < 2; j++ {
			if !bytes.Equal(first.Messages[j], turn.Messages[j]) {
				t.Errorf("turn %d messages[%d] differs from turn 1's byte-for-byte — messages[0] (system prompt) and messages[1] (the incident's findings) are the per-investigation prefix and must be reused verbatim.\nturn 1: %s\nturn %d: %s", i+1, j, first.Messages[j], i+1, turn.Messages[j])
			}
		}

		// Append-only: every message turn i-1 sent must still be present,
		// unchanged, in the same position, in turn i.
		prev := parseRaw(t, bodies.at(i-1))
		if len(turn.Messages) <= len(prev.Messages) {
			t.Errorf("turn %d sent %d messages, turn %d sent %d — each turn must ADD to the history, never shorten it", i+1, len(turn.Messages), i, len(prev.Messages))
			continue
		}
		for j := range prev.Messages {
			if !bytes.Equal(prev.Messages[j], turn.Messages[j]) {
				t.Errorf("turn %d rewrote messages[%d]: a provider matches a cached prefix from the start of the request, so editing an earlier message invalidates everything after it.\nbefore: %s\nafter:  %s", i+1, j, prev.Messages[j], turn.Messages[j])
			}
		}
	}
}

// TestInvestigatePrefixFingerprintIsStableAcrossAvailabilityCombinations
// pins the other end of the same property: the prefix is a function of its
// inputs and nothing else. Two prefixes built from the same arguments must
// fingerprint identically (no timestamp, no map iteration, no counter has
// crept into the assembly), and two built from different tool availability
// must not — a fingerprint that ignored the tool list would make the
// byte-identity test above pass vacuously.
func TestInvestigatePrefixFingerprintIsStableAcrossAvailabilityCombinations(t *testing.T) {
	avs := []toolAvailability{
		{},
		{dryRun: true},
		{metrics: true},
		{repo: true},
		{dryRun: true, metrics: true, repo: true},
	}
	seen := map[string]int{}
	for i, av := range avs {
		system := SystemPrompt(resolution.RoutePaired, av.dryRun, av.repo, av.metrics)
		a := newPromptPrefix("m", system, "user", av, false)
		b := newPromptPrefix("m", system, "user", av, false)
		if a.fingerprint != b.fingerprint {
			t.Errorf("av %+v: two prefixes built from identical arguments fingerprinted differently (%s vs %s) — something non-deterministic is in the assembly", av, a.fingerprint, b.fingerprint)
		}
		if prev, dup := seen[a.fingerprint]; dup {
			t.Errorf("av %+v fingerprints the same as av %+v — the fingerprint is not covering the tool list, so it cannot detect the drift it exists to detect", av, avs[prev])
		}
		seen[a.fingerprint] = i
	}
}

// TestSystemPromptIsDeterministic guards the input the invariant above rests
// on. SystemPrompt is assembled per incident and per route, which is fine —
// the cache is earned within one investigation. What would break it is the
// same arguments producing different text on two calls, which is exactly what
// a "current time" or "today's date" line, a map range, or a shuffled list in
// a future prompt-tuning pass would introduce.
func TestSystemPromptIsDeterministic(t *testing.T) {
	routes := []resolution.Route{
		resolution.RoutePullRequest,
		resolution.RouteInPlace,
		resolution.RoutePaired,
		resolution.RouteGuidance,
	}
	for _, route := range routes {
		for _, dryRun := range []bool{false, true} {
			for _, repo := range []bool{false, true} {
				for _, metrics := range []bool{false, true} {
					want := SystemPrompt(route, dryRun, repo, metrics)
					for i := 0; i < 3; i++ {
						if got := SystemPrompt(route, dryRun, repo, metrics); got != want {
							t.Fatalf("SystemPrompt(%v, %v, %v, %v) is not deterministic: call %d differs from call 1 — every turn of an investigation must be able to resend the identical prefix", route, dryRun, repo, metrics, i+2)
						}
					}
				}
			}
		}
	}
}

// TestOfferedToolDefinitionsMarshalIdentically is the same guard for the
// other half of the prefix. The tool schemas are raw JSON literals today, so
// this is cheap; it stops being cheap to get right the day one is generated
// from a Go value with a map in it.
func TestOfferedToolDefinitionsMarshalIdentically(t *testing.T) {
	for _, av := range []toolAvailability{{}, {dryRun: true}, {metrics: true}, {repo: true}, {dryRun: true, metrics: true, repo: true}} {
		want, err := json.Marshal(offeredToolDefinitions(av))
		if err != nil {
			t.Fatalf("marshal tool definitions for %+v: %v", av, err)
		}
		for i := 0; i < 3; i++ {
			got, err := json.Marshal(offeredToolDefinitions(av))
			if err != nil {
				t.Fatalf("marshal tool definitions for %+v: %v", av, err)
			}
			if !bytes.Equal(want, got) {
				t.Fatalf("offeredToolDefinitions(%+v) marshals differently on call %d — the tool schemas are part of the cached prefix", av, i+2)
			}
		}
	}
}

// --- explicit breakpoints ---

// TestCacheBreakpointsSupported pins which endpoint shapes get the explicit
// annotation. The default-false direction is the load-bearing half: sending
// cache_control to a provider that validates its request fields strictly
// fails the whole investigation, while not sending it to one that would have
// accepted it costs only the cache.
func TestCacheBreakpointsSupported(t *testing.T) {
	cases := []struct {
		baseURL, model string
		want           bool
	}{
		{"https://api.anthropic.com/v1", "claude-opus-5", true},
		{"https://API.Anthropic.com/v1/", "claude-opus-5", true},
		{"https://openrouter.ai/api/v1", "anthropic/claude-opus-5", true},
		{"https://gateway.openrouter.ai/api/v1", "some-model", true},
		{"https://llm.internal.example.com/v1", "anthropic/claude-opus-5", true},
		// Not recognized: a self-hosted server could be serving a model
		// called anything at all, and a strict one rejects the annotation.
		{"https://api.openai.com/v1", "gpt-5", false},
		{"http://localhost:11434/v1", "llama3", false},
		{"https://llm.internal.example.com/v1", "claude-opus-5", false},
		{"https://anthropic.com.evil.example/v1", "claude-opus-5", false},
		{"", "", false},
		{"://not a url", "", false},
	}
	for _, c := range cases {
		if got := cacheBreakpointsSupported(c.baseURL, c.model); got != c.want {
			t.Errorf("cacheBreakpointsSupported(%q, %q) = %v, want %v", c.baseURL, c.model, got, c.want)
		}
	}
}

// TestPrefixCacheBreakpointsAreOnTheWireAndStillIdentical checks both halves
// of the breakpoint change at once: the annotation is actually emitted, on
// the two prefix messages and nowhere else, AND turning it on does not itself
// make the prefix vary between turns. A breakpoint that moved, or that
// carried a per-request value, would be worse than none.
func TestPrefixCacheBreakpointsAreOnTheWireAndStillIdentical(t *testing.T) {
	srv, bodies := newRawCapturingLLMServer(t, threeToolCallScript(t), nil)

	prefix := newPromptPrefix("claude-opus-5", "system prompt", "user prompt", toolAvailability{}, true)
	history := []loopMessage{}

	for turn := 0; turn < 3; turn++ {
		_, _, _, _, _, err := callChat(t.Context(), srv.Client(), srv.URL, "", prefix, history)
		if err != nil {
			t.Fatalf("callChat turn %d: %v", turn+1, err)
		}
		// Grow the history the way the loop does.
		history = append(history,
			loopMessage{Role: "assistant", Content: strPtr("HYPOTHESIS: x"), ToolCalls: []toolCall{tc(t, fmt.Sprintf("call_%d", turn), "get_events", map[string]string{"namespace": "default"})}},
			loopMessage{Role: "tool", ToolCallID: fmt.Sprintf("call_%d", turn), Content: strPtr(`{"events":[]}`)})
	}

	first := parseRaw(t, bodies.at(0))
	for j, want := range []string{"system", "user"} {
		var msg struct {
			Role    string `json:"role"`
			Content []struct {
				Type         string `json:"type"`
				Text         string `json:"text"`
				CacheControl *struct {
					Type string `json:"type"`
				} `json:"cache_control"`
			} `json:"content"`
		}
		if err := json.Unmarshal(first.Messages[j], &msg); err != nil {
			t.Fatalf("messages[%d] is not the content-part shape a cache breakpoint needs: %v\nraw: %s", j, err, first.Messages[j])
		}
		if msg.Role != want {
			t.Fatalf("messages[%d].role = %q, want %q", j, msg.Role, want)
		}
		if len(msg.Content) != 1 || msg.Content[0].CacheControl == nil || msg.Content[0].CacheControl.Type != "ephemeral" {
			t.Errorf("messages[%d] carries no ephemeral cache_control breakpoint: %s", j, first.Messages[j])
		}
	}
	// Nowhere else: a breakpoint on a per-turn message would be a cache
	// WRITE every turn, which is not what this change claims to do.
	last := parseRaw(t, bodies.at(bodies.count()-1))
	for j := 2; j < len(last.Messages); j++ {
		if bytes.Contains(last.Messages[j], []byte("cache_control")) {
			t.Errorf("messages[%d] (a per-turn history message) carries a cache_control breakpoint: %s", j, last.Messages[j])
		}
	}

	for i := 1; i < bodies.count(); i++ {
		turn := parseRaw(t, bodies.at(i))
		for j := 0; j < 2; j++ {
			if !bytes.Equal(first.Messages[j], turn.Messages[j]) {
				t.Errorf("with breakpoints enabled, turn %d messages[%d] differs from turn 1's:\nturn 1: %s\nturn %d: %s", i+1, j, first.Messages[j], i+1, turn.Messages[j])
			}
		}
	}
}

// TestLoopMessageMarshalsPlainStringWithoutABreakpoint pins the default. Most
// endpoints this hub talks to are not on the breakpoint list, and for them the
// request must be byte-for-byte the shape it was before E18 — a bare string
// content, no content-part array.
func TestLoopMessageMarshalsPlainStringWithoutABreakpoint(t *testing.T) {
	b, err := json.Marshal(loopMessage{Role: "system", Content: strPtr("hello")})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if want := `{"role":"system","content":"hello"}`; string(b) != want {
		t.Errorf("loopMessage without a breakpoint marshaled as %s, want %s", b, want)
	}
	// An assistant message carrying tool_calls and a null content is the one
	// shape the pointer exists for; a breakpoint must not invent a content
	// array for it.
	b, err = json.Marshal(loopMessage{Role: "assistant", CacheBreakpoint: true, ToolCalls: []toolCall{{ID: "c1", Type: "function", Function: toolCallFunction{Name: "get_events", Arguments: "{}"}}}})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if bytes.Contains(b, []byte("cache_control")) {
		t.Errorf("a breakpoint on a message with no content produced a cache_control annotation: %s", b)
	}
}

// --- connecting the invariant to the figure that is actually recorded ---

// TestInvestigateReportsCacheReadsFromAPrefixCachingProvider closes the loop
// between "the prefix repeats" and the cached_tokens figure the hub already
// persists per analysis.
//
// **Be clear about what this does and does not prove.** The fake provider
// here implements a real prefix cache — it hashes the exact prefix bytes of
// each request and reports a hit only when it has genuinely seen those bytes
// before — so the test proves that the prefix repeats and that a hit, when a
// provider reports one, is accumulated into the Investigation the analyses
// row is built from. It does NOT prove that any real provider caches this
// prompt: only an endpoint that actually implements prompt caching can show
// that, and no such measurement has been taken for this change.
func TestInvestigateReportsCacheReadsFromAPrefixCachingProvider(t *testing.T) {
	var mu sync.Mutex
	seen := map[string]bool{}
	const cachedTokensPerHit = 4096

	cachedTokensFor := func(body []byte) int {
		var req rawRequest
		if err := json.Unmarshal(body, &req); err != nil || len(req.Messages) < 2 {
			return 0
		}
		key := string(req.Model) + "|" + string(req.Tools) + "|" + string(req.Messages[0]) + "|" + string(req.Messages[1])
		mu.Lock()
		defer mu.Unlock()
		if seen[key] {
			return cachedTokensPerHit
		}
		seen[key] = true
		return 0
	}

	srv, bodies := newRawCapturingLLMServer(t, threeToolCallScript(t), cachedTokensFor)
	fake := &fakeToolCallback{}

	result, err := investigate(t.Context(), srv.Client(), srv.URL, "", "fake-model",
		SystemPrompt(resolution.RouteInPlace, false, false, false), "user prompt",
		fake.callback(), 8, time.Minute, toolAvailability{})
	if err != nil {
		t.Fatalf("investigate: %v", err)
	}

	rounds := bodies.count()
	if rounds < 4 {
		t.Fatalf("fake provider saw %d requests, want 4", rounds)
	}
	// Turn 1 is the cache write; every turn after it is a hit.
	want := (rounds - 1) * cachedTokensPerHit
	if result.TokensCacheRead != want {
		t.Errorf("Investigation.TokensCacheRead = %d, want %d (%d of %d rounds served from the prefix cache). A zero here means the prefix changed between turns, which is exactly the failure prompt caching hides.", result.TokensCacheRead, want, rounds-1, rounds)
	}
}
