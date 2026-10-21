// prompt_prefix.go is PROJECT.md E18: the send side of prompt caching.
//
// callChat has read usage.prompt_tokens_details.cached_tokens since the loop
// was written, and that figure is persisted per analysis and rendered in the
// UI — so the hub could always REPORT a cache hit. Nothing was arranged to
// EARN one. A provider only serves a prompt from cache when the request's
// leading bytes are identical to a request it has already seen, and the
// investigation loop makes up to DefaultMaxIterations round trips, resending
// the whole system prompt and tool schema set every time. Whether those
// bytes actually repeated was not asserted anywhere; it was a property the
// code happened to have, which is the kind of property that stops being true
// in a later edit without anything failing.
//
// This file makes it a property the code HAS, in two parts:
//
//  1. promptPrefix freezes the prefix — model, tool definitions, the system
//     message and the incident's user message — once per investigation, at
//     the top of investigate(). Every turn's request is assembled as that
//     frozen prefix plus an append-only history, so the loop has no path by
//     which a later turn could send a different prefix than the first one.
//     prompt_prefix_test.go asserts the wire bytes, turn by turn, and fails
//     if they ever differ.
//
//  2. For providers that implement Anthropic's explicit cache_control
//     annotation, the two prefix messages carry a breakpoint, so the prefix
//     is cached rather than left to whatever automatic prefix caching the
//     endpoint may or may not do. See cacheBreakpointsSupported for why this
//     is default-OFF and matched against a short list of endpoint shapes
//     rather than sent everywhere.
//
// The scope boundary is worth stating plainly, because it is easy to assume
// this covers both backends. It covers the **api** backend only — the loop in
// toolloop.go, where the hub itself builds every request. The **cli** backend
// (cli_investigator.go) hands one systemPrompt to an external coding-agent CLI
// over HTTP and that CLI owns its own turn-taking and its own wire requests;
// the hub never sees them, so there is no prefix here for this file to freeze
// and no breakpoint for it to place. What the two backends share — the system
// prompt text (SystemPrompt) and the tool schemas (toolDefinitions, projected
// into the cli backend's MCP surface by InvestigationToolSchemas) — is
// unchanged by this file, which is what keeps the two from drifting.
//
// **What is NOT claimed.** No cache hit from a real provider has been measured
// for this. Proving one needs an endpoint that actually implements prompt
// caching; a fake server reporting cached_tokens proves only that the hub
// parses the field, which it already did. What IS proven here is the
// precondition: the prefix repeats byte-for-byte, so a caching provider has
// something to hit. See prompt_prefix_test.go's
// TestInvestigateReportsCacheReadsFromAPrefixCachingProvider for how far a
// local test can honestly take it.

package llm

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
)

// promptPrefix is one investigation's frozen request prefix: everything that
// is identical on every turn, computed once.
//
// "Identical across turns" is the property, not "identical across
// investigations" — SystemPrompt(route, dryRunAvailable, repoReadable,
// metricsAvailable) is assembled per incident and per resolution route, and
// the tool list varies with the same per-incident availability, so two
// investigations legitimately differ. A provider's cache is keyed on the
// bytes, not on our idea of what an investigation is, so a per-incident
// prefix simply means the cache is earned from turn 2 onward within one
// investigation rather than shared across them. That is the win E18 is
// after: at DefaultMaxIterations turns, seven of the eight sends can be
// cache reads.
//
// Fields are unexported and never mutated after construction. The loop holds
// one of these by value and an append-only []loopMessage beside it; there is
// no method here that writes to a prefix.
type promptPrefix struct {
	model string
	// tools is offeredToolDefinitions(av) evaluated ONCE. It was previously
	// re-evaluated inside every callChat, which was deterministic and so
	// produced identical bytes — but only because nothing in that function
	// happened to vary. Freezing it removes the "happened to".
	tools []toolDef
	// system and user are messages[0] and messages[1]. The user turn (the
	// incident's own findings, built by internal/api/analyze.go) is part of
	// the PREFIX, not of the history: it is written once before the first
	// call and never appended to, so it caches exactly as well as the system
	// prompt does.
	system loopMessage
	user   loopMessage
	// fingerprint is a sha256 over the marshaled prefix. It exists to be
	// asserted on (prompt_prefix_test.go) and to be logged once per round
	// trip, so that a prefix that starts varying in production is visible in
	// the hub's own log rather than only as a cache-hit rate that quietly
	// went to zero.
	fingerprint string
}

// cacheControl is Anthropic's cache-breakpoint annotation, as carried inside
// an OpenAI-chat-completions content part by the gateways that accept it.
// "ephemeral" is the only type there is.
type cacheControl struct {
	Type string `json:"type"`
}

// textPart is one OpenAI content-part. The array form of `content` is the
// only place a cache_control annotation can be attached in this wire shape —
// there is nowhere on a plain string content, and OpenAI-shaped `tools[]`
// entries have no such field either, which is why the system-message
// breakpoint is what covers the tool schemas (see promptPrefix.messages).
type textPart struct {
	Type         string        `json:"type"`
	Text         string        `json:"text"`
	CacheControl *cacheControl `json:"cache_control,omitempty"`
}

// newPromptPrefix freezes one investigation's prefix.
//
// cacheBreakpoints is passed in rather than derived here so the decision is
// made once, at a call site that has the resolved endpoint in hand, and so a
// test can construct either shape directly.
func newPromptPrefix(model, systemPrompt, userPrompt string, av toolAvailability, cacheBreakpoints bool) promptPrefix {
	p := promptPrefix{
		model:  model,
		tools:  offeredToolDefinitions(av),
		system: loopMessage{Role: "system", Content: strPtr(systemPrompt), CacheBreakpoint: cacheBreakpoints},
		user:   loopMessage{Role: "user", Content: strPtr(userPrompt), CacheBreakpoint: cacheBreakpoints},
	}
	p.fingerprint = fingerprintPrefix(p)
	return p
}

// messages returns the prefix's two leading messages, in wire order.
//
// Breakpoint placement, and why it is these two: a provider matches a cached
// prefix from the very start of the rendered request, and Anthropic's render
// order is tools, then system, then messages. A breakpoint on the SYSTEM
// message therefore covers the tool schemas as well — which is the larger
// half of the prefix and the half with no annotation slot of its own. The
// second breakpoint, on the incident's user message, extends the cached span
// over the last part of the request that is constant for this investigation.
//
// Deliberately two, not more. A rolling breakpoint on the last message of
// each turn would additionally cache the accumulated tool results, which at
// eight iterations is where most of the tokens eventually are — but it writes
// a fresh cache entry every turn (a cache write is billed above a plain
// input token), and unlike these two it is not a constant, so the
// byte-identity invariant that makes this file worth anything would not cover
// it. It is the obvious next step once a real endpoint makes the effect
// measurable; it is not something to add on the strength of reasoning alone.
func (p promptPrefix) messages() []loopMessage {
	return []loopMessage{p.system, p.user}
}

// request assembles one turn's wire request: the frozen prefix followed by
// the append-only history. history is copied into a fresh slice, so nothing a
// caller does to the returned request can reach back into the loop's own
// history slice.
func (p promptPrefix) request(history []loopMessage) loopChatRequest {
	messages := make([]loopMessage, 0, 2+len(history))
	messages = append(messages, p.system, p.user)
	messages = append(messages, history...)
	return loopChatRequest{
		Model:      p.model,
		Messages:   messages,
		Tools:      p.tools,
		ToolChoice: "auto",
	}
}

// fingerprintPrefix hashes exactly the bytes that must not vary between
// turns — model, tools, and the two prefix messages as they are marshaled
// for the wire, breakpoint annotations included. Not the history, which is
// supposed to grow.
//
// A marshal error cannot happen for these types (no channels, no functions,
// no NaN) and is reported in-band as a sentinel string rather than swallowed
// silently, so a future field that breaks marshaling shows up as a changed
// fingerprint in the test rather than as an identical empty hash everywhere.
func fingerprintPrefix(p promptPrefix) string {
	b, err := json.Marshal(struct {
		Model    string        `json:"model"`
		Tools    []toolDef     `json:"tools"`
		Messages []loopMessage `json:"messages"`
	}{Model: p.model, Tools: p.tools, Messages: []loopMessage{p.system, p.user}})
	if err != nil {
		return fmt.Sprintf("unmarshalable-prefix:%v", err)
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// cacheBreakpointsSupported reports whether the resolved endpoint is one that
// accepts Anthropic's cache_control annotation inside an
// OpenAI-chat-completions request.
//
// **Default is false, and that is the safe direction.** Two different things
// happen at a provider that does not understand the annotation: a tolerant
// one ignores the unknown key and the request behaves exactly as it did
// before, but a strict one (OpenAI's own API is strict about unrecognized
// request fields) rejects the whole request. Attaching a breakpoint also
// switches `content` from a bare string to a content-part array, which some
// self-hosted servers handle less well than the string form. A false positive
// here therefore breaks every investigation against that endpoint, while a
// false negative costs only the cache — so this matches a short list of
// endpoint shapes known to take the annotation instead of guessing from, say,
// a model name containing "claude", which a self-hosted server could equally
// well be serving.
//
// The consequence to be honest about: an operator running a gateway that DOES
// accept the annotation (a LiteLLM proxy in front of Claude, say) at some
// private hostname gets no breakpoints, only whatever automatic caching that
// gateway does. Adding that shape is a one-line change to the list below; the
// byte-identity invariant is what earns the automatic kind either way, and it
// applies to every endpoint unconditionally.
func cacheBreakpointsSupported(baseURL, model string) bool {
	// OpenRouter's model-routing syntax is unambiguous: an "anthropic/..."
	// model id is an Anthropic model reached through a gateway that speaks
	// this annotation, whatever host it is reached at.
	if strings.HasPrefix(strings.ToLower(strings.TrimSpace(model)), "anthropic/") {
		return true
	}
	u, err := url.Parse(strings.TrimSpace(baseURL))
	if err != nil {
		return false
	}
	host := strings.ToLower(u.Hostname())
	for _, known := range []string{"api.anthropic.com", "openrouter.ai"} {
		if host == known || strings.HasSuffix(host, "."+known) {
			return true
		}
	}
	return false
}
