// Package llm is the first, deliberately minimal piece of
// DESIGN.md §16.1's "AI provider layer" — a thin
// abstraction over an OpenAI-chat-completions-compatible HTTP API, chosen
// specifically because that shape is what most self-hosted/open-source
// model servers (Ollama, vLLM, LocalAI, text-generation-webui, llama.cpp's
// server, ...) already expose, matching §16.0's "hybrid AI hosting" decision
// (hosted API + self-hosted per task-tier).
//
// Complete itself (this file) makes exactly one call per invocation, with no
// tools, given only whatever text the caller already has — a stepping stone
// that wired the provider config and the request/response plumbing end to
// end before the real evidence-gathering loop existed. Callers should not
// present its output with the confidence §8.4's output contract implies.
//
// The bounded, multi-turn, tool-calling investigation loop §8.2 specs now
// exists — see toolloop.go's Investigate, built on top of the
// ToolRequest/ToolResult tunnel messages and internal/gateway.CallTool (see
// STATUS.md). internal/api/analyze.go calls Investigate, not Complete, for
// POST /incidents/{id}/analyze; Complete is unchanged and kept for whatever
// future caller wants a plain, tool-free completion.
//
// Config (§16.2) is now DB-backed and live-editable (internal/settings,
// PUT /api/v1/admin/settings) rather than env-var-only: Complete resolves
// internal/settings.Config fresh on every call, so a change made through
// that API takes effect on the very next analysis, no hub restart required.
// ARGUS_LLM_BASE_URL/ARGUS_LLM_API_KEY/ARGUS_LLM_MODEL still work exactly as
// before — they're now the seed default a null DB column falls back to,
// per internal/settings.Resolve's precedence rule, not the only source.
package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"argus/internal/outbound"
	"argus/internal/settings"
)

// ErrNotConfigured is returned by Complete when internal/settings.Resolve
// yields no LLM base URL from either the DB or ARGUS_LLM_BASE_URL — callers
// (internal/api/analyze.go's handleAnalyzeIncident) must turn this into a
// clear "AI provider not configured" response, never a generic failure, and
// never a crash. Unlike the old NewProviderFromEnv contract (a nil
// *Provider), this is now discovered per-call, since a hub with no provider
// configured at startup may still have one configured later, live, via
// PUT /api/v1/admin/settings.
// The wording is deliberately about USABILITY, not absence. It used to read
// "no AI provider configured", which reads as a contradiction once a wrapping
// message explains that a provider IS configured and something else is wrong —
// e.g. a fully-configured CLI runner on a hub with no MCP listener. The
// sentinel's identity (what errors.Is matches) is unchanged; only the sentence
// a user ends up reading is.
var ErrNotConfigured = errors.New("llm: no usable AI provider")

// Completer is the one-shot, tool-free seam BACKLOG.md P13 introduced:
// "here is a system+user prompt pair, give me back text" — nothing else.
// *Provider satisfies it directly (Complete, below, is exactly this
// contract already). *CLIInvestigator satisfies it via its own Complete
// method (cli_investigator.go), the one-shot sibling to Investigate that
// backend did not have before P13 — invoking the same underlying CLI agent
// with no MCP server configured and no tools offered, rather than driving
// the tool-calling loop. *Router satisfies it too, by dispatching to
// whichever of the two the operator actually configured — see Router.Complete.
//
// This is the seam Complete's real callers (internal/gateway's
// condition-polarity gate, CorrectPlanParams below) are written against, so
// that a cli-kind deployment — which is every deployment whose AI provider
// actually works, since Investigate is the only thing exercised against a
// cli-kind provider before this — gets a working answer instead of
// ErrNotConfigured or a DNS lookup against a stale, kind-irrelevant
// base_url (BUGS.md 125).
type Completer interface {
	Complete(ctx context.Context, systemPrompt, userPrompt string) (Result, error)
}

var _ Completer = (*Provider)(nil)

// Provider calls an OpenAI-chat-completions-compatible endpoint, resolving
// its base URL/model/API key fresh on every Complete call via
// internal/settings.Resolve rather than holding them fixed from process
// startup — see the package doc comment.
type Provider struct {
	pool   *pgxpool.Pool
	client *http.Client
}

// aiProviderOutboundPolicy builds the ONE outbound.Policy shape for the
// AI-provider base_url boundary (lld/01-threat-model.md T15/B5) — used by
// both NewProvider (the real completion/investigation path) and probe.go's
// probeAPIClient (the settings page's "test connection" button, which reads
// the same admin-configured base_url). Deliberately a single shared
// constructor rather than two literals that could drift: if probe and the
// real path disagreed, the settings page could report "connection OK" for a
// destination the real path then refuses — a false green, which this
// codebase treats as a defect in its own right, same as a fabricated zero.
// Both callers must also pass the SAME allowlist source, or the drift comes
// back through the argument instead of the literal.
//
// Default-deny (refuse loopback/link-local/private), with one narrow,
// operator-visible exception. The open posture question this comment used to
// record — a self-hosted vLLM or other OpenAI-compatible server on a private
// address is plausible for this product — was decided by the owner on
// 2026-09-19: keep default-deny, and let an operator NAME specific private
// destinations they trust. AllowPrivate is deliberately still not set here;
// what is passed instead is outbound.Policy.PrivateDestinations, which can
// only ever permit the specific addresses an operator listed, can never reach
// a cloud metadata address, and is matched against the resolved address at
// dial time rather than against the hostname. See internal/outbound/
// allowlist.go and migration 000115.
//
// src may be nil (a test, or a Provider built with no pool), and a nil source
// means the old behaviour exactly: every private destination refused.
func aiProviderOutboundPolicy(src outbound.AllowlistSource) outbound.Policy {
	return outbound.Policy{PrivateDestinations: src}
}

// NewProvider builds a Provider backed by pool. Always non-nil, unlike the
// old NewProviderFromEnv's nil-able "ok" contract — whether a real endpoint
// is actually configured can now change at runtime (via the settings API),
// so there is no longer a meaningful "not configured at construction time"
// state to represent by returning nil; Complete reports that per call
// instead, via ErrNotConfigured.
func NewProvider(pool *pgxpool.Pool) *Provider {
	return &Provider{
		pool: pool,
		// AI-provider base_url is admin-configured (internal/settings) and
		// may reflect a compromised admin session or a supply-chain-
		// tampered config value (lld/01-threat-model.md T15) — see
		// aiProviderOutboundPolicy's own comment for why this is shared
		// with probe.go rather than a second literal.
		//
		// The allowlist source closes over the pool rather than over a
		// resolved value, so an operator adding or removing a permitted
		// private destination takes effect on the next dial with no hub
		// restart — the same contract every other org setting has. A
		// Provider built with no pool (tests) gets no source, i.e. plain
		// default-deny.
		client: outbound.NewClient(aiProviderOutboundPolicy(privateDestinationSource(pool)), 60*time.Second),
	}
}

// privateDestinationSource returns the operator allowlist source for a pool,
// or nil when there is no pool to read it from. Nil is the safe answer: it
// means no private destination is permitted at all, which is what this
// boundary did before the allowlist existed.
func privateDestinationSource(pool *pgxpool.Pool) outbound.AllowlistSource {
	if pool == nil {
		return nil
	}
	return settings.PrivateDestinationSource(pool)
}

// Result is one completion's output plus the token accounting §16.3's cost
// model (eventually) depends on — cost itself is deliberately NOT computed
// here, since a self-hosted model's cost is $0 by definition and a hosted
// one's pricing table doesn't exist in this codebase yet (§16.3's own
// measurement-harness commitment, D16, still pending). TokensCacheRead is
// tracked separately from TokensIn (full prompt size, cached or not) per
// lld/07-analysis-contracts.md §7 — see chatUsageWire below for where it's
// actually parsed from.
type Result struct {
	Text            string
	TokensIn        int
	TokensCacheRead int
	TokensOut       int
	Model           string
	DurationMs      int
}

type chatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type chatRequest struct {
	Model    string        `json:"model"`
	Messages []chatMessage `json:"messages"`
}

// chatUsageWire is the normalized `usage` object this package parses from
// every OpenAI-chat-completions-compatible response — used here by
// chatResponse and reused verbatim by toolloop.go's loopChatResponse, so a
// provider-specific accounting quirk only ever needs handling in one place
// (lld/07-analysis-contracts.md §7's "per-provider quirks normalized at this
// layer, not left for callers to reconcile"). PromptTokensDetails.CachedTokens
// is the standard OpenAI extension field reporting how many of PromptTokens
// were served from a prompt cache (billed at a reduced rate) rather than
// full price — that's the one quirk this task's scope covers; a provider
// that signals caching some other way (e.g. folding a discount directly into
// PromptTokens with no separate field at all) isn't normalized here, since
// nothing in this codebase's current provider surface exercises that shape.
type chatUsageWire struct {
	PromptTokens        int `json:"prompt_tokens"`
	CompletionTokens    int `json:"completion_tokens"`
	PromptTokensDetails *struct {
		CachedTokens int `json:"cached_tokens"`
	} `json:"prompt_tokens_details,omitempty"`
}

// cacheReadTokens is 0 when the response carries no prompt_tokens_details at
// all (a provider that doesn't report caching, or a self-hosted server with
// no cache to report) rather than an error — cache reporting is an
// optional/best-effort extension, never a required field.
func (u chatUsageWire) cacheReadTokens() int {
	if u.PromptTokensDetails == nil {
		return 0
	}
	return u.PromptTokensDetails.CachedTokens
}

type chatResponse struct {
	Model   string `json:"model"`
	Choices []struct {
		Message chatMessage `json:"message"`
	} `json:"choices"`
	Usage chatUsageWire `json:"usage"`
}

// Complete sends one system+user prompt pair and returns the model's reply.
// No conversation history, no tool calls — see the package doc comment.
// Resolves configuration fresh via internal/settings.Resolve; returns
// ErrNotConfigured (never a generic error) if no base URL is configured
// through either the DB or ARGUS_LLM_BASE_URL.
func (p *Provider) Complete(ctx context.Context, systemPrompt, userPrompt string) (Result, error) {
	cfg, err := settings.Resolve(ctx, p.pool)
	if err != nil {
		return Result{}, fmt.Errorf("resolve AI provider settings: %w", err)
	}
	if cfg.LLMBaseURL == "" {
		return Result{}, ErrNotConfigured
	}
	return complete(ctx, p.client, cfg.LLMBaseURL, cfg.LLMAPIKey, cfg.LLMModel, systemPrompt, userPrompt)
}

// complete is Complete's pure-plumbing half: given an already-resolved
// baseURL/apiKey/model (rather than reaching into settings.Resolve itself),
// it builds and sends exactly one chat-completion request. Split out so it's
// unit-testable against an httptest.Server with a hand-built config, with no
// database involved at all (see provider_test.go).
func complete(ctx context.Context, client *http.Client, baseURL, apiKey, model, systemPrompt, userPrompt string) (Result, error) {
	start := time.Now()

	body, err := json.Marshal(chatRequest{
		Model: model,
		Messages: []chatMessage{
			{Role: "system", Content: systemPrompt},
			{Role: "user", Content: userPrompt},
		},
	})
	if err != nil {
		return Result{}, fmt.Errorf("marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL+"/chat/completions", bytes.NewReader(body))
	if err != nil {
		return Result{}, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+apiKey)
	}

	resp, err := client.Do(req)
	if err != nil {
		return Result{}, fmt.Errorf("call LLM provider at %s: %w", baseURL, err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return Result{}, fmt.Errorf("read LLM provider response: %w", err)
	}
	if resp.StatusCode >= 300 {
		return Result{}, fmt.Errorf("LLM provider returned %s: %s", resp.Status, string(respBody))
	}

	var parsed chatResponse
	if err := json.Unmarshal(respBody, &parsed); err != nil {
		return Result{}, fmt.Errorf("parse LLM provider response: %w", err)
	}
	if len(parsed.Choices) == 0 {
		return Result{}, fmt.Errorf("LLM provider returned no choices")
	}

	respModel := parsed.Model
	if respModel == "" {
		respModel = model
	}

	return Result{
		Text:            parsed.Choices[0].Message.Content,
		TokensIn:        parsed.Usage.PromptTokens,
		TokensCacheRead: parsed.Usage.cacheReadTokens(),
		TokensOut:       parsed.Usage.CompletionTokens,
		Model:           respModel,
		DurationMs:      int(time.Since(start).Milliseconds()),
	}, nil
}
