package llm

// The cli backend — lld/14-adrs.md ADR-17's second Investigator kind, and the
// hub-side half of the B12 boundary (lld/01-threat-model.md §4).
//
// What this file does NOT do is the point of it: it does not drive a
// tool-calling loop. It hands one prompt to a runner service, the CLI inside
// that runner drives its own loop calling back into the hub's MCP server
// (internal/mcp), and this file parses whatever final JSON comes back. That
// is why lld/07-analysis-contracts.md §10.3's guarantees stop holding here —
// there is no per-turn hook in which to check a bound or count a token,
// because there are no per-turn round-trips through this process at all.
//
// The two bounds that DO still hold are enforced here rather than trusted to
// the CLI: maxTurns is passed to the runner as a request, and the request
// context carries a hard deadline. §10.3 states plainly that the first can
// overshoot by up to one turn; the second cannot, which is why both exist.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"argus/internal/logging"
	"argus/internal/outbound"
	"argus/internal/settings"
)

// Cost bases, as persisted to analyses.cost_basis (migration 000033) —
// lld/07-analysis-contracts.md §10.5.
const (
	// CostBasisMetered: a real, measured per-investigation cost. Always the
	// case for the api backend, and the case for a cli backend whose
	// credential is a metered API key.
	CostBasisMetered = "metered"
	// CostBasisSubscription: the run was billed against a flat-rate
	// subscription, so per-investigation cost genuinely does not exist. Not
	// zero — unavailable. Nothing downstream may render this as $0.00.
	CostBasisSubscription = "subscription"
	// CostBasisUnknown: the runner could not determine which of the above
	// applied. Reported honestly rather than guessed at.
	CostBasisUnknown = "unknown"
)

// defaultCLITimeout bounds one investigation end to end when the resolved
// analysis time limit gives no tighter answer. Deliberately generous relative
// to the api backend's own default: a CLI pays process startup plus its own
// multi-turn loop, and killing a nearly-finished investigation to save
// seconds wastes the whole run.
const defaultCLITimeout = 10 * time.Minute

// runnerRequest is the hub -> runner protocol (B12 outbound). Stable, minimal,
// and deliberately carries no cluster identity: the runner has no business
// knowing which cluster this is, and could not act on it if it did — cluster
// scope lives inside MCPToken, resolved hub-side (SR-24).
type runnerRequest struct {
	Agent        string   `json:"agent"`
	SystemPrompt string   `json:"systemPrompt"`
	UserPrompt   string   `json:"userPrompt"`
	MCPURL       string   `json:"mcpUrl"`
	MCPToken     string   `json:"mcpToken"`
	AllowedTools []string `json:"allowedTools"`
	MaxTurns     int      `json:"maxTurns"`
	TimeoutSecs  int      `json:"timeoutSeconds"`
}

// runnerResponse is the runner -> hub protocol. Content is the CLI's final
// answer text. It is expected to CONTAIN the same pinned final-analysis JSON
// the api backend's own last turn produces — but, unlike that backend, it is
// not expected to consist of nothing else; see extractFinalAnalysis for why
// that distinction turned out to matter in practice.
type runnerResponse struct {
	Content         string  `json:"content"`
	Model           string  `json:"model"`
	Turns           int     `json:"turns"`
	DurationMs      int     `json:"durationMs"`
	CostUSD         float64 `json:"costUsd"`
	CostBasis       string  `json:"costBasis"`
	TokensIn        int     `json:"tokensIn"`
	TokensCacheRead int     `json:"tokensCacheRead"`
	TokensOut       int     `json:"tokensOut"`
	// TimedOut is the runner reporting that IT stopped the CLI on the
	// deadline, which becomes a partial analysis rather than an error — the
	// same outcome a bound-hit api investigation produces.
	TimedOut bool `json:"timedOut"`
	// Error is a runner-side failure (CLI missing, version unsupported, token
	// expired, malformed invocation). Non-empty means the investigation did
	// not happen at all, which is distinct from TimedOut.
	Error string `json:"error"`
}

// CLIInvestigator delegates the investigation loop to a runner service.
type CLIInvestigator struct {
	client *http.Client
	minter TokenMinter
	// toolNames is the exact allowlist minted into every token and passed to
	// the runner. Sourced from the MCP server's own offered surface at wiring
	// time, so the grant, the CLI's --allowedTools, and what the hub will
	// actually serve are one list rather than three (SR-22).
	toolNames []string
	resolve   func(ctx context.Context) (settings.Config, error)
	// mcpURL is the address the *runner* should dial to reach the hub's MCP
	// listener — not necessarily the hub's own bind address (a sidecar
	// reaches it on localhost, a separate Deployment via a Service DNS name),
	// which is why it is configured rather than derived.
	mcpURL string
	// ledger is BACKLOG.md C10's cross-check ledger — how this backend reads
	// back the hub's own record of which tool calls it actually served for an
	// investigation, to verify a self-reported causal chain against it. May be
	// nil (cmd/hub always wires one alongside the cli backend today, but a
	// test or a future caller might not) — see Investigate's own handling,
	// which asks for and reports a causal chain only when this is set.
	ledger ToolCallLedger
}

// cliRunnerOutboundPolicy is the ONE outbound.Policy value for the
// CLI-runner boundary (mcpURL/settings.CLIRunnerURL, lld/01-threat-model.md
// B12) — read by both NewCLIInvestigator (the real investigation path) and
// probe.go's probeCLIHTTPClient (the settings page's "test connection" for
// the cli backend), for the identical drift reason aiProviderOutboundPolicy
// documents in provider.go.
//
// AllowPrivate: the runner is a same-deployment sidecar or in-cluster
// Service by design — see this file's own package doc comment on the B12
// boundary — so a loopback or cluster-private address here is the expected
// case, not an attacker's. Cloud metadata addresses are still refused
// unconditionally regardless of this (internal/outbound).
var cliRunnerOutboundPolicy = outbound.Policy{
	AllowPrivate: true,
	Reason:       "CLI-runner sidecar/Service address is same-deployment by design (B12)",
}

// NewCLIInvestigator wires the backend. A nil minter or an empty mcpURL makes
// every Investigate call fail with a clear configuration error rather than
// producing an unscoped token or dialing nothing. A nil ledger is tolerated —
// see the ledger field's own comment — and simply disables this backend's
// causal chain reporting rather than failing every investigation.
func NewCLIInvestigator(minter TokenMinter, toolNames []string, mcpURL string, resolve func(ctx context.Context) (settings.Config, error), ledger ToolCallLedger) *CLIInvestigator {
	return &CLIInvestigator{
		// No global timeout on the client itself: the per-call context
		// deadline below is the real bound, and a client-level timeout would
		// silently take precedence over the resolved, configurable one.
		client:    outbound.NewClient(cliRunnerOutboundPolicy, 0),
		minter:    minter,
		toolNames: toolNames,
		resolve:   resolve,
		mcpURL:    mcpURL,
		ledger:    ledger,
	}
}

var (
	_ Investigator = (*CLIInvestigator)(nil)
	_ Completer    = (*CLIInvestigator)(nil)
)

// defaultCLICompleteTimeout bounds Complete (below), BACKLOG.md P13's
// one-shot sibling to Investigate. Deliberately far tighter than
// defaultCLITimeout: this call makes no MCP round trips at all — there is no
// tool loop to wait on — so a real answer takes seconds, and both of
// Complete's real callers (the polarity gate resolving one Finding, the
// plan-correction retry mid dry-run-rejection loop) are themselves on a much
// tighter budget than a whole investigation.
const defaultCLICompleteTimeout = 60 * time.Second

// completeRequest is the hub -> runner protocol for Complete — deliberately
// NOT runnerRequest: there is no MCP token, no cluster scope and no tool
// allowlist, because this call is never allowed to reach a tool at all.
// Mirrored (not shared) by cmd/cli-runner/main.go's own declaration of this
// shape, matching runnerRequest/investigateRequest's existing precedent
// (this file's package comment) for why the wire contract is duplicated
// rather than imported.
type completeRequest struct {
	Agent        string `json:"agent"`
	SystemPrompt string `json:"systemPrompt"`
	UserPrompt   string `json:"userPrompt"`
	TimeoutSecs  int    `json:"timeoutSeconds"`
}

// completeResponse mirrors runnerResponse's accounting fields, minus Turns
// (meaningless for a call that makes exactly one exchange) and everything
// else that only makes sense for a tool-calling loop.
type completeResponse struct {
	Content         string  `json:"content"`
	Model           string  `json:"model"`
	DurationMs      int     `json:"durationMs"`
	CostUSD         float64 `json:"costUsd"`
	CostBasis       string  `json:"costBasis"`
	TokensIn        int     `json:"tokensIn"`
	TokensCacheRead int     `json:"tokensCacheRead"`
	TokensOut       int     `json:"tokensOut"`
	TimedOut        bool    `json:"timedOut"`
	Error           string  `json:"error"`
}

// Complete is Investigate's one-shot, tool-free sibling — BACKLOG.md P13.
// It asks the SAME runner service to invoke the SAME underlying CLI agent,
// but for a single system+user prompt exchange: no MCP server is configured
// for the call at all (so no token is minted — there is nothing to scope,
// since no tool call can happen), and unlike Investigate it needs no
// cluster identity and refuses nothing for lacking one.
//
// This is what lets llm.Router.Complete route a cli-kind deployment's real
// callers (the condition-polarity gate, the plan-correction retry) through
// the CLI runner instead of through Provider.Complete, which has no path at
// all on a cli-kind deployment (BUGS.md 125 / BACKLOG.md P13).
func (c *CLIInvestigator) Complete(ctx context.Context, systemPrompt, userPrompt string) (Result, error) {
	cfg, err := c.resolve(ctx)
	if err != nil {
		return Result{}, fmt.Errorf("resolve AI provider settings: %w", err)
	}
	if cfg.CLIRunnerURL == "" {
		return Result{}, fmt.Errorf("%w: no CLI runner URL configured", ErrNotConfigured)
	}

	agent := cfg.CLIAgent
	if agent == "" {
		agent = "claude"
	}

	timeLimit := defaultCLICompleteTimeout

	callCtx, cancel := context.WithTimeout(ctx, timeLimit+10*time.Second)
	defer cancel()

	body, err := json.Marshal(completeRequest{
		Agent:        agent,
		SystemPrompt: systemPrompt,
		UserPrompt:   userPrompt,
		TimeoutSecs:  int(timeLimit.Seconds()),
	})
	if err != nil {
		return Result{}, fmt.Errorf("marshal runner request: %w", err)
	}

	url := strings.TrimSuffix(cfg.CLIRunnerURL, "/") + "/complete"
	req, err := http.NewRequestWithContext(callCtx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return Result{}, fmt.Errorf("build runner request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if cfg.CLIRunnerToken != "" {
		req.Header.Set("Authorization", "Bearer "+cfg.CLIRunnerToken)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return Result{}, fmt.Errorf("call CLI runner: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return Result{}, fmt.Errorf("CLI runner returned HTTP %d", resp.StatusCode)
	}

	var out completeResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return Result{}, fmt.Errorf("decode runner response: %w", err)
	}
	if out.Error != "" {
		return Result{}, fmt.Errorf("CLI runner: %s", out.Error)
	}
	if out.TimedOut {
		return Result{}, fmt.Errorf("CLI runner: one-shot completion exceeded its %s deadline", timeLimit)
	}

	return Result{
		Text:            strings.TrimSpace(out.Content),
		TokensIn:        out.TokensIn,
		TokensCacheRead: out.TokensCacheRead,
		TokensOut:       out.TokensOut,
		Model:           out.Model,
		DurationMs:      out.DurationMs,
	}, nil
}

// toolNamesForTarget narrows full (the MCP server's complete registered
// surface) to what one investigation should actually be allowed to call:
// dropping "dry_run_patch" unless the cluster holds the argus-dryrun grant,
// dropping "query_metrics" unless the cluster holds the configured metrics
// grant, and dropping the two repository tools (BACKLOG.md F22) unless this incident
// actually resolves to a readable repository. Kept as a small pure function,
// mirroring offeredToolDefinitions' shape in toolloop.go, so the api and cli
// backends apply the identical rule without sharing a type (Target lives in
// this package either way, but the two backends' internal tool-list
// representations — []toolDef vs []string — differ, which is why this isn't
// literally the same function).
//
// This list is the whole authorization story for the cli backend: internal/mcp's
// server refuses any name outside the minted grant's allowlist, hub-side, so a
// CLI talked into asking for a repository tool on an incident with no repository
// is refused by the hub rather than by the CLI's good behaviour.
func toolNamesForTarget(full []string, target Target) []string {
	out := make([]string, 0, len(full))
	for _, name := range full {
		if name == "dry_run_patch" && !target.DryRunAvailable {
			continue
		}
		if name == "query_metrics" && !target.MetricsAvailable {
			continue
		}
		if isRepoToolName(name) && !target.RepoReadable {
			continue
		}
		out = append(out, name)
	}
	return out
}

// isRepoToolName reads the answer off repoToolDefs rather than repeating the
// two names, so a repository tool added there is gated here automatically —
// the same "derived, never a second hand-maintained list" discipline
// isOfferedTool follows.
func isRepoToolName(name string) bool {
	for _, t := range repoToolDefs {
		if t.Function.Name == name {
			return true
		}
	}
	return false
}

// Investigate mints a scoped MCP token, asks the runner to drive the CLI, and
// parses the result into the same Investigation shape the api backend
// returns.
func (c *CLIInvestigator) Investigate(ctx context.Context, target Target, systemPrompt, userPrompt string, _ ToolCallback) (Investigation, error) {
	// callTool is deliberately ignored: the CLI reaches tools over MCP, not
	// through this process. Accepting and dropping it keeps one Investigator
	// interface for both backends, which is what makes the two
	// interchangeable at the call site.
	cfg, err := c.resolve(ctx)
	if err != nil {
		return Investigation{}, fmt.Errorf("resolve AI provider settings: %w", err)
	}
	if cfg.CLIRunnerURL == "" {
		return Investigation{}, fmt.Errorf("%w: no CLI runner URL configured", ErrNotConfigured)
	}
	if c.minter == nil || c.mcpURL == "" {
		return Investigation{}, fmt.Errorf("%w: CLI backend is not wired to an MCP server (no token minter or MCP URL)", ErrNotConfigured)
	}
	if target.ClusterID == "" {
		// Refused rather than defaulted: an unscoped token would be a
		// fleet-wide read grant handed to a subprocess, which is precisely
		// what SR-24 exists to prevent.
		return Investigation{}, fmt.Errorf("cli investigator: refusing to run without a cluster-scoped target")
	}

	agent := cfg.CLIAgent
	if agent == "" {
		agent = "claude"
	}

	maxTurns, timeLimit := resolveBounds(cfg)
	if timeLimit <= 0 {
		timeLimit = defaultCLITimeout
	}

	// BACKLOG.md C4: c.toolNames is the MCP server's FULL registered surface
	// (llm.InvestigationToolSchemas, which includes dry_run_patch
	// unconditionally — see that function's own doc comment for why). This
	// investigation's actual allowlist narrows it to exclude dry_run_patch
	// unless THIS cluster reported holding the argus-dryrun grant — the
	// same per-investigation decision the api backend makes in
	// offeredToolDefinitions. Doing it here, right before minting, is what
	// keeps a cluster that never opted in from ever being handed a token
	// that would let it try (and fail server-side) rather than never seeing
	// the tool at all.
	allowedTools := toolNamesForTarget(c.toolNames, target)

	// BACKLOG.md C10: ask for a self-reported causal chain ONLY when this
	// backend can actually verify one — see causalChainSystemPromptSuffix's
	// own comment for why this is appended here, per-call, rather than folded
	// into the shared SystemPrompt every backend's caller builds once before
	// knowing which backend will run it.
	if c.ledger != nil {
		systemPrompt += causalChainSystemPromptSuffix
	}

	token, err := c.minter.Mint(target.ClusterID, target.IncidentID, allowedTools)
	if err != nil {
		return Investigation{}, fmt.Errorf("mint MCP token: %w", err)
	}
	// Revoked unconditionally on every exit path, including a panic unwinding
	// through here: the TTL is a backstop for the case where this does not
	// run, not the primary lifecycle (internal/mcp/token.go's own comment).
	defer c.minter.Revoke(token)

	// The hard deadline §10.3 names as the bound that actually holds. Padded
	// past the runner's own timeout so the runner gets the chance to report a
	// clean TimedOut (which becomes a partial analysis carrying real
	// evidence) before this context cancels the HTTP call out from under it
	// (which would lose that).
	callCtx, cancel := context.WithTimeout(ctx, timeLimit+30*time.Second)
	defer cancel()

	body, err := json.Marshal(runnerRequest{
		Agent:        agent,
		SystemPrompt: systemPrompt,
		UserPrompt:   userPrompt,
		MCPURL:       c.mcpURL,
		MCPToken:     token,
		AllowedTools: allowedTools,
		MaxTurns:     maxTurns,
		TimeoutSecs:  int(timeLimit.Seconds()),
	})
	if err != nil {
		return Investigation{}, fmt.Errorf("marshal runner request: %w", err)
	}

	started := time.Now()
	url := strings.TrimSuffix(cfg.CLIRunnerURL, "/") + "/investigate"
	req, err := http.NewRequestWithContext(callCtx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return Investigation{}, fmt.Errorf("build runner request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if cfg.CLIRunnerToken != "" {
		req.Header.Set("Authorization", "Bearer "+cfg.CLIRunnerToken)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return Investigation{}, fmt.Errorf("call CLI runner: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return Investigation{}, fmt.Errorf("CLI runner returned HTTP %d", resp.StatusCode)
	}

	var out runnerResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return Investigation{}, fmt.Errorf("decode runner response: %w", err)
	}
	if out.Error != "" {
		return Investigation{}, fmt.Errorf("CLI runner: %s", out.Error)
	}

	durationMs := out.DurationMs
	if durationMs == 0 {
		durationMs = int(time.Since(started).Milliseconds())
	}
	costBasis := normalizeCostBasis(out.CostBasis)

	// A runner-reported timeout is a partial analysis, matching the api
	// backend's own bound-hit behaviour: RootCause and Confidence stay nil
	// (never numerology for an incomplete investigation,
	// lld/07-analysis-contracts.md §4), and the accounting that IS available
	// is still reported rather than zeroed.
	if out.TimedOut {
		return Investigation{
			Model:                 out.Model,
			Status:                "partial",
			PartialReason:         "time_limit",
			SuggestedNextSteps:    suggestedNextSteps(nil),
			CausalChain:           []CausalStep{},
			CausalChainProvenance: CausalChainProvenanceSelfReported,
			RuledOut:              []RuledOutHypothesis{},
			Iterations:            out.Turns,
			TokensIn:              out.TokensIn,
			TokensCacheRead:       out.TokensCacheRead,
			TokensOut:             out.TokensOut,
			DurationMs:            durationMs,
			CostUSD:               out.CostUSD,
			CostBasis:             costBasis,
		}, nil
	}

	final, err := extractFinalAnalysis(out.Content)
	if err != nil {
		// The CLI ran but its final answer did not parse. Reported as a
		// partial analysis rather than a hard error, for the same reason the
		// api backend does the same: the tool calls it made were real work
		// against a real cluster, and discarding the run entirely because the
		// last message was malformed would throw away that evidence and
		// charge for it twice on retry.
		// The answer text itself is logged, truncated, because it is otherwise
		// unrecoverable: nothing persists it (analyses has no raw-answer
		// column), so without this line a failed parse leaves no way to see
		// what the model actually said and therefore no way to tell a prompt
		// problem from a harness problem. Learned the hard way — a real
		// investigation failed this way and its answer was simply gone.
		logAnswerParseFailure(ctx, err, truncateForLog(out.Content, 2000))
		return Investigation{
			Model:         out.Model,
			Status:        "partial",
			PartialReason: "malformed_final_answer",
			// BACKLOG C2: the log line above stays (it is what a hub operator sees
			// during an incident), but the answer is now PERSISTED too, so it is
			// still there after a restart, attached to the analysis it belongs to,
			// and visible to whoever is reading the incident rather than only to
			// whoever is reading container logs.
			RawFinalAnswer:        strings.TrimSpace(out.Content),
			ParseError:            err.Error(),
			SuggestedNextSteps:    suggestedNextSteps(nil),
			CausalChain:           []CausalStep{},
			CausalChainProvenance: CausalChainProvenanceSelfReported,
			RuledOut:              []RuledOutHypothesis{},
			Iterations:            out.Turns,
			TokensIn:              out.TokensIn,
			TokensCacheRead:       out.TokensCacheRead,
			TokensOut:             out.TokensOut,
			DurationMs:            durationMs,
			CostUSD:               out.CostUSD,
			CostBasis:             costBasis,
		}, nil
	}

	rootCause := final.RootCause
	confidence := final.Confidence
	// BACKLOG.md C10: no longer unconditionally empty. final.CausalChain is
	// the model's own self-reported account of its reasoning (parsed off the
	// wire by extractFinalAnalysis, straight from finalAnalysisWire's
	// causalChain key — see causalChainStepWire's own comment for why the api
	// backend never populates this at all). crossCheckCausalChain is what
	// makes reporting it honest: every cited tool call is verified against
	// c.ledger — the hub's own mcp_tool_calls record of what this
	// investigation's token actually called — before being trusted, and a
	// citation that does not match a real, unclaimed call comes back marked
	// Corroborated: false rather than silently rendered as evidence. When no
	// ledger is wired at all, or reading it fails, this falls back to the
	// original empty chain rather than ever showing an unverifiable one — the
	// exact posture cli_investigator.go used to take unconditionally.
	causalChain := []CausalStep{}
	// Read once, independent of whether the model bothered to self-report a
	// causal chain: PROJECT.md E21's backstop below needs the REAL recorded
	// calls regardless, and a model that fabricates a root cause on empty
	// evidence has no reason to also self-report a chain admitting it — so
	// gating this ledger read on len(final.CausalChain) > 0, as the
	// crossCheckCausalChain call alone would, would make the backstop blind
	// in exactly the case it exists for.
	var real []RecordedToolCall
	ledgerOK := false
	if c.ledger != nil {
		r, ledgerErr := c.ledger(ctx, target.ClusterID, target.IncidentID)
		if ledgerErr != nil {
			logger.WarnContext(ctx, "could not read the mcp_tool_calls ledger; reporting an empty causal chain rather than an unverified one",
				logging.IncidentID(target.IncidentID), logging.ClusterID(target.ClusterID), logging.Err(ledgerErr))
		} else {
			real = r
			ledgerOK = true
		}
	}
	if ledgerOK && len(final.CausalChain) > 0 {
		causalChain = crossCheckCausalChain(final.CausalChain, real)
	}

	plan := final.Plan
	pairedPlan := final.PairedPlan
	// PROJECT.md E21's deterministic backstop (evidence_gate.go) — see
	// toolloop.go's identical check for the api backend for the full
	// rationale. Gated on ledgerOK: without a real ledger read to check
	// against, there is nothing honest to conclude about what was actually
	// gathered, so this backend falls back to the prompt alone exactly as it
	// did before this existed.
	if ledgerOK && confidence > noEvidenceConfidenceCeiling && investigationGatheredNoEvidence(real) {
		logger.WarnContext(ctx, "clamping a complete verdict's confidence: every real, hub-recorded tool call this investigation made returned no usable evidence",
			logging.IncidentID(target.IncidentID), logging.ClusterID(target.ClusterID),
			slog.Float64("model_reported_confidence", confidence))
		confidence = noEvidenceConfidenceCeiling
		plan = nil
		pairedPlan = nil
	}
	var coverage *EvidenceCoverage
	if ledgerOK {
		coverage = coverageFromRecorded(real, availabilityFor(target))
		if coverage.mostlyMissing() && confidence > partialEvidenceConfidenceCeiling {
			confidence = partialEvidenceConfidenceCeiling
		}
	}

	return Investigation{
		EvidenceCoverage:      coverage,
		Model:                 out.Model,
		Status:                "complete",
		RootCause:             &rootCause,
		Confidence:            &confidence,
		CausalChain:           causalChain,
		CausalChainProvenance: CausalChainProvenanceSelfReported,
		RuledOut:              final.RuledOut,
		Iterations:            out.Turns,
		TokensIn:              out.TokensIn,
		TokensCacheRead:       out.TokensCacheRead,
		TokensOut:             out.TokensOut,
		DurationMs:            durationMs,
		CostUSD:               out.CostUSD,
		CostBasis:             costBasis,
		ProposedPlan:          plan,
		ProposedPairedPlan:    pairedPlan,
		SuggestedNextSteps:    final.SuggestedNextSteps,
	}, nil
}

// causalChainSystemPromptSuffix is appended to the CLI backend's own copy of
// the system prompt (Investigate, above) — BACKLOG.md C10 — and ONLY when a
// ToolCallLedger is actually wired, i.e. only when the resulting chain can be
// verified. This is why it is a suffix appended here rather than a paragraph
// added to the shared SystemPrompt in toolloop.go: that function is called
// ONCE by internal/api/internal/autoanalyze, before the Router has decided
// which backend will actually run the investigation (see llm.Router), so it
// has no way to ask only "for the CLI path specifically." Appending here,
// inside the one backend that both needs this and can verify it, keeps the
// api backend's prompt (and its model's behaviour) completely untouched.
//
// What makes asking for this safe now, where it was refused before: every
// tool call cited under "toolCalls" is independently verified
// (crossCheckCausalChain) against mcp_tool_calls — the hub's own ledger of
// which calls it actually served this investigation, the same aggregate that
// already produces the "N tool calls, M failed" evidence summary
// (internal/api/evidence.go). A citation that does not match a real,
// unclaimed call is marked uncorroborated rather than rendered as evidence,
// and the resulting Investigation is always stamped
// CausalChainProvenanceSelfReported — never CausalChainProvenanceHubObserved
// — so nothing downstream can mistake a model's own account of its reasoning
// for the kind of chain the api backend builds from calls it dispatched
// itself.
const causalChainSystemPromptSuffix = `

Also report your own investigation's reasoning path as "causalChain": [{"hypothesis": "...", "toolCalls": ["<exact tool name(s) you called to test this hypothesis>", ...], "finding": "..."}, ...] — one entry per hypothesis you tested, in the order you tested them, covering the whole investigation from your first tool call to your conclusion. "toolCalls" must name only tools you actually called during THIS step, using their exact names (e.g. "get_logs", "describe_resource", "get_owner_chain") — ARGUS independently verifies every name you list here against its own record of which tool calls it actually served you this investigation, and a citation that does not match is shown to the operator as unverified rather than as evidence. Citing a tool you did not call, to make your reasoning look more thorough than it was, will be caught and will not read as evidence — name only what you actually called. "finding" is what that hypothesis's tool call(s) actually showed, in your own words, not a restatement of the hypothesis. This is required whenever you called at least one tool during this investigation; omit "causalChain" (or use an empty array) only if you reached your conclusion without calling any tool at all.`

// extractFinalAnalysis parses the final-analysis JSON out of a CLI's answer
// text, tolerating surrounding prose. It returns the same values as
// parseFinalAnalysis, and delegates to it for every candidate so the two
// backends can never disagree about what a valid final analysis IS — only
// about how much noise is allowed around it.
//
// Why this exists, concretely: the api backend owns its own loop, so its last
// assistant message is exactly what the prompt asked for and a strict
// whole-string parse is correct there (and stays strict — a model ignoring the
// instructed shape is a real failure worth surfacing). The cli backend does
// not own the loop. `claude -p` is an agentic harness whose `result` field is
// its final USER-FACING message, and it routinely prefixes a conversational
// sentence before the JSON no matter how firmly the prompt says "nothing
// else". A real 62-second, 16-iteration, 13-tool-call investigation against a
// live cluster was discarded as "malformed_final_answer" for exactly that
// reason — the whole run wasted on a leading "F". Insisting on purity from a
// harness we do not control is not a safety property, it is a guaranteed loss
// of work, so the noise is tolerated and only the JSON is required.
//
// Candidates are tried LAST-first: models narrate and then conclude, and any
// earlier brace-balanced span is far more likely to be an illustrative
// fragment mid-explanation than the verdict. A candidate only wins if it
// parses AND carries a non-empty root-cause statement, so a stray `{}` or an
// unrelated JSON snippet cannot masquerade as a conclusion.
//
// On total failure the ORIGINAL parse error is returned, not the last
// candidate's, so the logged diagnosis describes the answer as a whole rather
// than some incidental substring of it.
func extractFinalAnalysis(content string) (finalAnalysis, error) {
	final, firstErr := parseFinalAnalysis(content)
	if firstErr == nil {
		return final, nil
	}
	candidates := jsonObjectCandidates(content)
	for i := len(candidates) - 1; i >= 0; i-- {
		candidate, err := parseFinalAnalysis(candidates[i])
		if err == nil && strings.TrimSpace(candidate.RootCause.Statement) != "" {
			return candidate, nil
		}
	}
	return finalAnalysis{}, firstErr
}

// jsonObjectCandidates returns every brace-balanced span in s that could be a
// complete JSON object, outermost-first at each nesting start.
//
// The scan is string-literal aware: a `{` or `}` inside a quoted string (and
// any character after a backslash escape) is data, not structure. Without
// that, a root-cause statement mentioning a brace — entirely plausible when
// quoting manifests or Go templates — would desynchronize the depth counter
// and truncate the very object being looked for.
//
// Nested objects are not returned separately; only spans starting at depth 0
// are collected, since a sub-object of the verdict is never itself the
// verdict.
func jsonObjectCandidates(s string) []string {
	var out []string
	depth, start := 0, -1
	inString, escaped := false, false
	for i, r := range s {
		switch {
		case escaped:
			escaped = false
		case r == '\\' && inString:
			escaped = true
		case r == '"':
			inString = !inString
		case inString:
			// Braces inside a string literal are data.
		case r == '{':
			if depth == 0 {
				start = i
			}
			depth++
		case r == '}':
			if depth > 0 {
				depth--
				if depth == 0 && start >= 0 {
					// '}' is single-byte ASCII, so i+1 is the correct end
					// offset even though i is a byte index into a range over
					// runes.
					out = append(out, s[start:i+1])
					start = -1
				}
			}
		}
	}
	return out
}

// truncateForLog bounds untrusted model output before it reaches the log,
// keeping a genuinely diagnosable prefix without letting a runaway answer
// dominate the log stream.
func truncateForLog(s string, max int) string {
	s = strings.TrimSpace(s)
	if len(s) <= max {
		return s
	}
	return s[:max] + fmt.Sprintf("... [truncated, %d bytes total]", len(s))
}

// normalizeCostBasis maps anything unrecognized (including "") to
// CostBasisUnknown. Never to CostBasisMetered: defaulting an unknown basis to
// "metered" would let a fabricated cost_usd of 0 flow into the spend ceiling
// as though it were measured, which is the exact failure
// lld/07-analysis-contracts.md §10.5 is written to prevent.
func normalizeCostBasis(basis string) string {
	switch basis {
	case CostBasisMetered, CostBasisSubscription:
		return basis
	default:
		return CostBasisUnknown
	}
}
