// Command cli-runner is the CLI-agent runner service — lld/12-deployment-design.md
// §12, and the process that makes lld/14-adrs.md ADR-17's `cli` backend real.
//
// Its entire job: accept one authenticated investigation request from the hub,
// invoke a coding-agent CLI headlessly against the hub's MCP server, and
// return the CLI's final answer as JSON. It holds no database credential, no
// agent mTLS material and no plan-signing key (SR-23), and it never learns
// which cluster it is investigating — cluster scope lives inside the MCP token
// the hub mints, resolved hub-side (SR-24).
//
// Deliberately a separate binary from the hub rather than a mode of it, so the
// hub image stays distroless/read-only/shell-less (§12.1) while this one
// carries a Node runtime and the CLI's dependency tree.
//
// # On the CLI argv
//
// The exact flag surface of `claude` and `codex` is the one part of this
// design that cannot be pinned from inside this repository — it belongs to
// tools that version independently of ARGUS. Two deliberate consequences:
// every flag lives in one table (agentSpecs) rather than being scattered, and
// both the binary path and extra args are env-overridable so an operator can
// correct a drifted flag without waiting for an ARGUS release. validateAgent
// runs at startup so a wrong binary fails immediately and loudly rather than
// mid-investigation (§12.4).
package main

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"argus/internal/logging"
)

// investigateRequest mirrors internal/llm's runnerRequest. Kept as a separate
// declaration rather than a shared package: this binary is meant to be
// replaceable/reimplementable independently of the hub (an operator could run
// their own), so the protocol is a documented wire contract, not a Go type
// both sides import.
type investigateRequest struct {
	Agent        string   `json:"agent"`
	SystemPrompt string   `json:"systemPrompt"`
	UserPrompt   string   `json:"userPrompt"`
	MCPURL       string   `json:"mcpUrl"`
	MCPToken     string   `json:"mcpToken"`
	AllowedTools []string `json:"allowedTools"`
	MaxTurns     int      `json:"maxTurns"`
	TimeoutSecs  int      `json:"timeoutSeconds"`
}

// completeRequest mirrors internal/llm's completeRequest — BACKLOG.md P13's
// one-shot, tool-free sibling to investigateRequest. Deliberately smaller:
// no MCP URL/token and no tool allowlist at all, because a one-shot
// completion is never allowed to reach a tool, so there is nothing to
// configure or scope.
type completeRequest struct {
	Agent        string `json:"agent"`
	SystemPrompt string `json:"systemPrompt"`
	UserPrompt   string `json:"userPrompt"`
	TimeoutSecs  int    `json:"timeoutSeconds"`
}

type investigateResponse struct {
	Content    string  `json:"content"`
	Model      string  `json:"model"`
	Turns      int     `json:"turns"`
	DurationMs int     `json:"durationMs"`
	CostUSD    float64 `json:"costUsd"`
	CostBasis  string  `json:"costBasis"`
	TokensIn   int     `json:"tokensIn"`
	// TokensCacheRead is reported separately from TokensIn so the hub can keep
	// internal/llm.Investigation's existing TokensIn/TokensCacheRead split
	// meaningful for CLI-backed runs too, instead of leaving it at zero and
	// implying nothing was ever served from cache.
	TokensCacheRead int    `json:"tokensCacheRead"`
	TokensOut       int    `json:"tokensOut"`
	TimedOut        bool   `json:"timedOut"`
	Error           string `json:"error"`
}

// agentSpec is everything that differs between one CLI and another: the
// binary, how to ask it for a headless JSON answer, and how to read that
// answer back. Adding a third agent means adding a row here, not touching any
// other part of this file.
type agentSpec struct {
	name string
	// binary is the default executable name, overridable per-agent via
	// ARGUS_CLI_BINARY_<AGENT> (e.g. ARGUS_CLI_BINARY_CLAUDE).
	binary string
	// args builds the full argv (excluding the binary itself).
	args func(req investigateRequest, mcpConfigPath string) []string
	// completeArgs builds the full argv for a one-shot, tool-free completion
	// (BACKLOG.md P13) — no MCP config file, no --allowedTools at all,
	// because there is no MCP server wired for this call: nothing is
	// configured for the CLI to call back into. Mirrors args' own
	// belt-and-braces posture (every built-in tool explicitly denied via
	// --disallowedTools) rather than relying on "no MCP config" alone.
	completeArgs func(req completeRequest) []string
	// versionArgs asks the binary to identify itself, for startup validation.
	versionArgs []string
	// parse turns the CLI's stdout into a response. Only the CLI-specific
	// fields; the caller fills in duration and timeout state.
	parse func(stdout []byte) (investigateResponse, error)
	// mcpConfig renders the MCP server config file this agent expects.
	mcpConfig func(req investigateRequest) ([]byte, error)
	// supportsMaxTurns records whether this CLI can actually bound its own
	// turn count. Claude Code 2.0.1 cannot — it has no --max-turns flag
	// (verified against the pinned binary, not assumed) — so for that agent
	// the hard process deadline is the ONLY bound that exists, and the hub's
	// configured maxIterations is silently unenforceable. Tracked as a field
	// rather than left implicit so the log line in runInvestigation can say
	// so out loud instead of an operator discovering it from a cost report.
	supportsMaxTurns bool
}

// mcpServerName is the MCP server's local name inside the CLI's config. It
// matters beyond cosmetics: CLIs namespace MCP tools as
// mcp__<server>__<tool>, and the tool allowlist has to use those exact
// namespaced names, so this constant and namespacedTools must agree.
const mcpServerName = "argus"

func namespacedTools(tools []string) []string {
	out := make([]string, 0, len(tools))
	for _, t := range tools {
		out = append(out, fmt.Sprintf("mcp__%s__%s", mcpServerName, t))
	}
	return out
}

// httpMCPConfig is the config shape both supported CLIs accept for a
// streamable-HTTP MCP server: a single object keyed by server name, carrying
// the URL and the auth header the hub's MCP listener expects.
func httpMCPConfig(req investigateRequest) ([]byte, error) {
	return json.Marshal(map[string]any{
		"mcpServers": map[string]any{
			mcpServerName: map[string]any{
				"type": "http",
				"url":  req.MCPURL,
				"headers": map[string]string{
					"Authorization": "Bearer " + req.MCPToken,
				},
			},
		},
	})
}

var agentSpecs = map[string]agentSpec{
	"claude": {
		name:             "claude",
		binary:           "claude",
		versionArgs:      []string{"--version"},
		mcpConfig:        httpMCPConfig,
		supportsMaxTurns: false,
		// Every flag below was verified against a real `claude --help` at
		// version 2.0.1 (the version this image pins), which corrected three
		// guesses: --permission-mode has a closed choice list that does NOT
		// include a "dontAsk" value, --max-turns does not exist at all, and
		// --setting-sources is the actual mechanism for suppressing
		// project/user config discovery. See maxTurns' handling in
		// runInvestigation for what replaced the turn bound.
		args: func(req investigateRequest, mcpConfigPath string) []string {
			return []string{
				"-p", req.UserPrompt,
				"--output-format", "json",
				// Use ONLY the MCP servers in the file we just wrote, ignoring
				// any project/user-level MCP config.
				"--mcp-config", mcpConfigPath,
				"--strict-mcp-config",
				// The other half of lld/07-analysis-contracts.md §10.4's
				// "project-level configuration discovery skipped": an empty
				// source list means no user, project or local settings are
				// loaded, so no stray file in the working directory can add
				// tools, hooks or instructions to this investigation.
				"--setting-sources", "",
				// SR-22's core: an explicit allowlist of exactly the hub's
				// namespaced MCP tools, and nothing else.
				"--allowedTools", strings.Join(namespacedTools(req.AllowedTools), ","),
				// Belt and braces to the allowlist above: name every built-in
				// that can touch the filesystem, run a command, or reach the
				// network, and deny it explicitly. An allowlist alone should
				// be sufficient, but T21's whole premise is that this process
				// will eventually be talked into trying something, and a
				// second, positively-stated denial costs one flag.
				"--disallowedTools", "Bash,Read,Write,Edit,NotebookEdit,WebFetch,WebSearch,Task,TodoWrite",
				// "default" is the strictest of the four values this flag
				// actually accepts (acceptEdits/bypassPermissions/default/
				// plan). In -p mode there is no human to prompt, so a tool
				// that would need permission and is not allowlisted is simply
				// refused — which is the behaviour we want. Deliberately NOT
				// --dangerously-skip-permissions, which would bypass the very
				// checks SR-22 depends on.
				"--permission-mode", "default",
				"--append-system-prompt", req.SystemPrompt,
			}
		},
		parse: parseClaudeJSON,
		completeArgs: func(req completeRequest) []string {
			return []string{
				"-p", req.UserPrompt,
				"--output-format", "json",
				// Same discovery lockout as args() above — no stray
				// project/user/local config can add tools or instructions.
				"--setting-sources", "",
				// No --mcp-config/--strict-mcp-config/--allowedTools at
				// all: this call has no MCP server configured for it in
				// the first place, so there is nothing to allow. The
				// built-ins are still explicitly denied, matching args()'s
				// belt-and-braces posture rather than relying on "no MCP
				// config" alone to make this tool-free.
				"--disallowedTools", "Bash,Read,Write,Edit,NotebookEdit,WebFetch,WebSearch,Task,TodoWrite",
				"--permission-mode", "default",
				"--append-system-prompt", req.SystemPrompt,
			}
		},
	},
	"codex": {
		name:             "codex",
		binary:           "codex",
		versionArgs:      []string{"--version"},
		mcpConfig:        httpMCPConfig,
		supportsMaxTurns: true,
		args: func(req investigateRequest, mcpConfigPath string) []string {
			// Codex's headless surface is materially less settled than
			// Claude's, and is NOT verified against a real binary in this
			// repository — see this file's package comment. Shaped to the
			// same contract (one prompt in, JSON out, MCP config from a file,
			// tools allowlisted) so that correcting it is a change to this
			// one function plus possibly ARGUS_CLI_EXTRA_ARGS_CODEX, not a
			// redesign.
			args := []string{
				"exec",
				"--json",
				"--config", mcpConfigPath,
				"--full-auto=false",
			}
			if req.MaxTurns > 0 {
				args = append(args, "--max-turns", strconv.Itoa(req.MaxTurns))
			}
			return append(args, req.SystemPrompt+"\n\n"+req.UserPrompt)
		},
		parse: parseCodexJSON,
		completeArgs: func(req completeRequest) []string {
			// No --config at all: there is no MCP server wired for a
			// one-shot completion, so there is nothing to point codex at.
			return []string{
				"exec",
				"--json",
				"--full-auto=false",
				req.SystemPrompt + "\n\n" + req.UserPrompt,
			}
		},
	},
}

// claudeResult is the subset of `claude -p --output-format json`'s envelope
// this runner needs. Every field is optional-by-omission on purpose: a CLI
// release that adds or renames a field must degrade to "we got the text but
// not the accounting," not to a hard parse failure that discards a completed
// investigation.
// claudeResult is the shape of `claude -p --output-format json`'s single
// result object, as emitted by the pinned binary (2.0.1) — field names taken
// from real output, not from documentation.
//
// Two of these fields exist because the obvious reading of that output was
// wrong:
//
//   - There is NO top-level "model" key. The model is reported only as the
//     KEY of the modelUsage map (e.g. "claude-sonnet-4-5-20250929"), so
//     decoding into a Model string silently yielded "" for every run and the
//     hub recorded every CLI analysis with an empty model. ModelUsage below
//     is what actually carries it.
//   - usage.input_tokens counts ONLY fresh, uncached prompt tokens. For an
//     agentic CLI that caches aggressively this is a small fraction of the
//     real prompt: a verified run reported input_tokens=3 alongside
//     cache_creation_input_tokens=14415. Reading input_tokens alone
//     understated usage by ~3 orders of magnitude, so the cache counters are
//     read too and folded in by claudeTokens.
type claudeResult struct {
	Type         string  `json:"type"`
	Subtype      string  `json:"subtype"`
	Result       string  `json:"result"`
	IsError      bool    `json:"is_error"`
	TotalCostUSD float64 `json:"total_cost_usd"`
	NumTurns     int     `json:"num_turns"`
	DurationMS   int     `json:"duration_ms"`
	// Model is read opportunistically in case a future version adds the
	// top-level key this struct originally assumed; modelUsage is the real
	// source today. See modelName.
	Model      string                `json:"model"`
	ModelUsage map[string]modelUsage `json:"modelUsage"`
	Usage      claudeUsage           `json:"usage"`
}

// claudeUsage mirrors the result object's `usage` block. The two cache
// counters are the difference between a believable token figure and one that
// is wrong by three orders of magnitude — see claudeResult.
type claudeUsage struct {
	InputTokens              int `json:"input_tokens"`
	OutputTokens             int `json:"output_tokens"`
	CacheCreationInputTokens int `json:"cache_creation_input_tokens"`
	CacheReadInputTokens     int `json:"cache_read_input_tokens"`
}

// modelUsage is one entry of the result object's `modelUsage` map. Only the
// fields this runner reports are decoded; note the camelCase keys, which
// differ from the snake_case used in `usage` above (that inconsistency is in
// the CLI's own output, not a transcription error here).
type modelUsage struct {
	InputTokens              int `json:"inputTokens"`
	OutputTokens             int `json:"outputTokens"`
	CacheCreationInputTokens int `json:"cacheCreationInputTokens"`
	CacheReadInputTokens     int `json:"cacheReadInputTokens"`
}

// modelName resolves which model actually served the run. Prefers a
// top-level field if one ever appears, then the modelUsage keys — joined when
// a single run spanned more than one model (the CLI may fall back mid-run, and
// reporting only one of them would misattribute the usage). Sorted so the
// value is stable rather than dependent on Go's map iteration order.
func (r claudeResult) modelName() string {
	if r.Model != "" {
		return r.Model
	}
	names := make([]string, 0, len(r.ModelUsage))
	for name := range r.ModelUsage {
		names = append(names, name)
	}
	sort.Strings(names)
	return strings.Join(names, "+")
}

// claudeTokens returns (fresh-input, cache-read, output).
//
// Fresh input deliberately includes cache CREATION tokens: those are prompt
// tokens the provider genuinely processed and charged a write premium for,
// so grouping them with cached reads would understate the run. Cache READS
// stay separate, matching internal/llm.Investigation's own
// TokensIn/TokensCacheRead split.
//
// The `usage` block is preferred; modelUsage is summed as a fallback for the
// case where usage is absent but per-model figures are present.
func (r claudeResult) claudeTokens() (in, cacheRead, out int) {
	in = r.Usage.InputTokens + r.Usage.CacheCreationInputTokens
	cacheRead = r.Usage.CacheReadInputTokens
	out = r.Usage.OutputTokens
	if in == 0 && cacheRead == 0 && out == 0 {
		for _, m := range r.ModelUsage {
			in += m.InputTokens + m.CacheCreationInputTokens
			cacheRead += m.CacheReadInputTokens
			out += m.OutputTokens
		}
	}
	return in, cacheRead, out
}

func parseClaudeJSON(stdout []byte) (investigateResponse, error) {
	var r claudeResult
	if err := json.Unmarshal(bytes.TrimSpace(stdout), &r); err != nil {
		return investigateResponse{}, fmt.Errorf("parse claude JSON output: %w", err)
	}
	if r.IsError {
		return investigateResponse{}, fmt.Errorf("claude reported an error result (subtype %q)", r.Subtype)
	}
	tokensIn, tokensCacheRead, tokensOut := r.claudeTokens()
	return investigateResponse{
		Content:         r.Result,
		Model:           r.modelName(),
		Turns:           r.NumTurns,
		DurationMs:      r.DurationMS,
		CostUSD:         r.TotalCostUSD,
		CostBasis:       costBasisFor("claude", r.TotalCostUSD),
		TokensIn:        tokensIn,
		TokensCacheRead: tokensCacheRead,
		TokensOut:       tokensOut,
	}, nil
}

// parseCodexJSON reads Codex's streaming-JSON output, keeping the last
// message that carries text. Tolerant by design, for the same reason
// claudeResult's fields are all optional.
func parseCodexJSON(stdout []byte) (investigateResponse, error) {
	var last investigateResponse
	var sawAny bool
	for _, line := range strings.Split(string(stdout), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || !strings.HasPrefix(line, "{") {
			continue
		}
		var ev struct {
			Type    string  `json:"type"`
			Text    string  `json:"text"`
			Message string  `json:"message"`
			Model   string  `json:"model"`
			CostUSD float64 `json:"total_cost_usd"`
			Usage   struct {
				InputTokens  int `json:"input_tokens"`
				OutputTokens int `json:"output_tokens"`
			} `json:"usage"`
		}
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			continue
		}
		text := ev.Text
		if text == "" {
			text = ev.Message
		}
		if text != "" {
			last.Content = text
			sawAny = true
		}
		if ev.Model != "" {
			last.Model = ev.Model
		}
		if ev.CostUSD > 0 {
			last.CostUSD = ev.CostUSD
		}
		if ev.Usage.InputTokens > 0 {
			last.TokensIn = ev.Usage.InputTokens
		}
		if ev.Usage.OutputTokens > 0 {
			last.TokensOut = ev.Usage.OutputTokens
		}
	}
	if !sawAny {
		return investigateResponse{}, errors.New("codex produced no parsable text output")
	}
	last.CostBasis = costBasisFor("codex", last.CostUSD)
	return last, nil
}

// costBasisFor decides what a reported cost actually means —
// lld/07-analysis-contracts.md §10.5.
//
// PROJECT.md B169: an earlier version of this function trusted
// ARGUS_CLI_AUTH_MODE as the ONLY source of truth for "this run is
// subscription-billed." That works only while the operator both sets it and
// keeps it set — unset (the default; nothing requires it), a real
// subscription run's notional cost was written cost_basis='metered' and
// summed straight into the daily spend ceiling as money nobody was charged.
// 21 analyses (all `claude-sonnet-4-5-*`, live-measured 2026-09-18; migration
// 000080 hand-corrected two of the earliest such rows before this fix) carry
// exactly that pollution.
//
// The fix is to derive the basis from something this process already knows
// about itself rather than a fact an operator must separately remember to
// declare: WHICH credential the CLI actually authenticated with for this
// specific agent. cliEnv's passthrough list draws the line for us —
// CLAUDE_CODE_OAUTH_TOKEN is Claude Code's own flat-rate subscription
// credential (minted by `claude setup-token` against a Claude subscription;
// there is no other channel that produces one), so its presence for a
// "claude" run is itself the fact "this run is not billed per token." Every
// other credential this runner ever passes through — ANTHROPIC_API_KEY/
// ANTHROPIC_AUTH_TOKEN, the Bedrock/Vertex enterprise-cloud switches, or
// Codex's OPENAI_API_KEY — is billed per token by whoever issued it, so none
// of those implies "notional." credentialImpliesSubscription checks exactly
// that, keyed to the agent this particular run used (not just "is any such
// var set anywhere in this process's env," which would mislabel a codex run
// sharing a container with an idle claude subscription credential).
//
// ARGUS_CLI_AUTH_MODE is still honoured, but only as an operator override
// that can ADD "subscription" for a credential shape this function doesn't
// recognise yet — it can never remove the derived answer, so an unset or
// stale override can no longer mislabel a run whose credential we can
// already identify.
//
// An earlier version of this function also checked `cost > 0` first, on the
// assumption that a subscription-authenticated CLI reports no cost at all.
// That assumption is false, and was only caught by running the real binary:
// Claude Code under subscription auth still populates total_cost_usd with a
// NOTIONAL what-this-would-have-cost-on-the-API figure — a verified 0.054
// for a two-token smoke-test prompt. So a zero cost with no subscription
// signal at all is still "unknown," never metered-zero.
func costBasisFor(agentName string, cost float64) string {
	if credentialImpliesSubscription(agentName) {
		return "subscription"
	}
	if strings.EqualFold(os.Getenv("ARGUS_CLI_AUTH_MODE"), "subscription") {
		return "subscription"
	}
	if cost > 0 {
		return "metered"
	}
	return "unknown"
}

// credentialImpliesSubscription reports whether the credential THIS agent
// will actually authenticate with is a flat-rate subscription credential,
// derived from the same passthrough env vars cliEnv already reads — nothing
// new to configure or remember. See costBasisFor's doc comment for why only
// "claude" has one today.
func credentialImpliesSubscription(agentName string) bool {
	switch agentName {
	case "claude":
		return os.Getenv("CLAUDE_CODE_OAUTH_TOKEN") != ""
	default:
		// "codex" only ever authenticates with OPENAI_API_KEY here (see
		// cliEnv's passthrough list), which is metered by definition — there
		// is no subscription-shaped credential for it in this runner today.
		return false
	}
}

type server struct {
	authToken string
	// sem bounds concurrent CLI processes. Each is a real OS process with a
	// real memory footprint, so this is the difference between shedding load
	// and OOMKilling the container (§12.5).
	sem       chan struct{}
	queueSlot chan struct{}
}

// logger is this binary's package-local structured logger (PROJECT.md T22).
var logger = logging.For("cli-runner")

// fatal is the structured replacement for log.Fatalf: log at ERROR, then
// exit non-zero. The bridge cannot infer a level from a fatal's text, so an
// unconverted log.Fatalf came out at INFO.
func fatal(msg string, attrs ...any) {
	logger.Error(msg, attrs...)
	os.Exit(1)
}

func main() {
	// PROJECT.md T22, first statement in the process: install the structured
	// JSON logging chain and bridge the standard `log` package into it, so
	// every line this binary writes is levelled, redacted JSON.
	logging.Setup()
	addr := flag.String("addr", envOr("ARGUS_CLI_RUNNER_ADDR", ":8090"), "listen address")
	maxInFlight := flag.Int("max-in-flight", envOrInt("ARGUS_CLI_MAX_IN_FLIGHT", 2), "max concurrent CLI invocations")
	queueDepth := flag.Int("queue-depth", envOrInt("ARGUS_CLI_QUEUE_DEPTH", 16), "max queued requests before shedding")
	flag.Parse()

	authToken := os.Getenv("ARGUS_CLI_RUNNER_TOKEN")
	if authToken == "" {
		// Fail closed. An unauthenticated runner is a service that will run a
		// model against your credential for anyone who can reach it, which in
		// `mode: deployment` means anything with pod-network access.
		fatal("ARGUS_CLI_RUNNER_TOKEN is required (refusing to serve unauthenticated)")
	}

	// Startup validation (§12.4): confirm every agent we might be asked for
	// actually exists, before any request arrives. A missing binary becomes a
	// startup failure an operator sees in the pod's logs, not a per-incident
	// error discovered at 3am.
	validated := 0
	for name := range agentSpecs {
		if v, err := validateAgent(name); err != nil {
			logger.Debug("CLI agent unavailable", slog.String("agent", name), logging.Err(err))
		} else {
			logger.Info("CLI agent available", slog.String("agent", name), slog.String("version", v))
			validated++
		}
	}
	if validated == 0 {
		fatal("no supported CLI agent is installed or executable (checked: claude, codex)")
	}

	s := &server{
		authToken: authToken,
		sem:       make(chan struct{}, max(1, *maxInFlight)),
		queueSlot: make(chan struct{}, max(1, *maxInFlight)+max(0, *queueDepth)),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /investigate", s.handleInvestigate)
	mux.HandleFunc("POST /complete", s.handleComplete)
	mux.HandleFunc("GET /healthz", s.handleHealthz)

	srv := &http.Server{
		Addr:              *addr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}
	logger.Info("cli-runner listening",
		slog.String("addr", *addr), slog.Int("max_in_flight", *maxInFlight), slog.Int("queue_depth", *queueDepth))
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		fatal("the cli-runner listener failed", logging.Err(err))
	}
}

// handleHealthz reports which agents are actually usable. Deliberately
// unauthenticated and free of any configuration detail: it is a liveness
// probe target, so it must not require a credential, and it must not become a
// way to enumerate configuration.
func (s *server) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	agents := map[string]string{}
	for name := range agentSpecs {
		if v, err := validateAgent(name); err == nil {
			agents[name] = v
		}
	}
	w.Header().Set("Content-Type", "application/json")
	if len(agents) == 0 {
		w.WriteHeader(http.StatusServiceUnavailable)
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"agents": agents})
}

func (s *server) handleInvestigate(w http.ResponseWriter, r *http.Request) {
	if !s.authorized(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	var req investigateRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<20)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, investigateResponse{Error: "malformed request body"})
		return
	}
	if req.MCPURL == "" || req.MCPToken == "" {
		writeJSON(w, http.StatusBadRequest, investigateResponse{Error: "mcpUrl and mcpToken are required"})
		return
	}
	if len(req.AllowedTools) == 0 {
		// Refused rather than defaulted to "all tools": an empty allowlist
		// reaching the CLI would either offer nothing (a useless run) or, on a
		// CLI that treats empty as unrestricted, offer everything including
		// its own shell. Neither is acceptable, so this is a bad request.
		writeJSON(w, http.StatusBadRequest, investigateResponse{Error: "allowedTools must be non-empty"})
		return
	}

	// Shed rather than queue without bound (§12.5).
	select {
	case s.queueSlot <- struct{}{}:
		defer func() { <-s.queueSlot }()
	default:
		writeJSON(w, http.StatusServiceUnavailable, investigateResponse{Error: "analysis capacity exhausted; retry later"})
		return
	}

	select {
	case s.sem <- struct{}{}:
		defer func() { <-s.sem }()
	case <-r.Context().Done():
		writeJSON(w, http.StatusServiceUnavailable, investigateResponse{Error: "request cancelled while queued"})
		return
	}

	resp := runInvestigation(r.Context(), req)
	writeJSON(w, http.StatusOK, resp)
}

// handleComplete is BACKLOG.md P13's one-shot, tool-free sibling to
// handleInvestigate: same auth, same concurrency-shedding posture, but no
// mcpUrl/mcpToken/allowedTools requirement at all — a one-shot completion
// never reaches a tool, so there is nothing to configure or scope, and
// requiring an MCP wiring here would just be an obstacle to a call that
// does not need one.
func (s *server) handleComplete(w http.ResponseWriter, r *http.Request) {
	if !s.authorized(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	var req completeRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, investigateResponse{Error: "malformed request body"})
		return
	}
	if strings.TrimSpace(req.UserPrompt) == "" {
		writeJSON(w, http.StatusBadRequest, investigateResponse{Error: "userPrompt is required"})
		return
	}

	// Shed rather than queue without bound (§12.5) — the same posture and
	// the same shared semaphore as handleInvestigate: a one-shot completion
	// and a full investigation both spend a real OS process out of the same
	// bounded pool.
	select {
	case s.queueSlot <- struct{}{}:
		defer func() { <-s.queueSlot }()
	default:
		writeJSON(w, http.StatusServiceUnavailable, investigateResponse{Error: "analysis capacity exhausted; retry later"})
		return
	}

	select {
	case s.sem <- struct{}{}:
		defer func() { <-s.sem }()
	case <-r.Context().Done():
		writeJSON(w, http.StatusServiceUnavailable, investigateResponse{Error: "request cancelled while queued"})
		return
	}

	resp := runCompletion(r.Context(), req)
	writeJSON(w, http.StatusOK, resp)
}

func (s *server) authorized(r *http.Request) bool {
	presented := strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
	return subtle.ConstantTimeCompare([]byte(presented), []byte(s.authToken)) == 1
}

// runInvestigation is the actual CLI invocation.
func runInvestigation(ctx context.Context, req investigateRequest) investigateResponse {
	agentName := req.Agent
	if agentName == "" {
		agentName = "claude"
	}
	spec, ok := agentSpecs[agentName]
	if !ok {
		return investigateResponse{Error: fmt.Sprintf("unsupported agent %q", agentName)}
	}

	// A per-invocation scratch directory serving as both HOME and working
	// directory. Two reasons, both from lld/07-analysis-contracts.md §10.4:
	// the CLI needs a writable HOME for its own state, and starting from an
	// empty directory means no stray project config, agent-instruction file or
	// hook can alter this investigation's behaviour. Removed afterwards, so
	// nothing carries between investigations.
	workDir, err := os.MkdirTemp("", "argus-cli-*")
	if err != nil {
		return investigateResponse{Error: fmt.Sprintf("create work dir: %v", err)}
	}
	defer os.RemoveAll(workDir)

	mcpConfig, err := spec.mcpConfig(req)
	if err != nil {
		return investigateResponse{Error: fmt.Sprintf("render MCP config: %v", err)}
	}
	mcpPath := workDir + "/mcp.json"
	// 0600: the file contains the scoped MCP bearer token.
	if err := os.WriteFile(mcpPath, mcpConfig, 0o600); err != nil {
		return investigateResponse{Error: fmt.Sprintf("write MCP config: %v", err)}
	}

	if req.MaxTurns > 0 && !spec.supportsMaxTurns {
		// Said plainly rather than swallowed: the hub asked for a turn bound
		// this CLI has no way to honour, so only the deadline below applies.
		logger.WarnContext(ctx, "the CLI agent cannot enforce a turn limit; the process deadline is the only active bound",
			slog.String("agent", spec.name), slog.Int("requested_max_turns", req.MaxTurns),
			slog.Int("timeout_secs", req.TimeoutSecs))
	}

	args := append(spec.args(req, mcpPath), extraArgs(spec.name)...)
	return execAgent(ctx, spec, args, workDir, time.Duration(req.TimeoutSecs)*time.Second)
}

// runCompletion is Complete's actual CLI invocation — BACKLOG.md P13's
// one-shot, tool-free sibling to runInvestigation. No MCP config is written
// at all (there is no MCP server for this call to reach), which is the only
// structural difference from runInvestigation above; the rest (scratch
// workDir/HOME, process-group teardown, deadline, parsing) is identical, so
// both call the same execAgent helper rather than duplicating it.
func runCompletion(ctx context.Context, req completeRequest) investigateResponse {
	agentName := req.Agent
	if agentName == "" {
		agentName = "claude"
	}
	spec, ok := agentSpecs[agentName]
	if !ok {
		return investigateResponse{Error: fmt.Sprintf("unsupported agent %q", agentName)}
	}
	if spec.completeArgs == nil {
		// Should not happen given both entries in agentSpecs define one
		// today, but an agent added later without one must be refused
		// explicitly rather than invoked with a nil func value.
		return investigateResponse{Error: fmt.Sprintf("agent %q does not support one-shot completion", agentName)}
	}

	workDir, err := os.MkdirTemp("", "argus-cli-complete-*")
	if err != nil {
		return investigateResponse{Error: fmt.Sprintf("create work dir: %v", err)}
	}
	defer os.RemoveAll(workDir)

	args := append(spec.completeArgs(req), extraArgs(spec.name)...)
	return execAgent(ctx, spec, args, workDir, time.Duration(req.TimeoutSecs)*time.Second)
}

// execAgent runs one CLI invocation to completion (or its deadline) and
// parses the result — the shared second half of both runInvestigation and
// runCompletion, which differ only in how they build workDir/args before
// calling this.
func execAgent(ctx context.Context, spec agentSpec, args []string, workDir string, timeout time.Duration) investigateResponse {
	if timeout <= 0 {
		timeout = 10 * time.Minute
	}
	// The hard deadline lld/07-analysis-contracts.md §10.3 names as the bound
	// that actually holds, as opposed to --max-turns which the CLI is merely
	// asked to honour.
	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := exec.CommandContext(runCtx, binaryFor(spec), args...)
	cmd.Dir = workDir
	cmd.Env = cliEnv(workDir)

	// Two settings that together stop a hung CLI from wedging this service
	// permanently. Without them: cmd.Run() waits for the stdout/stderr copying
	// goroutines to finish *after* the process exits, and these CLIs are Node
	// programs that routinely spawn helper processes. If CommandContext kills
	// the direct child while a grandchild still holds the pipe, Run blocks
	// forever — the deferred semaphore release never happens, and after
	// maxInFlight such events every request is refused while /healthz keeps
	// reporting the agent available, so nothing ever restarts the container.
	//
	// Setpgid puts the CLI in its own process group and Cancel signals the
	// whole group, so helpers die with their parent rather than surviving it.
	// WaitDelay is the backstop for anything that still holds the pipe: Run
	// gives up on the copy and returns instead of blocking indefinitely.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		// Negative PID = the whole process group.
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
	cmd.WaitDelay = 10 * time.Second

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	started := time.Now()
	runErr := cmd.Run()
	elapsed := int(time.Since(started).Milliseconds())

	// Timeout is a partial result, not an error: the hub turns this into a
	// partial analysis that still records whatever the run cost.
	if errors.Is(runCtx.Err(), context.DeadlineExceeded) {
		logger.WarnContext(ctx, "the CLI agent exceeded its deadline",
			slog.String("agent", spec.name), slog.Duration("timeout", timeout))
		return investigateResponse{TimedOut: true, DurationMs: elapsed, CostBasis: costBasisFor(spec.name, 0)}
	}
	if runErr != nil {
		// stderr is truncated into the error: a CLI's stderr can be long, and
		// the hub logs this verbatim.
		return investigateResponse{
			Error:      fmt.Sprintf("agent %s failed: %v: %s", spec.name, runErr, truncate(stderr.String(), 2000)),
			DurationMs: elapsed,
		}
	}

	resp, err := spec.parse(stdout.Bytes())
	if err != nil {
		return investigateResponse{
			Error:      fmt.Sprintf("agent %s output unparsable: %v", spec.name, err),
			DurationMs: elapsed,
		}
	}
	if resp.DurationMs == 0 {
		resp.DurationMs = elapsed
	}
	if resp.CostBasis == "" {
		resp.CostBasis = costBasisFor(spec.name, resp.CostUSD)
	}
	return resp
}

// cliEnv builds the child process environment: HOME pointed at the scratch
// directory, plus an explicit passthrough allowlist.
//
// An allowlist rather than os.Environ() because this process's environment
// contains its own ARGUS_CLI_RUNNER_TOKEN, and there is no reason for a CLI
// subprocess — the very process T21 is about — to be able to read the
// credential that authenticates its caller.
func cliEnv(homeDir string) []string {
	env := []string{
		"HOME=" + homeDir,
		"PATH=" + os.Getenv("PATH"),
	}
	// Model-provider credentials and the knobs the CLIs themselves read. The
	// operator supplies whichever their chosen auth mode needs
	// (lld/07-analysis-contracts.md §10.7 — ARGUS never ships one).
	passthrough := []string{
		"ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "ANTHROPIC_BASE_URL",
		"CLAUDE_CODE_OAUTH_TOKEN", "CLAUDE_CODE_USE_BEDROCK", "CLAUDE_CODE_USE_VERTEX",
		"OPENAI_API_KEY", "OPENAI_BASE_URL",
		"AWS_REGION", "AWS_DEFAULT_REGION", "AWS_ROLE_ARN", "AWS_WEB_IDENTITY_TOKEN_FILE",
		"GOOGLE_APPLICATION_CREDENTIALS", "CLOUD_ML_REGION",
		"NO_PROXY", "HTTP_PROXY", "HTTPS_PROXY",
	}
	for _, k := range passthrough {
		if v := os.Getenv(k); v != "" {
			env = append(env, k+"="+v)
		}
	}
	return env
}

func binaryFor(spec agentSpec) string {
	if v := os.Getenv("ARGUS_CLI_BINARY_" + strings.ToUpper(spec.name)); v != "" {
		return v
	}
	return spec.binary
}

// extraArgs lets an operator append or correct flags without a new image —
// the escape hatch this file's package comment argues for, given the CLIs
// version independently of ARGUS.
func extraArgs(agent string) []string {
	raw := os.Getenv("ARGUS_CLI_EXTRA_ARGS_" + strings.ToUpper(agent))
	if raw == "" {
		return nil
	}
	return strings.Fields(raw)
}

func validateAgent(name string) (string, error) {
	spec, ok := agentSpecs[name]
	if !ok {
		return "", fmt.Errorf("unknown agent %q", name)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, binaryFor(spec), spec.versionArgs...).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("%s %s: %w", binaryFor(spec), strings.Join(spec.versionArgs, " "), err)
	}
	return strings.TrimSpace(strings.SplitN(string(out), "\n", 2)[0]), nil
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…(truncated)"
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func envOrInt(key string, fallback int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return fallback
}
