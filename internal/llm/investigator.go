package llm

// This file is lld/14-adrs.md ADR-17's seam: one interface, two kinds of
// backend behind it. lld/07-analysis-contracts.md §10.1 explains why the
// seam is here — at the whole-investigation level — rather than at the HTTP
// client: a CLI backend does not expose a per-turn chat-completions call for
// this package to intercept, so the loop itself is the unit that differs.
// Everything downstream of Investigate (internal/remediation's plan schema,
// the risk gate, the approval queue, the analyses row) is unaffected by
// construction, which is the property that makes the second backend addable
// without touching the parts of the system carrying real safety weight.

import (
	"context"
	"encoding/json"
	"fmt"

	"argus/internal/settings"
)

// ToolSchema is one investigation tool, in the provider-neutral shape a CLI
// backend's MCP surface needs (internal/mcp) — name, description, and the raw
// JSON Schema for its arguments.
//
// This exists so internal/mcp never imports this package: it would otherwise
// have to, for the schemas, while this package needs internal/mcp for token
// minting — a cycle. The schemas travel as data instead (see
// InvestigationToolSchemas), and minting travels as the TokenMinter interface
// below.
type ToolSchema struct {
	Name        string
	Description string
	InputSchema json.RawMessage
}

// InvestigationToolSchemas is toolloop.go's fixed toolDefinitions PLUS
// dryRunPatchToolDef and queryMetricsToolDef, projected into ToolSchema.
// Deliberately derived from those same package-level declarations rather
// than re-declared: the api backend's tool surface and the cli backend's MCP
// surface must be identical by construction, not by two hand-maintained
// lists that could drift.
//
// dry_run_patch and query_metrics are both included here UNCONDITIONALLY —
// this function is called once, at hub startup (cmd/hub/main.go), to
// register the MCP server's static tool catalog, which has no
// per-investigation notion of "this cluster". The per-cluster restriction
// (BACKLOG.md C4: only offer/allow dry_run_patch when Target.DryRunAvailable,
// query_metrics when Target.MetricsAvailable) is enforced one layer down, at
// the point a token is actually minted for one investigation —
// CLIInvestigator.Investigate computes that investigation's allowedTools
// list and passes it to TokenMinter.Mint, which is what internal/mcp's
// server actually authorizes a call against (internal/mcp/token.go's
// Grant.AllowedTools) — never by varying what schemas this function returns.
// A tool being REGISTERED on the MCP server is not the same claim as it
// being CALLABLE by any given token; only the latter is scoped per cluster.
//
// internal/remediation's real execution actions are still never present
// here — the invariant lld/07-analysis-contracts.md §10.4 requires. Unlike
// dry_run_patch, they have no server-side dry-run restriction bounding
// them, so they stay strictly off the investigation surface, in both
// backends, always.
func InvestigationToolSchemas() []ToolSchema {
	defs := append(append([]toolDef{}, toolDefinitions...), dryRunPatchToolDef, queryMetricsToolDef)
	// The repository tools are registered unconditionally too, and gated the
	// same way: per-investigation, at the point a token is minted
	// (toolNamesForTarget), never by varying what this function returns.
	// Unlike every other tool here they are executed by the HUB rather than
	// dispatched to a cluster agent — cmd/hub's ToolFunc dispatches on the
	// name (repotools.IsRepoTool) — so registering one here is a claim about
	// the surface, not about which executor serves it.
	defs = append(defs, repoToolDefs...)
	out := make([]ToolSchema, 0, len(defs))
	for _, t := range defs {
		out = append(out, ToolSchema{
			Name:        t.Function.Name,
			Description: t.Function.Description,
			InputSchema: t.Function.Parameters,
		})
	}
	return out
}

// Target identifies what is being investigated. The api backend does not need
// it — its callTool closure already carries the cluster it dispatches to — but
// the cli backend genuinely does: it cannot use that closure (the CLI calls
// the hub's MCP server directly, not back through Go), so it has to mint a
// cluster-scoped MCP token, and the cluster identity has to arrive here to do
// that.
//
// Passed explicitly rather than smuggled through a context value, so the
// requirement is visible in the signature: a backend that needs to know which
// cluster it is allowed to touch should say so in its type, not read it out of
// ambient state where a caller can silently forget to set it.
type Target struct {
	ClusterID  string
	IncidentID string

	// DryRunAvailable is BACKLOG.md C4's gate for the seventh, write-capable
	// investigation tool (dry_run_patch): whether THIS cluster's agent has
	// actually reported holding the opt-in argus-dryrun grant (see
	// internal/tunnel.ClusterDryRun and internal/api's
	// ClusterDryRunAvailable, which resolves this from the cluster's latest
	// reported cluster_facts row — never from a chart-value assumption).
	//
	// Both backends read this to decide whether to offer/allow
	// dry_run_patch for THIS investigation: the api backend
	// (toolloop.go's offeredToolDefinitions/isOfferedTool) folds it directly
	// into the tools it advertises to the model; the cli backend
	// (cli_investigator.go) folds it into the allowedTools list minted into
	// the MCP token and passed to the runner, so a cluster that never
	// enabled the pack is never even offered a tool call that would fail
	// server-side anyway.
	DryRunAvailable bool

	// MetricsAvailable is BACKLOG.md C4's gate for query_metrics: whether THIS
	// cluster's agent has actually reported holding the RBAC grant a
	// configured metrics.prometheusService needs (see
	// internal/tunnel.ClusterMetrics and internal/api's
	// ClusterMetricsAvailable, which resolves this from the cluster's latest
	// reported cluster_facts row — never from the chart value alone). Applied
	// by both backends exactly the way DryRunAvailable is.
	MetricsAvailable bool

	// RepoReadable is BACKLOG.md F22's gate for the two read-only repository
	// tools (list_repo_files, read_repo_file): whether THIS incident's object
	// resolves to a registered repository binding at a pinned synced commit,
	// so there is actually a source tree to read.
	//
	// A property of the incident, not of the cluster — which is the difference
	// from DryRunAvailable above. Two incidents on the same cluster can differ:
	// one object is Argo-managed with a resolved revision, the next was applied
	// by hand and names no repository at all.
	//
	// Resolved by non-AI code before the model is asked anything
	// (internal/api/analyze.go and internal/autoanalyze both call
	// api.IncidentRepoScope), and applied by both backends the same way
	// DryRunAvailable is: the api backend folds it into offeredToolDefinitions/
	// isOfferedTool, the cli backend into the allowedTools list minted into the
	// MCP token. A model on an incident with no repository is never shown a
	// tool whose only possible answer is "there is no repository".
	RepoReadable bool
}

// Investigator is what internal/api and internal/autoanalyze depend on,
// instead of the concrete *Provider they used to hold. Deliberately covers
// Investigate only: Provider.Complete has no callers anywhere in this repo
// (verified, not assumed), so widening this interface to include it would be
// inventing a requirement rather than describing one.
type Investigator interface {
	Investigate(ctx context.Context, target Target, systemPrompt, userPrompt string, callTool ToolCallback) (Investigation, error)
}

// TokenMinter is the slice of internal/mcp.Store the cli backend needs.
// Declared here, satisfied there — the direction that keeps internal/mcp free
// of any dependency on this package (see ToolSchema's doc comment).
type TokenMinter interface {
	Mint(clusterID, incidentID string, allowedTools []string) (string, error)
	Revoke(token string)
}

// Compile-time assertions that both backends really satisfy the interface —
// cheaper to find here than at the call site.
var (
	_ Investigator = (*Provider)(nil)
	_ Investigator = (*Router)(nil)
	_ Completer    = (*Router)(nil)
)

// Router resolves the configured provider kind fresh on every call and
// dispatches to the matching backend. Same "resolve per call, never cache"
// discipline Provider.Investigate and Provider.Complete already follow
// (internal/settings.Resolve, DB-overrides-env), for the same reason: a
// provider-kind change made through Settings must take effect on the very
// next investigation without a hub restart.
//
// Router is what cmd/hub wires into api.NewServer and autoanalyze.New. The
// concrete backends stay independently constructible and independently
// testable — Router adds dispatch, not behaviour.
type Router struct {
	api Investigator
	cli Investigator
	// resolve is settings.Resolve in production, swappable in tests so
	// dispatch can be exercised without a live database.
	resolve func(ctx context.Context) (settings.Config, error)
}

// NewRouter wires the two backends. Either may be nil: a nil backend means
// "this deployment cannot serve that kind," and selecting it yields a clear
// configuration error rather than a nil-pointer panic — which is the normal
// state for cli in a default install, where no runner is deployed at all
// (lld/12-deployment-design.md §12).
func NewRouter(apiBackend, cliBackend Investigator, resolve func(ctx context.Context) (settings.Config, error)) *Router {
	return &Router{api: apiBackend, cli: cliBackend, resolve: resolve}
}

// CLIBackendAvailable reports whether this deployment has a CLI backend wired
// at all — i.e. whether ARGUS_MCP_ADDR was set when the hub started.
//
// Exposed because the settings UI needs it and could not otherwise know: a
// `cli` provider can be configured completely and correctly (runner URL, token,
// agent) and still be unusable, because the missing piece is a hub-level env
// var rather than anything about the provider. Without this the UI happily lets
// an operator activate such a provider and the failure surfaces only when they
// click Analyze — which is exactly what happened (BUGS.md 39's investigation).
func (r *Router) CLIBackendAvailable() bool { return r.cli != nil }

// APIBackendAvailable is the same question for the API backend, for symmetry —
// a deployment with neither wired should be able to say so.
func (r *Router) APIBackendAvailable() bool { return r.api != nil }

// Investigate dispatches on settings.Config.LLMProviderKind.
//
// An unrecognized kind is a hard error, never a silent fallback to the api
// backend. Falling back would be actively harmful in exactly the case that
// matters: an operator who configured cli specifically because their
// deployment must not make metered API calls would get billed API calls
// instead, quietly. lld/07-analysis-contracts.md §10 makes the same argument
// against automatic api fallback on CLI failure.
func (r *Router) Investigate(ctx context.Context, target Target, systemPrompt, userPrompt string, callTool ToolCallback) (Investigation, error) {
	cfg, err := r.resolve(ctx)
	if err != nil {
		return Investigation{}, fmt.Errorf("resolve AI provider settings: %w", err)
	}

	switch kind := settings.NormalizeProviderKind(cfg.LLMProviderKind); kind {
	case settings.ProviderKindAPI:
		if r.api == nil {
			return Investigation{}, fmt.Errorf("%w: provider kind %q selected but no API backend is wired", ErrNotConfigured, kind)
		}
		return r.api.Investigate(ctx, target, systemPrompt, userPrompt, callTool)
	case settings.ProviderKindCLI:
		if r.cli == nil {
			// The common, non-exceptional case: cli selected in Settings but
			// no runner deployed. ErrNotConfigured-wrapped so every existing
			// caller's "AI provider not configured" handling (a 503 in
			// internal/api/analyze.go, an attempted-and-logged skip in
			// internal/autoanalyze) applies unchanged.
			return Investigation{}, fmt.Errorf("%w: the active AI provider is a CLI runner, but this hub has no MCP listener, which the CLI backend needs in order to serve tools back to the runner. Set ARGUS_MCP_ADDR on the hub and restart it, or switch to an API provider in Settings. Nothing about the provider's own configuration is wrong", ErrNotConfigured)
		}
		return r.cli.Investigate(ctx, target, systemPrompt, userPrompt, callTool)
	default:
		return Investigation{}, fmt.Errorf("unrecognized AI provider kind %q (want %q or %q)", cfg.LLMProviderKind, settings.ProviderKindAPI, settings.ProviderKindCLI)
	}
}

// RunSource names what an investigation is about to run on, as far as that
// is knowable before it starts: the backend kind ("api" or "cli") and, for
// the api backend, the configured model. Model is empty for the cli backend —
// the CLI agent picks its own model and reports it only in its result.
type RunSource struct {
	Backend string
	Model   string
}

// Preflight answers "would Investigate refuse to start right now?" without
// starting anything, and names the backend it would use. It mirrors the
// configuration checks Investigate and the two backends make before their
// first model call — backend wired, base URL / runner URL present — and
// returns the same ErrNotConfigured-wrapped errors, so POST
// /incidents/{id}/analyze, which now answers before the investigation runs,
// can still refuse a run that could never start with a 503 rather than
// accepting it and failing it a moment later.
//
// It is a preflight, not a guarantee: settings can change between this call
// and Investigate's own resolve, and Investigate still makes every check
// itself.
func (r *Router) Preflight(ctx context.Context) (RunSource, error) {
	cfg, err := r.resolve(ctx)
	if err != nil {
		return RunSource{}, fmt.Errorf("resolve AI provider settings: %w", err)
	}
	switch kind := settings.NormalizeProviderKind(cfg.LLMProviderKind); kind {
	case settings.ProviderKindAPI:
		if r.api == nil {
			return RunSource{}, fmt.Errorf("%w: provider kind %q selected but no API backend is wired", ErrNotConfigured, kind)
		}
		if cfg.LLMBaseURL == "" {
			return RunSource{}, fmt.Errorf("%w: no API base URL configured", ErrNotConfigured)
		}
		return RunSource{Backend: kind, Model: cfg.LLMModel}, nil
	case settings.ProviderKindCLI:
		if r.cli == nil {
			return RunSource{}, fmt.Errorf("%w: the active AI provider is a CLI runner, but this hub has no MCP listener, which the CLI backend needs in order to serve tools back to the runner. Set ARGUS_MCP_ADDR on the hub and restart it, or switch to an API provider in Settings. Nothing about the provider's own configuration is wrong", ErrNotConfigured)
		}
		if cfg.CLIRunnerURL == "" {
			return RunSource{}, fmt.Errorf("%w: no CLI runner URL configured", ErrNotConfigured)
		}
		return RunSource{Backend: kind}, nil
	default:
		return RunSource{}, fmt.Errorf("unrecognized AI provider kind %q (want %q or %q)", cfg.LLMProviderKind, settings.ProviderKindAPI, settings.ProviderKindCLI)
	}
}

// Complete is Investigate's one-shot, tool-free sibling — BACKLOG.md P13.
// It dispatches on settings.Config.LLMProviderKind exactly the way
// Investigate does, and for the same reason: an operator who configured
// `cli` specifically must get the cli backend's answer, never a silent api
// fallback (or vice versa).
//
// Before P13 this had no cli-kind path at all: *Provider's Complete is a
// plain chat-completions POST against LLMBaseURL, which a cli-kind
// provider's row carries only as unused/stale leftover data (BUGS.md 125) —
// every real caller of Complete (the condition-polarity gate,
// CorrectPlanParams below) was silently dead on any deployment whose
// configured provider is `cli`, which is every deployment actually running
// investigations, since `cli` is what an operator configures in Settings.
//
// r.api/r.cli are asserted against Completer here (rather than the field
// type being Completer directly) because Router's own fields stay
// Investigator — the type Investigate needs — and adding a second,
// parallel pair of Completer-typed fields to hold literally the same two
// backend instances would be two ways to express one fact. A backend that
// does not implement Completer at all (a future third backend, or a test
// fake built only for Investigate) reports ErrNotConfigured for Complete
// rather than failing to compile or panicking.
func (r *Router) Complete(ctx context.Context, systemPrompt, userPrompt string) (Result, error) {
	cfg, err := r.resolve(ctx)
	if err != nil {
		return Result{}, fmt.Errorf("resolve AI provider settings: %w", err)
	}

	switch kind := settings.NormalizeProviderKind(cfg.LLMProviderKind); kind {
	case settings.ProviderKindAPI:
		c, ok := r.api.(Completer)
		if !ok {
			return Result{}, fmt.Errorf("%w: provider kind %q selected but no API backend is wired", ErrNotConfigured, kind)
		}
		return c.Complete(ctx, systemPrompt, userPrompt)
	case settings.ProviderKindCLI:
		c, ok := r.cli.(Completer)
		if !ok {
			if r.cli == nil {
				return Result{}, fmt.Errorf("%w: the active AI provider is a CLI runner, but this hub has no MCP listener wired (ARGUS_MCP_ADDR unset). A one-shot completion does not itself need MCP tools, but the cli backend is only constructed alongside the listener today — set ARGUS_MCP_ADDR on the hub and restart it, or switch to an API provider in Settings", ErrNotConfigured)
			}
			return Result{}, fmt.Errorf("%w: provider kind %q selected but the wired CLI backend does not support one-shot completion", ErrNotConfigured, kind)
		}
		return c.Complete(ctx, systemPrompt, userPrompt)
	default:
		return Result{}, fmt.Errorf("unrecognized AI provider kind %q (want %q or %q)", cfg.LLMProviderKind, settings.ProviderKindAPI, settings.ProviderKindCLI)
	}
}
