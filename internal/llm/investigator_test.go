package llm

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"argus/internal/settings"
)

// fakeInvestigator records that it was called, so dispatch can be asserted
// without a real provider or runner.
type fakeInvestigator struct {
	name   string
	calls  int
	target Target
}

func (f *fakeInvestigator) Investigate(_ context.Context, target Target, _, _ string, _ ToolCallback) (Investigation, error) {
	f.calls++
	f.target = target
	return Investigation{Model: f.name, Status: "complete"}, nil
}

func fixedConfig(cfg settings.Config) func(context.Context) (settings.Config, error) {
	return func(context.Context) (settings.Config, error) { return cfg, nil }
}

func TestRouterDispatchesOnProviderKind(t *testing.T) {
	cases := []struct {
		name     string
		kind     string
		wantCall string
	}{
		// "" is the state every deployment is in before anyone picks a kind
		// (migration 000033 adds the column NULLable with no default), and it
		// must route to api — the behaviour those installs already had.
		{"unset defaults to api", "", "api"},
		{"explicit api", settings.ProviderKindAPI, "api"},
		{"explicit cli", settings.ProviderKindCLI, "cli"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			apiBackend := &fakeInvestigator{name: "api"}
			cliBackend := &fakeInvestigator{name: "cli"}
			r := NewRouter(apiBackend, cliBackend, fixedConfig(settings.Config{LLMProviderKind: tc.kind}))

			got, err := r.Investigate(context.Background(), Target{ClusterID: "cl_1", IncidentID: "inc_1"}, "sys", "user", nil)
			if err != nil {
				t.Fatalf("Investigate: %v", err)
			}
			if got.Model != tc.wantCall {
				t.Errorf("dispatched to %q, want %q", got.Model, tc.wantCall)
			}
			if tc.wantCall == "api" && cliBackend.calls != 0 {
				t.Error("cli backend must not be called for the api kind")
			}
			if tc.wantCall == "cli" && apiBackend.calls != 0 {
				t.Error("api backend must not be called for the cli kind")
			}
		})
	}
}

func TestRouterPassesTargetThrough(t *testing.T) {
	// The cli backend cannot mint a cluster-scoped MCP token without this, so
	// a Router that dropped it would silently break SR-24's scoping.
	cliBackend := &fakeInvestigator{name: "cli"}
	r := NewRouter(nil, cliBackend, fixedConfig(settings.Config{LLMProviderKind: settings.ProviderKindCLI}))
	want := Target{ClusterID: "cl_abc", IncidentID: "inc_xyz"}
	if _, err := r.Investigate(context.Background(), want, "sys", "user", nil); err != nil {
		t.Fatalf("Investigate: %v", err)
	}
	if cliBackend.target != want {
		t.Errorf("backend received target %+v, want %+v", cliBackend.target, want)
	}
}

func TestRouterUnknownKindIsAHardErrorNotAnAPIFallback(t *testing.T) {
	// Falling back to api would bill an operator who chose cli specifically to
	// avoid metered calls. That must not happen quietly.
	apiBackend := &fakeInvestigator{name: "api"}
	r := NewRouter(apiBackend, &fakeInvestigator{name: "cli"}, fixedConfig(settings.Config{LLMProviderKind: "gemini-cli"}))

	_, err := r.Investigate(context.Background(), Target{ClusterID: "cl_1"}, "sys", "user", nil)
	if err == nil {
		t.Fatal("an unrecognized provider kind should be an error")
	}
	if !strings.Contains(err.Error(), "gemini-cli") {
		t.Errorf("error should name the offending value, got %v", err)
	}
	if apiBackend.calls != 0 {
		t.Error("an unrecognized kind must NEVER fall back to the api backend")
	}
}

func TestRouterMissingBackendReportsNotConfigured(t *testing.T) {
	// The normal state of a default install: cli selected, no runner deployed.
	// Must be ErrNotConfigured so existing callers' handling (a 503 from
	// internal/api/analyze.go, an attempted-and-logged skip in
	// internal/autoanalyze) applies unchanged.
	r := NewRouter(&fakeInvestigator{name: "api"}, nil, fixedConfig(settings.Config{LLMProviderKind: settings.ProviderKindCLI}))
	_, err := r.Investigate(context.Background(), Target{ClusterID: "cl_1"}, "sys", "user", nil)
	if !errors.Is(err, ErrNotConfigured) {
		t.Errorf("err = %v, want it to wrap ErrNotConfigured", err)
	}
}

func TestRouterPropagatesResolveFailure(t *testing.T) {
	r := NewRouter(&fakeInvestigator{name: "api"}, nil, func(context.Context) (settings.Config, error) {
		return settings.Config{}, errors.New("db down")
	})
	if _, err := r.Investigate(context.Background(), Target{ClusterID: "cl_1"}, "s", "u", nil); err == nil {
		t.Fatal("a settings-resolution failure must not be swallowed")
	}
}

// fakeCompleterInvestigator implements both Investigator and Completer, so
// Router.Complete's dispatch (BACKLOG.md P13) can be exercised without a
// real *Provider or *CLIInvestigator — mirroring fakeInvestigator's role for
// Investigate, one level up.
type fakeCompleterInvestigator struct {
	name          string
	completeCalls int
	text          string
	err           error
}

func (f *fakeCompleterInvestigator) Investigate(_ context.Context, _ Target, _, _ string, _ ToolCallback) (Investigation, error) {
	return Investigation{Model: f.name, Status: "complete"}, nil
}

func (f *fakeCompleterInvestigator) Complete(_ context.Context, _, _ string) (Result, error) {
	f.completeCalls++
	if f.err != nil {
		return Result{}, f.err
	}
	return Result{Text: f.text, Model: f.name}, nil
}

// TestRouterCompleteDispatchesOnProviderKind is Complete's own version of
// TestRouterDispatchesOnProviderKind above — BACKLOG.md P13's whole point:
// Complete's real callers (the polarity gate, CorrectPlanParams) must reach
// whichever provider kind is actually configured, not always api.
func TestRouterCompleteDispatchesOnProviderKind(t *testing.T) {
	cases := []struct {
		name     string
		kind     string
		wantCall string
	}{
		{"unset defaults to api", "", "api"},
		{"explicit api", settings.ProviderKindAPI, "api"},
		{"explicit cli", settings.ProviderKindCLI, "cli"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			apiBackend := &fakeCompleterInvestigator{name: "api", text: "api answer"}
			cliBackend := &fakeCompleterInvestigator{name: "cli", text: "cli answer"}
			r := NewRouter(apiBackend, cliBackend, fixedConfig(settings.Config{LLMProviderKind: tc.kind}))

			got, err := r.Complete(context.Background(), "sys", "user")
			if err != nil {
				t.Fatalf("Complete: %v", err)
			}
			if got.Model != tc.wantCall {
				t.Errorf("dispatched to %q, want %q", got.Model, tc.wantCall)
			}
			if tc.wantCall == "api" && cliBackend.completeCalls != 0 {
				t.Error("cli backend must not be called for the api kind")
			}
			if tc.wantCall == "cli" && apiBackend.completeCalls != 0 {
				t.Error("api backend must not be called for the cli kind")
			}
		})
	}
}

func TestRouterCompleteUnknownKindIsAHardError(t *testing.T) {
	apiBackend := &fakeCompleterInvestigator{name: "api"}
	r := NewRouter(apiBackend, &fakeCompleterInvestigator{name: "cli"}, fixedConfig(settings.Config{LLMProviderKind: "gemini-cli"}))

	_, err := r.Complete(context.Background(), "sys", "user")
	if err == nil {
		t.Fatal("an unrecognized provider kind should be an error")
	}
	if !strings.Contains(err.Error(), "gemini-cli") {
		t.Errorf("error should name the offending value, got %v", err)
	}
	if apiBackend.completeCalls != 0 {
		t.Error("an unrecognized kind must NEVER fall back to the api backend")
	}
}

func TestRouterCompleteMissingBackendReportsNotConfigured(t *testing.T) {
	r := NewRouter(&fakeCompleterInvestigator{name: "api"}, nil, fixedConfig(settings.Config{LLMProviderKind: settings.ProviderKindCLI}))
	_, err := r.Complete(context.Background(), "sys", "user")
	if !errors.Is(err, ErrNotConfigured) {
		t.Errorf("err = %v, want it to wrap ErrNotConfigured", err)
	}
}

// TestRouterCompleteBackendWithoutCompleterSupport confirms a wired backend
// that satisfies Investigator but NOT Completer (a bare fakeInvestigator,
// standing in for a hypothetical future backend added for Investigate only)
// reports ErrNotConfigured for Complete rather than panicking on a failed
// type assertion.
func TestRouterCompleteBackendWithoutCompleterSupport(t *testing.T) {
	r := NewRouter(&fakeInvestigator{name: "api"}, nil, fixedConfig(settings.Config{LLMProviderKind: settings.ProviderKindAPI}))
	_, err := r.Complete(context.Background(), "sys", "user")
	if !errors.Is(err, ErrNotConfigured) {
		t.Errorf("err = %v, want it to wrap ErrNotConfigured", err)
	}
}

func TestRouterCompletePropagatesResolveFailure(t *testing.T) {
	r := NewRouter(&fakeCompleterInvestigator{name: "api"}, nil, func(context.Context) (settings.Config, error) {
		return settings.Config{}, errors.New("db down")
	})
	if _, err := r.Complete(context.Background(), "s", "u"); err == nil {
		t.Fatal("a settings-resolution failure must not be swallowed")
	}
}

func TestInvestigationToolSchemasAreReadOnly(t *testing.T) {
	// The invariant lld/07-analysis-contracts.md §10.4 requires: the MCP
	// surface offered to a CLI never contains a REAL, human-approval-gated
	// remediation EXECUTION action. If someone adds one of those to
	// toolDefinitions, this fails loudly here rather than quietly exposing
	// it to a subprocess.
	//
	// dry_run_patch is deliberately NOT in this list (BACKLOG.md C4,
	// ADR-14). It is not an execution action — approving nothing, running
	// unattended, changing nothing that survives the request — it is an
	// investigation-time tool restricted to dryRun=All by the cluster's own
	// ValidatingAdmissionPolicy (deploy/helm/argus-agent/templates/
	// dryrun.yaml), the same category §10.4 already treats get_events/
	// describe_resource/etc. as safe to expose. Its presence here is
	// intentional; TestDryRunPatchGatedByAvailability (this file) is what
	// actually protects the per-cluster restriction on whether it is ever
	// ALLOWED to be called.
	writeTools := map[string]bool{
		"scale_deployment":       true,
		"restart_pod":            true,
		"patch_resource_limits":  true,
		"revert_container_image": true,
		"patch_field":            true,
		"open_pr":                true,
	}
	schemas := InvestigationToolSchemas()
	if len(schemas) == 0 {
		t.Fatal("expected a non-empty tool surface")
	}
	for _, s := range schemas {
		if writeTools[s.Name] {
			t.Errorf("tool %q is a real remediation execution action and must never appear in the MCP surface", s.Name)
		}
		if s.Name == "" || s.Description == "" || len(s.InputSchema) == 0 {
			t.Errorf("tool %+v is missing a name, description or schema — a CLI needs all three", s)
		}
	}
}

func TestInvestigationToolSchemasMatchToolDefinitions(t *testing.T) {
	// The projection must stay total: one entry per toolDefinitions entry
	// plus dryRunPatchToolDef, so the api backend's tools and the cli
	// backend's MCP tools cannot drift. See InvestigationToolSchemas' own
	// doc comment for why dry_run_patch is included here UNCONDITIONALLY
	// (the per-cluster restriction is enforced at Mint time, not by varying
	// this projection).
	if got, want := len(InvestigationToolSchemas()), len(toolDefinitions)+2+len(repoToolDefs); got != want {
		t.Errorf("projected %d schemas, want %d (the fixed tools, plus dry_run_patch, plus query_metrics, plus the repository tools) — the projection dropped or added some", got, want)
	}
}

// TestDryRunPatchGatedByAvailability is the cli backend's half of
// BACKLOG.md C4's gating contract — the api backend's half is
// toolloop_test.go's TestDryRunPatchOfferedOnlyWhenAvailable. dry_run_patch
// is always REGISTERED (InvestigationToolSchemas, above) but must only ever
// be GRANTED — i.e. present in the list minted into an MCP token and handed
// to the runner — when the target cluster reported the argus-dryrun grant.
func TestDryRunPatchGatedByAvailability(t *testing.T) {
	full := InvestigationToolSchemas()
	names := make([]string, 0, len(full))
	for _, s := range full {
		names = append(names, s.Name)
	}

	// RepoReadable and MetricsAvailable are held TRUE throughout, so this test
	// still isolates the dry-run dimension — BACKLOG.md F22/C4 added two more
	// gates to the same function and a test that varied more than one at once
	// would stop proving any of them individually.
	without := toolNamesForTarget(names, Target{DryRunAvailable: false, MetricsAvailable: true, RepoReadable: true})
	for _, n := range without {
		if n == "dry_run_patch" {
			t.Error("toolNamesForTarget without the grant includes dry_run_patch — must be excluded when the cluster has not reported the grant")
		}
	}
	if len(without) != len(names)-1 {
		t.Errorf("toolNamesForTarget without the grant returned %d names, want %d (every registered tool except dry_run_patch)", len(without), len(names)-1)
	}

	with := toolNamesForTarget(names, Target{DryRunAvailable: true, MetricsAvailable: true, RepoReadable: true})
	if len(with) != len(names) {
		t.Errorf("toolNamesForTarget with the grant returned %d names, want all %d registered tools", len(with), len(names))
	}
	found := false
	for _, n := range with {
		if n == "dry_run_patch" {
			found = true
		}
	}
	if !found {
		t.Error("toolNamesForTarget with the grant does not include dry_run_patch")
	}
}

// TestQueryMetricsGatedByAvailability is BACKLOG.md C4's other cli-backend
// gating contract, the exact mirror of TestDryRunPatchGatedByAvailability
// above: query_metrics is always REGISTERED (InvestigationToolSchemas) but
// must only ever be GRANTED when the target cluster reported the metrics
// authorization.
func TestQueryMetricsGatedByAvailability(t *testing.T) {
	full := InvestigationToolSchemas()
	names := make([]string, 0, len(full))
	for _, s := range full {
		names = append(names, s.Name)
	}

	// DryRunAvailable and RepoReadable are held TRUE throughout, isolating
	// the metrics dimension.
	without := toolNamesForTarget(names, Target{DryRunAvailable: true, MetricsAvailable: false, RepoReadable: true})
	for _, n := range without {
		if n == "query_metrics" {
			t.Error("toolNamesForTarget without the grant includes query_metrics — must be excluded when the cluster has not reported the grant")
		}
	}
	if len(without) != len(names)-1 {
		t.Errorf("toolNamesForTarget without the grant returned %d names, want %d (every registered tool except query_metrics)", len(without), len(names)-1)
	}

	with := toolNamesForTarget(names, Target{DryRunAvailable: true, MetricsAvailable: true, RepoReadable: true})
	if len(with) != len(names) {
		t.Errorf("toolNamesForTarget with the grant returned %d names, want all %d registered tools", len(with), len(names))
	}
	found := false
	for _, n := range with {
		if n == "query_metrics" {
			found = true
		}
	}
	if !found {
		t.Error("toolNamesForTarget with the grant does not include query_metrics")
	}
}

// TestRepoToolsGatedByRepoReadable is BACKLOG.md F22's cli-backend gating
// contract, the exact mirror of the dry_run_patch one above: the repository
// tools are always REGISTERED but must only ever be GRANTED — present in the
// allowlist minted into an MCP token — for an incident that actually resolves
// to a readable repository. The grant allowlist is what makes a tool reachable
// on this backend at all (internal/mcp's server refuses anything outside it),
// so this is the whole authorization story for these two tools there.
func TestRepoToolsGatedByRepoReadable(t *testing.T) {
	full := InvestigationToolSchemas()
	names := make([]string, 0, len(full))
	for _, s := range full {
		names = append(names, s.Name)
	}
	if len(repoToolDefs) == 0 {
		t.Fatal("no repository tools declared — this test would pass vacuously")
	}

	without := toolNamesForTarget(names, Target{DryRunAvailable: true, MetricsAvailable: true, RepoReadable: false})
	for _, n := range without {
		if isRepoToolName(n) {
			t.Errorf("toolNamesForTarget granted %q for an incident with no readable repository", n)
		}
	}
	if len(without) != len(names)-len(repoToolDefs) {
		t.Errorf("granted %d names, want %d (every registered tool except the repository ones)", len(without), len(names)-len(repoToolDefs))
	}

	with := toolNamesForTarget(names, Target{DryRunAvailable: true, MetricsAvailable: true, RepoReadable: true})
	granted := map[string]bool{}
	for _, n := range with {
		granted[n] = true
	}
	for _, def := range repoToolDefs {
		if !granted[def.Function.Name] {
			t.Errorf("toolNamesForTarget did not grant %q for an incident with a readable repository", def.Function.Name)
		}
	}
}

func TestNormalizeCostBasis(t *testing.T) {
	// lld/07-analysis-contracts.md §10.5: anything unrecognized becomes
	// "unknown", never "metered". Defaulting to metered would let a
	// fabricated $0.00 flow into the spend ceiling as though measured.
	cases := map[string]string{
		CostBasisMetered:      CostBasisMetered,
		CostBasisSubscription: CostBasisSubscription,
		CostBasisUnknown:      CostBasisUnknown,
		"":                    CostBasisUnknown,
		"free":                CostBasisUnknown,
		"METERED":             CostBasisUnknown, // case-sensitive on purpose: the column's CHECK is too
	}
	for in, want := range cases {
		if got := normalizeCostBasis(in); got != want {
			t.Errorf("normalizeCostBasis(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestCLIInvestigatorRefusesUnscopedTarget(t *testing.T) {
	// Mirrors the Store-side check: an unscoped run would need an unscoped
	// token, so it is refused before one could be minted.
	c := NewCLIInvestigator(&fakeMinter{}, []string{"get_events"}, "http://mcp/mcp",
		fixedConfig(settings.Config{CLIRunnerURL: "http://runner:8090"}), nil)
	_, err := c.Investigate(context.Background(), Target{}, "sys", "user", nil)
	if err == nil || !strings.Contains(err.Error(), "cluster-scoped") {
		t.Errorf("err = %v, want a refusal naming the missing cluster scope", err)
	}
}

func TestCLIInvestigatorRequiresRunnerURL(t *testing.T) {
	c := NewCLIInvestigator(&fakeMinter{}, []string{"get_events"}, "http://mcp/mcp",
		fixedConfig(settings.Config{}), nil)
	_, err := c.Investigate(context.Background(), Target{ClusterID: "cl_1"}, "sys", "user", nil)
	if !errors.Is(err, ErrNotConfigured) {
		t.Errorf("err = %v, want ErrNotConfigured when no runner URL is configured", err)
	}
}

func TestCLIInvestigatorRequiresMCPWiring(t *testing.T) {
	// A CLI backend with no MCP server to point the CLI at cannot work, and
	// must say so rather than dialing an empty URL.
	c := NewCLIInvestigator(nil, []string{"get_events"}, "",
		fixedConfig(settings.Config{CLIRunnerURL: "http://runner:8090"}), nil)
	_, err := c.Investigate(context.Background(), Target{ClusterID: "cl_1"}, "sys", "user", nil)
	if !errors.Is(err, ErrNotConfigured) {
		t.Errorf("err = %v, want ErrNotConfigured when the MCP server isn't wired", err)
	}
}

// TestCLIInvestigatorEndToEndAgainstFakeRunner exercises the whole hub-side
// protocol against a stand-in runner: request shape out, response shape in,
// token minted before and revoked after, and the result mapped into the same
// Investigation shape the api backend produces.
func TestCLIInvestigatorEndToEndAgainstFakeRunner(t *testing.T) {
	var gotReq runnerRequest
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/investigate" {
			t.Errorf("runner called at %q, want /investigate", r.URL.Path)
		}
		gotAuth = r.Header.Get("Authorization")
		if err := json.NewDecoder(r.Body).Decode(&gotReq); err != nil {
			t.Errorf("decode runner request: %v", err)
		}
		// The pinned final-analysis JSON a real CLI is asked to produce — the
		// same shape the api backend's own last turn emits, which is why this
		// backend reuses parseFinalAnalysis rather than having its own parser.
		final := `{"rootCause":{"statement":"node memory exhausted"},"confidence":0.82,` +
			`"ruledOut":[{"hypothesis":"image pull failure","reason":"image digest resolved fine"}]}`
		_ = json.NewEncoder(w).Encode(runnerResponse{
			Content:   final,
			Model:     "claude-sonnet-5",
			Turns:     4,
			CostUSD:   0.0731,
			CostBasis: CostBasisMetered,
			TokensIn:  1200,
			TokensOut: 300,
		})
	}))
	defer srv.Close()

	minter := &fakeMinter{}
	c := NewCLIInvestigator(minter, []string{"get_events", "get_logs"}, "http://hub:9090/mcp",
		fixedConfig(settings.Config{
			CLIRunnerURL:   srv.URL,
			CLIRunnerToken: "runner-secret",
			CLIAgent:       "claude",
		}), nil)

	got, err := c.Investigate(context.Background(), Target{ClusterID: "cl_9", IncidentID: "inc_9"}, "SYSTEM", "USER", nil)
	if err != nil {
		t.Fatalf("Investigate: %v", err)
	}

	// Request side.
	if gotAuth != "Bearer runner-secret" {
		t.Errorf("runner Authorization = %q, want the configured bearer token", gotAuth)
	}
	if gotReq.Agent != "claude" || gotReq.SystemPrompt != "SYSTEM" || gotReq.UserPrompt != "USER" {
		t.Errorf("runner request = %+v, want agent/prompts passed through verbatim", gotReq)
	}
	if gotReq.MCPToken != "test-token" || gotReq.MCPURL != "http://hub:9090/mcp" {
		t.Errorf("runner request MCP wiring = %q at %q, want the minted token and configured URL", gotReq.MCPToken, gotReq.MCPURL)
	}
	if len(gotReq.AllowedTools) != 2 {
		t.Errorf("allowedTools = %v, want both configured tools", gotReq.AllowedTools)
	}
	if gotReq.MaxTurns <= 0 || gotReq.TimeoutSecs <= 0 {
		t.Errorf("bounds not sent: maxTurns=%d timeout=%d", gotReq.MaxTurns, gotReq.TimeoutSecs)
	}

	// Token lifecycle: minted for the right cluster, and revoked afterwards
	// rather than left to expire.
	if minter.minted != 1 || minter.last != "cl_9" {
		t.Errorf("minted %d token(s) for cluster %q, want 1 for cl_9", minter.minted, minter.last)
	}
	if minter.revoked != 1 {
		t.Errorf("revoked %d token(s), want 1 — a finished investigation must not leave a live token", minter.revoked)
	}

	// Result side.
	if got.Status != "complete" {
		t.Errorf("Status = %q, want complete", got.Status)
	}
	if got.RootCause == nil || got.RootCause.Statement != "node memory exhausted" {
		t.Errorf("RootCause = %+v, want the parsed statement", got.RootCause)
	}
	if got.Confidence == nil || *got.Confidence != 0.82 {
		t.Errorf("Confidence = %v, want 0.82", got.Confidence)
	}
	if len(got.RuledOut) != 1 {
		t.Errorf("RuledOut = %+v, want the one parsed entry", got.RuledOut)
	}
	if got.CostUSD != 0.0731 || got.CostBasis != CostBasisMetered {
		t.Errorf("cost = %v/%q, want the runner's reported figure and basis", got.CostUSD, got.CostBasis)
	}
	if got.Iterations != 4 || got.TokensIn != 1200 || got.TokensOut != 300 {
		t.Errorf("accounting = turns %d, in %d, out %d — want the runner's figures", got.Iterations, got.TokensIn, got.TokensOut)
	}
	// Empty, never fabricated: this process never observed the CLI's turns.
	if len(got.CausalChain) != 0 {
		t.Errorf("CausalChain = %+v, want empty — inventing steps would look like evidence", got.CausalChain)
	}
}

func TestCLIInvestigatorTimeoutBecomesPartialAnalysis(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(runnerResponse{TimedOut: true, Turns: 3, TokensIn: 900, CostBasis: CostBasisSubscription})
	}))
	defer srv.Close()

	c := NewCLIInvestigator(&fakeMinter{}, []string{"get_events"}, "http://hub/mcp",
		fixedConfig(settings.Config{CLIRunnerURL: srv.URL}), nil)
	got, err := c.Investigate(context.Background(), Target{ClusterID: "cl_1"}, "s", "u", nil)
	if err != nil {
		t.Fatalf("a runner timeout should be a partial result, not an error: %v", err)
	}
	if got.Status != "partial" || got.PartialReason != "time_limit" {
		t.Errorf("got %q/%q, want partial/time_limit", got.Status, got.PartialReason)
	}
	// Never numerology for an incomplete investigation (§4).
	if got.RootCause != nil || got.Confidence != nil {
		t.Errorf("partial result carried RootCause=%v Confidence=%v, want both nil", got.RootCause, got.Confidence)
	}
	// The accounting that IS available is still reported, not zeroed.
	if got.TokensIn != 900 || got.Iterations != 3 {
		t.Errorf("partial result dropped real accounting: in=%d turns=%d", got.TokensIn, got.Iterations)
	}
	if len(got.SuggestedNextSteps) == 0 {
		t.Error("a partial analysis must carry suggestedNextSteps")
	}
}

func TestCLIInvestigatorMalformedFinalAnswerBecomesPartial(t *testing.T) {
	// The CLI ran and did real work; only its last message was unparsable.
	// Discarding the run would throw away that evidence and pay for it twice.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(runnerResponse{Content: "I could not determine a root cause, sorry!", Turns: 2, CostUSD: 0.01, CostBasis: CostBasisMetered})
	}))
	defer srv.Close()

	c := NewCLIInvestigator(&fakeMinter{}, []string{"get_events"}, "http://hub/mcp",
		fixedConfig(settings.Config{CLIRunnerURL: srv.URL}), nil)
	got, err := c.Investigate(context.Background(), Target{ClusterID: "cl_1"}, "s", "u", nil)
	if err != nil {
		t.Fatalf("unparsable final answer should not be a hard error: %v", err)
	}
	if got.Status != "partial" || got.PartialReason != "malformed_final_answer" {
		t.Errorf("got %q/%q, want partial/malformed_final_answer — a parse failure must not masquerade as a budget bound", got.Status, got.PartialReason)
	}
	if got.CostUSD != 0.01 {
		t.Errorf("CostUSD = %v, want the real cost of the work that did happen", got.CostUSD)
	}
}

func TestCLIInvestigatorRunnerErrorIsAnError(t *testing.T) {
	// Distinct from TimedOut: a runner-side failure (CLI missing, bad flags)
	// means the investigation never happened, and must not be recorded as a
	// partial analysis implying real work occurred.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(runnerResponse{Error: "agent claude failed: executable not found"})
	}))
	defer srv.Close()

	c := NewCLIInvestigator(&fakeMinter{}, []string{"get_events"}, "http://hub/mcp",
		fixedConfig(settings.Config{CLIRunnerURL: srv.URL}), nil)
	_, err := c.Investigate(context.Background(), Target{ClusterID: "cl_1"}, "s", "u", nil)
	if err == nil || !strings.Contains(err.Error(), "executable not found") {
		t.Errorf("err = %v, want the runner's own error surfaced", err)
	}
}

func TestCLIInvestigatorRevokesTokenEvenWhenTheRunnerFails(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	minter := &fakeMinter{}
	c := NewCLIInvestigator(minter, []string{"get_events"}, "http://hub/mcp",
		fixedConfig(settings.Config{CLIRunnerURL: srv.URL}), nil)
	if _, err := c.Investigate(context.Background(), Target{ClusterID: "cl_1"}, "s", "u", nil); err == nil {
		t.Fatal("expected an error for a 500 from the runner")
	}
	if minter.revoked != 1 {
		t.Errorf("revoked %d, want 1 — a failed investigation must not leave a live token behind", minter.revoked)
	}
}

// --- BACKLOG.md P13: CLIInvestigator.Complete, the one-shot tool-free path ---

// TestCLIInvestigatorCompleteRequiresRunnerURL mirrors
// TestCLIInvestigatorRequiresRunnerURL for Complete: no minter, no MCP URL
// and no target are given at all, because Complete needs none of them —
// only cfg.CLIRunnerURL matters.
func TestCLIInvestigatorCompleteRequiresRunnerURL(t *testing.T) {
	c := NewCLIInvestigator(nil, nil, "", fixedConfig(settings.Config{}), nil)
	_, err := c.Complete(context.Background(), "sys", "user")
	if !errors.Is(err, ErrNotConfigured) {
		t.Errorf("err = %v, want ErrNotConfigured when no runner URL is configured", err)
	}
}

// TestCLIInvestigatorCompleteAgainstFakeRunner is Complete's end-to-end
// proof, the direct analogue of TestCLIInvestigatorEndToEndAgainstFakeRunner:
// a fake runner answers a POST to /complete (not /investigate), and the
// result's text/model/token accounting comes back exactly as reported. No
// minter is given at all, and the request the fake runner receives carries
// no mcpUrl/mcpToken/allowedTools field with any content — proving this call
// never touches MCP, matching the doc comment's claim that no token is
// minted because there is nothing to scope.
func TestCLIInvestigatorCompleteAgainstFakeRunner(t *testing.T) {
	var gotPath string
	var gotReq completeRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		_ = json.NewDecoder(r.Body).Decode(&gotReq)
		_ = json.NewEncoder(w).Encode(completeResponse{
			Content:         "True",
			Model:           "claude-sonnet-4-5",
			DurationMs:      842,
			CostUSD:         0.01,
			CostBasis:       CostBasisMetered,
			TokensIn:        120,
			TokensCacheRead: 30,
			TokensOut:       4,
		})
	}))
	defer srv.Close()

	c := NewCLIInvestigator(nil, nil, "", fixedConfig(settings.Config{CLIRunnerURL: srv.URL, CLIAgent: "claude"}), nil)
	got, err := c.Complete(context.Background(), "system prompt", "user prompt")
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if gotPath != "/complete" {
		t.Errorf("hit path %q, want /complete", gotPath)
	}
	if gotReq.SystemPrompt != "system prompt" || gotReq.UserPrompt != "user prompt" || gotReq.Agent != "claude" {
		t.Errorf("runner received %+v, want the system/user prompts and agent carried through", gotReq)
	}
	if got.Text != "True" || got.Model != "claude-sonnet-4-5" {
		t.Errorf("got Text=%q Model=%q, want True/claude-sonnet-4-5", got.Text, got.Model)
	}
	if got.TokensIn != 120 || got.TokensCacheRead != 30 || got.TokensOut != 4 {
		t.Errorf("token accounting not carried through: %+v", got)
	}
}

// TestCLIInvestigatorCompleteDoesNotMintAToken confirms the doc comment's
// central safety claim: Complete never touches the minter at all, even when
// one is wired — because a one-shot completion never reaches a tool, so
// there is nothing to scope a token to.
func TestCLIInvestigatorCompleteDoesNotMintAToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(completeResponse{Content: "False", Model: "m"})
	}))
	defer srv.Close()

	minter := &fakeMinter{}
	c := NewCLIInvestigator(minter, []string{"get_events"}, "http://hub/mcp",
		fixedConfig(settings.Config{CLIRunnerURL: srv.URL}), nil)
	if _, err := c.Complete(context.Background(), "s", "u"); err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if minter.minted != 0 || minter.revoked != 0 {
		t.Errorf("minter.Mint/Revoke called (%d/%d); a one-shot completion must never touch MCP token minting", minter.minted, minter.revoked)
	}
}

func TestCLIInvestigatorCompleteRunnerErrorIsAnError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(completeResponse{Error: "agent claude failed: executable not found"})
	}))
	defer srv.Close()

	c := NewCLIInvestigator(nil, nil, "", fixedConfig(settings.Config{CLIRunnerURL: srv.URL}), nil)
	_, err := c.Complete(context.Background(), "s", "u")
	if err == nil || !strings.Contains(err.Error(), "executable not found") {
		t.Errorf("err = %v, want the runner's own error surfaced", err)
	}
}

func TestCLIInvestigatorCompleteTimedOutIsAnError(t *testing.T) {
	// Unlike Investigate (where a timeout is a partial analysis carrying
	// real evidence), Complete has no partial-result shape at all: a
	// one-shot completion that did not finish produced no usable text, so
	// this must be a plain error, not a zero-value Result mistaken for an
	// empty answer.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(completeResponse{TimedOut: true})
	}))
	defer srv.Close()

	c := NewCLIInvestigator(nil, nil, "", fixedConfig(settings.Config{CLIRunnerURL: srv.URL}), nil)
	_, err := c.Complete(context.Background(), "s", "u")
	if err == nil {
		t.Fatal("expected an error when the runner reports timedOut for a one-shot completion")
	}
}

type fakeMinter struct {
	minted  int
	revoked int
	last    string
}

func (f *fakeMinter) Mint(clusterID, _ string, _ []string) (string, error) {
	f.minted++
	f.last = clusterID
	return "test-token", nil
}

func (f *fakeMinter) Revoke(string) { f.revoked++ }

// --- BACKLOG.md C10: the cli backend's self-reported, cross-checked chain ---

// fixedLedger returns a ToolCallLedger that always returns the same
// RecordedToolCall set regardless of clusterID/incidentID — enough for these
// tests, which only ever wire one investigation at a time.
func fixedLedger(calls []RecordedToolCall, err error) ToolCallLedger {
	return func(context.Context, string, string) ([]RecordedToolCall, error) {
		return calls, err
	}
}

// TestCLISystemPromptSuffixNamesCausalChainAndVerification pins the wording
// cli_investigator.go asks the model with — the F21 pattern
// (TestSystemPromptAsksEveryRouteForConcreteSteps) applied to this feature:
// the prose must name the exact JSON key, tell the model verification is
// real (not a formality), and warn against citing an uncalled tool.
func TestCLISystemPromptSuffixNamesCausalChainAndVerification(t *testing.T) {
	suffix := causalChainSystemPromptSuffix
	for _, want := range []string{
		`"causalChain"`,
		"hypothesis",
		"toolCalls",
		"finding",
		"exact tool name",
		"independently verifies",
		"will be caught",
	} {
		if !strings.Contains(suffix, want) {
			t.Errorf("causalChainSystemPromptSuffix does not contain %q", want)
		}
	}
}

// TestCLIInvestigatorAppendsCausalChainSuffixOnlyWithALedger confirms the
// suffix is appended to the outgoing runner request's SystemPrompt when a
// ledger is wired, and left completely untouched when it is not — this
// backend must never ask a model to self-report a chain it has no way to
// verify (see Investigate's own comment on why this is a per-call append
// here rather than a change to the shared SystemPrompt every caller builds
// before the Router even picks a backend).
func TestCLIInvestigatorAppendsCausalChainSuffixOnlyWithALedger(t *testing.T) {
	newServerCapturing := func(dst *runnerRequest) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_ = json.NewDecoder(r.Body).Decode(dst)
			_ = json.NewEncoder(w).Encode(runnerResponse{Content: `{"rootCause":{"statement":"x"},"confidence":0.5,"ruledOut":[]}`})
		}))
	}

	t.Run("with ledger", func(t *testing.T) {
		var got runnerRequest
		srv := newServerCapturing(&got)
		defer srv.Close()
		c := NewCLIInvestigator(&fakeMinter{}, []string{"get_events"}, "http://hub/mcp",
			fixedConfig(settings.Config{CLIRunnerURL: srv.URL}), fixedLedger(nil, nil))
		if _, err := c.Investigate(context.Background(), Target{ClusterID: "cl_1", IncidentID: "inc_1"}, "SYSTEM", "u", nil); err != nil {
			t.Fatalf("Investigate: %v", err)
		}
		if !strings.Contains(got.SystemPrompt, "causalChain") {
			t.Errorf("SystemPrompt = %q, want the causal-chain suffix appended when a ledger is wired", got.SystemPrompt)
		}
	})

	t.Run("without ledger", func(t *testing.T) {
		var got runnerRequest
		srv := newServerCapturing(&got)
		defer srv.Close()
		c := NewCLIInvestigator(&fakeMinter{}, []string{"get_events"}, "http://hub/mcp",
			fixedConfig(settings.Config{CLIRunnerURL: srv.URL}), nil)
		if _, err := c.Investigate(context.Background(), Target{ClusterID: "cl_1", IncidentID: "inc_1"}, "SYSTEM", "u", nil); err != nil {
			t.Fatalf("Investigate: %v", err)
		}
		if got.SystemPrompt != "SYSTEM" {
			t.Errorf("SystemPrompt = %q, want exactly the caller's prompt, untouched — no ledger means no honest way to verify a chain", got.SystemPrompt)
		}
	})
}

// TestCLIInvestigatorReportsACrossCheckedSelfReportedChain is the end-to-end
// happy path: the model reports a causal chain, the ledger confirms every
// citation really happened, and the result carries a fully-corroborated
// chain stamped CausalChainProvenanceSelfReported (never hub-observed — this
// backend never dispatched a single one of these calls itself).
func TestCLIInvestigatorReportsACrossCheckedSelfReportedChain(t *testing.T) {
	final := `{"rootCause":{"statement":"checkout-worker OOMKilled under load"},"confidence":0.9,"ruledOut":[],` +
		`"causalChain":[{"hypothesis":"container exceeding memory limit","toolCalls":["get_events","describe_resource"],"finding":"OOMKilled 4 times in 25 minutes"}]}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(runnerResponse{Content: final, Model: "claude-sonnet-5", Turns: 3})
	}))
	defer srv.Close()

	ledger := fixedLedger([]RecordedToolCall{
		{Tool: "get_events", Outcome: "ok"},
		{Tool: "describe_resource", Outcome: "ok"},
	}, nil)
	c := NewCLIInvestigator(&fakeMinter{}, []string{"get_events", "describe_resource"}, "http://hub/mcp",
		fixedConfig(settings.Config{CLIRunnerURL: srv.URL}), ledger)

	got, err := c.Investigate(context.Background(), Target{ClusterID: "cl_1", IncidentID: "inc_1"}, "SYSTEM", "u", nil)
	if err != nil {
		t.Fatalf("Investigate: %v", err)
	}
	if got.CausalChainProvenance != CausalChainProvenanceSelfReported {
		t.Errorf("CausalChainProvenance = %q, want %q", got.CausalChainProvenance, CausalChainProvenanceSelfReported)
	}
	if len(got.CausalChain) != 1 || len(got.CausalChain[0].ToolCalls) != 2 {
		t.Fatalf("CausalChain = %+v, want 1 step with 2 tool call citations", got.CausalChain)
	}
	for _, call := range got.CausalChain[0].ToolCalls {
		// The Finding ("OOMKilled 4 times in 25 minutes") cites no checkable
		// value, so a real, matched call reads "unchecked" — never
		// "unverified" (that would mean the call itself never happened).
		if call.Corroborated == toolCallVerdictUnverified {
			t.Errorf("call %+v marked unverified, want it matched — the ledger confirms it really happened", call)
		}
	}
}

// TestCLIInvestigatorMarksAFabricatedCitationRatherThanTrustingIt is C10's
// end-to-end version of the fabrication test: the model claims a causal chain
// step that cites a tool call the hub never actually recorded serving for
// this incident. The resulting Investigation must mark that citation
// uncorroborated, not silently render it as evidence — proving the wiring
// between cli_investigator.go and crossCheckCausalChain actually applies the
// check on the real Investigate path, not just in the pure function's own
// unit tests.
func TestCLIInvestigatorMarksAFabricatedCitationRatherThanTrustingIt(t *testing.T) {
	final := `{"rootCause":{"statement":"a plausible-sounding but unverified diagnosis"},"confidence":0.7,"ruledOut":[],` +
		`"causalChain":[{"hypothesis":"tested via logs and events","toolCalls":["get_logs","get_events"],"finding":"looked thorough"}]}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(runnerResponse{Content: final, Model: "claude-sonnet-5", Turns: 1})
	}))
	defer srv.Close()

	// The hub's own ledger says only get_events was ever actually served —
	// get_logs is a pure invention.
	ledger := fixedLedger([]RecordedToolCall{{Tool: "get_events", Outcome: "ok"}}, nil)
	c := NewCLIInvestigator(&fakeMinter{}, []string{"get_events", "get_logs"}, "http://hub/mcp",
		fixedConfig(settings.Config{CLIRunnerURL: srv.URL}), ledger)

	got, err := c.Investigate(context.Background(), Target{ClusterID: "cl_1", IncidentID: "inc_1"}, "SYSTEM", "u", nil)
	if err != nil {
		t.Fatalf("Investigate: %v", err)
	}
	if len(got.CausalChain) != 1 || len(got.CausalChain[0].ToolCalls) != 2 {
		t.Fatalf("CausalChain = %+v, want 1 step with 2 tool call citations", got.CausalChain)
	}
	var sawFabricated, sawReal bool
	for _, call := range got.CausalChain[0].ToolCalls {
		switch call.Tool {
		case "get_logs":
			sawFabricated = true
			if call.Corroborated != toolCallVerdictUnverified {
				t.Errorf("get_logs citation Corroborated = %q, want %q — this call was NEVER served, and rendering it as verified is exactly the fabrication this mechanism must catch", call.Corroborated, toolCallVerdictUnverified)
			}
		case "get_events":
			sawReal = true
			if call.Corroborated == toolCallVerdictUnverified {
				t.Errorf("get_events citation Corroborated = %q, want it matched — this call really was served", call.Corroborated)
			}
		}
	}
	if !sawFabricated || !sawReal {
		t.Fatalf("did not see both citations in the result: %+v", got.CausalChain[0].ToolCalls)
	}
}

// TestCLIInvestigatorLedgerFailureFallsBackToEmptyChain confirms that when
// the ledger itself cannot be read (a database problem, say), this backend
// reports an empty causal chain rather than an unverifiable one — the same
// "if it cannot be honestly verified, show nothing" posture
// cli_investigator.go took unconditionally before this feature existed, now
// applied to the one failure mode within this feature's own control.
func TestCLIInvestigatorLedgerFailureFallsBackToEmptyChain(t *testing.T) {
	final := `{"rootCause":{"statement":"x"},"confidence":0.5,"ruledOut":[],` +
		`"causalChain":[{"hypothesis":"h","toolCalls":["get_events"],"finding":"f"}]}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(runnerResponse{Content: final})
	}))
	defer srv.Close()

	ledger := fixedLedger(nil, errors.New("db unavailable"))
	c := NewCLIInvestigator(&fakeMinter{}, []string{"get_events"}, "http://hub/mcp",
		fixedConfig(settings.Config{CLIRunnerURL: srv.URL}), ledger)

	got, err := c.Investigate(context.Background(), Target{ClusterID: "cl_1", IncidentID: "inc_1"}, "SYSTEM", "u", nil)
	if err != nil {
		t.Fatalf("Investigate: %v", err)
	}
	if len(got.CausalChain) != 0 {
		t.Errorf("CausalChain = %+v, want empty — a ledger read failure must not surface an unverified chain", got.CausalChain)
	}
	if got.CausalChainProvenance != CausalChainProvenanceSelfReported {
		t.Errorf("CausalChainProvenance = %q, want %q even on this fallback path", got.CausalChainProvenance, CausalChainProvenanceSelfReported)
	}
}

// Preflight is what lets POST /incidents/{id}/analyze answer before the
// investigation runs and still refuse, synchronously, a run that could never
// start. Every refusal must be ErrNotConfigured-wrapped (the handler's 503)
// except an unrecognized kind, which is a hard error exactly as in Investigate.
func TestRouterPreflight(t *testing.T) {
	apiBackend := &fakeInvestigator{name: "api"}
	cliBackend := &fakeInvestigator{name: "cli"}
	cases := []struct {
		name          string
		api, cli      Investigator
		cfg           settings.Config
		wantSource    RunSource
		wantNotConfig bool
		wantErr       bool
	}{
		{"api ready", apiBackend, cliBackend, settings.Config{LLMProviderKind: settings.ProviderKindAPI, LLMBaseURL: "http://llm", LLMModel: "m1"}, RunSource{Backend: "api", Model: "m1"}, false, false},
		{"unset kind is api", apiBackend, nil, settings.Config{LLMBaseURL: "http://llm", LLMModel: "m2"}, RunSource{Backend: "api", Model: "m2"}, false, false},
		{"api without base URL", apiBackend, cliBackend, settings.Config{LLMProviderKind: settings.ProviderKindAPI}, RunSource{}, true, true},
		{"api backend not wired", nil, cliBackend, settings.Config{LLMProviderKind: settings.ProviderKindAPI, LLMBaseURL: "http://llm"}, RunSource{}, true, true},
		{"cli ready names no model", apiBackend, cliBackend, settings.Config{LLMProviderKind: settings.ProviderKindCLI, CLIRunnerURL: "http://runner"}, RunSource{Backend: "cli"}, false, false},
		{"cli without runner URL", apiBackend, cliBackend, settings.Config{LLMProviderKind: settings.ProviderKindCLI}, RunSource{}, true, true},
		{"cli without MCP listener", apiBackend, nil, settings.Config{LLMProviderKind: settings.ProviderKindCLI, CLIRunnerURL: "http://runner"}, RunSource{}, true, true},
		{"unknown kind", apiBackend, cliBackend, settings.Config{LLMProviderKind: "gemini-cli"}, RunSource{}, false, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := NewRouter(tc.api, tc.cli, fixedConfig(tc.cfg))
			got, err := r.Preflight(context.Background())
			if (err != nil) != tc.wantErr {
				t.Fatalf("Preflight error = %v, wantErr %v", err, tc.wantErr)
			}
			if errors.Is(err, ErrNotConfigured) != tc.wantNotConfig {
				t.Errorf("errors.Is(err, ErrNotConfigured) = %v, want %v (err %v)", errors.Is(err, ErrNotConfigured), tc.wantNotConfig, err)
			}
			if got != tc.wantSource {
				t.Errorf("source = %+v, want %+v", got, tc.wantSource)
			}
			if apiBackend.calls != 0 || cliBackend.calls != 0 {
				t.Error("Preflight must never start an investigation")
			}
		})
	}
}
