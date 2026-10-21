package main

import (
	"os"
	"strings"
	"testing"
)

// The fixture below is REAL output from `claude -p --output-format json` at
// version 2.0.1, captured from a live run rather than written from
// documentation. It is the fixture precisely because two assumptions this
// runner originally made about that shape were both false:
//
//   - there is no top-level "model" key (the model is a modelUsage KEY), so
//     every CLI analysis was recorded with an empty model; and
//   - usage.input_tokens counts only uncached tokens — 3 of them here,
//     alongside 14415 cache-creation tokens — so reading it alone understated
//     usage by three orders of magnitude.
//
// Keeping the raw shape here means a future CLI upgrade that changes it fails
// a test instead of silently zeroing a field again.
const realClaudeResultJSON = `{
  "type": "result",
  "subtype": "success",
  "is_error": false,
  "duration_ms": 1914,
  "num_turns": 1,
  "result": "AUTH_OK",
  "total_cost_usd": 0.05415525,
  "usage": {
    "input_tokens": 3,
    "cache_creation_input_tokens": 14415,
    "cache_read_input_tokens": 120,
    "output_tokens": 6
  },
  "modelUsage": {
    "claude-sonnet-4-5-20250929": {
      "inputTokens": 3,
      "outputTokens": 6,
      "cacheReadInputTokens": 120,
      "cacheCreationInputTokens": 14415
    }
  }
}`

func TestParseClaudeJSONRealOutput(t *testing.T) {
	t.Setenv("ARGUS_CLI_AUTH_MODE", "")
	got, err := parseClaudeJSON([]byte(realClaudeResultJSON))
	if err != nil {
		t.Fatalf("parse real claude output: %v", err)
	}
	if got.Content != "AUTH_OK" {
		t.Errorf("Content = %q, want AUTH_OK", got.Content)
	}
	if got.Model != "claude-sonnet-4-5-20250929" {
		t.Errorf("Model = %q; the model name lives in modelUsage's key, not a top-level field", got.Model)
	}
	// 3 fresh + 14415 cache-creation: creation tokens were really processed
	// and really carry a write premium, so they belong with fresh input.
	if got.TokensIn != 14418 {
		t.Errorf("TokensIn = %d, want 14418 (input + cache creation)", got.TokensIn)
	}
	if got.TokensCacheRead != 120 {
		t.Errorf("TokensCacheRead = %d, want 120", got.TokensCacheRead)
	}
	if got.TokensOut != 6 {
		t.Errorf("TokensOut = %d, want 6", got.TokensOut)
	}
	if got.Turns != 1 {
		t.Errorf("Turns = %d, want 1", got.Turns)
	}
}

func TestCostBasisForSubscriptionWithNotionalCost(t *testing.T) {
	// The regression that motivated inverting this function's checks: under
	// subscription auth the CLI still reports a notional total_cost_usd, so
	// trusting the sign of that number labelled unbilled runs "metered" and
	// fed money that was never charged into the hub's daily spend ceiling.
	t.Setenv("ARGUS_CLI_AUTH_MODE", "subscription")
	if got := costBasisFor("claude", 0.05415525); got != "subscription" {
		t.Errorf("costBasisFor(positive notional cost) = %q, want subscription", got)
	}
	if got := costBasisFor("claude", 0); got != "subscription" {
		t.Errorf("costBasisFor(0) = %q, want subscription", got)
	}
}

func TestCostBasisForWithoutAuthMode(t *testing.T) {
	t.Setenv("ARGUS_CLI_AUTH_MODE", "")
	if got := costBasisFor("claude", 1.25); got != "metered" {
		t.Errorf("costBasisFor(1.25) = %q, want metered", got)
	}
	// A zero cost with no declared auth mode and no subscription credential
	// is unknown, never metered-zero: a measured-looking $0.00 is what makes
	// a spend ceiling unfalsifiable.
	if got := costBasisFor("claude", 0); got != "unknown" {
		t.Errorf("costBasisFor(0) = %q, want unknown", got)
	}
}

func TestCostBasisForAuthModeCaseInsensitive(t *testing.T) {
	t.Setenv("ARGUS_CLI_AUTH_MODE", "Subscription")
	if got := costBasisFor("claude", 0.5); got != "subscription" {
		t.Errorf("auth mode should be case-insensitive, got %q", got)
	}
}

// TestCostBasisForDerivesFromCredentialWithoutAuthModeSet is PROJECT.md
// B169's exact regression: ARGUS_CLI_AUTH_MODE unset (never remembered by
// an operator) must still label a real subscription run "subscription," not
// "metered," because the credential itself already says which one this is.
func TestCostBasisForDerivesFromCredentialWithoutAuthModeSet(t *testing.T) {
	t.Setenv("ARGUS_CLI_AUTH_MODE", "")
	t.Setenv("CLAUDE_CODE_OAUTH_TOKEN", "sk-ant-oat01-fake-token-for-test")
	t.Setenv("ANTHROPIC_API_KEY", "")
	if got := costBasisFor("claude", 0.05415525); got != "subscription" {
		t.Errorf("costBasisFor with CLAUDE_CODE_OAUTH_TOKEN set and no ARGUS_CLI_AUTH_MODE = %q, want subscription", got)
	}
	// The notional-zero case must not collapse to "unknown" either, once the
	// credential itself is known to be the subscription one.
	if got := costBasisFor("claude", 0); got != "subscription" {
		t.Errorf("costBasisFor(0) with CLAUDE_CODE_OAUTH_TOKEN set = %q, want subscription", got)
	}
}

// TestCostBasisForApiKeyCredentialStaysMetered confirms the derivation does
// not overcorrect: an API-key-authenticated run is genuinely metered, and
// must stay that way whether or not ARGUS_CLI_AUTH_MODE happens to be unset.
func TestCostBasisForApiKeyCredentialStaysMetered(t *testing.T) {
	t.Setenv("ARGUS_CLI_AUTH_MODE", "")
	t.Setenv("CLAUDE_CODE_OAUTH_TOKEN", "")
	t.Setenv("ANTHROPIC_API_KEY", "sk-ant-api03-fake-key-for-test")
	if got := costBasisFor("claude", 1.25); got != "metered" {
		t.Errorf("costBasisFor with only ANTHROPIC_API_KEY set = %q, want metered", got)
	}
}

// TestCostBasisForClaudeCredentialDoesNotLeakToCodex guards the per-agent
// scoping: a claude subscription credential sitting unused in this
// process's env must never mislabel a DIFFERENT agent's (codex's) run,
// which has no subscription-shaped credential of its own here.
func TestCostBasisForClaudeCredentialDoesNotLeakToCodex(t *testing.T) {
	t.Setenv("ARGUS_CLI_AUTH_MODE", "")
	t.Setenv("CLAUDE_CODE_OAUTH_TOKEN", "sk-ant-oat01-fake-token-for-test")
	if got := costBasisFor("codex", 1.25); got != "metered" {
		t.Errorf("costBasisFor(%q) leaked claude's subscription credential = %q, want metered", "codex", got)
	}
}

func TestParseClaudeJSONSurfacesErrorResults(t *testing.T) {
	_, err := parseClaudeJSON([]byte(`{"type":"result","is_error":true,"subtype":"error_max_turns"}`))
	if err == nil {
		t.Fatal("an is_error result must not be reported as a successful investigation")
	}
}

func TestModelNameFallsBackToJoinedKeys(t *testing.T) {
	// A run that fell back mid-way spans two models; reporting only one would
	// misattribute the usage, so both are named.
	r := claudeResult{ModelUsage: map[string]modelUsage{
		"claude-sonnet-4-5": {}, "claude-haiku-4-5": {},
	}}
	// Sorted for stability, so the value does not depend on map iteration order.
	if got := r.modelName(); got != "claude-haiku-4-5+claude-sonnet-4-5" {
		t.Errorf("modelName() = %q", got)
	}
}

func TestClaudeTokensFallsBackToModelUsage(t *testing.T) {
	// If the usage block is ever absent, per-model figures are summed rather
	// than reporting zero tokens for a run that clearly used some.
	r := claudeResult{ModelUsage: map[string]modelUsage{
		"a": {InputTokens: 10, CacheCreationInputTokens: 5, CacheReadInputTokens: 2, OutputTokens: 7},
		"b": {InputTokens: 1, OutputTokens: 3},
	}}
	in, cacheRead, out := r.claudeTokens()
	if in != 16 || cacheRead != 2 || out != 10 {
		t.Errorf("claudeTokens() = (%d, %d, %d), want (16, 2, 10)", in, cacheRead, out)
	}
}

// TestCompleteArgsExcludeMCPWiring is BACKLOG.md P13's belt-and-braces
// check on the one-shot completion path: neither agent's completeArgs may
// ever emit --mcp-config/--config/--allowedTools/--strict-mcp-config —
// there is no MCP server configured for this call at all, so nothing
// should reference one. Built-in tools must still be explicitly denied
// (the same posture args() takes for the investigation path), and the
// system/user prompt text must actually reach the CLI.
func TestCompleteArgsExcludeMCPWiring(t *testing.T) {
	disallowed := []string{"--mcp-config", "--strict-mcp-config", "--allowedTools", "--config"}

	for name, spec := range agentSpecs {
		t.Run(name, func(t *testing.T) {
			if spec.completeArgs == nil {
				t.Fatalf("agent %q has no completeArgs at all", name)
			}
			args := spec.completeArgs(completeRequest{
				SystemPrompt: "SYSTEM_MARKER",
				UserPrompt:   "USER_MARKER",
			})
			joined := strings.Join(args, " ")
			for _, flag := range disallowed {
				if strings.Contains(joined, flag) {
					t.Errorf("agent %q completeArgs included %q — a one-shot completion must never reference MCP wiring: %v", name, flag, args)
				}
			}
			if !strings.Contains(joined, "SYSTEM_MARKER") {
				t.Errorf("agent %q completeArgs dropped the system prompt: %v", name, args)
			}
			if !strings.Contains(joined, "USER_MARKER") {
				t.Errorf("agent %q completeArgs dropped the user prompt: %v", name, args)
			}
		})
	}
}

// TestClaudeCompleteArgsDenyBuiltinTools locks in claude's specific
// belt-and-braces posture for completeArgs, mirroring what args() already
// does for the investigation path — every built-in that can touch the
// filesystem, run a command, or reach the network must be explicitly
// denied, not just left unoffered by omission.
func TestClaudeCompleteArgsDenyBuiltinTools(t *testing.T) {
	args := agentSpecs["claude"].completeArgs(completeRequest{SystemPrompt: "s", UserPrompt: "u"})
	joined := strings.Join(args, " ")
	for _, tool := range []string{"Bash", "Read", "Write", "Edit", "WebFetch", "WebSearch", "Task"} {
		if !strings.Contains(joined, tool) {
			t.Errorf("claude completeArgs does not explicitly deny built-in tool %q: %v", tool, args)
		}
	}
}

func TestMain(m *testing.M) {
	// Guard against a stray ambient value in the developer's environment
	// silently changing what costBasisFor returns under test. Now that the
	// basis is derived from the credential too (B169), that guard has to
	// cover the credential vars as well as the override.
	os.Unsetenv("ARGUS_CLI_AUTH_MODE")
	os.Unsetenv("CLAUDE_CODE_OAUTH_TOKEN")
	os.Unsetenv("ANTHROPIC_API_KEY")
	os.Exit(m.Run())
}
