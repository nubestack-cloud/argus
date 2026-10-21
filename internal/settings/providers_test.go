package settings

import (
	"errors"
	"strings"
	"testing"
)

// ProviderInput.Validate is the only pure logic in providers.go — everything
// else is a single SQL statement, which this codebase's convention verifies by
// integration rather than by mocking a database (see health_test.go's own note
// on that split). These tests cover the validation matrix, which is where a
// silent mistake would let an unusable provider be stored and then fail
// confusingly hours later at investigation time.
func TestProviderInputValidate(t *testing.T) {
	apiOK := ProviderInput{Name: "Prod", Kind: KindAPI, BaseURL: "https://api.example/v1"}
	cliOK := ProviderInput{Name: "Runner", Kind: KindCLI, RunnerURL: "http://runner:8090"}

	cases := []struct {
		name    string
		in      ProviderInput
		wantErr string // substring; "" means it must pass
	}{
		{"valid api", apiOK, ""},
		{"valid cli", cliOK, ""},
		{"valid cli with agent", ProviderInput{Name: "R", Kind: KindCLI, RunnerURL: "http://r", Agent: "codex"}, ""},

		{"missing name", ProviderInput{Kind: KindAPI, BaseURL: "https://x/v1"}, "name is required"},
		{"whitespace-only name", ProviderInput{Name: "   ", Kind: KindAPI, BaseURL: "https://x/v1"}, "name is required"},

		// The two cases that mirror migration 000034's CHECK constraint. The
		// database is the backstop; this is the message a human reads.
		{"api without baseUrl", ProviderInput{Name: "P", Kind: KindAPI}, "baseUrl is required"},
		{"api with whitespace baseUrl", ProviderInput{Name: "P", Kind: KindAPI, BaseURL: "  "}, "baseUrl is required"},
		{"cli without runnerUrl", ProviderInput{Name: "P", Kind: KindCLI}, "runnerUrl is required"},

		{"unknown kind", ProviderInput{Name: "P", Kind: "telepathy", BaseURL: "https://x/v1"}, `kind must be`},
		{"empty kind", ProviderInput{Name: "P", BaseURL: "https://x/v1"}, `kind must be`},
		{"unknown agent", ProviderInput{Name: "P", Kind: KindCLI, RunnerURL: "http://r", Agent: "gemini"}, `agent must be`},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.in.Validate()
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("Validate() = %v, want nil", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("Validate() = nil, want an error containing %q", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("Validate() = %q, want it to contain %q", err, tc.wantErr)
			}
		})
	}
}

// A credential is deliberately NOT required by Validate: an api provider may
// legitimately have none (a local Ollama endpoint), and a cli provider's model
// credential lives in the runner's environment, never in this table. Pinned so
// nobody "tightens" it later and breaks both cases.
func TestProviderInputValidateDoesNotRequireACredential(t *testing.T) {
	if err := (ProviderInput{Name: "Local Ollama", Kind: KindAPI, BaseURL: "http://ollama:11434/v1"}).Validate(); err != nil {
		t.Errorf("an api provider with no API key must be valid (local Ollama), got %v", err)
	}
	if err := (ProviderInput{Name: "Runner", Kind: KindCLI, RunnerURL: "http://runner:8090"}).Validate(); err != nil {
		t.Errorf("a cli provider with no runner token must be valid, got %v", err)
	}
}

func TestKindConstantsMatchTheStoredValues(t *testing.T) {
	// Migration 000034's CHECK constraint stores exactly 'api'/'cli', and
	// migration 000033 stored the same two before it. If these constants ever
	// drift, every existing row becomes unreadable.
	if KindAPI != "api" || KindCLI != "cli" {
		t.Errorf("kind constants drifted from the stored values: %q/%q", KindAPI, KindCLI)
	}
	// And they must stay the same values internal/llm.Router dispatches on.
	if KindAPI != ProviderKindAPI || KindCLI != ProviderKindCLI {
		t.Error("KindAPI/KindCLI must be the same values internal/llm.Router dispatches on")
	}
}

// TestClearedForKind is BUGS.md 125's second, additive gap: a create/update
// request that carries both kinds' fields (or a row switching kind) must not
// let the OTHER kind's fields survive into the write. Pure, no database.
func TestClearedForKind(t *testing.T) {
	key := "leftover-secret"

	t.Run("api kind clears the cli-only fields, including forcing the runner token cleared", func(t *testing.T) {
		in := ProviderInput{
			Name: "P", Kind: KindAPI, BaseURL: "https://x/v1", Model: "m", APIKey: &key,
			RunnerURL: "http://stale-runner:8090", Agent: "codex", RunnerToken: &key,
		}
		out := in.clearedForKind()
		if out.BaseURL != "https://x/v1" || out.Model != "m" || out.APIKey != &key {
			t.Errorf("api kind's own fields must survive unchanged, got BaseURL=%q Model=%q APIKey=%v", out.BaseURL, out.Model, out.APIKey)
		}
		if out.RunnerURL != "" || out.Agent != "" {
			t.Errorf("api kind must clear RunnerURL/Agent, got RunnerURL=%q Agent=%q", out.RunnerURL, out.Agent)
		}
		if out.RunnerToken == nil || *out.RunnerToken != "" {
			t.Errorf("api kind must force RunnerToken to an explicit-clear pointer, got %v", out.RunnerToken)
		}
	})

	t.Run("cli kind clears the api-only fields, including forcing the api key cleared", func(t *testing.T) {
		in := ProviderInput{
			Name: "P", Kind: KindCLI, RunnerURL: "http://runner:8090", Agent: "claude", RunnerToken: &key,
			BaseURL: "https://stale/v1", Model: "stale-model", APIKey: &key,
		}
		out := in.clearedForKind()
		if out.RunnerURL != "http://runner:8090" || out.Agent != "claude" || out.RunnerToken != &key {
			t.Errorf("cli kind's own fields must survive unchanged, got RunnerURL=%q Agent=%q RunnerToken=%v", out.RunnerURL, out.Agent, out.RunnerToken)
		}
		if out.BaseURL != "" || out.Model != "" {
			t.Errorf("cli kind must clear BaseURL/Model, got BaseURL=%q Model=%q", out.BaseURL, out.Model)
		}
		if out.APIKey == nil || *out.APIKey != "" {
			t.Errorf("cli kind must force APIKey to an explicit-clear pointer, got %v", out.APIKey)
		}
	})

	t.Run("a nil secret pointer for the OTHER kind is still forced to explicit-clear, not left nil", func(t *testing.T) {
		// nil means "leave whatever is stored alone" — but a kind switch must
		// clear the other kind's secret even when the caller never mentioned
		// it, or the old secret survives as exactly the kind of undetected
		// baggage this fix exists to stop.
		in := ProviderInput{Name: "P", Kind: KindAPI, BaseURL: "https://x/v1"}
		out := in.clearedForKind()
		if out.RunnerToken == nil || *out.RunnerToken != "" {
			t.Errorf("switching to api with no RunnerToken mentioned must still force-clear it, got %v", out.RunnerToken)
		}
	})
}

func TestSentinelErrorsAreDistinguishable(t *testing.T) {
	// The API layer maps these onto 404 vs 409, so errors.Is must work and they
	// must not be the same value.
	if errors.Is(ErrProviderNotFound, ErrDuplicateProviderName) {
		t.Error("ErrProviderNotFound and ErrDuplicateProviderName must be distinguishable")
	}
	wrapped := errors.Join(errors.New("context"), ErrProviderNotFound)
	if !errors.Is(wrapped, ErrProviderNotFound) {
		t.Error("ErrProviderNotFound must survive wrapping")
	}
}
