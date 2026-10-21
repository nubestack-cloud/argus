package settings

import (
	"context"
	"testing"

	"argus/internal/domain"
)

// TestResolve_CLIProviderWithStaleAPIColumns_ResolvesLLMBaseURLEmpty is
// BUGS.md 125's own requested proof: a real Postgres row, kind="cli", with
// stale api-shaped columns (base_url/model/api_key) still populated from an
// earlier life as an "api"-kind row (or simply never cleared), must resolve
// through the real end-to-end Resolve() — not just the pure resolve()
// helper TestResolveGatesLLMFieldsOnProviderKind already pins — to an EMPTY
// LLMBaseURL, not the stale value. Before this fix it resolved to the stale
// base_url, which is exactly what made a direct *llm.Provider.Complete
// caller attempt a real HTTP call to a meaningless URL instead of cleanly
// reporting ErrNotConfigured.
//
// Runs inside one transaction that is rolled back, never committed —
// org_settings is a real, shared singleton row on a live dev database, so
// this only points active_ai_provider_id at a throwaway row within its own
// transaction, matching providers_db_test.go's established discipline for
// this exact table.
func TestResolve_CLIProviderWithStaleAPIColumns_ResolvesLLMBaseURLEmpty(t *testing.T) {
	pool := providersTestPool(t)
	ctx := context.Background()

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()

	providerID := domain.NewID(domain.PrefixAIProvider)
	if _, err := tx.Exec(ctx, `
		INSERT INTO ai_providers (id, tenant_id, name, kind, base_url, model, api_key, runner_url, agent)
		VALUES ($1, 'tenant_test_bugs125', 'b125-cli-with-stale-api-fields', 'cli',
		        'http://smoketest-llm.invalid/v2', 'stale-model', 'stale-api-key',
		        'http://argus-runner:8090', 'claude')`,
		providerID); err != nil {
		t.Fatalf("insert cli provider with stale api columns: %v", err)
	}
	if _, err := tx.Exec(ctx, `UPDATE org_settings SET active_ai_provider_id = $1 WHERE id = $2`, providerID, singletonID); err != nil {
		t.Fatalf("activate the cli provider: %v", err)
	}

	cfg, err := Resolve(ctx, tx)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if cfg.LLMProviderKind != KindCLI {
		t.Fatalf("LLMProviderKind = %q, want %q", cfg.LLMProviderKind, KindCLI)
	}
	if cfg.LLMBaseURL != "" {
		t.Errorf("LLMBaseURL = %q, want empty — this is the row's stale, kind-irrelevant base_url column, not a real endpoint", cfg.LLMBaseURL)
	}
	if cfg.LLMModel != "" {
		t.Errorf("LLMModel = %q, want empty", cfg.LLMModel)
	}
	if cfg.LLMAPIKey != "" || cfg.LLMAPIKeySet {
		t.Errorf("LLMAPIKey = %q LLMAPIKeySet = %v, want empty/false", cfg.LLMAPIKey, cfg.LLMAPIKeySet)
	}
	// The cli provider's REAL access mechanism must be completely unaffected.
	if cfg.CLIRunnerURL != "http://argus-runner:8090" {
		t.Errorf("CLIRunnerURL = %q, want the row's runner_url untouched", cfg.CLIRunnerURL)
	}
}

// TestResolve_APIProviderOwnFieldsUnaffected is the fix's regression
// companion, run against the real database exactly like the test above: an
// "api"-kind provider's own base_url/model/api_key must resolve through
// unchanged.
func TestResolve_APIProviderOwnFieldsUnaffected(t *testing.T) {
	pool := providersTestPool(t)
	ctx := context.Background()

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()

	providerID := domain.NewID(domain.PrefixAIProvider)
	if _, err := tx.Exec(ctx, `
		INSERT INTO ai_providers (id, tenant_id, name, kind, base_url, model, api_key)
		VALUES ($1, 'tenant_test_bugs125', 'b125-real-api-provider', 'api',
		        'https://real-endpoint.example/v1', 'real-model', 'real-api-key')`,
		providerID); err != nil {
		t.Fatalf("insert api provider: %v", err)
	}
	if _, err := tx.Exec(ctx, `UPDATE org_settings SET active_ai_provider_id = $1 WHERE id = $2`, providerID, singletonID); err != nil {
		t.Fatalf("activate the api provider: %v", err)
	}

	cfg, err := Resolve(ctx, tx)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if cfg.LLMBaseURL != "https://real-endpoint.example/v1" || cfg.LLMModel != "real-model" || cfg.LLMAPIKey != "real-api-key" {
		t.Errorf("an api-kind provider's own fields must resolve unchanged, got LLMBaseURL=%q LLMModel=%q LLMAPIKey=%q",
			cfg.LLMBaseURL, cfg.LLMModel, cfg.LLMAPIKey)
	}
}
