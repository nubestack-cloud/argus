package settings

import (
	"context"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// providersTestPool connects to a real Postgres behind
// ARGUS_TEST_DATABASE_URL, matching internal/orchestrator/db_test.go's own
// testPool precedent for this repo (a DB-backed unit test, not a fixture
// edit) — and skips cleanly on a machine without one, e.g.:
//
//	export ARGUS_TEST_DATABASE_URL="postgres://argus_app:dev-local-password@localhost:5432/argus?sslmode=disable"
//
// (argus_app, not the postgres superuser, for the identical reason that
// file's own doc comment gives.)
//
// No data.SetRequestScope call here, unlike most other DB-backed tests in
// this codebase: org_settings and ai_providers both deliberately carry no
// row-level security at all (migration 000034's own comment explains why —
// settings.Resolve reads both through a bare pool connection with no
// app.tenant_id set on the investigation hot path, so an RLS policy here
// would silently hide every row exactly as it once did by accident). A
// plain, unscoped transaction is the correct way to exercise this code.
func providersTestPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	connString := os.Getenv("ARGUS_TEST_DATABASE_URL")
	if connString == "" {
		t.Skip("ARGUS_TEST_DATABASE_URL not set; skipping DB-backed UpdateActiveProvider tests (see this file's doc comment)")
	}
	pool, err := pgxpool.New(context.Background(), connString)
	if err != nil {
		t.Fatalf("connect to test database: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

// TestCreateAndUpdateProvider_ClearKindIrrelevantColumnsAtWriteTime is
// BUGS.md 125's write-time half (gap (b)): a create/update request that
// carries both kinds' fields — a client that always sends the full form —
// must not let the OTHER kind's fields land in the row at all, and
// switching an existing row's kind must clear out whatever the old kind
// left behind, rather than accumulating exactly the "stale api-shaped
// columns on a cli row" baggage the resolve()-side fix (settings.go's
// resolve(), same BUGS.md entry) has to defend against on every read.
func TestCreateAndUpdateProvider_ClearKindIrrelevantColumnsAtWriteTime(t *testing.T) {
	pool := providersTestPool(t)
	ctx := context.Background()

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()

	key := "should-not-be-stored"
	id, err := CreateProvider(ctx, tx, "tenant_test_bugs125", ProviderInput{
		Name: "b125-cli-with-api-fields-too", Kind: KindCLI,
		RunnerURL: "http://runner:8090", Agent: "claude",
		// A client sending the full form: api-shaped fields present even
		// though this is a cli-kind create.
		BaseURL: "https://leftover.example/v1", Model: "leftover-model", APIKey: &key,
	})
	if err != nil {
		t.Fatalf("CreateProvider: %v", err)
	}

	var baseURL, model string
	var apiKeySet bool
	if err := tx.QueryRow(ctx,
		`SELECT COALESCE(base_url, ''), COALESCE(model, ''), (api_key IS NOT NULL AND api_key <> '') FROM ai_providers WHERE id = $1`, id).
		Scan(&baseURL, &model, &apiKeySet); err != nil {
		t.Fatalf("read back created provider: %v", err)
	}
	if baseURL != "" || model != "" || apiKeySet {
		t.Errorf("CreateProvider stored api-shaped fields on a cli-kind row: base_url=%q model=%q api_key_set=%v, want all empty/false", baseURL, model, apiKeySet)
	}

	// Now switch it to api and confirm the OLD cli fields (runner_url/agent/
	// runner_token) get cleared out too, not left as baggage from the kind
	// it no longer is.
	if err := UpdateProvider(ctx, tx, id, ProviderInput{
		Name: "b125-cli-with-api-fields-too", Kind: KindAPI,
		BaseURL: "https://real.example/v1", Model: "real-model",
		// Still sending cli-shaped fields too, as a full-form client would.
		RunnerURL: "http://stale-runner:8090", Agent: "codex",
	}); err != nil {
		t.Fatalf("UpdateProvider (switch to api): %v", err)
	}

	var runnerURL, agent string
	if err := tx.QueryRow(ctx,
		`SELECT COALESCE(runner_url, ''), COALESCE(agent, '') FROM ai_providers WHERE id = $1`, id).
		Scan(&runnerURL, &agent); err != nil {
		t.Fatalf("read back updated provider: %v", err)
	}
	if runnerURL != "" || agent != "" {
		t.Errorf("UpdateProvider left cli-shaped fields on a row just switched to api: runner_url=%q agent=%q, want both empty", runnerURL, agent)
	}

	var baseURL2, model2 string
	if err := tx.QueryRow(ctx,
		`SELECT COALESCE(base_url, ''), COALESCE(model, '') FROM ai_providers WHERE id = $1`, id).
		Scan(&baseURL2, &model2); err != nil {
		t.Fatalf("read back updated provider's own fields: %v", err)
	}
	if baseURL2 != "https://real.example/v1" || model2 != "real-model" {
		t.Errorf("the api-kind row's own fields must have taken the update, got base_url=%q model=%q", baseURL2, model2)
	}
}

// TestUpdateActiveProvider_FreshInstallCreatesAndActivates is BUGS.md 92's
// own regression test, proved against a real Postgres: a legacy
// PUT /api/v1/admin/settings "llm" section reaches UpdateActiveProvider, and
// on a genuinely fresh install — org_settings.active_ai_provider_id still
// NULL, the exact state the bug report reproduced by testing against a
// clean `docker compose down -v` volume — this must now create and activate
// a provider instead of returning ErrProviderNotFound (which the API layer
// had no special case for, so it surfaced as a bare 500).
//
// Runs inside one transaction that is rolled back, never committed —
// org_settings is a real, shared singleton row on a live dev database, so
// this test forces active_ai_provider_id to NULL only within its own
// transaction (never visible to any other session) to simulate the fresh-
// install state, exactly the same "never leave a durable change on shared
// state" discipline internal/api/breaker_db_test.go already established.
func TestUpdateActiveProvider_FreshInstallCreatesAndActivates(t *testing.T) {
	pool := providersTestPool(t)
	ctx := context.Background()

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()

	if _, err := tx.Exec(ctx, `UPDATE org_settings SET active_ai_provider_id = NULL WHERE id = $1`, singletonID); err != nil {
		t.Fatalf("simulate fresh install (clear active_ai_provider_id): %v", err)
	}

	apiKey := "sk-test-fresh-install"
	err = UpdateActiveProvider(ctx, tx, "tenant_test_bugs92", LLMUpdate{
		BaseURL: "http://example.invalid/v1",
		Model:   "test-model",
		APIKey:  &apiKey,
		// ProviderKind deliberately left "" — the legacy PUT body BUGS.md 92
		// reproduced never sends one; NormalizeProviderKind must map that to
		// "api", not leave it to fail validation or create a "" kind row.
	})
	if err != nil {
		t.Fatalf("UpdateActiveProvider on a fresh install = %v, want nil (create-and-activate)", err)
	}

	var activeID string
	if err := tx.QueryRow(ctx, `SELECT active_ai_provider_id FROM org_settings WHERE id = $1`, singletonID).Scan(&activeID); err != nil {
		t.Fatalf("read back active_ai_provider_id: %v", err)
	}
	if activeID == "" {
		t.Fatal("active_ai_provider_id is still empty after UpdateActiveProvider — no provider was activated")
	}

	var name, kind, baseURL, model string
	var apiKeySet bool
	if err := tx.QueryRow(ctx, `
		SELECT name, kind, COALESCE(base_url, ''), COALESCE(model, ''), (api_key IS NOT NULL AND api_key <> '')
		  FROM ai_providers WHERE id = $1`, activeID).
		Scan(&name, &kind, &baseURL, &model, &apiKeySet); err != nil {
		t.Fatalf("read back the created provider: %v", err)
	}
	if name != "Default" {
		t.Errorf("created provider name = %q, want %q (matching migration 000034's own backfill naming)", name, "Default")
	}
	if kind != KindAPI {
		t.Errorf("created provider kind = %q, want %q (NormalizeProviderKind's \"\" -> api default)", kind, KindAPI)
	}
	if baseURL != "http://example.invalid/v1" {
		t.Errorf("created provider baseUrl = %q, want the value from the update", baseURL)
	}
	if model != "test-model" {
		t.Errorf("created provider model = %q, want the value from the update", model)
	}
	if !apiKeySet {
		t.Error("created provider's apiKey was not stored")
	}

	// Exactly one provider must exist now (well, exactly one MORE than
	// before this call) — this call must not have created two rows, or
	// activated a pre-existing row it should have left alone.
	var count int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM ai_providers WHERE id = $1`, activeID).Scan(&count); err != nil {
		t.Fatalf("count created providers: %v", err)
	}
	if count != 1 {
		t.Errorf("ai_providers rows with id = %q: got %d, want exactly 1", activeID, count)
	}
}

// TestUpdateActiveProvider_FreshInstallClearIsANoOp: on a fresh install, a
// PUT that clears the "llm" section (every field empty) has nothing to clear
// and nothing to create. It must succeed without creating a provider, rather
// than trying to create an empty one and failing validation (a 500).
func TestUpdateActiveProvider_FreshInstallClearIsANoOp(t *testing.T) {
	pool := providersTestPool(t)
	ctx := context.Background()

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()

	if _, err := tx.Exec(ctx, `UPDATE org_settings SET active_ai_provider_id = NULL WHERE id = $1`, singletonID); err != nil {
		t.Fatalf("simulate fresh install (clear active_ai_provider_id): %v", err)
	}
	var before int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM ai_providers`).Scan(&before); err != nil {
		t.Fatalf("count providers: %v", err)
	}

	empty := ""
	if err := UpdateActiveProvider(ctx, tx, "tenant_test_clear", LLMUpdate{APIKey: &empty}); err != nil {
		t.Fatalf("UpdateActiveProvider clearing an unconfigured install = %v, want nil", err)
	}

	var after int
	var active *string
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM ai_providers`).Scan(&after); err != nil {
		t.Fatalf("count providers: %v", err)
	}
	if err := tx.QueryRow(ctx, `SELECT active_ai_provider_id FROM org_settings WHERE id = $1`, singletonID).Scan(&active); err != nil {
		t.Fatalf("read back active_ai_provider_id: %v", err)
	}
	if after != before || active != nil {
		t.Errorf("clearing created or activated a provider: providers %d -> %d, active=%v", before, after, active)
	}
}

// TestUpdateActiveProvider_ExistingActiveProviderEditsInPlace is the other
// half of BUGS.md 92's own explicit ask: this fix must not make
// UpdateActiveProvider create a SECOND provider row on a subsequent legacy
// PUT once one already exists — the ordinary "edit whichever provider is
// active" behavior this function has always had must survive completely
// unchanged.
func TestUpdateActiveProvider_ExistingActiveProviderEditsInPlace(t *testing.T) {
	pool := providersTestPool(t)
	ctx := context.Background()

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()

	if _, err := tx.Exec(ctx, `UPDATE org_settings SET active_ai_provider_id = NULL WHERE id = $1`, singletonID); err != nil {
		t.Fatalf("simulate fresh install (clear active_ai_provider_id): %v", err)
	}

	// First call creates the provider (exactly like the test above) —
	// this is the "already has a provider" fixture, reached through the
	// same code path a real second call would go through, not a hand-built
	// row that might not match what CreateProvider actually produces.
	if err := UpdateActiveProvider(ctx, tx, "tenant_test_bugs92", LLMUpdate{
		BaseURL: "http://example.invalid/v1",
		Model:   "test-model",
	}); err != nil {
		t.Fatalf("first UpdateActiveProvider call (create) = %v, want nil", err)
	}

	var activeIDBefore string
	if err := tx.QueryRow(ctx, `SELECT active_ai_provider_id FROM org_settings WHERE id = $1`, singletonID).Scan(&activeIDBefore); err != nil {
		t.Fatalf("read back active_ai_provider_id after first call: %v", err)
	}
	var countBefore int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM ai_providers`).Scan(&countBefore); err != nil {
		t.Fatalf("count providers after first call: %v", err)
	}

	// Second call: the normal legacy-PUT case, editing the provider that is
	// already active. Must edit that same row in place, not create another.
	if err := UpdateActiveProvider(ctx, tx, "tenant_test_bugs92", LLMUpdate{
		BaseURL: "http://example.invalid/v2",
		Model:   "test-model-2",
	}); err != nil {
		t.Fatalf("second UpdateActiveProvider call (edit) = %v, want nil", err)
	}

	var activeIDAfter string
	if err := tx.QueryRow(ctx, `SELECT active_ai_provider_id FROM org_settings WHERE id = $1`, singletonID).Scan(&activeIDAfter); err != nil {
		t.Fatalf("read back active_ai_provider_id after second call: %v", err)
	}
	if activeIDAfter != activeIDBefore {
		t.Errorf("active_ai_provider_id changed from %q to %q — the second call must edit the SAME provider, not activate a new one", activeIDBefore, activeIDAfter)
	}

	var countAfter int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM ai_providers`).Scan(&countAfter); err != nil {
		t.Fatalf("count providers after second call: %v", err)
	}
	if countAfter != countBefore {
		t.Errorf("ai_providers row count changed from %d to %d — the second legacy PUT must not create a second row", countBefore, countAfter)
	}

	var name, baseURL, model string
	if err := tx.QueryRow(ctx, `SELECT name, COALESCE(base_url, ''), COALESCE(model, '') FROM ai_providers WHERE id = $1`, activeIDAfter).
		Scan(&name, &baseURL, &model); err != nil {
		t.Fatalf("read back the edited provider: %v", err)
	}
	if name != "Default" {
		t.Errorf("provider name = %q, want %q (edit must preserve the name — the legacy shape carries none)", name, "Default")
	}
	if baseURL != "http://example.invalid/v2" {
		t.Errorf("baseUrl = %q, want the second call's value (edited in place)", baseURL)
	}
	if model != "test-model-2" {
		t.Errorf("model = %q, want the second call's value (edited in place)", model)
	}
}
