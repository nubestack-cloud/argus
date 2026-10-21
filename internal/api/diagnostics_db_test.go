package api

// Adversarial, end-to-end proof against a REAL Postgres and a real local
// HTTP round trip — not just the pure-Go redaction unit tests in
// diagnostics_test.go. Two things are seeded exactly the way T18's own
// instructions describe: a secret resolved from an ENVIRONMENT VARIABLE
// fallback (settings.GetProbeConfig's orEnv, the same mechanism that would
// resolve a real ARGUS_LLM_API_KEY/ARGUS_CLI_RUNNER_TOKEN in a live
// deployment) that this bundle's own AI-provider probe actually loads into
// memory and sends over the wire, and a secret-shaped value inside an
// audited action's details blob. Both must be structurally absent from the
// marshaled bundle bytes, not merely "not shown in a named field".

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"argus/internal/authz"
	"argus/internal/data"
	"argus/internal/domain"
	"argus/internal/scm"
	"argus/internal/settings"
)

// diagnosticsProviderFixture creates one throwaway ai_providers row with NO
// stored api_key (forcing settings.GetProbeConfig's ARGUS_LLM_API_KEY env
// fallback), pointed at a local httptest server so the probe makes a real
// HTTP call with no external network dependency.
func diagnosticsProviderFixture(t *testing.T, pool *pgxpool.Pool, tenantID, baseURL string) string {
	t.Helper()
	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	// ai_providers deliberately carries no RLS (migration 000034's own
	// comment) but SetRequestScope is harmless here and keeps this fixture
	// consistent with every other one in this package.
	if err := data.SetRequestScope(ctx, tx, tenantID, nil); err != nil {
		t.Fatalf("set request scope: %v", err)
	}
	providerID, err := settings.CreateProvider(ctx, tx, tenantID, settings.ProviderInput{
		Name:    "diag-test-" + domain.NewID(domain.PrefixAIProvider),
		Kind:    settings.KindAPI,
		BaseURL: baseURL,
		Model:   "diag-test-model",
		// Deliberately nil: no stored key, so GetProbeConfig must fall back
		// to the ARGUS_LLM_API_KEY environment variable — see this file's
		// own doc comment.
		APIKey: nil,
	})
	if err != nil {
		t.Fatalf("create ai provider: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit: %v", err)
	}
	t.Cleanup(func() {
		cleanupCtx := context.Background()
		tx, err := pool.Begin(cleanupCtx)
		if err != nil {
			return
		}
		defer tx.Rollback(cleanupCtx) //nolint:errcheck
		_ = settings.DeleteProvider(cleanupCtx, tx, providerID)
		_ = tx.Commit(cleanupCtx)
	})
	return providerID
}

// diagnosticsAuditErrorFixture inserts one outcome=error audit_events row
// whose details contain a secret-shaped value, raw-SQL the same way
// audit_export_db_test.go's setupAuditExportFixture does (a synthetic
// prev_hash/hash, since this row is never meant to participate in the real
// chain — this package's existing precedent for seeding audit_events
// directly rather than through audit.RecordEvent).
func diagnosticsAuditErrorFixture(t *testing.T, pool *pgxpool.Pool, tenantID, secretValue string) {
	t.Helper()
	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if err := data.SetRequestScope(ctx, tx, tenantID, nil); err != nil {
		t.Fatalf("set request scope: %v", err)
	}
	id := domain.NewID(domain.PrefixAuditEvent)
	details, err := json.Marshal(map[string]any{
		"action": "diagnostics_test_probe",
		"detail": "outbound call failed while using " + secretValue,
	})
	if err != nil {
		t.Fatalf("marshal details: %v", err)
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO audit_events (id, tenant_id, outcome, occurred_at, details, prev_hash, hash)
		 VALUES ($1, $2, 'error', now(), $3, 'genesis-test', $4)`,
		id, tenantID, details, "hash-"+id); err != nil {
		t.Fatalf("insert audit event: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit: %v", err)
	}
	t.Cleanup(func() {
		cleanupCtx := context.Background()
		tx, err := pool.Begin(cleanupCtx)
		if err != nil {
			return
		}
		defer tx.Rollback(cleanupCtx) //nolint:errcheck
		if err := data.SetRequestScope(cleanupCtx, tx, tenantID, nil); err != nil {
			return
		}
		_, _ = tx.Exec(cleanupCtx, `DELETE FROM audit_events WHERE id = $1`, id)
		_ = tx.Commit(cleanupCtx)
	})
}

// callDiagnosticsBundle runs the real handler against a real Postgres
// transaction, matching this package's established by-hand request-scoping
// convention for DB-backed handler tests (callExportAuditEvents, etc.) —
// never committed, so any audit write handleGetDiagnosticsBundle itself
// makes is discarded along with the request's own transaction.
func callDiagnosticsBundle(t *testing.T, pool *pgxpool.Pool, tenantID, rawQuery string) *httptest.ResponseRecorder {
	t.Helper()
	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin request transaction: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if err := data.SetRequestScope(ctx, tx, tenantID, nil); err != nil {
		t.Fatalf("set request scope: %v", err)
	}

	path := "/api/v1/diagnostics/bundle"
	if rawQuery != "" {
		path += "?" + rawQuery
	}
	req := httptest.NewRequest(http.MethodGet, path, nil)
	rec := httptest.NewRecorder()
	// A real Store with a throwaway keeper, not scm.NewStore(nil):
	// fetchDiagnosticsRepositories calls ProviderFor for every EXISTING
	// repository binding this tenant has (this dev database can have some
	// from unrelated fixtures), and ProviderFor dereferences s.keeper
	// unconditionally. A binding sealed under a different keeper still
	// fails safely (a local decrypt error, no network call) — it does not
	// need to be OUR binding to be handled correctly, only to not panic.
	s := &Server{db: &data.DB{Pool: pool}, scmStore: scm.NewStore(f28TestKeeper(t))}
	rc := &requestContext{Tx: tx, TenantID: tenantID, UserID: "usr_test_diagnostics", Grants: grantsFor(authz.CapOrgSettingsWrite)}
	s.handleGetDiagnosticsBundle(rec, req, rc)
	return rec
}

// TestHandleGetDiagnosticsBundleNeverLeaksConfiguredOrEnvSecrets is the
// adversarial test T18's instructions ask for by name: seed a known
// secret-shaped value into (a) an environment variable an AI provider's
// resolved configuration actually falls back to, and (b) an audited
// action's details — then prove neither appears ANYWHERE in the bundle's
// raw response bytes, with probe=true so the provider secret really is
// loaded into memory and sent over a real (local) HTTP connection.
func TestHandleGetDiagnosticsBundleNeverLeaksConfiguredOrEnvSecrets(t *testing.T) {
	pool := authTestPool(t)
	ctx := context.Background()
	tenantID, err := singleOrgIDForTest(ctx, pool)
	if err != nil {
		t.Fatalf("resolve tenant: %v", err)
	}
	clusterID := clusterGroupTestCluster(t, pool, tenantID)

	// Detector fixture: one "ok" (never actually observed failing), one
	// never-observed, one currently failing — covers all three
	// diagnosticsStatusFor branches against a real cluster_facts row.
	insertClusterFactsFixtureRaw(t, pool, tenantID, clusterID, `{
		"detectors": {
			"warningEvents": {"lastSuccessAt": "2026-09-18T09:00:00Z"},
			"podConditions": {},
			"sweep": {"error": "jobs is forbidden", "errorAt": "2026-09-18T08:55:00Z", "deniedReads": ["jobs"]}
		}
	}`)

	// A local httptest server, deliberately never expected to actually
	// receive a request: internal/llm's probe HTTP client refuses to dial a
	// private/loopback destination at all (confirmed empirically — its own
	// classifyProbeTransportError reports "outbound: refused 127.0.0.1:
	// loopback address, and this caller's policy does not allow private
	// destinations"), which is a real egress-safety control this test must
	// not weaken just for its own convenience. That refusal still exercises
	// exactly the path this test cares about: settings.GetProbeConfig
	// resolves the real (env-fallback) secret, llm.ProbeProvider receives it
	// and builds a real *http.Request with it in the Authorization header,
	// and ONLY THEN is the destination rejected — so the secret was live in
	// memory and in a constructed request object the whole way through,
	// which is the realistic worst case this test needs to prove doesn't
	// leak. connectivityChecked below confirms the path actually ran rather
	// than being silently skipped.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"invalid api key"}`))
	}))
	defer srv.Close()

	const seededEnvSecret = "sk-ant-oat01-ADVERSARIAL-ENV-SECRET-0001"
	t.Setenv("ARGUS_LLM_API_KEY", seededEnvSecret)
	providerID := diagnosticsProviderFixture(t, pool, tenantID, srv.URL)

	const seededAuditSecret = "AKIAABCDEFGHIJKLMNOP"
	diagnosticsAuditErrorFixture(t, pool, tenantID, seededAuditSecret)

	rec := callDiagnosticsBundle(t, pool, tenantID, "probe=true")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body: %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()

	// The adversarial assertion: neither seeded secret appears ANYWHERE in
	// the raw bytes a caller receives — not "in the field we expected", the
	// whole body.
	if strings.Contains(body, seededEnvSecret) {
		t.Fatalf("bundle leaked the env-fallback AI-provider secret %q:\n%s", seededEnvSecret, body)
	}
	if strings.Contains(body, seededAuditSecret) {
		t.Fatalf("bundle leaked the audit-details secret %q:\n%s", seededAuditSecret, body)
	}

	var got map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}

	// Configuration presence, never value: apiKeySet must be false (the DB
	// column really is empty), even though the probe above resolved and
	// used the env fallback.
	providers, _ := got["aiProviders"].([]any)
	found := false
	for _, raw := range providers {
		p, _ := raw.(map[string]any)
		if p["id"] == providerID {
			found = true
			if apiKeySet, _ := p["apiKeySet"].(bool); apiKeySet {
				t.Errorf("apiKeySet = true, want false — the ai_providers row's own api_key column is empty")
			}
			if checked, _ := p["connectivityChecked"].(bool); !checked {
				t.Errorf("connectivityChecked = false with probe=true, want true")
			}
		}
	}
	if !found {
		t.Fatalf("seeded provider %s not present in aiProviders: %v", providerID, providers)
	}

	// Detector health, derived from the real cluster_facts row.
	clusters, _ := got["clusters"].([]any)
	var clusterEntry map[string]any
	for _, raw := range clusters {
		c, _ := raw.(map[string]any)
		if c["id"] == clusterID {
			clusterEntry = c
		}
	}
	if clusterEntry == nil {
		t.Fatalf("seeded cluster %s not present in clusters", clusterID)
	}
	detectors, ok := clusterEntry["detectors"].(map[string]any)
	if !ok {
		t.Fatalf("clusters[].detectors missing for %s: %v", clusterID, clusterEntry)
	}
	if we, _ := detectors["warningEvents"].(map[string]any); we["status"] != "ok" {
		t.Errorf("warningEvents.status = %v, want %q", we["status"], "ok")
	}
	if pc, _ := detectors["podConditions"].(map[string]any); pc["status"] != "unknown" {
		t.Errorf("podConditions.status = %v, want %q", pc["status"], "unknown")
	}
	if sw, _ := detectors["sweep"].(map[string]any); sw["status"] != "failing" {
		t.Errorf("sweep.status = %v, want %q", sw["status"], "failing")
	}

	// The manifest must exist and say something about what it left out.
	manifest, ok := got["manifest"].(map[string]any)
	if !ok {
		t.Fatalf("manifest missing from response: %v", got)
	}
	if omitted, _ := manifest["omitted"].([]any); len(omitted) == 0 {
		t.Errorf("manifest.omitted is empty — a diagnostics bundle must state what it deliberately left out")
	}
	if included, _ := manifest["included"].([]any); len(included) == 0 {
		t.Errorf("manifest.included is empty")
	}
	sizeBytes, _ := manifest["bundleSizeBytes"].(float64)
	maxBytes, _ := manifest["maxBundleBytes"].(float64)
	if sizeBytes <= 0 || maxBytes <= 0 || sizeBytes > maxBytes {
		t.Errorf("manifest size accounting looks wrong: bundleSizeBytes=%v maxBundleBytes=%v", sizeBytes, maxBytes)
	}

	if disp := rec.Header().Get("Content-Disposition"); !strings.Contains(disp, "attachment") {
		t.Errorf("Content-Disposition = %q, want an attachment so a browser download actually saves a file", disp)
	}
}

// TestHandleGetDiagnosticsBundleDefaultNeverProbesOrSpendsMoney is the other
// half of the opt-in design: without ?probe=true, the AI-provider endpoint
// must never receive a request at all — matching handleTestAIProvider's own
// "never automatically" rule generalized to a bundle download, which is a
// far more casual action than a deliberate per-provider "Test" click.
func TestHandleGetDiagnosticsBundleDefaultNeverProbesOrSpendsMoney(t *testing.T) {
	pool := authTestPool(t)
	ctx := context.Background()
	tenantID, err := singleOrgIDForTest(ctx, pool)
	if err != nil {
		t.Fatalf("resolve tenant: %v", err)
	}

	var requestCount int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requestCount, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	const seededEnvSecret = "sk-ant-oat01-SHOULD-NEVER-BE-TOUCHED"
	t.Setenv("ARGUS_LLM_API_KEY", seededEnvSecret)
	providerID := diagnosticsProviderFixture(t, pool, tenantID, srv.URL)

	rec := callDiagnosticsBundle(t, pool, tenantID, "") // no ?probe=true
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body: %s", rec.Code, rec.Body.String())
	}
	if n := atomic.LoadInt32(&requestCount); n != 0 {
		t.Fatalf("bundle download with no ?probe=true made %d request(s) to the AI provider — it must never probe unless explicitly asked", n)
	}
	if strings.Contains(rec.Body.String(), seededEnvSecret) {
		t.Fatalf("bundle leaked the env secret even though it was never probed:\n%s", rec.Body.String())
	}

	var got map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	manifest, _ := got["manifest"].(map[string]any)
	omitted, _ := manifest["omitted"].([]any)
	sawProbeOmission := false
	for _, raw := range omitted {
		o, _ := raw.(map[string]any)
		if field, _ := o["field"].(string); strings.HasPrefix(field, "live AI-provider") {
			sawProbeOmission = true
		}
	}
	if !sawProbeOmission {
		t.Errorf("manifest.omitted does not explain that connectivity checks were not requested: %v", omitted)
	}

	providers, _ := got["aiProviders"].([]any)
	for _, raw := range providers {
		p, _ := raw.(map[string]any)
		if p["id"] == providerID {
			if checked, _ := p["connectivityChecked"].(bool); checked {
				t.Errorf("connectivityChecked = true with no ?probe=true, want false")
			}
		}
	}
}
