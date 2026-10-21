package knowledge

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"argus/internal/data"
	"argus/internal/domain"
	"argus/internal/orchestrator"
)

// ---- Pure function tests: no database needed for any of these. ----

func TestBuildEmbeddedText(t *testing.T) {
	cases := []struct {
		name                             string
		symptom, rootCause, fix, outcome string
		wantContains                     []string
	}{
		{
			name:      "all fields present",
			symptom:   "ImagePullBackOff on payments/api-7c9",
			rootCause: "expired registry token",
			fix:       "OpenPR on Secret payments/registry-cred (params: {})",
			outcome:   "Resolved",
			wantContains: []string{
				"Symptom: ImagePullBackOff on payments/api-7c9",
				"Root cause: expired registry token",
				"Fix: OpenPR on Secret payments/registry-cred (params: {})",
				"Outcome: Resolved",
			},
		},
		{
			// A partial analysis and/or a still-open incident: every empty
			// field must render an honest placeholder, never a blank line
			// that could be misread as "the model looked and found nothing."
			name:    "everything unknown",
			symptom: "", rootCause: "", fix: "", outcome: "",
			wantContains: []string{
				"Symptom: unknown",
				"Root cause: not determined",
				"Fix: no plan (guidance only)",
				"Outcome: not yet known",
			},
		},
		{
			name:      "guidance-only route, no plan proposed",
			symptom:   "CrashLoopBackOff on default/worker-1",
			rootCause: "OOMKilled repeatedly, limits too low",
			fix:       "",
			outcome:   "not yet known (incident currently RecommendationReady)",
			wantContains: []string{
				"Fix: no plan (guidance only)",
				"Outcome: not yet known (incident currently RecommendationReady)",
			},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := BuildEmbeddedText(c.symptom, c.rootCause, c.fix, c.outcome)
			for _, want := range c.wantContains {
				if !strings.Contains(got, want) {
					t.Errorf("BuildEmbeddedText(%q,%q,%q,%q) = %q, want it to contain %q",
						c.symptom, c.rootCause, c.fix, c.outcome, got, want)
				}
			}
		})
	}
}

func TestBuildSymptom(t *testing.T) {
	cases := []struct {
		reason, objectKey, want string
	}{
		{"ImagePullBackOff", "apps/v1,Kind=Deployment|payments|api", "ImagePullBackOff on payments/api"},
		{"ImagePullBackOff", "", "ImagePullBackOff"},
		{"", "apps/v1,Kind=Deployment|payments|api", "payments/api"},
		{"", "", ""},
		{"NodeNotReady", "v1,Kind=Node||node-1", "NodeNotReady on node-1"}, // cluster-scoped: empty namespace
	}
	for _, c := range cases {
		got := buildSymptom(c.reason, c.objectKey)
		if got != c.want {
			t.Errorf("buildSymptom(%q,%q) = %q, want %q", c.reason, c.objectKey, got, c.want)
		}
	}
}

func TestBuildFix(t *testing.T) {
	empty := buildFix("", "", "", "", "", "")
	if empty != "" {
		t.Errorf("buildFix with no action type = %q, want empty (renders as \"no plan\" by BuildEmbeddedText)", empty)
	}

	withNamespace := buildFix("ScaleDeployment", "apps/v1,Kind=Deployment", "payments", "api", `{"replicas":3}`, "")
	if !strings.Contains(withNamespace, "ScaleDeployment") || !strings.Contains(withNamespace, "payments/api") || !strings.Contains(withNamespace, `{"replicas":3}`) {
		t.Errorf("buildFix = %q, missing expected components", withNamespace)
	}
	if strings.Contains(withNamespace, "approved") || strings.Contains(withNamespace, "rejected") {
		t.Errorf("buildFix with no verdict = %q, should not claim a decision that hasn't been made", withNamespace)
	}

	approved := buildFix("ScaleDeployment", "apps/v1,Kind=Deployment", "payments", "api", `{"replicas":3}`, "approved")
	if !strings.Contains(approved, "approved") {
		t.Errorf("buildFix with verdict=approved = %q, want it to say so", approved)
	}
}

func TestVectorLiteral(t *testing.T) {
	got := vectorLiteral([]float32{0.5, -1, 2.25})
	want := "[0.5,-1,2.25]"
	if got != want {
		t.Errorf("vectorLiteral = %q, want %q", got, want)
	}
	if empty := vectorLiteral(nil); empty != "[]" {
		t.Errorf("vectorLiteral(nil) = %q, want \"[]\"", empty)
	}
}

// ---- fakeProvider: a real EmbeddingProvider for testing everything in this
// package that talks to the database, without a real Ollama call. Returns a
// deterministic (not remotely realistic) vector derived from the input
// text's length, purely so two different EmbedAnalysis calls in the same
// test can be told apart — this is explicitly NOT standing in for "what a
// real embedding call would return" anywhere outside this package's own
// tests. ----

type fakeProvider struct {
	dims  int
	model string

	mu    sync.Mutex
	calls []string
	err   error // when set, Embed always fails with this — for testing that a provider failure writes NOTHING.
}

func newFakeProvider(dims int) *fakeProvider {
	return &fakeProvider{dims: dims, model: "fake-test-model"}
}

func (f *fakeProvider) Model() string   { return f.model }
func (f *fakeProvider) Dimensions() int { return f.dims }

func (f *fakeProvider) Embed(_ context.Context, text string) ([]float32, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, text)
	if f.err != nil {
		return nil, f.err
	}
	v := make([]float32, f.dims)
	for i := range v {
		v[i] = float32(len(text)%97) / 97
	}
	return v, nil
}

func (f *fakeProvider) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

// ---- DB-backed tests: real Postgres behind ARGUS_TEST_DATABASE_URL, same
// precedent and skip-if-unset convention as internal/orchestrator/db_test.go
// and internal/authz/session_test.go. ----

func testPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	connString := os.Getenv("ARGUS_TEST_DATABASE_URL")
	if connString == "" {
		t.Skip("ARGUS_TEST_DATABASE_URL not set; skipping DB-backed knowledge tests")
	}
	pool, err := pgxpool.New(context.Background(), connString)
	if err != nil {
		t.Fatalf("connect to test database: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

// testFixture inserts a throwaway cluster, one incident in startState, and
// one complete analyses row referencing it — everything queryEmbeddingInputs
// needs. Registers cleanup for all three (plus any analysis_embeddings /
// remediation_recommendations / remediation_approval_decisions rows a test
// went on to create against analysisID).
func testFixture(t *testing.T, pool *pgxpool.Pool, startState, openingReason, objectKey, rootCauseJSON string) (tenantID, clusterID, incidentID, analysisID string) {
	t.Helper()
	ctx := context.Background()

	clusterID = domain.NewID(domain.PrefixCluster)
	incidentID = domain.NewID(domain.PrefixIncident)
	analysisID = domain.NewID(domain.PrefixAnalysis)
	fingerprint := "test-knowledge-" + incidentID

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin setup transaction: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	tenantID, err = data.SingleOrganisationID(ctx, tx)
	if err != nil {
		t.Fatalf("resolve organisation: %v", err)
	}
	if err := data.SetRequestScope(ctx, tx, tenantID, []string{clusterID}); err != nil {
		t.Fatalf("set request scope: %v", err)
	}

	if _, err := tx.Exec(ctx,
		`INSERT INTO clusters (id, tenant_id, display_name, state, shard_id, cluster_fingerprint)
		 VALUES ($1, $2, $3, 'Active', 'shard-test', $4)`,
		clusterID, tenantID, "knowledge-test-"+clusterID, "fp-"+clusterID); err != nil {
		t.Fatalf("insert throwaway cluster: %v", err)
	}

	now := time.Now()
	if _, err := tx.Exec(ctx,
		`INSERT INTO incidents (id, tenant_id, cluster_id, fingerprint, severity, state, first_seen, last_seen, occurrence_count, opening_reason, object_key)
		 VALUES ($1, $2, $3, $4, 'high', $5, $6, $6, 1, $7, $8)`,
		incidentID, tenantID, clusterID, fingerprint, startState, now, nullIfEmpty(openingReason), nullIfEmpty(objectKey)); err != nil {
		t.Fatalf("insert test incident in state %s: %v", startState, err)
	}

	if _, err := tx.Exec(ctx,
		`INSERT INTO analyses (
		    id, incident_id, tenant_id, cluster_id, prompt_version, model, causal_chain, ruled_out,
		    root_cause, confidence, iterations, duration_ms, tokens_billed_in, tokens_cache_read, tokens_out,
		    cost_usd, cost_basis, created_at, triggered_by
		 ) VALUES ($1,$2,$3,$4,'v2-tool-loop','test-model','[]','[]',$5,0.9,1,100,0,0,0,0,'metered',$6,'manual')`,
		analysisID, incidentID, tenantID, clusterID, rootCauseJSON, now); err != nil {
		t.Fatalf("insert test analysis: %v", err)
	}

	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit setup transaction: %v", err)
	}

	t.Cleanup(func() {
		cctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		ctx := cctx

		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Errorf("cleanup: begin: %v", err)
			return
		}
		defer tx.Rollback(ctx) //nolint:errcheck
		if err := data.SetRequestScope(ctx, tx, tenantID, []string{clusterID}); err != nil {
			t.Errorf("cleanup: set request scope: %v", err)
			return
		}
		for _, stmt := range []string{
			`DELETE FROM analysis_embeddings WHERE analysis_id = $1`,
			`DELETE FROM remediation_approval_decisions WHERE recommendation_id IN (SELECT id FROM remediation_recommendations WHERE analysis_id = $1)`,
			`DELETE FROM remediation_recommendations WHERE analysis_id = $1`,
			`DELETE FROM analyses WHERE id = $1`,
		} {
			if _, err := tx.Exec(ctx, stmt, analysisID); err != nil {
				t.Errorf("cleanup: %s: %v", stmt, err)
				return
			}
		}
		if _, err := tx.Exec(ctx, `DELETE FROM incidents WHERE id = $1`, incidentID); err != nil {
			t.Errorf("cleanup: delete incident %s: %v", incidentID, err)
			return
		}
		if _, err := tx.Exec(ctx, `DELETE FROM clusters WHERE id = $1`, clusterID); err != nil {
			t.Errorf("cleanup: delete cluster %s: %v", clusterID, err)
			return
		}
		if err := tx.Commit(ctx); err != nil {
			t.Errorf("cleanup: commit: %v", err)
		}
	})

	return tenantID, clusterID, incidentID, analysisID
}

func nullIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// resolveTenantID reads the single organisation row directly off the pool.
// data.SingleOrganisationID takes a pgx.Tx (deliberately — see its own doc
// comment), which *pgxpool.Pool does not satisfy, and opening a throwaway
// transaction for a single no-RLS SELECT (organisations has none, by design)
// would only add ceremony these tests don't need.
func resolveTenantID(t *testing.T, pool *pgxpool.Pool) string {
	t.Helper()
	var id string
	if err := pool.QueryRow(context.Background(), "SELECT id FROM organisations LIMIT 1").Scan(&id); err != nil {
		t.Fatalf("resolve organisation: %v", err)
	}
	return id
}

// withScopedTx runs fn inside a fresh transaction scoped to (tenantID,
// clusterID). analysis_embeddings and incidents both carry FORCE ROW LEVEL
// SECURITY (migrations 000035/000082's two-policy shape — a PERMISSIVE
// tenant_id policy plus a RESTRICTIVE cluster_id one), so a bare
// pool.QueryRow/pool.Exec with no scope set doesn't error, it just sees
// nothing / affects zero rows — exactly the RLS gap class this codebase has
// hit before (internal/data.SetRequestScope's own doc comment, and the
// argus-context skill's "RLS scoping is mandatory" convention). Every
// read-back or direct write these tests do against a scope-bearing table
// goes through this rather than the bare pool.
func withScopedTx(t *testing.T, pool *pgxpool.Pool, tenantID, clusterID string, fn func(ctx context.Context, tx pgx.Tx)) {
	t.Helper()
	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin scoped transaction: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if err := data.SetRequestScope(ctx, tx, tenantID, []string{clusterID}); err != nil {
		t.Fatalf("set request scope: %v", err)
	}
	fn(ctx, tx)
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit scoped transaction: %v", err)
	}
}

func mustMarshalRootCause(t *testing.T, v analysisRootCause) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal root cause fixture: %v", err)
	}
	return string(b)
}

func TestEmbedAnalysis_OpenIncident_WritesRowWithOutcomeNotFinal(t *testing.T) {
	pool := testPool(t)
	rootCause := mustMarshalRootCause(t, analysisRootCause{Status: "complete", Statement: "expired registry token"})
	_, clusterID, incidentID, analysisID := testFixture(t, pool,
		orchestrator.StateRecommendationReady, "ImagePullBackOff", "v1,Kind=Pod|payments|api-1", rootCause)
	tenantID := resolveTenantID(t, pool)

	provider := newFakeProvider(DefaultEmbeddingDims)
	store := NewStore(pool, provider)

	if err := store.EmbedAnalysis(context.Background(), tenantID, clusterID, analysisID); err != nil {
		t.Fatalf("EmbedAnalysis: %v", err)
	}
	if provider.callCount() != 1 {
		t.Fatalf("provider called %d times, want 1", provider.callCount())
	}

	var embeddedText, model string
	var outcomeFinal bool
	var gotIncidentID string
	withScopedTx(t, pool, tenantID, clusterID, func(ctx context.Context, tx pgx.Tx) {
		if err := tx.QueryRow(ctx,
			`SELECT embedded_text, model, outcome_final, incident_id FROM analysis_embeddings WHERE analysis_id = $1`,
			analysisID).Scan(&embeddedText, &model, &outcomeFinal, &gotIncidentID); err != nil {
			t.Fatalf("read back analysis_embeddings row: %v", err)
		}
	})
	if outcomeFinal {
		t.Errorf("outcome_final = true for an open incident (state %s), want false", orchestrator.StateRecommendationReady)
	}
	if gotIncidentID != incidentID {
		t.Errorf("incident_id = %q, want %q", gotIncidentID, incidentID)
	}
	if model != provider.Model() {
		t.Errorf("model = %q, want %q", model, provider.Model())
	}
	if !strings.Contains(embeddedText, "ImagePullBackOff on payments/api-1") {
		t.Errorf("embedded_text = %q, want it to contain the symptom", embeddedText)
	}
	if !strings.Contains(embeddedText, "expired registry token") {
		t.Errorf("embedded_text = %q, want it to contain the root cause", embeddedText)
	}
	if !strings.Contains(embeddedText, "not yet known") {
		t.Errorf("embedded_text = %q, want an honest \"not yet known\" outcome for an open incident", embeddedText)
	}
}

func TestEmbedAnalysis_TerminalIncident_OutcomeFinal(t *testing.T) {
	pool := testPool(t)
	rootCause := mustMarshalRootCause(t, analysisRootCause{Status: "complete", Statement: "expired registry token"})
	_, clusterID, _, analysisID := testFixture(t, pool,
		orchestrator.StateResolved, "ImagePullBackOff", "v1,Kind=Pod|payments|api-1", rootCause)
	tenantID := resolveTenantID(t, pool)

	store := NewStore(pool, newFakeProvider(DefaultEmbeddingDims))
	if err := store.EmbedAnalysis(context.Background(), tenantID, clusterID, analysisID); err != nil {
		t.Fatalf("EmbedAnalysis: %v", err)
	}

	var embeddedText string
	var outcomeFinal bool
	withScopedTx(t, pool, tenantID, clusterID, func(ctx context.Context, tx pgx.Tx) {
		if err := tx.QueryRow(ctx,
			`SELECT embedded_text, outcome_final FROM analysis_embeddings WHERE analysis_id = $1`, analysisID,
		).Scan(&embeddedText, &outcomeFinal); err != nil {
			t.Fatalf("read back analysis_embeddings row: %v", err)
		}
	})
	if !outcomeFinal {
		t.Errorf("outcome_final = false for a %s incident, want true", orchestrator.StateResolved)
	}
	if !strings.Contains(embeddedText, "Outcome: "+orchestrator.StateResolved) {
		t.Errorf("embedded_text = %q, want it to state the real outcome %q", embeddedText, orchestrator.StateResolved)
	}
}

// A partial analysis (no root cause) must never have one fabricated.
func TestEmbedAnalysis_PartialAnalysis_NoFabricatedRootCause(t *testing.T) {
	pool := testPool(t)
	rootCause := mustMarshalRootCause(t, analysisRootCause{Status: "partial", PartialReason: "iteration limit reached"})
	_, clusterID, _, analysisID := testFixture(t, pool,
		orchestrator.StateInvestigating, "CrashLoopBackOff", "v1,Kind=Pod|default|worker-1", rootCause)
	tenantID := resolveTenantID(t, pool)

	store := NewStore(pool, newFakeProvider(DefaultEmbeddingDims))
	if err := store.EmbedAnalysis(context.Background(), tenantID, clusterID, analysisID); err != nil {
		t.Fatalf("EmbedAnalysis: %v", err)
	}

	var embeddedText string
	withScopedTx(t, pool, tenantID, clusterID, func(ctx context.Context, tx pgx.Tx) {
		if err := tx.QueryRow(ctx,
			`SELECT embedded_text FROM analysis_embeddings WHERE analysis_id = $1`, analysisID,
		).Scan(&embeddedText); err != nil {
			t.Fatalf("read back analysis_embeddings row: %v", err)
		}
	})
	if !strings.Contains(embeddedText, "not determined (iteration limit reached)") {
		t.Errorf("embedded_text = %q, want the real partial reason, not a fabricated statement", embeddedText)
	}
}

// The one hard rule: a provider failure must leave no row at all — never a
// zero-vector or placeholder standing in for a real one.
func TestEmbedAnalysis_ProviderFailure_WritesNothing(t *testing.T) {
	pool := testPool(t)
	rootCause := mustMarshalRootCause(t, analysisRootCause{Status: "complete", Statement: "x"})
	_, clusterID, _, analysisID := testFixture(t, pool,
		orchestrator.StateRecommendationReady, "ImagePullBackOff", "v1,Kind=Pod|payments|api-1", rootCause)
	tenantID := resolveTenantID(t, pool)

	provider := newFakeProvider(DefaultEmbeddingDims)
	provider.err = fmt.Errorf("ollama unreachable (simulated)")
	store := NewStore(pool, provider)

	if err := store.EmbedAnalysis(context.Background(), tenantID, clusterID, analysisID); err == nil {
		t.Fatalf("EmbedAnalysis with a failing provider returned no error, want one")
	}

	var count int
	withScopedTx(t, pool, tenantID, clusterID, func(ctx context.Context, tx pgx.Tx) {
		if err := tx.QueryRow(ctx,
			`SELECT count(*) FROM analysis_embeddings WHERE analysis_id = $1`, analysisID,
		).Scan(&count); err != nil {
			t.Fatalf("count analysis_embeddings rows: %v", err)
		}
	})
	if count != 0 {
		t.Errorf("analysis_embeddings has %d row(s) for a failed embed, want 0 (no fabricated placeholder)", count)
	}
}

func TestSelectBackfillCandidates_FindsMissingAndStaleOutcomes(t *testing.T) {
	pool := testPool(t)
	tenantID, clusterID, _, analysisID := testFixture(t, pool,
		orchestrator.StateRecommendationReady, "ImagePullBackOff", "v1,Kind=Pod|payments|api-1",
		mustMarshalRootCause(t, analysisRootCause{Status: "complete", Statement: "x"}))

	store := NewStore(pool, newFakeProvider(DefaultEmbeddingDims))

	// Never embedded — must show up as a candidate.
	candidates, err := store.selectBackfillCandidates(context.Background(), 10000)
	if err != nil {
		t.Fatalf("selectBackfillCandidates: %v", err)
	}
	if !containsAnalysis(candidates, analysisID) {
		t.Fatalf("never-embedded analysis %s not found among %d candidate(s)", analysisID, len(candidates))
	}

	// Embed it while still open (outcome_final = false) — must STILL show up,
	// since its outcome isn't known yet.
	if err := store.EmbedAnalysis(context.Background(), tenantID, clusterID, analysisID); err != nil {
		t.Fatalf("EmbedAnalysis: %v", err)
	}
	candidates, err = store.selectBackfillCandidates(context.Background(), 10000)
	if err != nil {
		t.Fatalf("selectBackfillCandidates: %v", err)
	}
	if !containsAnalysis(candidates, analysisID) {
		t.Fatalf("embedded-but-outcome-not-final analysis %s not found among %d candidate(s)", analysisID, len(candidates))
	}

	// Move the incident to a terminal state and re-embed (what
	// backfillOnce/RunBackfillSweep would do) — now it must drop out.
	withScopedTx(t, pool, tenantID, clusterID, func(ctx context.Context, tx pgx.Tx) {
		if _, err := tx.Exec(ctx,
			`UPDATE incidents SET state = $1 WHERE id = (SELECT incident_id FROM analyses WHERE id = $2)`,
			orchestrator.StateResolved, analysisID); err != nil {
			t.Fatalf("move incident to resolved: %v", err)
		}
	})
	if err := store.EmbedAnalysis(context.Background(), tenantID, clusterID, analysisID); err != nil {
		t.Fatalf("re-embed after resolution: %v", err)
	}
	candidates, err = store.selectBackfillCandidates(context.Background(), 10000)
	if err != nil {
		t.Fatalf("selectBackfillCandidates: %v", err)
	}
	if containsAnalysis(candidates, analysisID) {
		t.Errorf("analysis %s still a candidate after being embedded with a final outcome, want it excluded", analysisID)
	}
}

func containsAnalysis(candidates []backfillCandidate, analysisID string) bool {
	for _, c := range candidates {
		if c.analysisID == analysisID {
			return true
		}
	}
	return false
}

// TriggerAsync must never panic or block the caller, including on a nil
// *Store (embedding not configured) and on a provider failure.
func TestTriggerAsync_NilStoreIsANoOp(t *testing.T) {
	var s *Store
	s.TriggerAsync("tenant", "cluster", "analysis") // must not panic
}

func TestTriggerAsync_CompletesInBackground(t *testing.T) {
	pool := testPool(t)
	tenantID, clusterID, _, analysisID := testFixture(t, pool,
		orchestrator.StateResolved, "ImagePullBackOff", "v1,Kind=Pod|payments|api-1",
		mustMarshalRootCause(t, analysisRootCause{Status: "complete", Statement: "x"}))

	store := NewStore(pool, newFakeProvider(DefaultEmbeddingDims))
	store.TriggerAsync(tenantID, clusterID, analysisID)

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		var count int
		withScopedTx(t, pool, tenantID, clusterID, func(ctx context.Context, tx pgx.Tx) {
			if err := tx.QueryRow(ctx,
				`SELECT count(*) FROM analysis_embeddings WHERE analysis_id = $1`, analysisID,
			).Scan(&count); err != nil {
				t.Fatalf("count analysis_embeddings rows: %v", err)
			}
		})
		if count == 1 {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("TriggerAsync did not write an analysis_embeddings row for %s within 5s", analysisID)
}

// Sanity check that vectorLiteral's output is what pgvector's own text input
// format expects for a realistic dimension count, so a change to the
// formatting helper can't silently drift from what `::vector` will accept.
func TestVectorLiteral_RealisticDimension(t *testing.T) {
	v := make([]float32, DefaultEmbeddingDims)
	for i := range v {
		v[i] = float32(i) / float32(len(v))
	}
	lit := vectorLiteral(v)
	if !strings.HasPrefix(lit, "[") || !strings.HasSuffix(lit, "]") {
		t.Fatalf("vectorLiteral output %q is not bracketed", lit)
	}
	if got := strings.Count(lit, ","); got != len(v)-1 {
		t.Fatalf("vectorLiteral output has %d commas, want %d for a %d-element vector", got, len(v)-1, len(v))
	}
	// Every component must parse back as a float — a NaN/Inf would break the
	// `::vector` cast on the Postgres side with a confusing error far from
	// this code.
	for _, part := range strings.Split(strings.Trim(lit, "[]"), ",") {
		if _, err := strconv.ParseFloat(part, 32); err != nil {
			t.Fatalf("component %q of vectorLiteral output did not parse as a float: %v", part, err)
		}
	}
}
