package autoanalyze

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"argus/internal/data"
	"argus/internal/domain"
	"argus/internal/knowledge"
)

// fakeRetrievalProvider is a minimal knowledge.EmbeddingProvider for this
// file's own test: every embedding call returns the SAME fixed direction, so
// a prior analysis this test seeds is guaranteed to be found as "similar" to
// whatever the current incident's own symptom embeds to. Unlike
// internal/knowledge's own fakeProvider (unexported, a different package),
// this one only needs to prove retrieval fired at all, never a specific
// ordering by real similarity — that property is already covered by
// internal/knowledge's own retrieve_test.go.
type fakeRetrievalProvider struct{ dims int }

func (f *fakeRetrievalProvider) Model() string   { return "fake-retrieval-test-model" }
func (f *fakeRetrievalProvider) Dimensions() int { return f.dims }
func (f *fakeRetrievalProvider) Embed(_ context.Context, _ string) ([]float32, error) {
	v := make([]float32, f.dims)
	v[0] = 1
	return v, nil
}

// TestBuildUserPrompt_RetrievalGatedBySetting is PROJECT.md's own regression
// for the retrieval on/off switch (migration 000102): a live measurement
// found 31% higher cost with no measurable confidence benefit on one real
// repeated fault, so retrieval must default OFF and only run when an
// operator deliberately turns settings.Config.RetrievalEnabled on — not
// whenever an embedding provider happens to be configured, which was the
// only previous (and not a real) off switch.
func TestBuildUserPrompt_RetrievalGatedBySetting(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()

	tenantID, clusterID, currentIncidentID := setupRetrievalGateFixture(t, pool)
	provider := &fakeRetrievalProvider{dims: knowledge.DefaultEmbeddingDims}
	store := knowledge.NewStore(pool, provider)
	candidate := incidentCandidate{ID: currentIncidentID, ClusterID: clusterID, Fingerprint: "test-fp", Severity: "high", OccurrenceCount: 1}

	t.Run("default (retrieval_enabled=false): no retrieval section in the prompt", func(t *testing.T) {
		withScopedAutoanalyzeTx(t, pool, tenantID, clusterID, func(tx pgx.Tx) {
			prompt, err := buildUserPrompt(ctx, tx, candidate, store)
			if err != nil {
				t.Fatalf("buildUserPrompt: %v", err)
			}
			if strings.Contains(prompt, "Prior similar investigations") {
				t.Fatalf("prompt contains a retrieval section with retrieval_enabled at its default (false); prompt:\n%s", prompt)
			}
		})
	})

	setOrgRetrievalEnabled(t, pool, tenantID, clusterID, true)

	t.Run("retrieval_enabled=true: the prompt carries the retrieved prior case", func(t *testing.T) {
		withScopedAutoanalyzeTx(t, pool, tenantID, clusterID, func(tx pgx.Tx) {
			prompt, err := buildUserPrompt(ctx, tx, candidate, store)
			if err != nil {
				t.Fatalf("buildUserPrompt: %v", err)
			}
			if !strings.Contains(prompt, "Prior similar investigations") {
				t.Fatalf("prompt has no retrieval section with retrieval_enabled=true, want the prior embedded analysis surfaced; prompt:\n%s", prompt)
			}
		})
	})
}

// Commits rather than rolling back: setOrgRetrievalEnabled's write needs to
// be visible to a LATER, separate transaction (the next subtest's own call
// through this same helper), and a read-only caller (buildUserPrompt) is
// unaffected either way since it writes nothing.
func withScopedAutoanalyzeTx(t *testing.T, pool *pgxpool.Pool, tenantID, clusterID string, fn func(tx pgx.Tx)) {
	t.Helper()
	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if err := data.SetRequestScope(ctx, tx, tenantID, []string{clusterID}); err != nil {
		t.Fatalf("set request scope: %v", err)
	}
	fn(tx)
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit: %v", err)
	}
}

// setOrgRetrievalEnabled flips the singleton org_settings row's
// retrieval_enabled column directly — this test cares about buildUserPrompt
// respecting settings.Config, not about PUT /api/v1/admin/settings' own
// validation, which internal/api/settings_test.go already covers.
func setOrgRetrievalEnabled(t *testing.T, pool *pgxpool.Pool, tenantID, clusterID string, enabled bool) {
	t.Helper()
	withScopedAutoanalyzeTx(t, pool, tenantID, clusterID, func(tx pgx.Tx) {
		if _, err := tx.Exec(context.Background(),
			`UPDATE org_settings SET retrieval_enabled = $1 WHERE id = 'singleton'`, enabled); err != nil {
			t.Fatalf("set org_settings.retrieval_enabled: %v", err)
		}
	})
	t.Cleanup(func() {
		withScopedAutoanalyzeTx(t, pool, tenantID, clusterID, func(tx pgx.Tx) {
			_, _ = tx.Exec(context.Background(), `UPDATE org_settings SET retrieval_enabled = false WHERE id = 'singleton'`)
		})
	})
}

// setupRetrievalGateFixture builds a cluster with two incidents: the one
// under test (currentIncidentID, no analysis of its own) and another,
// already-analyzed-and-embedded one on the SAME cluster — RetrieveSimilar's
// own same-cluster RLS scoping (its doc comment) means both must share one
// cluster for the second to ever be visible to the first's retrieval query.
func setupRetrievalGateFixture(t *testing.T, pool *pgxpool.Pool) (tenantID, clusterID, currentIncidentID string) {
	t.Helper()
	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin setup: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	tenantID, err = data.SingleOrganisationID(ctx, tx)
	if err != nil {
		t.Fatalf("resolve organisation: %v", err)
	}
	clusterID = domain.NewID(domain.PrefixCluster)
	currentIncidentID = domain.NewID(domain.PrefixIncident)
	priorIncidentID := domain.NewID(domain.PrefixIncident)
	priorAnalysisID := domain.NewID(domain.PrefixAnalysis)

	if err := data.SetRequestScope(ctx, tx, tenantID, []string{clusterID}); err != nil {
		t.Fatalf("set request scope: %v", err)
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO clusters (id, tenant_id, display_name, state, shard_id, cluster_fingerprint)
		 VALUES ($1, $2, $3, 'Active', 'shard-test', $4)`,
		clusterID, tenantID, "retrieval-gate-test-"+clusterID, "fp-"+clusterID); err != nil {
		t.Fatalf("insert cluster: %v", err)
	}
	now := time.Now()
	if _, err := tx.Exec(ctx,
		`INSERT INTO incidents (id, tenant_id, cluster_id, fingerprint, severity, state, first_seen, last_seen, occurrence_count, opening_reason, object_key)
		 VALUES ($1, $2, $3, $4, 'high', 'Detected', $5, $5, 1, 'OOMKilled', 'v1,Kind=Pod|ns/current')`,
		currentIncidentID, tenantID, clusterID, "retrieval-gate-fp-"+currentIncidentID, now); err != nil {
		t.Fatalf("insert current incident: %v", err)
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO incidents (id, tenant_id, cluster_id, fingerprint, severity, state, first_seen, last_seen, occurrence_count, opening_reason, object_key)
		 VALUES ($1, $2, $3, $4, 'high', 'Resolved', $5, $5, 1, 'OOMKilled', 'v1,Kind=Pod|ns/prior')`,
		priorIncidentID, tenantID, clusterID, "retrieval-gate-fp-prior-"+priorIncidentID, now.Add(-48*time.Hour)); err != nil {
		t.Fatalf("insert prior incident: %v", err)
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO analyses (id, tenant_id, incident_id, cluster_id, prompt_version, model, causal_chain, ruled_out, root_cause, confidence, iterations, duration_ms, tokens_billed_in, tokens_cache_read, tokens_out, cost_usd)
		 VALUES ($1,$2,$3,$4,'test','test-model','[]'::jsonb,'[]'::jsonb,'{"status":"complete","statement":"memory limit too low"}'::jsonb,0.9,1,1,0,0,0,0)`,
		priorAnalysisID, tenantID, priorIncidentID, clusterID); err != nil {
		t.Fatalf("insert prior analysis: %v", err)
	}

	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit setup: %v", err)
	}

	// Embed the prior analysis so it's actually retrievable.
	store := knowledge.NewStore(pool, &fakeRetrievalProvider{dims: knowledge.DefaultEmbeddingDims})
	if err := store.EmbedAnalysis(ctx, tenantID, clusterID, priorAnalysisID); err != nil {
		t.Fatalf("embed prior analysis: %v", err)
	}

	t.Cleanup(func() {
		cctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		tx, err := pool.Begin(cctx)
		if err != nil {
			t.Logf("cleanup: begin: %v", err)
			return
		}
		defer tx.Rollback(cctx) //nolint:errcheck
		if err := data.SetRequestScope(cctx, tx, tenantID, []string{clusterID}); err != nil {
			t.Logf("cleanup: scope: %v", err)
			return
		}
		if _, err := tx.Exec(cctx, `DELETE FROM analysis_embeddings WHERE analysis_id = $1`, priorAnalysisID); err != nil {
			t.Logf("cleanup: delete embedding: %v", err)
		}
		if _, err := tx.Exec(cctx, `DELETE FROM analyses WHERE id = $1`, priorAnalysisID); err != nil {
			t.Logf("cleanup: delete analysis: %v", err)
		}
		if _, err := tx.Exec(cctx, `DELETE FROM incidents WHERE cluster_id = $1`, clusterID); err != nil {
			t.Logf("cleanup: delete incidents: %v", err)
			return
		}
		if _, err := tx.Exec(cctx, `DELETE FROM clusters WHERE id = $1`, clusterID); err != nil {
			t.Logf("cleanup: delete cluster: %v", err)
			return
		}
		if err := tx.Commit(cctx); err != nil {
			t.Logf("cleanup: commit: %v", err)
		}
	})

	return tenantID, clusterID, currentIncidentID
}
