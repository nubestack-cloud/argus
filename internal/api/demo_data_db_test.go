package api

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"argus/internal/data"
	"argus/internal/domain"
)

// --- BUGS.md 119: clearDemoData deleted analyses before its evidence/
// analysis_embeddings children, so any demo analysis that had ever picked up
// either row (a real /analyze run recording evidence, or internal/knowledge's
// backfill sweep embedding it) made DELETE /api/v1/demo-data 500 with a
// foreign-key violation from then on. Reproduced live against this repo's own
// dev Postgres (see the fix's comment in demo_data.go for the exact error);
// this test proves it against a real database rather than relying on the live
// repro alone. Run with the fix reverted (temporarily drop the two DELETE
// statements this bug fix added to clearDemoData's statement list) and this
// test fails with exactly the FK violation the live repro hit
// ("evidence_analysis_id_fkey" / "analysis_embeddings_analysis_id_fkey" on
// table "analyses") — confirmed by hand while fixing this bug.
//
// Every statement here — setup, the call under test, and verification —
// shares one transaction that has had data.SetRequestScope called on it:
// both evidence and analysis_embeddings carry FORCE ROW LEVEL SECURITY with
// no bypass for argus_app, so a query issued without first setting
// app.tenant_id/app.accessible_cluster_ids silently sees zero rows rather
// than erroring — indistinguishable from "already deleted" if you're not
// careful. Gated on ARGUS_TEST_DATABASE_URL exactly like this package's
// authTestPool (auth_test.go) and internal/orchestrator/db_test.go.

// demoDataFixture inserts one cluster/incident/analysis triple that
// clearDemoData is scoped to delete, and returns the ids the test needs.
// Unlike the real demo-data flow, this does NOT need the sentinel
// demoClusterFingerprint — clearDemoData(ctx, tx, clusterID) takes an
// already-resolved cluster id and never looks at the fingerprint itself, so
// any real cluster/incident/analysis triple exercises the same delete-order
// bug.
type demoDataFixture struct {
	tenantID   string
	clusterID  string
	incidentID string
	analysisID string
}

func setupDemoDataFixture(t *testing.T, pool *pgxpool.Pool) demoDataFixture {
	t.Helper()
	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin setup transaction: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	tenantID, err := data.SingleOrganisationID(ctx, tx)
	if err != nil {
		t.Fatalf("resolve organisation: %v", err)
	}

	f := demoDataFixture{
		tenantID:   tenantID,
		clusterID:  domain.NewID(domain.PrefixCluster),
		incidentID: domain.NewID(domain.PrefixIncident),
		analysisID: domain.NewID(domain.PrefixAnalysis),
	}

	if err := data.SetRequestScope(ctx, tx, tenantID, []string{f.clusterID}); err != nil {
		t.Fatalf("set request scope: %v", err)
	}

	if _, err := tx.Exec(ctx,
		`INSERT INTO clusters (id, tenant_id, display_name, state, shard_id, cluster_fingerprint)
		 VALUES ($1, $2, $3, 'Disconnected', 'shard-test', $4)`,
		f.clusterID, tenantID, "bugs119-demo-"+f.clusterID, "fp-"+f.clusterID); err != nil {
		t.Fatalf("insert cluster: %v", err)
	}

	now := time.Now()
	if _, err := tx.Exec(ctx,
		`INSERT INTO incidents (id, tenant_id, cluster_id, fingerprint, severity, state, first_seen, last_seen, occurrence_count, opening_reason, object_key)
		 VALUES ($1, $2, $3, $4, 'high', 'Investigating', $5, $5, 1, 'OOMKilled', $6)`,
		f.incidentID, tenantID, f.clusterID, "bugs119fp-"+f.incidentID, now, "v1/Pod|default|bugs119-"+f.incidentID); err != nil {
		t.Fatalf("insert incident: %v", err)
	}

	if _, err := tx.Exec(ctx,
		`INSERT INTO analyses (
		    id, incident_id, tenant_id, cluster_id, prompt_version, model, causal_chain, ruled_out,
		    iterations, duration_ms, tokens_billed_in, tokens_cache_read, tokens_out, cost_usd, cost_basis, created_at
		 ) VALUES ($1, $2, $3, $4, 'v1', 'fake-model', '[]'::jsonb, '[]'::jsonb, 1, 100, 0, 0, 0, 0, 'metered', $5)`,
		f.analysisID, f.incidentID, tenantID, f.clusterID, now); err != nil {
		t.Fatalf("insert analysis: %v", err)
	}

	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit setup transaction: %v", err)
	}

	t.Cleanup(func() {
		// Best-effort: clearDemoData itself is what's under test and is
		// expected to have already removed everything on success. This only
		// matters when a test fails before calling it, or fails inside it
		// (the whole point of running this against pre-fix code) and leaves
		// rows behind.
		cctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		tx, err := pool.Begin(cctx)
		if err != nil {
			return
		}
		defer tx.Rollback(cctx) //nolint:errcheck
		if err := data.SetRequestScope(cctx, tx, tenantID, []string{f.clusterID}); err != nil {
			return
		}
		for _, stmt := range []struct {
			sql string
			arg string
		}{
			{`DELETE FROM evidence WHERE analysis_id = $1`, f.analysisID},
			{`DELETE FROM analysis_embeddings WHERE analysis_id = $1`, f.analysisID},
			{`DELETE FROM analyses WHERE id = $1`, f.analysisID},
			{`DELETE FROM incidents WHERE id = $1`, f.incidentID},
			{`DELETE FROM clusters WHERE id = $1`, f.clusterID},
		} {
			_, _ = tx.Exec(cctx, stmt.sql, stmt.arg)
		}
		_ = tx.Commit(cctx)
	})

	return f
}

// scopedTx begins a transaction against pool, sets its RLS scope to the
// fixture's tenant/cluster, and fails the test immediately on either error —
// every test below runs its child-row insert, the clearDemoData call under
// test, and its own verification queries all inside the ONE transaction this
// returns, so RLS sees the scope for all three.
func scopedTx(t *testing.T, pool *pgxpool.Pool, f demoDataFixture) (context.Context, pgx.Tx) {
	t.Helper()
	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	t.Cleanup(func() { tx.Rollback(context.Background()) }) //nolint:errcheck
	if err := data.SetRequestScope(ctx, tx, f.tenantID, []string{f.clusterID}); err != nil {
		t.Fatalf("set request scope: %v", err)
	}
	return ctx, tx
}

func mustCount(t *testing.T, ctx context.Context, tx pgx.Tx, query string, arg string) int {
	t.Helper()
	var count int
	if err := tx.QueryRow(ctx, query, arg).Scan(&count); err != nil {
		t.Fatalf("count query %q: %v", query, err)
	}
	return count
}

// zeroVector1024 is a well-formed pgvector text literal for the fixed-size
// vector(1024) column analysis_embeddings.embedding uses (migration 000082)
// — its contents don't matter for this test, only that the row exists and
// carries a real foreign key to the analysis being deleted.
func zeroVector1024() string {
	return "[" + strings.TrimSuffix(strings.Repeat("0,", 1024), ",") + "]"
}

// TestClearDemoDataWithEvidenceRow is BUGS.md 119's evidence-table case:
// clearDemoData must succeed (and actually remove the evidence row) even
// though nothing else ever deletes evidence for this analysis first. Against
// the pre-fix clearDemoData (its own DELETE FROM analyses statement with no
// prior evidence delete), this test fails with the exact
// "evidence_analysis_id_fkey" violation the live repro hit.
func TestClearDemoDataWithEvidenceRow(t *testing.T) {
	pool := authTestPool(t)
	// t.Cleanup (not a plain defer): t.Fatalf triggers runtime.Goexit, which
	// runs this function's own defers before the testing package gets a
	// chance to run t.Cleanup-registered ones. scopedTx below registers its
	// tx.Rollback via t.Cleanup too, and Cleanups run LIFO, so registering
	// pool.Close() as a Cleanup FIRST (here) makes it run LAST — after the
	// transaction's connection has already been released by Rollback. A
	// plain `defer pool.Close()` here deadlocked on the FK-violation path:
	// it ran before the tx was rolled back and blocked forever waiting for
	// a connection that was still checked out (confirmed by hand while
	// writing this test, against pre-fix clearDemoData).
	t.Cleanup(func() { pool.Close() })
	f := setupDemoDataFixture(t, pool)
	ctx, tx := scopedTx(t, pool, f)

	if _, err := tx.Exec(ctx,
		`INSERT INTO evidence (id, analysis_id, tenant_id, cluster_id, kind, size_bytes, redacted, incident_id, tool, outcome, args, result)
		 VALUES ($1, $2, $3, $4, 'tool_call', 10, true, $5, 'get_pod_logs', 'ok', '{}'::jsonb, '{}'::jsonb)`,
		domain.NewID(domain.PrefixEvidence), f.analysisID, f.tenantID, f.clusterID, f.incidentID); err != nil {
		t.Fatalf("insert evidence row: %v", err)
	}

	if err := clearDemoData(ctx, tx, f.clusterID); err != nil {
		if strings.Contains(err.Error(), "evidence_analysis_id_fkey") {
			t.Fatalf("clearDemoData 500s with a foreign-key violation on evidence (BUGS.md 119): %v", err)
		}
		t.Fatalf("clearDemoData: %v", err)
	}

	if got := mustCount(t, ctx, tx, `SELECT count(*) FROM analyses WHERE cluster_id = $1`, f.clusterID); got != 0 {
		t.Errorf("analyses remaining after clearDemoData: got %d, want 0", got)
	}
	if got := mustCount(t, ctx, tx, `SELECT count(*) FROM evidence WHERE analysis_id = $1`, f.analysisID); got != 0 {
		t.Errorf("evidence remaining after clearDemoData: got %d, want 0 — clearDemoData must delete the child row it leaves behind, not just avoid erroring on it", got)
	}

	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit: %v", err)
	}
}

// TestClearDemoDataWithAnalysisEmbeddingsRow is BUGS.md 119's second case:
// the same ordering bug via analysis_embeddings (migration 000082), the
// table internal/knowledge's backfill sweep writes to once it reaches a demo
// analysis — the path the bug report calls out as the one nothing currently
// excludes demo clusters from.
func TestClearDemoDataWithAnalysisEmbeddingsRow(t *testing.T) {
	pool := authTestPool(t)
	// t.Cleanup (not a plain defer): t.Fatalf triggers runtime.Goexit, which
	// runs this function's own defers before the testing package gets a
	// chance to run t.Cleanup-registered ones. scopedTx below registers its
	// tx.Rollback via t.Cleanup too, and Cleanups run LIFO, so registering
	// pool.Close() as a Cleanup FIRST (here) makes it run LAST — after the
	// transaction's connection has already been released by Rollback. A
	// plain `defer pool.Close()` here deadlocked on the FK-violation path:
	// it ran before the tx was rolled back and blocked forever waiting for
	// a connection that was still checked out (confirmed by hand while
	// writing this test, against pre-fix clearDemoData).
	t.Cleanup(func() { pool.Close() })
	f := setupDemoDataFixture(t, pool)
	ctx, tx := scopedTx(t, pool, f)

	if _, err := tx.Exec(ctx,
		`INSERT INTO analysis_embeddings (analysis_id, incident_id, tenant_id, cluster_id, model, embedded_text, embedding, outcome_final)
		 VALUES ($1, $2, $3, $4, 'bge-m3', 'bugs119 repro text', $5::vector, false)`,
		f.analysisID, f.incidentID, f.tenantID, f.clusterID, zeroVector1024()); err != nil {
		t.Fatalf("insert analysis_embeddings row: %v", err)
	}

	if err := clearDemoData(ctx, tx, f.clusterID); err != nil {
		if strings.Contains(err.Error(), "analysis_embeddings_analysis_id_fkey") {
			t.Fatalf("clearDemoData 500s with a foreign-key violation on analysis_embeddings (BUGS.md 119): %v", err)
		}
		t.Fatalf("clearDemoData: %v", err)
	}

	if got := mustCount(t, ctx, tx, `SELECT count(*) FROM analyses WHERE cluster_id = $1`, f.clusterID); got != 0 {
		t.Errorf("analyses remaining after clearDemoData: got %d, want 0", got)
	}
	if got := mustCount(t, ctx, tx, `SELECT count(*) FROM analysis_embeddings WHERE analysis_id = $1`, f.analysisID); got != 0 {
		t.Errorf("analysis_embeddings remaining after clearDemoData: got %d, want 0", got)
	}

	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit: %v", err)
	}
}

// TestClearDemoDataWithBothChildRows covers both child tables on the same
// analysis at once — the realistic end state described in BUGS.md 119 (a
// demo analysis a human investigated manually, later also reached by the
// embedding backfill sweep).
func TestClearDemoDataWithBothChildRows(t *testing.T) {
	pool := authTestPool(t)
	// t.Cleanup (not a plain defer): t.Fatalf triggers runtime.Goexit, which
	// runs this function's own defers before the testing package gets a
	// chance to run t.Cleanup-registered ones. scopedTx below registers its
	// tx.Rollback via t.Cleanup too, and Cleanups run LIFO, so registering
	// pool.Close() as a Cleanup FIRST (here) makes it run LAST — after the
	// transaction's connection has already been released by Rollback. A
	// plain `defer pool.Close()` here deadlocked on the FK-violation path:
	// it ran before the tx was rolled back and blocked forever waiting for
	// a connection that was still checked out (confirmed by hand while
	// writing this test, against pre-fix clearDemoData).
	t.Cleanup(func() { pool.Close() })
	f := setupDemoDataFixture(t, pool)
	ctx, tx := scopedTx(t, pool, f)

	if _, err := tx.Exec(ctx,
		`INSERT INTO evidence (id, analysis_id, tenant_id, cluster_id, kind, size_bytes, redacted, incident_id, tool, outcome, args, result)
		 VALUES ($1, $2, $3, $4, 'tool_call', 10, true, $5, 'get_pod_logs', 'ok', '{}'::jsonb, '{}'::jsonb)`,
		domain.NewID(domain.PrefixEvidence), f.analysisID, f.tenantID, f.clusterID, f.incidentID); err != nil {
		t.Fatalf("insert evidence row: %v", err)
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO analysis_embeddings (analysis_id, incident_id, tenant_id, cluster_id, model, embedded_text, embedding, outcome_final)
		 VALUES ($1, $2, $3, $4, 'bge-m3', 'bugs119 repro text', $5::vector, false)`,
		f.analysisID, f.incidentID, f.tenantID, f.clusterID, zeroVector1024()); err != nil {
		t.Fatalf("insert analysis_embeddings row: %v", err)
	}

	if err := clearDemoData(ctx, tx, f.clusterID); err != nil {
		t.Fatalf("clearDemoData with both evidence and analysis_embeddings rows present (BUGS.md 119): %v", err)
	}

	if got := mustCount(t, ctx, tx, `SELECT count(*) FROM clusters WHERE id = $1`, f.clusterID); got != 0 {
		t.Errorf("cluster remaining after clearDemoData: got %d, want 0", got)
	}
	if got := mustCount(t, ctx, tx, `SELECT count(*) FROM evidence WHERE analysis_id = $1`, f.analysisID); got != 0 {
		t.Errorf("evidence remaining after clearDemoData: got %d, want 0", got)
	}
	if got := mustCount(t, ctx, tx, `SELECT count(*) FROM analysis_embeddings WHERE analysis_id = $1`, f.analysisID); got != 0 {
		t.Errorf("analysis_embeddings remaining after clearDemoData: got %d, want 0", got)
	}

	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit: %v", err)
	}
}
