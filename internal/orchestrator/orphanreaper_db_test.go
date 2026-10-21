package orchestrator

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"argus/internal/data"
	"argus/internal/dbtest"
	"argus/internal/domain"
)

// PROJECT.md B157's proof: OrphanReaper must delete every child row whose
// incident_id names an incident that no longer exists, and must leave every
// child row of a STILL-LIVE incident (and every intentionally-unlinked
// findings row) alone.
//
// Every test here calls sweepClusters (not sweep) scoped to its own single,
// freshly-generated cluster ID — see sweepClusters' own doc comment for why
// an unscoped call would be unsafe against this repo's shared dev database
// as opposed to a disposable per-test one.

// zeroVector1024 is a well-formed pgvector text literal for the fixed-size
// vector(1024) column analysis_embeddings.embedding uses (migration 000082)
// — mirrors internal/api/demo_data_db_test.go's helper of the same name;
// its contents don't matter here, only that the row exists and carries a
// real foreign key to the analysis being reaped.
func zeroVector1024() string {
	return "[" + strings.TrimSuffix(strings.Repeat("0,", 1024), ",") + "]"
}

// orphanReaperCluster inserts one throwaway cluster and returns a
// *dbtest.Fixture already tracking it (Created("clusters", 1)) plus a
// setScope callback narrowed to this one cluster. Mirrors breakerFixture's
// split (breaker_db_test.go): the fixture tracks the one row every test
// here shares, and each test decides for itself what else needs to survive
// to its own Cleanup call — which, for these tests, is nothing else: every
// incident/child row created below is either deleted by the test itself
// (simulating the orphaning) or by the OrphanReaper under test, both well
// before Cleanup ever runs.
func orphanReaperCluster(t *testing.T, pool *pgxpool.Pool) (fixture *dbtest.Fixture, tenantID, clusterID string, scope func(context.Context, pgx.Tx) error) {
	t.Helper()
	ctx := context.Background()

	clusterID = domain.NewID(domain.PrefixCluster)

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin setup: %v", err)
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
		clusterID, tenantID, "orphanreaper-test-"+clusterID, "fp-"+clusterID); err != nil {
		t.Fatalf("insert throwaway cluster: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit setup: %v", err)
	}

	fixture = dbtest.New(t)
	fixture.OwnsCluster(tenantID, clusterID)
	fixture.Created("clusters", 1)
	tid, cid := tenantID, clusterID
	scope = func(ctx context.Context, tx pgx.Tx) error {
		return data.SetRequestScope(ctx, tx, tid, []string{cid})
	}
	return fixture, tenantID, clusterID, scope
}

// TestOrphanReaperDeletesChildrenOfDeletedIncident is B157's core case:
// create an incident with a timeline_events, an analyses and a findings
// row, delete the incident directly (exactly what a cluster-scoped test
// cleanup or DELETE /api/v1/demo-data does today, with no cascade), and
// confirm sweepClusters removes all three children and reports doing so.
func TestOrphanReaperDeletesChildrenOfDeletedIncident(t *testing.T) {
	pool := testPool(t)
	_, tenantID, clusterID, scope := orphanReaperCluster(t, pool)
	ctx := context.Background()

	incidentID := domain.NewID(domain.PrefixIncident)
	now := time.Now()

	// Safety net, registered before any child row exists: even if an
	// assertion below fails partway through, this guarantees nothing this
	// test created survives it — scoped by this test's own fresh
	// incidentID/clusterID, which cannot match any other row, so it can
	// never delete more than this test itself inserted.
	t.Cleanup(func() {
		cctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		tx, err := pool.Begin(cctx)
		if err != nil {
			t.Errorf("safety-net cleanup: begin: %v", err)
			return
		}
		defer tx.Rollback(cctx) //nolint:errcheck
		if err := scope(cctx, tx); err != nil {
			t.Errorf("safety-net cleanup: scope: %v", err)
			return
		}
		for _, stmt := range []string{
			`DELETE FROM timeline_events WHERE incident_id = $1`,
			`DELETE FROM analyses WHERE incident_id = $1`,
			`DELETE FROM findings WHERE incident_id = $1`,
			`DELETE FROM incidents WHERE id = $1`,
		} {
			if _, err := tx.Exec(cctx, stmt, incidentID); err != nil {
				t.Errorf("safety-net cleanup: %s: %v", stmt, err)
				return
			}
		}
		if _, err := tx.Exec(cctx, `DELETE FROM clusters WHERE id = $1`, clusterID); err != nil {
			t.Errorf("safety-net cleanup: delete cluster: %v", err)
			return
		}
		if err := tx.Commit(cctx); err != nil {
			t.Errorf("safety-net cleanup: commit: %v", err)
		}
	})

	setupTx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin fixture setup: %v", err)
	}
	if err := scope(ctx, setupTx); err != nil {
		t.Fatalf("scope fixture setup: %v", err)
	}
	if _, err := setupTx.Exec(ctx,
		`INSERT INTO incidents (id, tenant_id, cluster_id, fingerprint, severity, state, first_seen, last_seen, occurrence_count)
		 VALUES ($1, $2, $3, $4, 'high', 'Resolved', $5, $5, 1)`,
		incidentID, tenantID, clusterID, "test-orphanreaper-"+incidentID, now); err != nil {
		t.Fatalf("insert incident: %v", err)
	}
	for i := 0; i < 2; i++ {
		if _, err := setupTx.Exec(ctx,
			`INSERT INTO timeline_events (id, incident_id, tenant_id, cluster_id, event_type, payload)
			 VALUES ($1, $2, $3, $4, 'Detected', '{}'::jsonb)`,
			domain.NewID(domain.PrefixTimelineEvent), incidentID, tenantID, clusterID); err != nil {
			t.Fatalf("insert timeline_events row %d: %v", i, err)
		}
	}
	analysisID := domain.NewID(domain.PrefixAnalysis)
	if _, err := setupTx.Exec(ctx,
		`INSERT INTO analyses
		   (id, tenant_id, incident_id, cluster_id, prompt_version, model, causal_chain,
		    iterations, duration_ms, tokens_billed_in, tokens_cache_read, tokens_out, cost_usd)
		 VALUES ($1, $2, $3, $4, 'test', 'test-model', '[]'::jsonb, 1, 1, 0, 0, 0, 0)`,
		analysisID, tenantID, incidentID, clusterID); err != nil {
		t.Fatalf("insert analysis: %v", err)
	}
	if _, err := setupTx.Exec(ctx,
		`INSERT INTO findings
		   (id, tenant_id, cluster_id, detector_id, detector_version, fingerprint, gvk,
		    namespace, object_name, reason, message, occurrence_count, severity, occurred_at, incident_id)
		 VALUES ($1, $2, $3, 'test-detector', 'v1', $4, 'v1/Pod', 'default', 'orphanreaper-test',
		         'Test', 'test finding', 1, 'low', $5, $6)`,
		domain.NewID(domain.PrefixFinding), tenantID, clusterID, "test-orphanreaper-finding-"+incidentID, now, incidentID); err != nil {
		t.Fatalf("insert finding: %v", err)
	}
	if err := setupTx.Commit(ctx); err != nil {
		t.Fatalf("commit fixture setup: %v", err)
	}

	// Simulate the orphaning bug directly: delete the incident WITHOUT
	// cascading to its children — exactly what internal/gateway/
	// correlation_db_test.go's cluster-scoped cleanups do today, and what
	// DELETE /api/v1/demo-data does in production.
	delTx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin incident delete: %v", err)
	}
	if err := scope(ctx, delTx); err != nil {
		t.Fatalf("scope incident delete: %v", err)
	}
	if _, err := delTx.Exec(ctx, `DELETE FROM incidents WHERE id = $1`, incidentID); err != nil {
		t.Fatalf("delete incident: %v", err)
	}
	if err := delTx.Commit(ctx); err != nil {
		t.Fatalf("commit incident delete: %v", err)
	}

	// Confirm the orphans actually exist before reaping — otherwise a
	// no-op reaper would pass this test for the wrong reason.
	if got := countWhereIncident(t, pool, "timeline_events", incidentID); got != 2 {
		t.Fatalf("precondition: timeline_events for deleted incident: got %d, want 2", got)
	}
	if got := countWhereIncident(t, pool, "analyses", incidentID); got != 1 {
		t.Fatalf("precondition: analyses for deleted incident: got %d, want 1", got)
	}
	if got := countWhereIncident(t, pool, "findings", incidentID); got != 1 {
		t.Fatalf("precondition: findings for deleted incident: got %d, want 1", got)
	}

	reaper := NewOrphanReaper(&data.DB{Pool: pool})
	counts, err := reaper.sweepClusters(ctx, []string{clusterID})
	if err != nil {
		t.Fatalf("sweepClusters: %v", err)
	}
	if counts.TimelineEvents != 2 {
		t.Errorf("counts.TimelineEvents = %d, want 2", counts.TimelineEvents)
	}
	if counts.Analyses != 1 {
		t.Errorf("counts.Analyses = %d, want 1", counts.Analyses)
	}
	if counts.Findings != 1 {
		t.Errorf("counts.Findings = %d, want 1", counts.Findings)
	}

	if got := countWhereIncident(t, pool, "timeline_events", incidentID); got != 0 {
		t.Errorf("timeline_events remaining after sweep: got %d, want 0", got)
	}
	if got := countWhereIncident(t, pool, "analyses", incidentID); got != 0 {
		t.Errorf("analyses remaining after sweep: got %d, want 0", got)
	}
	if got := countWhereIncident(t, pool, "findings", incidentID); got != 0 {
		t.Errorf("findings remaining after sweep: got %d, want 0", got)
	}
}

// TestOrphanReaperDoesNotTouchChildrenOfLiveIncident is the over-deletion
// guard internal/dbtest's own doc comment warns about: a reaper that
// matched too much would be strictly worse than the bug it fixes. An
// incident that is NOT deleted must keep every one of its children after a
// sweep.
func TestOrphanReaperDoesNotTouchChildrenOfLiveIncident(t *testing.T) {
	pool := testPool(t)
	fixture, tenantID, clusterID, scope := orphanReaperCluster(t, pool)
	ctx := context.Background()

	incidentID := domain.NewID(domain.PrefixIncident)
	now := time.Now()

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin setup: %v", err)
	}
	if err := scope(ctx, tx); err != nil {
		t.Fatalf("scope setup: %v", err)
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO incidents (id, tenant_id, cluster_id, fingerprint, severity, state, first_seen, last_seen, occurrence_count)
		 VALUES ($1, $2, $3, $4, 'high', 'Detected', $5, $5, 1)`,
		incidentID, tenantID, clusterID, "test-orphanreaper-live-"+incidentID, now); err != nil {
		t.Fatalf("insert incident: %v", err)
	}
	fixture.Created("incidents", 1)
	if _, err := tx.Exec(ctx,
		`INSERT INTO timeline_events (id, incident_id, tenant_id, cluster_id, event_type, payload)
		 VALUES ($1, $2, $3, $4, 'Detected', '{}'::jsonb)`,
		domain.NewID(domain.PrefixTimelineEvent), incidentID, tenantID, clusterID); err != nil {
		t.Fatalf("insert timeline_events row: %v", err)
	}
	fixture.Created("timeline_events", 1)
	analysisID := domain.NewID(domain.PrefixAnalysis)
	if _, err := tx.Exec(ctx,
		`INSERT INTO analyses
		   (id, tenant_id, incident_id, cluster_id, prompt_version, model, causal_chain,
		    iterations, duration_ms, tokens_billed_in, tokens_cache_read, tokens_out, cost_usd)
		 VALUES ($1, $2, $3, $4, 'test', 'test-model', '[]'::jsonb, 1, 1, 0, 0, 0, 0)`,
		analysisID, tenantID, incidentID, clusterID); err != nil {
		t.Fatalf("insert analysis: %v", err)
	}
	fixture.Created("analyses", 1)
	if _, err := tx.Exec(ctx,
		`INSERT INTO findings
		   (id, tenant_id, cluster_id, detector_id, detector_version, fingerprint, gvk,
		    namespace, object_name, reason, message, occurrence_count, severity, occurred_at, incident_id)
		 VALUES ($1, $2, $3, 'test-detector', 'v1', $4, 'v1/Pod', 'default', 'orphanreaper-live-test',
		         'Test', 'test finding', 1, 'low', $5, $6)`,
		domain.NewID(domain.PrefixFinding), tenantID, clusterID, "test-orphanreaper-live-finding-"+incidentID, now, incidentID); err != nil {
		t.Fatalf("insert finding: %v", err)
	}
	fixture.Created("findings", 1)
	// A findings row with NO incident at all (incident_id NULL) — the
	// intentional case migration 000041 documents (a Finding an
	// incident_tolerations rule suppressed before it ever opened one).
	// Must survive a sweep for a completely different reason than the
	// live incident's own findings row: NULL is never "orphaned", it is
	// "never linked".
	if _, err := tx.Exec(ctx,
		`INSERT INTO findings
		   (id, tenant_id, cluster_id, detector_id, detector_version, fingerprint, gvk,
		    namespace, object_name, reason, message, occurrence_count, severity, occurred_at, incident_id)
		 VALUES ($1, $2, $3, 'test-detector', 'v1', $4, 'v1/Pod', 'default', 'orphanreaper-unlinked-test',
		         'Test', 'test unlinked finding', 1, 'low', $5, NULL)`,
		domain.NewID(domain.PrefixFinding), tenantID, clusterID, "test-orphanreaper-unlinked-finding-"+incidentID, now); err != nil {
		t.Fatalf("insert unlinked finding: %v", err)
	}
	fixture.Created("findings", 1)
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit setup: %v", err)
	}

	reaper := NewOrphanReaper(&data.DB{Pool: pool})
	counts, err := reaper.sweepClusters(ctx, []string{clusterID})
	if err != nil {
		t.Fatalf("sweepClusters: %v", err)
	}
	if counts.Total() != 0 {
		t.Errorf("sweepClusters deleted %+v against a live incident — want nothing touched", counts)
	}

	if got := countWhereIncident(t, pool, "timeline_events", incidentID); got != 1 {
		t.Errorf("timeline_events for live incident: got %d, want 1 (must not be touched)", got)
	}
	if got := countWhereIncident(t, pool, "analyses", incidentID); got != 1 {
		t.Errorf("analyses for live incident: got %d, want 1 (must not be touched)", got)
	}
	if got := countWhereIncident(t, pool, "findings", incidentID); got != 1 {
		t.Errorf("findings for live incident: got %d, want 1 (must not be touched)", got)
	}
	if got := countWhereClusterUnlinkedFindings(t, pool, clusterID); got != 1 {
		t.Errorf("unlinked (incident_id IS NULL) findings for cluster: got %d, want 1 (must not be touched)", got)
	}

	fixture.Cleanup(pool, scope, []dbtest.TableDelete{
		{Table: "timeline_events", SQL: `DELETE FROM timeline_events WHERE incident_id = $1`, Args: []any{incidentID}},
		{Table: "analyses", SQL: `DELETE FROM analyses WHERE incident_id = $1`, Args: []any{incidentID}},
		{Table: "findings", SQL: `DELETE FROM findings WHERE cluster_id = $1`, Args: []any{clusterID}},
		{Table: "incidents", SQL: `DELETE FROM incidents WHERE id = $1`, Args: []any{incidentID}},
		{Table: "clusters", SQL: `DELETE FROM clusters WHERE id = $1`, Args: []any{clusterID}},
	})
}

// TestOrphanReaperReapsAnalysisWithEvidenceAndEmbeddings is BUGS.md 119's
// shape applied to this new mechanism instead of clearDemoData: an orphaned
// analyses row with a surviving evidence row AND a surviving
// analysis_embeddings row must still be reaped, in one pass, with no
// foreign-key violation — proving sweepClusters' evidence/analysis_embeddings-
// before-analyses ordering is actually load-bearing and not just asserted
// in a comment.
func TestOrphanReaperReapsAnalysisWithEvidenceAndEmbeddings(t *testing.T) {
	pool := testPool(t)
	_, tenantID, clusterID, scope := orphanReaperCluster(t, pool)
	ctx := context.Background()

	incidentID := domain.NewID(domain.PrefixIncident)
	analysisID := domain.NewID(domain.PrefixAnalysis)
	now := time.Now()

	t.Cleanup(func() {
		cctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		tx, err := pool.Begin(cctx)
		if err != nil {
			t.Errorf("safety-net cleanup: begin: %v", err)
			return
		}
		defer tx.Rollback(cctx) //nolint:errcheck
		if err := scope(cctx, tx); err != nil {
			t.Errorf("safety-net cleanup: scope: %v", err)
			return
		}
		for _, stmt := range []string{
			`DELETE FROM evidence WHERE incident_id = $1`,
			`DELETE FROM analysis_embeddings WHERE incident_id = $1`,
			`DELETE FROM analyses WHERE incident_id = $1`,
			`DELETE FROM incidents WHERE id = $1`,
		} {
			if _, err := tx.Exec(cctx, stmt, incidentID); err != nil {
				t.Errorf("safety-net cleanup: %s: %v", stmt, err)
				return
			}
		}
		if _, err := tx.Exec(cctx, `DELETE FROM clusters WHERE id = $1`, clusterID); err != nil {
			t.Errorf("safety-net cleanup: delete cluster: %v", err)
			return
		}
		if err := tx.Commit(cctx); err != nil {
			t.Errorf("safety-net cleanup: commit: %v", err)
		}
	})

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin fixture setup: %v", err)
	}
	if err := scope(ctx, tx); err != nil {
		t.Fatalf("scope fixture setup: %v", err)
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO incidents (id, tenant_id, cluster_id, fingerprint, severity, state, first_seen, last_seen, occurrence_count)
		 VALUES ($1, $2, $3, $4, 'high', 'Resolved', $5, $5, 1)`,
		incidentID, tenantID, clusterID, "test-orphanreaper-evidence-"+incidentID, now); err != nil {
		t.Fatalf("insert incident: %v", err)
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO analyses
		   (id, tenant_id, incident_id, cluster_id, prompt_version, model, causal_chain,
		    iterations, duration_ms, tokens_billed_in, tokens_cache_read, tokens_out, cost_usd)
		 VALUES ($1, $2, $3, $4, 'test', 'test-model', '[]'::jsonb, 1, 1, 0, 0, 0, 0)`,
		analysisID, tenantID, incidentID, clusterID); err != nil {
		t.Fatalf("insert analysis: %v", err)
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO evidence (id, analysis_id, tenant_id, cluster_id, kind, size_bytes, redacted, incident_id, tool, outcome, args, result)
		 VALUES ($1, $2, $3, $4, 'tool_call', 10, true, $5, 'get_pod_logs', 'ok', '{}'::jsonb, '{}'::jsonb)`,
		domain.NewID(domain.PrefixEvidence), analysisID, tenantID, clusterID, incidentID); err != nil {
		t.Fatalf("insert evidence: %v", err)
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO analysis_embeddings (analysis_id, incident_id, tenant_id, cluster_id, model, embedded_text, embedding, outcome_final)
		 VALUES ($1, $2, $3, $4, 'bge-m3', 'orphanreaper repro text', $5::vector, false)`,
		analysisID, incidentID, tenantID, clusterID, zeroVector1024()); err != nil {
		t.Fatalf("insert analysis_embeddings: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit fixture setup: %v", err)
	}

	// Orphan it: delete the incident with no cascade, same as every other
	// test in this file.
	delTx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin incident delete: %v", err)
	}
	if err := scope(ctx, delTx); err != nil {
		t.Fatalf("scope incident delete: %v", err)
	}
	if _, err := delTx.Exec(ctx, `DELETE FROM incidents WHERE id = $1`, incidentID); err != nil {
		t.Fatalf("delete incident: %v", err)
	}
	if err := delTx.Commit(ctx); err != nil {
		t.Fatalf("commit incident delete: %v", err)
	}

	reaper := NewOrphanReaper(&data.DB{Pool: pool})
	counts, err := reaper.sweepClusters(ctx, []string{clusterID})
	if err != nil {
		if strings.Contains(err.Error(), "fkey") {
			t.Fatalf("sweepClusters hit a foreign-key violation reaping an analysis with evidence/analysis_embeddings children (BUGS.md 119's shape): %v", err)
		}
		t.Fatalf("sweepClusters: %v", err)
	}
	if counts.Evidence != 1 {
		t.Errorf("counts.Evidence = %d, want 1", counts.Evidence)
	}
	if counts.AnalysisEmbeddings != 1 {
		t.Errorf("counts.AnalysisEmbeddings = %d, want 1", counts.AnalysisEmbeddings)
	}
	if counts.Analyses != 1 {
		t.Errorf("counts.Analyses = %d, want 1", counts.Analyses)
	}

	if got := countWhereIncident(t, pool, "evidence", incidentID); got != 0 {
		t.Errorf("evidence remaining after sweep: got %d, want 0", got)
	}
	if got := countWhereIncident(t, pool, "analysis_embeddings", incidentID); got != 0 {
		t.Errorf("analysis_embeddings remaining after sweep: got %d, want 0", got)
	}
	if got := countWhereIncident(t, pool, "analyses", incidentID); got != 0 {
		t.Errorf("analyses remaining after sweep: got %d, want 0", got)
	}
}

// countWhereIncident is a superuser-free (argus_app, same as production)
// read of how many rows of table match incidentID — table is always one
// of this test file's own five, whose column is always literally named
// incident_id, so building the query from a caller-controlled string is
// safe here (never from request input).
func countWhereIncident(t *testing.T, pool *pgxpool.Pool, table, incidentID string) int {
	t.Helper()
	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("countWhereIncident: begin: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	tenantID, err := data.SingleOrganisationID(ctx, tx)
	if err != nil {
		t.Fatalf("countWhereIncident: resolve organisation: %v", err)
	}
	if err := data.SetRequestScope(ctx, tx, tenantID, nil); err != nil {
		t.Fatalf("countWhereIncident: scope: %v", err)
	}
	var count int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM `+table+` WHERE incident_id = $1`, incidentID).Scan(&count); err != nil {
		t.Fatalf("countWhereIncident: query %s: %v", table, err)
	}
	return count
}

// countWhereClusterUnlinkedFindings counts findings on clusterID with no
// incident at all — the NULL case this file's tests must never delete.
func countWhereClusterUnlinkedFindings(t *testing.T, pool *pgxpool.Pool, clusterID string) int {
	t.Helper()
	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("countWhereClusterUnlinkedFindings: begin: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	tenantID, err := data.SingleOrganisationID(ctx, tx)
	if err != nil {
		t.Fatalf("countWhereClusterUnlinkedFindings: resolve organisation: %v", err)
	}
	if err := data.SetRequestScope(ctx, tx, tenantID, nil); err != nil {
		t.Fatalf("countWhereClusterUnlinkedFindings: scope: %v", err)
	}
	var count int
	if err := tx.QueryRow(ctx,
		`SELECT count(*) FROM findings WHERE cluster_id = $1 AND incident_id IS NULL`, clusterID).Scan(&count); err != nil {
		t.Fatalf("countWhereClusterUnlinkedFindings: query: %v", err)
	}
	return count
}
