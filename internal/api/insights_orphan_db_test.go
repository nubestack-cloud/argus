package api

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"argus/internal/data"
	"argus/internal/dbtest"
	"argus/internal/domain"
)

// BUGS.md 102: queryInvestigationOutcomes/queryCostAndTokens/queryDailyTrend
// used to INNER JOIN incidents to reach incidents.cluster_id for the
// clusterID filter, which silently dropped any `analyses` row whose
// incident_id no longer matched a live `incidents` row — a real, confirmed
// case (7 rows from 2026-08-23, after something deleted their
// incidents/clusters rows directly outside any code path that also cleans up
// `analyses`). `analyses.incident_id` carries no foreign key at all (and,
// per 000044/000053's own comments, cannot: `incidents` is PARTITION BY
// RANGE (first_seen) with PRIMARY KEY (id, first_seen), so there is no
// unique constraint on id alone for anything to reference), so this kind of
// orphan is a standing possibility, not a one-off. The fix filters on
// analyses.cluster_id directly — a column analyses already carries
// independently of incidents — instead of joining to reach it.
//
// This fixture reproduces the exact shape: one real incident with two
// ordinary analyses, plus one analysis whose incident_id points at an
// incident id that was never inserted (standing in for "later deleted").
// Every assertion below checks that the orphan is counted exactly like an
// ordinary row, not specially — the whole point of the fix is that
// `analyses` no longer needs a live incident to be correctly reported.
type orphanAnalysisFixture struct {
	tenantID    string
	clusterID   string
	incidentID  string
	orphanedID  string // an incident_id that intentionally has no incidents row
	analysisIDs []string
}

func setupOrphanAnalysisFixture(t *testing.T, pool *pgxpool.Pool) orphanAnalysisFixture {
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
	f := orphanAnalysisFixture{
		tenantID:   tenantID,
		clusterID:  domain.NewID(domain.PrefixCluster),
		incidentID: domain.NewID(domain.PrefixIncident),
		orphanedID: domain.NewID(domain.PrefixIncident), // never inserted below — the orphan
	}
	if err := data.SetRequestScope(ctx, tx, tenantID, []string{f.clusterID}); err != nil {
		t.Fatalf("set request scope: %v", err)
	}

	if _, err := tx.Exec(ctx,
		`INSERT INTO clusters (id, tenant_id, display_name, state, shard_id, cluster_fingerprint)
		 VALUES ($1, $2, $3, 'Active', 'shard-test', $4)`,
		f.clusterID, tenantID, "orphan-analysis-test-"+f.clusterID, "fp-"+f.clusterID); err != nil {
		t.Fatalf("insert cluster: %v", err)
	}
	fixture := dbtest.New(t)
	fixture.Created("clusters", 1)

	now := time.Now()
	if _, err := tx.Exec(ctx,
		`INSERT INTO incidents (id, tenant_id, cluster_id, fingerprint, severity, state, first_seen, last_seen, occurrence_count)
		 VALUES ($1, $2, $3, $4, 'high', 'Detected', $5, $5, 1)`,
		f.incidentID, tenantID, f.clusterID, "orphanfp-"+f.incidentID, now); err != nil {
		t.Fatalf("insert incident: %v", err)
	}
	fixture.Created("incidents", 1)

	insertAnalysis := func(incidentID string, tokensIn int64) string {
		id := domain.NewID(domain.PrefixAnalysis)
		if _, err := tx.Exec(ctx,
			`INSERT INTO analyses (
			   id, incident_id, tenant_id, cluster_id, prompt_version, model, causal_chain, ruled_out,
			   iterations, duration_ms, tokens_billed_in, tokens_cache_read, tokens_out, cost_usd, cost_basis, created_at
			 ) VALUES ($1, $2, $3, $4, 'v1', 'test-model', '[]', '[]', 1, 100, $5, 0, 0, 0, 'metered', $6)`,
			id, incidentID, tenantID, f.clusterID, tokensIn, now); err != nil {
			t.Fatalf("insert analysis %s (incident_id=%s): %v", id, incidentID, err)
		}
		fixture.Created("analyses", 1)
		return id
	}

	// Two ordinary analyses on the real, live incident.
	f.analysisIDs = append(f.analysisIDs, insertAnalysis(f.incidentID, 100))
	f.analysisIDs = append(f.analysisIDs, insertAnalysis(f.incidentID, 200))
	// One orphan: incident_id names an incident that was never inserted
	// (standing in for "already deleted"), exactly BUGS.md 102's live shape.
	f.analysisIDs = append(f.analysisIDs, insertAnalysis(f.orphanedID, 300))

	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit setup transaction: %v", err)
	}

	// dbtest.Fixture (BUGS.md, 2026-09-05): tracks exactly how many rows this
	// fixture created per table and refuses to commit a delete that doesn't
	// affect exactly that count, in either direction — see internal/dbtest's
	// own doc comment. evidence/analysis_embeddings are Created with 0 rows
	// (this fixture inserts none) so the `= ANY($1)` deletes below, which
	// legitimately match zero rows every run, are still checked rather than
	// silently trusted.
	fixture.Created("evidence", 0)
	fixture.Created("analysis_embeddings", 0)
	fixture.Cleanup(pool, func(ctx context.Context, tx pgx.Tx) error {
		return data.SetRequestScope(ctx, tx, tenantID, []string{f.clusterID})
	}, []dbtest.TableDelete{
		{Table: "evidence", SQL: `DELETE FROM evidence WHERE analysis_id = ANY($1)`, Args: []any{f.analysisIDs}},
		{Table: "analysis_embeddings", SQL: `DELETE FROM analysis_embeddings WHERE analysis_id = ANY($1)`, Args: []any{f.analysisIDs}},
		{Table: "analyses", SQL: `DELETE FROM analyses WHERE id = ANY($1)`, Args: []any{f.analysisIDs}},
		{Table: "incidents", SQL: `DELETE FROM incidents WHERE cluster_id = $1`, Args: []any{f.clusterID}},
		{Table: "clusters", SQL: `DELETE FROM clusters WHERE id = $1`, Args: []any{f.clusterID}},
	})

	return f
}

func openOrphanAnalysisTx(t *testing.T, pool *pgxpool.Pool, f orphanAnalysisFixture) (context.Context, pgx.Tx) {
	t.Helper()
	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin transaction: %v", err)
	}
	t.Cleanup(func() { tx.Rollback(ctx) }) //nolint:errcheck
	if err := data.SetRequestScope(ctx, tx, f.tenantID, []string{f.clusterID}); err != nil {
		t.Fatalf("set request scope: %v", err)
	}
	return ctx, tx
}

// TestQueryInvestigationOutcomesCountsOrphanedAnalyses is BUGS.md 102's
// regression test for queryInvestigationOutcomes: three analyses exist
// (two on a live incident, one whose incident_id matches nothing), and all
// three must count.
func TestQueryInvestigationOutcomesCountsOrphanedAnalyses(t *testing.T) {
	pool := authTestPool(t)
	f := setupOrphanAnalysisFixture(t, pool)
	ctx, tx := openOrphanAnalysisTx(t, pool, f)

	got, err := queryInvestigationOutcomes(ctx, tx, f.clusterID, 0)
	if err != nil {
		t.Fatalf("queryInvestigationOutcomes: %v", err)
	}
	if got.TotalAnalyses != 3 {
		t.Errorf("TotalAnalyses = %d, want 3 (the orphaned row must not be silently dropped)", got.TotalAnalyses)
	}
	if got.CompleteCount != 3 {
		t.Errorf("CompleteCount = %d, want 3", got.CompleteCount)
	}
}

// TestQueryCostAndTokensCountsOrphanedAnalyses is the same regression for
// queryCostAndTokens: the orphan's tokens must be included in both the
// count and the averages, and its day must show up in the daily trend.
func TestQueryCostAndTokensCountsOrphanedAnalyses(t *testing.T) {
	pool := authTestPool(t)
	f := setupOrphanAnalysisFixture(t, pool)
	ctx, tx := openOrphanAnalysisTx(t, pool, f)

	got, err := queryCostAndTokens(ctx, tx, f.clusterID, 0)
	if err != nil {
		t.Fatalf("queryCostAndTokens: %v", err)
	}
	if got.TotalInvestigations != 3 {
		t.Errorf("TotalInvestigations = %d, want 3 (the orphaned row must not be silently dropped)", got.TotalInvestigations)
	}
	// Average of 100, 200, 300 tokens_billed_in across all three rows.
	wantAvg := float64(100+200+300) / 3
	if got.AvgTokensBilledIn != wantAvg {
		t.Errorf("AvgTokensBilledIn = %v, want %v (orphan's 300 tokens must be included)", got.AvgTokensBilledIn, wantAvg)
	}

	var totalInTrend int
	for _, d := range got.DailyTrend {
		totalInTrend += d.Investigations
	}
	if totalInTrend != 3 {
		t.Errorf("DailyTrend sums to %d investigations, want 3 (the orphan's day must not lose it)", totalInTrend)
	}
}
