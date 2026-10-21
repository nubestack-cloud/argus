package api

import (
	"context"
	"testing"
	"time"

	"argus/internal/data"
	"argus/internal/domain"
)

// TestPersistAnalysis_TriggeredBy_ManualVsAuto is BACKLOG.md C6, proved
// against a real Postgres (as argus_app, via analyzeDetachTestPool's
// ARGUS_TEST_DATABASE_URL — never the postgres superuser role, which has
// silently hidden RLS bugs in this codebase before): a manually-triggered
// analysis (the value internal/api/analyze.go's handleAnalyzeIncident
// passes) persists analyses.triggered_by = 'manual', and an
// automatically-triggered one (the value internal/autoanalyze.Poller
// passes) persists 'auto' — never the same value for both, and never
// silently NULL for either. It also proves the column survives a read back
// through getLatestAnalysis, the function GET /incidents/{id} calls to
// build its embedded analysis object, so this isn't just a column that
// exists but one the API contract this task adds actually surfaces.
func TestPersistAnalysis_TriggeredBy_ManualVsAuto(t *testing.T) {
	pool := analyzeDetachTestPool(t)

	for _, tc := range []struct {
		name        string
		triggeredBy string
	}{
		{name: "manual", triggeredBy: TriggeredByManual},
		{name: "auto", triggeredBy: TriggeredByAuto},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tenantID, clusterID, incidentID := analyzeDetachTestIncident(t, pool)
			ctx := context.Background()

			tx, err := pool.Begin(ctx)
			if err != nil {
				t.Fatalf("begin: %v", err)
			}
			defer func() { _ = tx.Rollback(context.Background()) }()
			if err := data.SetRequestScope(ctx, tx, tenantID, []string{clusterID}); err != nil {
				t.Fatalf("set request scope: %v", err)
			}

			result := fakeInvestigationResult()
			analysisID := domain.NewID(domain.PrefixAnalysis)
			if _, err := PersistAnalysis(ctx, tx, tenantID, analysisID, incidentID, clusterID, result, time.Now(), tc.triggeredBy); err != nil {
				t.Fatalf("PersistAnalysis: %v", err)
			}
			if err := tx.Commit(ctx); err != nil {
				t.Fatalf("commit: %v", err)
			}

			// Read back in a FRESH transaction — proves this is durable, not
			// an artifact of reading inside the same transaction that wrote
			// it (same discipline as
			// TestLatestPlanViewForAnalysis_PairedRoute_ReturnsBothDeterministically).
			readTx, err := pool.Begin(ctx)
			if err != nil {
				t.Fatalf("begin read tx: %v", err)
			}
			defer func() { _ = readTx.Rollback(context.Background()) }()
			if err := data.SetRequestScope(ctx, readTx, tenantID, []string{clusterID}); err != nil {
				t.Fatalf("set request scope: %v", err)
			}

			var gotColumn string
			if err := readTx.QueryRow(ctx, `SELECT triggered_by FROM analyses WHERE id = $1`, analysisID).Scan(&gotColumn); err != nil {
				t.Fatalf("read triggered_by column: %v", err)
			}
			if gotColumn != tc.triggeredBy {
				t.Errorf("analyses.triggered_by = %q, want %q", gotColumn, tc.triggeredBy)
			}

			rc := &requestContext{Tx: readTx, TenantID: tenantID}
			resp, err := getLatestAnalysis(ctx, rc, incidentID)
			if err != nil {
				t.Fatalf("getLatestAnalysis: %v", err)
			}
			if resp == nil {
				t.Fatal("getLatestAnalysis returned nil, want the analysis just persisted")
			}
			if resp.TriggeredBy != tc.triggeredBy {
				t.Errorf("getLatestAnalysis TriggeredBy = %q, want %q — GET /incidents/{id}'s embedded analysis must surface this, not just the raw column", resp.TriggeredBy, tc.triggeredBy)
			}
		})
	}
}

// TestPersistAnalysis_TriggeredBy_NeverConflated proves the two constants
// this task adds (TriggeredByManual/TriggeredByAuto) are actually distinct
// values, not the same string under two names — a regression that would
// make every check above pass vacuously while still leaving manual and auto
// analyses indistinguishable, exactly the gap BACKLOG.md C6 reported.
func TestPersistAnalysis_TriggeredBy_NeverConflated(t *testing.T) {
	if TriggeredByManual == TriggeredByAuto {
		t.Fatalf("TriggeredByManual and TriggeredByAuto must be distinct, both were %q", TriggeredByManual)
	}
	if TriggeredByManual == "" || TriggeredByAuto == "" {
		t.Fatalf("neither TriggeredByManual (%q) nor TriggeredByAuto (%q) may be empty — an empty triggered_by is reserved for a pre-migration-000074 row", TriggeredByManual, TriggeredByAuto)
	}
}
