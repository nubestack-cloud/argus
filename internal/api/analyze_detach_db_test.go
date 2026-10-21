package api

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"argus/internal/data"
	"argus/internal/dbtest"
	"argus/internal/domain"
	"argus/internal/llm"
	"argus/internal/orchestrator"
	"argus/internal/resolution"
)

// BUGS.md 89: "navigating away from the incident page after clicking
// Analyze appears to stop the analysis." handleAnalyzeIncident used to run
// MarkInvestigating, the whole tool-calling investigation loop, and its
// persistence (PersistAnalysis/ApplyAnalysisResult) all on ONE transaction
// using r.Context() directly — and requireAuth's own eventual Commit of
// that same transaction (middleware.go's completeRequest) reuses that exact
// context too. net/http cancels r.Context() the instant a client's
// connection closes, which is exactly what a browser navigating away
// mid-request does to the fetch that triggered this handler.
//
// These two tests reproduce the mechanism against a real Postgres rather
// than inferring it from reading pgx's source (a throwaway probe against
// this same dev database confirmed: Commit/Exec on an already-cancelled
// context fail immediately AND close the underlying connection — so this is
// not just "the HTTP response can't be delivered," it is "nothing further
// on this transaction can ever become durable"), gated on
// ARGUS_TEST_DATABASE_URL exactly like internal/orchestrator/db_test.go's
// testPool/testIncident (this package's own precedent —
// insights_db_test.go's l4Fixture). A machine without one gets a clean
// skip.
func analyzeDetachTestPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	connString := os.Getenv("ARGUS_TEST_DATABASE_URL")
	if connString == "" {
		t.Skip("ARGUS_TEST_DATABASE_URL not set; skipping BUGS.md 89 detached-context regression test")
	}
	pool, err := pgxpool.New(context.Background(), connString)
	if err != nil {
		t.Fatalf("connect to test database: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

// analyzeDetachTestIncident inserts a throwaway cluster and one Detected
// incident, and registers cleanup for both — the same shape
// orchestrator/db_test.go's testIncident uses, duplicated here rather than
// exported cross-package (that helper is private to its own test file).
func analyzeDetachTestIncident(t *testing.T, pool *pgxpool.Pool) (tenantID, clusterID, incidentID string) {
	t.Helper()
	ctx := context.Background()

	clusterID = domain.NewID(domain.PrefixCluster)
	incidentID = domain.NewID(domain.PrefixIncident)
	fingerprint := "test-bug89-" + incidentID

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
		clusterID, tenantID, "bug89-test-"+clusterID, "fp-"+clusterID); err != nil {
		t.Fatalf("insert throwaway cluster: %v", err)
	}
	now := time.Now()
	if _, err := tx.Exec(ctx,
		`INSERT INTO incidents (id, tenant_id, cluster_id, fingerprint, severity, state, first_seen, last_seen, occurrence_count)
		 VALUES ($1, $2, $3, $4, 'high', $5, $6, $6, 1)`,
		incidentID, tenantID, clusterID, fingerprint, orchestrator.StateDetected, now); err != nil {
		t.Fatalf("insert test incident: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit setup transaction: %v", err)
	}

	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
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
		// timeline_events (BACKLOG.md B1): MarkInvestigating/ApplyAnalysisResult
		// now write it unconditionally, so this fixture leaves rows here too
		// unless cleaned up.
		if _, err := tx.Exec(ctx, `DELETE FROM timeline_events WHERE incident_id = $1`, incidentID); err != nil {
			t.Errorf("cleanup: delete timeline_events: %v", err)
			return
		}
		// BUGS.md 119: same delete-order footgun as clearDemoData — this
		// fixture doesn't insert evidence/analysis_embeddings today, but
		// clearing them before analyses matches every other fixture in this
		// package.
		if _, err := tx.Exec(ctx, `DELETE FROM evidence WHERE analysis_id IN (SELECT id FROM analyses WHERE incident_id = $1)`, incidentID); err != nil {
			t.Errorf("cleanup: delete evidence: %v", err)
			return
		}
		if _, err := tx.Exec(ctx, `DELETE FROM analysis_embeddings WHERE analysis_id IN (SELECT id FROM analyses WHERE incident_id = $1)`, incidentID); err != nil {
			t.Errorf("cleanup: delete analysis_embeddings: %v", err)
			return
		}
		if _, err := tx.Exec(ctx, `DELETE FROM analyses WHERE incident_id = $1`, incidentID); err != nil {
			t.Errorf("cleanup: delete analyses: %v", err)
			return
		}
		// PROJECT.md B175: these two are written by PRODUCT code, not by
		// this fixture — ApplyAnalysisResult persists one recommendation per
		// plan (two for a paired route), and a hop into a notifiable state
		// queues a notification — so reading the fixture's own INSERTs to
		// build this list, which is how it was built, could never have
		// included them. Every run of the tests that call
		// ApplyAnalysisResult left them behind, orphaned onto an incident id
		// that no longer existed. The AssertNoClusterResidue call at the end
		// of this cleanup is what stops the next such table going unnoticed.
		if _, err := tx.Exec(ctx, `DELETE FROM remediation_recommendations WHERE incident_id = $1`, incidentID); err != nil {
			t.Errorf("cleanup: delete remediation_recommendations: %v", err)
			return
		}
		if _, err := tx.Exec(ctx, `DELETE FROM incident_notifications WHERE incident_id = $1`, incidentID); err != nil {
			t.Errorf("cleanup: delete incident_notifications: %v", err)
			return
		}
		if _, err := tx.Exec(ctx, `DELETE FROM incidents WHERE id = $1`, incidentID); err != nil {
			t.Errorf("cleanup: delete incident: %v", err)
			return
		}
		if _, err := tx.Exec(ctx, `DELETE FROM clusters WHERE id = $1`, clusterID); err != nil {
			t.Errorf("cleanup: delete cluster: %v", err)
			return
		}
		if err := tx.Commit(ctx); err != nil {
			t.Errorf("cleanup: commit: %v", err)
			return
		}
		// Asked of the catalogue, not of whoever last edited the list above:
		// every public table carrying a cluster_id must now be empty for this
		// throwaway cluster. A table added by a future migration joins this
		// check the day it lands.
		dbtest.AssertNoClusterResidue(t, pool, tenantID, clusterID)
	})

	return tenantID, clusterID, incidentID
}

// analyzeDetachTestIncidentState reads one incident's state in its own,
// freshly-scoped transaction — never the transaction under test, so it
// really observes what is durable rather than what that transaction's own
// in-progress view would show.
func analyzeDetachTestIncidentState(t *testing.T, pool *pgxpool.Pool, tenantID, clusterID, incidentID string) string {
	t.Helper()
	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin read transaction: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if err := data.SetRequestScope(ctx, tx, tenantID, []string{clusterID}); err != nil {
		t.Fatalf("set request scope: %v", err)
	}
	var state string
	if err := tx.QueryRow(ctx, `SELECT state FROM incidents WHERE id = $1`, incidentID).Scan(&state); err != nil {
		t.Fatalf("read incident state: %v", err)
	}
	return state
}

// fakeInvestigationResult is a deterministic "complete, no proposed plan"
// investigation result, used identically on both sides of the before/after
// comparison below. Paired with resolution.RouteGuidance, orchestrator.
// Advance's own logic (Status "complete" + ProposedPlan nil + route
// guidance) always lands on StateDiagnosed without ever consulting
// remediation.Evaluate or the org's autonomy policy — so this test's outcome
// does not depend on whatever policy this shared dev database's
// org_settings row happens to hold today.
func fakeInvestigationResult() llm.Investigation {
	confidence := 0.9
	return llm.Investigation{
		Model:      "test-model",
		Status:     "complete",
		RootCause:  &llm.RootCause{Statement: "BUGS.md 89 regression test root cause"},
		Confidence: &confidence,
	}
}

// TestAnalyzeIncident_RequestContextCancellation_BeforeFix reproduces the
// bug's mechanism directly: MarkInvestigating, PersistAnalysis and
// ApplyAnalysisResult all run on ONE transaction using a single context,
// and that SAME (by-then-cancelled) context is what the final Commit uses
// too — exactly how handleAnalyzeIncident used to be wired to r.Context()
// and requireAuth's completeRequest. The cancellation is placed right after
// MarkInvestigating, standing in for the browser navigating away at any
// point during the tool-calling loop that used to run next: the effect on
// every subsequent operation sharing that context is identical regardless
// of when, during the loop, the disconnect actually happens.
func TestAnalyzeIncident_RequestContextCancellation_BeforeFix(t *testing.T) {
	pool := analyzeDetachTestPool(t)
	tenantID, clusterID, incidentID := analyzeDetachTestIncident(t, pool)

	reqCtx, cancelReq := context.WithCancel(context.Background())

	tx, err := pool.Begin(reqCtx)
	if err != nil {
		t.Fatalf("begin request-scoped transaction: %v", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()

	if err := data.SetRequestScope(reqCtx, tx, tenantID, []string{clusterID}); err != nil {
		t.Fatalf("set request scope: %v", err)
	}
	if err := orchestrator.MarkInvestigating(reqCtx, tx, tenantID, clusterID, incidentID); err != nil {
		t.Fatalf("MarkInvestigating: %v", err)
	}

	// The browser navigates away mid-investigation: net/http cancels
	// r.Context() right here — before this same request's persistence ever
	// runs, exactly as it would partway through the real tool-calling loop.
	cancelReq()

	result := fakeInvestigationResult()
	analysisID := domain.NewID(domain.PrefixAnalysis)
	_, persistErr := PersistAnalysis(reqCtx, tx, tenantID, analysisID, incidentID, clusterID, result, time.Now(), TriggeredByManual)

	var applyErr error
	if persistErr == nil {
		routeDecision := orchestrator.RouteDecision{Route: resolution.RouteGuidance, Reason: "test", Apply: true}
		_, applyErr = orchestrator.ApplyAnalysisResult(reqCtx, tx, tenantID, clusterID, incidentID, analysisID, result, routeDecision)
	}
	commitErr := tx.Commit(reqCtx)

	if persistErr == nil && applyErr == nil && commitErr == nil {
		t.Fatalf("expected the cancelled-context path to fail somewhere (persist=%v apply=%v commit=%v) — if nothing failed, BUGS.md 89's mechanism does not reproduce as described",
			persistErr, applyErr, commitErr)
	}
	if commitErr == nil {
		t.Errorf("Commit on an already-cancelled context succeeded; expected it to fail — that failure IS the bug, since it discards the whole transaction including MarkInvestigating's own write")
	}

	// The whole point: nothing from this attempt is durable, including
	// MarkInvestigating's own transition — a fresh, independent read must
	// see the incident exactly as it was before Analyze was ever clicked.
	state := analyzeDetachTestIncidentState(t, pool, tenantID, clusterID, incidentID)
	if state != orchestrator.StateDetected {
		t.Errorf("incident state after a cancelled request = %q, want %q (the click left no durable trace at all) — some other state means part of this attempt persisted despite the cancellation",
			state, orchestrator.StateDetected)
	}
}

// TestAnalyzeIncident_RequestContextCancellation_AfterFix proves the fix:
// running the same MarkInvestigating -> PersistAnalysis ->
// ApplyAnalysisResult sequence on a SEPARATE transaction, bound to a context
// detached from the (here, already-cancelled) request context via
// context.WithoutCancel plus its own timeout — exactly the shape
// handleAnalyzeIncident now uses (analyze.go's workCtx/workTx, bounded by
// investigationCommitMargin on top of the investigation's own configured
// time limit) — survives the client having disconnected before any of this
// ran, and the incident reaches its correct terminal analyzed state.
func TestAnalyzeIncident_RequestContextCancellation_AfterFix(t *testing.T) {
	pool := analyzeDetachTestPool(t)
	tenantID, clusterID, incidentID := analyzeDetachTestIncident(t, pool)

	reqCtx, cancelReq := context.WithCancel(context.Background())
	// The browser has ALREADY navigated away before the detached work even
	// starts — the strongest version of the race, and the one a slow first
	// model round-trip makes an entirely ordinary occurrence.
	cancelReq()

	workCtx, cancelWork := context.WithTimeout(context.WithoutCancel(reqCtx), investigationCommitMargin)
	defer cancelWork()

	workTx, err := pool.Begin(workCtx)
	if err != nil {
		t.Fatalf("begin detached transaction: %v", err)
	}
	defer func() { _ = workTx.Rollback(workCtx) }()

	if err := data.SetRequestScope(workCtx, workTx, tenantID, []string{clusterID}); err != nil {
		t.Fatalf("set request scope: %v", err)
	}
	if err := orchestrator.MarkInvestigating(workCtx, workTx, tenantID, clusterID, incidentID); err != nil {
		t.Fatalf("MarkInvestigating: %v", err)
	}

	result := fakeInvestigationResult()
	analysisID := domain.NewID(domain.PrefixAnalysis)
	if _, err := PersistAnalysis(workCtx, workTx, tenantID, analysisID, incidentID, clusterID, result, time.Now(), TriggeredByManual); err != nil {
		t.Fatalf("PersistAnalysis: %v", err)
	}
	routeDecision := orchestrator.RouteDecision{Route: resolution.RouteGuidance, Reason: "test", Apply: true}
	adv, err := orchestrator.ApplyAnalysisResult(workCtx, workTx, tenantID, clusterID, incidentID, analysisID, result, routeDecision)
	if err != nil {
		t.Fatalf("ApplyAnalysisResult: %v", err)
	}
	if err := workTx.Commit(workCtx); err != nil {
		t.Fatalf("Commit on the detached transaction failed despite the request context being cancelled — the fix did not work: %v", err)
	}

	if adv.NextState != orchestrator.StateDiagnosed {
		t.Errorf("Advancement.NextState = %q, want %q", adv.NextState, orchestrator.StateDiagnosed)
	}

	state := analyzeDetachTestIncidentState(t, pool, tenantID, clusterID, incidentID)
	if state != orchestrator.StateDiagnosed {
		t.Errorf("incident state after the detached transaction committed = %q, want %q — the analysis must be durable and the incident correctly advanced despite the request context having been cancelled before any of this ran",
			state, orchestrator.StateDiagnosed)
	}

	// Somebody coming back to the incident (or another operator looking at
	// it right now) must see a real, persisted analysis row — not silence.
	readCtx := context.Background()
	readTx, err := pool.Begin(readCtx)
	if err != nil {
		t.Fatalf("begin read transaction: %v", err)
	}
	defer readTx.Rollback(readCtx) //nolint:errcheck
	if err := data.SetRequestScope(readCtx, readTx, tenantID, []string{clusterID}); err != nil {
		t.Fatalf("set request scope: %v", err)
	}
	var analysisCount int
	if err := readTx.QueryRow(readCtx, `SELECT count(*) FROM analyses WHERE id = $1`, analysisID).Scan(&analysisCount); err != nil {
		t.Fatalf("count analyses: %v", err)
	}
	if analysisCount != 1 {
		t.Errorf("analyses row for %s: got %d rows, want 1 — the investigation's result must be durably recorded", analysisID, analysisCount)
	}
}
