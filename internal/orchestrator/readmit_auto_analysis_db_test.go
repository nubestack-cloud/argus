package orchestrator

import (
	"context"
	"testing"
	"time"

	"argus/internal/data"
)

// TestReadmitForAutoAnalysis is the regression test for the gap found live
// 2026-10-13 (see ReadmitForAutoAnalysis's own doc comment): a Finding
// recurring on a Diagnosed/NeedsHumanInvestigation incident never reset
// auto_analysis_attempted_at, so an incident whose first analysis already
// completed had no automatic path back to a fresh conclusion after it
// recurred, no matter how long it then sat quiet — sweepSelfHealing
// correctly refuses to close it against a conclusion a later recurrence
// invalidated (TestSelfHealSweeper_RecurrenceDuringGracePeriodPreventsClose
// pins that this permanence is deliberate), but nothing produced the fresh
// analysis that permanence is waiting for.
func TestReadmitForAutoAnalysis(t *testing.T) {
	pool := testPool(t)
	fixture, tenantID, clusterID, addIncident := selfHealFixture(t, pool)
	ctx := context.Background()

	setAttemptedAndReopenCount := func(incidentID string, attempted bool, reopenCount int) {
		t.Helper()
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatalf("begin: %v", err)
		}
		defer tx.Rollback(ctx) //nolint:errcheck
		if err := data.SetRequestScope(ctx, tx, tenantID, []string{clusterID}); err != nil {
			t.Fatalf("scope: %v", err)
		}
		var attemptedAt any
		if attempted {
			attemptedAt = time.Now().Add(-time.Hour)
		}
		if _, err := tx.Exec(ctx,
			`UPDATE incidents SET auto_analysis_attempted_at = $2, auto_analysis_reopen_count = $3 WHERE id = $1`,
			incidentID, attemptedAt, reopenCount); err != nil {
			t.Fatalf("set attempted/reopen_count: %v", err)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatalf("commit: %v", err)
		}
	}

	readBack := func(incidentID string) (attempted bool, reopenCount int) {
		t.Helper()
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatalf("begin: %v", err)
		}
		defer tx.Rollback(ctx) //nolint:errcheck
		if err := data.SetRequestScope(ctx, tx, tenantID, []string{clusterID}); err != nil {
			t.Fatalf("scope: %v", err)
		}
		var attemptedAt *time.Time
		if err := tx.QueryRow(ctx,
			`SELECT auto_analysis_attempted_at, auto_analysis_reopen_count FROM incidents WHERE id = $1`,
			incidentID).Scan(&attemptedAt, &reopenCount); err != nil {
			t.Fatalf("read back: %v", err)
		}
		return attemptedAt != nil, reopenCount
	}

	concludedAt := time.Now().Add(-2 * time.Hour)
	lastSeen := concludedAt.Add(-time.Minute)
	rootCause := map[string]any{"status": "complete", "statement": "transient; cleared on its own", "isFault": false}

	t.Run("Diagnosed with a spent gate and budget left gets re-armed", func(t *testing.T) {
		incidentID := addIncident(StateDiagnosed, rootCause, concludedAt, lastSeen)
		setAttemptedAndReopenCount(incidentID, true, 0)

		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatalf("begin: %v", err)
		}
		if err := data.SetRequestScope(ctx, tx, tenantID, []string{clusterID}); err != nil {
			t.Fatalf("scope: %v", err)
		}
		if err := ReadmitForAutoAnalysis(ctx, tx, incidentID, StateDiagnosed); err != nil {
			t.Fatalf("ReadmitForAutoAnalysis: %v", err)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatalf("commit: %v", err)
		}

		attempted, reopenCount := readBack(incidentID)
		if attempted {
			t.Error("auto_analysis_attempted_at was not reset to NULL — incident stays permanently ineligible for automatic re-analysis")
		}
		if reopenCount != 1 {
			t.Errorf("auto_analysis_reopen_count = %d, want 1", reopenCount)
		}
	})

	t.Run("NeedsHumanInvestigation with a spent gate also gets re-armed", func(t *testing.T) {
		incidentID := addIncident(StateNeedsHumanInvestigation, rootCause, concludedAt, lastSeen)
		setAttemptedAndReopenCount(incidentID, true, 0)

		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatalf("begin: %v", err)
		}
		if err := data.SetRequestScope(ctx, tx, tenantID, []string{clusterID}); err != nil {
			t.Fatalf("scope: %v", err)
		}
		if err := ReadmitForAutoAnalysis(ctx, tx, incidentID, StateNeedsHumanInvestigation); err != nil {
			t.Fatalf("ReadmitForAutoAnalysis: %v", err)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatalf("commit: %v", err)
		}

		attempted, _ := readBack(incidentID)
		if attempted {
			t.Error("NeedsHumanInvestigation incident was not re-armed the same way Diagnosed is")
		}
	})

	t.Run("never-attempted incident is left alone", func(t *testing.T) {
		incidentID := addIncident(StateDiagnosed, rootCause, concludedAt, lastSeen)
		setAttemptedAndReopenCount(incidentID, false, 0)

		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatalf("begin: %v", err)
		}
		if err := data.SetRequestScope(ctx, tx, tenantID, []string{clusterID}); err != nil {
			t.Fatalf("scope: %v", err)
		}
		if err := ReadmitForAutoAnalysis(ctx, tx, incidentID, StateDiagnosed); err != nil {
			t.Fatalf("ReadmitForAutoAnalysis: %v", err)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatalf("commit: %v", err)
		}

		attempted, reopenCount := readBack(incidentID)
		if attempted {
			t.Error("attempted_at should still be NULL")
		}
		if reopenCount != 0 {
			t.Errorf("auto_analysis_reopen_count = %d, want 0 — a no-op must not spend budget", reopenCount)
		}
	})

	t.Run("budget already exhausted leaves the gate permanently spent", func(t *testing.T) {
		incidentID := addIncident(StateDiagnosed, rootCause, concludedAt, lastSeen)
		setAttemptedAndReopenCount(incidentID, true, maxAutoAnalysisReopens)

		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatalf("begin: %v", err)
		}
		if err := data.SetRequestScope(ctx, tx, tenantID, []string{clusterID}); err != nil {
			t.Fatalf("scope: %v", err)
		}
		if err := ReadmitForAutoAnalysis(ctx, tx, incidentID, StateDiagnosed); err != nil {
			t.Fatalf("ReadmitForAutoAnalysis: %v", err)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatalf("commit: %v", err)
		}

		attempted, reopenCount := readBack(incidentID)
		if !attempted {
			t.Error("a chronically flip-flopping incident must stop re-arming once its budget is spent, same as the Reopened transition's own bound")
		}
		if reopenCount != maxAutoAnalysisReopens {
			t.Errorf("auto_analysis_reopen_count = %d, want unchanged %d", reopenCount, maxAutoAnalysisReopens)
		}
	})

	t.Run("a state outside the self-heal pair is left alone", func(t *testing.T) {
		incidentID := addIncident(StateInvestigating, rootCause, concludedAt, lastSeen)
		setAttemptedAndReopenCount(incidentID, true, 0)

		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatalf("begin: %v", err)
		}
		if err := data.SetRequestScope(ctx, tx, tenantID, []string{clusterID}); err != nil {
			t.Fatalf("scope: %v", err)
		}
		if err := ReadmitForAutoAnalysis(ctx, tx, incidentID, StateInvestigating); err != nil {
			t.Fatalf("ReadmitForAutoAnalysis: %v", err)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatalf("commit: %v", err)
		}

		attempted, reopenCount := readBack(incidentID)
		if !attempted {
			t.Error("Investigating is not one of the two self-heal states; ReadmitForAutoAnalysis must not touch it")
		}
		if reopenCount != 0 {
			t.Errorf("auto_analysis_reopen_count = %d, want unchanged 0", reopenCount)
		}
	})

	fixture.Created("timeline_events", 0)
	cleanupSelfHealFixture(fixture, pool, tenantID, clusterID)
}
