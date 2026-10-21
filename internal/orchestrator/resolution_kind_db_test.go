package orchestrator

import (
	"context"
	"testing"
	"time"

	"argus/internal/data"
	"argus/internal/domain"
)

// This file is BACKLOG.md T2's DB-backed proof for migration 000091's
// resolution_kind: SetState must call the split correctly in both
// directions — a genuinely-executed incident must never read as
// self-healed, and vice versa — and must leave Dismissed alone entirely.
// state_test.go's pure tests already cover the transition table itself;
// what only a real Postgres can show is that SetState's own UPDATE actually
// lands the right value, keyed on real remediation_executions/pr_merged_at
// rows rather than on what a test merely asserts in Go.

// TestSetStateResolutionKind_SelfHealedWithNoLinkedRemediation reproduces
// the common case measured 2026-09-04 on this dev DB (roughly 88% of
// Resolved incidents): nothing was ever executed and no pull request was
// ever merged for this incident, so closing it must record
// "self_healed" — matching autoanalyze.go's objectIsGone/stale-object
// closes and a plain human resolve with nothing behind it.
func TestSetStateResolutionKind_SelfHealedWithNoLinkedRemediation(t *testing.T) {
	pool := testPool(t)
	tenantID, clusterID, incidentID, _ := testIncident(t, pool, StateNeedsHumanInvestigation)
	ctx := context.Background()

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if err := data.SetRequestScope(ctx, tx, tenantID, []string{clusterID}); err != nil {
		t.Fatalf("set request scope: %v", err)
	}

	if err := SetState(ctx, tx, incidentID, StateResolved); err != nil {
		t.Fatalf("NeedsHumanInvestigation -> Resolved: %v", err)
	}

	var kind *string
	if err := tx.QueryRow(ctx, `SELECT resolution_kind FROM incidents WHERE id = $1`, incidentID).Scan(&kind); err != nil {
		t.Fatalf("read resolution_kind: %v", err)
	}
	if kind == nil || *kind != resolutionKindSelfHealed {
		t.Fatalf("resolution_kind = %v, want %q (no execution or merged PR is linked to this incident)", kind, resolutionKindSelfHealed)
	}
}

// TestSetStateResolutionKind_RemediatedWithSucceededExecution is the other
// direction: a real remediation_executions row with outcome='succeeded'
// exists for this incident (the in-place channel, ValidationSweeper's own
// "Route == inPlace" case) — closing it must say "remediated", never
// "self_healed", or the whole point of the split (telling a real fix apart
// from attrition) would be lost for the exact incidents it exists to credit.
func TestSetStateResolutionKind_RemediatedWithSucceededExecution(t *testing.T) {
	pool := testPool(t)
	tenantID, clusterID, incidentID, _ := testIncident(t, pool, StateValidating)
	ctx := context.Background()

	setupTx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin setup: %v", err)
	}
	if err := data.SetRequestScope(ctx, setupTx, tenantID, []string{clusterID}); err != nil {
		setupTx.Rollback(ctx) //nolint:errcheck
		t.Fatalf("set request scope: %v", err)
	}
	analysisID := domain.NewID(domain.PrefixAnalysis)
	recommendationID := domain.NewID(domain.PrefixPlan)
	executionID := domain.NewID(domain.PrefixExecution)
	// A minimal, real remediation_recommendations row — remediation_executions'
	// recommendation_id is NOT NULL REFERENCES remediation_recommendations(id),
	// so a succeeded execution cannot exist without one.
	if _, err := setupTx.Exec(ctx,
		`INSERT INTO remediation_recommendations
		   (id, incident_id, tenant_id, cluster_id, analysis_id, action_type,
		    target_gvk, target_namespace, target_name, params, reversible, risk_level,
		    gate_outcome, gate_reason)
		 VALUES ($1, $2, $3, $4, $5, 'ScaleDeployment', 'apps/v1/Deployment', 'default', 'test-workload',
		         '{"replicas": 3}', true, 'low', 'NeedsApproval', 'test fixture')`,
		recommendationID, incidentID, tenantID, clusterID, analysisID); err != nil {
		setupTx.Rollback(ctx) //nolint:errcheck
		t.Fatalf("insert test recommendation: %v", err)
	}
	if _, err := setupTx.Exec(ctx,
		`INSERT INTO remediation_executions
		   (id, recommendation_id, incident_id, tenant_id, cluster_id, outcome, executed_at)
		 VALUES ($1, $2, $3, $4, $5, 'succeeded', now())`,
		executionID, recommendationID, incidentID, tenantID, clusterID); err != nil {
		setupTx.Rollback(ctx) //nolint:errcheck
		t.Fatalf("insert test execution: %v", err)
	}
	if err := setupTx.Commit(ctx); err != nil {
		t.Fatalf("commit setup: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		cleanupTx, err := pool.Begin(ctx)
		if err != nil {
			t.Errorf("cleanup: begin: %v", err)
			return
		}
		defer cleanupTx.Rollback(ctx) //nolint:errcheck
		if err := data.SetRequestScope(ctx, cleanupTx, tenantID, []string{clusterID}); err != nil {
			t.Errorf("cleanup: set request scope: %v", err)
			return
		}
		if _, err := cleanupTx.Exec(ctx, `DELETE FROM remediation_executions WHERE id = $1`, executionID); err != nil {
			t.Errorf("cleanup: delete execution: %v", err)
			return
		}
		if _, err := cleanupTx.Exec(ctx, `DELETE FROM remediation_recommendations WHERE id = $1`, recommendationID); err != nil {
			t.Errorf("cleanup: delete recommendation: %v", err)
			return
		}
		if err := cleanupTx.Commit(ctx); err != nil {
			t.Errorf("cleanup: commit: %v", err)
		}
	})

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if err := data.SetRequestScope(ctx, tx, tenantID, []string{clusterID}); err != nil {
		t.Fatalf("set request scope: %v", err)
	}

	if err := SetState(ctx, tx, incidentID, StateResolved); err != nil {
		t.Fatalf("Validating -> Resolved: %v", err)
	}

	var kind *string
	if err := tx.QueryRow(ctx, `SELECT resolution_kind FROM incidents WHERE id = $1`, incidentID).Scan(&kind); err != nil {
		t.Fatalf("read resolution_kind: %v", err)
	}
	if kind == nil || *kind != resolutionKindRemediated {
		t.Fatalf("resolution_kind = %v, want %q (a succeeded execution is linked to this incident)", kind, resolutionKindRemediated)
	}
}

// TestSetStateResolutionKind_RemediatedWithMergedPullRequest is the second
// remediated shape: no remediation_executions row at all (the PR channel
// never writes one — BUGS.md 77), but incidents.pr_merged_at is set. Closing
// it must still say "remediated" — deriveResolutionKind's OR, not just its
// first half.
func TestSetStateResolutionKind_RemediatedWithMergedPullRequest(t *testing.T) {
	pool := testPool(t)
	tenantID, clusterID, incidentID, _ := testIncident(t, pool, StateAwaitingMerge)
	ctx := context.Background()

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if err := data.SetRequestScope(ctx, tx, tenantID, []string{clusterID}); err != nil {
		t.Fatalf("set request scope: %v", err)
	}

	if _, err := tx.Exec(ctx, `UPDATE incidents SET pr_merged_at = now() WHERE id = $1`, incidentID); err != nil {
		t.Fatalf("stamp pr_merged_at: %v", err)
	}

	if err := SetState(ctx, tx, incidentID, StateResolved); err != nil {
		t.Fatalf("AwaitingMerge -> Resolved: %v", err)
	}

	var kind *string
	if err := tx.QueryRow(ctx, `SELECT resolution_kind FROM incidents WHERE id = $1`, incidentID).Scan(&kind); err != nil {
		t.Fatalf("read resolution_kind: %v", err)
	}
	if kind == nil || *kind != resolutionKindRemediated {
		t.Fatalf("resolution_kind = %v, want %q (a merged pull request is linked to this incident)", kind, resolutionKindRemediated)
	}
}

// TestSetStateResolutionKind_DismissedGetsNoResolutionKind: a human
// rejecting a plan is a different fact than "this closed, and here is what
// closed it" (migration 000091's own comment) — Dismissed must leave
// resolution_kind NULL, never guess.
func TestSetStateResolutionKind_DismissedGetsNoResolutionKind(t *testing.T) {
	pool := testPool(t)
	tenantID, clusterID, incidentID, _ := testIncident(t, pool, StateAwaitingApproval)
	ctx := context.Background()

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if err := data.SetRequestScope(ctx, tx, tenantID, []string{clusterID}); err != nil {
		t.Fatalf("set request scope: %v", err)
	}

	if err := SetState(ctx, tx, incidentID, StateDismissed); err != nil {
		t.Fatalf("AwaitingApproval -> Dismissed: %v", err)
	}

	var kind *string
	if err := tx.QueryRow(ctx, `SELECT resolution_kind FROM incidents WHERE id = $1`, incidentID).Scan(&kind); err != nil {
		t.Fatalf("read resolution_kind: %v", err)
	}
	if kind != nil {
		t.Fatalf("resolution_kind = %q after Dismissed, want NULL", *kind)
	}
}
