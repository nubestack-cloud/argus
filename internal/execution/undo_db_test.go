package execution

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"argus/internal/data"
	"argus/internal/domain"
)

// rollbackFixture inserts one incident, one recommendation of actionType, and
// one succeeded execution against it, with rollbackActionType as the
// execution's own recorded compensating-action type (empty string means "no
// rollback recorded" — NULL in the column, the real shape for every
// irreversible action). Returns the execution id to load.
func rollbackFixture(t *testing.T, pool *pgxpool.Pool, actionType, rollbackActionType string) (tenantID, executionID string) {
	t.Helper()
	ctx := context.Background()

	clusterID := domain.NewID(domain.PrefixCluster)
	incidentID := domain.NewID(domain.PrefixIncident)
	analysisID := domain.NewID(domain.PrefixAnalysis)
	planID := domain.NewID(domain.PrefixPlan)
	executionID = domain.NewID(domain.PrefixExecution)

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
		t.Fatalf("scope: %v", err)
	}

	if _, err := tx.Exec(ctx,
		`INSERT INTO clusters (id, tenant_id, display_name, state, shard_id, cluster_fingerprint)
		 VALUES ($1, $2, $3, 'Active', 'shard-test', $4)`,
		clusterID, tenantID, "rollback-b143-test-"+clusterID, "fp-"+clusterID); err != nil {
		t.Fatalf("insert cluster: %v", err)
	}
	now := time.Now()
	if _, err := tx.Exec(ctx,
		`INSERT INTO incidents (id, tenant_id, cluster_id, fingerprint, severity, state, first_seen, last_seen, occurrence_count)
		 VALUES ($1, $2, $3, $4, 'high', 'Validating', $5, $5, 1)`,
		incidentID, tenantID, clusterID, "test-rollback-b143-"+incidentID, now); err != nil {
		t.Fatalf("insert incident: %v", err)
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO analyses (id, tenant_id, incident_id, cluster_id, prompt_version, model,
		    causal_chain, iterations, duration_ms, tokens_billed_in, tokens_cache_read, tokens_out, cost_usd)
		 VALUES ($1,$2,$3,$4,'test','test-model','[]'::jsonb,1,1,0,0,0,0)`,
		analysisID, tenantID, incidentID, clusterID); err != nil {
		t.Fatalf("insert analysis: %v", err)
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO remediation_recommendations (
		   id, incident_id, tenant_id, cluster_id, analysis_id, action_type,
		   target_gvk, target_namespace, target_name, params, reversible, risk_level,
		   gate_outcome, gate_reason
		 ) VALUES ($1,$2,$3,$4,$5,$6,'v1/PersistentVolumeClaim','ns','data-pvc','{}'::jsonb,false,'high','NeedsApproval','test')`,
		planID, incidentID, tenantID, clusterID, analysisID, actionType); err != nil {
		t.Fatalf("insert recommendation: %v", err)
	}

	// Mirrors recordExecutionOutcome's own insert (this package): all
	// three rollback_* columns NULL together for an action type with no
	// representable undo — migration 000050's CHECK enforces that pairing.
	var rollbackAT, rollbackParams, rollbackDesc any
	if rollbackActionType != "" {
		rollbackAT = rollbackActionType
		rollbackParams = []byte(`{}`)
		rollbackDesc = "test rollback"
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO remediation_executions (id, recommendation_id, incident_id, tenant_id, cluster_id, outcome,
		   rollback_action_type, rollback_params, rollback_description)
		 VALUES ($1,$2,$3,$4,$5,'succeeded',$6,$7,$8)`,
		executionID, planID, incidentID, tenantID, clusterID, rollbackAT, rollbackParams, rollbackDesc); err != nil {
		t.Fatalf("insert execution: %v", err)
	}

	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit setup: %v", err)
	}

	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Errorf("cleanup: begin: %v", err)
			return
		}
		defer tx.Rollback(ctx) //nolint:errcheck
		if err := data.SetRequestScope(ctx, tx, tenantID, []string{clusterID}); err != nil {
			t.Errorf("cleanup: scope: %v", err)
			return
		}
		for _, stmt := range []string{
			`DELETE FROM remediation_executions WHERE cluster_id = $1`,
			`DELETE FROM remediation_recommendations WHERE cluster_id = $1`,
			`DELETE FROM evidence WHERE analysis_id IN (SELECT id FROM analyses WHERE cluster_id = $1)`,
			`DELETE FROM analysis_embeddings WHERE analysis_id IN (SELECT id FROM analyses WHERE cluster_id = $1)`,
			`DELETE FROM analyses WHERE cluster_id = $1`,
			`DELETE FROM incidents WHERE cluster_id = $1`,
			`DELETE FROM clusters WHERE id = $1`,
		} {
			if _, err := tx.Exec(ctx, stmt, clusterID); err != nil {
				t.Errorf("cleanup %q: %v", stmt, err)
				return
			}
		}
		if err := tx.Commit(ctx); err != nil {
			t.Errorf("cleanup: commit: %v", err)
		}
	})

	return tenantID, executionID
}

// TestLoadUndoableExecutionDeleteResourceReachesRecommendationActionType is
// B143's regression test, run against a real database rather than only
// exercising interpretDeletionVerificationResult in isolation (which is
// exactly what let this ship broken: TestInterpretDeletionVerificationResult
// never touched LoadUndoableExecution's own query). A DeleteResource
// execution is unconditionally irreversible, so rollback_action_type is NULL
// and ActionType (sourced from that column) is empty — VerifyAppliedValue's
// DeleteResource branch must read RecommendationActionType (sourced from
// remediation_recommendations.action_type) instead, or it can never fire, as
// confirmed live 2026-09-06 (docs/VERIFICATION.md, b140verify fixture).
func TestLoadUndoableExecutionDeleteResourceReachesRecommendationActionType(t *testing.T) {
	pool := authTestPool(t)
	tenantID, executionID := rollbackFixture(t, pool, "DeleteResource", "")

	tx, err := pool.Begin(context.Background())
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer tx.Rollback(context.Background()) //nolint:errcheck
	if err := data.SetRequestScope(context.Background(), tx, tenantID, nil); err != nil {
		t.Fatalf("scope: %v", err)
	}

	exec, err := LoadUndoableExecution(context.Background(), tx, executionID)
	if err != nil {
		t.Fatalf("LoadUndoableExecution: %v", err)
	}

	if exec.ActionType != "" {
		t.Errorf("ActionType = %q, want empty — DeleteResource has no representable rollback, so rollback_action_type must be NULL", exec.ActionType)
	}
	if exec.RecommendationActionType != "DeleteResource" {
		t.Errorf("RecommendationActionType = %q, want %q — this is the field VerifyAppliedValue's DeleteResource branch must read; reading ActionType here reproduces B143 exactly", exec.RecommendationActionType, "DeleteResource")
	}
}

// TestLoadUndoableExecutionReversibleActionKeepsBothFieldsInSync is the
// complementary positive case: for a reversible action type, ActionType (the
// compensating action's own type) and RecommendationActionType (the forward
// action's type) coincide, which is exactly the property that let B143 go
// unnoticed until an irreversible action type was exercised live.
func TestLoadUndoableExecutionReversibleActionKeepsBothFieldsInSync(t *testing.T) {
	pool := authTestPool(t)
	tenantID, executionID := rollbackFixture(t, pool, "ScaleDeployment", "ScaleDeployment")

	tx, err := pool.Begin(context.Background())
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer tx.Rollback(context.Background()) //nolint:errcheck
	if err := data.SetRequestScope(context.Background(), tx, tenantID, nil); err != nil {
		t.Fatalf("scope: %v", err)
	}

	exec, err := LoadUndoableExecution(context.Background(), tx, executionID)
	if err != nil {
		t.Fatalf("LoadUndoableExecution: %v", err)
	}
	if exec.ActionType != "ScaleDeployment" || exec.RecommendationActionType != "ScaleDeployment" {
		t.Errorf("ActionType=%q RecommendationActionType=%q, want both %q", exec.ActionType, exec.RecommendationActionType, "ScaleDeployment")
	}
}
