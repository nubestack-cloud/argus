package api

import (
	"context"
	"testing"
	"time"

	"argus/internal/data"
	"argus/internal/domain"
	"argus/internal/llm"
	"argus/internal/orchestrator"
	"argus/internal/remediation"
	"argus/internal/resolution"
)

// pairedRouteInvestigationResult is a deterministic "complete, paired route"
// investigation result — the in-place half as the primary plan
// (ScaleDeployment, low risk, reversible, high confidence -> AutoApprove
// under DefaultAutonomyPolicy, matching orchestrator_test.go's own
// TestAdvance_PairedRoute fixture) and an OpenPR plan as its companion.
func pairedRouteInvestigationResult() llm.Investigation {
	confidence := 0.95
	return llm.Investigation{
		Model:      "test-model",
		Status:     "complete",
		RootCause:  &llm.RootCause{Statement: "BACKLOG D8 paired-route regression test root cause"},
		Confidence: &confidence,
		ProposedPlan: &remediation.RemediationPlan{
			ActionType:      remediation.ActionScaleDeployment,
			TargetGVK:       "apps/v1/Deployment",
			TargetNamespace: "payments",
			TargetName:      "checkout-worker",
			Params:          remediation.ScaleDeploymentParams{Replicas: 4},
			Reversible:      true,
			RiskLevel:       remediation.RiskLow,
		},
		ProposedPairedPlan: &remediation.RemediationPlan{
			ActionType:      remediation.ActionOpenPR,
			TargetGVK:       "apps/v1/Deployment",
			TargetNamespace: "payments",
			TargetName:      "checkout-worker",
			Params:          remediation.OpenPRParams{Repository: "org/repo", Files: []remediation.ProposedFile{{Path: "envs/prod/checkout-worker.yaml", Content: "spec:\n  replicas: 4\n"}}},
			Reversible:      true,
			RiskLevel:       remediation.RiskLow,
		},
	}
}

// TestLatestPlanViewForAnalysis_PairedRoute_ReturnsBothDeterministically is
// BACKLOG D8's paired-route-panel finding, proved against a real Postgres:
// before this task, nothing between orchestrator.ApplyAnalysisResult
// (which already computes and persists BOTH halves of a paired route,
// linked via sibling_of_recommendation_id) and the wire ever surfaced the
// second one — GET /incidents/{id}'s embedded analysis.plan came from
// latestPlanViewForAnalysis's `ORDER BY created_at DESC LIMIT 1`, and both
// of a pair's rows share an IDENTICAL created_at (DEFAULT now(), same
// transaction), so which one won was not even guaranteed to be the same
// plan on every read. This proves both the presence of PairedPlan on the
// read path AND that Plan always resolves to the primary (in-place) half.
func TestLatestPlanViewForAnalysis_PairedRoute_ReturnsBothDeterministically(t *testing.T) {
	pool := analyzeDetachTestPool(t)
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
	if err := orchestrator.MarkInvestigating(ctx, tx, tenantID, clusterID, incidentID); err != nil {
		t.Fatalf("MarkInvestigating: %v", err)
	}

	result := pairedRouteInvestigationResult()
	analysisID := domain.NewID(domain.PrefixAnalysis)
	if _, err := PersistAnalysis(ctx, tx, tenantID, analysisID, incidentID, clusterID, result, time.Now(), TriggeredByManual); err != nil {
		t.Fatalf("PersistAnalysis: %v", err)
	}
	routeDecision := orchestrator.RouteDecision{Route: resolution.RoutePaired, Reason: "test", Apply: true}
	adv, err := orchestrator.ApplyAnalysisResult(ctx, tx, tenantID, clusterID, incidentID, analysisID, result, routeDecision)
	if err != nil {
		t.Fatalf("ApplyAnalysisResult: %v", err)
	}
	if adv.PlanID == "" || adv.PairedPlanID == "" {
		t.Fatalf("expected both PlanID and PairedPlanID to be set, got Plan=%q Paired=%q", adv.PlanID, adv.PairedPlanID)
	}
	if adv.PlanID == adv.PairedPlanID {
		t.Fatalf("PlanID and PairedPlanID must be different rows, both were %q", adv.PlanID)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit: %v", err)
	}

	// A fresh, independent transaction — the same shape GET /incidents/{id}
	// reads through — proves this is durable, not an artifact of reading
	// back inside the same transaction that wrote it.
	readTx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin read tx: %v", err)
	}
	defer func() { _ = readTx.Rollback(context.Background()) }()
	if err := data.SetRequestScope(ctx, readTx, tenantID, []string{clusterID}); err != nil {
		t.Fatalf("set request scope: %v", err)
	}

	plan, pairedPlan, err := latestPlanViewForAnalysis(ctx, readTx, analysisID)
	if err != nil {
		t.Fatalf("latestPlanViewForAnalysis: %v", err)
	}
	if plan == nil {
		t.Fatal("plan = nil, want the primary (in-place) plan")
	}
	if plan.ID != adv.PlanID {
		t.Errorf("plan.ID = %q, want the primary plan's id %q — a paired route's plan must always resolve to its PRIMARY half, never its companion", plan.ID, adv.PlanID)
	}
	if plan.ActionType != string(remediation.ActionScaleDeployment) {
		t.Errorf("plan.ActionType = %q, want %q", plan.ActionType, remediation.ActionScaleDeployment)
	}
	if pairedPlan == nil {
		t.Fatal("pairedPlan = nil, want the OpenPR companion — this is the exact gap BACKLOG D8's paired-route panel needs closed")
	}
	if pairedPlan.ID != adv.PairedPlanID {
		t.Errorf("pairedPlan.ID = %q, want %q", pairedPlan.ID, adv.PairedPlanID)
	}
	if pairedPlan.ActionType != string(remediation.ActionOpenPR) {
		t.Errorf("pairedPlan.ActionType = %q, want %q", pairedPlan.ActionType, remediation.ActionOpenPR)
	}

	// The same determinism must hold for the single-decision path
	// (handleApproveIncident/handleRejectIncident's latestRecommendationForIncident)
	// and the approvals queue's LATERAL join — both resolved by the identical
	// tiebreak, both must land on the PRIMARY row, never the companion.
	planID, gotClusterID, err := latestRecommendationForIncident(ctx, readTx, incidentID)
	if err != nil {
		t.Fatalf("latestRecommendationForIncident: %v", err)
	}
	if planID != adv.PlanID {
		t.Errorf("latestRecommendationForIncident planID = %q, want the primary plan %q (a paired route must resolve today's single decision to its in-place half, deterministically)", planID, adv.PlanID)
	}
	if gotClusterID != clusterID {
		t.Errorf("latestRecommendationForIncident clusterID = %q, want %q", gotClusterID, clusterID)
	}
}
