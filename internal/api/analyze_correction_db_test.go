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

// openPRProposalWithNilParams is BUGS.md 109's exact live shape, built as a
// full llm.Investigation so it can be run through the same
// EnforceRoute -> correctBlockedPlanParams -> PersistAnalysis ->
// ApplyAnalysisResult sequence handleAnalyzeIncident itself runs.
func openPRProposalWithNilParams() llm.Investigation {
	confidence := 0.6
	return llm.Investigation{
		Model:      "test-model",
		Status:     "complete",
		RootCause:  &llm.RootCause{Statement: "BUGS.md 109 regression test: livenessProbe checks the wrong port (9999 instead of 80)"},
		Confidence: &confidence,
		ProposedPlan: &remediation.RemediationPlan{
			ActionType:      remediation.ActionOpenPR,
			TargetGVK:       "apps/v1/Deployment",
			TargetNamespace: "argus-r41-argo003",
			TargetName:      "argo003-selfheal",
			Reversible:      true,
			RiskLevel:       remediation.RiskLow,
			Params:          nil, // the model omitted params entirely — BUGS.md 109's own live repro
		},
	}
}

// TestHandleAnalyzeIncident_ParamsCorrection_SucceedsReachesAwaitingApproval
// is BUGS.md 109 / BACKLOG.md AG1's live-shape reproduction and proof of fix,
// run against a real Postgres. Before this fix, an OpenPR proposal with nil
// Params was Blocked by RemediationPlan.Validate() and orchestrator.Advance
// sent the incident straight to NeedsHumanInvestigation with the rejection
// reason discarded — this test drives the exact same sequence
// handleAnalyzeIncident itself runs (EnforceRoute, then the analyze-time
// correction attempt, then PersistAnalysis/ApplyAnalysisResult) and proves
// a successful correction reaches AwaitingApproval instead, with the
// corrected, now-valid plan actually persisted.
func TestHandleAnalyzeIncident_ParamsCorrection_SucceedsReachesAwaitingApproval(t *testing.T) {
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

	result := openPRProposalWithNilParams()
	routeDecision := orchestrator.RouteDecision{Route: resolution.RoutePullRequest, Reason: "test: GitOps-owned, PR-only route", Apply: true}
	result = orchestrator.EnforceRoute(result, routeDecision.Route)
	if result.ProposedPlan == nil {
		t.Fatal("EnforceRoute dropped the OpenPR proposal — test fixture invalid, OpenPR must be permitted on RoutePullRequest")
	}

	correct := func(_ context.Context, p remediation.RemediationPlan, rejection string) (remediation.ActionParams, error) {
		if p.ActionType != remediation.ActionOpenPR {
			t.Errorf("correct() called with ActionType %q, want OpenPR", p.ActionType)
		}
		return remediation.OpenPRParams{
			Files: []remediation.ProposedFile{{
				Path:    "envs/prod/checkout.yaml",
				Content: "spec:\n  template:\n    spec:\n      containers:\n        - livenessProbe:\n            httpGet:\n              port: 80\n",
			}},
		}, nil
	}
	correctedPlan, attempt := correctBlockedPlanParams(ctx, result.ProposedPlan, correct)
	result.ProposedPlan = correctedPlan
	if attempt == nil || !attempt.Succeeded {
		t.Fatalf("correctBlockedPlanParams: attempt = %#v, want a successful correction", attempt)
	}

	analysisID := domain.NewID(domain.PrefixAnalysis)
	if _, err := PersistAnalysis(ctx, tx, tenantID, analysisID, incidentID, clusterID, result, time.Now(), TriggeredByManual); err != nil {
		t.Fatalf("PersistAnalysis: %v", err)
	}
	adv, err := orchestrator.ApplyAnalysisResult(ctx, tx, tenantID, clusterID, incidentID, analysisID, result, routeDecision)
	if err != nil {
		t.Fatalf("ApplyAnalysisResult: %v", err)
	}
	if adv.NextState != orchestrator.StateAwaitingApproval {
		t.Fatalf("NextState = %v, want %v — a corrected, validly-parameterized plan must reach approval, not NeedsHumanInvestigation (BUGS.md 109's own gap)", adv.NextState, orchestrator.StateAwaitingApproval)
	}
	if adv.Plan == nil {
		t.Fatal("adv.Plan = nil, want the corrected plan to have been persisted")
	}
	if adv.PlanID == "" {
		t.Error("adv.PlanID is empty, want a real remediation_recommendations row id")
	}
	got, ok := adv.Plan.Params.(remediation.OpenPRParams)
	if !ok || len(got.Files) != 1 || got.Files[0].Path != "envs/prod/checkout.yaml" {
		t.Errorf("adv.Plan.Params = %#v, want the corrected OpenPRParams naming the one corrected file", adv.Plan.Params)
	}

	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit: %v", err)
	}

	if got := analyzeDetachTestIncidentState(t, pool, tenantID, clusterID, incidentID); got != orchestrator.StateAwaitingApproval {
		t.Fatalf("durable incident state = %v, want %v", got, orchestrator.StateAwaitingApproval)
	}
}

// TestHandleAnalyzeIncident_ParamsCorrection_StillFailsReachesNeedsHumanInvestigation
// is this fix's other required outcome: when the correction attempt itself
// cannot produce a valid plan (here, the model's replacement is STILL
// missing fieldPath/newValue), the incident falls through to today's
// unchanged Blocked -> NeedsHumanInvestigation behaviour — never a silent
// retry, never a fabricated plan.
func TestHandleAnalyzeIncident_ParamsCorrection_StillFailsReachesNeedsHumanInvestigation(t *testing.T) {
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

	result := openPRProposalWithNilParams()
	routeDecision := orchestrator.RouteDecision{Route: resolution.RoutePullRequest, Reason: "test: GitOps-owned, PR-only route", Apply: true}
	result = orchestrator.EnforceRoute(result, routeDecision.Route)

	var correctCalls int
	correct := func(_ context.Context, _ remediation.RemediationPlan, _ string) (remediation.ActionParams, error) {
		correctCalls++
		// Still invalid — the model tried, but its replacement is no better.
		return remediation.OpenPRParams{}, nil
	}
	correctedPlan, attempt := correctBlockedPlanParams(ctx, result.ProposedPlan, correct)
	result.ProposedPlan = correctedPlan
	if correctCalls != 1 {
		t.Fatalf("correct() called %d times, want exactly 1 — never retried a second time", correctCalls)
	}
	if attempt == nil || attempt.Succeeded {
		t.Fatalf("attempt = %#v, want a non-nil, unsuccessful record", attempt)
	}

	analysisID := domain.NewID(domain.PrefixAnalysis)
	if _, err := PersistAnalysis(ctx, tx, tenantID, analysisID, incidentID, clusterID, result, time.Now(), TriggeredByManual); err != nil {
		t.Fatalf("PersistAnalysis: %v", err)
	}
	adv, err := orchestrator.ApplyAnalysisResult(ctx, tx, tenantID, clusterID, incidentID, analysisID, result, routeDecision)
	if err != nil {
		t.Fatalf("ApplyAnalysisResult: %v", err)
	}
	if adv.NextState != orchestrator.StateNeedsHumanInvestigation {
		t.Fatalf("NextState = %v, want %v — an uncorrectable plan must fall through to today's unchanged behaviour", adv.NextState, orchestrator.StateNeedsHumanInvestigation)
	}
	if adv.Plan != nil {
		t.Errorf("adv.Plan = %#v, want nil — a still-invalid plan must never be persisted", adv.Plan)
	}
	if adv.Decision == nil || adv.Decision.Outcome != remediation.Blocked {
		t.Fatalf("adv.Decision = %+v, want Outcome Blocked", adv.Decision)
	}

	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit: %v", err)
	}

	if got := analyzeDetachTestIncidentState(t, pool, tenantID, clusterID, incidentID); got != orchestrator.StateNeedsHumanInvestigation {
		t.Fatalf("durable incident state = %v, want %v", got, orchestrator.StateNeedsHumanInvestigation)
	}
}
