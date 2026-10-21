package orchestrator

import (
	"context"
	"strings"
	"testing"

	"argus/internal/data"
	"argus/internal/llm"
	"argus/internal/remediation"
	"argus/internal/resolution"
)

// This file is BACKLOG.md F11's offline-testable safety-machinery slice,
// proven against a real Postgres the same way blocked_invalid_plan_db_test.go
// (BUGS.md 86) proves the adjacent case: a plan that fails
// RemediationPlan.Validate() must produce a clean Blocked/InvalidPlan outcome
// and must never reach persistRecommendation, let alone the CHECK constraint
// migration 000072 widened.
//
// All three tests below use a CONSTRUCTED remediation.RemediationPlan, never
// a live model call — exactly the offline-testable half of F11 this task is
// scoped to. Nothing here makes ActionStructuredPatch reachable by a model;
// see that constant's own doc comment (internal/remediation/plan.go) for the
// three independent reasons it still is not.

// TestApplyAnalysisResult_StructuredPatch_RejectsInFullOnOneInvalidPath is
// this task's central requirement: a multi-op plan where ONE path fails
// PatchFieldPermitted is invalid IN FULL — not "5 of 6 operations applied" —
// and, per BUGS.md 86's own lesson, never reaches persistRecommendation with
// a raw value the CHECK constraint would have to catch instead.
func TestApplyAnalysisResult_StructuredPatch_RejectsInFullOnOneInvalidPath(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()

	fixture, tenantID, clusterID, incidentID, analysisID := blockedInvalidPlanFixture(t, pool)

	plan := remediation.RemediationPlan{
		ActionType:      remediation.ActionStructuredPatch,
		TargetGVK:       "apps/v1/Deployment",
		TargetNamespace: "argus-test",
		TargetName:      "web",
		Reversible:      true,
		RiskLevel:       remediation.RiskMedium,
		Params: remediation.StructuredPatchParams{Ops: []remediation.StructuredPatchOp{
			// Operation 1: on the reviewed allowlist.
			{FieldPath: "spec.progressDeadlineSeconds", NewValue: "900"},
			// Operation 2: NOT on the allowlist at all — a plan-authoring bug,
			// not a permission this cluster merely lacks yet (NeedsGrant).
			{FieldPath: "spec.thisFieldIsNotAllowlisted", NewValue: "x"},
		}},
	}
	confidence := 0.9
	result := llm.Investigation{
		Status:       "complete",
		RootCause:    &llm.RootCause{Statement: "test root cause for F11's reject-in-full requirement"},
		Confidence:   &confidence,
		ProposedPlan: &plan,
	}
	routeDecision := RouteDecision{Route: resolution.RouteInPlace, Apply: true}

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if err := data.SetRequestScope(ctx, tx, tenantID, []string{clusterID}); err != nil {
		t.Fatalf("scope: %v", err)
	}

	adv, err := ApplyAnalysisResult(ctx, tx, tenantID, clusterID, incidentID, analysisID, result, routeDecision)
	if err != nil {
		t.Fatalf("ApplyAnalysisResult returned an error instead of a clean Blocked outcome "+
			"(this is BUGS.md 86's failure mode, reproduced for a multi-op plan): %v", err)
	}

	if adv.NextState != StateNeedsHumanInvestigation {
		t.Fatalf("NextState = %v, want %v", adv.NextState, StateNeedsHumanInvestigation)
	}
	if adv.Decision == nil || adv.Decision.Outcome != remediation.Blocked {
		t.Fatalf("Decision = %+v, want Outcome Blocked", adv.Decision)
	}
	if !adv.Decision.InvalidPlan {
		t.Fatalf("Decision.InvalidPlan = false, want true — this plan failed Validate() (an allowlist refusal), which is exactly the condition InvalidPlan exists to flag before persistence is ever attempted")
	}
	if !strings.Contains(adv.Reason, "operation 2 of 2") {
		t.Errorf("Reason = %q, want it to name WHICH operation was refused", adv.Reason)
	}
	if !strings.Contains(adv.Reason, "spec.thisFieldIsNotAllowlisted") {
		t.Errorf("Reason = %q, want it to name the refused field path", adv.Reason)
	}
	if adv.Plan != nil {
		t.Fatalf("Plan = %+v, want nil — a plan with one invalid operation must never be handed to persistRecommendation, "+
			"not even the valid operation alongside it: this is an all-or-nothing plan, not a set of independent ones", adv.Plan)
	}

	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit: %v", err)
	}

	// A clean Blocked/InvalidPlan outcome, same shape as
	// blocked_invalid_plan_db_test.go's own test: 0 remediation_recommendations,
	// 1 timeline_events (AnalysisCompleted), 0 incident_notifications.
	fixture.Created("remediation_recommendations", 0)
	fixture.Created("timeline_events", 1)
	fixture.Created("incident_notifications", 0)
	fixture.Created("evidence", 0)
	fixture.Created("analysis_embeddings", 0)
	cleanupBlockedInvalidPlanFixture(fixture, pool, tenantID, clusterID)
}

// TestApplyAnalysisResult_StructuredPatch_RejectsPathOwnedByAnotherActionType
// proves the three exclusions patchfield.go's header comment documents as
// load-bearing (spec.replicas, containers[*].image,
// containers[*].resources.limits.*) are refused for StructuredPatch for the
// SAME reason they are refused for PatchField — inherited automatically by
// reusing PatchFieldPermitted, not by a second check this file would have to
// keep in sync.
func TestApplyAnalysisResult_StructuredPatch_RejectsPathOwnedByAnotherActionType(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()

	cases := []struct {
		name string
		path string
	}{
		{"replicas (ScaleDeployment's field)", "spec.replicas"},
		{"container image (RevertContainerImage's field)", "spec.template.spec.containers[web].image"},
		{"resource limits (PatchResourceLimits' field)", "spec.template.spec.containers[web].resources.limits.memory"},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			fixture, tenantID, clusterID, incidentID, analysisID := blockedInvalidPlanFixture(t, pool)

			plan := remediation.RemediationPlan{
				ActionType:      remediation.ActionStructuredPatch,
				TargetGVK:       "apps/v1/Deployment",
				TargetNamespace: "argus-test",
				TargetName:      "web",
				Reversible:      true,
				RiskLevel:       remediation.RiskMedium,
				Params:          remediation.StructuredPatchParams{Ops: []remediation.StructuredPatchOp{{FieldPath: c.path, NewValue: "5"}}},
			}
			confidence := 0.9
			result := llm.Investigation{
				Status:       "complete",
				RootCause:    &llm.RootCause{Statement: "test root cause for F11's inherited-exclusion requirement"},
				Confidence:   &confidence,
				ProposedPlan: &plan,
			}
			routeDecision := RouteDecision{Route: resolution.RouteInPlace, Apply: true}

			tx, err := pool.Begin(ctx)
			if err != nil {
				t.Fatalf("begin: %v", err)
			}
			defer tx.Rollback(ctx) //nolint:errcheck
			if err := data.SetRequestScope(ctx, tx, tenantID, []string{clusterID}); err != nil {
				t.Fatalf("scope: %v", err)
			}

			adv, err := ApplyAnalysisResult(ctx, tx, tenantID, clusterID, incidentID, analysisID, result, routeDecision)
			if err != nil {
				t.Fatalf("ApplyAnalysisResult returned an error instead of a clean Blocked outcome: %v", err)
			}
			if adv.Decision == nil || adv.Decision.Outcome != remediation.Blocked || !adv.Decision.InvalidPlan {
				t.Fatalf("Decision = %+v, want Blocked/InvalidPlan — %s must be refused as not on the reviewed allowlist, exactly like a PatchField plan naming the same path", adv.Decision, c.path)
			}
			if adv.Plan != nil {
				t.Fatalf("Plan = %+v, want nil", adv.Plan)
			}

			// The SAME refusal a PatchField plan would get for the identical
			// (kind, path) pair — proving this is inherited from
			// PatchFieldPermitted, not a second, StructuredPatch-only opinion
			// about which paths those three action types own.
			_, wantErr := remediation.PatchFieldPermitted(plan.TargetGVK, c.path)
			if wantErr == nil {
				t.Fatalf("test setup bug: %s is unexpectedly on the allowlist", c.path)
			}
			if !strings.Contains(adv.Reason, wantErr.Error()) {
				t.Errorf("Reason = %q, want it to contain PatchFieldPermitted's own refusal (%q) verbatim — the same check, not a parallel one", adv.Reason, wantErr.Error())
			}

			if err := tx.Commit(ctx); err != nil {
				t.Fatalf("commit: %v", err)
			}

			// A clean Blocked/InvalidPlan outcome, same shape as the test above.
			fixture.Created("remediation_recommendations", 0)
			fixture.Created("timeline_events", 1)
			fixture.Created("incident_notifications", 0)
			fixture.Created("evidence", 0)
			fixture.Created("analysis_embeddings", 0)
			cleanupBlockedInvalidPlanFixture(fixture, pool, tenantID, clusterID)
		})
	}
}

// TestApplyAnalysisResult_StructuredPatch_ValidPlanPersistsAndRoundTrips is
// the positive case alongside the two refusal tests above: a plan naming
// several genuinely allowlisted paths clears Validate(), is classified
// NeedsApproval (ActionStructuredPatch is approval-only by construction —
// risk.go's neverAutoApprove), is persisted by persistRecommendation without
// tripping the CHECK constraint migration 000072 widened, and reads back
// through orchestrator.ReconstructPlan with every operation intact.
func TestApplyAnalysisResult_StructuredPatch_ValidPlanPersistsAndRoundTrips(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()

	fixture, tenantID, clusterID, incidentID, analysisID := blockedInvalidPlanFixture(t, pool)

	ops := []remediation.StructuredPatchOp{
		{FieldPath: "spec.progressDeadlineSeconds", NewValue: "900"},
		{FieldPath: "spec.template.spec.containers[api].resources.requests.cpu", NewValue: "250m"},
	}
	plan := remediation.RemediationPlan{
		ActionType:      remediation.ActionStructuredPatch,
		TargetGVK:       "apps/v1/Deployment",
		TargetNamespace: "argus-test",
		TargetName:      "web",
		Reversible:      true,
		RiskLevel:       remediation.RiskLow,
		Params:          remediation.StructuredPatchParams{Ops: ops},
	}
	confidence := 0.9
	result := llm.Investigation{
		Status:       "complete",
		RootCause:    &llm.RootCause{Statement: "test root cause for F11's valid multi-op persistence"},
		Confidence:   &confidence,
		ProposedPlan: &plan,
	}
	routeDecision := RouteDecision{Route: resolution.RouteInPlace, Apply: true}

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	if err := data.SetRequestScope(ctx, tx, tenantID, []string{clusterID}); err != nil {
		t.Fatalf("scope: %v", err)
	}

	adv, err := ApplyAnalysisResult(ctx, tx, tenantID, clusterID, incidentID, analysisID, result, routeDecision)
	if err != nil {
		t.Fatalf("ApplyAnalysisResult: %v (a valid multi-op plan must persist cleanly against the widened CHECK constraint)", err)
	}
	if adv.NextState != StateAwaitingApproval {
		t.Fatalf("NextState = %v, want %v", adv.NextState, StateAwaitingApproval)
	}
	if adv.Decision == nil || adv.Decision.Outcome != remediation.NeedsApproval {
		t.Fatalf("Decision = %+v, want Outcome NeedsApproval (StructuredPatch is approval-only by construction)", adv.Decision)
	}
	if adv.Plan == nil {
		t.Fatal("Plan = nil, want the valid plan attached for persistence")
	}
	if adv.PlanID == "" {
		t.Fatal("PlanID is empty, want the persisted recommendation's id")
	}

	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit: %v", err)
	}

	// Read the row back in a FRESH transaction, the way approvals.go's
	// loadRecommendationPlan does, and reconstruct the typed plan.
	tx2, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin readback: %v", err)
	}
	defer tx2.Rollback(ctx) //nolint:errcheck
	if err := data.SetRequestScope(ctx, tx2, tenantID, []string{clusterID}); err != nil {
		t.Fatalf("scope readback: %v", err)
	}
	var actionType, targetGVK, targetName, riskLevel string
	var targetNamespace *string
	var paramsJSON []byte
	var reversible bool
	if err := tx2.QueryRow(ctx,
		`SELECT action_type, target_gvk, target_namespace, target_name, params, reversible, risk_level
		   FROM remediation_recommendations WHERE id = $1`, adv.PlanID).
		Scan(&actionType, &targetGVK, &targetNamespace, &targetName, &paramsJSON, &reversible, &riskLevel); err != nil {
		t.Fatalf("read back persisted recommendation: %v", err)
	}

	ns := ""
	if targetNamespace != nil {
		ns = *targetNamespace
	}
	reconstructed, err := ReconstructPlan(incidentID, analysisID, actionType, targetGVK, ns, targetName, paramsJSON, reversible, riskLevel)
	if err != nil {
		t.Fatalf("ReconstructPlan: %v", err)
	}
	gotParams, ok := reconstructed.Params.(remediation.StructuredPatchParams)
	if !ok {
		t.Fatalf("reconstructed params are %T, not StructuredPatchParams", reconstructed.Params)
	}
	if len(gotParams.Ops) != len(ops) {
		t.Fatalf("round-tripped %d operations, want %d", len(gotParams.Ops), len(ops))
	}
	for i, op := range ops {
		if gotParams.Ops[i] != op {
			t.Errorf("operation %d round-tripped as %+v, want %+v", i, gotParams.Ops[i], op)
		}
	}

	// The reconstructed plan must still validate cleanly (it went through the
	// exact same allowlist on the way in) — a sanity check that the persisted
	// row is not just bytes-equal but a genuinely re-usable plan.
	if err := reconstructed.Validate(); err != nil {
		t.Errorf("reconstructed plan does not validate: %v", err)
	}

	// A persisted NeedsApproval plan: 1 remediation_recommendations row, 2
	// timeline_events rows (AnalysisCompleted + RecommendationReady), and 1
	// incident_notifications row — NextState was asserted above as
	// StateAwaitingApproval, one of BACKLOG.md N1's notified transitions.
	fixture.Created("remediation_recommendations", 1)
	fixture.Created("timeline_events", 2)
	fixture.Created("incident_notifications", 1)
	fixture.Created("evidence", 0)
	fixture.Created("analysis_embeddings", 0)
	cleanupBlockedInvalidPlanFixture(fixture, pool, tenantID, clusterID)
}
