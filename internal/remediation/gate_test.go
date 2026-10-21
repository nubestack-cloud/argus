package remediation

import (
	"strings"
	"testing"
)

func floatPtr(f float64) *float64 { return &f }

// --- Realistic example plans, one per ActionType --------------------------

// scaleUpPlan mirrors DESIGN.md §9.3's own low-risk example:
// "scale up within quota."
func scaleUpPlan() RemediationPlan {
	return RemediationPlan{
		IncidentID:      "inc_01example",
		AnalysisID:      "an_01example",
		ActionType:      ActionScaleDeployment,
		TargetGVK:       "apps/v1/Deployment",
		TargetNamespace: "payments",
		TargetName:      "checkout-api",
		Params:          ScaleDeploymentParams{Replicas: 4},
		Reversible:      true,
		RiskLevel:       RiskLow,
	}
}

// restartPodPlan mirrors §9.3's medium-risk example: "restart a pod."
func restartPodPlan() RemediationPlan {
	return RemediationPlan{
		IncidentID:      "inc_02example",
		AnalysisID:      "an_02example",
		ActionType:      ActionRestartPod,
		TargetGVK:       "v1/Pod",
		TargetNamespace: "payments",
		TargetName:      "checkout-api-7f8d9c-abcde",
		Params:          RestartPodParams{},
		Reversible:      true,
		RiskLevel:       RiskMedium,
	}
}

// deleteResourcePlan mirrors §9.3's high-risk example, "delete anything" —
// an honest one, with Reversible correctly false per DESIGN.md §10.5.
func deleteResourcePlan() RemediationPlan {
	return RemediationPlan{
		IncidentID:      "inc_09example",
		AnalysisID:      "an_09example",
		ActionType:      ActionDeleteResource,
		TargetGVK:       "v1/Pod",
		TargetNamespace: "payments",
		TargetName:      "checkout-api-stuck-terminating",
		Params:          DeleteResourceParams{},
		Reversible:      false,
		RiskLevel:       RiskHigh,
	}
}

// createResourcePlan is BACKLOG.md F9's last genuinely-buildable verb: an
// honest one (Reversible correctly false — see plan.go's ActionCreateResource
// comment for why there is no representable rollback).
func createResourcePlanForGateTest() RemediationPlan {
	return RemediationPlan{
		IncidentID:      "inc_10example",
		AnalysisID:      "an_10example",
		ActionType:      ActionCreateResource,
		TargetGVK:       "v1/ConfigMap",
		TargetNamespace: "payments",
		TargetName:      "checkout-api-config",
		Params:          CreateResourceParams{Data: map[string]string{"RETRY_LIMIT": "3"}},
		Reversible:      false,
		RiskLevel:       RiskMedium,
	}
}

// patchResourceLimitsPlan mirrors §9.3's medium-risk example, "change
// resource limits": the reproduced fault this action type exists for, a
// container OOMKilled against a 32Mi ceiling, raised to 256Mi.
func patchResourceLimitsPlan() RemediationPlan {
	return RemediationPlan{
		IncidentID:      "inc_04example",
		AnalysisID:      "an_04example",
		ActionType:      ActionPatchResourceLimits,
		TargetGVK:       "apps/v1/Deployment",
		TargetNamespace: "payments",
		TargetName:      "checkout-api",
		Params:          PatchResourceLimitsParams{Container: "api", MemoryLimit: "256Mi"},
		Reversible:      true,
		RiskLevel:       RiskMedium,
	}
}

// revertContainerImagePlan mirrors §9.3's other medium-risk example, "update
// an image tag": the fault this action type exists for, a container that
// started crash-looping when its Deployment was rolled to a new image. Note
// what the params do NOT contain — an image. That is the action's central
// property, not an omission in the fixture (see
// RevertContainerImageParams' doc comment).
func revertContainerImagePlan() RemediationPlan {
	return RemediationPlan{
		IncidentID:      "inc_05example",
		AnalysisID:      "an_05example",
		ActionType:      ActionRevertContainerImage,
		TargetGVK:       "apps/v1/Deployment",
		TargetNamespace: "payments",
		TargetName:      "checkout-api",
		Params:          RevertContainerImageParams{Container: "api"},
		Reversible:      true,
		RiskLevel:       RiskMedium,
	}
}

// openPRPlan mirrors the GitOps channel (§10.1-10.2): a proposed image-tag
// fix routed through a PR rather than a live patch.
func openPRPlan() RemediationPlan {
	return RemediationPlan{
		IncidentID:      "inc_03example",
		AnalysisID:      "an_03example",
		ActionType:      ActionOpenPR,
		TargetGVK:       "apps/v1/Deployment",
		TargetNamespace: "payments",
		TargetName:      "checkout-api",
		Params: OpenPRParams{
			Repository: "example-org/checkout-manifests",
			Files: []ProposedFile{{
				Path:    "envs/prod/checkout-api.yaml",
				Content: "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: checkout-api\n",
			}},
		},
		Reversible: true,
		RiskLevel:  RiskMedium,
	}
}

func permissivePolicy() AutonomyPolicy {
	return AutonomyPolicy{
		AutoApproveMaxRisk:              RiskMedium,
		MinConfidenceForAutoApprove:     0.7,
		RequireReversibleForAutoApprove: true,
	}
}

// --- AutoApprove ------------------------------------------------------------

func TestEvaluate_AutoApprove_ScaleDeployment_LowRiskHighConfidence(t *testing.T) {
	d := Evaluate(scaleUpPlan(), floatPtr(0.95), permissivePolicy())
	if d.Outcome != AutoApprove {
		t.Fatalf("Outcome = %v, reason = %q; want AutoApprove", d.Outcome, d.Reason)
	}
	if d.Reason == "" {
		t.Fatal("AutoApprove decision has no human-readable Reason")
	}
}

func TestEvaluate_AutoApprove_RestartPod_MediumRiskAtCeiling(t *testing.T) {
	d := Evaluate(restartPodPlan(), floatPtr(0.85), permissivePolicy())
	if d.Outcome != AutoApprove {
		t.Fatalf("Outcome = %v, reason = %q; want AutoApprove", d.Outcome, d.Reason)
	}
}

func TestEvaluate_AutoApprove_ConfidenceExactlyAtThreshold(t *testing.T) {
	policy := permissivePolicy()
	d := Evaluate(scaleUpPlan(), floatPtr(policy.MinConfidenceForAutoApprove), policy)
	if d.Outcome != AutoApprove {
		t.Fatalf("Outcome = %v, reason = %q; want AutoApprove (threshold is inclusive)", d.Outcome, d.Reason)
	}
}

// --- NeedsApproval -----------------------------------------------------------

func TestEvaluate_NeedsApproval_NilConfidence(t *testing.T) {
	// §26's PartialAnalysis models an incomplete investigation's confidence
	// as null. A nil confidence must never be treated as high confidence or
	// silently coerced to a number (e.g. 0.0, which would itself read as a
	// confident "very low" claim the model never made).
	d := Evaluate(scaleUpPlan(), nil, permissivePolicy())
	if d.Outcome != NeedsApproval {
		t.Fatalf("Outcome = %v, reason = %q; want NeedsApproval for nil confidence", d.Outcome, d.Reason)
	}
	if !strings.Contains(strings.ToLower(d.Reason), "null") && !strings.Contains(strings.ToLower(d.Reason), "unknown") {
		t.Fatalf("Reason %q does not explain that confidence is unknown/null", d.Reason)
	}
}

func TestEvaluate_NeedsApproval_OpenPR_ConfidenceBelowThreshold(t *testing.T) {
	// Realistic OpenPR example landing in NeedsApproval: a plausible but not
	// confident-enough fix.
	d := Evaluate(openPRPlan(), floatPtr(0.5), permissivePolicy())
	if d.Outcome != NeedsApproval {
		t.Fatalf("Outcome = %v, reason = %q; want NeedsApproval", d.Outcome, d.Reason)
	}
}

func TestEvaluate_NeedsApproval_RiskAboveCeiling(t *testing.T) {
	plan := restartPodPlan() // RiskMedium
	policy := AutonomyPolicy{
		AutoApproveMaxRisk:              RiskLow,
		MinConfidenceForAutoApprove:     0.5,
		RequireReversibleForAutoApprove: true,
	}
	d := Evaluate(plan, floatPtr(0.99), policy)
	if d.Outcome != NeedsApproval {
		t.Fatalf("Outcome = %v, reason = %q; want NeedsApproval (risk exceeds ceiling)", d.Outcome, d.Reason)
	}
}

func TestEvaluate_NeedsApproval_PolicyRequiresReversibleButPlanIsNot(t *testing.T) {
	plan := scaleUpPlan()
	plan.Reversible = false // RiskLow, so the hard high-risk floor doesn't apply here
	policy := permissivePolicy()
	d := Evaluate(plan, floatPtr(0.99), policy)
	if d.Outcome != NeedsApproval {
		t.Fatalf("Outcome = %v, reason = %q; want NeedsApproval (policy requires reversibility)", d.Outcome, d.Reason)
	}
}

func TestEvaluate_NeedsApproval_HighRiskIrreversibleNeverAutoApproves(t *testing.T) {
	// The hard, non-configurable safety floor: even a maximally permissive
	// policy and near-certain confidence must not auto-approve a high-risk,
	// irreversible action.
	plan := restartPodPlan()
	plan.RiskLevel = RiskHigh
	plan.Reversible = false

	maximallyPermissive := AutonomyPolicy{
		AutoApproveMaxRisk:              RiskHigh,
		MinConfidenceForAutoApprove:     0.0,
		RequireReversibleForAutoApprove: false,
	}

	d := Evaluate(plan, floatPtr(0.999), maximallyPermissive)
	if d.Outcome != NeedsApproval {
		t.Fatalf("Outcome = %v, reason = %q; want NeedsApproval regardless of confidence/policy", d.Outcome, d.Reason)
	}
}

func TestEvaluate_NeedsApproval_HighRiskIrreversible_EvenAtConfidence1(t *testing.T) {
	plan := scaleUpPlan()
	plan.RiskLevel = RiskHigh
	plan.Reversible = false

	d := Evaluate(plan, floatPtr(1.0), AutonomyPolicy{
		AutoApproveMaxRisk:          RiskHigh,
		MinConfidenceForAutoApprove: 0,
	})
	if d.Outcome != NeedsApproval {
		t.Fatalf("Outcome = %v; want NeedsApproval even at confidence 1.0", d.Outcome)
	}
}

// TestDeleteResourceNeverAutoApproves is this task's own named requirement:
// verify — do not assume — that DeleteResource can never reach AutoApprove,
// at any confidence, under any policy, matching
// TestEvaluate_NeedsApproval_HighRiskIrreversibleNeverAutoApproves's exact
// "maximally permissive policy" shape above. An honest DeleteResource plan
// (Reversible=false, per DESIGN.md §10.5) already trips the hard
// high-risk+irreversible floor gate.go enforces unconditionally — this test
// exists to confirm that specifically for DeleteResource, and to keep
// confirming it if risk.go's separate, explicit neverAutoApprove entry for
// DeleteResource were ever removed (the hard floor alone must still catch
// it, since Validate refuses a plan that lies about Reversible).
func TestDeleteResourceNeverAutoApproves(t *testing.T) {
	plan := deleteResourcePlan()

	maximallyPermissive := AutonomyPolicy{
		AutoApproveMaxRisk:              RiskHigh,
		MinConfidenceForAutoApprove:     0.0,
		RequireReversibleForAutoApprove: false,
	}

	d := Evaluate(plan, floatPtr(1.0), maximallyPermissive)
	if d.Outcome == AutoApprove {
		t.Fatalf("DeleteResource auto-approved (reason=%q) — DESIGN.md §10.5 requires this to never be automatic, at any confidence, under any policy", d.Reason)
	}
	if d.Outcome != NeedsApproval {
		t.Fatalf("Outcome = %v, reason = %q; want NeedsApproval", d.Outcome, d.Reason)
	}
}

// TestCreateResourceNeverAutoApproves is this task's own named requirement,
// mirroring TestDeleteResourceNeverAutoApproves exactly: verify — do not
// assume — that CreateResource can never reach AutoApprove, at any
// confidence, under a maximally permissive policy (AutoApproveMaxRisk high,
// zero minimum confidence, no reversibility requirement). Unlike
// DeleteResource, CreateResource's floor (medium) does not by itself trip
// gate.go's hard high-risk+irreversible floor — this test is what actually
// exercises risk.go's explicit neverAutoApprove entry for it, not a
// coincidental side effect of a different, higher floor.
func TestCreateResourceNeverAutoApproves(t *testing.T) {
	plan := createResourcePlanForGateTest()

	maximallyPermissive := AutonomyPolicy{
		AutoApproveMaxRisk:              RiskHigh,
		MinConfidenceForAutoApprove:     0.0,
		RequireReversibleForAutoApprove: false,
	}

	d := Evaluate(plan, floatPtr(1.0), maximallyPermissive)
	if d.Outcome == AutoApprove {
		t.Fatalf("CreateResource auto-approved (reason=%q) — creating cluster state must never be automatic, at any confidence, under any policy", d.Reason)
	}
	if d.Outcome != NeedsApproval {
		t.Fatalf("Outcome = %v, reason = %q; want NeedsApproval", d.Outcome, d.Reason)
	}
}

// --- Blocked -----------------------------------------------------------------

func TestEvaluate_Blocked_UnknownActionType(t *testing.T) {
	plan := RemediationPlan{
		IncidentID:      "inc_04example",
		ActionType:      ActionType("DeleteNamespace"), // not in the closed set
		TargetGVK:       "v1/Namespace",
		TargetNamespace: "",
		TargetName:      "payments",
		Reversible:      false,
		RiskLevel:       RiskHigh,
	}
	d := Evaluate(plan, floatPtr(0.99), permissivePolicy())
	if d.Outcome != Blocked {
		t.Fatalf("Outcome = %v, reason = %q; want Blocked for unrecognized ActionType", d.Outcome, d.Reason)
	}
	if !strings.Contains(d.Reason, "unrecognized action type") {
		t.Fatalf("Reason %q does not explain the unrecognized action type", d.Reason)
	}
}

func TestEvaluate_Blocked_ParamsDoNotMatchActionType(t *testing.T) {
	plan := scaleUpPlan()
	plan.Params = RestartPodParams{} // wrong params type for ActionScaleDeployment
	d := Evaluate(plan, floatPtr(0.99), permissivePolicy())
	if d.Outcome != Blocked {
		t.Fatalf("Outcome = %v, reason = %q; want Blocked for mismatched Params", d.Outcome, d.Reason)
	}
}

func TestEvaluate_Blocked_NilParams(t *testing.T) {
	plan := scaleUpPlan()
	plan.Params = nil
	d := Evaluate(plan, floatPtr(0.99), permissivePolicy())
	if d.Outcome != Blocked {
		t.Fatalf("Outcome = %v, reason = %q; want Blocked for nil Params", d.Outcome, d.Reason)
	}
}

func TestEvaluate_Blocked_InvalidRiskLevel(t *testing.T) {
	plan := scaleUpPlan()
	plan.RiskLevel = RiskLevel("critical") // not in the closed low/medium/high set
	d := Evaluate(plan, floatPtr(0.99), permissivePolicy())
	if d.Outcome != Blocked {
		t.Fatalf("Outcome = %v, reason = %q; want Blocked for invalid RiskLevel", d.Outcome, d.Reason)
	}
}

// TestEvaluate_Blocked_ForbiddenRiskNeverReachesApproval is BACKLOG.md R4's
// gate-level defense-in-depth: §9.3's "never, at any confidence" tier must
// land on Blocked, not NeedsApproval, even under the most permissive policy
// there is — a human being asked to approve it is exactly what "forbidden"
// rules out.
func TestEvaluate_Blocked_ForbiddenRiskNeverReachesApproval(t *testing.T) {
	plan := scaleUpPlan()
	plan.RiskLevel = RiskForbidden
	plan.Reversible = true // even the most favorable shape must still Block
	d := Evaluate(plan, floatPtr(1.0), permissivePolicy())
	if d.Outcome != Blocked {
		t.Fatalf("Outcome = %v, reason = %q; want Blocked for RiskForbidden", d.Outcome, d.Reason)
	}
	if !strings.Contains(d.Reason, "forbidden") {
		t.Fatalf("Reason %q does not explain the forbidden risk level", d.Reason)
	}
}

func TestEvaluate_Blocked_MissingTargetName(t *testing.T) {
	plan := scaleUpPlan()
	plan.TargetName = ""
	d := Evaluate(plan, floatPtr(0.99), permissivePolicy())
	if d.Outcome != Blocked {
		t.Fatalf("Outcome = %v, reason = %q; want Blocked for missing target name", d.Outcome, d.Reason)
	}
}

func TestEvaluate_Blocked_ConfidenceOutOfRange(t *testing.T) {
	for _, c := range []float64{-0.1, 1.1, 5} {
		d := Evaluate(scaleUpPlan(), floatPtr(c), permissivePolicy())
		if d.Outcome != Blocked {
			t.Fatalf("confidence=%v: Outcome = %v, reason = %q; want Blocked", c, d.Outcome, d.Reason)
		}
	}
}

// --- Decision always carries a Reason ---------------------------------------

func TestEvaluate_EveryOutcomeHasNonEmptyReason(t *testing.T) {
	cases := []Decision{
		Evaluate(scaleUpPlan(), floatPtr(0.95), permissivePolicy()),
		Evaluate(scaleUpPlan(), nil, permissivePolicy()),
		Evaluate(RemediationPlan{ActionType: ActionType("bogus"), TargetName: "x"}, floatPtr(0.5), permissivePolicy()),
	}
	for _, d := range cases {
		if strings.TrimSpace(d.Reason) == "" {
			t.Fatalf("Decision %+v has an empty Reason", d)
		}
	}
}
