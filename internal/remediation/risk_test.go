package remediation

import (
	"strings"
	"testing"
)

// TestBaseRiskFloors_CoverEveryActionType is the guard that makes the
// fail-safe fallback in RiskFloorFor a backstop rather than the norm: an
// action type added to validActionTypes without a considered floor would
// otherwise silently be treated as high-risk forever, and nobody would find
// out from the code.
func TestBaseRiskFloors_CoverEveryActionType(t *testing.T) {
	for actionType := range validActionTypes {
		floor, ok := baseRiskFloors[actionType]
		if !ok {
			t.Errorf("action type %q has no entry in baseRiskFloors", actionType)
			continue
		}
		if !floor.Valid() {
			t.Errorf("action type %q has an invalid risk floor %q", actionType, floor)
		}
	}
}

func TestRiskFloorFor_PerActionType(t *testing.T) {
	cases := []struct {
		plan RemediationPlan
		want RiskLevel
	}{
		// §9.3's own examples, one per action type.
		{scaleUpPlan(), RiskLow},
		{restartPodPlan(), RiskMedium},
		{patchResourceLimitsPlan(), RiskMedium},
		{revertContainerImagePlan(), RiskMedium},
		{openPRPlan(), RiskLow},
		{createResourcePlanForGateTest(), RiskMedium},
	}
	for _, c := range cases {
		if got := RiskFloorFor(c.plan); got != c.want {
			t.Errorf("RiskFloorFor(%s) = %q, want %q", c.plan.ActionType, got, c.want)
		}
	}
}

// TestRiskFloorFor_UnknownActionTypeFloorsHigh: "unrecognized" must never read
// as "harmless".
func TestRiskFloorFor_UnknownActionTypeFloorsHigh(t *testing.T) {
	p := scaleUpPlan()
	p.ActionType = ActionType("DeleteNamespace")
	if got := RiskFloorFor(p); got != RiskHigh {
		t.Errorf("RiskFloorFor(unknown action) = %q, want %q", got, RiskHigh)
	}
}

// TestRiskFloorFor_StatefulSetTargetRaisesFloor: §9.3's high row, "touch a
// StatefulSet or PVC". The same params and the same action type against a
// StatefulSet is not the same act as against a Deployment.
func TestRiskFloorFor_StatefulSetTargetRaisesFloor(t *testing.T) {
	p := patchResourceLimitsPlan()
	if got := RiskFloorFor(p); got != RiskMedium {
		t.Fatalf("RiskFloorFor(Deployment target) = %q, want %q", got, RiskMedium)
	}
	p.TargetGVK = "apps/v1/StatefulSet"
	if got := RiskFloorFor(p); got != RiskHigh {
		t.Errorf("RiskFloorFor(StatefulSet target) = %q, want %q", got, RiskHigh)
	}

	// The modifier is not action-specific — a scale of a StatefulSet is
	// floored the same way, even though its own base floor is low.
	s := scaleUpPlan()
	s.TargetGVK = "apps/v1/StatefulSet"
	if got := RiskFloorFor(s); got != RiskHigh {
		t.Errorf("RiskFloorFor(ScaleDeployment on a StatefulSet) = %q, want %q", got, RiskHigh)
	}
}

// TestRiskFloorFor_ProtectedNamespaceRaisesFloor: §9.3's "anything in
// kube-system -> minimum high", plus the platform's own namespace.
func TestRiskFloorFor_ProtectedNamespaceRaisesFloor(t *testing.T) {
	for _, ns := range []string{"kube-system", "kube-public", "kube-node-lease", "argus-system"} {
		p := scaleUpPlan()
		p.TargetNamespace = ns
		if got := RiskFloorFor(p); got != RiskHigh {
			t.Errorf("RiskFloorFor(namespace %q) = %q, want %q", ns, got, RiskHigh)
		}
	}
	p := scaleUpPlan()
	p.TargetNamespace = "payments"
	if got := RiskFloorFor(p); got != RiskLow {
		t.Errorf("RiskFloorFor(ordinary namespace) = %q, want %q", got, RiskLow)
	}
}

// TestDataTierRaisesFloor is BACKLOG.md R4's first live-metadata modifier:
// "touching a resource labelled tier=data -> minimum high."
func TestDataTierRaisesFloor(t *testing.T) {
	if !DataTierRaisesFloor(map[string]string{"tier": "data"}) {
		t.Error("tier=data must raise the floor")
	}
	for _, labels := range []map[string]string{
		nil,
		{},
		{"tier": "frontend"},
		{"Tier": "data"}, // wrong case — a different key entirely, not a normalization case
	} {
		if DataTierRaisesFloor(labels) {
			t.Errorf("DataTierRaisesFloor(%v) = true, want false", labels)
		}
	}
}

// TestVolumeMountedRaisesFloor covers another of R4's live-metadata
// modifiers, found
// concretely via issue catalogue PVC-014: a pod template mounting a
// PersistentVolumeClaim carries the same storage-risk property
// statefulTargetKinds already gives a bare PersistentVolumeClaim/StatefulSet
// TARGET, even when the workload itself is a Deployment.
func TestVolumeMountedRaisesFloor(t *testing.T) {
	mounted := []map[string]any{
		{"name": "cache", "emptyDir": map[string]any{}},
		{"name": "data", "persistentVolumeClaim": map[string]any{"claimName": "data-pvc"}},
	}
	if !VolumeMountedRaisesFloor(mounted) {
		t.Error("a volumes list containing a persistentVolumeClaim entry must raise the floor")
	}
	for _, volumes := range [][]map[string]any{
		nil,
		{},
		{{"name": "cache", "emptyDir": map[string]any{}}},
		{{"name": "cfg", "configMap": map[string]any{"name": "app-config"}}},
	} {
		if VolumeMountedRaisesFloor(volumes) {
			t.Errorf("VolumeMountedRaisesFloor(%v) = true, want false", volumes)
		}
	}
}

// TestNamespaceIsProtected is R4's second, absolute modifier: "a namespace
// with a argus.io/protected annotation -> forbidden." Presence-based,
// matching this codebase's syncPolicy.automated precedent — any value
// (including empty string) counts.
func TestNamespaceIsProtected(t *testing.T) {
	if !NamespaceIsProtected(map[string]string{"argus.io/protected": ""}) {
		t.Error("an empty-valued argus.io/protected annotation must still count as protected")
	}
	if !NamespaceIsProtected(map[string]string{"argus.io/protected": "true"}) {
		t.Error("argus.io/protected=true must count as protected")
	}
	for _, annotations := range []map[string]string{
		nil,
		{},
		{"argus.io/other": "true"},
	} {
		if NamespaceIsProtected(annotations) {
			t.Errorf("NamespaceIsProtected(%v) = true, want false", annotations)
		}
	}
}

// TestEffectiveRiskLevel_ModelMayRaiseButNeverLower is §9.3's sentence,
// tested in both directions — the whole reason this file exists.
func TestEffectiveRiskLevel_ModelMayRaiseButNeverLower(t *testing.T) {
	// Lowering: a PatchResourceLimits plan the model called "low" is treated
	// as medium regardless.
	under := patchResourceLimitsPlan()
	under.RiskLevel = RiskLow
	if got := EffectiveRiskLevel(under); got != RiskMedium {
		t.Errorf("EffectiveRiskLevel(declared low, floor medium) = %q, want %q", got, RiskMedium)
	}

	// Raising: the model's own higher judgement is honoured as written.
	over := patchResourceLimitsPlan()
	over.RiskLevel = RiskHigh
	if got := EffectiveRiskLevel(over); got != RiskHigh {
		t.Errorf("EffectiveRiskLevel(declared high, floor medium) = %q, want %q", got, RiskHigh)
	}

	// A garbage declared level can never come out looking safer than the rule.
	garbage := patchResourceLimitsPlan()
	garbage.RiskLevel = RiskLevel("trivial")
	if got := EffectiveRiskLevel(garbage); got != RiskMedium {
		t.Errorf("EffectiveRiskLevel(invalid declared level) = %q, want the floor %q", got, RiskMedium)
	}

	// And the declared value on the plan itself is left alone — §9.5's
	// calibration data is exactly the record of what the model claimed.
	if under.RiskLevel != RiskLow {
		t.Errorf("EffectiveRiskLevel mutated the plan's declared RiskLevel to %q", under.RiskLevel)
	}
}

// TestEvaluate_UsesEffectiveRiskAgainstThePolicyCeiling: the floor has to
// actually reach the decision, not just be computable.
func TestEvaluate_UsesEffectiveRiskAgainstThePolicyCeiling(t *testing.T) {
	// A ScaleDeployment (base floor low) on a StatefulSet is floored high, so
	// a low-risk ceiling must refuse it even though the plan says "low".
	p := scaleUpPlan()
	p.TargetGVK = "apps/v1/StatefulSet"
	p.RiskLevel = RiskLow

	d := Evaluate(p, floatPtr(1.0), AutonomyPolicy{
		AutoApproveMaxRisk:          RiskLow,
		MinConfidenceForAutoApprove: 0,
	})
	if d.Outcome != NeedsApproval {
		t.Fatalf("Outcome = %v (%q), want NeedsApproval — the declared low risk must not beat the StatefulSet floor", d.Outcome, d.Reason)
	}
	if !strings.Contains(d.Reason, "high") {
		t.Errorf("Reason %q does not name the floored risk level, so an operator cannot tell why", d.Reason)
	}
	if !strings.Contains(d.Reason, "deterministic floor") {
		t.Errorf("Reason %q does not explain that a deterministic floor applied", d.Reason)
	}
}

// TestEvaluate_PatchResourceLimitsIsNeverAutoApproved is the explicit verdict
// on automatic eligibility: not "unlikely to be auto-approved under today's
// default policy", but never, under any policy, at any confidence.
func TestEvaluate_PatchResourceLimitsIsNeverAutoApproved(t *testing.T) {
	if !NeverAutoApprove(ActionPatchResourceLimits) {
		t.Fatal("NeverAutoApprove(PatchResourceLimits) = false, want true")
	}

	maximallyPermissive := AutonomyPolicy{
		AutoApproveMaxRisk:              RiskHigh,
		MinConfidenceForAutoApprove:     0.0,
		RequireReversibleForAutoApprove: false,
	}
	d := Evaluate(patchResourceLimitsPlan(), floatPtr(1.0), maximallyPermissive)
	if d.Outcome != NeedsApproval {
		t.Fatalf("Outcome = %v (%q), want NeedsApproval at confidence 1.0 under a maximally permissive policy", d.Outcome, d.Reason)
	}
	if !strings.Contains(d.Reason, "approval-only") {
		t.Errorf("Reason %q does not say the action is approval-only by construction", d.Reason)
	}

	// The other action types are NOT swept up by this rule.
	for _, plan := range []RemediationPlan{scaleUpPlan(), restartPodPlan(), openPRPlan()} {
		if NeverAutoApprove(plan.ActionType) {
			t.Errorf("NeverAutoApprove(%s) = true, want false — this feature must not have changed the other action types' eligibility", plan.ActionType)
		}
	}
}

func TestMaxRisk(t *testing.T) {
	cases := []struct {
		a, b, want RiskLevel
	}{
		{RiskLow, RiskMedium, RiskMedium},
		{RiskHigh, RiskMedium, RiskHigh},
		{RiskMedium, RiskMedium, RiskMedium},
		{RiskLevel(""), RiskLow, RiskLow},
		{RiskHigh, RiskLevel("bogus"), RiskHigh},
	}
	for _, c := range cases {
		if got := maxRisk(c.a, c.b); got != c.want {
			t.Errorf("maxRisk(%q, %q) = %q, want %q", c.a, c.b, got, c.want)
		}
	}
}

// TestEvaluate_RevertContainerImageIsNeverAutoApproved is this action type's
// explicit automatic-eligibility verdict, and it is the one most likely to be
// argued with later — the action's own safety story ("the previous image
// provably ran") reads like an argument FOR unattended execution. It is not:
// see neverAutoApprove's reasoning in risk.go for why "which change was right"
// is not a question the deterministic layer can answer. Asserted under a
// maximally permissive policy at confidence 1.0, because "not auto-approved
// under today's defaults" would be a much weaker claim than the one being made.
func TestEvaluate_RevertContainerImageIsNeverAutoApproved(t *testing.T) {
	if !NeverAutoApprove(ActionRevertContainerImage) {
		t.Fatal("NeverAutoApprove(RevertContainerImage) = false, want true")
	}

	d := Evaluate(revertContainerImagePlan(), floatPtr(1.0), AutonomyPolicy{
		AutoApproveMaxRisk:              RiskHigh,
		MinConfidenceForAutoApprove:     0.0,
		RequireReversibleForAutoApprove: false,
	})
	if d.Outcome != NeedsApproval {
		t.Fatalf("Outcome = %v (%q), want NeedsApproval at confidence 1.0 under a maximally permissive policy", d.Outcome, d.Reason)
	}
	if !strings.Contains(d.Reason, "approval-only") {
		t.Errorf("Reason %q does not say the action is approval-only by construction", d.Reason)
	}
}

// TestRiskFloorFor_RevertContainerImageDeclaredLowIsRaised: a model that calls
// a revert "low risk" — a very natural mistake, since nothing new is being
// invented — must still be treated as medium. §9.3's floor, in the direction
// that actually matters.
func TestRiskFloorFor_RevertContainerImageDeclaredLowIsRaised(t *testing.T) {
	p := revertContainerImagePlan()
	p.RiskLevel = RiskLow
	if got := EffectiveRiskLevel(p); got != RiskMedium {
		t.Errorf("EffectiveRiskLevel(declared low) = %q, want %q", got, RiskMedium)
	}
}
