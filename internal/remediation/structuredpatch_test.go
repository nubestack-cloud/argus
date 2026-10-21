package remediation

import (
	"strings"
	"testing"
)

// --- StructuredPatchParams.Validate: shape checks that need no target kind --

func TestStructuredPatchParams_Validate_AcceptsAWellFormedMultiOpPlan(t *testing.T) {
	p := StructuredPatchParams{Ops: []StructuredPatchOp{
		{FieldPath: "spec.progressDeadlineSeconds", NewValue: "900"},
		{FieldPath: "spec.template.spec.containers[api].resources.requests.cpu", NewValue: "250m"},
	}}
	if err := p.Validate(); err != nil {
		t.Fatalf("Validate() = %v, want nil", err)
	}
}

func TestStructuredPatchParams_Validate_RejectsNoOperations(t *testing.T) {
	if err := (StructuredPatchParams{}).Validate(); err == nil {
		t.Fatal("Validate() = nil, want an error for a plan with zero operations")
	}
}

func TestStructuredPatchParams_Validate_RejectsDuplicatePaths(t *testing.T) {
	// Same field, written in the two notations this package treats as
	// identical (patchfield.go's normaliseFieldPath) — a plan that names it
	// twice cannot say which write wins, so it is refused outright rather than
	// letting the second operation silently shadow the first.
	p := StructuredPatchParams{Ops: []StructuredPatchOp{
		{FieldPath: "spec.ports[0].targetPort", NewValue: "8080"},
		{FieldPath: "spec.ports.0.targetPort", NewValue: "9090"},
	}}
	err := p.Validate()
	if err == nil {
		t.Fatal("Validate() = nil, want an error for two operations naming the same normalised field")
	}
	if !strings.Contains(err.Error(), "operation 1") || !strings.Contains(err.Error(), "operation 2") {
		t.Errorf("error = %q, want it to name both conflicting operations", err.Error())
	}
}

func TestStructuredPatchParams_Validate_ReusesPatchFieldParamsBoundsPerOperation(t *testing.T) {
	// These bounds are PatchFieldParams.Validate's own (patchfield.go) — this
	// test proves StructuredPatchParams.Validate calls that method rather than
	// re-stating the rules, by exercising bounds this file's own code never
	// mentions a number for (the 512-character cap, the no-newlines rule).
	cases := []struct {
		name string
		op   StructuredPatchOp
	}{
		{"empty fieldPath", StructuredPatchOp{FieldPath: "", NewValue: "x"}},
		{"empty newValue", StructuredPatchOp{FieldPath: "spec.foo", NewValue: ""}},
		{"newValue spans multiple lines", StructuredPatchOp{FieldPath: "spec.foo", NewValue: "a\nb"}},
		{"newValue too long", StructuredPatchOp{FieldPath: "spec.foo", NewValue: strings.Repeat("x", 513)}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := StructuredPatchParams{Ops: []StructuredPatchOp{
				{FieldPath: "spec.progressDeadlineSeconds", NewValue: "900"}, // a real, valid operation alongside the bad one
				c.op,
			}}
			err := p.Validate()
			if err == nil {
				t.Fatalf("Validate() = nil, want an error for operation shape %q", c.name)
			}
			if !strings.Contains(err.Error(), "operation 2 of 2") {
				t.Errorf("error = %q, want it to name operation 2 specifically (the bad one), not just fail generically", err.Error())
			}
		})
	}
}

// --- RemediationPlan.Validate's ActionStructuredPatch branch: needs a target kind --

func structuredPatchPlan(ops ...StructuredPatchOp) RemediationPlan {
	return RemediationPlan{
		ActionType:      ActionStructuredPatch,
		TargetGVK:       "apps/v1/Deployment",
		TargetNamespace: "default",
		TargetName:      "web",
		Reversible:      true,
		RiskLevel:       RiskMedium,
		Params:          StructuredPatchParams{Ops: ops},
	}
}

func TestRemediationPlan_Validate_AcceptsAMultiOpStructuredPatchOnTheAllowlist(t *testing.T) {
	p := structuredPatchPlan(
		StructuredPatchOp{FieldPath: "spec.progressDeadlineSeconds", NewValue: "900"},
		StructuredPatchOp{FieldPath: "spec.template.spec.containers[api].resources.requests.cpu", NewValue: "250m"},
	)
	if err := p.Validate(); err != nil {
		t.Fatalf("Validate() = %v, want nil for two genuinely allowlisted paths", err)
	}
}

// TestRemediationPlan_Validate_StructuredPatchRejectsInFullOnOneBadPath is
// this task's requirement 2, at the RemediationPlan level rather than the
// params level: a plan with several valid paths and ONE that is not on
// PatchFieldPermitted's allowlist is invalid as a WHOLE plan, and the error
// names which operation and what was wrong with it.
func TestRemediationPlan_Validate_StructuredPatchRejectsInFullOnOneBadPath(t *testing.T) {
	p := structuredPatchPlan(
		StructuredPatchOp{FieldPath: "spec.progressDeadlineSeconds", NewValue: "900"}, // valid
		StructuredPatchOp{FieldPath: "spec.notOnAnyAllowlist", NewValue: "x"},         // invalid
	)
	err := p.Validate()
	if err == nil {
		t.Fatal("Validate() = nil, want an error — one unpermitted path must invalidate the whole plan")
	}
	if !strings.Contains(err.Error(), "operation 2 of 2") {
		t.Errorf("error = %q, want it to name operation 2 (the second, bad, operation)", err.Error())
	}
	if !strings.Contains(err.Error(), "spec.notOnAnyAllowlist") {
		t.Errorf("error = %q, want it to name the refused field path", err.Error())
	}
	if !strings.Contains(err.Error(), "not in the reviewed allowlist") {
		t.Errorf("error = %q, want PatchFieldPermitted's own refusal text, not a re-worded one", err.Error())
	}
}

// TestRemediationPlan_Validate_StructuredPatchInheritsPatchFieldsExclusions
// proves this task's requirement 3: a path already owned by ScaleDeployment,
// RevertContainerImage or PatchResourceLimits is refused for StructuredPatch
// for the EXACT SAME reason PatchField refuses it — because both call the
// identical PatchFieldPermitted function, not because StructuredPatch has its
// own copy of the exclusion list.
func TestRemediationPlan_Validate_StructuredPatchInheritsPatchFieldsExclusions(t *testing.T) {
	cases := []struct {
		name string
		path string
	}{
		{"replicas belongs to ScaleDeployment", "spec.replicas"},
		{"container image belongs to RevertContainerImage", "spec.template.spec.containers[web].image"},
		{"resource limits belong to PatchResourceLimits", "spec.template.spec.containers[web].resources.limits.memory"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			// The SAME plan shape, once as a single-op PatchField plan and once
			// as a one-op StructuredPatch plan, must fail with THE SAME error —
			// proving the exclusion is inherited, not reimplemented.
			patchFieldPlan := RemediationPlan{
				ActionType: ActionPatchField, TargetGVK: "apps/v1/Deployment", TargetNamespace: "default", TargetName: "web",
				Reversible: true, RiskLevel: RiskMedium,
				Params: PatchFieldParams{FieldPath: c.path, NewValue: "5"},
			}
			wantErr := patchFieldPlan.Validate()
			if wantErr == nil {
				t.Fatalf("test setup bug: PatchField unexpectedly permits %q", c.path)
			}

			structuredPlan := structuredPatchPlan(StructuredPatchOp{FieldPath: c.path, NewValue: "5"})
			gotErr := structuredPlan.Validate()
			if gotErr == nil {
				t.Fatalf("Validate() = nil, want %q refused for StructuredPatch exactly as it is for PatchField", c.path)
			}
			// Both wrap PatchFieldPermitted's own error; StructuredPatch's is
			// prefixed with "operation 1 of 1: " (plan.go), so compare on
			// PatchFieldPermitted's own text rather than the two wrapper
			// strings being byte-identical.
			_, permErr := PatchFieldPermitted("apps/v1/Deployment", c.path)
			if permErr == nil {
				t.Fatalf("test setup bug: PatchFieldPermitted unexpectedly allows %q", c.path)
			}
			if !strings.Contains(wantErr.Error(), permErr.Error()) {
				t.Fatalf("test setup bug: PatchField's own error (%q) does not contain PatchFieldPermitted's (%q)", wantErr.Error(), permErr.Error())
			}
			if !strings.Contains(gotErr.Error(), permErr.Error()) {
				t.Errorf("StructuredPatch error = %q, want it to contain PatchFieldPermitted's refusal (%q) — the same check PatchField uses, inherited rather than reimplemented", gotErr.Error(), permErr.Error())
			}
		})
	}
}

func TestRemediationPlan_Validate_StructuredPatchRejectsMismatchedParams(t *testing.T) {
	p := structuredPatchPlan(StructuredPatchOp{FieldPath: "spec.progressDeadlineSeconds", NewValue: "900"})
	p.Params = PatchFieldParams{FieldPath: "spec.progressDeadlineSeconds", NewValue: "900"}
	if err := p.Validate(); err == nil {
		t.Fatal("Validate() = nil, want an error when Params is PatchFieldParams for an ActionStructuredPatch plan")
	}
}

// TestEvaluate_StructuredPatchInvalidPlanBlocksWithInvalidPlanFlag is the
// gate-level proof that a rejected multi-op plan never reaches persistence:
// remediation.Evaluate must classify it Blocked with Decision.InvalidPlan
// true, which is exactly what stops orchestrator.advanceForPlan from
// attaching the plan for persistRecommendation to write (BUGS.md 86).
func TestEvaluate_StructuredPatchInvalidPlanBlocksWithInvalidPlanFlag(t *testing.T) {
	p := structuredPatchPlan(
		StructuredPatchOp{FieldPath: "spec.progressDeadlineSeconds", NewValue: "900"},
		StructuredPatchOp{FieldPath: "spec.notOnAnyAllowlist", NewValue: "x"},
	)
	confidence := 0.95
	decision := Evaluate(p, &confidence, AutonomyPolicy{AutoApproveMaxRisk: RiskHigh, MinConfidenceForAutoApprove: 0})
	if decision.Outcome != Blocked {
		t.Fatalf("Outcome = %v, want Blocked", decision.Outcome)
	}
	if !decision.InvalidPlan {
		t.Fatal("InvalidPlan = false, want true — this Blocked came from Validate() failing, which is exactly the case that must never be persisted verbatim")
	}
}

// TestEvaluate_StructuredPatchNeverAutoApproves proves risk.go's
// neverAutoApprove entry for ActionStructuredPatch actually reaches Evaluate:
// even at maximum confidence and a policy ceiling that would otherwise
// auto-approve every risk level, a valid multi-op plan still comes back
// NeedsApproval.
func TestEvaluate_StructuredPatchNeverAutoApproves(t *testing.T) {
	p := structuredPatchPlan(StructuredPatchOp{FieldPath: "spec.progressDeadlineSeconds", NewValue: "900"})
	p.RiskLevel = RiskLow
	confidence := 1.0
	decision := Evaluate(p, &confidence, AutonomyPolicy{AutoApproveMaxRisk: RiskHigh, MinConfidenceForAutoApprove: 0})
	if decision.Outcome != NeedsApproval {
		t.Fatalf("Outcome = %v, want NeedsApproval — StructuredPatch is approval-only by construction", decision.Outcome)
	}
}

// --- Risk floor: the highest risk among the operations actually named ------

func TestRiskFloorFor_StructuredPatchTakesTheHighestMatchedOperationRisk(t *testing.T) {
	// spec.progressDeadlineSeconds is RiskLow; a PodDisruptionBudget's
	// minAvailable is RiskHigh (patchfield.go's own table) — the plan as a
	// whole must floor at the higher of the two, not at either alone and not
	// at the ActionStructuredPatch fallback (RiskHigh) by coincidence.
	p := RemediationPlan{
		ActionType: ActionStructuredPatch,
		TargetGVK:  "apps/v1/Deployment",
		Params: StructuredPatchParams{Ops: []StructuredPatchOp{
			{FieldPath: "spec.progressDeadlineSeconds", NewValue: "900"},
		}},
	}
	if got := RiskFloorFor(p); got != RiskLow {
		t.Errorf("a single RiskLow operation floors at %q, want %q", got, RiskLow)
	}

	mixed := RemediationPlan{
		ActionType: ActionStructuredPatch,
		TargetGVK:  "apps/v1/Deployment",
		Params: StructuredPatchParams{Ops: []StructuredPatchOp{
			{FieldPath: "spec.progressDeadlineSeconds", NewValue: "900"},                               // low
			{FieldPath: "spec.template.spec.containers[api].resources.requests.cpu", NewValue: "250m"}, // medium
		}},
	}
	if got := RiskFloorFor(mixed); got != RiskMedium {
		t.Errorf("mixing a low and a medium operation floors at %q, want %q (the higher of the two)", got, RiskMedium)
	}
}

func TestRiskFloorFor_StructuredPatchFallsBackToHighOnUnreadableParams(t *testing.T) {
	p := RemediationPlan{ActionType: ActionStructuredPatch, TargetGVK: "apps/v1/Deployment", Params: nil}
	if got := RiskFloorFor(p); got != RiskHigh {
		t.Errorf("RiskFloorFor with nil params = %q, want %q (the safe fallback)", got, RiskHigh)
	}
}

// --- PlannedFieldPaths: the multi-op case ----------------------------------

func TestPlannedFieldPaths_StructuredPatchListsEveryOperation(t *testing.T) {
	got, err := PlannedFieldPaths(RemediationPlan{
		ActionType: ActionStructuredPatch,
		Params: StructuredPatchParams{Ops: []StructuredPatchOp{
			{FieldPath: "spec.progressDeadlineSeconds", NewValue: "900"},
			{FieldPath: "spec.ports[0].targetPort", NewValue: "8080"},
		}},
	})
	if err != nil {
		t.Fatalf("PlannedFieldPaths: %v", err)
	}
	want := []string{"spec.progressDeadlineSeconds", "spec.ports.0.targetPort"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("path %d = %q, want %q", i, got[i], want[i])
		}
	}
}
