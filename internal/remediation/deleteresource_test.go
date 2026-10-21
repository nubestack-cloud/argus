package remediation

import "testing"

// TestDeleteResourcePermitted mirrors TestPatchFieldPermitted's shape: only
// the three reviewed kinds are permitted, and everything else — including
// the kinds this file's own header comment says must never be representable
// here at all (StatefulSet, Namespace, CRD) — is refused. PersistentVolumeClaim
// is permitted HERE (kind-level only — DeleteResourcePermitted has no live
// cluster state to ask whether a given claim is actually orphaned; that
// narrower condition is enforced elsewhere, see this package's
// deleteresource.go header comment and internal/agent/deleteresource_test.go /
// internal/api's own ownership-recheck tests).
func TestDeleteResourcePermitted(t *testing.T) {
	for _, tc := range []struct {
		gvk       string
		permitted bool
	}{
		{"v1/Pod", true},
		{"batch/v1/Job", true},
		{"v1/PersistentVolumeClaim", true},
		{"apps/v1/StatefulSet", false},
		{"v1/Namespace", false},
		{"apiextensions.k8s.io/v1/CustomResourceDefinition", false},
		{"apps/v1/Deployment", false},
		{"v1/ConfigMap", false},
	} {
		t.Run(tc.gvk, func(t *testing.T) {
			_, err := DeleteResourcePermitted(tc.gvk)
			if tc.permitted && err != nil {
				t.Errorf("expected permitted, got error: %v", err)
			}
			if !tc.permitted && err == nil {
				t.Errorf("%s was PERMITTED as a DeleteResource target and must not be", tc.gvk)
			}
		})
	}
}

// TestDeleteResourceAllowlistIsReviewable mirrors
// TestPatchFieldAllowlistIsReviewable: every row has a real justification
// and a fully-qualified GVK.
func TestDeleteResourceAllowlistIsReviewable(t *testing.T) {
	seen := map[string]bool{}
	for _, e := range DeleteResourceAllowlistEntries() {
		if seen[e.GVK] {
			t.Errorf("%s is listed twice", e.GVK)
		}
		seen[e.GVK] = true
		if len(e.Why) < 40 {
			t.Errorf("%s's justification is too short to be one: %q", e.GVK, e.Why)
		}
		if e.GVK == "" || !containsSlash(e.GVK) {
			t.Errorf("%s has no fully-qualified GVK", e.GVK)
		}
	}
	if len(DeleteResourceAllowlistEntries()) == 0 {
		t.Fatal("the allowlist is empty")
	}
	// The kinds DESIGN.md §10.5 and this file's own header comment say must
	// never be representable as a delete target, regardless of any future
	// row's own justification looking reasonable in isolation.
	// PersistentVolumeClaim is deliberately NOT in this list any more
	// (2026-09-01, BUGS.md 118 part (b)/BACKLOG.md AK1, a real owner
	// decision recorded in DESIGN.md §9.3's amended forbidden-tier row) —
	// see TestDeleteResourcePermitted and this package's deleteresource.go
	// header comment for the narrow, structurally-enforced condition that
	// keeps this from being a blanket grant.
	for _, forbidden := range []string{"StatefulSet", "Namespace", "CustomResourceDefinition"} {
		for gvk := range seen {
			if containsSlash(gvk) && stringsHasSuffixKind(gvk, forbidden) {
				t.Errorf("%s names %s, which must never be a DeleteResource target", gvk, forbidden)
			}
		}
	}
}

func containsSlash(s string) bool {
	for _, c := range s {
		if c == '/' {
			return true
		}
	}
	return false
}

func stringsHasSuffixKind(gvk, kind string) bool {
	// GVK is "<apiVersion>/<Kind>" — the Kind is everything after the last
	// slash, matching gvkKind's own convention in risk.go.
	idx := -1
	for i, c := range gvk {
		if c == '/' {
			idx = i
		}
	}
	if idx < 0 {
		return gvk == kind
	}
	return gvk[idx+1:] == kind
}

// TestDeleteResourceParamsMustNotBeReversible is DESIGN.md §10.5's honesty
// requirement, checked at the RemediationPlan level (not on
// DeleteResourceParams alone, which carries no Reversible field of its
// own — that field lives on RemediationPlan).
func TestDeleteResourceParamsMustNotBeReversible(t *testing.T) {
	base := RemediationPlan{
		ActionType:      ActionDeleteResource,
		Params:          DeleteResourceParams{},
		TargetGVK:       "v1/Pod",
		TargetNamespace: "apps",
		TargetName:      "stuck-pod",
		RiskLevel:       RiskHigh,
	}

	honest := base
	honest.Reversible = false
	if err := honest.Validate(); err != nil {
		t.Errorf("an honest (Reversible=false) DeleteResource plan was rejected: %v", err)
	}

	dishonest := base
	dishonest.Reversible = true
	err := dishonest.Validate()
	if err == nil {
		t.Fatal("a DeleteResource plan claiming Reversible=true was accepted — deletion is not undoable through this mechanism")
	}
}

// TestDeleteResourceRejectsForbiddenKind is the RemediationPlan-level
// analogue of TestDeleteResourcePermitted: Validate() must refuse a
// DeleteResource plan against a kind the allowlist does not name, exactly
// like PatchField's own allowlist check does at the same layer.
func TestDeleteResourceRejectsForbiddenKind(t *testing.T) {
	p := RemediationPlan{
		ActionType:      ActionDeleteResource,
		Params:          DeleteResourceParams{},
		TargetGVK:       "apps/v1/StatefulSet",
		TargetNamespace: "apps",
		TargetName:      "db",
		Reversible:      false,
		RiskLevel:       RiskHigh,
	}
	if err := p.Validate(); err == nil {
		t.Fatal("a DeleteResource plan targeting a StatefulSet was accepted — the allowlist must refuse it")
	}
}

// TestDeleteResourceIsApprovalOnly is this package's mechanical guard
// against risk.go's neverAutoApprove silently losing this entry.
func TestDeleteResourceIsApprovalOnly(t *testing.T) {
	if !NeverAutoApprove(ActionDeleteResource) {
		t.Error("DeleteResource can auto-approve — DESIGN.md §10.5 requires this to never be automatic, at any confidence")
	}
}

// TestDeleteResourceBaseRiskFloorIsHigh pins §9.3's "delete anything -> high"
// row directly against baseRiskFloors, independent of the neverAutoApprove
// check above — the two are separate mechanisms and this test is what
// would catch either one silently regressing on its own.
func TestDeleteResourceBaseRiskFloorIsHigh(t *testing.T) {
	p := RemediationPlan{ActionType: ActionDeleteResource, TargetGVK: "v1/Pod"}
	if got := RiskFloorFor(p); got != RiskHigh {
		t.Errorf("RiskFloorFor(DeleteResource) = %q, want %q", got, RiskHigh)
	}
}
