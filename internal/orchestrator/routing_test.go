package orchestrator

import (
	"testing"

	"argus/internal/llm"
	"argus/internal/remediation"
	"argus/internal/resolution"
)

func boolPtr(b bool) *bool { return &b }

func TestResolveRouteClassification(t *testing.T) {
	for _, tc := range []struct {
		name    string
		facts   OwnershipFacts
		execOK  bool
		want    resolution.Route
		applier resolution.Applier
	}{
		{"undetermined -> guidance", OwnershipFacts{Determined: false}, true, resolution.RouteGuidance, resolution.ApplierUnknown},
		{"argocd, automated, plain manifest -> pullRequest", OwnershipFacts{Determined: true, ManagedBy: "argocd", ApplierRaw: "gitopsController", SourceEditable: boolPtr(true)}, true, resolution.RoutePullRequest, resolution.ApplierGitOpsController},
		{"argocd, not automated, plain manifest, exec allowed -> paired (DESIGN §10.2 gap-fill)", OwnershipFacts{Determined: true, ManagedBy: "argocd", ApplierRaw: "none", SourceEditable: boolPtr(true)}, true, resolution.RoutePaired, resolution.ApplierNone},
		{"fleet, no applier check exists -> unknown applier -> guidance", OwnershipFacts{Determined: true, ManagedBy: "fleet", ApplierRaw: "", SourceEditable: boolPtr(true)}, true, resolution.RouteGuidance, resolution.ApplierUnknown},
		{"helm, execution allowed -> inPlace", OwnershipFacts{Determined: true, ManagedBy: "helm"}, true, resolution.RouteInPlace, resolution.ApplierUnknown},
		{"unmanaged, execution allowed -> inPlace", OwnershipFacts{Determined: true, ManagedBy: "none"}, true, resolution.RouteInPlace, resolution.ApplierUnknown},
		{"unmanaged, execution not allowed -> guidance", OwnershipFacts{Determined: true, ManagedBy: "none"}, false, resolution.RouteGuidance, resolution.ApplierUnknown},
		{"none managedBy but a repo is independently known -> repoRegistered", OwnershipFacts{Determined: true, ManagedBy: "none", RepoKnown: true, SourceEditable: boolPtr(true)}, true, resolution.RoutePaired, resolution.ApplierNone},
		// BACKLOG.md F19 mechanism 1: a Helm release matched against an
		// operator-declared objectMappings entry sets RepoKnown even though
		// ManagedBy stays "helm" — this must take it OUT of HelmNoRepo and
		// into RepoRegistered (ApplierNone, never ApplierUnknown: a matched
		// mapping means a repo IS known, just with nothing auto-applying it),
		// making resolution.OwnershipRepoRegistered reachable for the first
		// time. Without this case reaching RepoRegistered, F19 mechanism 1
		// would classify correctly but never actually unlock a route.
		{"helm with an operator-declared mapping match -> repoRegistered, not helmNoRepo", OwnershipFacts{Determined: true, ManagedBy: "helm", RepoKnown: true, ApplierRaw: "none", SourceEditable: boolPtr(true)}, true, resolution.RoutePaired, resolution.ApplierNone},
		{"helm with a mapping match but execution not allowed -> pullRequest, still the durable half", OwnershipFacts{Determined: true, ManagedBy: "helm", RepoKnown: true, ApplierRaw: "none", SourceEditable: boolPtr(true)}, false, resolution.RoutePullRequest, resolution.ApplierNone},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, applier := ResolveRoute(tc.facts, tc.execOK)
			if got.Route != tc.want {
				t.Errorf("ResolveRoute(%+v, %v) = %q (%s), want %q", tc.facts, tc.execOK, got.Route, got.Reason, tc.want)
			}
			if applier != tc.applier {
				t.Errorf("ResolveRoute(%+v, %v) applier = %q, want %q", tc.facts, tc.execOK, applier, tc.applier)
			}
		})
	}
}

func TestEnforceRouteRefusesOutOfRoutePlans(t *testing.T) {
	scale := &remediation.RemediationPlan{ActionType: remediation.ActionScaleDeployment}
	openPR := &remediation.RemediationPlan{ActionType: remediation.ActionOpenPR}

	t.Run("pullRequest route refuses an in-place plan", func(t *testing.T) {
		got := EnforceRoute(llm.Investigation{ProposedPlan: scale}, resolution.RoutePullRequest)
		if got.ProposedPlan != nil {
			t.Errorf("ProposedPlan = %+v, want nil — ScaleDeployment is not in the pullRequest route's permitted set", got.ProposedPlan)
		}
	})

	t.Run("inPlace route refuses OpenPR", func(t *testing.T) {
		got := EnforceRoute(llm.Investigation{ProposedPlan: openPR}, resolution.RouteInPlace)
		if got.ProposedPlan != nil {
			t.Errorf("ProposedPlan = %+v, want nil — OpenPR is not in the inPlace route's permitted set", got.ProposedPlan)
		}
	})

	t.Run("guidance route refuses any plan at all", func(t *testing.T) {
		got := EnforceRoute(llm.Investigation{ProposedPlan: scale}, resolution.RouteGuidance)
		if got.ProposedPlan != nil {
			t.Errorf("ProposedPlan = %+v, want nil — guidance permits nothing", got.ProposedPlan)
		}
	})

	t.Run("permitted plan survives", func(t *testing.T) {
		got := EnforceRoute(llm.Investigation{ProposedPlan: scale}, resolution.RouteInPlace)
		if got.ProposedPlan != scale {
			t.Errorf("ProposedPlan = %+v, want the original plan unchanged", got.ProposedPlan)
		}
	})

	// TestEnforceRouteRefusesOutOfRoutePlans's own DeleteResource case
	// (BUGS.md 118 part (b)): unlike ScaleDeployment/RestartPod/
	// PatchResourceLimits/RevertContainerImage, DeleteResource IS in the
	// pullRequest route's permitted set — see resolution.PermittedActionTypes'
	// own doc comment for why (the orphaned-PVC case it exists for is
	// exactly the shape that resolves to pullRequest once BUGS.md 118 part
	// (a)'s related-workload ownership fallback is in play).
	t.Run("pullRequest route permits DeleteResource", func(t *testing.T) {
		deleteResource := &remediation.RemediationPlan{ActionType: remediation.ActionDeleteResource}
		got := EnforceRoute(llm.Investigation{ProposedPlan: deleteResource}, resolution.RoutePullRequest)
		if got.ProposedPlan != deleteResource {
			t.Errorf("ProposedPlan = %+v, want the DeleteResource plan kept — it is in the pullRequest route's permitted set", got.ProposedPlan)
		}
	})

	t.Run("non-paired route drops a second plan with nothing to pair with", func(t *testing.T) {
		got := EnforceRoute(llm.Investigation{ProposedPlan: scale, ProposedPairedPlan: openPR}, resolution.RouteInPlace)
		if got.ProposedPairedPlan != nil {
			t.Errorf("ProposedPairedPlan = %+v, want nil — route %s does not offer a paired plan", got.ProposedPairedPlan, resolution.RouteInPlace)
		}
		if got.ProposedPlan != scale {
			t.Errorf("ProposedPlan should survive untouched, got %+v", got.ProposedPlan)
		}
	})
}

func TestEnforceRoutePairedNormalization(t *testing.T) {
	scale := &remediation.RemediationPlan{ActionType: remediation.ActionScaleDeployment}
	restart := &remediation.RemediationPlan{ActionType: remediation.ActionRestartPod}
	openPR := &remediation.RemediationPlan{ActionType: remediation.ActionOpenPR}
	openPR2 := &remediation.RemediationPlan{ActionType: remediation.ActionOpenPR, TargetName: "other"}

	t.Run("already in the right slots", func(t *testing.T) {
		got := EnforceRoute(llm.Investigation{ProposedPlan: scale, ProposedPairedPlan: openPR}, resolution.RoutePaired)
		if got.ProposedPlan != scale || got.ProposedPairedPlan != openPR {
			t.Errorf("got ProposedPlan=%+v ProposedPairedPlan=%+v, want unchanged", got.ProposedPlan, got.ProposedPairedPlan)
		}
	})

	t.Run("swapped — OpenPR under proposedPlan, in-place under proposedPairedPlan", func(t *testing.T) {
		got := EnforceRoute(llm.Investigation{ProposedPlan: openPR, ProposedPairedPlan: scale}, resolution.RoutePaired)
		if got.ProposedPlan != scale {
			t.Errorf("ProposedPlan = %+v, want the in-place plan reassigned here", got.ProposedPlan)
		}
		if got.ProposedPairedPlan != openPR {
			t.Errorf("ProposedPairedPlan = %+v, want the OpenPR plan reassigned here", got.ProposedPairedPlan)
		}
	})

	t.Run("duplicate OpenPR — keep the first, refuse the duplicate", func(t *testing.T) {
		got := EnforceRoute(llm.Investigation{ProposedPlan: openPR, ProposedPairedPlan: openPR2}, resolution.RoutePaired)
		if got.ProposedPlan != openPR {
			t.Errorf("ProposedPlan = %+v, want the first OpenPR kept", got.ProposedPlan)
		}
		if got.ProposedPairedPlan != nil {
			t.Errorf("ProposedPairedPlan = %+v, want nil — a duplicate OpenPR must be refused", got.ProposedPairedPlan)
		}
	})

	t.Run("duplicate in-place — keep the first, refuse the duplicate", func(t *testing.T) {
		got := EnforceRoute(llm.Investigation{ProposedPlan: scale, ProposedPairedPlan: restart}, resolution.RoutePaired)
		if got.ProposedPlan != scale {
			t.Errorf("ProposedPlan = %+v, want the first in-place plan kept", got.ProposedPlan)
		}
		if got.ProposedPairedPlan != nil {
			t.Errorf("ProposedPairedPlan = %+v, want nil — a second in-place action with no OpenPR must be refused", got.ProposedPairedPlan)
		}
	})

	t.Run("partial pairing — only the in-place half proposed — left as-is, not discarded", func(t *testing.T) {
		got := EnforceRoute(llm.Investigation{ProposedPlan: scale}, resolution.RoutePaired)
		if got.ProposedPlan != scale {
			t.Errorf("ProposedPlan = %+v, want the valid partial proposal kept rather than discarded", got.ProposedPlan)
		}
	})

	t.Run("partial pairing — only OpenPR proposed — left as-is", func(t *testing.T) {
		got := EnforceRoute(llm.Investigation{ProposedPlan: openPR}, resolution.RoutePaired)
		if got.ProposedPlan != openPR {
			t.Errorf("ProposedPlan = %+v, want the valid partial OpenPR proposal kept", got.ProposedPlan)
		}
	})
}
