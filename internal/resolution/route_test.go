package resolution

import (
	"os"
	"strings"
	"testing"
)

// TestRouteForMatchesTheRoutingTable covers lld/08-remediation-contracts.md
// §12.4's table row by row, plus the combinations the table leaves
// unwritten (documented in RouteFor's own comments) — this is the
// acceptance criterion §12.2 itself states: "exhaustively table-testable...
// which is the point, because it is the decision the product turns on."
func TestRouteForMatchesTheRoutingTable(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   RouteInputs
		want Route
	}{
		// Rows 1-3: GitOps controller, applier confirmed active.
		{"row1: controller applies, source editable", RouteInputs{Ownership: OwnershipGitOpsController, Applier: ApplierGitOpsController, SourceEditable: true, ExecutionAllowed: true}, RoutePullRequest},
		{"row1: controller applies, source editable, execution not allowed either — still pullRequest", RouteInputs{Ownership: OwnershipGitOpsController, Applier: ApplierGitOpsController, SourceEditable: true, ExecutionAllowed: false}, RoutePullRequest},
		{"row2: controller applies, templated source, execution allowed", RouteInputs{Ownership: OwnershipGitOpsController, Applier: ApplierGitOpsController, SourceEditable: false, ExecutionAllowed: true}, RouteGuidance},
		{"row3: controller applies, templated source, execution not allowed", RouteInputs{Ownership: OwnershipGitOpsController, Applier: ApplierGitOpsController, SourceEditable: false, ExecutionAllowed: false}, RouteGuidance},

		// Rows 4-6: a repository is known, nothing applies it.
		{"row4: repo registered, editable, execution allowed -> paired", RouteInputs{Ownership: OwnershipRepoRegistered, Applier: ApplierNone, SourceEditable: true, ExecutionAllowed: true}, RoutePaired},
		{"row5: repo registered, editable, execution not allowed -> pullRequest only", RouteInputs{Ownership: OwnershipRepoRegistered, Applier: ApplierNone, SourceEditable: true, ExecutionAllowed: false}, RoutePullRequest},
		{"row6: repo registered, not editable, execution allowed -> inPlace only", RouteInputs{Ownership: OwnershipRepoRegistered, Applier: ApplierNone, SourceEditable: false, ExecutionAllowed: true}, RouteInPlace},
		{"gap: repo registered, not editable, execution not allowed -> nothing left but guidance", RouteInputs{Ownership: OwnershipRepoRegistered, Applier: ApplierNone, SourceEditable: false, ExecutionAllowed: false}, RouteGuidance},

		// Row 7: repo registered, applier unknown — fail closed regardless
		// of source editability or execution.
		{"row7: repo registered, applier unknown, editable+execution -> still guidance", RouteInputs{Ownership: OwnershipRepoRegistered, Applier: ApplierUnknown, SourceEditable: true, ExecutionAllowed: true}, RouteGuidance},
		{"row7: repo registered, applier unknown, neither editable nor execution", RouteInputs{Ownership: OwnershipRepoRegistered, Applier: ApplierUnknown, SourceEditable: false, ExecutionAllowed: false}, RouteGuidance},

		// Row 8: Helm, no repo.
		{"row8: helm no repo, execution allowed -> inPlace", RouteInputs{Ownership: OwnershipHelmNoRepo, ExecutionAllowed: true}, RouteInPlace},
		{"gap: helm no repo, execution not allowed -> nothing left but guidance", RouteInputs{Ownership: OwnershipHelmNoRepo, ExecutionAllowed: false}, RouteGuidance},

		// Rows 9-10: unmanaged.
		{"row9: unmanaged, execution allowed -> inPlace", RouteInputs{Ownership: OwnershipUnmanaged, ExecutionAllowed: true}, RouteInPlace},
		{"row10: unmanaged, execution not allowed -> guidance", RouteInputs{Ownership: OwnershipUnmanaged, ExecutionAllowed: false}, RouteGuidance},

		// Row 11: cannot determine ownership at all.
		{"row11: ownership unknown -> guidance, regardless of everything else", RouteInputs{Ownership: OwnershipUnknown, Applier: ApplierGitOpsController, SourceEditable: true, ExecutionAllowed: true}, RouteGuidance},

		// The gap §12.4's table never writes at all: a GitOps controller
		// object exists, but automated sync is confirmed OFF. Routed like
		// "repo registered, no applier" per DESIGN.md §10.2's own explicit
		// carve-out (RouteFor's own comment cites this).
		{"gap: controller found but automated sync off, editable+execution -> paired, same as repo-registered", RouteInputs{Ownership: OwnershipGitOpsController, Applier: ApplierNone, SourceEditable: true, ExecutionAllowed: true}, RoutePaired},
		{"gap: controller found but automated sync off, not editable, execution allowed -> inPlace", RouteInputs{Ownership: OwnershipGitOpsController, Applier: ApplierNone, SourceEditable: false, ExecutionAllowed: true}, RouteInPlace},
		{"gap: controller found but automated sync off, editable, execution not allowed -> pullRequest", RouteInputs{Ownership: OwnershipGitOpsController, Applier: ApplierNone, SourceEditable: true, ExecutionAllowed: false}, RoutePullRequest},

		// The same "applier could not be checked" fail-closed rule, reached
		// through the OTHER Ownership value that can produce it.
		{"gap: controller found, applier check itself failed -> guidance, never collapses to none", RouteInputs{Ownership: OwnershipGitOpsController, Applier: ApplierUnknown, SourceEditable: true, ExecutionAllowed: true}, RouteGuidance},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := RouteFor(tc.in)
			if got.Route != tc.want {
				t.Errorf("RouteFor(%+v) = %q, want %q (reason: %s)", tc.in, got.Route, tc.want, got.Reason)
			}
			if got.Reason == "" {
				t.Errorf("RouteFor(%+v) returned an empty reason — every route decision must be explainable to the operator", tc.in)
			}
		})
	}
}

// TestApplierUnknownNeverCollapsesIntoApplierNone is §12.3's own explicit
// safety property, asserted directly rather than only incidentally covered
// by the table test above: for every Ownership value where Applier is
// actually consulted, swapping ApplierUnknown in for ApplierNone must never
// produce the SAME route when that route is capable of opening a pull
// request — an Unknown applier must fail closed to guidance, full stop.
func TestApplierUnknownNeverCollapsesIntoApplierNone(t *testing.T) {
	for _, ownership := range []Ownership{OwnershipGitOpsController, OwnershipRepoRegistered} {
		for _, sourceEditable := range []bool{true, false} {
			for _, executionAllowed := range []bool{true, false} {
				got := RouteFor(RouteInputs{Ownership: ownership, Applier: ApplierUnknown, SourceEditable: sourceEditable, ExecutionAllowed: executionAllowed})
				if got.Route != RouteGuidance {
					t.Errorf("RouteFor(Ownership=%s, Applier=Unknown, SourceEditable=%v, ExecutionAllowed=%v) = %q, want guidance — an unknown applier must always fail closed",
						ownership, sourceEditable, executionAllowed, got.Route)
				}
			}
		}
	}
}

func TestPermittedActionTypes(t *testing.T) {
	for _, tc := range []struct {
		route Route
		want  []string
	}{
		{RoutePullRequest, []string{"OpenPR", "DeleteResource"}},
		{RouteInPlace, []string{"ScaleDeployment", "RestartPod", "PatchResourceLimits", "RevertContainerImage", "DeleteResource", "AnnotateResource", "LabelResource", "CreateResource", "CordonNode", "DrainNode"}},
		{RoutePaired, []string{"ScaleDeployment", "RestartPod", "PatchResourceLimits", "RevertContainerImage", "DeleteResource", "AnnotateResource", "LabelResource", "CreateResource", "CordonNode", "DrainNode", "OpenPR"}},
		{RouteGuidance, nil},
	} {
		t.Run(string(tc.route), func(t *testing.T) {
			got := PermittedActionTypes(tc.route)
			if len(got) != len(tc.want) {
				t.Fatalf("PermittedActionTypes(%s) = %v, want %v", tc.route, got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Errorf("PermittedActionTypes(%s)[%d] = %q, want %q", tc.route, i, got[i], tc.want[i])
				}
			}
			for _, at := range got {
				if at == "PatchField" {
					t.Errorf("PermittedActionTypes(%s) offered PatchField — BACKLOG.md F11 deliberately keeps it off the model's route pending a fresh decision to reopen it, not because internal/api can't execute it (BUGS.md 78 was fixed)", tc.route)
				}
			}
		})
	}
}

// TestAnnotateLabelCreate_GatedLikeExistingInPlaceActions pins PROJECT.md
// B130/F9's 2026-09-06 decision: AnnotateResource/LabelResource are gated
// identically to the four pre-existing in-place actions (offered on
// RouteInPlace/RoutePaired, never RoutePullRequest — a live metadata patch
// to a GitOps-managed object is reverted/fought by the next sync exactly
// like a live field patch would be), and CreateResource is in-place-only
// for a different reason: OpenPR cannot yet create a genuinely new file
// (see route.go's own doc comment on this function), so it has nowhere
// else to go until that is fixed.
func TestAnnotateLabelCreate_GatedLikeExistingInPlaceActions(t *testing.T) {
	for _, at := range []string{"AnnotateResource", "LabelResource", "CreateResource"} {
		t.Run(at, func(t *testing.T) {
			if !containsString(PermittedActionTypes(RouteInPlace), at) {
				t.Errorf("%s not offered on RouteInPlace", at)
			}
			if !containsString(PermittedActionTypes(RoutePaired), at) {
				t.Errorf("%s not offered on RoutePaired", at)
			}
			if containsString(PermittedActionTypes(RoutePullRequest), at) {
				t.Errorf("%s offered on RoutePullRequest — a live metadata/create action on an object Git owns is exactly the anti-pattern the other in-place actions are gated away from", at)
			}
			if containsString(PermittedActionTypes(RouteGuidance), at) {
				t.Errorf("%s offered on RouteGuidance — no execution identity exists to run anything on this route", at)
			}
		})
	}
}

func containsString(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// TestPatchFieldExclusionReasonIsHonest is BACKLOG.md F27's "do now,
// regardless" fix: PermittedActionTypes' own doc comment used to state that
// PatchField is excluded because "internal/api has no execution case for it
// (BUGS.md 78)" — a claim that was true once and is false today.
// internal/execution's ActionPatchField case executes it end
// to end, and four real executions have succeeded live (STATUS.md /
// BACKLOG.md F27). The exclusion itself is still correct, just for a
// different reason: BACKLOG.md F11 is a deliberately parked decision to
// keep PatchField off the model's route, not a missing execution path.
//
// Reading the source is the only way to pin a doc-comment's own wording
// (nothing here is a runtime string) — the same technique
// internal/api/unattended_test.go's TestSweepChecksTimeWindowsBeforeBudget
// already uses to assert a structural property of a comment/ordering that
// has no other observable surface. This exists so the stale, false reason
// cannot silently come back the next time someone edits the comment nearby.
func TestPatchFieldExclusionReasonIsHonest(t *testing.T) {
	src, err := os.ReadFile("route.go")
	if err != nil {
		t.Fatalf("read route.go: %v", err)
	}
	body := string(src)

	if strings.Contains(body, "internal/api has no execution case for it") {
		t.Error("route.go still states the false BUGS.md 78 reason (\"internal/api has no execution case for it\") for excluding PatchField — that bug is fixed and removed; internal/execution's ActionPatchField case executes it live")
	}
	if !strings.Contains(body, "BACKLOG.md F11") {
		t.Error("route.go's PatchField-exclusion comment no longer cites BACKLOG.md F11 as the real, current reason for the exclusion")
	}
	if !strings.Contains(body, "deliberately parked decision") {
		t.Error("route.go's PatchField-exclusion comment no longer frames F11 as a deliberately parked decision rather than a missing capability")
	}
}
