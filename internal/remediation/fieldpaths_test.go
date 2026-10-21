package remediation

import (
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// TestEveryActionTypeDeclaresItsFieldPaths is the lint failure BACKLOG F11 asked
// for in place of a silent gap.
//
// Before fieldpaths.go this mapping was a switch in internal/api, and an action
// type with no case returned nil — which made the field-contention check return ""
// and silently gave the new action NO warning that a GitOps controller owned the
// field it was about to write. Nothing errored. This test is what makes that a
// build-time problem.
func TestEveryActionTypeDeclaresItsFieldPaths(t *testing.T) {
	declared := ActionTypesWithDeclaredFieldPaths()
	for _, action := range AllActionTypes() {
		if !slices.Contains(declared, action) {
			t.Errorf("action type %q is in validActionTypes but declares no field paths — add it to actionFieldPaths in fieldpaths.go, marking writesNoClusterFields if it genuinely patches no live object. Without an entry its field-contention warning is silently skipped.", action)
		}
	}
	// And the other direction: a declared entry for an action type that no longer
	// exists is dead weight that reads as coverage.
	for _, action := range declared {
		if !action.Valid() {
			t.Errorf("actionFieldPaths declares %q, which is not a valid action type", action)
		}
	}
}

// TestPlannedFieldPathsRefusesRatherThanReturningNothing: the distinction between
// "writes no fields" and "nobody declared this" has to survive at the call site,
// because they were the same value before and only one of them is safe.
func TestPlannedFieldPathsRefusesRatherThanReturningNothing(t *testing.T) {
	t.Run("an undeclared action type is an error, not an empty allowlist", func(t *testing.T) {
		_, err := PlannedFieldPaths(RemediationPlan{ActionType: ActionType("SomethingNew")})
		if err == nil {
			t.Fatal("want an error — an empty allowlist reads as 'writes nothing', which silently skips the contention check")
		}
	})

	t.Run("OpenPR writes no cluster fields, with no error", func(t *testing.T) {
		paths, err := PlannedFieldPaths(RemediationPlan{ActionType: ActionOpenPR})
		if err != nil {
			t.Fatalf("unexpected error: %v — OpenPR genuinely writes no live object", err)
		}
		if len(paths) != 0 {
			t.Errorf("paths = %v, want none", paths)
		}
	})

	t.Run("params of the wrong type is an error", func(t *testing.T) {
		// Validate already rejects this, so reaching it means Validate was bypassed
		// — which must not silently produce an empty allowlist.
		_, err := PlannedFieldPaths(RemediationPlan{
			ActionType: ActionPatchResourceLimits,
			Params:     ScaleDeploymentParams{Replicas: 3},
		})
		if err == nil {
			t.Fatal("want an error for mismatched params")
		}
	})

	t.Run("nil params is an error for an action that derives paths from them", func(t *testing.T) {
		if _, err := PlannedFieldPaths(RemediationPlan{ActionType: ActionScaleDeployment}); err == nil {
			t.Fatal("want an error for nil params")
		}
	})
}

// TestPatchResourceLimitsClaimsOnlyTheFieldsItSets. A plan that changes the memory
// limit must not claim to be writing CPU: the contention warning names the field
// the approver is about to change, so over-claiming produces a warning wider than
// the truth, and under-claiming misses a real conflict.
func TestPatchResourceLimitsClaimsOnlyTheFieldsItSets(t *testing.T) {
	cases := []struct {
		name   string
		params PatchResourceLimitsParams
		want   []string
	}{
		{
			name:   "memory limit only",
			params: PatchResourceLimitsParams{Container: "web", MemoryLimit: "512Mi"},
			want:   []string{"spec.template.spec.containers[web].resources.limits.memory"},
		},
		{
			name:   "both memory fields",
			params: PatchResourceLimitsParams{Container: "web", MemoryLimit: "512Mi", MemoryRequest: "256Mi"},
			want: []string{
				"spec.template.spec.containers[web].resources.limits.memory",
				"spec.template.spec.containers[web].resources.requests.memory",
			},
		},
		{
			name:   "cpu only does not claim memory",
			params: PatchResourceLimitsParams{Container: "sidecar", CPULimit: "500m"},
			want:   []string{"spec.template.spec.containers[sidecar].resources.limits.cpu"},
		},
		{
			name: "all four",
			params: PatchResourceLimitsParams{
				Container: "api", MemoryLimit: "1Gi", MemoryRequest: "512Mi", CPULimit: "1", CPURequest: "500m",
			},
			want: []string{
				"spec.template.spec.containers[api].resources.limits.memory",
				"spec.template.spec.containers[api].resources.requests.memory",
				"spec.template.spec.containers[api].resources.limits.cpu",
				"spec.template.spec.containers[api].resources.requests.cpu",
			},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := PlannedFieldPaths(RemediationPlan{ActionType: ActionPatchResourceLimits, Params: c.params})
			if err != nil {
				t.Fatalf("PlannedFieldPaths: %v", err)
			}
			if !slices.Equal(got, c.want) {
				t.Errorf("got %v, want %v", got, c.want)
			}
		})
	}
}

// TestFieldPathsMatchTheLLD keeps lld/08-remediation-contracts.md §3 load-bearing
// rather than decorative.
//
// The LLD documents the allowlist as JSONPointer, because that is what the
// admission policy's CEL consumes; this package uses dot paths, because that is
// what objdiff.OwnersOf walks managedFields with. Two notations for one fact is
// exactly the shape that drifts, so the conversion is done here and compared.
//
// Only the two operations whose vocabulary maps cleanly are checked —
// `scaleWorkload` and `restartWorkload` name a specific field path in the LLD.
// The others are documented as "whatever the target action's pack allows", which
// is a pointer rather than a path and has nothing to compare against.
func TestFieldPathsMatchTheLLD(t *testing.T) {
	doc, err := os.ReadFile("../../lld/08-remediation-contracts.md")
	if err != nil {
		t.Skipf("LLD not readable (%v) — skipping rather than failing", err)
	}

	cases := []struct {
		lldOperation string
		action       ActionType
		params       ActionParams
	}{
		{"scaleWorkload", ActionScaleDeployment, ScaleDeploymentParams{Replicas: 3}},
		{"restartWorkload", ActionRestartPod, RestartPodParams{}},
	}

	for _, c := range cases {
		t.Run(c.lldOperation, func(t *testing.T) {
			documented := lldAllowedPaths(string(doc), c.lldOperation)
			if len(documented) == 0 {
				t.Fatalf("found no documented field path for %s in lld/08 §3 — this test cannot protect anything if it cannot find the row", c.lldOperation)
			}
			got, err := PlannedFieldPaths(RemediationPlan{ActionType: c.action, Params: c.params})
			if err != nil {
				t.Fatalf("PlannedFieldPaths: %v", err)
			}
			for _, want := range documented {
				if !slices.Contains(got, want) {
					t.Errorf("lld/08 §3 documents %s as writing %q, but this package plans %v — one of the two is wrong and they must not diverge silently",
						c.lldOperation, want, got)
				}
			}
		})
	}
}

// lldAllowedPaths pulls the backtick-quoted JSONPointer paths out of the row for
// one operation in lld/08 §3's table, converted to this package's dot notation.
func lldAllowedPaths(doc, operation string) []string {
	row := regexp.MustCompile(`(?m)^\|\s*` + "`" + regexp.QuoteMeta(operation) + "`" + `\s*\|.*$`).FindString(doc)
	if row == "" {
		return nil
	}
	// The last cell of the table is the allowed-field-paths column.
	cells := strings.Split(row, "|")
	if len(cells) < 2 {
		return nil
	}
	last := cells[len(cells)-2]

	var out []string
	for _, quoted := range regexp.MustCompile("`([^`]+)`").FindAllStringSubmatch(last, -1) {
		p := quoted[1]
		if !strings.HasPrefix(p, "/") {
			continue
		}
		// /spec/template/metadata/annotations/argus.io~1restartedAt and
		// /spec/template/metadata/annotations/* both describe writing INTO the
		// annotations map, which this package names by the map itself — the honest
		// claim, since ARGUS adds a key rather than owning every annotation.
		p = strings.TrimSuffix(p, "/*")
		if idx := strings.Index(p, "~1"); idx >= 0 {
			p = p[:strings.LastIndex(p[:idx], "/")]
		}
		out = append(out, strings.ReplaceAll(strings.TrimPrefix(p, "/"), "/", "."))
	}
	return out
}
