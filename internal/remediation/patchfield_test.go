package remediation

import (
	"strings"
	"testing"
)

// TestPatchFieldPermitted distinguishes three outcomes, and the middle one is why
// this test was restructured: a path can be **reviewed and permitted** and still
// not be executable, because the shipped agent chart does not grant the
// cluster-side permission. Calling that "not permitted" would hide that the design
// work is done and only a chart line is missing; calling it "permitted" is what
// would let a human approve a change the API server then refuses with a 403.
//
// BACKLOG.md "still open" #9 (2026-08-29) closed that chart gap for every kind
// this table names — deploy/helm/argus-agent/templates/clusterrole.yaml's
// remediate.enabled section now grants `patch` on all five — so every row below
// is `executable` now; the `needsGrant` outcome (and its assertions) stays in
// this test for the next row that adds a kind the chart hasn't caught up with.
func TestPatchFieldPermitted(t *testing.T) {
	const (
		executable   = "executable"  // reviewed, and the shipped chart grants it
		needsGrant   = "needs-grant" // reviewed; chart does not grant it yet
		notPermitted = "not-permitted"
	)
	for _, tc := range []struct {
		name     string
		gvk      string
		path     string
		outcome  string
		wantRisk RiskLevel
	}{
		// --- reviewed and permitted; the shipped chart now grants patch on all of
		//     these kinds too (BACKLOG.md "still open" #9, 2026-08-29)
		{"service targetPort, bracket form", "v1/Service", "spec.ports[0].targetPort", executable, RiskMedium},
		{"service targetPort, dotted form", "v1/Service", "spec.ports.0.targetPort", executable, RiskMedium},
		{"service selector key", "v1/Service", "spec.selector.app", executable, RiskMedium},
		{"ingress backend service name", "networking.k8s.io/v1/Ingress",
			"spec.rules[0].http.paths[0].backend.service.name", executable, RiskMedium},
		{"hpa ceiling", "autoscaling/v2/HorizontalPodAutoscaler", "spec.maxReplicas", executable, RiskMedium},
		{"deployment memory REQUEST", "apps/v1/Deployment",
			"spec.template.spec.containers[app].resources.requests.memory", executable, RiskMedium},
		{"progress deadline is low risk", "apps/v1/Deployment", "spec.progressDeadlineSeconds", executable, RiskLow},
		// A PDB relaxation blocks or unblocks node drains, so its floor is high
		// even though it is one integer.
		{"pdb minAvailable is high risk", "policy/v1/PodDisruptionBudget", "spec.minAvailable", executable, RiskHigh},

		// --- refused because a dedicated action owns the field AND carries a
		//     guardrail that routing through here would bypass
		{"replicas belongs to ScaleDeployment", "apps/v1/Deployment", "spec.replicas", notPermitted, ""},
		{"image belongs to RevertContainerImage", "apps/v1/Deployment",
			"spec.template.spec.containers[app].image", notPermitted, ""},
		{"limits belong to PatchResourceLimits", "apps/v1/Deployment",
			"spec.template.spec.containers[app].resources.limits.memory", notPermitted, ""},

		// --- refused because the value expresses intent, not correctness
		{"cronjob suspend is intent", "batch/v1/CronJob", "spec.suspend", notPermitted, ""},
		{"deployment paused is intent", "apps/v1/Deployment", "spec.paused", notPermitted, ""},

		// --- refused because permission is per-KIND: the same path being safe on
		//     one kind says nothing about another
		{"deployment request path on a StatefulSet", "apps/v1/StatefulSet",
			"spec.template.spec.containers[app].resources.requests.memory", notPermitted, ""},
		{"service path on an unknown kind", "v1/ConfigMap", "spec.ports[0].targetPort", notPermitted, ""},

		// --- refused: anything not written down
		{"arbitrary field", "apps/v1/Deployment", "spec.template.spec.serviceAccountName", notPermitted, ""},
		{"empty path", "v1/Service", "", notPermitted, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			entry, err := PatchFieldPermitted(tc.gvk, tc.path)
			switch tc.outcome {
			case executable:
				if err != nil {
					t.Fatalf("a path the chart grants was refused: %v", err)
				}
				if entry.Risk != tc.wantRisk {
					t.Errorf("risk = %q, want %q", entry.Risk, tc.wantRisk)
				}
			case needsGrant:
				if err == nil {
					t.Fatalf("%q on %s was allowed through, but the agent has no RBAC to write it — a human would approve and then see a 403", tc.path, tc.gvk)
				}
				// The refusal has to name the missing permission and where to fix
				// it, or it reads as "ARGUS refuses this" rather than "your agent
				// needs one more grant".
				if !strings.Contains(err.Error(), "Missing grant") {
					t.Errorf("refusal does not name the missing grant: %v", err)
				}
				if !strings.Contains(err.Error(), "deploy/helm/argus-agent") {
					t.Errorf("refusal does not say where to fix it: %v", err)
				}
			default:
				if err == nil {
					t.Fatalf("%q on %s was PERMITTED and must not be", tc.path, tc.gvk)
				}
				if strings.Contains(err.Error(), "Missing grant") {
					t.Errorf("an unlisted path was reported as an RBAC problem, which wrongly implies a chart change would enable it: %v", err)
				}
			}
		})
	}
}

// TestFieldPathWildcardIsSingleSegment is the test that keeps the allowlist an
// allowlist. If "*" ever matched more than one segment, `spec.selector.*` would
// authorise arbitrary depth beneath it and the cluster-side admission policy
// would be enumerating a set the hub no longer bounds.
func TestFieldPathWildcardIsSingleSegment(t *testing.T) {
	for _, tc := range []struct {
		pattern, path string
		match         bool
	}{
		{"spec.selector.*", "spec.selector.app", true},
		{"spec.selector.*", "spec.selector.app.nested", false},
		{"spec.selector.*", "spec.selector", false},
		{"spec.ports.*.targetPort", "spec.ports.0.targetPort", true},
		{"spec.ports.*.targetPort", "spec.ports.0.1.targetPort", false},
		{"spec.ports.*.targetPort", "spec.ports.targetPort", false},
		// A traversal token must never satisfy a wildcard.
		{"spec.selector.*", "spec.selector...", false},
	} {
		if got := fieldPathMatches(tc.pattern, normaliseFieldPath(tc.path)); got != tc.match {
			t.Errorf("fieldPathMatches(%q, %q) = %v, want %v", tc.pattern, tc.path, got, tc.match)
		}
	}
}

// TestPatchFieldAllowlistIsReviewable asserts the properties that make the table
// trustworthy rather than merely present: nothing undocumented, no
// multi-segment wildcard, and no entry that silently duplicates a dedicated
// action's field.
func TestPatchFieldAllowlistIsReviewable(t *testing.T) {
	seen := map[string]bool{}
	for _, e := range PatchFieldAllowlistEntries() {
		key := e.GVK + " " + e.Path
		if seen[key] {
			t.Errorf("%s is listed twice — two rows for one permission means two places to revoke it", key)
		}
		seen[key] = true

		if strings.TrimSpace(e.Why) == "" {
			t.Errorf("%s has no justification; an entry nobody could explain is an entry nobody reviewed", key)
		}
		if len(e.Why) < 40 {
			t.Errorf("%s's justification is too short to be one: %q", key, e.Why)
		}
		if strings.Contains(e.Path, "**") {
			t.Errorf("%s uses a multi-segment wildcard, which turns the allowlist into a wildcard", key)
		}
		if e.GVK == "" || !strings.Contains(e.GVK, "/") {
			t.Errorf("%s has no fully-qualified GVK; a bare kind would match across API groups", key)
		}
		if e.Risk != RiskLow && e.Risk != RiskMedium && e.Risk != RiskHigh {
			t.Errorf("%s has risk %q, which is not a level", key, e.Risk)
		}
		// An untyped entry would leave the agent inferring the type, which is
		// exactly the guess this field exists to remove.
		if e.Type != FieldString && e.Type != FieldInt && e.Type != FieldIntOrString {
			t.Errorf("%s declares no field type (%q); the agent would have to guess it", key, e.Type)
		}
		// The three exclusions are load-bearing; assert no row reintroduces them.
		for _, banned := range []string{".image", ".resources.limits.", "spec.replicas", "spec.suspend", "spec.paused"} {
			if strings.Contains(e.Path, banned) {
				t.Errorf("%s reintroduces %q, which a dedicated action owns or which expresses intent — see patchfield.go's exclusion reasoning", key, banned)
			}
		}
	}
	if PatchFieldAllowlistSize() == 0 {
		t.Fatal("the allowlist is empty")
	}
}

// PatchField must never auto-approve: every field in the table sets a value that
// cannot be derived from the API, which is why those faults were unreachable in
// the first place.
func TestPatchFieldIsApprovalOnly(t *testing.T) {
	if !NeverAutoApprove(ActionPatchField) {
		t.Error("PatchField can auto-approve; every path in its allowlist carries a human judgement in the value")
	}
}
