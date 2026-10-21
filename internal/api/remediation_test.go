package api

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestPlanSummary covers planSummary's plain-language rendering for each of
// internal/remediation's ActionTypes — the DB-free unit test for the
// exact function ApprovalsPage.tsx depends on to avoid ever having to
// interpret raw params JSON itself (this task's brief: "Scale
// payments/checkout-worker from 2 to 4 replicas" rather than dumping
// ScaleDeploymentParams{Replicas:4}").
func TestPlanSummary(t *testing.T) {
	cases := []struct {
		name       string
		actionType string
		namespace  string
		target     string
		params     string
		want       []string // substrings that must all appear
	}{
		{
			"ScaleDeployment with namespace",
			"ScaleDeployment", "payments", "checkout-worker", `{"replicas":4}`,
			[]string{"payments/checkout-worker", "4 replicas"},
		},
		{
			"RestartPod",
			"RestartPod", "payments", "checkout-worker-abc123", `{}`,
			[]string{"Restart", "payments/checkout-worker-abc123"},
		},
		{
			// One file: the summary names it. It deliberately does NOT try to
			// characterise what changed inside it — the approver is shown the
			// diff, and a one-line paraphrase of a patch is exactly the kind of
			// confident summary that lets someone approve without reading it.
			"OpenPR, one file",
			"OpenPR", "payments", "checkout-worker",
			`{"repository":"org/repo","files":[{"path":"apps/checkout/deployment.yaml","content":"image: registry.example.com/checkout:1.2.3\n"}]}`,
			[]string{"pull request", "apps/checkout/deployment.yaml", "payments/checkout-worker"},
		},
		{
			"OpenPR, several files",
			"OpenPR", "payments", "checkout-worker",
			`{"repository":"org/repo","files":[{"path":"charts/checkout/values.yaml","content":"tag: 1.2.3\n"},{"path":"charts/checkout/templates/deployment.yaml","content":"image: x\n"}]}`,
			[]string{"2 files", "charts/checkout/values.yaml", "charts/checkout/templates/deployment.yaml"},
		},
		{
			// A row written before 2026-08-28. It is still DISPLAYED — the
			// record of what was proposed must survive — but the summary says
			// plainly that this build cannot act on it, which is what
			// orchestrator.UnmarshalPlanParams enforces if anyone tries.
			"OpenPR, a stored plan in the retired single-field shape",
			"OpenPR", "payments", "checkout-worker",
			`{"repository":"org/repo","filePath":"apps/checkout/deployment.yaml","fieldPath":"/spec/template/spec/containers/0/image","newValue":"registry.example.com/checkout:1.2.3"}`,
			[]string{"pull request", "retired", "re-analyse"},
		},
		{
			"no namespace falls back to bare target name",
			"RestartPod", "", "checkout-worker-abc123", `{}`,
			[]string{"checkout-worker-abc123"},
		},
		{
			// BACKLOG.md D11 #5: before this case existed, DeleteResource fell
			// through to the generic `default: "%s %s"` branch and rendered the
			// raw action-type identifier ("DeleteResource payments/orphaned-pod")
			// as the plain-language summary — a real bug, not a hypothetical one.
			"DeleteResource says what a human would, never the raw identifier",
			"DeleteResource", "kube-system", "orphaned-completed-pod", `{}`,
			[]string{"Delete", "kube-system/orphaned-completed-pod"},
		},
		{
			// The numbers themselves must be in the summary: "adjust
			// resources" is not something a human can responsibly approve,
			// and neither is a summary that hides the rollout.
			"PatchResourceLimits names the container, the values and the rollout",
			"PatchResourceLimits", "payments", "checkout-api",
			`{"container":"api","memoryLimit":"256Mi","memoryRequest":"64Mi"}`,
			[]string{"api", "payments/checkout-api", "memory limit to 256Mi", "memory request to 64Mi", "rolls the workload"},
		},
		{
			// The summary must name the RULE (previous revision) and both
			// consequences, and must NOT invent an image: the image is not known
			// until approval time, by design.
			"RevertContainerImage names the container and the rule, never an image",
			"RevertContainerImage", "payments", "checkout-api",
			`{"container":"api"}`,
			[]string{"api", "payments/checkout-api", "previous revision", "rolls the workload"},
		},
		{
			"RevertContainerImage with unreadable params still says something true",
			"RevertContainerImage", "payments", "checkout-api", `{}`,
			[]string{"previous revision", "payments/checkout-api"},
		},
		{
			"PatchResourceLimits with unreadable params still says something true",
			"PatchResourceLimits", "payments", "checkout-api", `{}`,
			[]string{"resource limits", "payments/checkout-api"},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := planSummary(c.actionType, c.namespace, c.target, json.RawMessage(c.params))
			for _, want := range c.want {
				if !strings.Contains(got, want) {
					t.Errorf("planSummary(...) = %q, want it to contain %q", got, want)
				}
			}
			if strings.Contains(got, "{") {
				t.Errorf("planSummary(...) = %q, should never contain raw JSON", got)
			}
		})
	}
}

// TestPlanSummary_DeleteResourceNeverRawIdentifier is the regression test for
// the bug the DeleteResource case above fixes: before it existed,
// planSummary's `default` branch rendered the raw action-type string
// verbatim, which is exactly the "never show a raw API identifier" rule
// components.md states by name (its own worked examples are "ScaleDeployment"
// and "NeedsApproval").
func TestPlanSummary_DeleteResourceNeverRawIdentifier(t *testing.T) {
	got := planSummary("DeleteResource", "kube-system", "orphaned-completed-pod", json.RawMessage(`{}`))
	if strings.Contains(got, "DeleteResource") {
		t.Errorf("planSummary(DeleteResource, ...) = %q, must not contain the raw action-type identifier", got)
	}
}

// TestBuildPlanView_EffectiveRiskLevel is BACKLOG.md D11 #1's backend half:
// buildPlanView must expose the gate-ENFORCED risk level alongside the
// model's declared one, computed via the exact same
// internal/remediation.EffectiveRiskLevel the gate itself calls (gate.go),
// never a second opinion.
func TestBuildPlanView_EffectiveRiskLevel(t *testing.T) {
	t.Run("declared risk under the deterministic floor is raised", func(t *testing.T) {
		// DeleteResource floors at high (risk.go's baseRiskFloors) — a model
		// that declared "low" must not have that echoed back as the effective
		// value, which is precisely BACKLOG D11 #1's defect: the badge showed
		// "low risk" while the gate text said "risk=high and reversible=false".
		view := buildPlanView("plan_1", "DeleteResource", "v1/Pod", "kube-system", "orphaned-pod",
			json.RawMessage(`{}`), false, "low", "NeedsApproval",
			`blocked from auto-approval by a hard safety floor: risk=high and reversible=false`, "2026-09-05T00:00:00Z")
		if view.RiskLevel != "low" {
			t.Errorf("RiskLevel = %q, want the model's own declared value %q untouched", view.RiskLevel, "low")
		}
		if view.EffectiveRiskLevel != "high" {
			t.Errorf("EffectiveRiskLevel = %q, want the deterministic floor %q", view.EffectiveRiskLevel, "high")
		}
	})

	t.Run("declared risk at or above the floor is left alone", func(t *testing.T) {
		view := buildPlanView("plan_2", "ScaleDeployment", "apps/v1/Deployment", "payments", "checkout-worker",
			json.RawMessage(`{"replicas":4}`), true, "low", "AutoApprove", "risk within ceiling", "2026-09-05T00:00:00Z")
		if view.EffectiveRiskLevel != "low" {
			t.Errorf("EffectiveRiskLevel = %q, want %q (ScaleDeployment's own floor, matching the declared value)", view.EffectiveRiskLevel, "low")
		}
	})

	t.Run("a plan whose params cannot be reconstructed falls back to the declared level rather than crashing", func(t *testing.T) {
		view := buildPlanView("plan_3", "ScaleDeployment", "apps/v1/Deployment", "payments", "checkout-worker",
			json.RawMessage(`not json`), true, "medium", "NeedsApproval", "reason", "2026-09-05T00:00:00Z")
		if view.EffectiveRiskLevel != "medium" {
			t.Errorf("EffectiveRiskLevel = %q, want the declared value %q as a safe fallback", view.EffectiveRiskLevel, "medium")
		}
	})
}
