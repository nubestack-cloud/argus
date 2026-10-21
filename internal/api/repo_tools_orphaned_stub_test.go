package api

// Tests for BUGS.md 117's enforcement point:
// RefuseOrphanedRecreatedResourceProposals. Reuses newTestReader/openPRPlan
// from repo_tools_test.go (F25's own test file) — the same real
// repotools.Reader/fake-checkout harness, since this guard also drives real
// gitops.ReadCheckoutFile calls against a real (fake-cloned) checkout rather
// than a hand-built stand-in.

import (
	"context"
	"testing"

	"argus/internal/llm"
	"argus/internal/remediation"
)

// TestRefuseOrphanedRecreatedResourceProposals_ContradictoryPlanRefused is
// GC-007's exact shape: the plan recreates a deleted ConfigMap as an empty
// placeholder WHILE removing, in the same plan, the only envFrom reference
// to it from the sibling Deployment manifest — directly contradicting a plan
// whose point was supposedly restoring the missing ConfigMap. Must be
// refused outright (nil), not merely flagged.
func TestRefuseOrphanedRecreatedResourceProposals_ContradictoryPlanRefused(t *testing.T) {
	r, _ := newTestReader(t, map[string]string{
		// configmap.yaml deliberately absent -- it was pruned from Git,
		// which is the whole reason the plan proposes to recreate it.
		"charts/web/deployment.yaml": "apiVersion: apps/v1\n" +
			"kind: Deployment\n" +
			"metadata:\n  name: app\n" +
			"spec:\n" +
			"  template:\n" +
			"    spec:\n" +
			"      containers:\n" +
			"        - name: app\n" +
			"          envFrom:\n" +
			"            - configMapRef:\n" +
			"                name: shared-config\n",
	})

	plan := openPRPlan(
		remediation.ProposedFile{
			Path: "charts/web/configmap.yaml",
			Content: "apiVersion: v1\n" +
				"kind: ConfigMap\n" +
				"metadata:\n  name: shared-config\n" +
				"data: {}\n" +
				"# key: value\n",
		},
		remediation.ProposedFile{
			Path: "charts/web/deployment.yaml",
			Content: "apiVersion: apps/v1\n" +
				"kind: Deployment\n" +
				"metadata:\n  name: app\n" +
				"spec:\n" +
				"  template:\n" +
				"    spec:\n" +
				"      containers:\n" +
				"        - name: app\n",
		},
	)
	result := llm.Investigation{Status: "complete", ProposedPlan: plan}

	got := RefuseOrphanedRecreatedResourceProposals(context.Background(), result, r, testRepoScope().SourceDir)
	if got.ProposedPlan != nil {
		t.Fatal("a plan recreating a resource as a stub while removing its only other reference in the same plan must be refused outright")
	}
}

// TestRefuseOrphanedRecreatedResourceProposals_OrdinaryMultiFilePlanUnaffected
// is the negative case the task asks for: an ordinary, non-contradictory
// multi-file plan (a values-file scalar bump and its consuming template,
// neither creating nor removing anything) must sail through unchanged.
func TestRefuseOrphanedRecreatedResourceProposals_OrdinaryMultiFilePlanUnaffected(t *testing.T) {
	r, _ := newTestReader(t, map[string]string{
		"charts/web/values.yaml":               "resources:\n  limits:\n    memory: 64Mi\n",
		"charts/web/templates/deployment.yaml": "memory: {{ .Values.resources.limits.memory }}\n",
	})

	plan := openPRPlan(
		remediation.ProposedFile{Path: "charts/web/values.yaml", Content: "resources:\n  limits:\n    memory: 128Mi\n"},
	)
	result := llm.Investigation{Status: "complete", ProposedPlan: plan}

	got := RefuseOrphanedRecreatedResourceProposals(context.Background(), result, r, testRepoScope().SourceDir)
	if got.ProposedPlan == nil {
		t.Fatal("an ordinary, non-contradictory plan must not be refused")
	}
}

// TestRefuseOrphanedRecreatedResourceProposals_ReferenceKeptElsewhereUnaffected
// is the "recreated but still used" case: the plan recreates the same stub
// ConfigMap, but the sibling file's PROPOSED content still references it (an
// entirely reasonable "restore the missing manifest, keep using it" plan).
// The recreation is not orphaned, so this must not be refused.
func TestRefuseOrphanedRecreatedResourceProposals_ReferenceKeptElsewhereUnaffected(t *testing.T) {
	r, _ := newTestReader(t, map[string]string{
		"charts/web/deployment.yaml": "envFrom:\n  - configMapRef:\n      name: shared-config\n",
	})

	plan := openPRPlan(
		remediation.ProposedFile{
			Path: "charts/web/configmap.yaml",
			Content: "apiVersion: v1\n" +
				"kind: ConfigMap\n" +
				"metadata:\n  name: shared-config\n" +
				"data: {}\n",
		},
		remediation.ProposedFile{
			Path:    "charts/web/deployment.yaml",
			Content: "envFrom:\n  - configMapRef:\n      name: shared-config\n",
		},
	)
	result := llm.Investigation{Status: "complete", ProposedPlan: plan}

	got := RefuseOrphanedRecreatedResourceProposals(context.Background(), result, r, testRepoScope().SourceDir)
	if got.ProposedPlan == nil {
		t.Fatal("recreating a resource that this same plan's sibling file still references must not be refused")
	}
}

// TestRefuseOrphanedRecreatedResourceProposals_RealContentRecreationUnaffected
// is the "not actually a stub" case: the recreated file has real, non-empty
// data — the model may have genuinely reconstructed the content from other
// evidence rather than guessing a placeholder. This check only names the
// specific placeholder-stub shape, so a real recreation must not be refused
// even though the reference was also removed elsewhere.
func TestRefuseOrphanedRecreatedResourceProposals_RealContentRecreationUnaffected(t *testing.T) {
	r, _ := newTestReader(t, map[string]string{
		"charts/web/deployment.yaml": "envFrom:\n  - configMapRef:\n      name: shared-config\n",
	})

	plan := openPRPlan(
		remediation.ProposedFile{
			Path: "charts/web/configmap.yaml",
			Content: "apiVersion: v1\n" +
				"kind: ConfigMap\n" +
				"metadata:\n  name: shared-config\n" +
				"data:\n  FEATURE_FLAG: \"true\"\n",
		},
		remediation.ProposedFile{Path: "charts/web/deployment.yaml", Content: "spec: {}\n"},
	)
	result := llm.Investigation{Status: "complete", ProposedPlan: plan}

	got := RefuseOrphanedRecreatedResourceProposals(context.Background(), result, r, testRepoScope().SourceDir)
	if got.ProposedPlan == nil {
		t.Fatal("a recreation with real, non-empty content is not the placeholder-stub shape this check names, and must not be refused")
	}
}

// TestRefuseOrphanedRecreatedResourceProposals_IgnoresNonOpenPRAndNilCases
// mirrors F25's own guard's scope test: a nil plan, a nil reader, and a
// non-OpenPR plan must all pass through untouched rather than panicking or
// refusing something outside this check's business.
func TestRefuseOrphanedRecreatedResourceProposals_IgnoresNonOpenPRAndNilCases(t *testing.T) {
	r, _ := newTestReader(t, map[string]string{"charts/web/deployment.yaml": "kind: Deployment\n"})

	t.Run("nil plans and nil reader", func(t *testing.T) {
		got := RefuseOrphanedRecreatedResourceProposals(context.Background(), llm.Investigation{}, nil, "charts/web")
		if got.ProposedPlan != nil || got.ProposedPairedPlan != nil {
			t.Error("nil plans must stay nil")
		}
	})
	t.Run("non-OpenPR plan is untouched", func(t *testing.T) {
		scaleDeploy := &remediation.RemediationPlan{ActionType: remediation.ActionScaleDeployment, Params: remediation.ScaleDeploymentParams{Replicas: 2}}
		got := RefuseOrphanedRecreatedResourceProposals(context.Background(), llm.Investigation{ProposedPlan: scaleDeploy}, r, "charts/web")
		if got.ProposedPlan != scaleDeploy {
			t.Error("a non-OpenPR plan must be returned unchanged")
		}
	})
	t.Run("nil reader is a no-op", func(t *testing.T) {
		plan := openPRPlan(remediation.ProposedFile{Path: "charts/web/configmap.yaml", Content: "kind: ConfigMap\nmetadata:\n  name: x\ndata: {}\n"})
		got := RefuseOrphanedRecreatedResourceProposals(context.Background(), llm.Investigation{ProposedPlan: plan}, nil, "charts/web")
		if got.ProposedPlan != plan {
			t.Error("a nil repoReader must be a complete no-op")
		}
	})
}
