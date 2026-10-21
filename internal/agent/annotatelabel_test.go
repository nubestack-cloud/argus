package agent

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"argus/internal/remediation"
)

func annotatePlanContent(rv, value string) remediation.PlanContent {
	return remediation.PlanContent{
		RecommendationID: "plan_1",
		ActionType:       remediation.ActionAnnotateResource,
		TargetGVK:        "apps/v1/Deployment",
		TargetNamespace:  "default",
		TargetName:       "web",
		Params:           mustMarshal(remediation.AnnotateResourceParams{Key: "argus.io/incident-id", Value: value}),
		ResourceVersion:  rv,
	}
}

func labelPlanContent(rv, value string) remediation.PlanContent {
	return remediation.PlanContent{
		RecommendationID: "plan_1",
		ActionType:       remediation.ActionLabelResource,
		TargetGVK:        "apps/v1/Deployment",
		TargetNamespace:  "default",
		TargetName:       "web",
		Params:           mustMarshal(remediation.LabelResourceParams{Key: "argus.io/remediated", Value: value}),
		ResourceVersion:  rv,
	}
}

func TestAnnotateResource_ValidSignedPlanSetsTheAnnotation(t *testing.T) {
	executor := newRemediationTestExecutor("clu_1", testDeployment("web", "default", 1, "100"))
	signed := signTestPlan(t, annotatePlanContent("100", "inc_01test"), "clu_1", time.Now().Add(time.Minute))
	args, _ := json.Marshal(map[string]any{"plan": signed})

	if _, _, err := executor.annotateResource(context.Background(), args); err != nil {
		t.Fatalf("annotateResource: %v", err)
	}

	live, err := executor.dynamic.Resource(deploymentsGVR).Namespace("default").Get(context.Background(), "web", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("re-read: %v", err)
	}
	annotations, _, _ := unstructuredNestedMap(live.Object, "metadata", "annotations")
	if got, _ := annotations["argus.io/incident-id"].(string); got != "inc_01test" {
		t.Errorf("annotation value = %q, want %q", got, "inc_01test")
	}
}

func TestLabelResource_ValidSignedPlanSetsTheLabel(t *testing.T) {
	executor := newRemediationTestExecutor("clu_1", testDeployment("web", "default", 1, "100"))
	signed := signTestPlan(t, labelPlanContent("100", "true"), "clu_1", time.Now().Add(time.Minute))
	args, _ := json.Marshal(map[string]any{"plan": signed})

	if _, _, err := executor.labelResource(context.Background(), args); err != nil {
		t.Fatalf("labelResource: %v", err)
	}

	live, err := executor.dynamic.Resource(deploymentsGVR).Namespace("default").Get(context.Background(), "web", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("re-read: %v", err)
	}
	labels, _, _ := unstructuredNestedMap(live.Object, "metadata", "labels")
	if got, _ := labels["argus.io/remediated"].(string); got != "true" {
		t.Errorf("label value = %q, want %q", got, "true")
	}
}

// TestAnnotateResource_RejectsValueOutsideTheAllowlist is the agent-side
// re-check: a value that would pass AnnotateResourceParams' own shape-only
// Validate (it is a non-empty, single-line, bounded string) but violates
// the (kind, key) -> allowed-value entry must still be refused here, not
// just at hub-side plan validation.
func TestAnnotateResource_RejectsValueOutsideTheAllowlist(t *testing.T) {
	executor := newRemediationTestExecutor("clu_1", testDeployment("web", "default", 1, "100"))
	signed := signTestPlan(t, annotatePlanContent("100", "not-a-timestamp-or-incident-id"), "clu_1", time.Now().Add(time.Minute))
	args, _ := json.Marshal(map[string]any{"plan": signed})

	if _, _, err := executor.annotateResource(context.Background(), args); err == nil {
		t.Fatal("annotateResource accepted a value outside the allowed pattern")
	}
}

func TestAnnotateResource_NoOpRefused(t *testing.T) {
	dep := testDeployment("web", "default", 1, "100")
	dep.Annotations = map[string]string{"argus.io/incident-id": "inc_01test"}
	executor := newRemediationTestExecutor("clu_1", dep)
	signed := signTestPlan(t, annotatePlanContent("100", "inc_01test"), "clu_1", time.Now().Add(time.Minute))
	args, _ := json.Marshal(map[string]any{"plan": signed})

	if _, _, err := executor.annotateResource(context.Background(), args); err == nil {
		t.Fatal("annotateResource executed a change that sets nothing new")
	}
}

func TestAnnotateResource_StaleResourceVersionFailsClosed(t *testing.T) {
	executor := newRemediationTestExecutor("clu_1", testDeployment("web", "default", 1, "100"))
	signed := signTestPlan(t, annotatePlanContent("999", "inc_01test"), "clu_1", time.Now().Add(time.Minute))
	args, _ := json.Marshal(map[string]any{"plan": signed})

	if _, _, err := executor.annotateResource(context.Background(), args); err == nil {
		t.Fatal("annotateResource proceeded against a stale resourceVersion")
	}
}

// TestAnnotateResource_RejectsRollbackForADifferentKey mirrors
// patch_field's own rollback-must-address-the-same-field guard.
func TestAnnotateResource_RejectsRollbackForADifferentKey(t *testing.T) {
	executor := newRemediationTestExecutor("clu_1", testDeployment("web", "default", 1, "100"))
	content := annotatePlanContent("100", "inc_01test")
	restoreParams, _ := json.Marshal(remediation.AnnotateResourceParams{Key: "argus.io/last-remediated-at", Value: "2026-08-29T00:00:00Z"})
	content.Rollback = &remediation.CompensatingAction{ActionType: remediation.ActionAnnotateResource, Params: restoreParams, Description: "restore a different key"}
	signed := signTestPlan(t, content, "clu_1", time.Now().Add(time.Minute))
	args, _ := json.Marshal(map[string]any{"plan": signed})

	if _, _, err := executor.annotateResource(context.Background(), args); err == nil {
		t.Fatal("annotateResource accepted a rollback that targets a different key")
	}
}

// TestAnnotateResource_AbsentRollbackIsAcceptable is this mechanism's
// deliberate divergence from patch_field/patch_resource_limits: a nil
// rollback is the expected state when the key is being newly added, and
// must NOT be refused the way those two refuse a missing rollback
// unconditionally.
func TestAnnotateResource_AbsentRollbackIsAcceptable(t *testing.T) {
	executor := newRemediationTestExecutor("clu_1", testDeployment("web", "default", 1, "100"))
	content := annotatePlanContent("100", "inc_01test")
	content.Rollback = nil
	signed := signTestPlan(t, content, "clu_1", time.Now().Add(time.Minute))
	args, _ := json.Marshal(map[string]any{"plan": signed})

	if _, _, err := executor.annotateResource(context.Background(), args); err != nil {
		t.Fatalf("annotateResource refused a plan with no rollback, which should be acceptable for a brand-new key: %v", err)
	}
}

func TestLabelResource_RejectsWrongActionTypeEnvelope(t *testing.T) {
	executor := newRemediationTestExecutor("clu_1", testDeployment("web", "default", 1, "100"))
	content := labelPlanContent("100", "true")
	content.ActionType = remediation.ActionAnnotateResource
	signed := signTestPlan(t, content, "clu_1", time.Now().Add(time.Minute))
	args, _ := json.Marshal(map[string]any{"plan": signed})

	if _, _, err := executor.labelResource(context.Background(), args); err == nil {
		t.Fatal("labelResource accepted an envelope signed for a different action type")
	}
}

func TestAnnotateResource_RejectsUnsupportedKind(t *testing.T) {
	executor := newRemediationTestExecutor("clu_1", testDeletablePod("web", "default", "100"))
	content := annotatePlanContent("100", "inc_01test")
	content.TargetGVK = "v1/Pod"
	signed := signTestPlan(t, content, "clu_1", time.Now().Add(time.Minute))
	args, _ := json.Marshal(map[string]any{"plan": signed})

	if _, _, err := executor.annotateResource(context.Background(), args); err == nil {
		t.Fatal("annotateResource permitted a Pod target, which annotateLabelPatchableResources must refuse")
	}
}
