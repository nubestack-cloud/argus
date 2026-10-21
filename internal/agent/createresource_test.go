package agent

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"

	dynamicfake "k8s.io/client-go/dynamic/fake"
	k8stesting "k8s.io/client-go/testing"

	"argus/internal/remediation"
)

var configMapsGVR = schema.GroupVersionResource{Group: "", Version: "v1", Resource: "configmaps"}

// installRealisticCreateReactor mirrors installRealisticDeleteReactor's own
// dry-run handling (deleteresource_test.go): the bare fake tracker's default
// Create (client-go's testing.tracker.Create) does not honour
// metav1.CreateOptions.DryRun at all — it always persists the object — so a
// test asserting "a dry run created nothing" needs this the same way
// TestDeleteResource_DryRunLeavesTheObjectInPlace needs its own delete
// reactor.
func installRealisticCreateReactor(dynFake *dynamicfake.FakeDynamicClient) {
	dynFake.PrependReactor("create", "*", func(action k8stesting.Action) (bool, runtime.Object, error) {
		createAction, ok := action.(k8stesting.CreateActionImpl)
		if !ok {
			return false, nil, nil
		}
		if !hasDryRunAll(createAction.GetCreateOptions().DryRun) {
			return false, nil, nil
		}
		obj := createAction.GetObject().DeepCopyObject()
		if u, ok := obj.(*unstructured.Unstructured); ok {
			u.SetResourceVersion("dryrun-1")
		}
		return true, obj, nil
	})
}

func hasDryRunAll(dryRun []string) bool {
	for _, d := range dryRun {
		if d == metav1.DryRunAll {
			return true
		}
	}
	return false
}

// newCreateTestExecutor is newRemediationTestExecutor plus
// installRealisticCreateReactor — a separate constructor for the same
// reason newDeleteTestExecutor is: no other mutating-tool test file needs a
// create reactor.
func newCreateTestExecutor(clusterID string, objs ...runtime.Object) *ToolExecutor {
	executor := newRemediationTestExecutor(clusterID, objs...)
	installRealisticCreateReactor(executor.dynamic.(*dynamicfake.FakeDynamicClient))
	return executor
}

func testExistingConfigMap(name, namespace, resourceVersion string) *corev1.ConfigMap {
	return &corev1.ConfigMap{
		TypeMeta:   metav1.TypeMeta{APIVersion: "v1", Kind: "ConfigMap"},
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace, ResourceVersion: resourceVersion, UID: "uid-1"},
		Data:       map[string]string{"EXISTING": "value"},
	}
}

func createResourcePlanContent(dryRun bool) remediation.PlanContent {
	return remediation.PlanContent{
		RecommendationID: "plan_1",
		ActionType:       remediation.ActionCreateResource,
		TargetGVK:        "v1/ConfigMap",
		TargetNamespace:  "default",
		TargetName:       "checkout-api-config",
		Params:           mustMarshal(remediation.CreateResourceParams{Data: map[string]string{"RETRY_LIMIT": "3"}}),
		// No ResourceVersion: CreateResource's target does not exist yet —
		// see verifySignedPlan's own comment for why this is the one action
		// type an empty precondition is legitimate for.
		DryRun: dryRun,
	}
}

func TestCreateResource_ValidSignedPlanCreatesTheObject(t *testing.T) {
	executor := newCreateTestExecutor("clu_1")
	signed := signTestPlan(t, createResourcePlanContent(false), "clu_1", time.Now().Add(time.Minute))
	args, _ := json.Marshal(map[string]any{"plan": signed})

	data, _, err := executor.createResource(context.Background(), args)
	if err != nil {
		t.Fatalf("createResource: %v", err)
	}
	var result createResourceResult
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("decode result: %v", err)
	}
	if result.DryRun {
		t.Error("result.DryRun = true for a real create")
	}

	obj, err := executor.dynamic.Resource(configMapsGVR).Namespace("default").Get(context.Background(), "checkout-api-config", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("the ConfigMap does not exist after a real create: %v", err)
	}
	data2, found, err := unstructured.NestedStringMap(obj.Object, "data")
	if err != nil || !found {
		t.Fatalf("created object has no readable data: found=%v err=%v", found, err)
	}
	if data2["RETRY_LIMIT"] != "3" {
		t.Errorf("created object's data[RETRY_LIMIT] = %q, want %q", data2["RETRY_LIMIT"], "3")
	}
}

func TestCreateResource_DryRunLeavesNothingCreated(t *testing.T) {
	executor := newCreateTestExecutor("clu_1")
	signed := signTestPlan(t, createResourcePlanContent(true), "clu_1", time.Now().Add(time.Minute))
	args, _ := json.Marshal(map[string]any{"plan": signed})

	data, _, err := executor.createResource(context.Background(), args)
	if err != nil {
		t.Fatalf("createResource (dry run): %v", err)
	}
	var result createResourceResult
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("decode result: %v", err)
	}
	if !result.DryRun {
		t.Error("result.DryRun = false for a dry-run create")
	}

	if _, err := executor.dynamic.Resource(configMapsGVR).Namespace("default").Get(context.Background(), "checkout-api-config", metav1.GetOptions{}); err == nil {
		t.Fatal("the ConfigMap was actually created during a dry run")
	} else if !apierrors.IsNotFound(err) {
		t.Fatalf("unexpected error checking for the (should not exist) object: %v", err)
	}
}

// TestCreateResource_AlreadyExistsRefusesRatherThanReplacing is this task's
// own named requirement: refuse if the object already exists — fail closed,
// never silently become a replace/update.
func TestCreateResource_AlreadyExistsRefusesRatherThanReplacing(t *testing.T) {
	executor := newCreateTestExecutor("clu_1", testExistingConfigMap("checkout-api-config", "default", "100"))
	signed := signTestPlan(t, createResourcePlanContent(false), "clu_1", time.Now().Add(time.Minute))
	args, _ := json.Marshal(map[string]any{"plan": signed})

	if _, _, err := executor.createResource(context.Background(), args); err == nil {
		t.Fatal("createResource succeeded against an object that already exists, want refusal")
	}

	// The pre-existing object's own data must be untouched — a refusal, not
	// a silent replace.
	obj, err := executor.dynamic.Resource(configMapsGVR).Namespace("default").Get(context.Background(), "checkout-api-config", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("re-reading the existing object: %v", err)
	}
	data, _, _ := unstructured.NestedStringMap(obj.Object, "data")
	if _, hasRetryLimit := data["RETRY_LIMIT"]; hasRetryLimit {
		t.Error("the plan's data was written into the existing object — createResource must refuse, never replace")
	}
	if data["EXISTING"] != "value" {
		t.Error("the existing object's own data was altered")
	}
}

// TestCreateResource_RejectsKindOutsideTheAllowlist: Secret is a supported
// GVK generally (describe_resource can read it, narrowly) but is never a
// createResource target — checked agent-side too, the same defense-in-depth
// every other mutating tool carries.
func TestCreateResource_RejectsKindOutsideTheAllowlist(t *testing.T) {
	executor := newCreateTestExecutor("clu_1")
	content := createResourcePlanContent(false)
	content.TargetGVK = "v1/Secret"
	signed := signTestPlan(t, content, "clu_1", time.Now().Add(time.Minute))
	args, _ := json.Marshal(map[string]any{"plan": signed})

	if _, _, err := executor.createResource(context.Background(), args); err == nil {
		t.Fatal("createResource permitted a Secret target, which the allowlist must refuse")
	}
}

func TestCreateResource_RejectsWrongActionTypeEnvelope(t *testing.T) {
	executor := newCreateTestExecutor("clu_1")
	content := createResourcePlanContent(false)
	content.ActionType = remediation.ActionRestartPod // signed for a different tool
	signed := signTestPlan(t, content, "clu_1", time.Now().Add(time.Minute))
	args, _ := json.Marshal(map[string]any{"plan": signed})

	if _, _, err := executor.createResource(context.Background(), args); err == nil {
		t.Fatal("createResource accepted an envelope signed for a different action type")
	}
}

// TestCreateResource_InvalidDataFailsAgentSideRevalidation confirms this
// tool re-runs CreateResourceParams.Validate itself rather than trusting
// whatever the hub signed — DESIGN.md §10.3's agent-side re-validation.
func TestCreateResource_InvalidDataFailsAgentSideRevalidation(t *testing.T) {
	executor := newCreateTestExecutor("clu_1")
	content := createResourcePlanContent(false)
	content.Params = mustMarshal(remediation.CreateResourceParams{}) // empty Data
	signed := signTestPlan(t, content, "clu_1", time.Now().Add(time.Minute))
	args, _ := json.Marshal(map[string]any{"plan": signed})

	if _, _, err := executor.createResource(context.Background(), args); err == nil {
		t.Fatal("createResource accepted params with an empty Data map")
	}

	if _, err := executor.dynamic.Resource(configMapsGVR).Namespace("default").Get(context.Background(), "checkout-api-config", metav1.GetOptions{}); err == nil {
		t.Fatal("an object was created despite invalid params")
	} else if !apierrors.IsNotFound(err) {
		t.Fatalf("unexpected error: %v", err)
	}
}
