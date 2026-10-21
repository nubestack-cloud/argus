package agent

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"

	dynamicfake "k8s.io/client-go/dynamic/fake"
	k8sfake "k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"

	"argus/internal/remediation"
)

var podsGVR = schema.GroupVersionResource{Group: "", Version: "v1", Resource: "pods"}
var pvcGVR = schema.GroupVersionResource{Group: "", Version: "v1", Resource: "persistentvolumeclaims"}

// installRealisticDeleteReactor mirrors installRealisticPatchReactor's own
// dry-run handling (remediation_exec_test.go): the bare fake tracker's
// default Delete (client-go's testing.tracker.Delete) does not honour
// metav1.DeleteOptions.DryRun at all — it always removes the object — so a
// test asserting "a dry run left the object alone" needs this the same way
// TestPatchResourceLimits' dry-run coverage needs its own patch reactor.
//
// Deliberately does not attempt to model precondition evaluation the way
// installRealisticPatchReactor models the resourceVersion check for Patch:
// deleteResource itself already performs that exact Get-then-compare before
// ever calling Delete (see deleteresource.go's own doc comment on why —
// there is no patch BODY to embed a precondition in, unlike every
// Patch-based tool), so a reactor re-implementing it here would duplicate
// logic this test suite already exercises directly.
func installRealisticDeleteReactor(dynFake *dynamicfake.FakeDynamicClient) {
	dynFake.PrependReactor("delete", "*", func(action k8stesting.Action) (bool, runtime.Object, error) {
		deleteAction, ok := action.(k8stesting.DeleteActionImpl)
		if !ok {
			return false, nil, nil
		}
		if slices.Contains(deleteAction.GetDeleteOptions().DryRun, metav1.DryRunAll) {
			return true, nil, nil
		}
		return false, nil, nil
	})
}

// newDeleteTestExecutor is newRemediationTestExecutor plus
// installRealisticDeleteReactor — a separate constructor rather than
// changing the shared one, since every other mutating-tool test file
// (scale/restart/patch_resource_limits/revert_container_image/patch_field)
// only ever issues Patch calls and has no need for a delete reactor at all.
func newDeleteTestExecutor(clusterID string, objs ...runtime.Object) *ToolExecutor {
	executor := newRemediationTestExecutor(clusterID, objs...)
	installRealisticDeleteReactor(executor.dynamic.(*dynamicfake.FakeDynamicClient))
	return executor
}

func testDeletablePod(name, namespace, resourceVersion string) *corev1.Pod {
	return &corev1.Pod{
		TypeMeta:   metav1.TypeMeta{APIVersion: "v1", Kind: "Pod"},
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace, ResourceVersion: resourceVersion, UID: "uid-1"},
	}
}

func testDeletablePVC(name, namespace, resourceVersion string) *corev1.PersistentVolumeClaim {
	return &corev1.PersistentVolumeClaim{
		TypeMeta:   metav1.TypeMeta{APIVersion: "v1", Kind: "PersistentVolumeClaim"},
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace, ResourceVersion: resourceVersion, UID: "uid-pvc-1"},
	}
}

// newDeleteTestExecutorWithPods is newDeleteTestExecutor plus a typed fake
// clientset seeded with pods — the liveness precondition
// (checkPVCNotReferenced) reads e.typed, unlike every other check in this
// file, which only ever touches e.dynamic. newRemediationTestExecutor
// deliberately leaves e.typed nil (every OTHER delete/patch test in this
// package has no need for it), so this is its own constructor rather than a
// change to the shared one.
func newDeleteTestExecutorWithPods(clusterID string, pods []runtime.Object, objs ...runtime.Object) *ToolExecutor {
	executor := newDeleteTestExecutor(clusterID, objs...)
	executor.typed = k8sfake.NewSimpleClientset(pods...)
	return executor
}

func testPodMountingClaim(name, namespace, claimName string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
		Spec: corev1.PodSpec{
			Volumes: []corev1.Volume{
				{
					Name: "data",
					VolumeSource: corev1.VolumeSource{
						PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: claimName},
					},
				},
			},
		},
	}
}

func deletePVCPlanContent(name, rv string) remediation.PlanContent {
	return remediation.PlanContent{
		RecommendationID: "plan_1",
		ActionType:       remediation.ActionDeleteResource,
		TargetGVK:        "v1/PersistentVolumeClaim",
		TargetNamespace:  "default",
		TargetName:       name,
		Params:           mustMarshal(remediation.DeleteResourceParams{}),
		ResourceVersion:  rv,
	}
}

// TestDeleteResource_PersistentVolumeClaim_Orphaned_Succeeds is the positive
// case BUGS.md 118 part (b) exists to make reachable: a PVC with no Pod
// anywhere referencing it, targeted by an otherwise-valid signed plan,
// really gets deleted. No Pods at all are seeded — not even an unrelated
// one — the same "no live Pod references this claim" state
// checkOrphanedPVC itself would flag.
func TestDeleteResource_PersistentVolumeClaim_Orphaned_Succeeds(t *testing.T) {
	executor := newDeleteTestExecutorWithPods("clu_1", nil, testDeletablePVC("data-sts8-victim-1", "default", "100"))
	signed := signTestPlan(t, deletePVCPlanContent("data-sts8-victim-1", "100"), "clu_1", time.Now().Add(time.Minute))
	args, _ := json.Marshal(map[string]any{"plan": signed})

	data, _, err := executor.deleteResource(context.Background(), args)
	if err != nil {
		t.Fatalf("deleteResource: %v", err)
	}
	var result deleteResourceResult
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("decode result: %v", err)
	}
	if result.GVK != "v1/PersistentVolumeClaim" {
		t.Errorf("result.GVK = %q, want v1/PersistentVolumeClaim", result.GVK)
	}

	if _, err := executor.dynamic.Resource(pvcGVR).Namespace("default").Get(context.Background(), "data-sts8-victim-1", metav1.GetOptions{}); err == nil {
		t.Fatal("the PVC still exists after a real delete")
	} else if !apierrors.IsNotFound(err) {
		t.Fatalf("unexpected error re-reading the deleted PVC: %v", err)
	}
}

// TestDeleteResource_PersistentVolumeClaim_StillReferenced_Refused is the
// liveness precondition's whole point: a Pod in the same namespace still
// has a volume naming this claim, so the delete must be refused even
// though the signed plan itself, the resourceVersion, and the allowlist
// check would all otherwise pass.
func TestDeleteResource_PersistentVolumeClaim_StillReferenced_Refused(t *testing.T) {
	pods := []runtime.Object{testPodMountingClaim("still-running", "default", "data-sts8-victim-1")}
	executor := newDeleteTestExecutorWithPods("clu_1", pods, testDeletablePVC("data-sts8-victim-1", "default", "100"))
	signed := signTestPlan(t, deletePVCPlanContent("data-sts8-victim-1", "100"), "clu_1", time.Now().Add(time.Minute))
	args, _ := json.Marshal(map[string]any{"plan": signed})

	_, _, err := executor.deleteResource(context.Background(), args)
	if err == nil {
		t.Fatal("deleteResource deleted a PersistentVolumeClaim a live Pod still references")
	}
	if !errors.Is(err, errPVCStillReferenced) {
		t.Errorf("error = %v, want errPVCStillReferenced", err)
	}

	if _, getErr := executor.dynamic.Resource(pvcGVR).Namespace("default").Get(context.Background(), "data-sts8-victim-1", metav1.GetOptions{}); getErr != nil {
		t.Fatalf("the PVC was deleted despite still being referenced: %v", getErr)
	}
}

// TestDeleteResource_PersistentVolumeClaim_ReferencedInAnotherNamespace_Succeeds
// pins the liveness check's namespace scoping: a PVC can only ever be
// mounted by a Pod in its OWN namespace (the same fact
// resolveRelatedWorkloadForPVC's own doc comment relies on), so a
// same-named claim referenced by a Pod in a DIFFERENT namespace must not
// block this delete.
func TestDeleteResource_PersistentVolumeClaim_ReferencedInAnotherNamespace_Succeeds(t *testing.T) {
	pods := []runtime.Object{testPodMountingClaim("other-ns-pod", "other-namespace", "data-sts8-victim-1")}
	executor := newDeleteTestExecutorWithPods("clu_1", pods, testDeletablePVC("data-sts8-victim-1", "default", "100"))
	signed := signTestPlan(t, deletePVCPlanContent("data-sts8-victim-1", "100"), "clu_1", time.Now().Add(time.Minute))
	args, _ := json.Marshal(map[string]any{"plan": signed})

	if _, _, err := executor.deleteResource(context.Background(), args); err != nil {
		t.Fatalf("deleteResource: %v", err)
	}
}

func deletePlanContent(rv string) remediation.PlanContent {
	return remediation.PlanContent{
		RecommendationID: "plan_1",
		ActionType:       remediation.ActionDeleteResource,
		TargetGVK:        "v1/Pod",
		TargetNamespace:  "default",
		TargetName:       "stuck-pod",
		Params:           mustMarshal(remediation.DeleteResourceParams{}),
		ResourceVersion:  rv,
	}
}

func TestDeleteResource_ValidSignedPlanDeletesTheObject(t *testing.T) {
	executor := newDeleteTestExecutor("clu_1", testDeletablePod("stuck-pod", "default", "100"))
	signed := signTestPlan(t, deletePlanContent("100"), "clu_1", time.Now().Add(time.Minute))
	args, _ := json.Marshal(map[string]any{"plan": signed})

	data, _, err := executor.deleteResource(context.Background(), args)
	if err != nil {
		t.Fatalf("deleteResource: %v", err)
	}
	var result deleteResourceResult
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("decode result: %v", err)
	}
	if result.DryRun {
		t.Error("result.DryRun = true for a real delete")
	}
	if result.Outcome != deleteResourceOutcomeDeleted {
		t.Errorf("Outcome = %q, want %q", result.Outcome, deleteResourceOutcomeDeleted)
	}

	if _, err := executor.dynamic.Resource(podsGVR).Namespace("default").Get(context.Background(), "stuck-pod", metav1.GetOptions{}); err == nil {
		t.Fatal("the pod still exists after a real delete")
	} else if !apierrors.IsNotFound(err) {
		t.Fatalf("unexpected error re-reading the deleted pod: %v", err)
	}
}

func TestDeleteResource_DryRunLeavesTheObjectInPlace(t *testing.T) {
	executor := newDeleteTestExecutor("clu_1", testDeletablePod("stuck-pod", "default", "100"))
	content := deletePlanContent("100")
	content.DryRun = true
	signed := signTestPlan(t, content, "clu_1", time.Now().Add(time.Minute))
	args, _ := json.Marshal(map[string]any{"plan": signed})

	data, _, err := executor.deleteResource(context.Background(), args)
	if err != nil {
		t.Fatalf("deleteResource (dry run): %v", err)
	}
	var result deleteResourceResult
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("decode result: %v", err)
	}
	if !result.DryRun {
		t.Error("result.DryRun = false for a dry-run delete")
	}

	if _, err := executor.dynamic.Resource(podsGVR).Namespace("default").Get(context.Background(), "stuck-pod", metav1.GetOptions{}); err != nil {
		t.Fatalf("the pod was actually deleted during a dry run: %v", err)
	}
}

func TestDeleteResource_StaleResourceVersionFailsClosed(t *testing.T) {
	executor := newDeleteTestExecutor("clu_1", testDeletablePod("stuck-pod", "default", "100"))
	// Signed against a resourceVersion that no longer matches the live object.
	signed := signTestPlan(t, deletePlanContent("999"), "clu_1", time.Now().Add(time.Minute))
	args, _ := json.Marshal(map[string]any{"plan": signed})

	if _, _, err := executor.deleteResource(context.Background(), args); err == nil {
		t.Fatal("deleteResource proceeded against a stale resourceVersion")
	}
	if _, err := executor.dynamic.Resource(podsGVR).Namespace("default").Get(context.Background(), "stuck-pod", metav1.GetOptions{}); err != nil {
		t.Fatalf("the pod was deleted despite a stale-resourceVersion refusal: %v", err)
	}
}

func TestDeleteResource_RejectsKindOutsideTheAllowlist(t *testing.T) {
	// StatefulSet is never a DeleteResource target, per
	// internal/remediation/deleteresource.go's own allowlist — checked
	// agent-side too, the same defense-in-depth every other mutating tool
	// carries.
	executor := newRemediationTestExecutor("clu_1", testDeployment("web", "default", 1, "100"))
	content := deletePlanContent("100")
	content.TargetGVK = "apps/v1/StatefulSet"
	content.TargetName = "web"
	signed := signTestPlan(t, content, "clu_1", time.Now().Add(time.Minute))
	args, _ := json.Marshal(map[string]any{"plan": signed})

	if _, _, err := executor.deleteResource(context.Background(), args); err == nil {
		t.Fatal("deleteResource permitted a StatefulSet target, which the allowlist must refuse")
	}
}

func TestDeleteResource_RejectsWrongActionTypeEnvelope(t *testing.T) {
	executor := newDeleteTestExecutor("clu_1", testDeletablePod("stuck-pod", "default", "100"))
	content := deletePlanContent("100")
	content.ActionType = remediation.ActionRestartPod // signed for a different tool
	signed := signTestPlan(t, content, "clu_1", time.Now().Add(time.Minute))
	args, _ := json.Marshal(map[string]any{"plan": signed})

	if _, _, err := executor.deleteResource(context.Background(), args); err == nil {
		t.Fatal("deleteResource accepted an envelope signed for a different action type")
	}
}

// TestDeleteResource_AlreadyGoneIsAnHonestSuccessNotAFailure is PROJECT.md
// B146's second-pass regression test. This used to be
// TestDeleteResource_NotFoundIsAClearError, asserting the OPPOSITE behavior —
// but reporting "the object does not exist" as an ERROR was itself a smaller
// version of B146's own false-positive/false-negative honesty problem, just
// in the other direction: DeleteResource's whole point is "this object must
// not exist", and an already-absent object already satisfies that. Treating
// it as a failure blocked the incident in a Failed state a human had to
// manually discover was actually fine, instead of letting it reach
// Validating and be confirmed the ordinary way. See deleteResourceResult's
// own doc comment for the full reasoning and the third outcome
// ("deletion already in progress") that correctly stays a hard error.
func TestDeleteResource_AlreadyGoneIsAnHonestSuccessNotAFailure(t *testing.T) {
	executor := newDeleteTestExecutor("clu_1")
	signed := signTestPlan(t, deletePlanContent("100"), "clu_1", time.Now().Add(time.Minute))
	args, _ := json.Marshal(map[string]any{"plan": signed})

	raw, retryable, err := executor.deleteResource(context.Background(), args)
	if err != nil {
		t.Fatalf("deleteResource against an already-absent object returned an error, want success: %v", err)
	}
	if retryable {
		t.Error("deleteResource returned retryable=true on a success path")
	}
	var result deleteResourceResult
	if err := json.Unmarshal(raw, &result); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}
	if result.Outcome != deleteResourceOutcomeAlreadyGone {
		t.Errorf("Outcome = %q, want %q", result.Outcome, deleteResourceOutcomeAlreadyGone)
	}
	if result.ResourceVersion != "" {
		t.Errorf("ResourceVersion = %q, want empty — there is no live object to have one", result.ResourceVersion)
	}
}

// TestDeleteResource_AlreadyTerminatingRefusesRatherThanFalselySucceeding is
// PROJECT.md B146's regression test: found live 2026-09-06 (breadth-campaign
// TERM-001 fixture) — an approved DeleteResource execution against an object
// that already carried a deletionTimestamp (a finalizer blocking full
// removal) was recorded outcome='succeeded' while nothing about the object
// actually changed. A plain Kubernetes DELETE call against an object already
// marked for deletion cannot touch metadata.finalizers and cannot make
// removal happen any faster — this must be refused with a clear reason
// (routing the execution to Failed, not a false Validating), not reported as
// a successful deletion.
func TestDeleteResource_AlreadyTerminatingRefusesRatherThanFalselySucceeding(t *testing.T) {
	pod := testDeletablePod("stuck-pod", "default", "100")
	now := metav1.Now()
	pod.DeletionTimestamp = &now
	pod.Finalizers = []string{"example.com/fake-finalizer-no-controller"}

	executor := newDeleteTestExecutor("clu_1", pod)
	signed := signTestPlan(t, deletePlanContent("100"), "clu_1", time.Now().Add(time.Minute))
	args, _ := json.Marshal(map[string]any{"plan": signed})

	if _, _, err := executor.deleteResource(context.Background(), args); err == nil {
		t.Fatal("deleteResource reported success against an object already marked for deletion — this is exactly B146's false positive")
	} else if !errors.Is(err, errDeletionAlreadyInProgress) {
		t.Errorf("deleteResource error = %v, want it to wrap errDeletionAlreadyInProgress", err)
	}

	// The finalizer must be genuinely untouched — this call must not have
	// attempted to clear it either.
	live, err := executor.dynamic.Resource(podsGVR).Namespace("default").Get(context.Background(), "stuck-pod", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("re-read the pod after the refusal: %v", err)
	}
	if finalizers := live.GetFinalizers(); len(finalizers) != 1 || finalizers[0] != "example.com/fake-finalizer-no-controller" {
		t.Errorf("finalizers = %v, want unchanged", finalizers)
	}
}
