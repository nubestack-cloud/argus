package agent

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"

	"argus/internal/remediation"
)

// These tests exercise revert_container_image through the same fake-clientset
// seam the other three execution tools use (newRemediationTestExecutor +
// installRealisticPatchReactor, in remediation_exec_test.go — itself a thin
// wrapper over the NewToolExecutorForTest constructor's clients), so the patch
// really is issued, the resourceVersion precondition really is enforced, and the
// merged result can be inspected afterwards.
//
// The fault this action exists for, reproduced as the fixture: a workload whose
// current revision (3) rolled container "app" to a broken 1.3.0 image, with
// revision 2 still recording the 1.2.0 image it ran before. A second container
// and a second, unrelated Deployment's ReplicaSet are present throughout so
// every test can also check what was NOT collateral damage.

const (
	brokenImage = "registry.example.com/app:1.3.0"
	goodImage   = "registry.example.com/app:1.2.0"
	sidecarImg  = "registry.example.com/log-shipper:0.9.0"

	testDeploymentUID = "11111111-1111-1111-1111-111111111111"
	otherWorkloadUID  = "22222222-2222-2222-2222-222222222222"
)

// imageTestContainer carries resources as well as an image so the tests can
// prove an image revert leaves a container's cpu/memory alone — the field the
// OTHER pod-template action owns, and the one a whole-template revert would
// have quietly rewritten.
func imageTestContainer(name, image string) corev1.Container {
	return corev1.Container{
		Name:  name,
		Image: image,
		Resources: corev1.ResourceRequirements{
			Limits:   corev1.ResourceList{corev1.ResourceMemory: resource.MustParse("256Mi")},
			Requests: corev1.ResourceList{corev1.ResourceMemory: resource.MustParse("128Mi")},
		},
	}
}

// imageTestDeployment is the live target: two containers, "app" on the broken
// image, at revision 3.
func imageTestDeployment(resourceVersion string) *appsv1.Deployment {
	replicas := int32(2)
	return &appsv1.Deployment{
		TypeMeta: metav1.TypeMeta{APIVersion: "apps/v1", Kind: "Deployment"},
		ObjectMeta: metav1.ObjectMeta{
			Name: "web", Namespace: "default",
			ResourceVersion: resourceVersion,
			UID:             types.UID(testDeploymentUID),
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: &replicas,
			Template: corev1.PodTemplateSpec{
				Spec: corev1.PodSpec{Containers: []corev1.Container{
					imageTestContainer("app", brokenImage),
					imageTestContainer("sidecar", sidecarImg),
				}},
			},
		},
	}
}

// imageTestReplicaSet is one entry of the rollout history. ownerUID is a
// parameter so a test can plant a ReplicaSet that carries a tempting image but
// belongs to a DIFFERENT Deployment — the case ownership-by-UID exists to
// reject.
func imageTestReplicaSet(name, ownerUID, appImage string) *appsv1.ReplicaSet {
	replicas := int32(0)
	return &appsv1.ReplicaSet{
		TypeMeta: metav1.TypeMeta{APIVersion: "apps/v1", Kind: "ReplicaSet"},
		ObjectMeta: metav1.ObjectMeta{
			Name: name, Namespace: "default",
			OwnerReferences: []metav1.OwnerReference{{
				APIVersion: "apps/v1", Kind: "Deployment", Name: "web", UID: types.UID(ownerUID),
			}},
		},
		Spec: appsv1.ReplicaSetSpec{
			Replicas: &replicas,
			Template: corev1.PodTemplateSpec{
				Spec: corev1.PodSpec{Containers: []corev1.Container{
					imageTestContainer("app", appImage),
					imageTestContainer("sidecar", sidecarImg),
				}},
			},
		},
	}
}

// revertPlan is the happy-path envelope content: put container "app" back on
// the 1.2.0 image revision 2 recorded, with the compensating action the hub
// captured from the live object (the 1.3.0 image it is running now).
func revertPlan(rv string) remediation.PlanContent {
	return remediation.PlanContent{
		RecommendationID: "plan_1",
		ActionType:       remediation.ActionRevertContainerImage,
		TargetGVK:        "apps/v1/Deployment",
		TargetNamespace:  "default",
		TargetName:       "web",
		Params:           mustMarshal(remediation.RevertContainerImageExecParams{Container: "app", Image: goodImage}),
		Rollback: &remediation.CompensatingAction{
			ActionType:  remediation.ActionRevertContainerImage,
			Params:      mustMarshal(remediation.RevertContainerImageExecParams{Container: "app", Image: brokenImage}),
			Description: `restore container "app" to image ` + brokenImage,
		},
		ResourceVersion: rv,
	}
}

// newRevertTestExecutor builds an executor whose fake cluster holds the live
// Deployment, its two-revision history, and one unrelated Deployment's
// ReplicaSet that happens to run the image under test.
func newRevertTestExecutor(t *testing.T, rv string) *ToolExecutor {
	t.Helper()
	return newRemediationTestExecutor("clu_1",
		imageTestDeployment(rv),
		imageTestReplicaSet("web-rev3", testDeploymentUID, brokenImage),
		imageTestReplicaSet("web-rev2", testDeploymentUID, goodImage),
		// Same image, different owner — must not satisfy the history check.
		imageTestReplicaSet("someone-else-rev1", otherWorkloadUID, "registry.example.com/app:9.9.9"),
	)
}

func liveImageOf(t *testing.T, e *ToolExecutor, container string) string {
	t.Helper()
	obj, err := e.dynamic.Resource(deploymentsGVR).Namespace("default").Get(context.Background(), "web", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("re-read deployment: %v", err)
	}
	image, found, err := podTemplateContainerImage(obj, container)
	if err != nil || !found {
		t.Fatalf("re-read container %q image: found=%v err=%v", container, found, err)
	}
	return image
}

func TestRevertContainerImage_ValidSignedPlanPatchesOnlyTheImage(t *testing.T) {
	executor := newRevertTestExecutor(t, "100")
	signed := signTestPlan(t, revertPlan("100"), "clu_1", time.Now().Add(5*time.Minute))

	data, truncated, err := executor.revertContainerImage(context.Background(), mustMarshal(signedPlanArgs{Plan: signed}))
	if err != nil {
		t.Fatalf("revertContainerImage: %v", err)
	}
	if truncated {
		t.Errorf("truncated = true, want false")
	}
	var result executeResult
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("decode result: %v", err)
	}
	if result.ResourceVersion == "" || result.ResourceVersion == "100" {
		t.Errorf("result resourceVersion = %q, want a bumped value proving a real write happened", result.ResourceVersion)
	}

	if got := liveImageOf(t, executor, "app"); got != goodImage {
		t.Errorf("app image = %q, want the reverted %q", got, goodImage)
	}
	// The sibling container, and the patched container's own resources, must
	// survive untouched: this action changes one field of one container, and a
	// whole-pod-template revert (the rejected alternative) would not have.
	if got := liveImageOf(t, executor, "sidecar"); got != sidecarImg {
		t.Errorf("sidecar image = %q, want it untouched", got)
	}
	app := liveContainer(t, executor, "app")
	if got := containerQuantity(t, app, "limits", "memory"); got != "256Mi" {
		t.Errorf("app limits.memory = %q, want it untouched at 256Mi", got)
	}
	if got := containerQuantity(t, app, "requests", "memory"); got != "128Mi" {
		t.Errorf("app requests.memory = %q, want it untouched at 128Mi", got)
	}
}

// TestRevertContainerImage_RejectsTamperedParams is the attack this action is
// most exposed to: the envelope is otherwise exactly what the hub produced, and
// the substituted image is even well-formed — the only thing wrong with it is
// that nobody signed THIS version.
func TestRevertContainerImage_RejectsTamperedParams(t *testing.T) {
	executor := newRevertTestExecutor(t, "100")
	signed := signTestPlan(t, revertPlan("100"), "clu_1", time.Now().Add(5*time.Minute))

	signed.Params = mustMarshal(remediation.RevertContainerImageExecParams{
		Container: "app", Image: "evil.example.com/backdoor:latest",
	})

	if _, _, err := executor.revertContainerImage(context.Background(), mustMarshal(signedPlanArgs{Plan: signed})); err == nil {
		t.Fatal("revertContainerImage accepted a plan whose params were tampered with after signing")
	}
	if got := liveImageOf(t, executor, "app"); got != brokenImage {
		t.Errorf("app image = %q, want the original %q — the rejected plan must not have been applied", got, brokenImage)
	}
}

// TestRevertContainerImage_RejectsImageNotInThisWorkloadsHistory is the most
// important test in this file. It models a fully compromised hub: the envelope
// is signed with this cluster's real key, names a real container, carries a
// consistent rollback, and passes every structural check — and the image it
// asks for is one this workload has never run. The ONLY thing standing in the
// way is the agent's own read of the Deployment's ReplicaSets.
func TestRevertContainerImage_RejectsImageNotInThisWorkloadsHistory(t *testing.T) {
	executor := newRevertTestExecutor(t, "100")
	content := revertPlan("100")
	content.Params = mustMarshal(remediation.RevertContainerImageExecParams{
		Container: "app", Image: "evil.example.com/backdoor:latest",
	})
	signed := signTestPlan(t, content, "clu_1", time.Now().Add(5*time.Minute))

	if _, _, err := executor.revertContainerImage(context.Background(), mustMarshal(signedPlanArgs{Plan: signed})); err == nil {
		t.Fatal("revertContainerImage accepted an image that appears in no ReplicaSet this workload owns")
	}
	if got := liveImageOf(t, executor, "app"); got != brokenImage {
		t.Errorf("app image = %q, want the original %q", got, brokenImage)
	}
}

// TestRevertContainerImage_RejectsImageFromAnotherWorkloadsHistory: the history
// check is scoped by ownerReference UID, not by "some ReplicaSet in this
// namespace runs it". Without that, any image running anywhere in the namespace
// would be a valid revert target — which for a shared namespace is most of the
// cluster.
func TestRevertContainerImage_RejectsImageFromAnotherWorkloadsHistory(t *testing.T) {
	executor := newRevertTestExecutor(t, "100")
	content := revertPlan("100")
	content.Params = mustMarshal(remediation.RevertContainerImageExecParams{
		Container: "app", Image: "registry.example.com/app:9.9.9", // only the other Deployment's ReplicaSet has this
	})
	signed := signTestPlan(t, content, "clu_1", time.Now().Add(5*time.Minute))

	if _, _, err := executor.revertContainerImage(context.Background(), mustMarshal(signedPlanArgs{Plan: signed})); err == nil {
		t.Fatal("revertContainerImage accepted an image belonging to a different Deployment's rollout history")
	}
}

// TestRevertContainerImage_RejectsWhenThereIsNoPreviousReplicaSet is the
// first-ever-deployment case as it reaches the agent: the workload has exactly
// one revision, so the image the plan names is nowhere in its history. The hub
// refuses this before signing (resolvePreviousImage), so reaching the agent at
// all means the hub was wrong or compromised — and the answer must still be no.
func TestRevertContainerImage_RejectsWhenThereIsNoPreviousReplicaSet(t *testing.T) {
	// Only the current revision exists.
	executor := newRemediationTestExecutor("clu_1",
		imageTestDeployment("100"),
		imageTestReplicaSet("web-rev1", testDeploymentUID, brokenImage),
	)
	signed := signTestPlan(t, revertPlan("100"), "clu_1", time.Now().Add(5*time.Minute))

	if _, _, err := executor.revertContainerImage(context.Background(), mustMarshal(signedPlanArgs{Plan: signed})); err == nil {
		t.Fatal("revertContainerImage executed against a workload with no previous revision")
	}
	if got := liveImageOf(t, executor, "app"); got != brokenImage {
		t.Errorf("app image = %q, want the original %q", got, brokenImage)
	}
}

// TestRevertContainerImage_RejectsWhenTheWorkloadHasNoReplicaSetsAtAll: a
// pruned history (revisionHistoryLimit: 0) must fail closed rather than reading
// as "nothing contradicts this image".
func TestRevertContainerImage_RejectsWhenTheWorkloadHasNoReplicaSetsAtAll(t *testing.T) {
	executor := newRemediationTestExecutor("clu_1", imageTestDeployment("100"))
	signed := signTestPlan(t, revertPlan("100"), "clu_1", time.Now().Add(5*time.Minute))

	if _, _, err := executor.revertContainerImage(context.Background(), mustMarshal(signedPlanArgs{Plan: signed})); err == nil {
		t.Fatal("revertContainerImage executed against a workload with no rollout history at all")
	}
}

// TestRevertContainerImage_RejectsWhenTheImageIsAlreadyLive: the previous
// revision's image equals the one running now, so there is nothing to revert.
// The hub refuses this too; the agent refuses it independently because a
// "successful" no-op execution would still roll every pod of the workload and
// would be recorded as a remediation that fixed something.
func TestRevertContainerImage_RejectsWhenTheImageIsAlreadyLive(t *testing.T) {
	executor := newRevertTestExecutor(t, "100")
	content := revertPlan("100")
	content.Params = mustMarshal(remediation.RevertContainerImageExecParams{Container: "app", Image: brokenImage})
	content.Rollback.Params = mustMarshal(remediation.RevertContainerImageExecParams{Container: "app", Image: goodImage})
	signed := signTestPlan(t, content, "clu_1", time.Now().Add(5*time.Minute))

	if _, _, err := executor.revertContainerImage(context.Background(), mustMarshal(signedPlanArgs{Plan: signed})); err == nil {
		t.Fatal("revertContainerImage executed a plan that sets the image the container already runs")
	}
}

// TestRevertContainerImage_RejectsTamperedRollback: stripping the compensating
// action must invalidate the signature, which is why Rollback lives inside
// PlanContent rather than beside it.
func TestRevertContainerImage_RejectsTamperedRollback(t *testing.T) {
	executor := newRevertTestExecutor(t, "100")
	signed := signTestPlan(t, revertPlan("100"), "clu_1", time.Now().Add(5*time.Minute))
	signed.Rollback = nil

	if _, _, err := executor.revertContainerImage(context.Background(), mustMarshal(signedPlanArgs{Plan: signed})); err == nil {
		t.Fatal("revertContainerImage accepted a plan whose rollback was stripped after signing")
	}
}

// TestRevertContainerImage_RejectsMissingRollback is the unsigned-omission case:
// a validly signed envelope that never carried a rollback at all. This is what
// makes §10.3's "captured before execution" enforced rather than assumed.
func TestRevertContainerImage_RejectsMissingRollback(t *testing.T) {
	executor := newRevertTestExecutor(t, "100")
	content := revertPlan("100")
	content.Rollback = nil
	signed := signTestPlan(t, content, "clu_1", time.Now().Add(5*time.Minute))

	if _, _, err := executor.revertContainerImage(context.Background(), mustMarshal(signedPlanArgs{Plan: signed})); err == nil {
		t.Fatal("revertContainerImage executed a plan with no pre-computed rollback")
	}
}

// TestRevertContainerImage_RejectsRollbackThatDisagreesWithLiveState covers what
// a signature cannot: a correctly signed rollback describing an image the
// container is not running, i.e. an undo that would move the workload to a
// state it was never in. In practice this is the concurrent-change case — a
// human rolled the workload again between the hub's read and this Patch.
func TestRevertContainerImage_RejectsRollbackThatDisagreesWithLiveState(t *testing.T) {
	executor := newRevertTestExecutor(t, "100")
	content := revertPlan("100")
	content.Rollback.Params = mustMarshal(remediation.RevertContainerImageExecParams{
		Container: "app", Image: "registry.example.com/app:1.4.0",
	})
	signed := signTestPlan(t, content, "clu_1", time.Now().Add(5*time.Minute))

	if _, _, err := executor.revertContainerImage(context.Background(), mustMarshal(signedPlanArgs{Plan: signed})); err == nil {
		t.Fatal("revertContainerImage accepted a rollback that does not match the live container's image")
	}
}

// TestRevertContainerImage_RejectsRollbackForADifferentContainer: an undo aimed
// at another container is not an undo of this plan.
func TestRevertContainerImage_RejectsRollbackForADifferentContainer(t *testing.T) {
	executor := newRevertTestExecutor(t, "100")
	content := revertPlan("100")
	content.Rollback.Params = mustMarshal(remediation.RevertContainerImageExecParams{
		Container: "sidecar", Image: sidecarImg,
	})
	signed := signTestPlan(t, content, "clu_1", time.Now().Add(5*time.Minute))

	if _, _, err := executor.revertContainerImage(context.Background(), mustMarshal(signedPlanArgs{Plan: signed})); err == nil {
		t.Fatal("revertContainerImage accepted a rollback naming a different container")
	}
}

func TestRevertContainerImage_StaleResourceVersionFailsClosed(t *testing.T) {
	executor := newRevertTestExecutor(t, "100")
	signed := signTestPlan(t, revertPlan("99-since-superseded"), "clu_1", time.Now().Add(5*time.Minute))

	if _, _, err := executor.revertContainerImage(context.Background(), mustMarshal(signedPlanArgs{Plan: signed})); err == nil {
		t.Fatal("revertContainerImage succeeded despite a stale resourceVersion precondition")
	}
	if got := liveImageOf(t, executor, "app"); got != brokenImage {
		t.Errorf("app image = %q, want the original %q", got, brokenImage)
	}
}

// TestRevertContainerImage_RejectsUnknownContainer: a strategic-merge patch keyed
// on an unmatched container name APPENDS a container rather than failing (the
// fake reproduces that — see mergeByName), so without the live-object check this
// plan would "succeed" by adding a third container to somebody's pod template —
// here one with an image and no resources, which would actually start.
func TestRevertContainerImage_RejectsUnknownContainer(t *testing.T) {
	executor := newRevertTestExecutor(t, "100")
	content := revertPlan("100")
	content.Params = mustMarshal(remediation.RevertContainerImageExecParams{Container: "not-a-container", Image: goodImage})
	content.Rollback.Params = mustMarshal(remediation.RevertContainerImageExecParams{Container: "not-a-container", Image: brokenImage})
	signed := signTestPlan(t, content, "clu_1", time.Now().Add(5*time.Minute))

	if _, _, err := executor.revertContainerImage(context.Background(), mustMarshal(signedPlanArgs{Plan: signed})); err == nil {
		t.Fatal("revertContainerImage accepted a plan naming a container that does not exist")
	}

	obj, err := executor.dynamic.Resource(deploymentsGVR).Namespace("default").Get(context.Background(), "web", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("re-read deployment: %v", err)
	}
	containers, _, _ := unstructured.NestedSlice(obj.Object, "spec", "template", "spec", "containers")
	if len(containers) != 2 {
		t.Fatalf("pod template has %d containers, want the original 2 — a container was appended", len(containers))
	}
}

// TestRevertContainerImage_RejectsMalformedImages: the same absolute shape
// bounds the hub applied, re-run agent-side against a correctly signed
// envelope. None of these can come from a cluster; all of them can come from a
// compromised or buggy hub.
func TestRevertContainerImage_RejectsMalformedImages(t *testing.T) {
	cases := map[string]string{
		"empty image":         "",
		"embedded newline":    "registry.example.com/app:1.2.0\nsomething",
		"shell metacharacter": "registry.example.com/app:1.2.0;id",
		"whitespace":          "registry.example.com/app :1.2.0",
	}
	for name, image := range cases {
		t.Run(name, func(t *testing.T) {
			executor := newRevertTestExecutor(t, "100")
			content := revertPlan("100")
			content.Params = mustMarshal(remediation.RevertContainerImageExecParams{Container: "app", Image: image})
			signed := signTestPlan(t, content, "clu_1", time.Now().Add(5*time.Minute))

			if _, _, err := executor.revertContainerImage(context.Background(), mustMarshal(signedPlanArgs{Plan: signed})); err == nil {
				t.Fatalf("revertContainerImage accepted %s", name)
			}
			if got := liveImageOf(t, executor, "app"); got != brokenImage {
				t.Errorf("app image = %q, want the original %q", got, brokenImage)
			}
		})
	}
}

func TestRevertContainerImage_RejectsWrongActionTypeEnvelope(t *testing.T) {
	executor := newRevertTestExecutor(t, "100")
	content := revertPlan("100")
	content.ActionType = remediation.ActionPatchResourceLimits
	signed := signTestPlan(t, content, "clu_1", time.Now().Add(5*time.Minute))

	if _, _, err := executor.revertContainerImage(context.Background(), mustMarshal(signedPlanArgs{Plan: signed})); err == nil {
		t.Fatal("revertContainerImage honored a validly-signed PatchResourceLimits envelope")
	}
}

// TestRevertContainerImage_RejectsWrongRollbackActionType: a rollback of another
// action type cannot undo this one, and accepting it would mean executing with
// an undo nobody could apply.
func TestRevertContainerImage_RejectsWrongRollbackActionType(t *testing.T) {
	executor := newRevertTestExecutor(t, "100")
	content := revertPlan("100")
	content.Rollback.ActionType = remediation.ActionRestartPod
	signed := signTestPlan(t, content, "clu_1", time.Now().Add(5*time.Minute))

	if _, _, err := executor.revertContainerImage(context.Background(), mustMarshal(signedPlanArgs{Plan: signed})); err == nil {
		t.Fatal("revertContainerImage accepted a rollback of a different action type")
	}
}

func TestRevertContainerImage_RejectsWrongClusterAndExpiredPlans(t *testing.T) {
	executor := newRevertTestExecutor(t, "100")

	wrongCluster := signTestPlan(t, revertPlan("100"), "clu_OTHER", time.Now().Add(5*time.Minute))
	if _, _, err := executor.revertContainerImage(context.Background(), mustMarshal(signedPlanArgs{Plan: wrongCluster})); err == nil {
		t.Error("revertContainerImage accepted a plan signed for a different cluster")
	}

	expired := signTestPlan(t, revertPlan("100"), "clu_1", time.Now().Add(-time.Minute))
	if _, _, err := executor.revertContainerImage(context.Background(), mustMarshal(signedPlanArgs{Plan: expired})); err == nil {
		t.Error("revertContainerImage accepted an expired plan")
	}
}

// TestRevertContainerImage_RejectsUnsupportedKind: a StatefulSet has container
// images too, but its revision history is ControllerRevisions — which this agent
// cannot read, so the "this image already ran here" check cannot be made. The
// admission policy refuses an image change there as well; this is the refusal
// that happens before anything is sent.
func TestRevertContainerImage_RejectsUnsupportedKind(t *testing.T) {
	executor := newRevertTestExecutor(t, "100")
	for _, gvk := range []string{"apps/v1/StatefulSet", "apps/v1/DaemonSet", "v1/Pod"} {
		content := revertPlan("100")
		content.TargetGVK = gvk
		signed := signTestPlan(t, content, "clu_1", time.Now().Add(5*time.Minute))

		if _, _, err := executor.revertContainerImage(context.Background(), mustMarshal(signedPlanArgs{Plan: signed})); err == nil {
			t.Errorf("revertContainerImage accepted a %s target", gvk)
		}
	}
}

func TestRevertContainerImage_RejectsWithoutCredentials(t *testing.T) {
	executor := newRevertTestExecutor(t, "100")
	executor.SetRemediationCredentials("", nil) // as if enrollment never delivered a key

	signed := signTestPlan(t, revertPlan("100"), "clu_1", time.Now().Add(5*time.Minute))
	if _, _, err := executor.revertContainerImage(context.Background(), mustMarshal(signedPlanArgs{Plan: signed})); err == nil {
		t.Fatal("revertContainerImage executed against an executor with no remediation credentials installed")
	}
}

func TestExecute_DispatchesRevertContainerImage(t *testing.T) {
	executor := newRevertTestExecutor(t, "100")
	signed := signTestPlan(t, revertPlan("100"), "clu_1", time.Now().Add(time.Minute))

	if _, _, err := executor.Execute(context.Background(), "revert_container_image", mustMarshal(signedPlanArgs{Plan: signed})); err != nil {
		t.Fatalf("Execute(revert_container_image): %v", err)
	}
	if got := liveImageOf(t, executor, "app"); got != goodImage {
		t.Errorf("app image = %q, want %q", got, goodImage)
	}
}

// TestPodTemplateContainerImage_DistinguishesAbsentFromUnreadable pins the
// three-valued contract the history walk depends on: a container that simply
// isn't in a revision is (", false, nil) — ordinary information — while an
// object whose template cannot be read is an error, never a quiet "not there".
func TestPodTemplateContainerImage_DistinguishesAbsentFromUnreadable(t *testing.T) {
	rs := imageTestReplicaSet("web-rev2", testDeploymentUID, goodImage)
	obj := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "apps/v1", "kind": "ReplicaSet",
		"metadata": map[string]any{"name": rs.Name, "namespace": rs.Namespace},
		"spec": map[string]any{"template": map[string]any{"spec": map[string]any{
			"containers": []any{map[string]any{"name": "app", "image": goodImage}},
		}}},
	}}

	image, found, err := podTemplateContainerImage(obj, "app")
	if err != nil || !found || image != goodImage {
		t.Errorf("podTemplateContainerImage(app) = (%q, %v, %v), want (%q, true, nil)", image, found, err, goodImage)
	}

	// Absent container: not an error.
	if _, found, err := podTemplateContainerImage(obj, "added-later"); err != nil || found {
		t.Errorf("podTemplateContainerImage(absent) = (found=%v, err=%v), want (false, nil)", found, err)
	}

	// Unreadable template: an error, not "absent".
	empty := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "apps/v1", "kind": "ReplicaSet",
		"metadata": map[string]any{"name": "x", "namespace": "default"},
		"spec":     map[string]any{},
	}}
	if _, _, err := podTemplateContainerImage(empty, "app"); err == nil {
		t.Error("podTemplateContainerImage on an object with no pod template = nil error, want an error")
	}

	// Present container with no image: an error too — an empty image is never a
	// usable answer, and it is also what a rollback would carry.
	noImage := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "apps/v1", "kind": "ReplicaSet",
		"metadata": map[string]any{"name": "x", "namespace": "default"},
		"spec": map[string]any{"template": map[string]any{"spec": map[string]any{
			"containers": []any{map[string]any{"name": "app"}},
		}}},
	}}
	if _, _, err := podTemplateContainerImage(noImage, "app"); err == nil {
		t.Error("podTemplateContainerImage on a container with no image = nil error, want an error")
	}
}
