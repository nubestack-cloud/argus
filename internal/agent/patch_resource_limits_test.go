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
	"k8s.io/apimachinery/pkg/runtime/schema"

	"argus/internal/remediation"
)

// deploymentsGVR is the same GVR supportedGVKs maps apps/v1 Deployment to —
// spelled out here so these tests can re-read the patched object directly
// from the fake's tracker without going through a tool.
var deploymentsGVR = schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "deployments"}

// These tests exercise patch_resource_limits through the same fake-clientset
// seam scale_deployment/restart_pod use (newRemediationTestExecutor +
// installRealisticPatchReactor, in remediation_exec_test.go), so the patch
// really is issued, the resourceVersion precondition really is enforced, and
// the merged result can be inspected afterwards.
//
// The fault this action exists for, reproduced as the fixture: a container
// OOMKilled against a 32Mi memory limit, on a two-container pod template, so
// every test can also check that the sibling container and the patched
// container's OTHER fields (image above all) came through untouched.

// testWorkloadWithResources builds a two-container Deployment where the first
// container carries the too-small limit and a matching request, and the
// second exists purely so the tests can prove it was not collateral damage.
func testWorkloadWithResources(name, namespace, resourceVersion string) *appsv1.Deployment {
	container := func(cName, image, memLimit, memRequest, cpuLimit, cpuRequest string) corev1.Container {
		c := corev1.Container{
			Name:  cName,
			Image: image,
			Resources: corev1.ResourceRequirements{
				Limits:   corev1.ResourceList{},
				Requests: corev1.ResourceList{},
			},
		}
		if memLimit != "" {
			c.Resources.Limits[corev1.ResourceMemory] = resource.MustParse(memLimit)
		}
		if cpuLimit != "" {
			c.Resources.Limits[corev1.ResourceCPU] = resource.MustParse(cpuLimit)
		}
		if memRequest != "" {
			c.Resources.Requests[corev1.ResourceMemory] = resource.MustParse(memRequest)
		}
		if cpuRequest != "" {
			c.Resources.Requests[corev1.ResourceCPU] = resource.MustParse(cpuRequest)
		}
		return c
	}
	replicas := int32(2)
	return &appsv1.Deployment{
		TypeMeta:   metav1.TypeMeta{APIVersion: "apps/v1", Kind: "Deployment"},
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace, ResourceVersion: resourceVersion},
		Spec: appsv1.DeploymentSpec{
			Replicas: &replicas,
			Template: corev1.PodTemplateSpec{
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						container("app", "registry.example.com/app:1.2.3", "32Mi", "32Mi", "500m", "100m"),
						container("sidecar", "registry.example.com/log-shipper:0.9.0", "64Mi", "64Mi", "", ""),
					},
				},
			},
		},
	}
}

// patchLimitsPlan is the happy-path envelope content: raise container "app"'s
// memory limit from the 32Mi it is being OOMKilled against to 256Mi, with the
// compensating action the hub would have captured from the live object.
func patchLimitsPlan(rv string) remediation.PlanContent {
	return remediation.PlanContent{
		RecommendationID: "plan_1",
		ActionType:       remediation.ActionPatchResourceLimits,
		TargetGVK:        "apps/v1/Deployment",
		TargetNamespace:  "default",
		TargetName:       "web",
		Params:           mustMarshal(remediation.PatchResourceLimitsParams{Container: "app", MemoryLimit: "256Mi"}),
		Rollback: &remediation.CompensatingAction{
			ActionType:  remediation.ActionPatchResourceLimits,
			Params:      mustMarshal(remediation.PatchResourceLimitsParams{Container: "app", MemoryLimit: "32Mi"}),
			Description: `restore container "app" to memory limit 32Mi`,
		},
		ResourceVersion: rv,
	}
}

// liveContainer re-reads one container out of the fake's tracker so a test can
// assert on what the patch actually produced, rather than on what it sent.
func liveContainer(t *testing.T, e *ToolExecutor, name string) map[string]any {
	t.Helper()
	obj, err := e.dynamic.Resource(deploymentsGVR).Namespace("default").Get(context.Background(), "web", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("re-read deployment: %v", err)
	}
	containers, found, err := unstructured.NestedSlice(obj.Object, "spec", "template", "spec", "containers")
	if err != nil || !found {
		t.Fatalf("re-read containers: found=%v err=%v", found, err)
	}
	for _, raw := range containers {
		c, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		if got, _ := c["name"].(string); got == name {
			return c
		}
	}
	t.Fatalf("container %q not found on the live object after patching", name)
	return nil
}

func containerQuantity(t *testing.T, container map[string]any, kind, resourceName string) string {
	t.Helper()
	m, _, _ := unstructured.NestedStringMap(container, "resources", kind)
	return m[resourceName]
}

func TestPatchResourceLimits_ValidSignedPlanPatchesOnlyTheNamedQuantity(t *testing.T) {
	executor := newRemediationTestExecutor("clu_1", testWorkloadWithResources("web", "default", "100"))
	signed := signTestPlan(t, patchLimitsPlan("100"), "clu_1", time.Now().Add(5*time.Minute))

	data, truncated, err := executor.patchResourceLimits(context.Background(), mustMarshal(signedPlanArgs{Plan: signed}))
	if err != nil {
		t.Fatalf("patchResourceLimits: %v", err)
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

	app := liveContainer(t, executor, "app")
	if got := containerQuantity(t, app, "limits", "memory"); got != "256Mi" {
		t.Errorf("app limits.memory = %q, want 256Mi", got)
	}
	// The three quantities the plan never mentioned must survive the patch —
	// this is the property that makes a merge-key strategic patch the right
	// mechanism, and the one a whole-list replacement would silently break.
	if got := containerQuantity(t, app, "requests", "memory"); got != "32Mi" {
		t.Errorf("app requests.memory = %q, want it untouched at 32Mi", got)
	}
	if got := containerQuantity(t, app, "limits", "cpu"); got != "500m" {
		t.Errorf("app limits.cpu = %q, want it untouched at 500m", got)
	}
	if got := containerQuantity(t, app, "requests", "cpu"); got != "100m" {
		t.Errorf("app requests.cpu = %q, want it untouched at 100m", got)
	}
	// And the fields this action must never be able to reach, on the very
	// container it did patch.
	if got, _ := app["image"].(string); got != "registry.example.com/app:1.2.3" {
		t.Errorf("app image = %q, want it untouched", got)
	}

	sidecar := liveContainer(t, executor, "sidecar")
	if got, _ := sidecar["image"].(string); got != "registry.example.com/log-shipper:0.9.0" {
		t.Errorf("sidecar image = %q, want it untouched", got)
	}
	if got := containerQuantity(t, sidecar, "limits", "memory"); got != "64Mi" {
		t.Errorf("sidecar limits.memory = %q, want it untouched at 64Mi", got)
	}
}

func TestPatchResourceLimits_SetsBothRequestAndLimit(t *testing.T) {
	executor := newRemediationTestExecutor("clu_1", testWorkloadWithResources("web", "default", "100"))
	content := patchLimitsPlan("100")
	content.Params = mustMarshal(remediation.PatchResourceLimitsParams{
		Container: "app", MemoryLimit: "256Mi", MemoryRequest: "64Mi",
	})
	content.Rollback.Params = mustMarshal(remediation.PatchResourceLimitsParams{
		Container: "app", MemoryLimit: "32Mi", MemoryRequest: "32Mi",
	})
	signed := signTestPlan(t, content, "clu_1", time.Now().Add(5*time.Minute))

	if _, _, err := executor.patchResourceLimits(context.Background(), mustMarshal(signedPlanArgs{Plan: signed})); err != nil {
		t.Fatalf("patchResourceLimits: %v", err)
	}
	app := liveContainer(t, executor, "app")
	if got := containerQuantity(t, app, "limits", "memory"); got != "256Mi" {
		t.Errorf("app limits.memory = %q, want 256Mi", got)
	}
	if got := containerQuantity(t, app, "requests", "memory"); got != "64Mi" {
		t.Errorf("app requests.memory = %q, want 64Mi", got)
	}
}

func TestPatchResourceLimits_RejectsTamperedParams(t *testing.T) {
	executor := newRemediationTestExecutor("clu_1", testWorkloadWithResources("web", "default", "100"))
	signed := signTestPlan(t, patchLimitsPlan("100"), "clu_1", time.Now().Add(5*time.Minute))

	// Post-signing tampering: the envelope is otherwise exactly what the hub
	// produced, and the requested value is even within bounds — the only
	// thing wrong with it is that nobody signed THIS version.
	signed.Params = mustMarshal(remediation.PatchResourceLimitsParams{Container: "app", MemoryLimit: "1Gi"})

	if _, _, err := executor.patchResourceLimits(context.Background(), mustMarshal(signedPlanArgs{Plan: signed})); err == nil {
		t.Fatal("patchResourceLimits accepted a plan whose params were tampered with after signing")
	}
	if got := containerQuantity(t, liveContainer(t, executor, "app"), "limits", "memory"); got != "32Mi" {
		t.Errorf("app limits.memory = %q, want the original 32Mi — the rejected plan must not have been applied", got)
	}
}

// TestPatchResourceLimits_RejectsTamperedRollback is the same attack aimed at
// the field this action type newly depends on: strip or rewrite the
// compensating action and the signature must stop being valid, which is the
// reason Rollback lives inside PlanContent rather than beside it.
func TestPatchResourceLimits_RejectsTamperedRollback(t *testing.T) {
	executor := newRemediationTestExecutor("clu_1", testWorkloadWithResources("web", "default", "100"))
	signed := signTestPlan(t, patchLimitsPlan("100"), "clu_1", time.Now().Add(5*time.Minute))
	signed.Rollback = nil

	if _, _, err := executor.patchResourceLimits(context.Background(), mustMarshal(signedPlanArgs{Plan: signed})); err == nil {
		t.Fatal("patchResourceLimits accepted a plan whose rollback was stripped after signing")
	}
}

// TestPatchResourceLimits_RejectsMissingRollback is the unsigned-omission
// case: a validly signed envelope that never carried a rollback at all. This
// is the check that makes §10.3's "captured before execution" an enforced
// property rather than a convention the hub is trusted to follow.
func TestPatchResourceLimits_RejectsMissingRollback(t *testing.T) {
	executor := newRemediationTestExecutor("clu_1", testWorkloadWithResources("web", "default", "100"))
	content := patchLimitsPlan("100")
	content.Rollback = nil
	signed := signTestPlan(t, content, "clu_1", time.Now().Add(5*time.Minute))

	if _, _, err := executor.patchResourceLimits(context.Background(), mustMarshal(signedPlanArgs{Plan: signed})); err == nil {
		t.Fatal("patchResourceLimits executed a plan with no pre-computed rollback")
	}
}

// TestPatchResourceLimits_RejectsRollbackThatDisagreesWithLiveState covers the
// case a signature cannot: a rollback that is correctly signed but describes
// values the live container does not hold, i.e. an undo that would put the
// workload into a state it was never in.
func TestPatchResourceLimits_RejectsRollbackThatDisagreesWithLiveState(t *testing.T) {
	executor := newRemediationTestExecutor("clu_1", testWorkloadWithResources("web", "default", "100"))
	content := patchLimitsPlan("100")
	content.Rollback.Params = mustMarshal(remediation.PatchResourceLimitsParams{Container: "app", MemoryLimit: "128Mi"})
	signed := signTestPlan(t, content, "clu_1", time.Now().Add(5*time.Minute))

	if _, _, err := executor.patchResourceLimits(context.Background(), mustMarshal(signedPlanArgs{Plan: signed})); err == nil {
		t.Fatal("patchResourceLimits accepted a rollback that does not match the live container's values")
	}
}

func TestPatchResourceLimits_StaleResourceVersionFailsClosed(t *testing.T) {
	executor := newRemediationTestExecutor("clu_1", testWorkloadWithResources("web", "default", "100"))
	signed := signTestPlan(t, patchLimitsPlan("99-since-superseded"), "clu_1", time.Now().Add(5*time.Minute))

	if _, _, err := executor.patchResourceLimits(context.Background(), mustMarshal(signedPlanArgs{Plan: signed})); err == nil {
		t.Fatal("patchResourceLimits succeeded despite a stale resourceVersion precondition")
	}
	if got := containerQuantity(t, liveContainer(t, executor, "app"), "limits", "memory"); got != "32Mi" {
		t.Errorf("app limits.memory = %q, want the original 32Mi", got)
	}
}

func TestPatchResourceLimits_RejectsOutOfBoundsValues(t *testing.T) {
	cases := []struct {
		name   string
		params remediation.PatchResourceLimitsParams
	}{
		{"memory limit in the terabytes", remediation.PatchResourceLimitsParams{Container: "app", MemoryLimit: "2Ti"}},
		{"memory limit below the floor", remediation.PatchResourceLimitsParams{Container: "app", MemoryLimit: "1Mi"}},
		{"cpu limit above the ceiling", remediation.PatchResourceLimitsParams{Container: "app", CPULimit: "128"}},
		{"unparseable quantity", remediation.PatchResourceLimitsParams{Container: "app", MemoryLimit: "lots"}},
		{"negative quantity", remediation.PatchResourceLimitsParams{Container: "app", MemoryLimit: "-256Mi"}},
		{"no fields set", remediation.PatchResourceLimitsParams{Container: "app"}},
		{"empty container name", remediation.PatchResourceLimitsParams{MemoryLimit: "256Mi"}},
		{"requests above limits", remediation.PatchResourceLimitsParams{Container: "app", MemoryLimit: "64Mi", MemoryRequest: "256Mi"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			executor := newRemediationTestExecutor("clu_1", testWorkloadWithResources("web", "default", "100"))
			content := patchLimitsPlan("100")
			content.Params = mustMarshal(c.params)
			// Signed properly: the point is that a correctly signed plan is
			// still refused on its VALUES, agent-side, without consulting the
			// hub about whether it meant it.
			signed := signTestPlan(t, content, "clu_1", time.Now().Add(5*time.Minute))

			if _, _, err := executor.patchResourceLimits(context.Background(), mustMarshal(signedPlanArgs{Plan: signed})); err == nil {
				t.Fatalf("patchResourceLimits accepted %s", c.name)
			}
			if got := containerQuantity(t, liveContainer(t, executor, "app"), "limits", "memory"); got != "32Mi" {
				t.Errorf("app limits.memory = %q, want the original 32Mi", got)
			}
		})
	}
}

// TestPatchResourceLimits_RejectsUnknownContainer is the most important
// negative test in this file. A strategic-merge patch keyed on an unmatched
// container name APPENDS a container rather than failing — the fake's own
// reactor reproduces that (see mergeByName) — so without the live-object
// check this plan would "succeed" by adding a third, imageless container to
// somebody's pod template.
func TestPatchResourceLimits_RejectsUnknownContainer(t *testing.T) {
	executor := newRemediationTestExecutor("clu_1", testWorkloadWithResources("web", "default", "100"))
	content := patchLimitsPlan("100")
	content.Params = mustMarshal(remediation.PatchResourceLimitsParams{Container: "not-a-container", MemoryLimit: "256Mi"})
	content.Rollback.Params = mustMarshal(remediation.PatchResourceLimitsParams{Container: "not-a-container", MemoryLimit: "32Mi"})
	signed := signTestPlan(t, content, "clu_1", time.Now().Add(5*time.Minute))

	if _, _, err := executor.patchResourceLimits(context.Background(), mustMarshal(signedPlanArgs{Plan: signed})); err == nil {
		t.Fatal("patchResourceLimits accepted a plan naming a container that does not exist")
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

// TestPatchResourceLimits_RejectsFieldNotAlreadySet: this action never
// introduces a request or limit that isn't there, because doing so changes the
// pod's QoS class and because the undo would have to express a deletion.
func TestPatchResourceLimits_RejectsFieldNotAlreadySet(t *testing.T) {
	executor := newRemediationTestExecutor("clu_1", testWorkloadWithResources("web", "default", "100"))
	content := patchLimitsPlan("100")
	// "sidecar" has memory limits/requests but no CPU values at all.
	content.Params = mustMarshal(remediation.PatchResourceLimitsParams{Container: "sidecar", CPULimit: "500m"})
	content.Rollback.Params = mustMarshal(remediation.PatchResourceLimitsParams{Container: "sidecar", CPULimit: "250m"})
	signed := signTestPlan(t, content, "clu_1", time.Now().Add(5*time.Minute))

	if _, _, err := executor.patchResourceLimits(context.Background(), mustMarshal(signedPlanArgs{Plan: signed})); err == nil {
		t.Fatal("patchResourceLimits introduced a CPU limit where the live container had none")
	}
}

func TestPatchResourceLimits_RejectsWrongActionTypeEnvelope(t *testing.T) {
	executor := newRemediationTestExecutor("clu_1", testWorkloadWithResources("web", "default", "100"))
	content := patchLimitsPlan("100")
	content.ActionType = remediation.ActionScaleDeployment
	signed := signTestPlan(t, content, "clu_1", time.Now().Add(5*time.Minute))

	if _, _, err := executor.patchResourceLimits(context.Background(), mustMarshal(signedPlanArgs{Plan: signed})); err == nil {
		t.Fatal("patchResourceLimits honored a validly-signed ScaleDeployment envelope")
	}
}

func TestPatchResourceLimits_RejectsWrongClusterAndExpiredPlans(t *testing.T) {
	executor := newRemediationTestExecutor("clu_1", testWorkloadWithResources("web", "default", "100"))

	wrongCluster := signTestPlan(t, patchLimitsPlan("100"), "clu_OTHER", time.Now().Add(5*time.Minute))
	if _, _, err := executor.patchResourceLimits(context.Background(), mustMarshal(signedPlanArgs{Plan: wrongCluster})); err == nil {
		t.Error("patchResourceLimits accepted a plan signed for a different cluster")
	}

	expired := signTestPlan(t, patchLimitsPlan("100"), "clu_1", time.Now().Add(-time.Minute))
	if _, _, err := executor.patchResourceLimits(context.Background(), mustMarshal(signedPlanArgs{Plan: expired})); err == nil {
		t.Error("patchResourceLimits accepted an expired plan")
	}
}

// TestPatchResourceLimits_RejectsUnsupportedKind: a DaemonSet has a pod
// template, so this action would be meaningful on one — but neither the
// argus-remediate ClusterRole nor the ValidatingAdmissionPolicy covers
// daemonsets, so it is refused here rather than by a 403 after the hub has
// already committed the incident to Executing.
func TestPatchResourceLimits_RejectsUnsupportedKind(t *testing.T) {
	executor := newRemediationTestExecutor("clu_1")
	content := patchLimitsPlan("100")
	content.TargetGVK = "apps/v1/DaemonSet"
	signed := signTestPlan(t, content, "clu_1", time.Now().Add(5*time.Minute))

	if _, _, err := executor.patchResourceLimits(context.Background(), mustMarshal(signedPlanArgs{Plan: signed})); err == nil {
		t.Fatal("patchResourceLimits accepted a DaemonSet target")
	}
}

func TestPatchResourceLimits_RejectsWithoutCredentials(t *testing.T) {
	executor := newRemediationTestExecutor("clu_1", testWorkloadWithResources("web", "default", "100"))
	executor.SetRemediationCredentials("", nil) // as if enrollment never delivered a key

	signed := signTestPlan(t, patchLimitsPlan("100"), "clu_1", time.Now().Add(5*time.Minute))
	if _, _, err := executor.patchResourceLimits(context.Background(), mustMarshal(signedPlanArgs{Plan: signed})); err == nil {
		t.Fatal("patchResourceLimits executed against an executor with no remediation credentials installed")
	}
}

func TestExecute_DispatchesPatchResourceLimits(t *testing.T) {
	executor := newRemediationTestExecutor("clu_1", testWorkloadWithResources("web", "default", "100"))
	signed := signTestPlan(t, patchLimitsPlan("100"), "clu_1", time.Now().Add(time.Minute))

	if _, _, err := executor.Execute(context.Background(), "patch_resource_limits", mustMarshal(signedPlanArgs{Plan: signed})); err != nil {
		t.Fatalf("Execute(patch_resource_limits): %v", err)
	}
	if got := containerQuantity(t, liveContainer(t, executor, "app"), "limits", "memory"); got != "256Mi" {
		t.Errorf("app limits.memory = %q, want 256Mi", got)
	}
}
