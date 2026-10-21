package agent

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	k8sscheme "k8s.io/client-go/kubernetes/scheme"
	k8stesting "k8s.io/client-go/testing"

	"argus/internal/redact"
)

// newDryRunTestExecutor builds a ToolExecutor whose dryRunDynamic (never
// dynamic — dry_run_patch must not be reachable through the ordinary
// read-only/remediation clients) is backed by a fake carrying objs, with
// installRealisticPatchReactor's merge-and-honour-dryRun semantics installed
// (remediation_exec_test.go — reused here rather than reimplemented, so
// dry_run_patch and the four real execution tools are proven against the
// same fake Patch behaviour).
func newDryRunTestExecutor(objs ...runtime.Object) (*ToolExecutor, *dynamicfake.FakeDynamicClient) {
	dyn := dynamicfake.NewSimpleDynamicClient(k8sscheme.Scheme, objs...)
	installRealisticPatchReactor(dyn)
	return NewToolExecutorForTestWithDryRun(nil, nil, dyn), dyn
}

// installDryRunOnlyEnforcingReactor is prepended AFTER
// installRealisticPatchReactor (client-go's fake runs the MOST RECENTLY
// prepended reactor first), so this one sees every Patch call before the
// merge logic does. It fails the test outright — not just an assertion the
// caller might forget to check — the instant a Patch arrives WITHOUT
// dryRun=All, which is exactly the property the task's own verification
// bar asks for: "a fake clientset/interceptor that would fail the test if a
// real mutation flag ever leaked through."
func installDryRunOnlyEnforcingReactor(t *testing.T, dynFake *dynamicfake.FakeDynamicClient) {
	t.Helper()
	dynFake.PrependReactor("patch", "*", func(action k8stesting.Action) (bool, runtime.Object, error) {
		patchAction, ok := action.(k8stesting.PatchActionImpl)
		if !ok {
			return false, nil, nil
		}
		if !slices.Contains(patchAction.PatchOptions.DryRun, metav1.DryRunAll) {
			t.Fatalf("dry_run_patch submitted a Patch WITHOUT dryRun=All (PatchOptions=%+v) against %s %s/%s — this would have been a REAL mutation against a live cluster",
				patchAction.PatchOptions, patchAction.GetResource(), patchAction.GetNamespace(), patchAction.GetName())
		}
		return false, nil, nil // fall through to installRealisticPatchReactor
	})
}

func dryRunPatchArgsJSON(t *testing.T, gvk, namespace, name string, patch map[string]any) json.RawMessage {
	t.Helper()
	patchBytes, err := json.Marshal(patch)
	if err != nil {
		t.Fatalf("marshal patch: %v", err)
	}
	args, err := json.Marshal(dryRunPatchArgs{GVK: gvk, Namespace: namespace, Name: name, Patch: patchBytes})
	if err != nil {
		t.Fatalf("marshal args: %v", err)
	}
	return args
}

// TestDryRunPatch_RefusesWhenNotConfigured is the cluster-side default: no
// argus-dryrun mount, no client, and the tool says so cleanly rather than
// panicking on a nil dereference or returning a generic Kubernetes error
// that would mislead an operator into thinking the cluster itself refused
// the call.
func TestDryRunPatch_RefusesWhenNotConfigured(t *testing.T) {
	e := &ToolExecutor{} // dryRunDynamic is nil — the default, unconfigured state
	_, _, err := e.dryRunPatch(context.Background(), dryRunPatchArgsJSON(t, "apps/v1/Deployment", "default", "web", map[string]any{"spec": map[string]any{"replicas": 3}}))
	if err == nil {
		t.Fatal("dryRunPatch succeeded with no dry-run client configured")
	}
	if err != errDryRunNotConfigured {
		t.Errorf("dryRunPatch error = %v, want errDryRunNotConfigured", err)
	}
}

// TestDryRunPatch_AlwaysSubmitsDryRunAll is this feature's single most
// important proof: every Patch this tool issues carries dryRun=All, with no
// argument path that can ever omit or override it. installDryRunOnlyEnforcingReactor
// would fail this test immediately if that ever stopped being true.
func TestDryRunPatch_AlwaysSubmitsDryRunAll(t *testing.T) {
	dep := testDeployment("web", "default", 2, "100")
	e, dyn := newDryRunTestExecutor(dep)
	installDryRunOnlyEnforcingReactor(t, dyn)

	_, _, err := e.dryRunPatch(context.Background(), dryRunPatchArgsJSON(t, "apps/v1/Deployment", "default", "web", map[string]any{"spec": map[string]any{"replicas": 5}}))
	if err != nil {
		t.Fatalf("dryRunPatch: %v", err)
	}
}

// TestDryRunPatch_AcceptedDoesNotPersistAndReturnsTheResult proves the
// actual safety property, not merely the flag: the stored object is
// unchanged (installRealisticPatchReactor's dry-run branch never calls
// tracker.Update), while the tool still reports acceptance and the
// resulting (unpersisted) object back to the caller — the model needs to
// see what WOULD have happened, distinct from the cluster's live state.
func TestDryRunPatch_AcceptedDoesNotPersistAndReturnsTheResult(t *testing.T) {
	dep := testDeployment("web", "default", 2, "100")
	e, dyn := newDryRunTestExecutor(dep)

	data, truncated, err := e.dryRunPatch(context.Background(), dryRunPatchArgsJSON(t, "apps/v1/Deployment", "default", "web", map[string]any{"spec": map[string]any{"replicas": 9}}))
	if err != nil {
		t.Fatalf("dryRunPatch: %v", err)
	}
	if truncated {
		t.Errorf("truncated = true, want false")
	}

	var result dryRunPatchResult
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}
	if !result.Accepted {
		t.Fatal("Accepted = false, want true")
	}
	if len(result.Object) == 0 {
		t.Fatal("Object is empty — the accepted result must carry the API server's own resulting object")
	}
	var obj map[string]any
	if err := json.Unmarshal(result.Object, &obj); err != nil {
		t.Fatalf("Object does not parse as JSON: %v", err)
	}
	spec, _ := obj["spec"].(map[string]any)
	if spec == nil || spec["replicas"] != float64(9) {
		t.Errorf("Object.spec.replicas = %v, want 9 (the dry-run result should reflect the patch even though it was never persisted)", spec)
	}

	// The live object itself must be untouched.
	live, err := dyn.Resource(schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "deployments"}).
		Namespace("default").Get(context.Background(), "web", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get live object: %v", err)
	}
	liveReplicas, _, _ := unstructuredNestedInt64(live.Object, "spec", "replicas")
	if liveReplicas != 2 {
		t.Errorf("live spec.replicas = %d, want 2 (unchanged) — dry_run_patch must never persist", liveReplicas)
	}
	if live.GetResourceVersion() != "100" {
		t.Errorf("live resourceVersion = %q, want unchanged %q", live.GetResourceVersion(), "100")
	}
}

// unstructuredNestedInt64 is a tiny local helper (k8s' own NestedInt64
// insists on an actual int64, but unstructured JSON round-trips numbers as
// float64) so this file doesn't need a second import for one lookup.
func unstructuredNestedInt64(obj map[string]any, fields ...string) (int64, bool, error) {
	var cur any = obj
	for _, f := range fields {
		m, ok := cur.(map[string]any)
		if !ok {
			return 0, false, nil
		}
		cur, ok = m[f]
		if !ok {
			return 0, false, nil
		}
	}
	switch v := cur.(type) {
	case float64:
		return int64(v), true, nil
	case int64:
		return v, true, nil
	default:
		return 0, false, nil
	}
}

// TestDryRunPatch_AdmissionRejectionSurfacesTheClustersOwnReason proves the
// other half of what makes this tool worth having: a rejection is not a
// generic failure, it is the cluster's OWN explanation, passed through
// admissionRejection's existing bounded/flattened discipline (already
// covered generically by TestAdmissionRejection_* elsewhere in this
// package) — this test only proves dry_run_patch actually routes through
// that same function rather than a bespoke path.
func TestDryRunPatch_AdmissionRejectionSurfacesTheClustersOwnReason(t *testing.T) {
	dep := testDeployment("web", "default", 2, "100")
	dyn := dynamicfake.NewSimpleDynamicClient(k8sscheme.Scheme, dep)
	dyn.PrependReactor("patch", "deployments", func(action k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewInvalid(
			schema.GroupKind{Group: "apps", Kind: "Deployment"}, "web",
			nil, // field.ErrorList — nil is fine, NewInvalid still renders a message naming the resource
		)
	})
	e := NewToolExecutorForTestWithDryRun(nil, nil, dyn)

	_, _, err := e.dryRunPatch(context.Background(), dryRunPatchArgsJSON(t, "apps/v1/Deployment", "default", "web", map[string]any{"spec": map[string]any{"replicas": 3}}))
	if err == nil {
		t.Fatal("dryRunPatch succeeded, want an admission rejection")
	}
	if !strings.Contains(err.Error(), "the cluster would reject this change") {
		t.Errorf("error = %q, want it to carry the cluster's own rejection reason", err.Error())
	}
}

// TestDryRunPatch_UnsupportedResourceRejectedBeforeAnyAPICall proves the
// agent-side allowlist (dryRunPatchAllowedResources) is independently
// enforced — a resource the argus-dryrun ClusterRole was never granted on
// (e.g. a bare Pod) is refused with a clear, specific error rather than
// ever reaching e.dryRunDynamic at all.
func TestDryRunPatch_UnsupportedResourceRejectedBeforeAnyAPICall(t *testing.T) {
	e, dyn := newDryRunTestExecutor()
	dyn.PrependReactor("patch", "*", func(action k8stesting.Action) (bool, runtime.Object, error) {
		t.Fatal("dryRunPatch reached the API server for an unsupported resource — the allowlist check must happen first")
		return true, nil, nil
	})

	_, _, err := e.dryRunPatch(context.Background(), dryRunPatchArgsJSON(t, "v1/Pod", "default", "web", map[string]any{"spec": map[string]any{}}))
	if err == nil {
		t.Fatal("dryRunPatch succeeded for v1/Pod, want a refusal")
	}
	if !strings.Contains(err.Error(), "does not support") {
		t.Errorf("error = %q, want it to name the unsupported resource", err.Error())
	}
}

// TestDryRunPatch_RequiresNonEmptyPatch guards against a caller that
// forgets the one field that actually matters — an empty or missing patch
// would otherwise be a no-op dry run that tells the model nothing.
func TestDryRunPatch_RequiresNonEmptyPatch(t *testing.T) {
	e, _ := newDryRunTestExecutor(testDeployment("web", "default", 2, "100"))
	args, err := json.Marshal(dryRunPatchArgs{GVK: "apps/v1/Deployment", Namespace: "default", Name: "web"})
	if err != nil {
		t.Fatalf("marshal args: %v", err)
	}
	if _, _, err := e.dryRunPatch(context.Background(), args); err == nil {
		t.Fatal("dryRunPatch succeeded with an empty patch body, want a refusal")
	}
}

// TestDryRunPatch_RedactsSecretShapedValueInTheAcceptedObject is BUGS.md
// 84's proof style, applied to this tool's own accepted-response path: a
// canary planted in the object's env value must not survive Execute's
// redact.Object chokepoint, exactly as it must not for the six read-only
// tools (redact_egress_test.go) or for the real execution tools' own
// dry-run diff (planPatchResult's Object field, tools.go). Driven through
// Execute — the real entry point client.go's executeToolRequest uses — not
// through dryRunPatch directly, so a future refactor that bypasses Execute
// would fail this test the same way TestExecuteIsTheRedactionChokepoint
// fails for the read-only tools.
func TestDryRunPatch_RedactsSecretShapedValueInTheAcceptedObject(t *testing.T) {
	dep := &appsv1.Deployment{
		TypeMeta:   metav1.TypeMeta{APIVersion: "apps/v1", Kind: "Deployment"},
		ObjectMeta: metav1.ObjectMeta{Name: "payments", Namespace: "prod", ResourceVersion: "1"},
		Spec: appsv1.DeploymentSpec{
			Replicas: int32Ptr(1),
			Template: corev1.PodTemplateSpec{
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{{
						Name:  "app",
						Image: "registry.io/payments:1.0",
						Env: []corev1.EnvVar{
							{Name: "DB_PASSWORD", Value: egressCanary},
						},
					}},
				},
			},
		},
	}
	dyn := dynamicfake.NewSimpleDynamicClient(k8sscheme.Scheme, dep)
	installRealisticPatchReactor(dyn)
	e := NewToolExecutorForTestWithDryRun(nil, nil, dyn)

	args := dryRunPatchArgsJSON(t, "apps/v1/Deployment", "prod", "payments", map[string]any{"spec": map[string]any{"replicas": 2}})

	// First prove the fixture actually carries the canary through the
	// UNWRAPPED dispatch — otherwise a later "redacted" assertion would be
	// vacuous, the exact failure mode TestExecuteIsTheRedactionChokepoint's
	// own comment warns about.
	rawData, _, err := e.executeTool(context.Background(), "dry_run_patch", args)
	if err != nil {
		t.Fatalf("executeTool: %v", err)
	}
	if !strings.Contains(string(rawData), egressCanary) {
		t.Fatal("the unwrapped dry_run_patch result did NOT contain the canary — the fixture is not planting secret material, so this test would prove nothing")
	}

	redactedData, _, err := e.Execute(context.Background(), "dry_run_patch", args)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if strings.Contains(string(redactedData), egressCanary) {
		t.Fatalf("Execute did not redact dry_run_patch's accepted object.\noutput: %s", redactedData)
	}
	if !redact.ContainsMarker(string(redactedData)) {
		t.Errorf("expected a redaction marker, got: %s", redactedData)
	}
	// The shape must survive redaction, or the fix traded a leak for a
	// blind spot the model can no longer reason about at all.
	for _, want := range []string{"DB_PASSWORD", "registry.io/payments:1.0", `"accepted":true`} {
		if !strings.Contains(string(redactedData), want) {
			t.Errorf("expected %q to survive redaction, output: %s", want, redactedData)
		}
	}
}

// TestDryRunPatch_RejectionPathNeverCarriesTheFullObject is the rejected
// half of the same BUGS.md 84 discipline, proven differently because a
// rejection is a Go error, not JSON data (Execute's own doc comment: errors
// deliberately do not go through redact.Object — admissionRejection's
// bounded, flattened passthrough is the control on that path instead,
// already proven generically by TestAdmissionRejection_IsBounded/
// IsSingleLine elsewhere in this package). What THIS test adds is specific
// to dry_run_patch: proving its own error path never echoes the submitted
// patch body or the live object verbatim — only the cluster's own
// (bounded) admission message — so a secret-shaped value in either could
// not survive even if it wanted to.
func TestDryRunPatch_RejectionPathNeverCarriesTheFullObject(t *testing.T) {
	dep := &appsv1.Deployment{
		TypeMeta:   metav1.TypeMeta{APIVersion: "apps/v1", Kind: "Deployment"},
		ObjectMeta: metav1.ObjectMeta{Name: "payments", Namespace: "prod", ResourceVersion: "1"},
		Spec: appsv1.DeploymentSpec{
			Replicas: int32Ptr(1),
			Template: corev1.PodTemplateSpec{
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{{
						Name:  "app",
						Image: "registry.io/payments:1.0",
						Env:   []corev1.EnvVar{{Name: "DB_PASSWORD", Value: egressCanary}},
					}},
				},
			},
		},
	}
	dyn := dynamicfake.NewSimpleDynamicClient(k8sscheme.Scheme, dep)
	dyn.PrependReactor("patch", "deployments", func(action k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewInvalid(schema.GroupKind{Group: "apps", Kind: "Deployment"}, "payments", nil)
	})
	e := NewToolExecutorForTestWithDryRun(nil, nil, dyn)

	args := dryRunPatchArgsJSON(t, "apps/v1/Deployment", "prod", "payments", map[string]any{"spec": map[string]any{"replicas": 2}})
	_, _, err := e.Execute(context.Background(), "dry_run_patch", args)
	if err == nil {
		t.Fatal("Execute succeeded, want a rejection")
	}
	if strings.Contains(err.Error(), egressCanary) {
		t.Fatalf("rejection error carries the canary — the rejection path must never echo the live object: %v", err)
	}
}
