package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/validation/field"
	k8sscheme "k8s.io/client-go/kubernetes/scheme"
	k8stesting "k8s.io/client-go/testing"

	dynamicfake "k8s.io/client-go/dynamic/fake"

	"argus/internal/remediation"
)

const testPlanSigningKey = "a-32-byte-per-cluster-test-key!!"

// newRemediationTestExecutor builds a ToolExecutor with remediation
// credentials already installed (SetRemediationCredentials), backed by a
// fake dynamic client with a realistic Patch reactor installed (see
// installRealisticPatchReactor) — the bare fake tracker's own
// StrategicMergePatchType support only works against real typed Go structs
// (it errors on the Unstructured objects a dynamic client always deals in,
// which is exactly what this file's Patch calls do against a real
// cluster's API server just fine, since there the server-side OpenAPI
// schema does the merging, not client-side reflection).
func newRemediationTestExecutor(clusterID string, objs ...runtime.Object) *ToolExecutor {
	dyn := dynamicfake.NewSimpleDynamicClient(k8sscheme.Scheme, objs...)
	installRealisticPatchReactor(dyn)
	e := &ToolExecutor{dynamic: dyn}
	e.SetRemediationCredentials(clusterID, []byte(testPlanSigningKey))
	return e
}

// installRealisticPatchReactor replaces the fake dynamic client's default
// "patch" handling with one that: (1) enforces the same resourceVersion
// precondition a real API server enforces when a strategic-merge/merge
// patch body embeds metadata.resourceVersion (lld/08 §5's whole premise —
// mismatched precondition -> 409 Conflict, never silently applied), and
// (2) otherwise deep-merges the patch body into the live object and bumps
// its resourceVersion, standing in for the API server's own merge (which
// this specific fake cannot do for Unstructured objects — see this file's
// header comment). Good enough for the flat replicas/annotations shapes
// scale_deployment/restart_pod send, plus the ONE merge-key list case
// patch_resource_limits needs (see deepMergeInto's containers handling) —
// still not a general strategic-merge implementation, and deliberately not
// one: a fake that reimplemented the whole algorithm would be a second thing
// to be wrong.
func installRealisticPatchReactor(dynFake *dynamicfake.FakeDynamicClient) {
	dynFake.PrependReactor("patch", "*", func(action k8stesting.Action) (bool, runtime.Object, error) {
		patchAction, ok := action.(k8stesting.PatchAction)
		if !ok {
			return false, nil, nil
		}
		tracker := dynFake.Tracker()
		existing, err := tracker.Get(patchAction.GetResource(), patchAction.GetNamespace(), patchAction.GetName())
		if err != nil {
			return true, nil, err
		}
		u, ok := existing.(*unstructured.Unstructured)
		if !ok {
			return true, nil, fmt.Errorf("installRealisticPatchReactor: object is not unstructured")
		}

		var patchMap map[string]any
		if err := json.Unmarshal(patchAction.GetPatch(), &patchMap); err != nil {
			return true, nil, err
		}
		if patchMeta, ok := patchMap["metadata"].(map[string]any); ok {
			if wantRV, ok := patchMeta["resourceVersion"].(string); ok && wantRV != u.GetResourceVersion() {
				gvr := patchAction.GetResource()
				return true, nil, apierrors.NewConflict(gvr.GroupResource(), patchAction.GetName(),
					fmt.Errorf("the object has been modified; please apply your changes to the latest version and try again"))
			}
		}
		deepMergeInto(u.Object, patchMap)
		u.SetResourceVersion(u.GetResourceVersion() + "1") // any deterministic change is enough to prove a real bump happened

		// (3) Honour dryRun=All by returning the merged object WITHOUT
		// persisting it — which is exactly what a real API server does, and
		// what the fake dynamic client's own tracker does not (it applies the
		// write regardless of PatchOptions). Modeling it here is what lets a
		// test assert the property that actually matters — "the stored object
		// did not change" — instead of the much weaker "the right flag was
		// passed". A gate that submitted dryRun=All and mutated anyway would
		// pass the weak assertion.
		//
		// This models the *persistence* half of dry-run only. The other half —
		// that admission control still runs and can still reject — has no fake
		// to model it, so it is proven on a live cluster instead (WORKLOG).
		if opts, ok := action.(k8stesting.PatchActionImpl); ok && slices.Contains(opts.PatchOptions.DryRun, metav1.DryRunAll) {
			return true, u, nil
		}

		if err := tracker.Update(patchAction.GetResource(), u, patchAction.GetNamespace()); err != nil {
			return true, nil, err
		}
		return true, u, nil
	})
}

// deepMergeInto recursively merges src into dst in place (RFC 7396 JSON
// Merge Patch semantics: a nil value would delete a key, though nothing in
// this file's patches ever sends one) — dst is a live Unstructured.Object
// map, mutated directly.
//
// With ONE strategic-merge deviation from RFC 7396, added for
// patch_resource_limits: a "containers" list is merged by each element's
// `name` rather than replaced wholesale. That deviation is the entire point
// of the test, not a convenience — a plain merge-patch would replace the
// pod template's container list with the patch's single-element one, which
// would make the test pass while proving the opposite of what a real API
// server does (Kubernetes declares `name` as the strategic merge key for
// this list, which is why the production patch can name one container and
// leave its siblings, and every other field of the named container, alone).
// Without this, a test asserting "the sibling container was untouched" would
// be asserting against the fake's behaviour instead of Kubernetes'.
//
// An unmatched name APPENDS, exactly as a real strategic merge does — which
// is the behaviour patchResourceLimits' live-container check exists to
// prevent, so the fake has to be able to do the wrong thing for the test
// that proves we refuse to ask for it.
func deepMergeInto(dst, src map[string]any) {
	for k, v := range src {
		if srcMap, ok := v.(map[string]any); ok {
			if dstMap, ok := dst[k].(map[string]any); ok {
				deepMergeInto(dstMap, srcMap)
				continue
			}
		}
		if k == "containers" {
			if srcList, ok := v.([]any); ok {
				if dstList, ok := dst[k].([]any); ok {
					dst[k] = mergeByName(dstList, srcList)
					continue
				}
			}
		}
		dst[k] = v
	}
}

// mergeByName merges src into dst by each element's "name" key, appending
// elements whose name matches nothing — Kubernetes' strategic-merge
// semantics for a list whose patchMergeKey is `name`.
func mergeByName(dst, src []any) []any {
	for _, rawSrc := range src {
		srcItem, ok := rawSrc.(map[string]any)
		if !ok {
			continue
		}
		srcName, _ := srcItem["name"].(string)
		merged := false
		for _, rawDst := range dst {
			dstItem, ok := rawDst.(map[string]any)
			if !ok {
				continue
			}
			if name, _ := dstItem["name"].(string); name == srcName {
				deepMergeInto(dstItem, srcItem)
				merged = true
				break
			}
		}
		if !merged {
			dst = append(dst, srcItem)
		}
	}
	return dst
}

func signTestPlan(t *testing.T, content remediation.PlanContent, clusterID string, expiresAt time.Time) remediation.SignedPlan {
	t.Helper()
	signed, err := remediation.Sign(content, clusterID, expiresAt, []byte(testPlanSigningKey))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	return signed
}

func testDeployment(name, namespace string, replicas int32, resourceVersion string) *appsv1.Deployment {
	return &appsv1.Deployment{
		TypeMeta:   metav1.TypeMeta{APIVersion: "apps/v1", Kind: "Deployment"},
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace, ResourceVersion: resourceVersion},
		Spec:       appsv1.DeploymentSpec{Replicas: &replicas},
	}
}

func TestScaleDeployment_ValidSignedPlanPatches(t *testing.T) {
	dep := testDeployment("web", "default", 2, "100")
	executor := newRemediationTestExecutor("clu_1", dep)

	content := remediation.PlanContent{
		RecommendationID: "plan_1",
		ActionType:       remediation.ActionScaleDeployment,
		TargetGVK:        "apps/v1/Deployment",
		TargetNamespace:  "default",
		TargetName:       "web",
		Params:           mustMarshal(map[string]any{"replicas": 4}),
		ResourceVersion:  "100",
	}
	signed := signTestPlan(t, content, "clu_1", time.Now().Add(5*time.Minute))

	data, truncated, err := executor.scaleDeployment(context.Background(), mustMarshal(signedPlanArgs{Plan: signed}))
	if err != nil {
		t.Fatalf("scaleDeployment: %v", err)
	}
	if truncated {
		t.Errorf("scaleDeployment: truncated = true, want false")
	}
	var result executeResult
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("decode result: %v", err)
	}
	if result.ResourceVersion == "" {
		t.Errorf("scaleDeployment: result has no resourceVersion")
	}
}

func TestScaleDeployment_RejectsTamperedParams(t *testing.T) {
	dep := testDeployment("web", "default", 2, "100")
	executor := newRemediationTestExecutor("clu_1", dep)

	content := remediation.PlanContent{
		RecommendationID: "plan_1",
		ActionType:       remediation.ActionScaleDeployment,
		TargetGVK:        "apps/v1/Deployment",
		TargetNamespace:  "default",
		TargetName:       "web",
		Params:           mustMarshal(map[string]any{"replicas": 4}),
		ResourceVersion:  "100",
	}
	signed := signTestPlan(t, content, "clu_1", time.Now().Add(5*time.Minute))

	// Tamper with the signed envelope after signing — a compromised or
	// buggy caller between signing and dispatch, not a fresh forgery.
	signed.Params = mustMarshal(map[string]any{"replicas": 999})

	if _, _, err := executor.scaleDeployment(context.Background(), mustMarshal(signedPlanArgs{Plan: signed})); err == nil {
		t.Fatalf("scaleDeployment accepted a plan whose params were tampered with after signing")
	}
}

func TestScaleDeployment_RejectsWrongActionType(t *testing.T) {
	dep := testDeployment("web", "default", 2, "100")
	executor := newRemediationTestExecutor("clu_1", dep)

	// A validly-signed RestartPod envelope sent to scale_deployment must
	// never be honored just because the signature checks out — the action
	// type itself is part of what verifySignedPlan enforces.
	content := remediation.PlanContent{
		RecommendationID: "plan_1",
		ActionType:       remediation.ActionRestartPod,
		TargetGVK:        "apps/v1/Deployment",
		TargetNamespace:  "default",
		TargetName:       "web",
		Params:           mustMarshal(map[string]any{}),
		ResourceVersion:  "100",
	}
	signed := signTestPlan(t, content, "clu_1", time.Now().Add(5*time.Minute))

	if _, _, err := executor.scaleDeployment(context.Background(), mustMarshal(signedPlanArgs{Plan: signed})); err == nil {
		t.Fatalf("scaleDeployment accepted a validly-signed plan whose action type was RestartPod")
	}
}

func TestScaleDeployment_RejectsExpiredPlan(t *testing.T) {
	dep := testDeployment("web", "default", 2, "100")
	executor := newRemediationTestExecutor("clu_1", dep)

	content := remediation.PlanContent{
		RecommendationID: "plan_1",
		ActionType:       remediation.ActionScaleDeployment,
		TargetGVK:        "apps/v1/Deployment",
		TargetNamespace:  "default",
		TargetName:       "web",
		Params:           mustMarshal(map[string]any{"replicas": 4}),
		ResourceVersion:  "100",
	}
	signed := signTestPlan(t, content, "clu_1", time.Now().Add(-time.Minute)) // already expired

	if _, _, err := executor.scaleDeployment(context.Background(), mustMarshal(signedPlanArgs{Plan: signed})); err == nil {
		t.Fatalf("scaleDeployment accepted an expired plan")
	}
}

func TestScaleDeployment_RejectsWrongCluster(t *testing.T) {
	dep := testDeployment("web", "default", 2, "100")
	executor := newRemediationTestExecutor("clu_1", dep)

	content := remediation.PlanContent{
		RecommendationID: "plan_1",
		ActionType:       remediation.ActionScaleDeployment,
		TargetGVK:        "apps/v1/Deployment",
		TargetNamespace:  "default",
		TargetName:       "web",
		Params:           mustMarshal(map[string]any{"replicas": 4}),
		ResourceVersion:  "100",
	}
	// Signed for a different cluster than the one this executor belongs to.
	signed := signTestPlan(t, content, "clu_OTHER", time.Now().Add(5*time.Minute))

	if _, _, err := executor.scaleDeployment(context.Background(), mustMarshal(signedPlanArgs{Plan: signed})); err == nil {
		t.Fatalf("scaleDeployment accepted a plan signed for a different cluster")
	}
}

func TestScaleDeployment_RejectsWithoutCredentials(t *testing.T) {
	dep := testDeployment("web", "default", 2, "100")
	dyn := dynamicfake.NewSimpleDynamicClient(k8sscheme.Scheme, dep)
	executor := &ToolExecutor{dynamic: dyn} // SetRemediationCredentials never called

	content := remediation.PlanContent{
		RecommendationID: "plan_1",
		ActionType:       remediation.ActionScaleDeployment,
		TargetGVK:        "apps/v1/Deployment",
		TargetNamespace:  "default",
		TargetName:       "web",
		Params:           mustMarshal(map[string]any{"replicas": 4}),
		ResourceVersion:  "100",
	}
	signed := signTestPlan(t, content, "clu_1", time.Now().Add(5*time.Minute))

	if _, _, err := executor.scaleDeployment(context.Background(), mustMarshal(signedPlanArgs{Plan: signed})); err == nil {
		t.Fatalf("scaleDeployment executed against an executor with no remediation credentials installed")
	}
}

func TestScaleDeployment_RejectsReplicasOutOfRange(t *testing.T) {
	dep := testDeployment("web", "default", 2, "100")
	executor := newRemediationTestExecutor("clu_1", dep)

	content := remediation.PlanContent{
		RecommendationID: "plan_1",
		ActionType:       remediation.ActionScaleDeployment,
		TargetGVK:        "apps/v1/Deployment",
		TargetNamespace:  "default",
		TargetName:       "web",
		Params:           mustMarshal(map[string]any{"replicas": 100000}),
		ResourceVersion:  "100",
	}
	signed := signTestPlan(t, content, "clu_1", time.Now().Add(5*time.Minute))

	if _, _, err := executor.scaleDeployment(context.Background(), mustMarshal(signedPlanArgs{Plan: signed})); err == nil {
		t.Fatalf("scaleDeployment accepted an out-of-range replica count")
	}
}

// TestScaleDeployment_StaleResourceVersionFailsClosed proves a plan signed
// against a resourceVersion that no longer matches the live object's is
// rejected — installRealisticPatchReactor enforces the same precondition
// check a real API server does for a patch body embedding
// metadata.resourceVersion (lld/08 §5, SR-20), never silently applying it
// against a value that's since moved on.
func TestScaleDeployment_StaleResourceVersionFailsClosed(t *testing.T) {
	dep := testDeployment("web", "default", 2, "100")
	executor := newRemediationTestExecutor("clu_1", dep)

	content := remediation.PlanContent{
		RecommendationID: "plan_1",
		ActionType:       remediation.ActionScaleDeployment,
		TargetGVK:        "apps/v1/Deployment",
		TargetNamespace:  "default",
		TargetName:       "web",
		Params:           mustMarshal(map[string]any{"replicas": 4}),
		ResourceVersion:  "stale-does-not-match",
	}
	signed := signTestPlan(t, content, "clu_1", time.Now().Add(5*time.Minute))

	if _, _, err := executor.scaleDeployment(context.Background(), mustMarshal(signedPlanArgs{Plan: signed})); err == nil {
		t.Fatalf("scaleDeployment succeeded despite a stale resourceVersion precondition")
	}
}

func TestRestartPod_ValidSignedPlanPatchesOwningDeployment(t *testing.T) {
	dep := testDeployment("web", "default", 2, "100")
	executor := newRemediationTestExecutor("clu_1", dep)

	content := remediation.PlanContent{
		RecommendationID: "plan_1",
		ActionType:       remediation.ActionRestartPod,
		TargetGVK:        "apps/v1/Deployment", // pre-resolved to the owning workload, per this tool's own contract
		TargetNamespace:  "default",
		TargetName:       "web",
		Params:           mustMarshal(map[string]any{}),
		ResourceVersion:  "100",
	}
	signed := signTestPlan(t, content, "clu_1", time.Now().Add(5*time.Minute))

	data, _, err := executor.restartPod(context.Background(), mustMarshal(signedPlanArgs{Plan: signed}))
	if err != nil {
		t.Fatalf("restartPod: %v", err)
	}
	var result executeResult
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("decode result: %v", err)
	}
	if result.ResourceVersion == "" {
		t.Errorf("restartPod: result has no resourceVersion")
	}
}

func TestRestartPod_RejectsBarePodTarget(t *testing.T) {
	executor := newRemediationTestExecutor("clu_1")

	content := remediation.PlanContent{
		RecommendationID: "plan_1",
		ActionType:       remediation.ActionRestartPod,
		TargetGVK:        "v1/Pod", // not pre-resolved to an owning workload
		TargetNamespace:  "default",
		TargetName:       "web-abc123",
		Params:           mustMarshal(map[string]any{}),
		ResourceVersion:  "100",
	}
	signed := signTestPlan(t, content, "clu_1", time.Now().Add(5*time.Minute))

	if _, _, err := executor.restartPod(context.Background(), mustMarshal(signedPlanArgs{Plan: signed})); err == nil {
		t.Fatalf("restartPod accepted a bare Pod target instead of requiring a pre-resolved owning workload")
	}
}

func TestExecute_DispatchesScaleDeploymentAndRestartPod(t *testing.T) {
	dep := testDeployment("web", "default", 2, "100")
	executor := newRemediationTestExecutor("clu_1", dep)

	scaleContent := remediation.PlanContent{
		RecommendationID: "plan_1", ActionType: remediation.ActionScaleDeployment,
		TargetGVK: "apps/v1/Deployment", TargetNamespace: "default", TargetName: "web",
		Params: mustMarshal(map[string]any{"replicas": 3}), ResourceVersion: "100",
	}
	signedScale := signTestPlan(t, scaleContent, "clu_1", time.Now().Add(time.Minute))
	scaleData, _, err := executor.Execute(context.Background(), "scale_deployment", mustMarshal(signedPlanArgs{Plan: signedScale}))
	if err != nil {
		t.Fatalf("Execute(scale_deployment): %v", err)
	}
	var scaleResult executeResult
	if err := json.Unmarshal(scaleData, &scaleResult); err != nil {
		t.Fatalf("decode scale result: %v", err)
	}

	restartContent := remediation.PlanContent{
		RecommendationID: "plan_2", ActionType: remediation.ActionRestartPod,
		TargetGVK: "apps/v1/Deployment", TargetNamespace: "default", TargetName: "web",
		Params: mustMarshal(map[string]any{}), ResourceVersion: scaleResult.ResourceVersion,
	}
	signedRestart := signTestPlan(t, restartContent, "clu_1", time.Now().Add(time.Minute))
	if _, _, err := executor.Execute(context.Background(), "restart_pod", mustMarshal(signedPlanArgs{Plan: signedRestart})); err != nil {
		t.Fatalf("Execute(restart_pod): %v", err)
	}
}

// ---------------------------------------------------------------------------
// BACKLOG.md F12 — the machine-attested dry-run gate.
//
// The property under test is the one an operator's trust rests on: a plan
// marked DryRun must be submitted to the API server with dryRun=All and must
// leave the cluster untouched, while returning the object the server says
// would result. Asserting the flag alone would not be enough — a handler that
// passed dryRun=All and then also wrote would satisfy it.
// ---------------------------------------------------------------------------

// dryRunPlanFor is the two-plan setup every test below shares: one content
// value, signed twice, differing only in DryRun. Built this way on purpose —
// it is the same construction attestByDryRun uses, and it makes "identical
// except for the flag" a property of the test rather than a claim about it.
func dryRunPlanFor(t *testing.T, content remediation.PlanContent, clusterID string) (real, dry remediation.SignedPlan) {
	t.Helper()
	expiry := time.Now().Add(5 * time.Minute)
	real = signTestPlan(t, content, clusterID, expiry)
	dryContent := content
	dryContent.DryRun = true
	dry = signTestPlan(t, dryContent, clusterID, expiry)
	return real, dry
}

func scaleContent(replicas int) remediation.PlanContent {
	return remediation.PlanContent{
		RecommendationID: "plan_dryrun",
		ActionType:       remediation.ActionScaleDeployment,
		TargetGVK:        "apps/v1/Deployment",
		TargetNamespace:  "default",
		TargetName:       "web",
		Params:           mustMarshal(map[string]any{"replicas": replicas}),
		ResourceVersion:  "100",
	}
}

// replicasOf reads spec.replicas tolerating either numeric type.
//
// Not defensive coding — a fake-harness artifact, and worth naming so it is
// not mistaken for one. installRealisticPatchReactor merges the patch body
// after json.Unmarshal into map[string]any, which makes every number a
// float64; a real API server decodes against the Deployment schema and stores
// an int32. unstructured.NestedInt64 refuses the float64, so a strict read
// would fail on the fake for a reason that cannot occur in production.
func replicasOf(t *testing.T, obj map[string]any) int64 {
	t.Helper()
	raw, found, err := unstructured.NestedFieldNoCopy(obj, "spec", "replicas")
	if err != nil || !found {
		t.Fatalf("object has no spec.replicas (found=%v err=%v)", found, err)
	}
	switch v := raw.(type) {
	case int64:
		return v
	case float64:
		return int64(v)
	default:
		t.Fatalf("spec.replicas has unexpected type %T", raw)
		return 0
	}
}

func storedReplicas(t *testing.T, e *ToolExecutor) int64 {
	t.Helper()
	gvr := schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "deployments"}
	obj, err := e.dynamic.Resource(gvr).Namespace("default").Get(context.Background(), "web", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("read back the stored Deployment: %v", err)
	}
	return replicasOf(t, obj.Object)
}

func TestDryRun_DoesNotMutateTheClusterButReportsTheResult(t *testing.T) {
	executor := newRemediationTestExecutor("clu_1", testDeployment("web", "default", 2, "100"))
	_, dry := dryRunPlanFor(t, scaleContent(4), "clu_1")

	data, _, err := executor.scaleDeployment(context.Background(), mustMarshal(signedPlanArgs{Plan: dry}))
	if err != nil {
		t.Fatalf("dry-run scaleDeployment: %v", err)
	}

	// The whole point: nothing changed.
	if got := storedReplicas(t, executor); got != 2 {
		t.Errorf("a dry run changed the cluster: stored spec.replicas = %d, want the original 2", got)
	}

	var result executeResult
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("decode result: %v", err)
	}
	// The echo the hub fails closed on.
	if !result.DryRun {
		t.Error("dry-run result did not echo dryRun=true — the hub treats this as version skew and refuses to execute")
	}
	// The object F13's diff is computed from must actually be there, and must
	// show the CHANGE (4), not the current state (2) — a dry run that returned
	// the unmodified object would produce an empty diff and tell the operator
	// nothing.
	if len(result.Object) == 0 {
		t.Fatal("dry-run result carries no object, so there is nothing to diff")
	}
	var returned unstructured.Unstructured
	if err := json.Unmarshal(result.Object, &returned.Object); err != nil {
		t.Fatalf("decode returned object: %v", err)
	}
	if replicas := replicasOf(t, returned.Object); replicas != 4 {
		t.Errorf("returned object shows spec.replicas = %d, want the proposed 4", replicas)
	}
}

func TestDryRun_RealExecutionStillMutatesAndDoesNotClaimToBeADryRun(t *testing.T) {
	executor := newRemediationTestExecutor("clu_1", testDeployment("web", "default", 2, "100"))
	real, _ := dryRunPlanFor(t, scaleContent(4), "clu_1")

	data, _, err := executor.scaleDeployment(context.Background(), mustMarshal(signedPlanArgs{Plan: real}))
	if err != nil {
		t.Fatalf("scaleDeployment: %v", err)
	}
	if got := storedReplicas(t, executor); got != 4 {
		t.Errorf("real execution did not apply: stored spec.replicas = %d, want 4", got)
	}
	var result executeResult
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("decode result: %v", err)
	}
	// The inverse of the fail-closed check: a real execution must never claim
	// to have been a rehearsal, or the hub would skip the mutation it needs.
	if result.DryRun {
		t.Error("a real execution reported dryRun=true")
	}
	if len(result.Object) != 0 {
		t.Error("a real execution returned the full object; that payload is dry-run-only")
	}
}

// The flag is inside the signature, so the two plans are different plans. This
// is what stops a rehearsal being rewritten into a mutation (or the reverse)
// in flight — the guarantee the doc comment on PlanContent.DryRun claims.
func TestDryRun_FlagCannotBeFlippedAfterSigning(t *testing.T) {
	executor := newRemediationTestExecutor("clu_1", testDeployment("web", "default", 2, "100"))
	_, dry := dryRunPlanFor(t, scaleContent(4), "clu_1")

	tampered := dry
	tampered.DryRun = false // "make this rehearsal real"

	if _, _, err := executor.scaleDeployment(context.Background(), mustMarshal(signedPlanArgs{Plan: tampered})); err == nil {
		t.Fatal("clearing DryRun on a signed dry-run plan was accepted — the flag is not covered by the signature")
	}
	if got := storedReplicas(t, executor); got != 2 {
		t.Errorf("a plan with a flipped DryRun flag mutated the cluster: spec.replicas = %d", got)
	}
}

// Every execution tool must honour the flag, not just the one the tests above
// exercise. This is the regression guard for applyPlanPatch's whole reason to
// exist: a fifth action type added by copying a neighbour must not be able to
// omit the dry-run option.
func TestDryRun_EveryExecutionToolHonoursTheFlag(t *testing.T) {
	cases := []struct {
		tool    string
		content remediation.PlanContent
	}{
		{"scale_deployment", scaleContent(4)},
		{"restart_pod", remediation.PlanContent{
			RecommendationID: "plan_dryrun", ActionType: remediation.ActionRestartPod,
			TargetGVK: "apps/v1/Deployment", TargetNamespace: "default", TargetName: "web",
			Params: mustMarshal(map[string]any{}), ResourceVersion: "100",
		}},
	}
	for _, tc := range cases {
		t.Run(tc.tool, func(t *testing.T) {
			executor := newRemediationTestExecutor("clu_1", testDeployment("web", "default", 2, "100"))
			_, dry := dryRunPlanFor(t, tc.content, "clu_1")
			data, _, err := executor.Execute(context.Background(), tc.tool, mustMarshal(signedPlanArgs{Plan: dry}))
			if err != nil {
				t.Fatalf("%s dry run: %v", tc.tool, err)
			}
			var result executeResult
			if err := json.Unmarshal(data, &result); err != nil {
				t.Fatalf("decode result: %v", err)
			}
			if !result.DryRun {
				t.Errorf("%s did not echo dryRun=true", tc.tool)
			}
			// restart_pod writes an annotation rather than replicas, so the
			// generic proof that nothing was persisted is the resourceVersion
			// of the STORED object, which a real write would have bumped.
			gvr := schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "deployments"}
			obj, err := executor.dynamic.Resource(gvr).Namespace("default").Get(context.Background(), "web", metav1.GetOptions{})
			if err != nil {
				t.Fatalf("read back: %v", err)
			}
			if obj.GetResourceVersion() != "100" {
				t.Errorf("%s dry run persisted a write: stored resourceVersion moved to %q", tc.tool, obj.GetResourceVersion())
			}
		})
	}
}

// admissionRejection is a deliberate hole in sanitizeK8sErr, so its edges are
// worth pinning: what goes through, what does not, and that nothing goes
// through unbounded.
func TestAdmissionRejection_PassesPolicyDenialsAndNothingElse(t *testing.T) {
	gr := schema.GroupResource{Group: "apps", Resource: "deployments"}

	// The shape a real cluster returns for a ValidatingAdmissionPolicy denial
	// (verified live against rke2, WORKLOG).
	vapDenial := apierrors.NewInvalid(
		schema.GroupKind{Group: "apps", Kind: "Deployment"}, "web",
		field.ErrorList{field.Forbidden(field.NewPath(""),
			"ValidatingAdmissionPolicy 'argus-probe' denied request: this policy refuses any change to spec.replicas")})
	msg, ok := admissionRejection(vapDenial)
	if !ok {
		t.Fatal("a ValidatingAdmissionPolicy denial was sanitized to a generic message — the gate would tell the operator nothing")
	}
	if !strings.Contains(msg, "refuses any change to spec.replicas") {
		t.Errorf("the policy's own reason did not survive: %q", msg)
	}

	// A webhook denial arrives as Forbidden with the API server's fixed prefix.
	webhookDenial := apierrors.NewForbidden(gr, "web",
		errors.New(`admission webhook "quota.example.com" denied the request: namespace quota exceeded`))
	if msg, ok := admissionRejection(webhookDenial); !ok || !strings.Contains(msg, "quota exceeded") {
		t.Errorf("a webhook denial did not pass through: ok=%v msg=%q", ok, msg)
	}

	// An ordinary RBAC 403 must NOT — it names roles and service accounts and
	// has no diagnostic value for an approver.
	rbacDenial := apierrors.NewForbidden(gr, "web",
		errors.New(`deployments.apps "web" is forbidden: User "system:serviceaccount:argus-system:argus-remediate" cannot patch resource`))
	if _, ok := admissionRejection(rbacDenial); ok {
		t.Error("a plain RBAC denial was passed through verbatim; it should keep the generic message")
	}
	if got := sanitizeK8sErr(rbacDenial).Error(); got != "permission denied" {
		t.Errorf("sanitizeK8sErr(RBAC 403) = %q, want the generic message", got)
	}

	// Unrelated errors are untouched.
	if _, ok := admissionRejection(apierrors.NewNotFound(gr, "web")); ok {
		t.Error("a NotFound was treated as an admission rejection")
	}
	if _, ok := admissionRejection(nil); ok {
		t.Error("a nil error was treated as an admission rejection")
	}
}

func TestAdmissionRejection_IsBounded(t *testing.T) {
	long := strings.Repeat("x", maxAdmissionMessageLen*3)
	err := apierrors.NewInvalid(schema.GroupKind{Group: "apps", Kind: "Deployment"}, "web",
		field.ErrorList{field.Forbidden(field.NewPath(""), long)})
	msg, ok := admissionRejection(err)
	if !ok {
		t.Fatal("expected pass-through")
	}
	// A webhook's message length is not ARGUS's to control, so the bound is
	// the real control here — not the category check.
	if len(msg) > maxAdmissionMessageLen+len("… (truncated)") {
		t.Errorf("message is %d bytes, past the %d bound", len(msg), maxAdmissionMessageLen)
	}
	if !strings.HasSuffix(msg, "(truncated)") {
		t.Error("a truncated message does not say so, which would read as the whole reason")
	}
}

// Newlines matter: these messages land in an HTTP error body and in logs, and
// a multi-line webhook message would fragment both.
func TestAdmissionRejection_IsSingleLine(t *testing.T) {
	err := apierrors.NewInvalid(schema.GroupKind{Group: "apps", Kind: "Deployment"}, "web",
		field.ErrorList{field.Forbidden(field.NewPath(""), "line one\nline two\ttabbed")})
	msg, _ := admissionRejection(err)
	if strings.ContainsAny(msg, "\n\t") {
		t.Errorf("message still contains newlines or tabs: %q", msg)
	}
}

// Grounded in what an rke2 v1.35 API server actually returned for a
// ValidatingAdmissionPolicy denial on a server-side dry run, captured with
// `kubectl -v=8` (WORKLOG). Pinned as a literal Status rather than built with
// a helper because the interesting part is a mismatch no one would invent:
// the reason is Invalid (422) while the message reads "is forbidden". Any
// future refactor that classifies these by matching the message text instead
// of the reason would pass every other test in this file and break this one.
func TestAdmissionRejection_MatchesWhatARealClusterSends(t *testing.T) {
	live := &apierrors.StatusError{ErrStatus: metav1.Status{
		Status:  metav1.StatusFailure,
		Code:    422,
		Reason:  metav1.StatusReasonInvalid,
		Message: `deployments.apps "f12-target" is forbidden: ValidatingAdmissionPolicy 'argus-f12-dryrun-probe' with binding 'argus-f12-dryrun-probe' denied request: F12 probe: this policy refuses any change to spec.replicas`,
	}}
	if !apierrors.IsInvalid(live) {
		t.Fatal("the captured Status is not classified as Invalid; the premise of admissionRejection's primary branch is wrong")
	}
	msg, ok := admissionRejection(live)
	if !ok {
		t.Fatal("a real ValidatingAdmissionPolicy denial was sanitized away")
	}
	if !strings.Contains(msg, "refuses any change to spec.replicas") {
		t.Errorf("the policy's reason did not reach the operator: %q", msg)
	}
}
