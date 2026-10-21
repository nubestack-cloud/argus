package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	certificatesv1 "k8s.io/api/certificates/v1"
	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	schedulingv1 "k8s.io/api/scheduling/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	k8sfake "k8s.io/client-go/kubernetes/fake"
	k8sscheme "k8s.io/client-go/kubernetes/scheme"
	k8stesting "k8s.io/client-go/testing"
)

// newTestExecutor builds a ToolExecutor backed entirely by fakes: typed
// (k8s.io/client-go/kubernetes/fake) for get_events/get_logs, dynamic
// (k8s.io/client-go/dynamic/fake) for describe_resource/get_owner_chain —
// exactly the split ToolExecutor itself uses against a real cluster,
// standing in for the real cluster this sandbox doesn't have.
func newTestExecutor(dynamicObjs ...runtime.Object) (*ToolExecutor, *k8sfake.Clientset) {
	typed := k8sfake.NewSimpleClientset()
	// GitOps CRD list kinds must be declared: they are not in
	// k8sscheme.Scheme, and repo resolution LISTs Applications as its
	// fallback (Argo's tracking-id annotation does not carry the
	// Application's own namespace). Without them the fake client panics on
	// any ownership test, including ones that predate that lookup.
	dyn := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(k8sscheme.Scheme, gitOpsTestListKinds(), dynamicObjs...)
	return &ToolExecutor{typed: typed, dynamic: dyn}, typed
}

func gitOpsTestListKinds() map[schema.GroupVersionResource]string {
	return map[schema.GroupVersionResource]string{
		{Group: "argoproj.io", Version: "v1alpha1", Resource: "applications"}:             "ApplicationList",
		{Group: "fleet.cattle.io", Version: "v1alpha1", Resource: "gitrepos"}:             "GitRepoList",
		{Group: "fleet.cattle.io", Version: "v1alpha1", Resource: "bundles"}:              "BundleList",
		{Group: "kustomize.toolkit.fluxcd.io", Version: "v1", Resource: "kustomizations"}: "KustomizationList",
		{Group: "source.toolkit.fluxcd.io", Version: "v1", Resource: "gitrepositories"}:   "GitRepositoryList",
	}
}

// installEventsReactor replaces the fake clientset's default "list events"
// handling (which ignores ListOptions.FieldSelector entirely — verified
// empirically against this exact client-go version) with one that actually
// applies the field selector the way a real API server would. Without
// this, a test against the bare fake could never distinguish "getEvents
// built the right selector" from "getEvents built no selector at all,"
// since the fake would return the same (unfiltered) result either way.
func installEventsReactor(typed *k8sfake.Clientset, events []corev1.Event) {
	typed.PrependReactor("list", "events", func(action k8stesting.Action) (bool, runtime.Object, error) {
		listAction, ok := action.(k8stesting.ListAction)
		if !ok {
			return false, nil, nil
		}
		restrictions := listAction.GetListRestrictions()

		out := &corev1.EventList{}
		for _, ev := range events {
			if action.GetNamespace() != "" && ev.Namespace != action.GetNamespace() {
				continue
			}
			fieldSet := map[string]string{
				"involvedObject.kind": ev.InvolvedObject.Kind,
				"involvedObject.name": ev.InvolvedObject.Name,
			}
			if restrictions.Fields != nil && !restrictions.Fields.Matches(fieldSetOf(fieldSet)) {
				continue
			}
			out.Items = append(out.Items, ev)
		}
		return true, out, nil
	})
}

// fieldSetOf avoids importing k8s.io/apimachinery/pkg/fields just for its
// Set type's Has/Get methods in this one helper — fields.Set is exactly
// map[string]string, so a local alias with the same method set does the
// same job for this test file.
type fieldSetOf map[string]string

func (f fieldSetOf) Has(field string) bool   { _, ok := f[field]; return ok }
func (f fieldSetOf) Get(field string) string { return f[field] }

func TestParseGVKString(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		want    schema.GroupVersionKind
		wantErr bool
	}{
		{name: "core group", in: "v1/Pod", want: schema.GroupVersionKind{Version: "v1", Kind: "Pod"}},
		{name: "named group", in: "apps/v1/Deployment", want: schema.GroupVersionKind{Group: "apps", Version: "v1", Kind: "Deployment"}},
		{name: "batch group", in: "batch/v1/CronJob", want: schema.GroupVersionKind{Group: "batch", Version: "v1", Kind: "CronJob"}},
		{name: "no slash at all", in: "Pod", wantErr: true},
		{name: "empty kind", in: "apps/v1/", wantErr: true},
		{name: "empty string", in: "", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseGVKString(tt.in)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("parseGVKString(%q) = %v, want error", tt.in, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseGVKString(%q): unexpected error: %v", tt.in, err)
			}
			if got != tt.want {
				t.Fatalf("parseGVKString(%q) = %+v, want %+v", tt.in, got, tt.want)
			}
		})
	}
}

func TestGetEvents_FiltersByInvolvedObjectAndSince(t *testing.T) {
	base := time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC)
	events := []corev1.Event{
		{
			ObjectMeta:     metav1.ObjectMeta{Name: "ev1", Namespace: "default"},
			InvolvedObject: corev1.ObjectReference{Kind: "Pod", Name: "web-1"},
			Reason:         "FailedScheduling",
			Type:           "Warning",
			Count:          1,
			LastTimestamp:  metav1.NewTime(base),
		},
		{
			ObjectMeta:     metav1.ObjectMeta{Name: "ev2", Namespace: "default"},
			InvolvedObject: corev1.ObjectReference{Kind: "Pod", Name: "other-pod"},
			Reason:         "Started",
			Type:           "Normal",
			LastTimestamp:  metav1.NewTime(base),
		},
		{
			ObjectMeta:     metav1.ObjectMeta{Name: "ev3", Namespace: "default"},
			InvolvedObject: corev1.ObjectReference{Kind: "Pod", Name: "web-1"},
			Reason:         "BackOff",
			Type:           "Warning",
			Count:          1, // legacy field — deliberately stale, series.count must win
			Series:         &corev1.EventSeries{Count: 10, LastObservedTime: metav1.NewMicroTime(base.Add(time.Hour))},
		},
	}

	executor, typed := newTestExecutor()
	installEventsReactor(typed, events)

	// Filter to involvedObjectName=web-1 only: must exclude ev2 (other-pod).
	data, truncated, err := executor.getEvents(context.Background(), mustMarshal(getEventsArgs{
		Namespace:          "default",
		InvolvedObjectName: "web-1",
	}))
	if err != nil {
		t.Fatalf("getEvents: %v", err)
	}
	if truncated {
		t.Error("getEvents: truncated = true, want false for a 2-item result")
	}
	var results []eventResult
	if err := json.Unmarshal(data, &results); err != nil {
		t.Fatalf("decode result: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("getEvents(involvedObjectName=web-1): got %d results, want 2: %+v", len(results), results)
	}
	for _, r := range results {
		if r.InvolvedObjectName != "web-1" {
			t.Errorf("getEvents leaked an event for a different object: %+v", r)
		}
	}
	// series.count must be preferred over the legacy Count field.
	var ev3Result *eventResult
	for i := range results {
		if results[i].Reason == "BackOff" {
			ev3Result = &results[i]
		}
	}
	if ev3Result == nil {
		t.Fatal("expected the BackOff (ev3) event in the result")
	}
	if ev3Result.Count != 10 {
		t.Errorf("ev3 Count = %d, want 10 (series.count, not the legacy count=1)", ev3Result.Count)
	}

	// "since" set after ev1's timestamp but before ev3's series
	// LastObservedTime must return only ev3.
	since := base.Add(30 * time.Minute)
	data, _, err = executor.getEvents(context.Background(), mustMarshal(getEventsArgs{
		Namespace:          "default",
		InvolvedObjectName: "web-1",
		Since:              &since,
	}))
	if err != nil {
		t.Fatalf("getEvents with since: %v", err)
	}
	if err := json.Unmarshal(data, &results); err != nil {
		t.Fatalf("decode result: %v", err)
	}
	if len(results) != 1 || results[0].Reason != "BackOff" {
		t.Fatalf("getEvents with since=%v: got %+v, want exactly the BackOff event", since, results)
	}
}

func TestGetLogs_TailLimitedAndParsed(t *testing.T) {
	executor, typed := newTestExecutor()

	var capturedTailLines int64
	var capturedContainer string
	typed.PrependReactor("get", "pods/log", func(action k8stesting.Action) (bool, runtime.Object, error) {
		generic, ok := action.(k8stesting.GenericAction)
		if !ok {
			t.Fatalf("expected a GenericAction for pods/log, got %T", action)
		}
		opts, ok := generic.GetValue().(*corev1.PodLogOptions)
		if !ok {
			t.Fatalf("expected *corev1.PodLogOptions, got %T", generic.GetValue())
		}
		if opts.TailLines != nil {
			capturedTailLines = *opts.TailLines
		}
		capturedContainer = opts.Container
		return true, &runtime.Unknown{Raw: []byte("line one\nline two\nline three\n")}, nil
	})

	data, truncated, err := executor.getLogs(context.Background(), mustMarshal(getLogsArgs{
		Namespace: "default",
		Pod:       "web-1",
		Container: "app",
		TailLines: 50,
	}))
	if err != nil {
		t.Fatalf("getLogs: %v", err)
	}
	if capturedTailLines != 50 {
		t.Errorf("PodLogOptions.TailLines = %d, want 50 (the requested value, passed to the real pods/log subresource)", capturedTailLines)
	}
	if capturedContainer != "app" {
		t.Errorf("PodLogOptions.Container = %q, want %q", capturedContainer, "app")
	}
	var result getLogsResult
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("decode result: %v", err)
	}
	if len(result.Lines) != 3 {
		t.Fatalf("getLogs: got %d lines, want 3: %+v", len(result.Lines), result.Lines)
	}
	if result.Lines[0] != "line one" {
		t.Errorf("getLogs: first line = %q, want %q", result.Lines[0], "line one")
	}
	// 3 lines returned for a 50-line tail request: not indistinguishable
	// from "there were more," so truncated must be false.
	if truncated {
		t.Error("getLogs: truncated = true for a result well under the tail cap, want false")
	}
}

func TestGetLogs_UnreasonableTailIsCapped(t *testing.T) {
	executor, typed := newTestExecutor()

	var capturedTailLines int64
	typed.PrependReactor("get", "pods/log", func(action k8stesting.Action) (bool, runtime.Object, error) {
		generic := action.(k8stesting.GenericAction)
		opts := generic.GetValue().(*corev1.PodLogOptions)
		if opts.TailLines != nil {
			capturedTailLines = *opts.TailLines
		}
		return true, &runtime.Unknown{Raw: []byte("only one line\n")}, nil
	})

	if _, _, err := executor.getLogs(context.Background(), mustMarshal(getLogsArgs{
		Namespace: "default",
		Pod:       "web-1",
		TailLines: 10_000_000,
	})); err != nil {
		t.Fatalf("getLogs: %v", err)
	}
	if capturedTailLines != maxLogTailLines {
		t.Errorf("PodLogOptions.TailLines = %d, want the capped max %d", capturedTailLines, maxLogTailLines)
	}
}

func TestGetLogs_MissingArgsRejected(t *testing.T) {
	executor, _ := newTestExecutor()
	if _, _, err := executor.getLogs(context.Background(), mustMarshal(getLogsArgs{Pod: "web-1"})); err == nil {
		t.Fatal("getLogs with no namespace: want error, got nil")
	}
}

func TestDescribeResource_InlinesLiveObjectAndEvents(t *testing.T) {
	deployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Name: "web", Namespace: "default", UID: types.UID("uid-deploy")},
		Spec:       appsv1.DeploymentSpec{},
	}
	executor, typed := newTestExecutor(deployment)
	installEventsReactor(typed, []corev1.Event{
		{
			ObjectMeta:     metav1.ObjectMeta{Name: "ev1", Namespace: "default"},
			InvolvedObject: corev1.ObjectReference{Kind: "Deployment", Name: "web"},
			Reason:         "ScalingReplicaSet",
		},
		{
			ObjectMeta:     metav1.ObjectMeta{Name: "ev2", Namespace: "default"},
			InvolvedObject: corev1.ObjectReference{Kind: "Deployment", Name: "unrelated"},
			Reason:         "ScalingReplicaSet",
		},
	})

	data, truncated, err := executor.describeResource(context.Background(), mustMarshal(describeResourceArgs{
		GVK:       "apps/v1/Deployment",
		Namespace: "default",
		Name:      "web",
	}))
	if err != nil {
		t.Fatalf("describeResource: %v", err)
	}
	if truncated {
		t.Error("describeResource: truncated = true, want false")
	}

	var result describeResourceResult
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("decode result: %v", err)
	}
	var obj map[string]any
	if err := json.Unmarshal(result.Object, &obj); err != nil {
		t.Fatalf("decode object: %v", err)
	}
	metadata, _ := obj["metadata"].(map[string]any)
	if metadata["name"] != "web" {
		t.Errorf("describeResource: object.metadata.name = %v, want %q", metadata["name"], "web")
	}
	if len(result.Events) != 1 || result.Events[0].Reason != "ScalingReplicaSet" {
		t.Fatalf("describeResource: events = %+v, want exactly the one event for this Deployment", result.Events)
	}
}

func TestDescribeResource_NotFound(t *testing.T) {
	executor, _ := newTestExecutor()
	_, _, err := executor.describeResource(context.Background(), mustMarshal(describeResourceArgs{
		GVK:       "apps/v1/Deployment",
		Namespace: "default",
		Name:      "does-not-exist",
	}))
	if err == nil {
		t.Fatal("describeResource for a nonexistent object: want error, got nil")
	}
	// Built from the caller's own kind/namespace/name, never client-go's
	// raw text (`deployments.apps "does-not-exist" not found`).
	if want := "Deployment default/does-not-exist not found"; err.Error() != want {
		t.Errorf("describeResource error = %q, want %q (never a raw client-go error)", err.Error(), want)
	}
}

func TestDescribeResource_UnsupportedGVK(t *testing.T) {
	executor, _ := newTestExecutor()
	// v1/Secret used to be this test's example (BACKLOG.md's #1 called out
	// it being both unsupported and sensitive as the same fact) — that
	// stopped being true 2026-08-29: Secret is now a supported-but-severely-
	// restricted gvk (see TestDescribeResource_SecretReturnsMetadataAndTypeOnly),
	// not an unsupported one. PodTemplate is a real, registered core/v1 kind
	// this map has simply never had a reason to add.
	_, _, err := executor.describeResource(context.Background(), mustMarshal(describeResourceArgs{
		GVK:       "v1/PodTemplate",
		Namespace: "default",
		Name:      "anything",
	}))
	if err == nil {
		t.Fatal("describeResource for an unsupported GVK: want error, got nil")
	}
}

func TestGetOwnerChain_Up_WalksAndMarksDangling(t *testing.T) {
	deployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Name: "web", Namespace: "default", UID: types.UID("uid-deploy")},
	}
	replicaSet := &appsv1.ReplicaSet{
		ObjectMeta: metav1.ObjectMeta{
			Name: "web-abc123", Namespace: "default", UID: types.UID("uid-rs"),
			OwnerReferences: []metav1.OwnerReference{
				{APIVersion: "apps/v1", Kind: "Deployment", Name: "web", UID: types.UID("uid-deploy")},
			},
		},
	}
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: "web-abc123-xyz", Namespace: "default", UID: types.UID("uid-pod"),
			OwnerReferences: []metav1.OwnerReference{
				{APIVersion: "apps/v1", Kind: "ReplicaSet", Name: "web-abc123", UID: types.UID("uid-rs")},
				// Dangling: this ReplicaSet no longer exists (already deleted).
				{APIVersion: "apps/v1", Kind: "ReplicaSet", Name: "web-old", UID: types.UID("uid-deleted-rs")},
			},
		},
	}

	executor, _ := newTestExecutor(deployment, replicaSet, pod)

	data, _, err := executor.getOwnerChain(context.Background(), mustMarshal(getOwnerChainArgs{
		GVK:       "v1/Pod",
		Namespace: "default",
		Name:      "web-abc123-xyz",
		Direction: "up",
	}))
	if err != nil {
		t.Fatalf("getOwnerChain up: %v", err)
	}

	var nodes []ownerChainNode
	if err := json.Unmarshal(data, &nodes); err != nil {
		t.Fatalf("decode result: %v", err)
	}

	byName := map[string]ownerChainNode{}
	for _, n := range nodes {
		byName[n.Name] = n
	}

	rsNode, ok := byName["web-abc123"]
	if !ok || !rsNode.Resolved || rsNode.GVK != "apps/v1/ReplicaSet" {
		t.Errorf("expected a resolved apps/v1/ReplicaSet node for web-abc123, got %+v (present=%v)", rsNode, ok)
	}
	danglingNode, ok := byName["web-old"]
	if !ok || danglingNode.Resolved {
		t.Errorf("expected an UNresolved node for the deleted ReplicaSet web-old, got %+v (present=%v)", danglingNode, ok)
	}
	deployNode, ok := byName["web"]
	if !ok || !deployNode.Resolved || deployNode.GVK != "apps/v1/Deployment" {
		t.Errorf("expected the walk to continue past the resolved ReplicaSet to a resolved Deployment node, got %+v (present=%v)", deployNode, ok)
	}
	if len(nodes) != 3 {
		t.Errorf("getOwnerChain up: got %d nodes, want exactly 3 (resolved RS, dangling RS, resolved Deployment): %+v", len(nodes), nodes)
	}
}

func TestGetOwnerChain_Up_UnsupportedOwnerKindMarkedUnresolved(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: "standalone-pod", Namespace: "default", UID: types.UID("uid-pod"),
			OwnerReferences: []metav1.OwnerReference{
				// Node is a real Kind but not one of the eight this executor
				// supports (and not namespaced) — must be reported
				// unresolved, never attempted, never a crash.
				{APIVersion: "v1", Kind: "Node", Name: "node-1", UID: types.UID("uid-node")},
			},
		},
	}
	executor, _ := newTestExecutor(pod)

	data, _, err := executor.getOwnerChain(context.Background(), mustMarshal(getOwnerChainArgs{
		GVK: "v1/Pod", Namespace: "default", Name: "standalone-pod", Direction: "up",
	}))
	if err != nil {
		t.Fatalf("getOwnerChain up: %v", err)
	}
	var nodes []ownerChainNode
	if err := json.Unmarshal(data, &nodes); err != nil {
		t.Fatalf("decode result: %v", err)
	}
	if len(nodes) != 1 || nodes[0].Resolved || nodes[0].Name != "node-1" {
		t.Fatalf("expected exactly one unresolved node-1 node, got %+v", nodes)
	}
}

func TestGetOwnerChain_Down_FindsImmediateChildrenOnly(t *testing.T) {
	deployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Name: "web", Namespace: "default", UID: types.UID("uid-deploy")},
	}
	replicaSet := &appsv1.ReplicaSet{
		ObjectMeta: metav1.ObjectMeta{
			Name: "web-abc123", Namespace: "default", UID: types.UID("uid-rs"),
			OwnerReferences: []metav1.OwnerReference{
				{APIVersion: "apps/v1", Kind: "Deployment", Name: "web", UID: types.UID("uid-deploy")},
			},
		},
	}
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: "web-abc123-xyz", Namespace: "default", UID: types.UID("uid-pod"),
			OwnerReferences: []metav1.OwnerReference{
				{APIVersion: "apps/v1", Kind: "ReplicaSet", Name: "web-abc123", UID: types.UID("uid-rs")},
			},
		},
	}
	unrelatedDeployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Name: "other", Namespace: "default", UID: types.UID("uid-other")},
	}

	executor, _ := newTestExecutor(deployment, replicaSet, pod, unrelatedDeployment)

	data, _, err := executor.getOwnerChain(context.Background(), mustMarshal(getOwnerChainArgs{
		GVK: "apps/v1/Deployment", Namespace: "default", Name: "web", Direction: "down",
	}))
	if err != nil {
		t.Fatalf("getOwnerChain down: %v", err)
	}
	var nodes []ownerChainNode
	if err := json.Unmarshal(data, &nodes); err != nil {
		t.Fatalf("decode result: %v", err)
	}
	sort.Slice(nodes, func(i, j int) bool { return nodes[i].Name < nodes[j].Name })
	if len(nodes) != 1 {
		t.Fatalf("getOwnerChain down from the Deployment: got %d nodes, want exactly 1 (the immediate-child ReplicaSet, not the grandchild Pod): %+v", len(nodes), nodes)
	}
	if nodes[0].Name != "web-abc123" || !nodes[0].Resolved || nodes[0].GVK != "apps/v1/ReplicaSet" {
		t.Errorf("getOwnerChain down: got %+v, want the resolved web-abc123 ReplicaSet", nodes[0])
	}
}

func TestGetGitOpsOwnership_ArgoOwnerInChain(t *testing.T) {
	deployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name: "web", Namespace: "default", UID: types.UID("uid-deploy"),
			OwnerReferences: []metav1.OwnerReference{
				{APIVersion: "argoproj.io/v1alpha1", Kind: "Application", Name: "my-app", UID: types.UID("uid-app")},
			},
		},
	}
	executor, _ := newTestExecutor(deployment)

	data, _, err := executor.getGitOpsOwnership(context.Background(), mustMarshal(getGitOpsOwnershipArgs{
		GVK: "apps/v1/Deployment", Namespace: "default", Name: "web",
	}))
	if err != nil {
		t.Fatalf("getGitOpsOwnership: %v", err)
	}
	var result gitOpsOwnershipResult
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("decode result: %v", err)
	}
	if result.ManagedBy != "argocd" {
		t.Fatalf("ManagedBy = %q, want %q", result.ManagedBy, "argocd")
	}
	if result.AppRef == nil || result.AppRef.Kind != "Application" || result.AppRef.Name != "my-app" {
		t.Fatalf("AppRef = %+v, want Kind=Application Name=my-app", result.AppRef)
	}
}

func TestGetGitOpsOwnership_FluxOwnerInChain(t *testing.T) {
	deployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name: "web", Namespace: "default", UID: types.UID("uid-deploy"),
			OwnerReferences: []metav1.OwnerReference{
				{APIVersion: "kustomize.toolkit.fluxcd.io/v1", Kind: "Kustomization", Name: "my-ks", UID: types.UID("uid-ks")},
			},
		},
	}
	executor, _ := newTestExecutor(deployment)

	data, _, err := executor.getGitOpsOwnership(context.Background(), mustMarshal(getGitOpsOwnershipArgs{
		GVK: "apps/v1/Deployment", Namespace: "default", Name: "web",
	}))
	if err != nil {
		t.Fatalf("getGitOpsOwnership: %v", err)
	}
	var result gitOpsOwnershipResult
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("decode result: %v", err)
	}
	if result.ManagedBy != "flux" {
		t.Fatalf("ManagedBy = %q, want %q", result.ManagedBy, "flux")
	}
	if result.AppRef == nil || result.AppRef.Kind != "Kustomization" || result.AppRef.Name != "my-ks" {
		t.Fatalf("AppRef = %+v, want Kind=Kustomization Name=my-ks", result.AppRef)
	}
}

// The label-tracking variant. Two corrections since this was written
// (WORKLOG §125): the key is `app.kubernetes.io/instance`, not
// `argocd.argoproj.io/instance` which a real Argo install never writes; and
// because Helm charts conventionally set that same label to the release name,
// it is only accepted when corroborated by an Argo Application of that name
// actually existing — so this test now seeds one.
func TestGetGitOpsOwnership_ArgoInstanceLabelFallback(t *testing.T) {
	deployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name: "web", Namespace: "default", UID: types.UID("uid-deploy"),
			Labels: map[string]string{"app.kubernetes.io/instance": "labeled-app"},
		},
	}
	app := unstructuredOf("argoproj.io/v1alpha1", "Application", "argocd", "labeled-app", nil,
		map[string]any{"source": map[string]any{"repoURL": "https://github.com/x/y.git"}}, nil)
	executor, _ := newTestExecutor(deployment, app)

	data, _, err := executor.getGitOpsOwnership(context.Background(), mustMarshal(getGitOpsOwnershipArgs{
		GVK: "apps/v1/Deployment", Namespace: "default", Name: "web",
	}))
	if err != nil {
		t.Fatalf("getGitOpsOwnership: %v", err)
	}
	var result gitOpsOwnershipResult
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("decode result: %v", err)
	}
	if result.ManagedBy != "argocd" {
		t.Fatalf("ManagedBy = %q, want %q", result.ManagedBy, "argocd")
	}
	if result.AppRef == nil || result.AppRef.Kind != "Application" || result.AppRef.Name != "labeled-app" {
		t.Fatalf("AppRef = %+v, want Kind=Application Name=labeled-app", result.AppRef)
	}
}

func TestGetGitOpsOwnership_ArgoTrackingIDAnnotationFallback(t *testing.T) {
	deployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name: "web", Namespace: "default", UID: types.UID("uid-deploy"),
			Annotations: map[string]string{
				"argocd.argoproj.io/tracking-id": "tracked-app:apps/Deployment:default/web",
			},
		},
	}
	executor, _ := newTestExecutor(deployment)

	data, _, err := executor.getGitOpsOwnership(context.Background(), mustMarshal(getGitOpsOwnershipArgs{
		GVK: "apps/v1/Deployment", Namespace: "default", Name: "web",
	}))
	if err != nil {
		t.Fatalf("getGitOpsOwnership: %v", err)
	}
	var result gitOpsOwnershipResult
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("decode result: %v", err)
	}
	if result.ManagedBy != "argocd" {
		t.Fatalf("ManagedBy = %q, want %q", result.ManagedBy, "argocd")
	}
	if result.AppRef == nil || result.AppRef.Kind != "Application" || result.AppRef.Name != "tracked-app" {
		t.Fatalf("AppRef = %+v, want Kind=Application Name=tracked-app", result.AppRef)
	}
}

func TestGetGitOpsOwnership_FluxAnnotationFallback(t *testing.T) {
	deployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name: "web", Namespace: "default", UID: types.UID("uid-deploy"),
			Annotations: map[string]string{
				"kustomize.toolkit.fluxcd.io/name":      "my-ks",
				"kustomize.toolkit.fluxcd.io/namespace": "flux-system",
			},
		},
	}
	executor, _ := newTestExecutor(deployment)

	data, _, err := executor.getGitOpsOwnership(context.Background(), mustMarshal(getGitOpsOwnershipArgs{
		GVK: "apps/v1/Deployment", Namespace: "default", Name: "web",
	}))
	if err != nil {
		t.Fatalf("getGitOpsOwnership: %v", err)
	}
	var result gitOpsOwnershipResult
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("decode result: %v", err)
	}
	if result.ManagedBy != "flux" {
		t.Fatalf("ManagedBy = %q, want %q", result.ManagedBy, "flux")
	}
	if result.AppRef == nil || result.AppRef.Kind != "Kustomization" || result.AppRef.Name != "my-ks" || result.AppRef.Namespace != "flux-system" {
		t.Fatalf("AppRef = %+v, want Kind=Kustomization Name=my-ks Namespace=flux-system", result.AppRef)
	}
}

func TestGetGitOpsOwnership_None(t *testing.T) {
	deployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name: "plain", Namespace: "default", UID: types.UID("uid-plain"),
			Labels: map[string]string{"app": "plain", "team": "payments"},
		},
	}
	executor, _ := newTestExecutor(deployment)

	data, _, err := executor.getGitOpsOwnership(context.Background(), mustMarshal(getGitOpsOwnershipArgs{
		GVK: "apps/v1/Deployment", Namespace: "default", Name: "plain",
	}))
	if err != nil {
		t.Fatalf("getGitOpsOwnership: %v", err)
	}
	var result gitOpsOwnershipResult
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("decode result: %v", err)
	}
	if result.ManagedBy != "none" {
		t.Fatalf("ManagedBy = %q, want %q for a plain object with no GitOps metadata", result.ManagedBy, "none")
	}
	if result.AppRef != nil {
		t.Fatalf("AppRef = %+v, want nil when ManagedBy is none", result.AppRef)
	}
	// BACKLOG.md F19 mechanism 1 (operator-declared label-selector mapping)
	// needs the object's own labels on the wire even when ManagedBy is
	// "none" — this is the exact case a plain kubectl-applied object lands
	// on, and it is the ONLY form F19 says can match one.
	if result.Labels["team"] != "payments" || result.Labels["app"] != "plain" {
		t.Fatalf("Labels = %+v, want the queried object's own labels for the unmanaged case", result.Labels)
	}
}

func TestGetGitOpsOwnership_NotFound(t *testing.T) {
	executor, _ := newTestExecutor()
	_, _, err := executor.getGitOpsOwnership(context.Background(), mustMarshal(getGitOpsOwnershipArgs{
		GVK: "apps/v1/Deployment", Namespace: "default", Name: "does-not-exist",
	}))
	if err == nil {
		t.Fatal("getGitOpsOwnership for a nonexistent object: want error, got nil")
	}
	if err.Error() != "resource not found" {
		t.Errorf("getGitOpsOwnership error = %q, want the sanitized %q", err.Error(), "resource not found")
	}
}

// --- BACKLOG.md Q4 / BUGS.md 88: IsNotFound falls back to the ancestor ---

// TestGetGitOpsOwnership_NotFoundFallsBackToAncestor is the core case Q4
// decided: the exact Pod an incident named has been rescheduled under a new
// name during its own backoff cycle (an ordinary CrashLoopBackOff lifecycle
// event, not an outage) — Get on it 404s — but its ReplicaSet is completely
// unaffected and still resolves all the way up to an Argo-managed
// Deployment. Before this fix, ANY Get failure (IsNotFound included) failed
// the whole call, which routing.go's gatherOwnershipFacts turns into
// Determined:false — discarding the in-cluster plan the model could
// otherwise have proposed. Named "guestbook-ui-abc-xyz" so
// resolveVanishedObjectAncestor's name-split derives exactly
// "guestbook-ui-abc", the ReplicaSet actually seeded below — deliberately
// not registering that Pod object in the fake dynamic client at all, so Get
// on it genuinely 404s rather than merely having been deleted after being
// seen.
func TestGetGitOpsOwnership_NotFoundFallsBackToAncestor(t *testing.T) {
	deploy := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{
		Name: "guestbook-ui", Namespace: "apps", UID: types.UID("d1"),
		Annotations: map[string]string{
			"argocd.argoproj.io/tracking-id": "argus-e2e-guestbook:apps/Deployment:apps/guestbook-ui",
		},
	}}
	rs := &appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{
		Name: "guestbook-ui-abc", Namespace: "apps", UID: types.UID("r1"),
		OwnerReferences: []metav1.OwnerReference{{
			APIVersion: "apps/v1", Kind: "Deployment", Name: "guestbook-ui", UID: types.UID("d1"), Controller: boolPtr(true),
		}},
	}}
	// Note: no Pod object at all — "guestbook-ui-abc-xyz" is genuinely gone.
	executor := newGitOpsTestExecutor(deploy, rs)

	res := ownershipOf(t, executor, "v1/Pod", "apps", "guestbook-ui-abc-xyz")
	if res.ManagedBy != "argocd" {
		t.Fatalf("ManagedBy = %q, want argocd — the vanished Pod's still-existing ReplicaSet resolves up to an Argo-managed Deployment", res.ManagedBy)
	}
	if res.AppRef == nil || res.AppRef.Name != "argus-e2e-guestbook" {
		t.Errorf("AppRef = %+v, want the Application name from the ancestor's tracking-id", res.AppRef)
	}
}

// TestGetGitOpsOwnership_NotFoundAncestorAlsoGone proves the fallback is a
// second chance, not a guarantee (BACKLOG.md Q4): when NEITHER the queried
// Pod NOR any of its plausible parent kinds can be found, this must still
// fail exactly like today — the same sanitized "resource not found" error
// TestGetGitOpsOwnership_NotFound already asserts for the no-fallback-
// possible case — so a caller like gatherOwnershipFacts still correctly
// lands on OwnershipFacts{Determined: false} / resolution.OwnershipUnknown
// rather than a fabricated ownership answer.
func TestGetGitOpsOwnership_NotFoundAncestorAlsoGone(t *testing.T) {
	executor := newGitOpsTestExecutor() // nothing exists at all
	_, _, err := executor.getGitOpsOwnership(context.Background(), mustMarshal(getGitOpsOwnershipArgs{
		GVK: "v1/Pod", Namespace: "apps", Name: "guestbook-ui-abc-xyz",
	}))
	if err == nil {
		t.Fatal("getGitOpsOwnership for a vanished Pod with no resolvable ancestor: want error, got nil")
	}
	if err.Error() != "resource not found" {
		t.Errorf("getGitOpsOwnership error = %q, want the sanitized %q", err.Error(), "resource not found")
	}
}

// TestGetGitOpsOwnership_NonNotFoundErrorUnaffected proves the fallback is
// scoped to IsNotFound only, per BACKLOG.md Q4's explicit "not other error
// types — those should keep failing exactly as they do now." An RBAC
// denial or network failure worded identically to IsNotFound by the time it
// reaches the hub (BUGS.md 88's own complaint) must still fail immediately,
// with no ancestor-name guessing attempted at all.
func TestGetGitOpsOwnership_NonNotFoundErrorUnaffected(t *testing.T) {
	typed := k8sfake.NewSimpleClientset()
	dyn := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(k8sscheme.Scheme, gitOpsTestListKinds())
	dyn.PrependReactor("get", "pods", func(action k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewForbidden(schema.GroupResource{Resource: "pods"}, "guestbook-ui-abc-xyz", errors.New("denied"))
	})
	executor := &ToolExecutor{typed: typed, dynamic: dyn}

	_, _, err := executor.getGitOpsOwnership(context.Background(), mustMarshal(getGitOpsOwnershipArgs{
		GVK: "v1/Pod", Namespace: "apps", Name: "guestbook-ui-abc-xyz",
	}))
	if err == nil {
		t.Fatal("getGitOpsOwnership with a Forbidden Get: want error, got nil")
	}
	if err.Error() != "permission denied" {
		t.Errorf("getGitOpsOwnership error = %q, want sanitizeK8sErr's Forbidden mapping — a non-IsNotFound error must fail immediately, not attempt the ancestor fallback", err.Error())
	}
}

// --- BACKLOG.md "still open" #3 (2026-08-29): the incident's own object IS
// the Argo Application/Flux Kustomization/HelmRelease ---

// TestGetGitOpsOwnership_SelfApplication is AI1's exact live shape
// (STS-004/JOB-016/JOB-019): the incident is anchored directly on the Argo
// Application object, not on a workload it manages — a sync failure surfaces
// there. Before this fix, getGitOpsOwnership had nothing to walk UP from an
// Application (Argo sets no ownerReferences on what it manages) and no
// metadata fallback that matches an Application's own annotations either, so
// this landed on "none" every time — the mechanism `AI1`'s own update named.
// Asserts not just ManagedBy/AppRef but that Repo is populated straight from
// the object's own spec.source/status.sync, since that is the whole point:
// without a repo target, no repository change can ever be proposed.
func TestGetGitOpsOwnership_SelfApplication(t *testing.T) {
	app := unstructuredOf("argoproj.io/v1alpha1", "Application", "argocd", "guestbook", nil,
		map[string]any{"source": map[string]any{
			"repoURL":        "https://github.com/x/guestbook.git",
			"path":           "apps/guestbook",
			"targetRevision": "main",
		}},
		map[string]any{"sync": map[string]any{"revision": "abc123def"}},
	)
	executor := newGitOpsTestExecutor(app)

	res := ownershipOf(t, executor, "argoproj.io/v1alpha1/Application", "argocd", "guestbook")
	if res.ManagedBy != "argocd" {
		t.Fatalf("ManagedBy = %q, want %q — an incident anchored on the Application itself must still resolve GitOps ownership", res.ManagedBy, "argocd")
	}
	if res.AppRef == nil || res.AppRef.Kind != "Application" || res.AppRef.Name != "guestbook" || res.AppRef.Namespace != "argocd" {
		t.Fatalf("AppRef = %+v, want Kind=Application Name=guestbook Namespace=argocd", res.AppRef)
	}
	if res.Repo == nil {
		t.Fatal("Repo = nil, want the Application's own spec.source resolved — this is the whole point of the fix: without it, no repository change can be proposed for an Application-anchored incident")
	}
	if res.Repo.RepoURL != "https://github.com/x/guestbook.git" {
		t.Errorf("Repo.RepoURL = %q, want the Application's own spec.source.repoURL", res.Repo.RepoURL)
	}
	if res.Repo.Path != "apps/guestbook" {
		t.Errorf("Repo.Path = %q, want spec.source.path", res.Repo.Path)
	}
	if res.Repo.Revision != "abc123def" || !res.Repo.RevisionPinned {
		t.Errorf("Repo.Revision/RevisionPinned = %q/%v, want the PINNED status.sync.revision, not the branch", res.Repo.Revision, res.Repo.RevisionPinned)
	}
}

// TestGetGitOpsOwnership_SelfKustomization is the Flux equivalent of the
// above: the incident is anchored on the Kustomization object itself. Also
// seeds the GitRepository it points at, so Repo resolution is exercised
// end-to-end through the existing repoFromFluxKustomization machinery — the
// self-source fast path only needs to get ManagedBy/AppRef right; everything
// downstream of that is unchanged, already-tested code.
func TestGetGitOpsOwnership_SelfKustomization(t *testing.T) {
	gitRepo := unstructuredOf("source.toolkit.fluxcd.io/v1", "GitRepository", "flux-system", "guestbook-src", nil,
		map[string]any{"url": "https://github.com/x/guestbook.git", "ref": map[string]any{"branch": "main"}}, nil)
	ks := unstructuredOf("kustomize.toolkit.fluxcd.io/v1", "Kustomization", "flux-system", "guestbook", nil,
		map[string]any{
			"path":      "./apps/guestbook",
			"sourceRef": map[string]any{"kind": "GitRepository", "name": "guestbook-src"},
		},
		map[string]any{"lastAppliedRevision": "main@sha1:def456"},
	)
	executor := newGitOpsTestExecutor(ks, gitRepo)

	res := ownershipOf(t, executor, "kustomize.toolkit.fluxcd.io/v1/Kustomization", "flux-system", "guestbook")
	if res.ManagedBy != "flux" {
		t.Fatalf("ManagedBy = %q, want %q — an incident anchored on the Kustomization itself must still resolve GitOps ownership", res.ManagedBy, "flux")
	}
	if res.AppRef == nil || res.AppRef.Kind != "Kustomization" || res.AppRef.Name != "guestbook" || res.AppRef.Namespace != "flux-system" {
		t.Fatalf("AppRef = %+v, want Kind=Kustomization Name=guestbook Namespace=flux-system", res.AppRef)
	}
	if res.Repo == nil || res.Repo.RepoURL != "https://github.com/x/guestbook.git" {
		t.Fatalf("Repo = %+v, want the GitRepository's url resolved through the Kustomization's sourceRef", res.Repo)
	}
}

// TestGetGitOpsOwnership_ApplicationSetIsNotSelfResolved guards the
// deliberate exclusion documented on gitOpsSelfSourceKinds: an ApplicationSet
// generates many Applications from a template plus generators and has no
// single spec.source of its own, so it must NOT hit the self-source fast
// path — it should fall through to the ordinary owner-chain/metadata logic
// exactly as before this fix, landing on "none" for a plain ApplicationSet
// with no owner and no tracking metadata of its own.
func TestGetGitOpsOwnership_ApplicationSetIsNotSelfResolved(t *testing.T) {
	appSet := unstructuredOf("argoproj.io/v1alpha1", "ApplicationSet", "argocd", "guestbook-set", nil,
		map[string]any{"generators": []any{}}, nil)
	executor := newGitOpsTestExecutor(appSet)

	res := ownershipOf(t, executor, "argoproj.io/v1alpha1/ApplicationSet", "argocd", "guestbook-set")
	if res.ManagedBy != "none" {
		t.Fatalf("ManagedBy = %q, want %q — an ApplicationSet has no spec.source of its own and must not be self-resolved", res.ManagedBy, "none")
	}
}

// --- BACKLOG.md "still open" #5a (2026-08-29): widening the IsNotFound
// ancestor fallback past Pod ---

// TestGetGitOpsOwnership_NotFoundFallsBackToAncestor_ReplicaSetToDeployment
// mirrors TestGetGitOpsOwnership_NotFoundFallsBackToAncestor, one level up:
// a ReplicaSet named "web-7d9f8b6c9d" (checkReplicaSetReplicaFailure's own
// anchor object) pruned by revisionHistoryLimit before /analyze runs. Its
// owning Deployment "web" is unaffected and still resolves via its own
// tracking-id annotation.
func TestGetGitOpsOwnership_NotFoundFallsBackToAncestor_ReplicaSetToDeployment(t *testing.T) {
	deploy := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{
		Name: "web", Namespace: "apps", UID: types.UID("d1"),
		Annotations: map[string]string{
			"argocd.argoproj.io/tracking-id": "argus-e2e-web:apps/Deployment:apps/web",
		},
	}}
	// Note: no ReplicaSet object at all — "web-7d9f8b6c9d" is genuinely gone.
	executor := newGitOpsTestExecutor(deploy)

	res := ownershipOf(t, executor, "apps/v1/ReplicaSet", "apps", "web-7d9f8b6c9d")
	if res.ManagedBy != "argocd" {
		t.Fatalf("ManagedBy = %q, want argocd — the vanished ReplicaSet's still-existing Deployment carries the tracking-id", res.ManagedBy)
	}
	if res.AppRef == nil || res.AppRef.Name != "argus-e2e-web" {
		t.Errorf("AppRef = %+v, want the Application name from the ancestor Deployment's tracking-id", res.AppRef)
	}
}

// TestGetGitOpsOwnership_NotFoundFallsBackToAncestor_JobToCronJob is
// checkFailedJobs' own anchor object vanishing the same way: a CronJob-owned
// Job named "nightly-report-1693440000" cleaned up by
// spec.ttlSecondsAfterFinished before /analyze runs. Its owning CronJob is
// unaffected and still resolves via its own tracking-id annotation.
func TestGetGitOpsOwnership_NotFoundFallsBackToAncestor_JobToCronJob(t *testing.T) {
	cronJob := &batchv1.CronJob{ObjectMeta: metav1.ObjectMeta{
		Name: "nightly-report", Namespace: "batch", UID: types.UID("cj1"),
		Annotations: map[string]string{
			"argocd.argoproj.io/tracking-id": "argus-e2e-batch:batch/CronJob:batch/nightly-report",
		},
	}}
	// Note: no Job object at all — "nightly-report-1693440000" is genuinely gone.
	executor := newGitOpsTestExecutor(cronJob)

	res := ownershipOf(t, executor, "batch/v1/Job", "batch", "nightly-report-1693440000")
	if res.ManagedBy != "argocd" {
		t.Fatalf("ManagedBy = %q, want argocd — the vanished Job's still-existing CronJob carries the tracking-id", res.ManagedBy)
	}
	if res.AppRef == nil || res.AppRef.Name != "argus-e2e-batch" {
		t.Errorf("AppRef = %+v, want the Application name from the ancestor CronJob's tracking-id", res.AppRef)
	}
}

// TestGetGitOpsOwnership_NotFoundConfigMapHasNoAncestorFallback is #5a's
// honest negative result: a garbage-collected ConfigMap (AC1's GC-002) gets
// no ancestor guess at all, and must fail exactly like
// TestGetGitOpsOwnership_NotFound's plain "not found" case — proving the
// widening is deliberately bounded to ReplicaSet/Job, not a blind attempt on
// every kind. See vanishedObjectNameFallbackCandidates' doc comment for why
// ConfigMap/Secret cannot be helped the same way a Pod/ReplicaSet/Job can.
func TestGetGitOpsOwnership_NotFoundConfigMapHasNoAncestorFallback(t *testing.T) {
	// A Deployment named "app" exists (and would even be a plausible name-
	// split guess), but ConfigMap is not in vanishedObjectNameFallbackCandidates
	// at all, so it must never be tried.
	deploy := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "app", Namespace: "apps", UID: types.UID("d1")}}
	executor := newGitOpsTestExecutor(deploy)

	_, _, err := executor.getGitOpsOwnership(context.Background(), mustMarshal(getGitOpsOwnershipArgs{
		GVK: "v1/ConfigMap", Namespace: "apps", Name: "app-config",
	}))
	if err == nil {
		t.Fatal("getGitOpsOwnership for a vanished ConfigMap: want error (no ancestor fallback exists for this kind), got nil")
	}
	if err.Error() != "resource not found" {
		t.Errorf("getGitOpsOwnership error = %q, want the sanitized %q — unchanged from before this task's widening", err.Error(), "resource not found")
	}
}

func TestExecute_UnknownTool(t *testing.T) {
	executor, _ := newTestExecutor()
	if _, _, err := executor.Execute(context.Background(), "delete_everything", nil); err == nil {
		t.Fatal("Execute with an unknown tool name: want error, got nil")
	}
}

func TestExecute_DispatchesGetGitOpsOwnership(t *testing.T) {
	deployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Name: "web", Namespace: "default", UID: types.UID("uid-deploy")},
	}
	executor, _ := newTestExecutor(deployment)
	data, _, err := executor.Execute(context.Background(), "get_gitops_ownership", mustMarshal(getGitOpsOwnershipArgs{
		GVK: "apps/v1/Deployment", Namespace: "default", Name: "web",
	}))
	if err != nil {
		t.Fatalf("Execute(get_gitops_ownership): %v", err)
	}
	var result gitOpsOwnershipResult
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("decode result: %v", err)
	}
	if result.ManagedBy != "none" {
		t.Fatalf("ManagedBy = %q, want %q — confirms Execute's switch actually reaches getGitOpsOwnership", result.ManagedBy, "none")
	}
}

func TestExecute_NilExecutorNeverPanics(t *testing.T) {
	var executor *ToolExecutor
	data, truncated, err := executor.Execute(context.Background(), "get_events", nil)
	if err == nil {
		t.Fatal("Execute on a nil ToolExecutor (no reachable cluster): want error, got nil")
	}
	if data != nil || truncated {
		t.Errorf("Execute on a nil ToolExecutor: want (nil, false, err), got (%v, %v, %v)", data, truncated, err)
	}
}

func TestSanitizeK8sErr_NeverEchoesRawError(t *testing.T) {
	rawErr := errors.New("dial tcp 10.0.0.1:6443: connection refused, tls certificate for CN=super-secret-internal-host")
	got := sanitizeK8sErr(rawErr)
	if got.Error() == rawErr.Error() {
		t.Fatal("sanitizeK8sErr must never pass a raw client-go/API-server error string through verbatim")
	}
}

// TestDescribeResourceSupportsEveryKindTheDetectorsEmit is the regression
// guard for a real gap found by driving a live multi-step investigation:
// WORKLOG.md §72/§73 taught the sweep detector to report stuck
// PersistentVolumeClaims, NotReady Nodes, blocked HorizontalPodAutoscalers
// and endpoint-less Services, but supportedGVKs still listed only the eight
// kinds the two older detectors pointed at — so ARGUS would raise an
// incident about a PVC and then fail its own first describe_resource on it
// with "unsupported gvk".
//
// Asserts the two sides agree by construction rather than by memory: every
// GVK string any detector puts on a Finding must be describable.
func TestDescribeResourceSupportsEveryKindTheDetectorsEmit(t *testing.T) {
	// Exactly the GVK strings the detectors set on a Finding — sweep_detector.go's
	// sweepCandidate.GVK values plus the pod/workload kinds the other two use.
	detectorEmitted := []string{
		"v1/Pod",
		"v1/Service",
		"v1/PersistentVolumeClaim",
		"v1/Node",
		"apps/v1/Deployment",
		"apps/v1/StatefulSet",
		"apps/v1/DaemonSet",
		"batch/v1/Job",
		"autoscaling/v2/HorizontalPodAutoscaler",
	}
	for _, gvkStr := range detectorEmitted {
		gvk, err := parseGVKString(gvkStr)
		if err != nil {
			t.Errorf("parseGVKString(%q): %v", gvkStr, err)
			continue
		}
		if _, ok := supportedGVKs[gvk]; !ok {
			t.Errorf("detectors emit GVK %q but supportedGVKs cannot describe it — an incident would be raised that the investigation loop cannot dig into", gvkStr)
		}
	}
}

// TestDefaultRulesGVKsAreSupported is TestDescribeResourceSupportsEveryKindTheDetectorsEmit's
// counterpart for BACKLOG.md E9's declarative rules: the embedded default
// rule set (internal/agent/rules/default-rules.yaml) is a fourth source of
// Finding.GVK values, alongside the three hand-written detectors above, and
// it must satisfy the exact same invariant — every GVK a firing rule could
// put on a Finding has to be describable, or the same "incident raised, then
// the investigation loop's first describe_resource fails" gap this test file
// already guards against reopens through the new mechanism instead of the
// old one. rules.go's own LoadRules/validateRule already enforce this at
// load time for ANY rule file, including a future operator-supplied one —
// this test additionally pins it for the specific default set this binary
// ships, so a future edit to default-rules.yaml that removes RBAC/
// supportedGVKs coverage for a kind it still uses fails a test, not just a
// runtime log line the first time an agent using the default set starts.
func TestDefaultRulesGVKsAreSupported(t *testing.T) {
	rules, err := LoadRules("")
	if err != nil {
		t.Fatalf("LoadRules(\"\") (the embedded default set): %v", err)
	}
	if len(rules) == 0 {
		t.Fatal("the embedded default rule set is empty — BACKLOG.md E9 asks for a representative initial set, not zero rules")
	}
	for _, r := range rules {
		gvk, err := parseGVKString(r.GVK)
		if err != nil {
			t.Errorf("rule %s: parseGVKString(%q): %v", r.ID, r.GVK, err)
			continue
		}
		if _, ok := supportedGVKs[gvk]; !ok {
			t.Errorf("rule %s emits GVK %q but supportedGVKs cannot describe it", r.ID, r.GVK)
		}
	}
}

// TestClusterScopedKindsAreNotNamespaceQualified pins the namespaced flag,
// since getting it wrong is invisible until a real cluster-scoped Get 404s:
// a namespace-qualified request for a Node returns not-found rather than an
// obvious error.
func TestClusterScopedKindsAreNotNamespaceQualified(t *testing.T) {
	clusterScoped := []string{
		"v1/Node", "v1/PersistentVolume", "storage.k8s.io/v1/StorageClass",
		"rbac.authorization.k8s.io/v1/ClusterRole", "rbac.authorization.k8s.io/v1/ClusterRoleBinding",
		"scheduling.k8s.io/v1/PriorityClass", "certificates.k8s.io/v1/CertificateSigningRequest",
	}
	for _, gvkStr := range clusterScoped {
		gvk, _ := parseGVKString(gvkStr)
		res, ok := supportedGVKs[gvk]
		if !ok {
			t.Errorf("%q missing from supportedGVKs", gvkStr)
			continue
		}
		if res.namespaced {
			t.Errorf("%q is cluster-scoped but is marked namespaced — a Get would be namespace-qualified and 404", gvkStr)
		}
	}
	// And a spot-check the other way, so the flag isn't just false everywhere.
	podGVK, _ := parseGVKString("v1/Pod")
	if !supportedGVKs[podGVK].namespaced {
		t.Error("v1/Pod must be namespaced")
	}
}

// TestDescribeResourceOnAPersistentVolumeClaim exercises the actual path that
// failed live: describe_resource against a PVC.
func TestDescribeResourceOnAPersistentVolumeClaim(t *testing.T) {
	pvc := &corev1.PersistentVolumeClaim{
		ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "spack-cache"},
		Spec:       corev1.PersistentVolumeClaimSpec{StorageClassName: strPtr("standard")},
		Status:     corev1.PersistentVolumeClaimStatus{Phase: corev1.ClaimPending},
	}
	exec, _ := newTestExecutor(pvc)

	raw, _, err := exec.Execute(context.Background(), "describe_resource",
		json.RawMessage(`{"gvk":"v1/PersistentVolumeClaim","namespace":"apps","name":"spack-cache"}`))
	if err != nil {
		t.Fatalf("describe_resource on a PVC failed: %v", err)
	}
	var out struct {
		Object map[string]any `json:"object"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}
	if out.Object["kind"] != "PersistentVolumeClaim" {
		t.Errorf("returned object kind = %v, want PersistentVolumeClaim", out.Object["kind"])
	}
}

// --- BACKLOG.md "still open" #1: the 2026-08-29 supportedGVKs widening ---

// TestDescribeResource_NewlyAddedKindsAreReachable is
// TestDescribeResourceOnAPersistentVolumeClaim's counterpart for the seven
// non-Secret kinds this change adds: each one unblocks a specific finding
// named in BACKLOG.md (AC1/AJ1 for the RBAC kinds and ServiceAccount, AE1 for
// PriorityClass, W2 for CertificateSigningRequest, AD1 for ServiceMonitor),
// and the shared regression this whole file exists to prevent is "an
// incident names a kind describe_resource cannot fetch" — so each of these
// gets the same live-fetch-through-Execute proof PVC already has above,
// rather than a bare presence check against the map.
func TestDescribeResource_NewlyAddedKindsAreReachable(t *testing.T) {
	role := &rbacv1.Role{ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "web-reader"}}
	roleBinding := &rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "web-reader-binding"}}
	clusterRole := &rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "fleet-viewer"}}
	clusterRoleBinding := &rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "fleet-viewer-binding"}}
	serviceAccount := &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "web"}}
	priorityClass := &schedulingv1.PriorityClass{ObjectMeta: metav1.ObjectMeta{Name: "high-priority"}, Value: 1000000}
	csr := &certificatesv1.CertificateSigningRequest{ObjectMeta: metav1.ObjectMeta{Name: "node-csr-abc123"}}
	serviceMonitor := unstructuredOf("monitoring.coreos.com/v1", "ServiceMonitor", "apps", "web", nil, map[string]any{"selector": map[string]any{}}, nil)

	executor, _ := newTestExecutor(role, roleBinding, clusterRole, clusterRoleBinding, serviceAccount, priorityClass, csr)
	// ServiceMonitor is a CRD kind not in k8sscheme.Scheme, so it goes into a
	// second executor the same way the GitOps CRD tests build theirs
	// (newGitOpsTestExecutor) — a single fake tracker mixing scheme-typed
	// objects and raw unstructured ones works fine for Get, which is all
	// this test needs.
	smExecutor := newGitOpsTestExecutor(serviceMonitor)

	cases := []struct {
		name      string
		exec      *ToolExecutor
		gvk       string
		namespace string
		objName   string
		wantKind  string
	}{
		{"Role", executor, "rbac.authorization.k8s.io/v1/Role", "apps", "web-reader", "Role"},
		{"RoleBinding", executor, "rbac.authorization.k8s.io/v1/RoleBinding", "apps", "web-reader-binding", "RoleBinding"},
		{"ClusterRole", executor, "rbac.authorization.k8s.io/v1/ClusterRole", "", "fleet-viewer", "ClusterRole"},
		{"ClusterRoleBinding", executor, "rbac.authorization.k8s.io/v1/ClusterRoleBinding", "", "fleet-viewer-binding", "ClusterRoleBinding"},
		{"ServiceAccount", executor, "v1/ServiceAccount", "apps", "web", "ServiceAccount"},
		{"PriorityClass", executor, "scheduling.k8s.io/v1/PriorityClass", "", "high-priority", "PriorityClass"},
		{"CertificateSigningRequest", executor, "certificates.k8s.io/v1/CertificateSigningRequest", "", "node-csr-abc123", "CertificateSigningRequest"},
		{"ServiceMonitor", smExecutor, "monitoring.coreos.com/v1/ServiceMonitor", "apps", "web", "ServiceMonitor"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw, _, err := tc.exec.Execute(context.Background(), "describe_resource", mustMarshal(describeResourceArgs{
				GVK: tc.gvk, Namespace: tc.namespace, Name: tc.objName,
			}))
			if err != nil {
				t.Fatalf("describe_resource(%s): %v", tc.gvk, err)
			}
			var out struct {
				Object map[string]any `json:"object"`
			}
			if err := json.Unmarshal(raw, &out); err != nil {
				t.Fatalf("unmarshal result: %v", err)
			}
			if out.Object["kind"] != tc.wantKind {
				t.Errorf("returned object kind = %v, want %v", out.Object["kind"], tc.wantKind)
			}
		})
	}
}

// TestListResources_NewlyAddedNamespacedAndClusterScopedKindsAreReachable is
// TestDescribeResource_NewlyAddedKindsAreReachable's list_resources
// counterpart: describe_resource and list_resources share supportedGVKs but
// are separate code paths (separate dynamic client calls, separate
// projections), so reachability through one is not evidence for the other.
// One namespaced kind (Role) and one cluster-scoped kind (ClusterRole) are
// exercised — Secret is deliberately excluded from this list, since
// TestListResources_SecretCannotBeEnumerated pins the opposite behavior for
// it on purpose.
func TestListResources_NewlyAddedNamespacedAndClusterScopedKindsAreReachable(t *testing.T) {
	role := &rbacv1.Role{ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "web-reader"}}
	clusterRole := &rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "fleet-viewer"}}
	executor, _ := newTestExecutor(role, clusterRole)

	raw, _, err := executor.Execute(context.Background(), "list_resources", mustMarshal(listResourcesArgs{
		Kind: "Role", Namespace: "apps",
	}))
	if err != nil {
		t.Fatalf("list_resources(Role): %v", err)
	}
	var roleResult listResourcesResult
	if err := json.Unmarshal(raw, &roleResult); err != nil {
		t.Fatalf("unmarshal Role result: %v", err)
	}
	if len(roleResult.Items) != 1 || roleResult.Items[0].Name != "web-reader" {
		t.Fatalf("list_resources(Role) items = %+v, want the one Role", roleResult.Items)
	}

	raw, _, err = executor.Execute(context.Background(), "list_resources", mustMarshal(listResourcesArgs{
		Kind: "ClusterRole",
	}))
	if err != nil {
		t.Fatalf("list_resources(ClusterRole): %v", err)
	}
	var clusterRoleResult listResourcesResult
	if err := json.Unmarshal(raw, &clusterRoleResult); err != nil {
		t.Fatalf("unmarshal ClusterRole result: %v", err)
	}
	if len(clusterRoleResult.Items) != 1 || clusterRoleResult.Items[0].Name != "fleet-viewer" {
		t.Fatalf("list_resources(ClusterRole) items = %+v, want the one ClusterRole", clusterRoleResult.Items)
	}
}

// TestDescribeResource_SecretReturnsMetadataAndTypeOnly is this task's most
// safety-sensitive test: it proves data/stringData are ABSENT from a
// describe_resource result for a Secret — not present-but-redacted, which
// internal/redact's existing data/stringData handling would produce for any
// OTHER kind (it keeps keys, marks values) — and that metadata/type survive.
// Built as raw unstructured JSON, not a typed corev1.Secret round-tripped
// through the scheme, so the test object demonstrably carries "data" and
// "stringData" keys the way a real Secret fetched from a live API server
// would, rather than relying on Go zero-value omission to accidentally make
// the assertion trivially true.
func TestDescribeResource_SecretReturnsMetadataAndTypeOnly(t *testing.T) {
	secret := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "v1",
		"kind":       "Secret",
		"metadata": map[string]any{
			"name":              "db-creds",
			"namespace":         "apps",
			"labels":            map[string]any{"app": "web"},
			"annotations":       map[string]any{"argus.io/example": "true"},
			"creationTimestamp": "2026-08-01T00:00:00Z",
		},
		"type": "Opaque",
		"data": map[string]any{
			"password": "aHVudGVyMg==", // base64("hunter2")
		},
		"stringData": map[string]any{
			"password": "hunter2",
		},
	}}
	executor := newGitOpsTestExecutor(secret)

	raw, _, err := executor.Execute(context.Background(), "describe_resource", mustMarshal(describeResourceArgs{
		GVK: "v1/Secret", Namespace: "apps", Name: "db-creds",
	}))
	if err != nil {
		t.Fatalf("describe_resource on a Secret: %v", err)
	}

	// Belt and suspenders, ahead of the structured checks below: neither raw
	// credential value may appear ANYWHERE in the wire bytes, redacted marker
	// or not — there should be no key at all for them to hide behind.
	if strings.Contains(string(raw), "hunter2") || strings.Contains(string(raw), "aHVudGVyMg==") {
		t.Fatalf("describe_resource(Secret) result contains the raw credential value verbatim: %s", raw)
	}

	var out struct {
		Object map[string]any `json:"object"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}
	if _, present := out.Object["data"]; present {
		t.Errorf("describe_resource(Secret) result carries a %q key at all: %v — must be genuinely absent, not redacted", "data", out.Object["data"])
	}
	if _, present := out.Object["stringData"]; present {
		t.Errorf("describe_resource(Secret) result carries a %q key at all: %v — must be genuinely absent, not redacted", "stringData", out.Object["stringData"])
	}
	if out.Object["type"] != "Opaque" {
		t.Errorf("describe_resource(Secret) result type = %v, want %q", out.Object["type"], "Opaque")
	}
	metadata, _ := out.Object["metadata"].(map[string]any)
	if metadata == nil {
		t.Fatalf("describe_resource(Secret) result has no metadata block: %+v", out.Object)
	}
	if metadata["name"] != "db-creds" || metadata["namespace"] != "apps" {
		t.Errorf("describe_resource(Secret) metadata = %+v, want name=db-creds namespace=apps", metadata)
	}
	labels, _ := metadata["labels"].(map[string]any)
	if labels["app"] != "web" {
		t.Errorf("describe_resource(Secret) metadata.labels = %+v, want app=web preserved", metadata["labels"])
	}
	// Only the two fields this task's brief names may appear at the object's
	// top level — apiVersion/kind (present on every kind) plus metadata/type.
	// Any other top-level key would mean secretMetadataOnly grew a new,
	// unreviewed pass-through.
	wantKeys := map[string]bool{"apiVersion": true, "kind": true, "metadata": true, "type": true}
	for k := range out.Object {
		if !wantKeys[k] {
			t.Errorf("describe_resource(Secret) result has unexpected top-level key %q", k)
		}
	}
}

// --- list_resources ---
//
// The tool BACKLOG.md C1 adds because the other five all
// require a name the caller already has. The tests below are weighted towards
// the truncation contract on purpose: a wrong projection field is a cosmetic
// bug, whereas a truncated list that does not admit it is a correctness bug
// in every conclusion drawn from it (see TestListResources_TruncationIsExplicit).

// testPod builds a Pod with a container-readiness tally, so the projection's
// "n/m ready" derivation is exercised against the real shape rather than a
// hand-built unstructured map.
func testPod(namespace, name, phase string, readyContainers, totalContainers int) *corev1.Pod {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name},
		Status:     corev1.PodStatus{Phase: corev1.PodPhase(phase)},
	}
	for i := 0; i < totalContainers; i++ {
		pod.Status.ContainerStatuses = append(pod.Status.ContainerStatuses, corev1.ContainerStatus{
			Name:  "c" + string(rune('0'+i)),
			Ready: i < readyContainers,
		})
	}
	return pod
}

func TestListResources_EnumeratesOneNamespaceWithACompactProjection(t *testing.T) {
	created := time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)
	web1 := testPod("apps", "web-1", "Running", 2, 2)
	web1.CreationTimestamp = metav1.NewTime(created)

	executor, _ := newTestExecutor(
		testPod("apps", "web-2", "Running", 1, 2),
		web1,
		// Same kind, different namespace: must not appear. A list that leaks
		// neighbouring namespaces would make "is it in a different namespace?"
		// — the exact question WORKLOG.md §86 could not answer — unanswerable
		// in the other direction too.
		testPod("other", "web-3", "Running", 1, 1),
	)

	data, truncated, err := executor.Execute(context.Background(), "list_resources",
		json.RawMessage(`{"kind":"Pod","namespace":"apps"}`))
	if err != nil {
		t.Fatalf("Execute(list_resources): %v", err)
	}
	if truncated {
		t.Error("truncated = true for a 2-item result under the default limit, want false")
	}

	var result listResourcesResult
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("decode result: %v", err)
	}
	if result.GVK != "v1/Pod" || result.Namespace != "apps" {
		t.Errorf("result gvk/namespace = %q/%q, want \"v1/Pod\"/\"apps\" — the echo a caller feeds into describe_resource", result.GVK, result.Namespace)
	}
	if result.TotalMatched != 2 || result.Returned != 2 || result.Truncated {
		t.Fatalf("totalMatched/returned/truncated = %d/%d/%v, want 2/2/false: %+v", result.TotalMatched, result.Returned, result.Truncated, result.Items)
	}
	// Name-sorted, not API-server order.
	if result.Items[0].Name != "web-1" || result.Items[1].Name != "web-2" {
		t.Fatalf("items are not name-sorted: %+v", result.Items)
	}
	if result.Items[0].Phase != "Running" || result.Items[0].Ready != "2/2" {
		t.Errorf("web-1 projection = %+v, want phase Running ready 2/2", result.Items[0])
	}
	if result.Items[1].Ready != "1/2" {
		t.Errorf("web-2 ready = %q, want \"1/2\" — the partially-ready tally is the whole reason this field exists", result.Items[1].Ready)
	}
	// creationTimestamp is carried through, which is what makes "this has been
	// stuck for 156 days" (CAPABILITIES.md §2's case) visible from a list
	// without a describe_resource per item.
	if !result.Items[0].CreationTimestamp.Equal(created) {
		t.Errorf("web-1 creationTimestamp = %v, want %v", result.Items[0].CreationTimestamp, created)
	}
}

// TestListResources_CanResolveAServiceSelectorAcrossNamespacesWhenExplicitlyAsked
// is BACKLOG.md "still open" #12 / AQ1 / CAPABILITIES.md's `SVC-002` fixture,
// reproduced exactly: a Service ("svc002-shared") in one namespace
// ("argus-r53-svc002-a") whose selector (app: svc002-shared) matches Pods
// that actually live in a different namespace ("argus-r53-svc002-b"). Before
// this task, the investigation loop only ever called list_resources scoped
// to the incident's own namespace (argus-r53-svc002-a), where the selector
// genuinely matches nothing — the exact structurally-undiscoverable premise
// AQ1 records, reached at 0.95 confidence with the false claim that no such
// workload exists anywhere.
//
// list_resources was never code-restricted to the incident's own namespace —
// args.Namespace already flows straight to the List call for whatever
// namespace is named (see listResources' own doc comment). What was missing
// was reason for the model to ever name a different one; that's the system
// prompt/tool-description fix (internal/llm/toolloop.go), covered separately
// by TestSystemPromptGuidesCrossNamespaceServiceSelectorCheck. This test
// proves the code path itself: a caller that explicitly checks the OTHER,
// specific namespace (exactly what the new guidance tells the model to do)
// correctly finds the workload that was there the entire time.
func TestListResources_CanResolveAServiceSelectorAcrossNamespacesWhenExplicitlyAsked(t *testing.T) {
	const serviceNamespace = "argus-r53-svc002-a"
	const workloadNamespace = "argus-r53-svc002-b"
	selector := map[string]string{"app": "svc002-shared"}

	pod1 := testPod(workloadNamespace, "svc002-shared-abc123", "Running", 1, 1)
	pod1.Labels = selector
	pod2 := testPod(workloadNamespace, "svc002-shared-def456", "Running", 1, 1)
	pod2.Labels = selector
	deployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Namespace: workloadNamespace, Name: "svc002-shared", Labels: selector},
		Spec:       appsv1.DeploymentSpec{Replicas: int32Ptr(2)},
		Status:     appsv1.DeploymentStatus{ReadyReplicas: 2, Replicas: 2},
	}
	// The Service itself, in its own namespace, with no Pod or Deployment
	// alongside it — mirrors the fixture's "the namespace contains only the
	// Service itself" observation.
	svc := testService(serviceNamespace, "svc002-shared")
	svc.Spec.Selector = selector

	executor, _ := newTestExecutor(svc, pod1, pod2, deployment)

	// First, the call the model made before this fix: scoped to the Service's
	// own (the incident's own) namespace. This must still find nothing — that
	// is the real, correct signal a Service-selector mismatch produces, and
	// this fix does not change it.
	sameNSData, _, err := executor.listResources(context.Background(), mustMarshal(listResourcesArgs{
		Kind: "Pod", Namespace: serviceNamespace, LabelSelector: "app=svc002-shared",
	}))
	if err != nil {
		t.Fatalf("listResources(Pod, %s): %v", serviceNamespace, err)
	}
	var sameNSResult listResourcesResult
	if err := json.Unmarshal(sameNSData, &sameNSResult); err != nil {
		t.Fatalf("decode same-namespace result: %v", err)
	}
	if sameNSResult.TotalMatched != 0 {
		t.Fatalf("listResources(Pod, %s) totalMatched = %d, want 0 — the Service's own namespace genuinely has no matching Pod",
			serviceNamespace, sameNSResult.TotalMatched)
	}

	// Now the call this fix's guidance tells the model to make once it has a
	// concrete namespace to suspect: the SAME selector, against the OTHER,
	// explicitly named namespace. This must now find the workload.
	otherNSData, _, err := executor.listResources(context.Background(), mustMarshal(listResourcesArgs{
		Kind: "Pod", Namespace: workloadNamespace, LabelSelector: "app=svc002-shared",
	}))
	if err != nil {
		t.Fatalf("listResources(Pod, %s): %v", workloadNamespace, err)
	}
	var otherNSResult listResourcesResult
	if err := json.Unmarshal(otherNSData, &otherNSResult); err != nil {
		t.Fatalf("decode other-namespace result: %v", err)
	}
	if otherNSResult.TotalMatched != 2 || otherNSResult.Returned != 2 {
		t.Fatalf("listResources(Pod, %s) totalMatched/returned = %d/%d, want 2/2 — the workload AQ1 said did not exist anywhere",
			workloadNamespace, otherNSResult.TotalMatched, otherNSResult.Returned)
	}
	names := map[string]bool{}
	for _, item := range otherNSResult.Items {
		names[item.Name] = true
	}
	if !names["svc002-shared-abc123"] || !names["svc002-shared-def456"] {
		t.Errorf("other-namespace items = %+v, want both svc002-shared pods", otherNSResult.Items)
	}

	// And the Deployment itself is likewise discoverable once the caller
	// names the right namespace — the full AQ1 correction, not just the Pods.
	deployData, _, err := executor.listResources(context.Background(), mustMarshal(listResourcesArgs{
		Kind: "Deployment", Namespace: workloadNamespace, LabelSelector: "app=svc002-shared",
	}))
	if err != nil {
		t.Fatalf("listResources(Deployment, %s): %v", workloadNamespace, err)
	}
	var deployResult listResourcesResult
	if err := json.Unmarshal(deployData, &deployResult); err != nil {
		t.Fatalf("decode deployment result: %v", err)
	}
	if deployResult.TotalMatched != 1 || len(deployResult.Items) != 1 || deployResult.Items[0].Name != "svc002-shared" {
		t.Fatalf("listResources(Deployment, %s) = %+v, want exactly the one svc002-shared Deployment",
			workloadNamespace, deployResult)
	}
}

// TestListResources_CrossNamespaceCheckStaysBoundedToOneNamedNamespace pins
// the "still bounded" half of BACKLOG.md #12's fix: naming a different,
// explicit namespace is a repeatable single-namespace call, exactly like
// every other list_resources call — never a scan of every namespace, and
// never usable without naming one.
func TestListResources_CrossNamespaceCheckStaysBoundedToOneNamedNamespace(t *testing.T) {
	selector := map[string]string{"app": "svc002-shared"}
	podA := testPod("argus-r53-svc002-a", "unrelated-a", "Running", 1, 1)
	podB := testPod("argus-r53-svc002-b", "svc002-shared-abc123", "Running", 1, 1)
	podB.Labels = selector
	podC := testPod("argus-r53-svc002-c", "svc002-shared-should-not-appear", "Running", 1, 1)
	podC.Labels = selector

	executor, _ := newTestExecutor(podA, podB, podC)

	// Naming namespace B must return ONLY namespace B's matching Pod, never
	// namespace C's same-labeled one — a cross-namespace check is still one
	// namespace per call, not a fan-out across every namespace that happens to
	// have a match.
	data, _, err := executor.listResources(context.Background(), mustMarshal(listResourcesArgs{
		Kind: "Pod", Namespace: "argus-r53-svc002-b", LabelSelector: "app=svc002-shared",
	}))
	if err != nil {
		t.Fatalf("listResources: %v", err)
	}
	var result listResourcesResult
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("decode result: %v", err)
	}
	if result.TotalMatched != 1 || len(result.Items) != 1 || result.Items[0].Name != "svc002-shared-abc123" {
		t.Fatalf("items = %+v, want exactly namespace B's one matching Pod — a named-namespace check must not also surface namespace C's match", result.Items)
	}

	// There is still no all-namespaces mode: a namespaced kind with no
	// namespace at all is still rejected, exactly as it always was.
	if _, _, err := executor.listResources(context.Background(), mustMarshal(listResourcesArgs{
		Kind: "Pod", LabelSelector: "app=svc002-shared",
	})); err == nil {
		t.Error("listResources(Pod, no namespace, label matching 3 namespaces): want error, got nil — there must be no unbounded cross-namespace mode")
	}
}

func TestListResources_ProjectsWorkloadReplicaReadiness(t *testing.T) {
	// The measured case from WORKLOG.md §86: the investigator needed to know
	// whether a Deployment existed in the namespace at all, and — once it
	// does — "0/3 ready" is the answer, not a name it then has to describe.
	// spec.replicas is the only counter set here (status is empty, as it is on
	// a workload the controller has not reconciled), pinning the documented
	// status-then-spec fallback.
	deployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "web"},
		Spec:       appsv1.DeploymentSpec{Replicas: int32Ptr(3)},
	}
	executor, _ := newTestExecutor(deployment)

	data, _, err := executor.listResources(context.Background(), mustMarshal(listResourcesArgs{Kind: "Deployment", Namespace: "apps"}))
	if err != nil {
		t.Fatalf("listResources: %v", err)
	}
	var result listResourcesResult
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("decode result: %v", err)
	}
	if len(result.Items) != 1 || result.Items[0].Ready != "0/3" {
		t.Fatalf("items = %+v, want one item with ready \"0/3\"", result.Items)
	}
}

func TestListResources_TruncationIsExplicitAndReportsTheRealTotal(t *testing.T) {
	// The single most important behaviour in this tool. A caller that receives
	// 10 of 120 Pods and is not told so will conclude things about the 110 it
	// never saw — so this asserts all three signals independently: the cut
	// happened, the payload admits it, and the payload states the true size.
	const total = 120
	objs := make([]runtime.Object, 0, total)
	for i := 0; i < total; i++ {
		objs = append(objs, testPod("apps", fmt.Sprintf("pod-%03d", i), "Running", 1, 1))
	}
	executor, _ := newTestExecutor(objs...)

	data, truncated, err := executor.Execute(context.Background(), "list_resources",
		json.RawMessage(`{"kind":"Pod","namespace":"apps","limit":10}`))
	if err != nil {
		t.Fatalf("Execute(list_resources): %v", err)
	}
	if !truncated {
		t.Error("Execute's truncated return = false, want true")
	}

	var result listResourcesResult
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("decode result: %v", err)
	}
	if !result.Truncated {
		t.Error("payload truncated = false — the wire-level flag is dropped before the model sees it, so this field is the only signal that survives")
	}
	if result.TotalMatched != total {
		t.Errorf("totalMatched = %d, want the real total %d (not the returned count, and not a \"at least\" floor)", result.TotalMatched, total)
	}
	if result.Returned != 10 || len(result.Items) != 10 {
		t.Fatalf("returned/len(items) = %d/%d, want 10/10", result.Returned, len(result.Items))
	}
	// The window is the first 10 by name, deterministically — two identical
	// calls against an unchanged cluster must agree.
	if result.Items[0].Name != "pod-000" || result.Items[9].Name != "pod-009" {
		t.Errorf("truncated window = %q..%q, want pod-000..pod-009", result.Items[0].Name, result.Items[9].Name)
	}
}

func TestListResources_LimitIsCappedNotHonoredVerbatim(t *testing.T) {
	const total = maxListLimit + 25
	objs := make([]runtime.Object, 0, total)
	for i := 0; i < total; i++ {
		objs = append(objs, testPod("apps", fmt.Sprintf("pod-%03d", i), "Running", 1, 1))
	}
	executor, _ := newTestExecutor(objs...)

	data, _, err := executor.listResources(context.Background(), mustMarshal(listResourcesArgs{
		Kind:      "Pod",
		Namespace: "apps",
		Limit:     100000,
	}))
	if err != nil {
		t.Fatalf("listResources: %v", err)
	}
	var result listResourcesResult
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("decode result: %v", err)
	}
	if result.Returned != maxListLimit || !result.Truncated {
		t.Fatalf("returned/truncated = %d/%v for limit=100000, want %d/true — the ceiling is not raisable by argument", result.Returned, result.Truncated, maxListLimit)
	}
	if result.TotalMatched != total {
		t.Errorf("totalMatched = %d, want %d", result.TotalMatched, total)
	}
}

func TestListResources_LabelSelectorNarrowsTheMatchedSet(t *testing.T) {
	web1 := testPod("apps", "web-1", "Running", 1, 1)
	web1.Labels = map[string]string{"app": "web"}
	web2 := testPod("apps", "web-2", "Running", 1, 1)
	web2.Labels = map[string]string{"app": "web"}
	api1 := testPod("apps", "api-1", "Running", 1, 1)
	api1.Labels = map[string]string{"app": "api"}

	executor, _ := newTestExecutor(web1, web2, api1)

	data, _, err := executor.listResources(context.Background(), mustMarshal(listResourcesArgs{
		Kind:          "Pod",
		Namespace:     "apps",
		LabelSelector: "app=web",
	}))
	if err != nil {
		t.Fatalf("listResources: %v", err)
	}
	var result listResourcesResult
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("decode result: %v", err)
	}
	// totalMatched, not just the returned window: the selector is applied
	// where the list happens, so a caller narrowing a truncated result with a
	// selector genuinely shrinks the set it might be missing.
	if result.TotalMatched != 2 || result.Returned != 2 {
		t.Fatalf("totalMatched/returned = %d/%d for app=web, want 2/2: %+v", result.TotalMatched, result.Returned, result.Items)
	}
	for _, item := range result.Items {
		if item.Name == "api-1" {
			t.Errorf("app=web selector returned api-1: %+v", result.Items)
		}
	}
}

func TestListResources_MalformedLabelSelectorIsRejectedLocally(t *testing.T) {
	// Not sent to the API server to come back as a generic 400 that
	// sanitizeK8sErr flattens to "kubernetes API request failed" — the caller
	// needs to know it was the selector.
	executor, _ := newTestExecutor()
	_, _, err := executor.listResources(context.Background(), mustMarshal(listResourcesArgs{
		Kind:          "Pod",
		Namespace:     "apps",
		LabelSelector: "app=!!!broken",
	}))
	if err == nil {
		t.Fatal("listResources with a malformed labelSelector: want error, got nil")
	}
	if !strings.Contains(err.Error(), "labelSelector") {
		t.Errorf("error = %q, want it to name labelSelector as the bad argument", err.Error())
	}
}

func TestListResources_NamespaceRulesMatchTheKindsScope(t *testing.T) {
	// Both halves of requireNamespaceFor, which list_resources reuses rather
	// than reimplementing: a namespaced kind cannot be listed cluster-wide
	// (that is the unbounded case the caps exist to prevent), and a namespace
	// passed for a cluster-scoped kind is a caller misunderstanding worth
	// reporting rather than silently ignoring.
	executor, _ := newTestExecutor(
		testPod("apps", "web-1", "Running", 1, 1),
		&corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "node-1"}},
	)

	if _, _, err := executor.listResources(context.Background(), mustMarshal(listResourcesArgs{Kind: "Pod"})); err == nil {
		t.Error("list_resources for a namespaced kind with no namespace: want error, got nil")
	}
	if _, _, err := executor.listResources(context.Background(), mustMarshal(listResourcesArgs{Kind: "Node", Namespace: "apps"})); err == nil {
		t.Error("list_resources for the cluster-scoped Node WITH a namespace: want error, got nil")
	}

	// And the cluster-scoped kind listed correctly, so the rule above isn't
	// just "Node never works".
	data, _, err := executor.listResources(context.Background(), mustMarshal(listResourcesArgs{Kind: "Node"}))
	if err != nil {
		t.Fatalf("listResources(Node, no namespace): %v", err)
	}
	var result listResourcesResult
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("decode result: %v", err)
	}
	if result.Namespace != "" {
		t.Errorf("result namespace = %q for a cluster-scoped kind, want empty", result.Namespace)
	}
	if len(result.Items) != 1 || result.Items[0].Name != "node-1" {
		t.Fatalf("items = %+v, want the one Node", result.Items)
	}
}

func TestListResources_UnsupportedKindIsRejectedWithTheSupportedSet(t *testing.T) {
	executor, _ := newTestExecutor()
	// PodTemplate, not Secret: Secret is a recognized (supportedGVKs) kind
	// now, just one list_resources explicitly refuses to enumerate — see
	// TestListResources_SecretCannotBeEnumerated. This test is about a kind
	// this map has never heard of at all.
	_, _, err := executor.listResources(context.Background(), mustMarshal(listResourcesArgs{
		Kind:      "PodTemplate",
		Namespace: "apps",
	}))
	if err == nil {
		t.Fatal("list_resources for an unsupported kind: want error, got nil")
	}
	// Self-correcting: the caller is usually a model spending a turn out of a
	// bounded budget, so the error names what IS listable.
	if !strings.Contains(err.Error(), "Deployment") {
		t.Errorf("error = %q, want it to list the supported kinds so the caller can retry correctly", err.Error())
	}

	if _, _, err := executor.listResources(context.Background(), mustMarshal(listResourcesArgs{Namespace: "apps"})); err == nil {
		t.Error("list_resources with no kind at all: want error, got nil")
	}
}

// TestListResources_SecretCannotBeEnumerated pins BACKLOG.md "still open"
// #1's narrower reachability for Secret: describe_resource can look one up
// by name (TestDescribeResource_SecretReturnsMetadataAndTypeOnly), but
// list_resources refuses outright rather than enumerating every Secret in a
// namespace — clusterrole.yaml deliberately grants only "get" on secrets,
// never "list"/"watch", and this refusal is the explicit, readable version
// of that same guarantee rather than an RBAC 403 the caller has to infer it
// from.
func TestListResources_SecretCannotBeEnumerated(t *testing.T) {
	executor, _ := newTestExecutor()
	_, _, err := executor.listResources(context.Background(), mustMarshal(listResourcesArgs{
		Kind:      "Secret",
		Namespace: "apps",
	}))
	if err == nil {
		t.Fatal("list_resources for Secret: want error, got nil")
	}
	if !strings.Contains(err.Error(), "does not support Secret") {
		t.Errorf("error = %q, want it to explicitly name Secret as refused rather than a generic failure", err.Error())
	}
}

func TestListResources_AlsoAcceptsTheGVKFormTheOtherToolsUse(t *testing.T) {
	// A caller holding a Finding.GVK, or a model that just made four calls in
	// the "[group/]version/Kind" convention, must not lose a turn to a
	// gratuitously different argument name.
	executor, _ := newTestExecutor(testPod("apps", "web-1", "Running", 1, 1))

	data, _, err := executor.listResources(context.Background(), mustMarshal(listResourcesArgs{
		GVK:       "v1/Pod",
		Namespace: "apps",
	}))
	if err != nil {
		t.Fatalf("listResources by gvk: %v", err)
	}
	var result listResourcesResult
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("decode result: %v", err)
	}
	if len(result.Items) != 1 || result.Items[0].Name != "web-1" {
		t.Fatalf("items = %+v, want the one Pod", result.Items)
	}
}

// TestListableKindNamesAreUnambiguous guards the assumption resolveListKind's
// bare-kind lookup rests on: no two supported GVKs share a Kind name today.
// If one ever does, the lookup correctly refuses rather than guessing — but
// the advertised "kind" argument silently stops working for that name, which
// is worth failing here rather than discovering mid-investigation.
func TestListableKindNamesAreUnambiguous(t *testing.T) {
	for name, candidates := range listableKindsByName {
		if len(candidates) != 1 {
			t.Errorf("kind name %q maps to %d GVKs (%v) — list_resources' kind argument can no longer resolve it; callers must pass gvk", name, len(candidates), candidates)
		}
	}
	if len(listableKindsByName) != len(supportedGVKs) {
		t.Errorf("indexed %d kind names from %d supported GVKs — the index dropped some", len(listableKindsByName), len(supportedGVKs))
	}
}

func strPtr(s string) *string { return &s }

func int32Ptr(i int32) *int32 { return &i }

// --- list_nodeport_allocations (BACKLOG.md "still open" #11) ---
//
// A dedicated typed-fake constructor rather than newTestExecutor: this tool
// reads e.typed.CoreV1().Services directly (the same "typed client, no
// dynamic dispatch" shape get_events/get_logs use, not the generic
// supportedGVKs dynamic path list_resources/describe_resource share), and
// newTestExecutor's typed fake is always seeded empty — only its dynamic
// fake takes constructor arguments.

func testService(namespace, name string, ports ...corev1.ServicePort) *corev1.Service {
	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name},
		Spec:       corev1.ServiceSpec{Ports: ports},
	}
}

func newNodePortTestExecutor(services ...runtime.Object) *ToolExecutor {
	return &ToolExecutor{typed: k8sfake.NewSimpleClientset(services...)}
}

// TestListNodePortAllocations_TargetedCheckFindsAnAllocatedPort is the
// positive case: AM1's actual need, a specific candidate port that turns out
// to already be taken, and by which Service.
func TestListNodePortAllocations_TargetedCheckFindsAnAllocatedPort(t *testing.T) {
	svc := testService("prod", "web", corev1.ServicePort{Name: "http", Protocol: corev1.ProtocolTCP, Port: 80, NodePort: 30500})
	executor := newNodePortTestExecutor(svc)

	data, truncated, err := executor.Execute(context.Background(), "list_nodeport_allocations",
		mustMarshal(listNodePortAllocationsArgs{Port: 30500}))
	if err != nil {
		t.Fatalf("Execute(list_nodeport_allocations): %v", err)
	}
	if truncated {
		t.Error("truncated = true for a single targeted port check, want false")
	}
	var result listNodePortAllocationsResult
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("decode result: %v", err)
	}
	if result.Port == nil || *result.Port != 30500 {
		t.Fatalf("Port = %v, want 30500 echoed back", result.Port)
	}
	if result.Available == nil || *result.Available {
		t.Fatalf("Available = %v, want false — a Service already holds this port", result.Available)
	}
	if len(result.Allocations) != 1 {
		t.Fatalf("Allocations = %+v, want exactly the one holding Service", result.Allocations)
	}
	if alloc := result.Allocations[0]; alloc.Namespace != "prod" || alloc.Service != "web" || alloc.Protocol != "TCP" || alloc.ServicePort != "http" {
		t.Errorf("allocation = %+v, want prod/web TCP http", alloc)
	}
}

// TestListNodePortAllocations_TargetedCheckReportsAFreePortAvailable is the
// negative case: a port nothing in the cluster holds must come back
// available, not merely absent from some other list a caller has to infer
// freedom from.
func TestListNodePortAllocations_TargetedCheckReportsAFreePortAvailable(t *testing.T) {
	svc := testService("prod", "web", corev1.ServicePort{Name: "http", Protocol: corev1.ProtocolTCP, Port: 80, NodePort: 30500})
	executor := newNodePortTestExecutor(svc)

	data, _, err := executor.Execute(context.Background(), "list_nodeport_allocations",
		mustMarshal(listNodePortAllocationsArgs{Port: 30501}))
	if err != nil {
		t.Fatalf("Execute(list_nodeport_allocations): %v", err)
	}
	var result listNodePortAllocationsResult
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("decode result: %v", err)
	}
	if result.Port == nil || *result.Port != 30501 {
		t.Fatalf("Port = %v, want 30501 echoed back", result.Port)
	}
	if result.Available == nil || !*result.Available {
		t.Fatalf("Available = %v, want true — nothing in this cluster holds 30501", result.Available)
	}
	if len(result.Allocations) != 0 {
		t.Errorf("Allocations = %+v, want empty for a free port", result.Allocations)
	}
}

// TestListNodePortAllocations_ListShapeIsBoundedAndTruncationIsExplicit is
// the boundary/pagination case, mirroring list_resources' own truncation
// contract: a caller that omits port gets the survey shape, capped, with the
// cut made explicit rather than silent.
func TestListNodePortAllocations_ListShapeIsBoundedAndTruncationIsExplicit(t *testing.T) {
	const total = 5
	objs := make([]runtime.Object, 0, total)
	for i := 0; i < total; i++ {
		objs = append(objs, testService("apps", fmt.Sprintf("svc-%d", i),
			corev1.ServicePort{Name: "http", Protocol: corev1.ProtocolTCP, Port: 80, NodePort: int32(30000 + i)}))
	}
	executor := newNodePortTestExecutor(objs...)

	data, truncated, err := executor.Execute(context.Background(), "list_nodeport_allocations",
		mustMarshal(listNodePortAllocationsArgs{Limit: 2}))
	if err != nil {
		t.Fatalf("Execute(list_nodeport_allocations): %v", err)
	}
	if !truncated {
		t.Error("Execute's truncated return = false, want true for 5 allocations capped at 2")
	}
	var result listNodePortAllocationsResult
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("decode result: %v", err)
	}
	if result.Port != nil || result.Available != nil {
		t.Errorf("Port/Available = %v/%v, want both absent for the list shape (no port named)", result.Port, result.Available)
	}
	if result.TotalMatched != total || result.Returned != 2 || !result.Truncated {
		t.Fatalf("totalMatched/returned/truncated = %d/%d/%v, want %d/2/true", result.TotalMatched, result.Returned, result.Truncated, total)
	}
	// Port-sorted, not API-server order — same reasoning list_resources' own
	// name-sort test states.
	if result.Allocations[0].Port != 30000 || result.Allocations[1].Port != 30001 {
		t.Fatalf("allocations are not port-sorted: %+v", result.Allocations)
	}
}

// TestListNodePortAllocations_ServicesWithNoNodePortAreIgnored guards the
// zero-value trap: ServicePort.NodePort is 0 for an ordinary ClusterIP
// Service's port, which must never be mistaken for "port 0 is allocated."
func TestListNodePortAllocations_ServicesWithNoNodePortAreIgnored(t *testing.T) {
	svc := testService("apps", "internal-only", corev1.ServicePort{Name: "http", Protocol: corev1.ProtocolTCP, Port: 80})
	executor := newNodePortTestExecutor(svc)

	data, _, err := executor.Execute(context.Background(), "list_nodeport_allocations", mustMarshal(listNodePortAllocationsArgs{}))
	if err != nil {
		t.Fatalf("Execute(list_nodeport_allocations): %v", err)
	}
	var result listNodePortAllocationsResult
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("decode result: %v", err)
	}
	if result.TotalMatched != 0 || len(result.Allocations) != 0 {
		t.Fatalf("allocations = %+v, want empty — a ClusterIP-only Service has no nodePort", result.Allocations)
	}
}

// TestListNodePortAllocations_RejectsAnOutOfRangePort pins basic argument
// sanity independent of any cluster-configured NodePort range this agent has
// no way to know.
func TestListNodePortAllocations_RejectsAnOutOfRangePort(t *testing.T) {
	executor := newNodePortTestExecutor()
	if _, _, err := executor.listNodePortAllocations(context.Background(), mustMarshal(listNodePortAllocationsArgs{Port: 70000})); err == nil {
		t.Error("list_nodeport_allocations with port 70000: want error, got nil")
	}
}

// TestListNodePortAllocations_IsClusterWideNotNamespaceScoped pins the one
// deliberate departure from this file's usual single-namespace-scoping
// discipline: a nodePort allocated in one namespace must be visible to a
// caller investigating an object in a completely different namespace,
// because the conflict itself is cluster-wide.
func TestListNodePortAllocations_IsClusterWideNotNamespaceScoped(t *testing.T) {
	svc := testService("other-namespace", "unrelated-svc", corev1.ServicePort{Name: "http", Protocol: corev1.ProtocolTCP, Port: 80, NodePort: 30777})
	executor := newNodePortTestExecutor(svc)

	data, _, err := executor.Execute(context.Background(), "list_nodeport_allocations",
		mustMarshal(listNodePortAllocationsArgs{Port: 30777}))
	if err != nil {
		t.Fatalf("Execute(list_nodeport_allocations): %v", err)
	}
	var result listNodePortAllocationsResult
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("decode result: %v", err)
	}
	if result.Available == nil || *result.Available {
		t.Fatalf("Available = %v, want false — the allocation in a different namespace must still be visible", result.Available)
	}
}

// --- reevaluate_rule (BACKLOG.md V3) ---
//
// Reuses rules_test.go's pdbBlocksAllDisruptionsRule/mustRule fixtures (same
// package) rather than inventing a second PDB rule — evaluateRule itself is
// already covered there; these tests are about reevaluateRule's OWN logic
// layered on top: looking a rule up by ID, filtering evaluateRule's output
// down to one named object, and telling "exists but clear" apart from "no
// longer exists" via the one direct Get on the non-firing path.
//
// A TYPED *policyv1.PodDisruptionBudget, not rules_test.go's unstructured
// pdbObj — the same reason redact_egress_test.go's canaryCluster uses a
// typed *corev1.Pod rather than an unstructured one (see that file's own
// comment): newTestExecutor's dynamic fake is built against the REAL
// client-go scheme (k8sscheme.Scheme), which knows PodDisruptionBudget as a
// typed type, and seeding it as unstructured serves a Get fine but fails
// List (the call evaluateRule — and therefore reevaluate_rule — actually
// makes) with "can't assign or convert unstructured.Unstructured into
// v1.PodDisruptionBudget". rules_test.go's own newRulesFake avoids this by
// using a bare, empty scheme instead, which is not what production code
// (newToolExecutor) or this file's own newTestExecutor use.
func typedPDB(namespace, name string, disruptionsAllowed int32) *policyv1.PodDisruptionBudget {
	return &policyv1.PodDisruptionBudget{
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name, UID: types.UID("uid-" + name)},
		Status:     policyv1.PodDisruptionBudgetStatus{DisruptionsAllowed: disruptionsAllowed},
	}
}

func TestReevaluateRule_Fires(t *testing.T) {
	exec, _ := newTestExecutor(typedPDB("checkout", "checkout-pdb", 0))
	exec.SetRules([]Rule{mustRule(t, pdbBlocksAllDisruptionsRule)})

	raw, _, err := exec.Execute(context.Background(), "reevaluate_rule",
		mustMarshal(reevaluateRuleArgs{RuleID: "pdb-blocks-all-disruptions", Namespace: "checkout", Name: "checkout-pdb"}))
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	var result reevaluateRuleResult
	if err := json.Unmarshal(raw, &result); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !result.Found || !result.Fires {
		t.Fatalf("got %+v, want found=true fires=true", result)
	}
	if !strings.Contains(result.Message, "disruptionsAllowed=0") {
		t.Errorf("Message = %q, want the rule's own rendered text", result.Message)
	}
}

func TestReevaluateRule_ObjectExistsButConditionCleared(t *testing.T) {
	// disruptionsAllowed=2, not 0 — the rule's condition no longer matches,
	// but the object itself is very much still there. This is the
	// distinction Found exists to carry: a caller must not read this the
	// same way as the object having been deleted.
	exec, _ := newTestExecutor(typedPDB("checkout", "checkout-pdb", 2))
	exec.SetRules([]Rule{mustRule(t, pdbBlocksAllDisruptionsRule)})

	raw, _, err := exec.Execute(context.Background(), "reevaluate_rule",
		mustMarshal(reevaluateRuleArgs{RuleID: "pdb-blocks-all-disruptions", Namespace: "checkout", Name: "checkout-pdb"}))
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	var result reevaluateRuleResult
	if err := json.Unmarshal(raw, &result); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !result.Found || result.Fires {
		t.Fatalf("got %+v, want found=true fires=false", result)
	}
}

func TestReevaluateRule_ObjectNoLongerExists(t *testing.T) {
	// No PDB seeded at all — the rule's own GVK has zero objects, standing
	// in for "the object this incident named has since been deleted".
	exec, _ := newTestExecutor()
	exec.SetRules([]Rule{mustRule(t, pdbBlocksAllDisruptionsRule)})

	raw, _, err := exec.Execute(context.Background(), "reevaluate_rule",
		mustMarshal(reevaluateRuleArgs{RuleID: "pdb-blocks-all-disruptions", Namespace: "checkout", Name: "checkout-pdb"}))
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	var result reevaluateRuleResult
	if err := json.Unmarshal(raw, &result); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if result.Found || result.Fires {
		t.Fatalf("got %+v, want found=false fires=false — the object no longer exists", result)
	}
}

// TestReevaluateRule_UnknownRuleID covers exactly the case V3's task
// description names: a rule that has been removed or renamed from the
// agent's currently-loaded set since the incident opened. Must be an honest
// error, never a silent "doesn't fire".
func TestReevaluateRule_UnknownRuleID(t *testing.T) {
	exec, _ := newTestExecutor(pdbObj("checkout", "checkout-pdb", 0))
	exec.SetRules([]Rule{mustRule(t, pdbBlocksAllDisruptionsRule)})

	_, _, err := exec.Execute(context.Background(), "reevaluate_rule",
		mustMarshal(reevaluateRuleArgs{RuleID: "no-such-rule", Namespace: "checkout", Name: "checkout-pdb"}))
	if err == nil {
		t.Fatal("expected an error for an unknown ruleId, got none")
	}
}

// TestReevaluateRule_NoRulesLoaded is the same case as
// TestReevaluateRule_UnknownRuleID but for an executor that never had
// SetRules called at all (e.rules is nil) — the state a fresh ToolExecutor
// is in before client.go's Run wires the loaded rule set through.
func TestReevaluateRule_NoRulesLoaded(t *testing.T) {
	exec, _ := newTestExecutor(pdbObj("checkout", "checkout-pdb", 0))

	_, _, err := exec.Execute(context.Background(), "reevaluate_rule",
		mustMarshal(reevaluateRuleArgs{RuleID: "pdb-blocks-all-disruptions", Namespace: "checkout", Name: "checkout-pdb"}))
	if err == nil {
		t.Fatal("expected an error when no rules are loaded, got none")
	}
}

func TestReevaluateRule_RequiresRuleIDAndName(t *testing.T) {
	exec, _ := newTestExecutor(pdbObj("checkout", "checkout-pdb", 0))
	exec.SetRules([]Rule{mustRule(t, pdbBlocksAllDisruptionsRule)})

	for _, args := range []reevaluateRuleArgs{
		{Namespace: "checkout", Name: "checkout-pdb"},                 // no ruleId
		{RuleID: "pdb-blocks-all-disruptions", Namespace: "checkout"}, // no name
	} {
		if _, _, err := exec.Execute(context.Background(), "reevaluate_rule", mustMarshal(args)); err == nil {
			t.Errorf("args %+v: expected an error, got none", args)
		}
	}
}

// TestGetGitOpsOwnershipDetectsPlainHelm covers the branch added after a live
// check showed the tool reporting "none" for a Helm-managed workload. "none" is
// not a harmless absence of information: downstream it asserts that an in-place
// fix will stick, which on a chart-managed cluster is wrong — the next
// `helm upgrade` reverts the remediation and the incident reopens.
func TestGetGitOpsOwnershipDetectsPlainHelm(t *testing.T) {
	deployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name: "checkout", Namespace: "apps", UID: types.UID("uid-checkout"),
			Labels: map[string]string{"app.kubernetes.io/name": "checkout"},
			Annotations: map[string]string{
				"meta.helm.sh/release-name":      "shop-apps",
				"meta.helm.sh/release-namespace": "flux-system",
			},
		},
	}
	executor, _ := newTestExecutor(deployment)
	data, _, err := executor.Execute(context.Background(), "get_gitops_ownership", mustMarshal(getGitOpsOwnershipArgs{
		GVK: "apps/v1/Deployment", Namespace: "apps", Name: "checkout",
	}))
	if err != nil {
		t.Fatalf("Execute(get_gitops_ownership): %v", err)
	}
	var result gitOpsOwnershipResult
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("decode result: %v", err)
	}
	if result.ManagedBy != "helm" {
		t.Fatalf("ManagedBy = %q, want %q", result.ManagedBy, "helm")
	}
	if result.AppRef == nil || result.AppRef.Name != "shop-apps" {
		t.Fatalf("AppRef = %+v, want the release name shop-apps", result.AppRef)
	}
	// The release namespace is where `helm` itself looks, and is not
	// necessarily the object's own namespace.
	if result.AppRef.Namespace != "flux-system" {
		t.Errorf("AppRef.Namespace = %q, want flux-system", result.AppRef.Namespace)
	}
	// BACKLOG.md F19 mechanism 1's label-selector form needs these on the
	// wire even for the "helm" verdict — an operator may prefer a label
	// selector over naming the release.
	if result.Labels["app.kubernetes.io/name"] != "checkout" {
		t.Fatalf("Labels = %+v, want the queried object's own labels for the helm case too", result.Labels)
	}
}

// TestGetGitOpsOwnershipPrefersControllerOverHelm pins the ordering, which is
// the part that is easy to get wrong: a chart applied BY Flux or Argo carries
// Helm's release annotations too, and reporting "helm" for it would send an
// operator to `helm upgrade` when the source of truth is Git — where the
// controller would revert them anyway.
func TestGetGitOpsOwnershipPrefersControllerOverHelm(t *testing.T) {
	deployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name: "checkout", Namespace: "apps", UID: types.UID("uid-checkout-2"),
			Annotations: map[string]string{
				"meta.helm.sh/release-name":        "shop-apps",
				"helm.toolkit.fluxcd.io/name":      "shop-apps",
				"helm.toolkit.fluxcd.io/namespace": "flux-system",
			},
		},
	}
	executor, _ := newTestExecutor(deployment)
	data, _, err := executor.Execute(context.Background(), "get_gitops_ownership", mustMarshal(getGitOpsOwnershipArgs{
		GVK: "apps/v1/Deployment", Namespace: "apps", Name: "checkout",
	}))
	if err != nil {
		t.Fatalf("Execute(get_gitops_ownership): %v", err)
	}
	var result gitOpsOwnershipResult
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("decode result: %v", err)
	}
	if result.ManagedBy != "flux" {
		t.Errorf("ManagedBy = %q, want flux — a controller-managed chart must not report as plain helm", result.ManagedBy)
	}
}

// TestGetGitOpsOwnershipIgnoresManagedByLabel guards the deliberate exclusion:
// app.kubernetes.io/managed-by: Helm is a convention any chart rendered through
// `helm template | kubectl apply` also carries, where no release exists and
// nothing will ever revert anything. Treating it as ownership would produce
// confident warnings about a reconcile that cannot happen.
func TestGetGitOpsOwnershipIgnoresManagedByLabel(t *testing.T) {
	deployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name: "checkout", Namespace: "apps", UID: types.UID("uid-checkout-3"),
			Labels: map[string]string{"app.kubernetes.io/managed-by": "Helm"},
		},
	}
	executor, _ := newTestExecutor(deployment)
	data, _, err := executor.Execute(context.Background(), "get_gitops_ownership", mustMarshal(getGitOpsOwnershipArgs{
		GVK: "apps/v1/Deployment", Namespace: "apps", Name: "checkout",
	}))
	if err != nil {
		t.Fatalf("Execute(get_gitops_ownership): %v", err)
	}
	var result gitOpsOwnershipResult
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("decode result: %v", err)
	}
	if result.ManagedBy != "none" {
		t.Errorf("ManagedBy = %q, want none — the managed-by label alone is not release ownership", result.ManagedBy)
	}
}

// --- REMEDIATION_ROADMAP.md milestone 2.0: repo-target resolution ---

// newGitOpsTestExecutor builds an executor whose dynamic client can serve
// GitOps CRDs. NewSimpleDynamicClient alone cannot: those kinds are not in
// k8sscheme.Scheme, so the tracker needs its list kinds declared explicitly.
func newGitOpsTestExecutor(objs ...runtime.Object) *ToolExecutor {
	e, _ := newTestExecutor(objs...)
	return e
}

func unstructuredOf(apiVersion, kind, namespace, name string, labels map[string]string, spec, status map[string]any) *unstructured.Unstructured {
	o := map[string]any{
		"apiVersion": apiVersion,
		"kind":       kind,
		"metadata":   map[string]any{"name": name, "namespace": namespace},
	}
	if labels != nil {
		l := map[string]any{}
		for k, v := range labels {
			l[k] = v
		}
		o["metadata"].(map[string]any)["labels"] = l
	}
	if spec != nil {
		o["spec"] = spec
	}
	if status != nil {
		o["status"] = status
	}
	return &unstructured.Unstructured{Object: o}
}

func ownershipOf(t *testing.T, e *ToolExecutor, gvk, namespace, name string) gitOpsOwnershipResult {
	t.Helper()
	data, _, err := e.Execute(context.Background(), "get_gitops_ownership", mustMarshal(getGitOpsOwnershipArgs{
		GVK: gvk, Namespace: namespace, Name: name,
	}))
	if err != nil {
		t.Fatalf("get_gitops_ownership: %v", err)
	}
	var res gitOpsOwnershipResult
	if err := json.Unmarshal(data, &res); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return res
}

// TestRepoTarget_ArgoPinnedRevision is the milestone's core case: status.sync
// .revision is the commit Argo actually synced, which is what lld/09 §4/§5
// mean by a pinned revision and why they say never HEAD.
func TestRepoTarget_ArgoPinnedRevision(t *testing.T) {
	dep := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{
		Name: "web", Namespace: "apps", UID: types.UID("u1"),
		Labels: map[string]string{"app.kubernetes.io/instance": "web"},
	}}
	// Seeded in "apps", the workload's own namespace: the instance-label
	// detection branch carries no namespace, so resolution falls back to the
	// object's — this exercises that fallback rather than the argocd/ case.
	app := unstructuredOf("argoproj.io/v1alpha1", "Application", "apps", "web", nil,
		map[string]any{"source": map[string]any{
			"repoURL": "https://github.com/example/infra.git", "path": "apps/web", "targetRevision": "main",
		}},
		map[string]any{"sync": map[string]any{"revision": "abc123def456"}})

	res := ownershipOf(t, newGitOpsTestExecutor(dep, app), "apps/v1/Deployment", "apps", "web")
	if res.ManagedBy != "argocd" {
		t.Fatalf("ManagedBy = %q, want argocd", res.ManagedBy)
	}
	if res.Repo == nil {
		t.Fatal("Repo = nil — milestone 2.0's whole point is resolving it")
	}
	if res.Repo.RepoURL != "https://github.com/example/infra.git" {
		t.Errorf("RepoURL = %q", res.Repo.RepoURL)
	}
	if res.Repo.Path != "apps/web" {
		t.Errorf("Path = %q, want apps/web", res.Repo.Path)
	}
	if res.Repo.Revision != "abc123def456" || !res.Repo.RevisionPinned {
		t.Errorf("Revision = %q pinned=%v, want the synced commit marked pinned", res.Repo.Revision, res.Repo.RevisionPinned)
	}
	if !strings.Contains(res.Repo.ResolvedFrom, "status.sync.revision") {
		t.Errorf("ResolvedFrom = %q, want it to name the field so a human can check it", res.Repo.ResolvedFrom)
	}
}

// TestRepoTarget_ArgoUnsyncedIsNotPinned guards the honesty property: with no
// synced revision, the branch name is all there is, and it must NOT be
// presented as a pinned commit. lld/09 forbids treating a branch as a revision.
func TestRepoTarget_ArgoUnsyncedIsNotPinned(t *testing.T) {
	app := unstructuredOf("argoproj.io/v1alpha1", "Application", "apps", "web", nil,
		map[string]any{"source": map[string]any{"repoURL": "https://git/x.git", "targetRevision": "main"}}, nil)
	dep := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{
		Name: "web", Namespace: "apps", Labels: map[string]string{"app.kubernetes.io/instance": "web"}}}

	res := ownershipOf(t, newGitOpsTestExecutor(dep, app), "apps/v1/Deployment", "apps", "web")
	if res.Repo == nil {
		t.Fatal("Repo = nil")
	}
	if res.Repo.RevisionPinned {
		t.Error("RevisionPinned = true for an unsynced Application — a branch name is not a revision")
	}
	if res.Repo.Revision != "main" {
		t.Errorf("Revision = %q, want the branch reported as-is", res.Repo.Revision)
	}
}

// TestRepoTarget_FleetTwoHops covers BACKLOG.md F10 and Fleet's indirection:
// the object names a Bundle, the Bundle names the GitRepo, and only the
// GitRepo carries the URL and (in status.commit) the resolved SHA.
func TestRepoTarget_FleetTwoHops(t *testing.T) {
	bundle := unstructuredOf("fleet.cattle.io/v1alpha1", "Bundle", "fleet-default", "web-bundle",
		map[string]string{"fleet.cattle.io/repo-name": "infra"}, nil, nil)
	gitRepo := unstructuredOf("fleet.cattle.io/v1alpha1", "GitRepo", "fleet-default", "infra", nil,
		map[string]any{
			"repo":   "https://github.com/example/fleet-infra.git",
			"branch": "main",
			"paths":  []any{"apps/web", "apps/shared"},
		},
		map[string]any{"commit": "fleetsha999"})
	dep := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{
		Name: "web", Namespace: "apps",
		Labels: map[string]string{
			"fleet.cattle.io/bundle-name":      "web-bundle",
			"fleet.cattle.io/bundle-namespace": "fleet-default",
		},
	}}

	res := ownershipOf(t, newGitOpsTestExecutor(dep, bundle, gitRepo), "apps/v1/Deployment", "apps", "web")
	if res.ManagedBy != "fleet" {
		t.Fatalf("ManagedBy = %q, want fleet — F10: Fleet was previously reported as helm or none", res.ManagedBy)
	}
	if res.Repo == nil {
		t.Fatal("Repo = nil after a two-hop Fleet resolution")
	}
	if res.Repo.RepoURL != "https://github.com/example/fleet-infra.git" {
		t.Errorf("RepoURL = %q", res.Repo.RepoURL)
	}
	if res.Repo.Revision != "fleetsha999" || !res.Repo.RevisionPinned {
		t.Errorf("Revision = %q pinned=%v, want status.commit marked pinned", res.Repo.Revision, res.Repo.RevisionPinned)
	}
	// Several paths must both be reported — a caller narrowing to one file
	// needs to know the source was ambiguous rather than be handed one guess.
	if res.Repo.Path != "apps/web,apps/shared" {
		t.Errorf("Path = %q, want both Fleet paths joined", res.Repo.Path)
	}
}

// TestRepoTarget_FleetBeatsHelmAnnotations pins the precedence F10 turns on:
// Fleet deploys charts, so its objects carry Helm's release annotations too.
// Reporting "helm" would send an operator to `helm upgrade` when the real
// source of truth is the Git repo Fleet reconciles.
func TestRepoTarget_FleetBeatsHelmAnnotations(t *testing.T) {
	dep := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{
		Name: "web", Namespace: "apps",
		Labels:      map[string]string{"fleet.cattle.io/bundle-name": "web-bundle"},
		Annotations: map[string]string{"meta.helm.sh/release-name": "web"},
	}}
	res := ownershipOf(t, newGitOpsTestExecutor(dep), "apps/v1/Deployment", "apps", "web")
	if res.ManagedBy != "fleet" {
		t.Errorf("ManagedBy = %q, want fleet to win over the Helm annotations", res.ManagedBy)
	}
}

// TestRepoTarget_FluxKustomizationViaGitRepository walks Flux's sourceRef
// indirection. Only Kustomization is handled — a HelmRelease's chart source
// may be an OCI/HTTP registry rather than Git, so it has no single Git answer.
func TestRepoTarget_FluxKustomizationViaGitRepository(t *testing.T) {
	ks := unstructuredOf("kustomize.toolkit.fluxcd.io/v1", "Kustomization", "flux-system", "apps", nil,
		map[string]any{
			"path":      "./clusters/prod",
			"sourceRef": map[string]any{"kind": "GitRepository", "name": "infra"},
		},
		map[string]any{"lastAppliedRevision": "main@sha1:deadbeef"})
	gr := unstructuredOf("source.toolkit.fluxcd.io/v1", "GitRepository", "flux-system", "infra", nil,
		map[string]any{"url": "https://github.com/example/flux-infra.git", "ref": map[string]any{"branch": "main"}}, nil)
	dep := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{
		Name: "web", Namespace: "flux-system",
		Annotations: map[string]string{
			"kustomize.toolkit.fluxcd.io/name":      "apps",
			"kustomize.toolkit.fluxcd.io/namespace": "flux-system",
		},
	}}

	res := ownershipOf(t, newGitOpsTestExecutor(dep, ks, gr), "apps/v1/Deployment", "flux-system", "web")
	if res.ManagedBy != "flux" {
		t.Fatalf("ManagedBy = %q, want flux", res.ManagedBy)
	}
	if res.Repo == nil {
		t.Fatal("Repo = nil after a Flux sourceRef resolution")
	}
	if res.Repo.RepoURL != "https://github.com/example/flux-infra.git" {
		t.Errorf("RepoURL = %q", res.Repo.RepoURL)
	}
	if res.Repo.Path != "./clusters/prod" {
		t.Errorf("Path = %q — the path is on the Kustomization, not the GitRepository", res.Repo.Path)
	}
	// Flux reports "branch@sha1:<commit>"; the whole string is kept rather
	// than split, and the ":" is what marks it as carrying a real commit.
	if res.Repo.Revision != "main@sha1:deadbeef" || !res.Repo.RevisionPinned {
		t.Errorf("Revision = %q pinned=%v", res.Repo.Revision, res.Repo.RevisionPinned)
	}
}

// TestRepoTarget_HelmNeverResolves is the honest-negative case, and it is the
// reason repository_bindings has to exist: a plain Helm release records
// nothing about where its chart came from, so there is no object to read and
// no repo to report. Absent, not guessed.
func TestRepoTarget_HelmNeverResolves(t *testing.T) {
	dep := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{
		Name: "web", Namespace: "apps",
		Annotations: map[string]string{"meta.helm.sh/release-name": "web"},
	}}
	res := ownershipOf(t, newGitOpsTestExecutor(dep), "apps/v1/Deployment", "apps", "web")
	if res.ManagedBy != "helm" {
		t.Fatalf("ManagedBy = %q, want helm", res.ManagedBy)
	}
	if res.Repo != nil {
		t.Errorf("Repo = %+v, want nil — plain Helm leaves no in-cluster record of its chart's origin", res.Repo)
	}
}

// TestRepoTarget_MissingControllerObjectDegradesGracefully: ownership is still
// the answer the gitOpsManaged guardrail consumes, so a failed repo lookup
// must not fail the whole call.
func TestRepoTarget_MissingControllerObjectDegradesGracefully(t *testing.T) {
	// A self-referencing tracking-id, so DETECTION succeeds, but no Application
	// object exists so the repo lookup fails. Ownership must survive that —
	// it is what the gitOpsManaged guardrail consumes.
	dep := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{
		Name: "web", Namespace: "apps",
		Annotations: map[string]string{
			"argocd.argoproj.io/tracking-id": "gone:apps/Deployment:apps/web",
		}}}
	res := ownershipOf(t, newGitOpsTestExecutor(dep), "apps/v1/Deployment", "apps", "web")
	if res.ManagedBy != "argocd" {
		t.Errorf("ManagedBy = %q — detection must survive a failed repo lookup", res.ManagedBy)
	}
	if res.Repo != nil {
		t.Errorf("Repo = %+v, want nil when the Application cannot be read", res.Repo)
	}
}

// TestOwnership_PodInheritsFromAncestorDeployment is the regression test for a
// bug found by testing against a REAL Argo CD install rather than by
// inspection (WORKLOG §121). Everything about this scenario is what a real
// cluster produces:
//
//   - the incident's object is a Pod, because that is what detectors fire on;
//   - the Pod carries no GitOps metadata at all — Argo/Flux/Fleet mark the
//     top-level object they manage, and none of it propagates into the pod
//     template;
//   - Argo CD does not use ownerReferences, so the owner-chain scan for an
//     Application NODE cannot match either;
//   - the only signal is an annotation on the Deployment, two hops up.
//
// Before the ancestor walk, this answered "none" — an active assertion that an
// in-place fix will stick, which is what the gitOpsManaged guardrail consumes.
func TestOwnership_PodInheritsFromAncestorDeployment(t *testing.T) {
	deploy := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{
		Name: "guestbook-ui", Namespace: "apps", UID: types.UID("d1"),
		// Exactly the annotation a real Argo CD install writes, in Argo's own
		// "<app>:<group>/<Kind>:<ns>/<name>" tracking-id format.
		Annotations: map[string]string{
			"argocd.argoproj.io/tracking-id": "argus-e2e-guestbook:apps/Deployment:apps/guestbook-ui",
		},
	}}
	rs := &appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{
		Name: "guestbook-ui-abc", Namespace: "apps", UID: types.UID("r1"),
		OwnerReferences: []metav1.OwnerReference{{
			APIVersion: "apps/v1", Kind: "Deployment", Name: "guestbook-ui", UID: types.UID("d1"), Controller: boolPtr(true),
		}},
	}}
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
		Name: "guestbook-ui-abc-xyz", Namespace: "apps", UID: types.UID("p1"),
		// No GitOps metadata whatsoever — just the ordinary pod-template labels.
		Labels: map[string]string{"app": "guestbook-ui", "pod-template-hash": "abc"},
		OwnerReferences: []metav1.OwnerReference{{
			APIVersion: "apps/v1", Kind: "ReplicaSet", Name: "guestbook-ui-abc", UID: types.UID("r1"), Controller: boolPtr(true),
		}},
	}}

	res := ownershipOf(t, newGitOpsTestExecutor(pod, rs, deploy), "v1/Pod", "apps", "guestbook-ui-abc-xyz")
	if res.ManagedBy != "argocd" {
		t.Fatalf("ManagedBy = %q, want argocd — the Pod's grandparent Deployment is Argo-managed, and reporting anything else tells an operator an in-place fix will stick when the next sync reverts it", res.ManagedBy)
	}
	if res.AppRef == nil || res.AppRef.Name != "argus-e2e-guestbook" {
		t.Errorf("AppRef = %+v, want the Application name from the ancestor's tracking-id", res.AppRef)
	}
}

// TestOwnership_AncestorWalkStillPrefersHelmLast guards the precedence rule
// through the new ancestor path too: a Deployment marked by BOTH Fleet and
// Helm must report fleet, since Fleet deploys charts and answering "helm"
// would send an operator to `helm upgrade` instead of the Git source.
func TestOwnership_AncestorWalkStillPrefersHelmLast(t *testing.T) {
	deploy := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{
		Name: "web", Namespace: "apps", UID: types.UID("d2"),
		Labels:      map[string]string{"fleet.cattle.io/bundle-name": "web-bundle"},
		Annotations: map[string]string{"meta.helm.sh/release-name": "web"},
	}}
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
		Name: "web-xyz", Namespace: "apps", UID: types.UID("p2"),
		OwnerReferences: []metav1.OwnerReference{{
			APIVersion: "apps/v1", Kind: "Deployment", Name: "web", UID: types.UID("d2"), Controller: boolPtr(true),
		}},
	}}
	res := ownershipOf(t, newGitOpsTestExecutor(pod, deploy), "v1/Pod", "apps", "web-xyz")
	if res.ManagedBy != "fleet" {
		t.Errorf("ManagedBy = %q, want fleet to win over the Helm annotations on the same ancestor", res.ManagedBy)
	}
}

// --- DESIGN.md §11.2's "critical subtlety": tracking-id self-reference ---

// TestOwnership_RejectsNonSelfReferencingTrackingID is the resource-adoption
// defence. Argo itself treats a tracking-id that does not name the object
// carrying it as NOT managed. Copying an annotation onto an unrelated object —
// by an attacker, or by someone copy-pasting a manifest — must not attribute
// that object to another team's Application, because once PR generation exists
// the consequence is a pull request against the wrong repository.
func TestOwnership_RejectsNonSelfReferencingTrackingID(t *testing.T) {
	// The annotation names a DIFFERENT object than the one it sits on.
	dep := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{
		Name: "victim", Namespace: "apps",
		Annotations: map[string]string{
			"argocd.argoproj.io/tracking-id": "someone-elses-app:apps/Deployment:other-ns/other-name",
		}}}
	res := ownershipOf(t, newGitOpsTestExecutor(dep), "apps/v1/Deployment", "apps", "victim")
	if res.ManagedBy == "argocd" {
		t.Fatalf("ManagedBy = argocd from a tracking-id naming other-ns/other-name — Argo treats these as unmanaged; attributing it risks a PR against the wrong repo")
	}
	if res.ManagedBy != "none" {
		t.Errorf("ManagedBy = %q, want none", res.ManagedBy)
	}
}

func TestOwnership_AcceptsSelfReferencingTrackingID(t *testing.T) {
	dep := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{
		Name: "web", Namespace: "apps",
		Annotations: map[string]string{
			"argocd.argoproj.io/tracking-id": "my-app:apps/Deployment:apps/web",
		}}}
	res := ownershipOf(t, newGitOpsTestExecutor(dep), "apps/v1/Deployment", "apps", "web")
	if res.ManagedBy != "argocd" || res.AppRef == nil || res.AppRef.Name != "my-app" {
		t.Errorf("ManagedBy=%q AppRef=%+v, want argocd/my-app for a correctly self-referencing id", res.ManagedBy, res.AppRef)
	}
}

// The ancestor walk must check self-reference against the ANCESTOR, not the
// originally-queried object — a Deployment's tracking-id self-references the
// Deployment, and checking it against the Pod would reject every real case.
func TestOwnership_AncestorTrackingIDSelfReferencesTheAncestor(t *testing.T) {
	deploy := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{
		Name: "web", Namespace: "apps", UID: types.UID("d9"),
		Annotations: map[string]string{
			"argocd.argoproj.io/tracking-id": "my-app:apps/Deployment:apps/web",
		}}}
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
		Name: "web-xyz", Namespace: "apps",
		OwnerReferences: []metav1.OwnerReference{{
			APIVersion: "apps/v1", Kind: "Deployment", Name: "web", UID: types.UID("d9"), Controller: boolPtr(true),
		}}}}
	res := ownershipOf(t, newGitOpsTestExecutor(pod, deploy), "v1/Pod", "apps", "web-xyz")
	if res.ManagedBy != "argocd" {
		t.Errorf("ManagedBy = %q, want argocd — the ancestor's id self-references the ancestor, which is correct", res.ManagedBy)
	}
}

// --- the Helm label collision DESIGN.md §11.2 warns about ---

// TestOwnership_UncorroboratedInstanceLabelFallsThroughToHelm is the reason the
// label is a weak signal. `app.kubernetes.io/instance` is Argo's label-tracking
// key AND the conventional Helm release label. With no Argo Application of that
// name, this object is Helm's — and answering "argocd" would send an operator
// (or a PR) to a repository that has nothing to do with it.
func TestOwnership_UncorroboratedInstanceLabelFallsThroughToHelm(t *testing.T) {
	dep := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{
		Name: "web", Namespace: "apps",
		Labels:      map[string]string{"app.kubernetes.io/instance": "my-release"},
		Annotations: map[string]string{"meta.helm.sh/release-name": "my-release"},
	}}
	res := ownershipOf(t, newGitOpsTestExecutor(dep), "apps/v1/Deployment", "apps", "web")
	if res.ManagedBy != "helm" {
		t.Errorf("ManagedBy = %q, want helm — no Argo Application named my-release exists, so the shared label is Helm's", res.ManagedBy)
	}
}

func TestTrackingIDSelfReferences(t *testing.T) {
	self := objectIdentity{Kind: "Deployment", Group: "apps", Namespace: "apps", Name: "web"}
	if !trackingIDSelfReferences("my-app:apps/Deployment:apps/web", self) {
		t.Error("an exactly-matching id should self-reference")
	}
	for _, bad := range []string{
		"my-app:apps/Deployment:other/web",  // wrong namespace
		"my-app:apps/Deployment:apps/other", // wrong name
		"my-app:apps/StatefulSet:apps/web",  // wrong kind
		"my-app:batch/Deployment:apps/web",  // wrong group
		"my-app",                            // unparseable — must fail closed
		"my-app:apps/Deployment",            // truncated — must fail closed
		"",
	} {
		if trackingIDSelfReferences(bad, self) {
			t.Errorf("trackingIDSelfReferences(%q) = true, want false", bad)
		}
	}
	// A core-group object writes an empty group prefix.
	core := objectIdentity{Kind: "Service", Group: "", Namespace: "apps", Name: "web"}
	if !trackingIDSelfReferences("my-app:/Service:apps/web", core) {
		t.Error("a core-group id should self-reference")
	}
	// BACKLOG.md F16 item 3: a "<namespace>/<app>"-prefixed tracking-id
	// (Argo's apps-in-any-namespace format, DESIGN.md §11.2) must
	// self-reference exactly like an unprefixed one — the app segment
	// (parts[0]) is never consulted by this check, only group/kind/ns/name
	// (parts[1]/parts[2]) are, so a "/" inside parts[0] changes nothing.
	// Verified directly rather than assumed: this was found already correct
	// by tracing strings.Split's behavior, not by discovering a bug to fix.
	if !trackingIDSelfReferences("team-a/my-app:apps/Deployment:apps/web", self) {
		t.Error("a namespace-prefixed app segment must not change self-reference — the app segment is never consulted by this check")
	}
}

// TestParseArgoTrackingID_NamespacePrefixedApp is the other half of F16 item
// 3: the AppRef itself must carry the Application's namespace when the
// tracking-id's app segment is "<namespace>/<app>" (apps-in-any-namespace),
// not just the self-reference check.
func TestParseArgoTrackingID_NamespacePrefixedApp(t *testing.T) {
	ref := parseArgoTrackingID("team-a/my-app:apps/Deployment:apps/web")
	if ref == nil {
		t.Fatal("parseArgoTrackingID returned nil for a namespace-prefixed app segment")
	}
	if ref.Namespace != "team-a" || ref.Name != "my-app" {
		t.Errorf("got Namespace=%q Name=%q, want Namespace=%q Name=%q", ref.Namespace, ref.Name, "team-a", "my-app")
	}

	// Unprefixed stays unprefixed (own-namespace Application, the common case).
	ref = parseArgoTrackingID("my-app:apps/Deployment:apps/web")
	if ref == nil || ref.Namespace != "" || ref.Name != "my-app" {
		t.Errorf("unprefixed app segment: got %+v, want Namespace=\"\" Name=%q", ref, "my-app")
	}
}

// TestFindArgoApplicationByName_InstallationIDDisambiguates is BACKLOG.md F16
// item 2's acceptance test: two Argo Applications sharing a name across two
// namespaces (two separate Argo CD installations, DESIGN.md §11.2) must
// resolve to the correct one when the managed object's installation-id
// narrows it to exactly one match, and must keep refusing (nil) when it
// doesn't narrow — ambiguity is never silently guessed away.
func TestFindArgoApplicationByName_InstallationIDDisambiguates(t *testing.T) {
	appA := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "argoproj.io/v1alpha1", "kind": "Application",
		"metadata": map[string]any{
			"name": "web", "namespace": "argocd-a",
			"annotations": map[string]any{"argocd.argoproj.io/installation-id": "install-a"},
		},
		"spec": map[string]any{"source": map[string]any{"repoURL": "https://example.com/team-a/repo.git"}},
	}}
	appB := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "argoproj.io/v1alpha1", "kind": "Application",
		"metadata": map[string]any{
			"name": "web", "namespace": "argocd-b",
			"annotations": map[string]any{"argocd.argoproj.io/installation-id": "install-b"},
		},
		"spec": map[string]any{"source": map[string]any{"repoURL": "https://example.com/team-b/repo.git"}},
	}}
	e := newGitOpsTestExecutor(appA, appB)
	gvk := schema.GroupVersionKind{Group: "argoproj.io", Version: "v1alpha1", Kind: "Application"}

	got := e.findArgoApplicationByName(context.Background(), gvk, "web", "install-b")
	if got == nil || got.GetNamespace() != "argocd-b" {
		t.Errorf("with installationID=%q, got %v, want the argocd-b Application", "install-b", got)
	}

	if got := e.findArgoApplicationByName(context.Background(), gvk, "web", ""); got != nil {
		t.Errorf("with no installationID, ambiguity must still refuse — got %v, want nil", got)
	}
	if got := e.findArgoApplicationByName(context.Background(), gvk, "web", "install-c"); got != nil {
		t.Errorf("an installationID matching neither candidate must still refuse — got %v, want nil", got)
	}
}
