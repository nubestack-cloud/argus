package gitopsinsight

import (
	"strings"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func argoApp(status map[string]any) *unstructured.Unstructured {
	app := &unstructured.Unstructured{Object: map[string]any{"status": status}}
	app.SetAPIVersion("argoproj.io/v1alpha1")
	app.SetKind("Application")
	app.SetNamespace("argocd")
	app.SetName("billing")
	_ = unstructured.SetNestedField(app.Object, "https://kubernetes.default.svc", "spec", "destination", "server")
	return app
}

// The auto-sync words are read by the model and shown to people, so every
// state is pinned; renaming one should be a decision.
func TestDescribeArgoAutoSync(t *testing.T) {
	policy := func(kind string, automated any) *unstructured.Unstructured {
		u := &unstructured.Unstructured{Object: map[string]any{"kind": kind, "spec": map[string]any{}}}
		if automated != nil {
			u.Object["spec"] = map[string]any{"syncPolicy": map[string]any{"automated": automated}}
		}
		return u
	}
	on := func(kv ...any) map[string]any {
		m := map[string]any{}
		for i := 0; i < len(kv); i += 2 {
			m[kv[i].(string)] = kv[i+1]
		}
		return m
	}
	cases := []struct {
		obj  *unstructured.Unstructured
		want string
	}{
		{policy("Application", nil), "Manual"},
		{&unstructured.Unstructured{Object: map[string]any{"kind": "Application", "spec": map[string]any{"syncPolicy": map[string]any{"syncOptions": []any{"CreateNamespace=true"}}}}}, "Manual"},
		{policy("Application", on()), "Auto"},
		{policy("Application", on("prune", true)), "Auto · prune"},
		{policy("Application", on("selfHeal", true)), "Auto · self-heal"},
		{policy("Application", on("selfHeal", true, "prune", true)), "Auto · prune · self-heal"},
		{policy("Application", on("prune", false, "selfHeal", false)), "Auto"},
		// The CRD says bool; a string from a mangling webhook is not "on".
		{policy("Application", on("prune", "true", "selfHeal", 1)), "Auto"},
		// An ApplicationSet's syncPolicy governs the Applications it makes,
		// not a sync mode of its own, even when its template carries one.
		{policy("ApplicationSet", nil), ""},
		{policy("ApplicationSet", on("prune", true)), ""},
	}
	for _, c := range cases {
		if got := describeArgoAutoSync(c.obj); got != c.want {
			t.Errorf("%s %v: %q, want %q", c.obj.GetKind(), c.obj.Object["spec"], got, c.want)
		}
	}
}

// A pending deletion is why a controller's work does not stick; the summary
// carries when it started and what holds it.
func TestSummarize_TerminatingFields(t *testing.T) {
	app := argoApp(map[string]any{})
	when := metav1.NewTime(time.Date(2026, 9, 2, 7, 45, 0, 0, time.UTC))
	app.SetDeletionTimestamp(&when)
	app.SetFinalizers([]string{"resources-finalizer.argocd.argoproj.io/background"})

	s := Summarize(app)
	if !s.Terminating || s.TerminationStartedAt != "2026-09-02T07:45:00Z" || strings.Join(s.Finalizers, ",") != "resources-finalizer.argocd.argoproj.io/background" {
		t.Fatalf("terminating=%v since=%q finalizers=%v", s.Terminating, s.TerminationStartedAt, s.Finalizers)
	}
}

func TestSummarize_Argo(t *testing.T) {
	root := argoApp(map[string]any{
		"sync":         map[string]any{"status": "OutOfSync", "revision": "abc123"},
		"health":       map[string]any{"status": "Degraded"},
		"reconciledAt": "2026-10-01T10:00:00Z",
		"operationState": map[string]any{
			"phase":      "Failed",
			"message":    `rpc error: code = Unknown desc = namespaces "payments" not found (retried 5 times)`,
			"syncResult": map[string]any{"revision": "def456"},
		},
		"conditions": []any{
			map[string]any{"type": "ComparisonError", "status": "True", "message": "rpc error: code = Unknown desc = repo not found"},
			map[string]any{"type": "", "message": ""},
		},
		"resources": []any{
			map[string]any{"group": "apps", "kind": "Deployment", "namespace": "payments", "name": "api", "status": "OutOfSync", "health": map[string]any{"status": "Missing"}},
			map[string]any{"kind": "Service", "namespace": "payments", "name": "api", "status": "Synced"},
			map[string]any{"kind": "", "name": "dropped"},
		},
	})
	root.Object["spec"].(map[string]any)["source"] = map[string]any{"repoURL": "https://git.example/r.git", "path": "apps/payments"}
	root.Object["spec"].(map[string]any)["syncPolicy"] = map[string]any{"automated": map[string]any{"prune": true, "selfHeal": true}}

	s := Summarize(root)
	if s.Tool != ToolArgoCD || s.Kind != "Application" || s.Namespace != "argocd" || s.Name != "billing" {
		t.Fatalf("identity = %+v", s)
	}
	if s.Sync != "OutOfSync" || s.Health != "Degraded" || s.OperationPhase != "Failed" {
		t.Fatalf("status = %s/%s/%s", s.Sync, s.Health, s.OperationPhase)
	}
	if strings.HasPrefix(s.OperationMessage, "rpc error") || !strings.HasPrefix(s.RawOperationMessage, "rpc error") {
		t.Fatalf("message = %q raw = %q", s.OperationMessage, s.RawOperationMessage)
	}
	if s.Source != "https://git.example/r.git · apps/payments" || s.TargetRevision != "abc123" || s.LastRevision != "def456" || s.LastReconcile != "2026-10-01T10:00:00Z" {
		t.Fatalf("source/revisions = %q %q %q %q", s.Source, s.TargetRevision, s.LastRevision, s.LastReconcile)
	}
	if s.AutoSync != "Auto · prune · self-heal" {
		t.Fatalf("AutoSync = %q", s.AutoSync)
	}
	if len(s.Conditions) != 1 || s.Conditions[0].Message != "repo not found" || s.Conditions[0].Action == "" {
		t.Fatalf("conditions = %+v", s.Conditions)
	}
	if s.ManagedResourcesTotal != 2 || len(s.ManagedResources) != 2 || s.Truncated {
		t.Fatalf("managed = %+v total=%d", s.ManagedResources, s.ManagedResourcesTotal)
	}
	if got := s.ManagedResources[0]; got.Group != "apps" || got.Health != "Missing" || got.Status != "OutOfSync" {
		t.Fatalf("managed[0] = %+v", got)
	}

	pf := FailureFor(root)
	if pf == nil || pf.Class != FailureClassNamespaceNotFound || pf.MissingNamespace != "payments" || !pf.Stuck {
		t.Fatalf("FailureFor = %+v", pf)
	}
}

func TestSummarize_ArgoSourcesFallback(t *testing.T) {
	root := argoApp(map[string]any{})
	root.Object["spec"].(map[string]any)["sources"] = []any{map[string]any{"repoURL": "https://charts.example", "chart": "redis"}}
	if s := Summarize(root); s.Source != "https://charts.example · redis" || s.AutoSync != "Manual" {
		t.Fatalf("Source = %q AutoSync = %q", s.Source, s.AutoSync)
	}
}

func TestFailureFor_OnlyFailedArgoOperations(t *testing.T) {
	running := argoApp(map[string]any{"operationState": map[string]any{"phase": "Running", "message": "x"}})
	if FailureFor(running) != nil {
		t.Fatal("Running operation should not yield a failure")
	}
	if FailureFor(flux("1/1", "Ready=False")) != nil {
		t.Fatal("Flux object should not yield an Argo failure")
	}
}

func TestSummarize_Flux(t *testing.T) {
	obj := flux("2/2",
		map[string]any{"type": "Ready", "status": "False", "reason": "BuildFailed", "message": "kustomize build failed", "lastTransitionTime": "2026-10-01T09:00:00Z"},
		map[string]any{"type": "Reconciling", "status": "False", "reason": "Done", "lastTransitionTime": "2026-10-01T09:05:00Z"},
	)
	obj.Object["spec"] = map[string]any{"sourceRef": map[string]any{"kind": "GitRepository", "name": "flux-system"}}
	status := obj.Object["status"].(map[string]any)
	status["lastAttemptedRevision"] = "main@sha1:aaa"
	status["lastAppliedRevision"] = "main@sha1:bbb"
	status["inventory"] = map[string]any{"entries": []any{
		map[string]any{"id": "payments_api_apps_Deployment", "v": "v1"},
		map[string]any{"id": "bad"},
	}}

	s := Summarize(obj)
	if s.Tool != ToolFlux || s.Sync != "OutOfSync" || s.Health != "Degraded" {
		t.Fatalf("status = %+v", s)
	}
	if s.Source != "GitRepository/flux-system" || s.TargetRevision != "main@sha1:aaa" || s.LastRevision != "main@sha1:bbb" || s.AutoSync != "Auto" {
		t.Fatalf("source/revisions = %+v", s)
	}
	// No lastHandledReconcileAt: the newest condition transition stands in.
	if s.LastReconcile != "2026-10-01T09:05:00Z" {
		t.Fatalf("LastReconcile = %q", s.LastReconcile)
	}
	if len(s.Conditions) != 2 || s.Conditions[0].Action == "" || s.Conditions[1].Action != "" {
		t.Fatalf("conditions = %+v (only the failing one gets guidance)", s.Conditions)
	}
	if len(s.ManagedResources) != 1 || s.ManagedResources[0] != (ManagedResource{Group: "apps", Kind: "Deployment", Namespace: "payments", Name: "api"}) {
		t.Fatalf("managed = %+v", s.ManagedResources)
	}
}

func TestSummarize_FluxHelmReleaseChartSource(t *testing.T) {
	obj := flux("-/- suspended", "Ready=True")
	obj.Object["apiVersion"] = "helm.toolkit.fluxcd.io/v2"
	obj.Object["kind"] = "HelmRelease"
	obj.Object["spec"].(map[string]any)["chart"] = map[string]any{"spec": map[string]any{"sourceRef": map[string]any{"kind": "HelmRepository", "name": "bitnami"}}}
	s := Summarize(obj)
	if s.Source != "HelmRepository/bitnami" || s.AutoSync != "Suspended" || s.Health != "Suspended" {
		t.Fatalf("summary = %+v", s)
	}
}

func TestSummarize_ManagedResourcesCapped(t *testing.T) {
	resources := make([]any, 0, MaxManagedResources+5)
	for i := 0; i < MaxManagedResources+5; i++ {
		resources = append(resources, map[string]any{"kind": "ConfigMap", "namespace": "ns", "name": "cm"})
	}
	s := Summarize(argoApp(map[string]any{"resources": resources}))
	if len(s.ManagedResources) != MaxManagedResources || !s.Truncated || s.ManagedResourcesTotal != MaxManagedResources+5 {
		t.Fatalf("len=%d truncated=%v total=%d", len(s.ManagedResources), s.Truncated, s.ManagedResourcesTotal)
	}
}

func TestSummarize_LongMessagesCapped(t *testing.T) {
	long := strings.Repeat("x", MaxMessageRunes+10)
	s := Summarize(argoApp(map[string]any{
		"operationState": map[string]any{"phase": "Failed", "message": long},
		"conditions":     []any{map[string]any{"type": "SyncError", "message": long}},
	}))
	if n := len([]rune(s.OperationMessage)); n != MaxMessageRunes+1 {
		t.Fatalf("operation message runes = %d", n)
	}
	if n := len([]rune(s.Conditions[0].Message)); n != MaxMessageRunes+1 {
		t.Fatalf("condition message runes = %d", n)
	}
}

func TestDetectTool(t *testing.T) {
	cases := map[string]string{
		"argoproj.io/v1alpha1":                ToolArgoCD,
		"kustomize.toolkit.fluxcd.io/v1":      ToolFlux,
		"helm.toolkit.fluxcd.io/v2":           ToolFlux,
		"source.toolkit.fluxcd.io/v1":         ToolFlux,
		"apps/v1":                             "",
		"fleet.cattle.io/v1alpha1":            "",
		"notargoproj.io.example.com/v1alpha1": "",
	}
	for apiVersion, want := range cases {
		obj := &unstructured.Unstructured{Object: map[string]any{"apiVersion": apiVersion, "kind": "X"}}
		if got := DetectTool(obj); got != want {
			t.Errorf("DetectTool(%q) = %q, want %q", apiVersion, got, want)
		}
	}
	if DetectTool(nil) != "" {
		t.Error("nil object should have no tool")
	}
	if s := Summarize(&unstructured.Unstructured{Object: map[string]any{"apiVersion": "apps/v1", "kind": "Deployment", "metadata": map[string]any{"name": "d"}}}); s.Tool != "" || s.Name != "d" || s.ManagedResourcesTotal != 0 {
		t.Fatalf("non-GitOps summary = %+v", s)
	}
}
