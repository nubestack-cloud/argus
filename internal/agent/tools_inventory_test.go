package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	k8sfake "k8s.io/client-go/kubernetes/fake"
	k8sscheme "k8s.io/client-go/kubernetes/scheme"
)

const inventoryCanary = "CANARY-helm-payload-must-never-be-read"

func helmAnn(release, ns string) map[string]string {
	return map[string]string{"meta.helm.sh/release-name": release, "meta.helm.sh/release-namespace": ns}
}

func helmReleaseSecret(ns, release string, rev int, status string, modified time.Time) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name: fmt.Sprintf("sh.helm.release.v1.%s.v%d", release, rev), Namespace: ns,
			Labels: map[string]string{"owner": "helm", "name": release, "status": status,
				"version": fmt.Sprint(rev), "modifiedAt": fmt.Sprint(modified.Unix())},
		},
		Type: "helm.sh/release.v1",
		Data: map[string][]byte{"release": []byte("H4sI-" + inventoryCanary)},
	}
}

func deployment(ns, name string, ann map[string]string, replicas, ready int32) *appsv1.Deployment {
	return &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns, Annotations: ann, Generation: 1},
		Spec: appsv1.DeploymentSpec{Replicas: &replicas,
			Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": name}},
			Template: corev1.PodTemplateSpec{ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"app": name}},
				Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "c", Image: "img"}}}}},
		Status: appsv1.DeploymentStatus{ObservedGeneration: 1, Replicas: replicas, ReadyReplicas: ready, AvailableReplicas: ready},
	}
}

func execInventory(t *testing.T, exec *ToolExecutor, tool string, args string) (map[string]any, string) {
	t.Helper()
	raw, _, err := exec.Execute(context.Background(), tool, json.RawMessage(args))
	if err != nil {
		t.Fatalf("%s: %v", tool, err)
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("%s: %v", tool, err)
	}
	return out, string(raw)
}

// Shaped like rke2's argus-system: a release with two Deployments (one not
// ready), a StatefulSet-less ConfigMap and a cluster-scoped ClusterRole, and
// three revisions of which the newest is deployed; plus a CRD-only release
// whose objects were adopted with no release Secret behind them.
func TestListHelmReleases_StatusFromLabelsOnly(t *testing.T) {
	exec, typed := newTestExecutor()
	now := time.Now()
	for _, s := range []*corev1.Secret{
		helmReleaseSecret("argus-system", "argus-hub", 1, "superseded", now.Add(-72*time.Hour)),
		helmReleaseSecret("argus-system", "argus-hub", 2, "superseded", now.Add(-48*time.Hour)),
		helmReleaseSecret("argus-system", "argus-hub", 3, "deployed", now.Add(-time.Hour)),
	} {
		if err := typed.Tracker().Add(s); err != nil {
			t.Fatal(err)
		}
	}
	ann := helmAnn("argus-hub", "argus-system")
	attachObjectCache(t, exec, typed, nil,
		deployment("argus-system", "argus-hub-api", ann, 2, 2),
		deployment("argus-system", "argus-hub", ann, 1, 0),
		&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "argus-hub-config", Namespace: "argus-system", Annotations: ann}},
		&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "argus-hub", Annotations: ann}},
		&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "crds", Namespace: "monitoring", Annotations: helmAnn("monitoring-crd", "monitoring")}},
		&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "unrelated", Namespace: "argus-system"}},
	)

	out, raw := execInventory(t, exec, "list_helm_releases", `{}`)
	if strings.Contains(raw, inventoryCanary) || strings.Contains(raw, "H4sI") {
		t.Fatalf("release Secret payload reached the output: %s", raw)
	}
	for _, a := range typed.Actions() {
		if a.GetResource().Resource == "secrets" && a.GetVerb() != "get" {
			t.Errorf("secrets %s issued; only named gets are allowed (D-R12)", a.GetVerb())
		}
	}
	if out["total"].(float64) != 2 {
		t.Fatalf("total = %v, want 2: %s", out["total"], raw)
	}
	rels := out["releases"].([]any)
	hub := rels[0].(map[string]any)
	if hub["name"] != "argus-hub" || hub["revision"].(float64) != 3 || hub["status"] != "deployed" {
		t.Errorf("hub release = %v, want revision 3 deployed", hub)
	}
	if hub["updated"] == nil {
		t.Error("updated missing: modifiedAt label should be read")
	}
	if hub["objects"].(float64) != 4 || hub["graded"].(float64) != 2 {
		t.Errorf("objects/graded = %v/%v, want 4/2 (the unannotated ConfigMap is not counted)", hub["objects"], hub["graded"])
	}
	if hub["health"] != "unhealthy" {
		t.Errorf("health = %v, want the worst graded object (unhealthy)", hub["health"])
	}
	if p := hub["problems"].([]any); len(p) != 1 || p[0].(map[string]any)["name"] != "argus-hub" {
		t.Errorf("problems = %v, want the not-ready argus-hub Deployment", p)
	}
	if m := hub["mainObject"].(map[string]any); m["kind"] != "Deployment" || m["name"] != "argus-hub" {
		t.Errorf("mainObject = %v, want the Deployment named after the release", m)
	}
	crd := rels[1].(map[string]any)
	if crd["name"] != "monitoring-crd" || crd["status"] != nil || !strings.Contains(fmt.Sprint(crd["statusUnavailable"]), "no release Secret") {
		t.Errorf("adopted release = %v, want statusUnavailable naming the missing Secret", crd)
	}
	if crd["health"] != nil || crd["graded"].(float64) != 0 {
		t.Errorf("a ConfigMap-only release has no graded health, got %v", crd)
	}
	if !strings.Contains(fmt.Sprint(out["note"]), "not read") {
		t.Errorf("note must say what is not read: %v", out["note"])
	}

	ns, _ := execInventory(t, exec, "list_helm_releases", `{"namespace":"monitoring"}`)
	if ns["total"].(float64) != 1 {
		t.Errorf("namespace filter: total = %v, want 1", ns["total"])
	}
}

func TestListHelmReleases_CapsAndSaysSo(t *testing.T) {
	exec, typed := newTestExecutor()
	var objs []runtime.Object
	for i := 0; i < maxHelmReleases+5; i++ {
		name := fmt.Sprintf("rel-%03d", i)
		objs = append(objs, &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "many", Annotations: helmAnn(name, "many")}})
	}
	attachObjectCache(t, exec, typed, nil, objs...)
	out, _ := execInventory(t, exec, "list_helm_releases", `{}`)
	if got := len(out["releases"].([]any)); got != maxHelmReleases {
		t.Errorf("releases = %d, want the cap %d", got, maxHelmReleases)
	}
	if out["truncated"] != true || out["total"].(float64) != maxHelmReleases+5 {
		t.Errorf("truncated/total = %v/%v, want true/%d", out["truncated"], out["total"], maxHelmReleases+5)
	}
}

// ---------------------------------------------------------------- GitOps

var inventoryGitOpsGVRs = map[string]schema.GroupVersionResource{
	"argoproj.io/Application":                   {Group: "argoproj.io", Version: "v1alpha1", Resource: "applications"},
	"kustomize.toolkit.fluxcd.io/Kustomization": {Group: "kustomize.toolkit.fluxcd.io", Version: "v1", Resource: "kustomizations"},
	"helm.toolkit.fluxcd.io/HelmRelease":        {Group: "helm.toolkit.fluxcd.io", Version: "v2", Resource: "helmreleases"},
}

func gitOpsExecutor(objs ...runtime.Object) (*ToolExecutor, *k8sfake.Clientset) {
	kinds := gitOpsTestListKinds()
	kinds[schema.GroupVersionResource{Group: "helm.toolkit.fluxcd.io", Version: "v2", Resource: "helmreleases"}] = "HelmReleaseList"
	dyn := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(k8sscheme.Scheme, kinds, objs...)
	typed := k8sfake.NewSimpleClientset()
	return &ToolExecutor{typed: typed, dynamic: dyn}, typed
}

func u(obj map[string]any) *unstructured.Unstructured { return &unstructured.Unstructured{Object: obj} }

// Shapes taken from rke2's argocd namespace (read-only, 2026-10-11): an
// Application whose repo credentials stopped working reports sync Unknown
// with a ComparisonError, next to a healthy one.
func TestListGitOpsApps_HeadlinesCountsAndOrder(t *testing.T) {
	argoApp := func(name, sync, health string, extra map[string]any) *unstructured.Unstructured {
		status := map[string]any{
			"sync":           map[string]any{"status": sync, "revision": "b5ee441b"},
			"health":         map[string]any{"status": health},
			"reconciledAt":   "2026-10-11T09:17:57Z",
			"operationState": map[string]any{"phase": "Succeeded", "finishedAt": "2026-09-19T14:05:55Z", "message": "successfully synced (all tasks run)", "syncResult": map[string]any{"revision": "b5ee441b"}},
		}
		for k, v := range extra {
			status[k] = v
		}
		return u(map[string]any{
			"apiVersion": "argoproj.io/v1alpha1", "kind": "Application",
			"metadata": map[string]any{"name": name, "namespace": "argocd"},
			"spec": map[string]any{
				"source":      map[string]any{"repoURL": "https://github.com/example/argocd-test.git", "path": "apps/" + name, "targetRevision": "main"},
				"destination": map[string]any{"server": "https://kubernetes.default.svc", "namespace": "argus-gitops-rke2"},
				"syncPolicy":  map[string]any{"automated": map[string]any{"prune": true, "selfHeal": true}},
			},
			"status": status,
		})
	}
	broken := argoApp("api", "Unknown", "Healthy", map[string]any{"conditions": []any{map[string]any{
		"type": "ComparisonError", "lastTransitionTime": "2026-09-21T21:57:14Z",
		"message": "Failed to load target state: failed to generate manifest for source 1 of 1: rpc error: code = Unknown desc = failed to list refs: authentication required: Invalid username or token.",
	}}})
	healthy := argoApp("guestbook", "Synced", "Healthy", nil)
	drifted := argoApp("web", "OutOfSync", "Healthy", map[string]any{"resources": []any{
		map[string]any{"group": "apps", "kind": "Deployment", "namespace": "argus-gitops-rke2", "name": "web", "status": "OutOfSync"},
		map[string]any{"kind": "Service", "namespace": "argus-gitops-rke2", "name": "web", "status": "Synced"},
	}})
	suspended := u(map[string]any{
		"apiVersion": "kustomize.toolkit.fluxcd.io/v1", "kind": "Kustomization",
		"metadata": map[string]any{"name": "infra", "namespace": "flux-system", "generation": int64(2)},
		"spec":     map[string]any{"suspend": true, "path": "./infra", "sourceRef": map[string]any{"kind": "GitRepository", "name": "flux-system"}},
		"status": map[string]any{"observedGeneration": int64(2), "conditions": []any{
			map[string]any{"type": "Ready", "status": "True", "reason": "ReconciliationSucceeded", "lastTransitionTime": "2026-10-10T08:00:00Z"}}},
	})
	failingHR := u(map[string]any{
		"apiVersion": "helm.toolkit.fluxcd.io/v2", "kind": "HelmRelease",
		"metadata": map[string]any{"name": "podinfo", "namespace": "apps", "generation": int64(1)},
		"spec": map[string]any{"targetNamespace": "podinfo", "chart": map[string]any{"spec": map[string]any{
			"chart": "podinfo", "version": "6.5.x", "sourceRef": map[string]any{"kind": "HelmRepository", "name": "podinfo"}}}},
		"status": map[string]any{"observedGeneration": int64(1), "conditions": []any{
			map[string]any{"type": "Ready", "status": "False", "reason": "UpgradeFailed", "message": "Helm upgrade failed: timed out waiting for the condition", "lastTransitionTime": "2026-10-11T07:00:00Z"}}},
	})
	exec, typed := gitOpsExecutor(broken, healthy, drifted, suspended, failingHR)
	attachObjectCache(t, exec, typed, inventoryGitOpsGVRs)

	out, raw := execInventory(t, exec, "list_gitops_apps", `{}`)
	c := out["counts"].(map[string]any)
	want := map[string]float64{"total": 5, "outOfSync": 2, "syncUnknown": 1, "suspended": 1}
	for k, v := range want {
		if c[k].(float64) != v {
			t.Errorf("counts.%s = %v, want %v (%v)", k, c[k], v, c)
		}
	}
	apps := out["apps"].([]any)
	byName := map[string]map[string]any{}
	for _, a := range apps {
		m := a.(map[string]any)
		byName[m["name"].(string)] = m
	}
	if h := fmt.Sprint(byName["api"]["headline"]); !strings.Contains(h, "cannot build the desired state from Git") || !strings.Contains(h, "authentication required") {
		t.Errorf("api headline = %q", h)
	}
	if !strings.Contains(fmt.Sprint(byName["api"]["causes"]), "credentials") {
		t.Errorf("api causes = %v, want the ComparisonError action", byName["api"]["causes"])
	}
	if h := fmt.Sprint(byName["web"]["headline"]); !strings.Contains(h, "1 of 2 managed objects out of sync (Deployment web)") {
		t.Errorf("web headline = %q", h)
	}
	if byName["guestbook"]["headline"] != nil || byName["guestbook"]["problem"] != nil {
		t.Errorf("a synced, healthy app has no headline: %v", byName["guestbook"])
	}
	if g := byName["guestbook"]; g["repoURL"] == nil || g["path"] != "apps/guestbook" || g["destinationNamespace"] != "argus-gitops-rke2" || g["lastSync"] != "2026-09-19T14:05:55Z" {
		t.Errorf("argo source/destination/lastSync = %v", g)
	}
	if k := byName["infra"]; k["suspended"] != true || k["problem"] != nil || !strings.Contains(fmt.Sprint(k["headline"]), "Suspended") {
		t.Errorf("suspended kustomization = %v", k)
	}
	if hr := byName["podinfo"]; hr["chart"] != "podinfo" || hr["sourceRef"] != "HelmRepository/podinfo" || hr["destinationNamespace"] != "podinfo" ||
		!strings.Contains(fmt.Sprint(hr["headline"]), "UpgradeFailed") || hr["problem"] != true {
		t.Errorf("failing helmrelease = %v", hr)
	}
	// Problems sort ahead of quiet apps.
	if apps[len(apps)-1].(map[string]any)["problem"] == true {
		t.Errorf("a problem app sorted last: %s", raw)
	}

	filtered, _ := execInventory(t, exec, "list_gitops_apps", `{"namespace":"argus-gitops-rke2"}`)
	if filtered["counts"].(map[string]any)["total"].(float64) != 3 {
		t.Errorf("namespace filter matches an Argo app's destination: %v", filtered["counts"])
	}
}

func TestListGitOpsApps_NoControllersIsCoverageNotError(t *testing.T) {
	exec, typed := newTestExecutor()
	attachObjectCache(t, exec, typed, nil)
	out, _ := execInventory(t, exec, "list_gitops_apps", `{}`)
	if len(out["apps"].([]any)) != 0 || out["counts"].(map[string]any)["total"].(float64) != 0 {
		t.Errorf("want no apps: %v", out)
	}
	kinds := out["kinds"].([]any)
	if len(kinds) != 3 {
		t.Fatalf("kinds = %v, want all three listed kinds reported", kinds)
	}
	for _, k := range kinds {
		if k.(map[string]any)["state"] != "absent" {
			t.Errorf("kind %v: want absent", k)
		}
	}
}

// ---------------------------------------------------------------- namespace topology

func TestGetNamespaceTopology_GraphCapAndIndex(t *testing.T) {
	exec, typed := newTestExecutor()
	dep := deployment("shop", "cart", nil, 3, 3)
	isController := true
	rs := &appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{Name: "cart-6f7", Namespace: "shop",
		OwnerReferences: []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "Deployment", Name: "cart", Controller: &isController}}}}
	var objs []runtime.Object
	objs = append(objs, dep, rs,
		&corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: "cart", Namespace: "shop"}, Spec: corev1.ServiceSpec{Selector: map[string]string{"app": "cart"}}},
		&corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "node-a"}},
		&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "other", Namespace: "elsewhere"}},
	)
	for i := 0; i < 3; i++ {
		objs = append(objs, &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: fmt.Sprintf("cart-%d", i), Namespace: "shop", Labels: map[string]string{"app": "cart"},
				OwnerReferences: []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "ReplicaSet", Name: "cart-6f7", Controller: &isController}}},
			Spec:   corev1.PodSpec{NodeName: "node-a", Containers: []corev1.Container{{Name: "c", Image: "img"}}},
			Status: corev1.PodStatus{Phase: corev1.PodRunning},
		})
	}
	// Unreferenced ConfigMaps are not drawn (as in the neighbourhood), so
	// they neither appear nor count as omitted.
	for i := 0; i < 4; i++ {
		objs = append(objs, &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: fmt.Sprintf("cm-%d", i), Namespace: "shop"}})
	}
	attachObjectCache(t, exec, typed, nil, objs...)

	out, raw := execInventory(t, exec, "get_namespace_topology", `{"namespace":"shop"}`)
	kinds := map[string]int{}
	for _, n := range out["nodes"].([]any) {
		m := n.(map[string]any)
		kinds[m["kind"].(string)]++
		if m["namespace"] != "shop" {
			t.Errorf("node from another namespace: %v", m)
		}
	}
	if kinds["Node"] != 0 || out["clusterNodes"].(float64) != 1 {
		t.Errorf("cluster Nodes must be counted, not drawn: kinds %v, clusterNodes %v", kinds, out["clusterNodes"])
	}
	if kinds["PodGroup"] != 1 || kinds["Pod"] != 0 || kinds["Deployment"] != 1 || kinds["Service"] != 1 {
		t.Errorf("want the 3 replicas collapsed to one PodGroup under the Deployment and Service: %v\n%s", kinds, raw)
	}
	if out["omittedNodes"] != nil || out["truncated"] != nil {
		t.Errorf("an uncapped namespace reports no omission: %v/%v", out["omittedNodes"], out["truncated"])
	}

	capped, _ := execInventory(t, exec, "get_namespace_topology", `{"namespace":"shop","cap":2}`)
	if len(capped["nodes"].([]any)) != 2 || capped["truncated"] != true {
		t.Fatalf("cap 2: nodes %d truncated %v", len(capped["nodes"].([]any)), capped["truncated"])
	}
	total := capped["totalNodes"].(float64)
	if capped["omittedNodes"].(float64) != total-2 {
		t.Errorf("omittedNodes = %v, want totalNodes-2 = %v", capped["omittedNodes"], total-2)
	}
	if capped["omittedByKind"].(map[string]any)["PodGroup"] == nil {
		t.Errorf("pods rank after their Service and Deployment and must be what the cap drops: %v", capped["omittedByKind"])
	}
	for _, n := range capped["nodes"].([]any) {
		if k := n.(map[string]any)["kind"]; k != "Service" && k != "Deployment" {
			t.Errorf("cap kept %v ahead of the Service and Deployment", k)
		}
	}

	idx, _ := execInventory(t, exec, "get_namespace_topology", `{}`)
	ns := idx["namespaces"].([]any)
	if len(ns) < 2 || ns[0].(map[string]any)["name"] != "shop" || ns[0].(map[string]any)["pods"].(float64) != 3 {
		t.Errorf("index = %v, want shop first with 3 pods", ns)
	}
	if idx["nodes"] != nil {
		t.Errorf("the index carries no graph: %v", idx["nodes"])
	}

	if _, _, err := exec.Execute(context.Background(), "get_namespace_topology", json.RawMessage(`{"namespace":"shop","cap":-1}`)); err != nil {
		t.Errorf("a non-positive cap means the default, not an error: %v", err)
	}
}

// A Helm chart stamps one app.kubernetes.io/name on every workload in a
// release (rke2's nebula namespace: sixteen Deployments, one label value). The
// namespace map groups pods by owner, so each workload keeps its own pods.
func TestGetNamespaceTopology_PodsGroupByOwnerNotSharedAppLabel(t *testing.T) {
	exec, typed := newTestExecutor()
	isController := true
	var objs []runtime.Object
	for _, name := range []string{"nebula-api", "nebula-control"} {
		objs = append(objs, deployment("nebula", name, nil, 2, 2),
			&appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{Name: name + "-rs", Namespace: "nebula",
				OwnerReferences: []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "Deployment", Name: name, Controller: &isController}}}})
		for i := 0; i < 2; i++ {
			objs = append(objs, &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{Name: fmt.Sprintf("%s-%d", name, i), Namespace: "nebula",
					Labels:          map[string]string{"app.kubernetes.io/name": "nebula"},
					OwnerReferences: []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "ReplicaSet", Name: name + "-rs", Controller: &isController}}},
				Spec:   corev1.PodSpec{Containers: []corev1.Container{{Name: "c", Image: "img"}}},
				Status: corev1.PodStatus{Phase: corev1.PodRunning},
			})
		}
	}
	attachObjectCache(t, exec, typed, nil, objs...)
	out, raw := execInventory(t, exec, "get_namespace_topology", `{"namespace":"nebula"}`)
	groups := 0
	for _, n := range out["nodes"].([]any) {
		if n.(map[string]any)["kind"] == "PodGroup" {
			groups++
		}
	}
	if groups != 2 {
		t.Errorf("want one pod group per Deployment, got %d:\n%s", groups, raw)
	}
}

// The picker's index counts what the namespace map draws a card for — a
// CronJob-owned Job joins its CronJob's card, so it is not a workload of its
// own — and names pods and workloads not healthy separately, so its workload
// figure is the same count as the map's status line.
func TestNamespaceIndexSplitsNotHealthyAndCountsCards(t *testing.T) {
	exec, typed := newTestExecutor()
	isController := true
	objs := []runtime.Object{
		deployment("batchy", "web", nil, 2, 1), // degraded
		&batchv1.CronJob{ObjectMeta: metav1.ObjectMeta{Name: "nightly", Namespace: "batchy", CreationTimestamp: metav1.Now()}, Spec: batchv1.CronJobSpec{Schedule: "0 0 * * *"}}, // never run yet, freshly created: neutral
		&batchv1.Job{ObjectMeta: metav1.ObjectMeta{Name: "nightly-1", Namespace: "batchy",
			OwnerReferences: []metav1.OwnerReference{{APIVersion: "batch/v1", Kind: "CronJob", Name: "nightly", Controller: &isController}}}},
		&batchv1.Job{ObjectMeta: metav1.ObjectMeta{Name: "oneoff", Namespace: "batchy"},
			Status: batchv1.JobStatus{Conditions: []batchv1.JobCondition{{Type: batchv1.JobFailed, Status: corev1.ConditionTrue}}}},
		&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "web-1", Namespace: "batchy"}, Status: corev1.PodStatus{Phase: corev1.PodFailed}},
	}
	attachObjectCache(t, exec, typed, nil, objs...)
	idx, raw := execInventory(t, exec, "get_namespace_topology", `{}`)
	var row map[string]any
	for _, n := range idx["namespaces"].([]any) {
		if n.(map[string]any)["name"] == "batchy" {
			row = n.(map[string]any)
		}
	}
	if row == nil {
		t.Fatalf("no batchy row: %s", raw)
	}
	if row["workloads"] != float64(3) {
		t.Errorf("workloads = %v, want 3 (Deployment, CronJob, the Job no CronJob owns)", row["workloads"])
	}
	if row["workloadsNotHealthy"] != float64(2) || row["podsNotHealthy"] != float64(1) || row["notHealthy"] != float64(3) {
		t.Errorf("not healthy: workloads %v pods %v total %v; want 2, 1, 3", row["workloadsNotHealthy"], row["podsNotHealthy"], row["notHealthy"])
	}
}
