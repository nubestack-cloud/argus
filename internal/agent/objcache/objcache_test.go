package objcache

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

const canary = "s3cr3t-canary-value"

type allowAll struct{ deny map[string]bool }

func (a allowAll) Lookup(group, kind string, versions []string) (schema.GroupVersionResource, bool, string) {
	if a.deny[group+"/"+kind] {
		return schema.GroupVersionResource{}, false, StateForbidden
	}
	if group != "" && group != "apps" && group != "batch" && !strings.Contains(group, "k8s.io") {
		return schema.GroupVersionResource{}, false, StateAbsent
	}
	return schema.GroupVersionResource{Group: group, Version: versions[0], Resource: strings.ToLower(kind) + "s"}, true, ""
}

func waitSynced(t *testing.T, c *Cache, group, kind string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if c.State(group, kind) == StateSynced {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("%s/%s never synced (state %q)", group, kind, c.State(group, kind))
}

func TestTransformHashesSensitiveValuesAndDropsLastApplied(t *testing.T) {
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: "cfg", Namespace: "ns",
			Annotations:   map[string]string{LastAppliedAnnotation: `{"data":{"password":"` + canary + `"}}`, "keep": "yes"},
			ManagedFields: []metav1.ManagedFieldsEntry{{Manager: "kubectl"}}},
		Data:       map[string]string{"password": canary},
		BinaryData: map[string][]byte{"blob": []byte(canary)},
	}
	dep := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Name: "app", Namespace: "ns"},
		Spec: appsv1.DeploymentSpec{Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{
			Containers: []corev1.Container{{Name: "c", Env: []corev1.EnvVar{{Name: "TOKEN", Value: canary}, {Name: "FROM", ValueFrom: &corev1.EnvVarSource{}}}}},
		}}},
	}
	client := fake.NewSimpleClientset(cm, dep)
	var hookSaw string
	c := New(client, nil, allowAll{}, Options{LastAppliedHook: func(_, _ string, _ *unstructured.Unstructured, la string) { hookSaw = la }})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c.Start(ctx)
	waitSynced(t, c, "", "ConfigMap")
	waitSynced(t, c, "apps", "Deployment")

	cms, err := c.ConfigMaps("ns")
	if err != nil || len(cms) != 1 {
		t.Fatalf("ConfigMaps = %v, %v", cms, err)
	}
	got := cms[0]
	if got.Data["password"] != HashValue([]byte(canary)) {
		t.Errorf("data value not hashed: %q", got.Data["password"])
	}
	if string(got.BinaryData["blob"]) != HashValue([]byte(canary)) {
		t.Errorf("binaryData value not hashed")
	}
	if _, ok := got.Annotations[LastAppliedAnnotation]; ok {
		t.Error("last-applied annotation retained")
	}
	if got.Annotations["keep"] != "yes" {
		t.Error("unrelated annotation dropped")
	}
	if len(got.ManagedFields) != 0 {
		t.Error("managedFields retained")
	}
	if !strings.Contains(hookSaw, canary) {
		t.Error("LastAppliedHook did not see the annotation before it was dropped")
	}
	deps, _ := c.Deployments("ns")
	env := deps[0].Spec.Template.Spec.Containers[0].Env
	if env[0].Value != HashValue([]byte(canary)) || env[1].ValueFrom == nil {
		t.Errorf("env not hashed / valueFrom lost: %+v", env)
	}
}

func TestUnstructuredHashing(t *testing.T) {
	u := &unstructured.Unstructured{Object: map[string]any{
		"spec": map[string]any{
			"template": map[string]any{"spec": map[string]any{"containers": []any{
				map[string]any{"env": []any{map[string]any{"name": "A", "value": canary}}},
			}}},
			"data": map[string]any{"k": canary},
		},
	}}
	hashSensitive(u)
	s := strings.Join([]string{
		u.Object["spec"].(map[string]any)["data"].(map[string]any)["k"].(string),
	}, "")
	if strings.Contains(s, canary) {
		t.Error("unstructured data value not hashed")
	}
	envVal := u.Object["spec"].(map[string]any)["template"].(map[string]any)["spec"].(map[string]any)["containers"].([]any)[0].(map[string]any)["env"].([]any)[0].(map[string]any)["value"]
	if envVal != HashValue([]byte(canary)) {
		t.Errorf("unstructured env value not hashed: %v", envVal)
	}
}

func TestUnavailableKindsAreNotEmpty(t *testing.T) {
	client := fake.NewSimpleClientset()
	c := New(client, nil, allowAll{deny: map[string]bool{"networking.k8s.io/NetworkPolicy": true}},
		Options{Exclude: map[string]bool{"/ConfigMap": true}})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c.Start(ctx)

	_, err := c.NetworkPolicies("")
	var ue *UnavailableError
	if !errors.As(err, &ue) || ue.State != StateForbidden {
		t.Fatalf("forbidden kind: err = %v", err)
	}
	if _, err := c.ConfigMaps(""); !errors.Is(err, ErrUnavailable) || c.State("", "ConfigMap") != StateDisabled {
		t.Fatalf("disabled kind: err = %v state = %s", err, c.State("", "ConfigMap"))
	}
	if _, err := c.Dynamic("argoproj.io", "Application", ""); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("absent CRD kind should be unavailable, got %v", err)
	}
	cov := c.Coverage([2]string{"networking.k8s.io", "NetworkPolicy"}, [2]string{"", "Pod"})
	if len(cov) == 0 || cov[0].Kind != "NetworkPolicy" {
		t.Fatalf("coverage = %+v", cov)
	}
}

func TestChangesDeliveredAfterInitialSync(t *testing.T) {
	existing := &corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: "old", Namespace: "ns"}}
	client := fake.NewSimpleClientset(existing)
	c := New(client, nil, allowAll{}, Options{})
	var mu sync.Mutex
	var got []Change
	c.OnChange(func(ch Change) {
		if ch.Kind == "Service" {
			mu.Lock()
			got = append(got, ch)
			mu.Unlock()
		}
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c.Start(ctx)
	waitSynced(t, c, "", "Service")
	_, err := client.CoreV1().Services("ns").Create(ctx, &corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: "new", Namespace: "ns"}}, metav1.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		n := len(got)
		mu.Unlock()
		if n > 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(got) != 1 || got[0].Op != "add" || got[0].New.(*corev1.Service).Name != "new" {
		t.Fatalf("changes = %+v (the pre-existing object must not be reported as a change)", got)
	}
}

// A just-started cache must say it is still syncing — SyncedAt zero and
// FirstSync open — while any kind's initial list is in flight, and close
// FirstSync the moment the last one lands. The cluster summary keys "still
// reading the cluster" off exactly this.
func TestFirstSyncWaitsForEveryKind(t *testing.T) {
	client := fake.NewSimpleClientset(&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "p", Namespace: "ns"}})
	release := make(chan struct{})
	client.PrependReactor("list", "pods", func(k8stesting.Action) (bool, runtime.Object, error) {
		<-release
		return false, nil, nil
	})
	c := New(client, nil, allowAll{}, Options{})
	if !c.StartedAt().IsZero() {
		t.Fatal("StartedAt must be zero before Start")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c.Start(ctx)
	if c.StartedAt().IsZero() {
		t.Fatal("StartedAt must be set by Start")
	}
	// (The fake clientset serialises reactors, so every kind waits behind
	// the held Pod list — which is the point: nothing has finished.)
	select {
	case <-c.FirstSync():
		t.Fatal("FirstSync closed while Pods were still listing")
	case <-time.After(1200 * time.Millisecond):
	}
	if !c.SyncedAt().IsZero() || c.State("", "Pod") != StateSyncing {
		t.Fatalf("SyncedAt = %v, Pod state = %s; want zero / syncing", c.SyncedAt(), c.State("", "Pod"))
	}
	close(release)
	select {
	case <-c.FirstSync():
	case <-time.After(5 * time.Second):
		t.Fatal("FirstSync never closed after the last kind synced")
	}
	if c.SyncedAt().IsZero() {
		t.Fatal("SyncedAt must be set once FirstSync is closed")
	}
}

// A kind refused when the cache was built (a read granted later, or a CRD
// installed later) is watched after Rediscover, without a restart, and kinds
// already running or deliberately disabled are left alone.
func TestRediscoverAttachesKindsThatBecameAvailable(t *testing.T) {
	np := &networkingv1.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: "deny-all", Namespace: "ns"}}
	client := fake.NewSimpleClientset(np)
	c := New(client, nil, allowAll{deny: map[string]bool{"networking.k8s.io/NetworkPolicy": true}},
		Options{Exclude: map[string]bool{"/ConfigMap": true}})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c.Start(ctx)
	waitSynced(t, c, "", "Pod")
	if c.State("networking.k8s.io", "NetworkPolicy") != StateForbidden || !c.NeedsRediscovery() {
		t.Fatalf("precondition: state %q", c.State("networking.k8s.io", "NetworkPolicy"))
	}
	if added := c.Rediscover(allowAll{deny: map[string]bool{"networking.k8s.io/NetworkPolicy": true}}); len(added) != 0 {
		t.Fatalf("nothing changed, yet Rediscover attached %v", added)
	}
	added := c.Rediscover(allowAll{})
	if len(added) != 1 || added[0] != "networking.k8s.io/NetworkPolicy" {
		t.Fatalf("added = %v", added)
	}
	// Status is re-read every 10 s once the first sync is done.
	for deadline := time.Now().Add(15 * time.Second); c.State("networking.k8s.io", "NetworkPolicy") != StateSynced; time.Sleep(100 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("never synced: %q", c.State("networking.k8s.io", "NetworkPolicy"))
		}
	}
	if got, err := c.NetworkPolicies("ns"); err != nil || len(got) != 1 {
		t.Fatalf("network policies = %v, %v", got, err)
	}
	if c.State("", "ConfigMap") != StateDisabled {
		t.Fatalf("a disabled kind must stay disabled, got %q", c.State("", "ConfigMap"))
	}
}
