package topology

import (
	"errors"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	autoscalingv2 "k8s.io/api/autoscaling/v2"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	policyv1 "k8s.io/api/policy/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// testNow is the fixed clock the builder tests grade with.
var testNow = time.Date(2026, 6, 25, 12, 0, 0, 0, time.UTC)

// mockProvider serves fixed object lists, honouring the namespace argument
// the way the agent's object cache does, and fails the kinds named in fail.
type mockProvider struct {
	// Workloads and their pods, in the order the builder links them.
	deployments  []*appsv1.Deployment
	statefulSets []*appsv1.StatefulSet
	daemonSets   []*appsv1.DaemonSet
	replicaSets  []*appsv1.ReplicaSet
	cronJobs     []*batchv1.CronJob
	jobs         []*batchv1.Job
	pods         []*corev1.Pod

	// Traffic.
	services  []*corev1.Service
	ingresses []*networkingv1.Ingress

	// What workloads use.
	configMaps      []*corev1.ConfigMap
	serviceAccounts []*corev1.ServiceAccount
	pvcs            []*corev1.PersistentVolumeClaim
	pvs             []*corev1.PersistentVolume

	// What scales or guards them.
	hpas            []*autoscalingv2.HorizontalPodAutoscaler
	pdbs            []*policyv1.PodDisruptionBudget
	networkPolicies []*networkingv1.NetworkPolicy

	nodes []*corev1.Node

	fail map[NodeKind]bool
	// calls records the namespace argument of every list call, by kind.
	calls map[NodeKind][]string
}

var errForbidden = errors.New("forbidden")

func filterNS[T metav1.Object](m *mockProvider, kind NodeKind, items []T, ns string) ([]T, error) {
	if m.calls == nil {
		m.calls = map[NodeKind][]string{}
	}
	m.calls[kind] = append(m.calls[kind], ns)
	if m.fail[kind] {
		return nil, errForbidden
	}
	if ns == "" {
		return items, nil
	}
	var out []T
	for _, it := range items {
		if it.GetNamespace() == ns {
			out = append(out, it)
		}
	}
	return out, nil
}

func (m *mockProvider) Pods(ns string) ([]*corev1.Pod, error) {
	return filterNS(m, KindPod, m.pods, ns)
}
func (m *mockProvider) Services(ns string) ([]*corev1.Service, error) {
	return filterNS(m, KindService, m.services, ns)
}
func (m *mockProvider) Deployments(ns string) ([]*appsv1.Deployment, error) {
	return filterNS(m, KindDeployment, m.deployments, ns)
}
func (m *mockProvider) DaemonSets(ns string) ([]*appsv1.DaemonSet, error) {
	return filterNS(m, KindDaemonSet, m.daemonSets, ns)
}
func (m *mockProvider) StatefulSets(ns string) ([]*appsv1.StatefulSet, error) {
	return filterNS(m, KindStatefulSet, m.statefulSets, ns)
}
func (m *mockProvider) ReplicaSets(ns string) ([]*appsv1.ReplicaSet, error) {
	return filterNS(m, KindReplicaSet, m.replicaSets, ns)
}
func (m *mockProvider) Jobs(ns string) ([]*batchv1.Job, error) {
	return filterNS(m, KindJob, m.jobs, ns)
}
func (m *mockProvider) CronJobs(ns string) ([]*batchv1.CronJob, error) {
	return filterNS(m, KindCronJob, m.cronJobs, ns)
}
func (m *mockProvider) Ingresses(ns string) ([]*networkingv1.Ingress, error) {
	return filterNS(m, KindIngress, m.ingresses, ns)
}
func (m *mockProvider) ConfigMaps(ns string) ([]*corev1.ConfigMap, error) {
	return filterNS(m, KindConfigMap, m.configMaps, ns)
}
func (m *mockProvider) PersistentVolumeClaims(ns string) ([]*corev1.PersistentVolumeClaim, error) {
	return filterNS(m, KindPVC, m.pvcs, ns)
}
func (m *mockProvider) PersistentVolumes(ns string) ([]*corev1.PersistentVolume, error) {
	return filterNS(m, KindPV, m.pvs, ns)
}
func (m *mockProvider) HorizontalPodAutoscalers(ns string) ([]*autoscalingv2.HorizontalPodAutoscaler, error) {
	return filterNS(m, KindHPA, m.hpas, ns)
}
func (m *mockProvider) PodDisruptionBudgets(ns string) ([]*policyv1.PodDisruptionBudget, error) {
	return filterNS(m, KindPDB, m.pdbs, ns)
}
func (m *mockProvider) NetworkPolicies(ns string) ([]*networkingv1.NetworkPolicy, error) {
	return filterNS(m, KindNetworkPolicy, m.networkPolicies, ns)
}
func (m *mockProvider) Nodes(ns string) ([]*corev1.Node, error) {
	return filterNS(m, KindNode, m.nodes, ns)
}
func (m *mockProvider) ServiceAccounts(ns string) ([]*corev1.ServiceAccount, error) {
	return filterNS(m, KindServiceAccount, m.serviceAccounts, ns)
}

// gatewayDynamic serves Gateway API objects by kind; kinds absent from objs
// are reported as not served.
type gatewayDynamic struct {
	objs map[string][]*unstructured.Unstructured
	fail map[string]bool
}

func (g *gatewayDynamic) List(gk schema.GroupKind, ns string) ([]*unstructured.Unstructured, error) {
	if gk.Group != GatewayAPIGroup {
		return nil, ErrNotServed
	}
	if g.fail[gk.Kind] {
		return nil, errForbidden
	}
	items, ok := g.objs[gk.Kind]
	if !ok {
		return nil, ErrNotServed
	}
	var out []*unstructured.Unstructured
	for _, it := range items {
		if ns == "" || it.GetNamespace() == ns {
			out = append(out, it)
		}
	}
	return out, nil
}

func gatewayObject(kind, ns, name string) *unstructured.Unstructured {
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": GatewayAPIGroup + "/v1",
		"kind":       kind,
		"metadata":   map[string]any{"name": name, "namespace": ns},
	}}
}

func build(t interface {
	Helper()
	Fatalf(string, ...any)
}, p ResourceProvider, opts BuildOptions) *Topology {
	t.Helper()
	topo, err := NewBuilder(p).WithClock(func() time.Time { return testNow }).Build(opts)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	return topo
}

func nodeByID(nodes []Node, id string) *Node {
	for i := range nodes {
		if nodes[i].ID == id {
			return &nodes[i]
		}
	}
	return nil
}

func edgeSet(edges []Edge) map[string]bool {
	out := map[string]bool{}
	for _, e := range edges {
		out[e.Source+" -"+string(e.Type)+"-> "+e.Target] = true
	}
	return out
}

func boolPtr(b bool) *bool    { return &b }
func int32Ptr(i int32) *int32 { return &i }

func controllerRef(apiVersion, kind, name string) metav1.OwnerReference {
	return metav1.OwnerReference{APIVersion: apiVersion, Kind: kind, Name: name, Controller: boolPtr(true)}
}

func deployment(ns, name string, labels map[string]string) *appsv1.Deployment {
	return &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
		Spec: appsv1.DeploymentSpec{
			Replicas: int32Ptr(1),
			Template: corev1.PodTemplateSpec{ObjectMeta: metav1.ObjectMeta{Labels: labels}},
		},
		Status: appsv1.DeploymentStatus{ReadyReplicas: 1, AvailableReplicas: 1},
	}
}

func replicaSet(ns, name, deploymentName string, labels map[string]string) *appsv1.ReplicaSet {
	return &appsv1.ReplicaSet{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns, OwnerReferences: []metav1.OwnerReference{
			controllerRef("apps/v1", "Deployment", deploymentName),
		}},
		Spec: appsv1.ReplicaSetSpec{
			Replicas: int32Ptr(1),
			Template: corev1.PodTemplateSpec{ObjectMeta: metav1.ObjectMeta{Labels: labels}},
		},
	}
}

func runningPod(ns, name, rsName string, labels map[string]string) *corev1.Pod {
	p := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns, Labels: labels},
		Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "app"}}},
		Status: corev1.PodStatus{
			Phase:             corev1.PodRunning,
			ContainerStatuses: []corev1.ContainerStatus{{Name: "app", Ready: true}},
		},
	}
	if rsName != "" {
		p.OwnerReferences = []metav1.OwnerReference{controllerRef("apps/v1", "ReplicaSet", rsName)}
	}
	return p
}
