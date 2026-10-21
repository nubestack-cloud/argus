package pathtrace

import (
	"errors"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/util/intstr"
)

var errUnreadable = errors.New("kind not available in the object cache")

// fakeProvider is an in-memory Provider. A kind listed in unreadable returns
// errUnreadable; a Gateway API kind listed in absent reports StateAbsent.
type fakeProvider struct {
	services       []*corev1.Service
	pods           []*corev1.Pod
	slices         []*discoveryv1.EndpointSlice
	replicaSets    []*appsv1.ReplicaSet
	ingresses      []*networkingv1.Ingress
	ingressClasses []*networkingv1.IngressClass
	policies       []*networkingv1.NetworkPolicy
	dynamic        map[string][]*unstructured.Unstructured // by kind
	unreadable     map[string]bool                         // by kind
	absent         map[string]bool                         // by kind
}

func newFake() *fakeProvider {
	return &fakeProvider{dynamic: map[string][]*unstructured.Unstructured{}, unreadable: map[string]bool{}, absent: map[string]bool{}}
}

func inNS[T metav1.Object](items []T, ns string) []T {
	var out []T
	for _, it := range items {
		if ns == "" || it.GetNamespace() == ns {
			out = append(out, it)
		}
	}
	return out
}

func (f *fakeProvider) check(kind string) error {
	if f.unreadable[kind] {
		return errUnreadable
	}
	return nil
}

func (f *fakeProvider) Services(ns string) ([]*corev1.Service, error) {
	if err := f.check("Service"); err != nil {
		return nil, err
	}
	return inNS(f.services, ns), nil
}

func (f *fakeProvider) Pods(ns string) ([]*corev1.Pod, error) {
	if err := f.check("Pod"); err != nil {
		return nil, err
	}
	return inNS(f.pods, ns), nil
}

func (f *fakeProvider) EndpointSlices(ns string) ([]*discoveryv1.EndpointSlice, error) {
	if err := f.check("EndpointSlice"); err != nil {
		return nil, err
	}
	return inNS(f.slices, ns), nil
}

func (f *fakeProvider) ReplicaSets(ns string) ([]*appsv1.ReplicaSet, error) {
	if err := f.check("ReplicaSet"); err != nil {
		return nil, err
	}
	return inNS(f.replicaSets, ns), nil
}

func (f *fakeProvider) Ingresses(ns string) ([]*networkingv1.Ingress, error) {
	if err := f.check("Ingress"); err != nil {
		return nil, err
	}
	return inNS(f.ingresses, ns), nil
}

func (f *fakeProvider) IngressClasses() ([]*networkingv1.IngressClass, error) {
	if err := f.check("IngressClass"); err != nil {
		return nil, err
	}
	return f.ingressClasses, nil
}

func (f *fakeProvider) NetworkPolicies(ns string) ([]*networkingv1.NetworkPolicy, error) {
	if err := f.check("NetworkPolicy"); err != nil {
		return nil, err
	}
	return inNS(f.policies, ns), nil
}

func (f *fakeProvider) Dynamic(group, kind, ns string) ([]*unstructured.Unstructured, error) {
	if err := f.check(kind); err != nil {
		return nil, err
	}
	if f.absent[kind] {
		return nil, errUnreadable
	}
	var out []*unstructured.Unstructured
	for _, u := range f.dynamic[kind] {
		if ns == "" || u.GetNamespace() == ns {
			out = append(out, u)
		}
	}
	return out, nil
}

func (f *fakeProvider) State(group, kind string) string {
	if f.absent[kind] {
		return StateAbsent
	}
	return "synced"
}

func (f *fakeProvider) addDynamic(objs ...*unstructured.Unstructured) {
	for _, o := range objs {
		f.dynamic[o.GetKind()] = append(f.dynamic[o.GetKind()], o)
	}
}

// --- fixtures ---

func readyCond(ready bool) []corev1.PodCondition {
	s := corev1.ConditionFalse
	if ready {
		s = corev1.ConditionTrue
	}
	return []corev1.PodCondition{{Type: corev1.PodReady, Status: s, LastTransitionTime: metav1.NewTime(time.Now())}}
}

func mkPod(name, ns string, lbls map[string]string, ready bool, ports ...corev1.ContainerPort) *corev1.Pod {
	phase := corev1.PodRunning
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns, Labels: lbls},
		Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "main", Ports: ports}}},
		Status:     corev1.PodStatus{Phase: phase, PodIP: "10.0.0.1", Conditions: readyCond(ready)},
	}
}

func crashingPod(name, ns string, lbls map[string]string) *corev1.Pod {
	p := mkPod(name, ns, lbls, false)
	p.Status.ContainerStatuses = []corev1.ContainerStatus{{Name: "main", State: corev1.ContainerState{Waiting: &corev1.ContainerStateWaiting{Reason: "CrashLoopBackOff"}}}}
	return p
}

func mkService(name, ns string, sel map[string]string, ports ...corev1.ServicePort) *corev1.Service {
	if len(ports) == 0 {
		ports = []corev1.ServicePort{{Name: "http", Port: 80, TargetPort: intstr.FromInt32(8080)}}
	}
	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
		Spec:       corev1.ServiceSpec{Selector: sel, Ports: ports},
	}
}

func ingressTo(name, ns string, backends ...string) *networkingv1.Ingress {
	var paths []networkingv1.HTTPIngressPath
	for _, b := range backends {
		paths = append(paths, networkingv1.HTTPIngressPath{
			Path:    "/" + b,
			Backend: networkingv1.IngressBackend{Service: &networkingv1.IngressServiceBackend{Name: b, Port: networkingv1.ServiceBackendPort{Number: 80}}},
		})
	}
	return &networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
		Spec: networkingv1.IngressSpec{Rules: []networkingv1.IngressRule{{
			IngressRuleValue: networkingv1.IngressRuleValue{HTTP: &networkingv1.HTTPIngressRuleValue{Paths: paths}},
		}}},
	}
}

// gwObject is a Gateway API object of kind with the given spec.
func gwObject(kind, name, namespace string, spec map[string]any) *unstructured.Unstructured {
	u := &unstructured.Unstructured{Object: map[string]any{"spec": spec}}
	u.SetAPIVersion(gatewayGroup + "/v1")
	u.SetKind(kind)
	u.SetNamespace(namespace)
	u.SetName(name)
	return u
}

// gatewayObject is a Gateway with one plain-HTTP listener on port 80.
func gatewayObject(name, namespace string) *unstructured.Unstructured {
	return gwObject("Gateway", name, namespace, map[string]any{
		"gatewayClassName": "test",
		"listeners":        []any{map[string]any{"name": "http", "protocol": "HTTP", "port": int64(80)}},
	})
}

// httpRoute is an HTTPRoute whose single rule sends to the given backendRefs,
// attached to Gateway gw in its own namespace.
func httpRoute(name, ns, gw string, backends ...map[string]any) *unstructured.Unstructured {
	var refs []any
	for _, b := range backends {
		refs = append(refs, b)
	}
	return gwObject("HTTPRoute", name, ns, map[string]any{
		"parentRefs": []any{map[string]any{"name": gw}},
		"rules":      []any{map[string]any{"backendRefs": refs}},
	})
}

func backend(name string, port int64) map[string]any {
	return map[string]any{"name": name, "port": port}
}

func setParentStatus(route *unstructured.Unstructured, gw, ns, accepted, reason string) {
	parents, _, _ := unstructured.NestedSlice(route.Object, "status", "parents")
	parents = append(parents, map[string]any{
		"parentRef": map[string]any{"name": gw, "namespace": ns},
		"conditions": []any{map[string]any{
			"type": "Accepted", "status": accepted, "reason": reason, "message": "test",
		}},
	})
	_ = unstructured.SetNestedSlice(route.Object, parents, "status", "parents")
}

func findingByCode(findings []Finding, code string) *Finding {
	for i := range findings {
		if findings[i].Code == code {
			return &findings[i]
		}
	}
	return nil
}
