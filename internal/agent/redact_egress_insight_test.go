package agent

import (
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	autoscalingv2 "k8s.io/api/autoscaling/v2"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/apimachinery/pkg/version"
	fakediscovery "k8s.io/client-go/discovery/fake"
	k8sfake "k8s.io/client-go/kubernetes/fake"
)

// attachCanaryObjectCache gives the canary cluster an object cache whose
// objects carry the canary in every field class a cluster-insight tool might
// echo: env values, annotations, labels-adjacent text, a ConfigMap value, and
// a bearer-shaped annotation for the pattern layer.
func attachCanaryObjectCache(t *testing.T, exec *ToolExecutor, typed *k8sfake.Clientset, pod *corev1.Pod) {
	t.Helper()
	p := pod.DeepCopy()
	p.Labels = map[string]string{"app": "payments"}
	p.Spec.Containers[0].Ports = []corev1.ContainerPort{{Name: "http", ContainerPort: 8080}}
	p.Spec.ServiceAccountName = "payments"
	p.Spec.NodeName = "worker-1"
	replicas := int32(3)
	maxRep := int32(5)
	minRep := int32(2)
	dep := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Name: "payments", Namespace: "prod",
			Annotations: map[string]string{"canary-token": "bearer " + egressCanary,
				// Names the Helm release whose Secret payload carries the
				// canary, so list_helm_releases reaches the label-only get.
				"meta.helm.sh/release-name": "payments", "meta.helm.sh/release-namespace": "prod"}},
		Spec: appsv1.DeploymentSpec{
			Replicas: &replicas,
			Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "payments"}},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"app": "payments"}},
				Spec:       p.Spec,
			},
		},
	}
	objs := []runtime.Object{
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "prod"}},
		// The node get_drain_impact is asked about; it lists the canary pod.
		&corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "worker-1"}},
		p,
		dep,
		&corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: "payments", Namespace: "prod"},
			Spec: corev1.ServiceSpec{Selector: map[string]string{"app": "payments"},
				Ports: []corev1.ServicePort{{Port: 80, TargetPort: intstr.FromString("http")}}}},
		&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "payments", Namespace: "prod"},
			Data: map[string]string{"DATABASE_URL": "postgres://app:" + egressCanary + "@db/payments"}},
		&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: "payments", Namespace: "prod"}},
		&rbacv1.Role{ObjectMeta: metav1.ObjectMeta{Name: "payments", Namespace: "prod"},
			Rules: []rbacv1.PolicyRule{{APIGroups: []string{""}, Resources: []string{"configmaps"}, Verbs: []string{"get"}}}},
		&rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "payments", Namespace: "prod"},
			RoleRef:  rbacv1.RoleRef{Kind: "Role", Name: "payments", APIGroup: "rbac.authorization.k8s.io"},
			Subjects: []rbacv1.Subject{{Kind: "ServiceAccount", Name: "payments", Namespace: "prod"}}},
		&networkingv1.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: "deny-all", Namespace: "prod"},
			Spec: networkingv1.NetworkPolicySpec{PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress}}},
		&autoscalingv2.HorizontalPodAutoscaler{ObjectMeta: metav1.ObjectMeta{Name: "payments", Namespace: "prod"},
			Spec: autoscalingv2.HorizontalPodAutoscalerSpec{MinReplicas: &minRep, MaxReplicas: maxRep,
				ScaleTargetRef: autoscalingv2.CrossVersionObjectReference{Kind: "Deployment", Name: "payments", APIVersion: "apps/v1"}}},
	}
	// A Helm release Secret whose payload carries the canary: the Helm
	// status tool must read its labels and never its data.
	helmSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "sh.helm.release.v1.payments.v1", Namespace: "prod",
			Labels: map[string]string{"owner": "helm", "name": "payments", "status": "deployed", "version": "1"}},
		Type: "helm.sh/release.v1",
		Data: map[string][]byte{"release": []byte("H4sI-" + egressCanary)},
	}
	if err := typed.Tracker().Add(helmSecret); err != nil {
		t.Fatal(err)
	}
	if fd, ok := typed.Discovery().(*fakediscovery.FakeDiscovery); ok {
		fd.FakedServerVersion = &version.Info{Major: "1", Minor: "36", GitVersion: "v1.36.2"}
	}
	attachObjectCache(t, exec, typed, nil, objs...)
}
