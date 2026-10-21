package objcache

import (
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	appsv1 "k8s.io/api/apps/v1"
	autoscalingv2 "k8s.io/api/autoscaling/v2"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	networkingv1 "k8s.io/api/networking/v1"
	policyv1 "k8s.io/api/policy/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	schedulingv1 "k8s.io/api/scheduling/v1"
	storagev1 "k8s.io/api/storage/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/tools/cache"
)

type typedKind struct {
	group, version, kind string
	informer             func(informers.SharedInformerFactory) cache.SharedIndexInformer
}

// typedKinds is every built-in kind the cluster-insight features read. All of
// them are in the argus-investigate ClusterRole
// (deploy/helm/argus-agent/templates/clusterrole.yaml); a kind RBAC narrows
// away resolves to StateForbidden and is simply not watched. Secrets are
// deliberately absent and must stay absent. Events are not cached either —
// their churn would dominate memory and get_events already reads them live.
var typedKinds = []typedKind{
	{"", "v1", "Pod", func(f informers.SharedInformerFactory) cache.SharedIndexInformer {
		return f.Core().V1().Pods().Informer()
	}},
	{"", "v1", "Service", func(f informers.SharedInformerFactory) cache.SharedIndexInformer {
		return f.Core().V1().Services().Informer()
	}},
	{"", "v1", "Endpoints", func(f informers.SharedInformerFactory) cache.SharedIndexInformer {
		return f.Core().V1().Endpoints().Informer()
	}},
	{"", "v1", "ConfigMap", func(f informers.SharedInformerFactory) cache.SharedIndexInformer {
		return f.Core().V1().ConfigMaps().Informer()
	}},
	{"", "v1", "PersistentVolumeClaim", func(f informers.SharedInformerFactory) cache.SharedIndexInformer {
		return f.Core().V1().PersistentVolumeClaims().Informer()
	}},
	{"", "v1", "PersistentVolume", func(f informers.SharedInformerFactory) cache.SharedIndexInformer {
		return f.Core().V1().PersistentVolumes().Informer()
	}},
	{"", "v1", "Node", func(f informers.SharedInformerFactory) cache.SharedIndexInformer {
		return f.Core().V1().Nodes().Informer()
	}},
	{"", "v1", "Namespace", func(f informers.SharedInformerFactory) cache.SharedIndexInformer {
		return f.Core().V1().Namespaces().Informer()
	}},
	{"", "v1", "ServiceAccount", func(f informers.SharedInformerFactory) cache.SharedIndexInformer {
		return f.Core().V1().ServiceAccounts().Informer()
	}},
	{"", "v1", "ResourceQuota", func(f informers.SharedInformerFactory) cache.SharedIndexInformer {
		return f.Core().V1().ResourceQuotas().Informer()
	}},
	{"", "v1", "LimitRange", func(f informers.SharedInformerFactory) cache.SharedIndexInformer {
		return f.Core().V1().LimitRanges().Informer()
	}},
	{"apps", "v1", "Deployment", func(f informers.SharedInformerFactory) cache.SharedIndexInformer {
		return f.Apps().V1().Deployments().Informer()
	}},
	{"apps", "v1", "ReplicaSet", func(f informers.SharedInformerFactory) cache.SharedIndexInformer {
		return f.Apps().V1().ReplicaSets().Informer()
	}},
	{"apps", "v1", "StatefulSet", func(f informers.SharedInformerFactory) cache.SharedIndexInformer {
		return f.Apps().V1().StatefulSets().Informer()
	}},
	{"apps", "v1", "DaemonSet", func(f informers.SharedInformerFactory) cache.SharedIndexInformer {
		return f.Apps().V1().DaemonSets().Informer()
	}},
	{"batch", "v1", "Job", func(f informers.SharedInformerFactory) cache.SharedIndexInformer {
		return f.Batch().V1().Jobs().Informer()
	}},
	{"batch", "v1", "CronJob", func(f informers.SharedInformerFactory) cache.SharedIndexInformer {
		return f.Batch().V1().CronJobs().Informer()
	}},
	{"networking.k8s.io", "v1", "Ingress", func(f informers.SharedInformerFactory) cache.SharedIndexInformer {
		return f.Networking().V1().Ingresses().Informer()
	}},
	{"networking.k8s.io", "v1", "IngressClass", func(f informers.SharedInformerFactory) cache.SharedIndexInformer {
		return f.Networking().V1().IngressClasses().Informer()
	}},
	{"networking.k8s.io", "v1", "NetworkPolicy", func(f informers.SharedInformerFactory) cache.SharedIndexInformer {
		return f.Networking().V1().NetworkPolicies().Informer()
	}},
	{"discovery.k8s.io", "v1", "EndpointSlice", func(f informers.SharedInformerFactory) cache.SharedIndexInformer {
		return f.Discovery().V1().EndpointSlices().Informer()
	}},
	{"autoscaling", "v2", "HorizontalPodAutoscaler", func(f informers.SharedInformerFactory) cache.SharedIndexInformer {
		return f.Autoscaling().V2().HorizontalPodAutoscalers().Informer()
	}},
	{"policy", "v1", "PodDisruptionBudget", func(f informers.SharedInformerFactory) cache.SharedIndexInformer {
		return f.Policy().V1().PodDisruptionBudgets().Informer()
	}},
	{"rbac.authorization.k8s.io", "v1", "Role", func(f informers.SharedInformerFactory) cache.SharedIndexInformer {
		return f.Rbac().V1().Roles().Informer()
	}},
	{"rbac.authorization.k8s.io", "v1", "ClusterRole", func(f informers.SharedInformerFactory) cache.SharedIndexInformer {
		return f.Rbac().V1().ClusterRoles().Informer()
	}},
	{"rbac.authorization.k8s.io", "v1", "RoleBinding", func(f informers.SharedInformerFactory) cache.SharedIndexInformer {
		return f.Rbac().V1().RoleBindings().Informer()
	}},
	{"rbac.authorization.k8s.io", "v1", "ClusterRoleBinding", func(f informers.SharedInformerFactory) cache.SharedIndexInformer {
		return f.Rbac().V1().ClusterRoleBindings().Informer()
	}},
	{"storage.k8s.io", "v1", "StorageClass", func(f informers.SharedInformerFactory) cache.SharedIndexInformer {
		return f.Storage().V1().StorageClasses().Informer()
	}},
	{"storage.k8s.io", "v1", "CSIDriver", func(f informers.SharedInformerFactory) cache.SharedIndexInformer {
		return f.Storage().V1().CSIDrivers().Informer()
	}},
	{"scheduling.k8s.io", "v1", "PriorityClass", func(f informers.SharedInformerFactory) cache.SharedIndexInformer {
		return f.Scheduling().V1().PriorityClasses().Informer()
	}},
	{"admissionregistration.k8s.io", "v1", "ValidatingWebhookConfiguration", func(f informers.SharedInformerFactory) cache.SharedIndexInformer {
		return f.Admissionregistration().V1().ValidatingWebhookConfigurations().Informer()
	}},
	{"admissionregistration.k8s.io", "v1", "MutatingWebhookConfiguration", func(f informers.SharedInformerFactory) cache.SharedIndexInformer {
		return f.Admissionregistration().V1().MutatingWebhookConfigurations().Informer()
	}},
}

type dynamicKind struct {
	group, kind string
	versions    []string
}

// dynamicKinds are CRD-backed kinds, watched only when the CRD is served and
// readable. Versions are a preference order.
var dynamicKinds = []dynamicKind{
	{"apiextensions.k8s.io", "CustomResourceDefinition", []string{"v1"}},
	{"apiregistration.k8s.io", "APIService", []string{"v1"}},
	{"argoproj.io", "Application", []string{"v1alpha1"}},
	{"argoproj.io", "ApplicationSet", []string{"v1alpha1"}},
	{"kustomize.toolkit.fluxcd.io", "Kustomization", []string{"v1", "v1beta2"}},
	{"helm.toolkit.fluxcd.io", "HelmRelease", []string{"v2", "v2beta2", "v2beta1"}},
	{"source.toolkit.fluxcd.io", "GitRepository", []string{"v1", "v1beta2"}},
	{"source.toolkit.fluxcd.io", "OCIRepository", []string{"v1", "v1beta2"}},
	{"source.toolkit.fluxcd.io", "HelmRepository", []string{"v1", "v1beta2"}},
	{"fleet.cattle.io", "GitRepo", []string{"v1alpha1"}},
	{"fleet.cattle.io", "Bundle", []string{"v1alpha1"}},
	{"cert-manager.io", "Certificate", []string{"v1"}},
	// CertificateRequest/Order/Challenge (PG5, 2026-10-13 parity review):
	// cert-manager's own renewal chain, read for the SAME reason Certificate
	// already is — public status, never a Secret.
	{"cert-manager.io", "CertificateRequest", []string{"v1"}},
	{"acme.cert-manager.io", "Order", []string{"v1"}},
	{"acme.cert-manager.io", "Challenge", []string{"v1"}},
	{"traefik.io", "IngressRoute", []string{"v1alpha1"}},
	{"traefik.io", "Middleware", []string{"v1alpha1"}},
	{"gateway.networking.k8s.io", "Gateway", []string{"v1", "v1beta1"}},
	{"gateway.networking.k8s.io", "HTTPRoute", []string{"v1", "v1beta1"}},
	{"gateway.networking.k8s.io", "GRPCRoute", []string{"v1", "v1alpha2"}},
	{"wgpolicyk8s.io", "PolicyReport", []string{"v1alpha2"}},
	{"wgpolicyk8s.io", "ClusterPolicyReport", []string{"v1alpha2"}},
	{"karpenter.sh", "NodePool", []string{"v1", "v1beta1"}},
	{"karpenter.sh", "NodeClaim", []string{"v1", "v1beta1"}},
	{"monitoring.coreos.com", "PrometheusRule", []string{"v1"}},
}

// TypedKinds and DynamicKinds return (group, kind) pairs, for a resolver
// that wants to pre-compute lookups.
func TypedKinds() [][2]string {
	out := make([][2]string, 0, len(typedKinds))
	for _, k := range typedKinds {
		out = append(out, [2]string{k.group, k.kind})
	}
	return out
}

// Accessors. Each returns *UnavailableError when the kind is not synced.

func (c *Cache) Pods(ns string) ([]*corev1.Pod, error) {
	return listTyped[*corev1.Pod](c, "", "Pod", ns)
}
func (c *Cache) Services(ns string) ([]*corev1.Service, error) {
	return listTyped[*corev1.Service](c, "", "Service", ns)
}
func (c *Cache) Endpoints(ns string) ([]*corev1.Endpoints, error) {
	return listTyped[*corev1.Endpoints](c, "", "Endpoints", ns)
}
func (c *Cache) ConfigMaps(ns string) ([]*corev1.ConfigMap, error) {
	return listTyped[*corev1.ConfigMap](c, "", "ConfigMap", ns)
}
func (c *Cache) PersistentVolumeClaims(ns string) ([]*corev1.PersistentVolumeClaim, error) {
	return listTyped[*corev1.PersistentVolumeClaim](c, "", "PersistentVolumeClaim", ns)
}
func (c *Cache) PersistentVolumes() ([]*corev1.PersistentVolume, error) {
	return listTyped[*corev1.PersistentVolume](c, "", "PersistentVolume", "")
}
func (c *Cache) Nodes() ([]*corev1.Node, error) { return listTyped[*corev1.Node](c, "", "Node", "") }
func (c *Cache) Namespaces() ([]*corev1.Namespace, error) {
	return listTyped[*corev1.Namespace](c, "", "Namespace", "")
}
func (c *Cache) ServiceAccounts(ns string) ([]*corev1.ServiceAccount, error) {
	return listTyped[*corev1.ServiceAccount](c, "", "ServiceAccount", ns)
}
func (c *Cache) ResourceQuotas(ns string) ([]*corev1.ResourceQuota, error) {
	return listTyped[*corev1.ResourceQuota](c, "", "ResourceQuota", ns)
}
func (c *Cache) LimitRanges(ns string) ([]*corev1.LimitRange, error) {
	return listTyped[*corev1.LimitRange](c, "", "LimitRange", ns)
}
func (c *Cache) Deployments(ns string) ([]*appsv1.Deployment, error) {
	return listTyped[*appsv1.Deployment](c, "apps", "Deployment", ns)
}
func (c *Cache) ReplicaSets(ns string) ([]*appsv1.ReplicaSet, error) {
	return listTyped[*appsv1.ReplicaSet](c, "apps", "ReplicaSet", ns)
}
func (c *Cache) StatefulSets(ns string) ([]*appsv1.StatefulSet, error) {
	return listTyped[*appsv1.StatefulSet](c, "apps", "StatefulSet", ns)
}
func (c *Cache) DaemonSets(ns string) ([]*appsv1.DaemonSet, error) {
	return listTyped[*appsv1.DaemonSet](c, "apps", "DaemonSet", ns)
}
func (c *Cache) Jobs(ns string) ([]*batchv1.Job, error) {
	return listTyped[*batchv1.Job](c, "batch", "Job", ns)
}
func (c *Cache) CronJobs(ns string) ([]*batchv1.CronJob, error) {
	return listTyped[*batchv1.CronJob](c, "batch", "CronJob", ns)
}
func (c *Cache) Ingresses(ns string) ([]*networkingv1.Ingress, error) {
	return listTyped[*networkingv1.Ingress](c, "networking.k8s.io", "Ingress", ns)
}
func (c *Cache) IngressClasses() ([]*networkingv1.IngressClass, error) {
	return listTyped[*networkingv1.IngressClass](c, "networking.k8s.io", "IngressClass", "")
}
func (c *Cache) NetworkPolicies(ns string) ([]*networkingv1.NetworkPolicy, error) {
	return listTyped[*networkingv1.NetworkPolicy](c, "networking.k8s.io", "NetworkPolicy", ns)
}
func (c *Cache) EndpointSlices(ns string) ([]*discoveryv1.EndpointSlice, error) {
	return listTyped[*discoveryv1.EndpointSlice](c, "discovery.k8s.io", "EndpointSlice", ns)
}
func (c *Cache) HorizontalPodAutoscalers(ns string) ([]*autoscalingv2.HorizontalPodAutoscaler, error) {
	return listTyped[*autoscalingv2.HorizontalPodAutoscaler](c, "autoscaling", "HorizontalPodAutoscaler", ns)
}
func (c *Cache) PodDisruptionBudgets(ns string) ([]*policyv1.PodDisruptionBudget, error) {
	return listTyped[*policyv1.PodDisruptionBudget](c, "policy", "PodDisruptionBudget", ns)
}
func (c *Cache) Roles(ns string) ([]*rbacv1.Role, error) {
	return listTyped[*rbacv1.Role](c, "rbac.authorization.k8s.io", "Role", ns)
}
func (c *Cache) ClusterRoles() ([]*rbacv1.ClusterRole, error) {
	return listTyped[*rbacv1.ClusterRole](c, "rbac.authorization.k8s.io", "ClusterRole", "")
}
func (c *Cache) RoleBindings(ns string) ([]*rbacv1.RoleBinding, error) {
	return listTyped[*rbacv1.RoleBinding](c, "rbac.authorization.k8s.io", "RoleBinding", ns)
}
func (c *Cache) ClusterRoleBindings() ([]*rbacv1.ClusterRoleBinding, error) {
	return listTyped[*rbacv1.ClusterRoleBinding](c, "rbac.authorization.k8s.io", "ClusterRoleBinding", "")
}
func (c *Cache) StorageClasses() ([]*storagev1.StorageClass, error) {
	return listTyped[*storagev1.StorageClass](c, "storage.k8s.io", "StorageClass", "")
}
func (c *Cache) CSIDrivers() ([]*storagev1.CSIDriver, error) {
	return listTyped[*storagev1.CSIDriver](c, "storage.k8s.io", "CSIDriver", "")
}
func (c *Cache) PriorityClasses() ([]*schedulingv1.PriorityClass, error) {
	return listTyped[*schedulingv1.PriorityClass](c, "scheduling.k8s.io", "PriorityClass", "")
}
func (c *Cache) ValidatingWebhookConfigurations() ([]*admissionregistrationv1.ValidatingWebhookConfiguration, error) {
	return listTyped[*admissionregistrationv1.ValidatingWebhookConfiguration](c, "admissionregistration.k8s.io", "ValidatingWebhookConfiguration", "")
}
func (c *Cache) MutatingWebhookConfigurations() ([]*admissionregistrationv1.MutatingWebhookConfiguration, error) {
	return listTyped[*admissionregistrationv1.MutatingWebhookConfiguration](c, "admissionregistration.k8s.io", "MutatingWebhookConfiguration", "")
}

// Pod returns one pod.
func (c *Cache) Pod(ns, name string) (*corev1.Pod, bool, error) {
	return getTyped[*corev1.Pod](c, "", "Pod", ns, name)
}

// Node returns one node.
func (c *Cache) Node(name string) (*corev1.Node, bool, error) {
	return getTyped[*corev1.Node](c, "", "Node", "", name)
}

// Get returns one cached object of any registered kind (typed or dynamic),
// for tools that take a kind/namespace/name triple.
func (c *Cache) Get(group, kind, ns, name string) (any, bool, error) {
	return getTyped[any](c, group, kind, ns, name)
}

// List returns every cached object of a kind as untyped values.
func (c *Cache) List(group, kind, ns string) ([]any, error) {
	return listTyped[any](c, group, kind, ns)
}

var _ = unstructured.Unstructured{}
