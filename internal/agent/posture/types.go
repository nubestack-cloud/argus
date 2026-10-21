// Package posture grades how a cluster is configured rather than whether it
// is failing: privileged containers, absent limits and probes, a lone
// replica with no disruption budget, an API about to be removed, a reference
// to something that does not exist. It reads typed objects the agent already
// holds and never calls the API server. A Finding is a risk, not an incident;
// it names a check in CheckRegistry, which carries the check's category,
// default severity, explanation, fix and framework labels.
package posture

import (
	appsv1 "k8s.io/api/apps/v1"
	autoscalingv2 "k8s.io/api/autoscaling/v2"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	policyv1 "k8s.io/api/policy/v1"

	"argus/internal/agent/certexpiry"
)

// CheckInput is everything one scan reads.
//
// A nil slice and an empty one mean different things. Empty is a listed kind
// with no objects; nil is a kind that was never listed (RBAC, a CRD that is
// not installed). A check whose inputs were not listed is skipped and the
// gap is reported in ScanResults.MissingInputs, so "could not look" never
// reads as "looked and found nothing".
//
// Secrets are absent by design: the agent does not list them. ConfigMap
// values reach this package already hashed ("sha256:<hex>"), so a check may
// read a ConfigMap's keys and metadata but never its data.
type CheckInput struct {
	Pods                     []*corev1.Pod
	Deployments              []*appsv1.Deployment
	ReplicaSets              []*appsv1.ReplicaSet
	StatefulSets             []*appsv1.StatefulSet
	DaemonSets               []*appsv1.DaemonSet
	Jobs                     []*batchv1.Job
	CronJobs                 []*batchv1.CronJob
	Services                 []*corev1.Service
	Ingresses                []*networkingv1.Ingress
	HorizontalPodAutoscalers []*autoscalingv2.HorizontalPodAutoscaler
	PodDisruptionBudgets     []*policyv1.PodDisruptionBudget
	ConfigMaps               []*corev1.ConfigMap
	LimitRanges              []*corev1.LimitRange
	PersistentVolumeClaims   []*corev1.PersistentVolumeClaim
	PersistentVolumes        []*corev1.PersistentVolume

	ServiceAccounts []*corev1.ServiceAccount
	// ServiceAccountsNamespace, when set, says ServiceAccounts covers that
	// one namespace only; a workload elsewhere cannot be judged against it.
	ServiceAccountsNamespace string

	// ClusterVersion ("1.30") and ServedAPIs (discovery group/versions such
	// as "batch/v1beta1") feed the deprecated-API check.
	ClusterVersion string
	ServedAPIs     []string

	// ConfigObjectRefs are ConfigMap and Secret names used by objects the
	// typed fields above do not cover (custom resources, Gateway routes).
	ConfigObjectRefs []ConfigObjectRef
	// ConfigReferenceEvidence widens what the unused-ConfigMap check may
	// conclude; without it no ConfigMap is ever called unused.
	ConfigReferenceEvidence *ConfigReferenceEvidence

	// GitOpsToolsPresent is true when at least one Argo CD Application, Flux
	// Kustomization or Flux HelmRelease exists. CRDs alone do not count —
	// they outlive an uninstall. The GitOps coverage checks run only when
	// this is set: on a cluster that does not do GitOps they would flag
	// every workload.
	GitOpsToolsPresent bool
	// ArgoAppNames holds every Argo CD Application name. Under Argo's label
	// tracking the only mark on a managed object is
	// app.kubernetes.io/instance, which Helm and kustomize also set, so that
	// label counts as GitOps only when it names one of these.
	ArgoAppNames map[string]struct{}

	// Certificates are cert-manager Certificates already graded by
	// certexpiry, so this tab and the Certificates tab share one meaning of
	// "close to expiry". Nil when cert-manager's CRD is not readable.
	Certificates []certexpiry.Cert

	// Traefik's checks run only when one of its CRDs is served; a cluster
	// without Traefik is "not applicable", not a missing input.
	TraefikCRDsPresent bool
	TraefikRoutes      []TraefikIngressRoute
	TraefikMiddlewares []TraefikMiddleware

	// Crossplane's readiness check runs only when its CRDs are present. A
	// claim or composite can be any kind a CompositeResourceDefinition
	// declares, so the agent would have to discover those kinds and be
	// granted read access to each before it could fill CrossplaneObjects;
	// that wiring does not exist yet, and the check is exercised by fixtures
	// alone.
	CrossplaneCRDsPresent bool
	CrossplaneObjects     []CrossplaneObject
}

// NamespacedRef is a namespace and name, with any defaulting already done.
type NamespacedRef struct {
	Namespace string
	Name      string
}

// TraefikIngressRoute is what the Traefik checks need from an IngressRoute:
// the Services and Middlewares its routes name, a reference without a
// namespace already resolved to the route's own.
type TraefikIngressRoute struct {
	Namespace   string
	Name        string
	Services    []NamespacedRef
	Middlewares []NamespacedRef
}

// TraefikMiddleware is what the Traefik checks need from a Middleware: the
// error-page Service of an "errors" middleware, or the members of a "chain".
type TraefikMiddleware struct {
	Namespace        string
	Name             string
	ErrorsService    *NamespacedRef
	ChainMiddlewares []NamespacedRef
}

// CrossplaneObject is a claim or composite resource and its Ready condition;
// Ready is nil when the object has not reported one.
type CrossplaneObject struct {
	Group     string
	Kind      string
	Namespace string
	Name      string
	Ready     *bool
	Message   string
}

// ConfigObjectRef names a ConfigMap or Secret something depends on.
type ConfigObjectRef struct {
	Kind      string
	Namespace string
	Name      string
}

// Finding is one check failing on one object. Group is empty for the core
// API group; it tells apart kinds that share a name across groups.
type Finding struct {
	Kind      string `json:"kind"`
	Group     string `json:"group,omitempty"`
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
	CheckID   string `json:"checkID"`
	Category  string `json:"category"`
	Severity  string `json:"severity"`
	Message   string `json:"message"`
	// Excepted: an argus.io/ignore-checks annotation on the object or its
	// namespace sets this check aside (exceptions.go).
	Excepted bool `json:"excepted,omitempty"`
}

// ScanResults is one scan's outcome.
type ScanResults struct {
	Summary  ScanSummary          `json:"summary"`
	Findings []Finding            `json:"findings"`
	Checks   map[string]CheckMeta `json:"checks"`
	// CheckCounts holds, per check that looked at anything, how many subjects
	// it looked at and how many passed. A check that could not run is absent
	// rather than shown as all-passing.
	CheckCounts map[string]CheckCount `json:"checkCounts,omitempty"`
	// EvaluatedByNamespace is the per-namespace detail behind CheckCounts
	// ("" for cluster-scoped subjects), kept so settings and exceptions can
	// recount without scanning again.
	EvaluatedByNamespace map[string]map[string]int `json:"evaluatedByNamespace,omitempty"`
	// MissingInputs names what this scan could not see, wholly or in part
	// ("poddisruptionbudgets", "configmap-references").
	MissingInputs []string `json:"missingInputs,omitempty"`
}

// CheckCount is one check's subjects looked at and passed. A subject is an
// object, so a check failing on two containers of one workload is one
// failure here, matching how findings merge.
type CheckCount struct {
	Evaluated int `json:"evaluated"`
	Passed    int `json:"passed"`
}

// ScanSummary totals a scan. Excepted findings are in none of the other
// counts.
type ScanSummary struct {
	Passing    int                        `json:"passing"`
	Warning    int                        `json:"warning"`
	Danger     int                        `json:"danger"`
	Excepted   int                        `json:"excepted,omitempty"`
	Categories map[string]CategorySummary `json:"categories"`
}

// CategorySummary totals one category.
type CategorySummary struct {
	Passing int `json:"passing"`
	Warning int `json:"warning"`
	Danger  int `json:"danger"`
}

// The three categories a check belongs to.
const (
	CategorySecurity    = "Security"
	CategoryReliability = "Reliability"
	CategoryEfficiency  = "Efficiency"
)

var categories = []string{CategorySecurity, CategoryReliability, CategoryEfficiency}

// The two severities a check emits. The catalogue's DefaultSeverity speaks
// the reported ladder instead: danger is shown as high, warning as medium.
const (
	SeverityWarning = "warning"
	SeverityDanger  = "danger"
)
