// Package topology builds a bounded relationship graph around one Kubernetes
// object — what owns it, what sends it traffic, what it uses and what protects
// it — from the agent's cached objects. It is pure: the builder reads typed
// object lists through ResourceProvider (and, optionally, Gateway API routes
// through DynamicProvider) and returns nodes and typed edges. Nothing here talks
// to the API server.
//
// Secrets are deliberately absent: there is no Secret list on the provider and
// no Secret node kind, so a Secret's name, keys or existence can never reach a
// graph. Node summaries are a curated, per-kind set of status counters; spec,
// env, annotations and ConfigMap data never enter a node.
package topology

import (
	"errors"

	appsv1 "k8s.io/api/apps/v1"
	autoscalingv2 "k8s.io/api/autoscaling/v2"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	policyv1 "k8s.io/api/policy/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"argus/internal/agent/health"
)

// NodeKind is the kind of a graph node. It is the Kubernetes kind, except for
// PodGroup, which stands for several pods collapsed into one node.
type NodeKind string

const (
	// Workloads, and the pods they run.
	KindDeployment  NodeKind = "Deployment"
	KindStatefulSet NodeKind = "StatefulSet"
	KindDaemonSet   NodeKind = "DaemonSet"
	KindReplicaSet  NodeKind = "ReplicaSet"
	KindCronJob     NodeKind = "CronJob"
	KindJob         NodeKind = "Job"
	KindPod         NodeKind = "Pod"
	KindPodGroup    NodeKind = "PodGroup"

	// Where traffic enters and how it is routed. The four route kinds are
	// Gateway API; see gatewayRouteKinds.
	KindService   NodeKind = "Service"
	KindIngress   NodeKind = "Ingress"
	KindGateway   NodeKind = "Gateway"
	KindHTTPRoute NodeKind = "HTTPRoute"
	KindGRPCRoute NodeKind = "GRPCRoute"
	KindTLSRoute  NodeKind = "TLSRoute"
	KindTCPRoute  NodeKind = "TCPRoute"

	// What a workload is configured by, stores into, and is scaled or
	// protected by.
	KindConfigMap      NodeKind = "ConfigMap"
	KindServiceAccount NodeKind = "ServiceAccount"
	KindPVC            NodeKind = "PersistentVolumeClaim"
	KindPV             NodeKind = "PersistentVolume"
	KindHPA            NodeKind = "HorizontalPodAutoscaler"
	KindPDB            NodeKind = "PodDisruptionBudget"
	KindNetworkPolicy  NodeKind = "NetworkPolicy"

	// The machine a pod is scheduled on.
	KindNode NodeKind = "Node"
)

// GatewayAPIGroup is the API group of the Gateway API kinds the builder reads
// through DynamicProvider.
const GatewayAPIGroup = "gateway.networking.k8s.io"

// gatewayRouteKinds are the Gateway API route kinds the builder links
// Gateway → route → Service through.
var gatewayRouteKinds = []NodeKind{KindHTTPRoute, KindGRPCRoute, KindTCPRoute, KindTLSRoute}

// HealthStatus is a node's health. The values are internal/agent/health's
// levels, taken from there so the two vocabularies cannot drift apart.
type HealthStatus string

const (
	StatusHealthy   = HealthStatus(health.LevelHealthy)
	StatusDegraded  = HealthStatus(health.LevelDegraded)
	StatusUnhealthy = HealthStatus(health.LevelUnhealthy)
	// StatusNeutral is intentional or idle — suspended, scaled to zero,
	// completed — and is not StatusUnknown, "cannot tell".
	StatusNeutral = HealthStatus(health.LevelNeutral)
	StatusUnknown = HealthStatus(health.LevelUnknown)
)

// EdgeType is the kind of relationship an edge records. Source and target
// follow the direction of control or flow:
//
//	owns        controller → what it created (Deployment → Pod, CronJob → Job)
//	routes-to   traffic entry → next hop (Ingress → Service, Gateway → HTTPRoute)
//	exposes     Service → the workload or pods it selects
//	uses        a resource → its consumer (PVC → workload, PV → PVC,
//	            Node → Pod), and HPA → the workload it scales
//	configures  ConfigMap / ServiceAccount → the workload that mounts or runs as it
//	protects    PodDisruptionBudget / NetworkPolicy → the workload it selects
type EdgeType string

const (
	EdgeOwns       EdgeType = "owns"
	EdgeRoutesTo   EdgeType = "routes-to"
	EdgeExposes    EdgeType = "exposes"
	EdgeUses       EdgeType = "uses"
	EdgeConfigures EdgeType = "configures"
	EdgeProtects   EdgeType = "protects"
)

// Node is one object (or, for KindPodGroup, one collapsed set of pods) in the
// graph. Summary holds only the curated status counters for its kind.
type Node struct {
	ID           string            `json:"id"`
	Kind         NodeKind          `json:"kind"`
	APIGroup     string            `json:"apiGroup,omitempty"`
	Namespace    string            `json:"namespace,omitempty"`
	Name         string            `json:"name"`
	Status       HealthStatus      `json:"status"`
	StatusReason string            `json:"statusReason,omitempty"`
	Labels       map[string]string `json:"labels,omitempty"`
	Summary      map[string]any    `json:"summary,omitempty"`
}

// Edge is a typed, directed relationship between two nodes.
type Edge struct {
	ID string `json:"id"`
	// Source is the controlling or upstream end (see EdgeType), Target the
	// end it controls, feeds or protects; both are Node IDs.
	Source string   `json:"source"`
	Target string   `json:"target"`
	Type   EdgeType `json:"type"`
}

// Topology is the full graph the builder produced for a namespace set. It is
// an intermediate: callers normally want Neighborhood's bounded Subgraph.
type Topology struct {
	Nodes []Node `json:"nodes"`
	Edges []Edge `json:"edges"`
	// Unavailable names the kinds whose list failed (forbidden, not synced),
	// so a caller can say the graph is partial instead of implying absence.
	Unavailable []string `json:"unavailable,omitempty"`
}

// Ref identifies one object. APIGroup is "" for the core group; for a
// built-in kind an empty APIGroup also means "the built-in group".
type Ref struct {
	Kind      string `json:"kind"`
	APIGroup  string `json:"apiGroup,omitempty"`
	Namespace string `json:"namespace,omitempty"`
	Name      string `json:"name"`
}

// BuildOptions configures a topology build.
type BuildOptions struct {
	// Namespaces limits the build. nil means every namespace; an explicit
	// empty slice matches nothing.
	Namespaces []string
	// MaxIndividualPods is the group size above which pods sharing a group
	// key collapse into one PodGroup node (default 5).
	MaxIndividualPods int
	// GroupPodsByOwner groups pods by their controller owner rather than by
	// app label (see podGroupOf), so each workload gets its own
	// pod group. The namespace map sets it; the neighbourhood does not.
	GroupPodsByOwner bool
	// IncludeReplicaSets shows every active ReplicaSet. When false, a
	// ReplicaSet owned by a Deployment in the graph is hidden and its pods
	// hang off the Deployment directly; a ReplicaSet without such an owner is
	// always shown, so a pod's owner chain is never cut.
	IncludeReplicaSets bool
	// Focus is always drawn as its own node when it exists: a Pod is kept out
	// of any PodGroup, and a ConfigMap / ServiceAccount / PVC / PV / Node is
	// drawn even when no workload in the graph references it. It is how a
	// neighbourhood root is guaranteed a node. Zero value = no focus.
	Focus Ref
}

// isFocus reports whether (kind, namespace, name) is the build's focus.
func (o BuildOptions) isFocus(kind NodeKind, namespace, name string) bool {
	if o.Focus.Name == "" || o.Focus.Name != name || o.Focus.Namespace != namespace {
		return false
	}
	k, ok := normalizeKind(o.Focus.Kind)
	return ok && k == kind
}

func (o BuildOptions) matchesNamespace(ns string) bool {
	if o.Namespaces == nil {
		return true
	}
	for _, n := range o.Namespaces {
		if n == ns {
			return true
		}
	}
	return false
}

// ResourceProvider is the builder's read-only view of the cluster. Each list
// takes a namespace ("" = all namespaces); cluster-scoped lists (Nodes,
// PersistentVolumes) are called with "". An error marks that kind unavailable
// for this build — the graph is built from the rest.
type ResourceProvider interface {
	Pods(ns string) ([]*corev1.Pod, error)
	Services(ns string) ([]*corev1.Service, error)
	Deployments(ns string) ([]*appsv1.Deployment, error)
	DaemonSets(ns string) ([]*appsv1.DaemonSet, error)
	StatefulSets(ns string) ([]*appsv1.StatefulSet, error)
	ReplicaSets(ns string) ([]*appsv1.ReplicaSet, error)
	Jobs(ns string) ([]*batchv1.Job, error)
	CronJobs(ns string) ([]*batchv1.CronJob, error)
	Ingresses(ns string) ([]*networkingv1.Ingress, error)
	ConfigMaps(ns string) ([]*corev1.ConfigMap, error)
	PersistentVolumeClaims(ns string) ([]*corev1.PersistentVolumeClaim, error)
	PersistentVolumes(ns string) ([]*corev1.PersistentVolume, error)
	HorizontalPodAutoscalers(ns string) ([]*autoscalingv2.HorizontalPodAutoscaler, error)
	PodDisruptionBudgets(ns string) ([]*policyv1.PodDisruptionBudget, error)
	NetworkPolicies(ns string) ([]*networkingv1.NetworkPolicy, error)
	Nodes(ns string) ([]*corev1.Node, error)
	ServiceAccounts(ns string) ([]*corev1.ServiceAccount, error)
}

// DynamicProvider lists custom-resource kinds by group and kind, leaving the
// served version to the implementation. The builder uses it only for the
// Gateway API (Gateway, HTTPRoute, GRPCRoute, TCPRoute, TLSRoute). It may be
// nil.
type DynamicProvider interface {
	// List returns the objects of gk in ns ("" = all). It returns
	// ErrNotServed when the cluster does not serve (or the agent does not
	// watch) the kind, which the builder treats as "no such objects" rather
	// than as an incomplete graph.
	List(gk schema.GroupKind, ns string) ([]*unstructured.Unstructured, error)
}

// ErrNotServed is returned by DynamicProvider.List for a kind the cluster does
// not serve.
var ErrNotServed = errors.New("kind not served")

// builtinGroups maps each built-in node kind to its API group ("" = core).
var builtinGroups = map[NodeKind]string{
	KindPod:            "",
	KindDeployment:     "apps",
	KindReplicaSet:     "apps",
	KindStatefulSet:    "apps",
	KindDaemonSet:      "apps",
	KindJob:            "batch",
	KindCronJob:        "batch",
	KindService:        "",
	KindIngress:        "networking.k8s.io",
	KindConfigMap:      "",
	KindServiceAccount: "",
	KindPVC:            "",
	KindPV:             "",
	KindHPA:            "autoscaling",
	KindPDB:            "policy",
	KindNetworkPolicy:  "networking.k8s.io",
	KindNode:           "",
	KindGateway:        GatewayAPIGroup,
	KindHTTPRoute:      GatewayAPIGroup,
	KindGRPCRoute:      GatewayAPIGroup,
	KindTCPRoute:       GatewayAPIGroup,
	KindTLSRoute:       GatewayAPIGroup,
}

// clusterScopedKinds are the node kinds that have no namespace.
var clusterScopedKinds = map[NodeKind]bool{KindNode: true, KindPV: true}
