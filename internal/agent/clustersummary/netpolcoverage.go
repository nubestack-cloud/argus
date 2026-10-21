package clustersummary

import (
	"sort"

	appsv1 "k8s.io/api/apps/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
)

// NetworkPolicyCoverage reports how many workloads at least one core
// networking.k8s.io NetworkPolicy selects.
//
// This is a static evaluation of podSelector against each workload's pod
// template labels. It says nothing about what traffic is allowed — the CNI is
// the enforcement authority — and a CNI that does not implement NetworkPolicy
// enforces none of it. CNI-specific policy kinds (Cilium, Calico) use their
// own selector languages and are listed in NotEvaluated instead of being
// folded into the figure, so the figure never claims coverage it did not
// check.
type NetworkPolicyCoverage struct {
	Policies         int `json:"policies"`
	CoveredWorkloads int `json:"coveredWorkloads"`
	TotalWorkloads   int `json:"totalWorkloads"`
	// InvalidPolicies counts core policies whose podSelector did not parse;
	// they cover nothing here.
	InvalidPolicies int                    `json:"invalidPolicies,omitempty"`
	NotEvaluated    []NotEvaluatedPolicies `json:"notEvaluated,omitempty"`
}

// NotEvaluatedPolicies counts policy objects of one CNI-specific kind that
// exist on the cluster but are not part of the coverage figure.
type NotEvaluatedPolicies struct {
	Group string `json:"group"`
	Kind  string `json:"kind"`
	Count int    `json:"count"`
}

// CoverageInput is the set of listed objects the coverage is computed over.
type CoverageInput struct {
	Policies     []*networkingv1.NetworkPolicy
	Deployments  []*appsv1.Deployment
	StatefulSets []*appsv1.StatefulSet
	DaemonSets   []*appsv1.DaemonSet
	// CNIPolicies are CNI-specific policy objects (CiliumNetworkPolicy,
	// CiliumClusterwideNetworkPolicy, Calico NetworkPolicy/GlobalNetworkPolicy
	// and their staged variants). Only their kind and count are reported.
	CNIPolicies []*unstructured.Unstructured
}

type policySelector struct {
	namespace string
	selector  labels.Selector
}

type policyWorkload struct {
	namespace string
	labels    map[string]string
}

// ComputeNetworkPolicyCoverage evaluates every core NetworkPolicy's
// podSelector against every Deployment, StatefulSet and DaemonSet pod
// template in the same namespace. An empty podSelector selects every pod in
// its namespace, matching the API's semantics.
func ComputeNetworkPolicyCoverage(in CoverageInput) *NetworkPolicyCoverage {
	out := &NetworkPolicyCoverage{}

	selectors := make([]policySelector, 0, len(in.Policies))
	for _, np := range in.Policies {
		if np == nil {
			continue
		}
		out.Policies++
		sel, err := metav1.LabelSelectorAsSelector(&np.Spec.PodSelector)
		if err != nil {
			out.InvalidPolicies++
			continue
		}
		selectors = append(selectors, policySelector{namespace: np.Namespace, selector: sel})
	}

	workloads := make([]policyWorkload, 0, len(in.Deployments)+len(in.StatefulSets)+len(in.DaemonSets))
	for _, d := range in.Deployments {
		if d != nil {
			workloads = append(workloads, policyWorkload{namespace: d.Namespace, labels: d.Spec.Template.Labels})
		}
	}
	for _, s := range in.StatefulSets {
		if s != nil {
			workloads = append(workloads, policyWorkload{namespace: s.Namespace, labels: s.Spec.Template.Labels})
		}
	}
	for _, d := range in.DaemonSets {
		if d != nil {
			workloads = append(workloads, policyWorkload{namespace: d.Namespace, labels: d.Spec.Template.Labels})
		}
	}
	out.TotalWorkloads = len(workloads)

	for _, w := range workloads {
		set := labels.Set(w.labels)
		for _, p := range selectors {
			if p.namespace == w.namespace && p.selector.Matches(set) {
				out.CoveredWorkloads++
				break
			}
		}
	}

	out.NotEvaluated = countCNIPolicies(in.CNIPolicies)
	return out
}

func countCNIPolicies(objs []*unstructured.Unstructured) []NotEvaluatedPolicies {
	type key struct{ group, kind string }
	counts := make(map[key]int)
	for _, obj := range objs {
		if obj == nil {
			continue
		}
		gvk := obj.GroupVersionKind()
		if gvk.Kind == "" {
			continue
		}
		counts[key{gvk.Group, gvk.Kind}]++
	}
	if len(counts) == 0 {
		return nil
	}
	out := make([]NotEvaluatedPolicies, 0, len(counts))
	for k, n := range counts {
		out = append(out, NotEvaluatedPolicies{Group: k.group, Kind: k.kind, Count: n})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Group != out[j].Group {
			return out[i].Group < out[j].Group
		}
		return out[i].Kind < out[j].Kind
	})
	return out
}
