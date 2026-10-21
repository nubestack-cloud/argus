package agent

// Resolves BACKLOG.md's A3b: the two cross-object reference patterns this
// codebase has to construct and maintain itself, because Kubernetes does not
// (unlike OwnerReferences, which workload.go's resolveWorkloadFromOwnerRefs
// simply walks) —
//
//   - selector-based: a Service's spec.selector to the Pod(s) it targets.
//   - volume-reference-based: a Pod's
//     spec.volumes[*].persistentVolumeClaim.claimName to the
//     PersistentVolumeClaim it mounts.
//
// Both helpers below answer the SAME question in the end — "what workload,
// if any, does this OTHER object (found via a Service selector or a PVC's
// mounting Pods) belong to?" — by finding the matching Pod(s) and handing
// them to resolveWorkloadFromOwnerRefs, the exact same one-hop walk
// workload.go already uses for a Pod's OWN findings. That reuse is
// deliberate: it is already the cheap, already-tested, at-most-one-extra-GET
// resolution this package relies on elsewhere, so cross-object correlation
// costs nothing new past finding the right Pod(s) to hand it.
//
// # Why these live agent-side, not hub-side
//
// The hub only ever learns about a cluster's objects through Findings (and
// InventoryDelta's coarse cluster-wide facts, which carry no per-object
// detail) — it has no live Pod/Service/PVC listing to search. The agent
// already lists every kind these two checks need for its own detection
// (checkPVCPending lists PersistentVolumeClaims, checkServiceNoEndpoints
// lists Services/EndpointSlices), so resolving "which Pod does this PVC/
// Service relate to" is cheapest where the live objects already are —
// exactly A1/A3a's own precedent (the agent resolves raw identity; the hub
// only ever joins strings it's handed). See sweep_detector.go's
// checkPVCPending/checkServiceNoEndpoints for the call sites, and
// internal/gateway/finding.go's relatedWorkloadCorrelationKey for the hub
// side of that split.
//
// # Cost/scale
//
// Both helpers are called only for candidates ALREADY flagged as a problem
// (a Pending PVC past its threshold, a Service already lacking ready
// endpoints) — never for every PVC/Service in the cluster — and each does
// exactly one further List call, scoped to one namespace and (for the
// selector case) server-side label-filtered, so the added cost is bounded by
// "how many objects are currently broken", not by fleet size or a
// namespace×namespace cross product.

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/kubernetes"
)

// resolveRelatedWorkloadForPVC finds the Pod(s) in namespace that mount
// claimName via spec.volumes[*].persistentVolumeClaim.claimName, and resolves
// the owning workload of the first one (sorted by name, for determinism)
// exactly as resolveWorkloadFromOwnerRefs would for that Pod's own findings.
//
// Scoped to ONE namespace (a PersistentVolumeClaim is itself
// namespace-scoped and can only ever be mounted by a Pod in that same
// namespace), so this is one List call bounded by that namespace's Pod
// count — not a cluster-wide scan.
//
// Returns ok=false when no Pod in the namespace references this claim at
// all (the PVC's WaitForFirstConsumer binding is stuck before any Pod was
// ever created referencing it — a real case, see CAPABILITIES.md §5's
// "156 days Pending, no consuming pod ever" — and there is genuinely nothing
// to correlate against) or when the matching Pod itself resolves to no
// workload (a bare Pod referencing the PVC directly, with no controller).
// Either way this degrades to "no cross-object correlation for this
// Finding", never an error — the PVC's own object-level incident is
// unaffected either way.
func resolveRelatedWorkloadForPVC(ctx context.Context, clientset kubernetes.Interface, namespace, claimName string) (gvk, name string, ok bool) {
	pods, err := clientset.CoreV1().Pods(namespace).List(ctx, sweepListOptions)
	if err != nil {
		return "", "", false
	}

	// Deterministic choice among several matching Pods (e.g. a ReadWriteMany
	// PVC mounted by more than one Pod) — same pragmatic "pick one, don't
	// agonize" posture resolveWorkloadFromOwnerRefs itself takes with
	// refs[0]. The lowest name wins rather than whatever order the API server
	// returned, so which Pod gets picked doesn't silently depend on list
	// ordering. Picked by a single min scan over the list in place: Pod names
	// are unique within a namespace, so "lowest name" is a total order and
	// this selects exactly the Pod a sort-then-take-[0] would, without
	// copying every corev1.Pod in the namespace into a second slice first.
	var chosen *corev1.Pod
	for i := range pods.Items {
		p := &pods.Items[i]
		if !podMountsClaim(p, claimName) {
			continue
		}
		if chosen == nil || p.Name < chosen.Name {
			chosen = p
		}
	}
	if chosen == nil {
		return "", "", false
	}
	return resolveWorkloadFromOwnerRefs(ctx, clientset, namespace, chosen.GetOwnerReferences())
}

// podMountsClaim reports whether pod has a volume backed by a
// PersistentVolumeClaim named claimName.
func podMountsClaim(pod *corev1.Pod, claimName string) bool {
	for _, vol := range pod.Spec.Volumes {
		if vol.PersistentVolumeClaim != nil && vol.PersistentVolumeClaim.ClaimName == claimName {
			return true
		}
	}
	return false
}

// resolveRelatedWorkloadForSelector finds the Pod(s) in namespace matching
// selector (a Service's spec.selector), and resolves the owning workload of
// the first one (sorted by name, for determinism) exactly as
// resolveWorkloadFromOwnerRefs would for that Pod's own findings.
//
// The List call itself is server-side label-filtered (labels.SelectorFromSet
// (selector).String() as the ListOptions.LabelSelector), not a client-side
// scan of every Pod in the namespace followed by local matching — the API
// server does the selector evaluation, the same way kube-controller-manager's
// own endpoint controller does it. Scoped to one namespace (a Service's
// selector is itself namespace-scoped; it can never match a Pod in another
// namespace), so cost is bounded by that namespace's Pod count filtered
// server-side, not a cluster-wide or cross-namespace scan.
//
// Returns ok=false when selector is empty (checkServiceNoEndpoints already
// skips selector-less Services before calling this, but this function
// doesn't assume that of every future caller — an empty selector would
// otherwise list and "match" every Pod in the namespace, which is not what a
// missing selector means), when nothing matches (a genuine "selector matches
// zero Pods" misconfiguration — there's no Pod to correlate against, which
// is itself informative but not this function's job to say), or when the
// matching Pod resolves to no workload.
func resolveRelatedWorkloadForSelector(ctx context.Context, clientset kubernetes.Interface, namespace string, selector map[string]string) (gvk, name string, ok bool) {
	if len(selector) == 0 {
		return "", "", false
	}
	pods, err := clientset.CoreV1().Pods(namespace).List(ctx, sweepListOptionsFor(labels.SelectorFromSet(selector).String()))
	if err != nil {
		return "", "", false
	}
	if len(pods.Items) == 0 {
		return "", "", false
	}
	// Same lowest-name-wins rule (and same reasoning) as
	// resolveRelatedWorkloadForPVC above, by a min scan rather than sorting
	// the whole list to read one element off the front.
	chosen := &pods.Items[0]
	for i := range pods.Items {
		if pods.Items[i].Name < chosen.Name {
			chosen = &pods.Items[i]
		}
	}
	return resolveWorkloadFromOwnerRefs(ctx, clientset, namespace, chosen.GetOwnerReferences())
}

// relatedWorkloadDescription renders a short, human-readable "why" for a
// resolved related workload, used only in Finding messages so an operator
// reading the raw text (before any UI badge renders) already sees the link.
// Not load-bearing for correlation itself — that's RelatedWorkloadGVK/Name on
// the wire — just a readability aid.
func relatedWorkloadDescription(gvk, name string) string {
	if name == "" {
		return ""
	}
	return fmt.Sprintf(" (likely related to %s %s)", gvk, name)
}
