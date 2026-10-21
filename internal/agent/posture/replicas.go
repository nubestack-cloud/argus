package posture

import (
	"fmt"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
)

// replicated is a Deployment or StatefulSet seen as what the replica checks
// need.
type replicated struct {
	at       subject
	replicas int32
	selector map[string]string
	spec     *corev1.PodSpec
}

func wanted(r *int32) int32 {
	if r == nil {
		return 1 // the API default
	}
	return *r
}

func matchLabels(sel *metav1.LabelSelector) map[string]string {
	if sel == nil {
		return nil
	}
	return sel.MatchLabels
}

func (in *CheckInput) replicated() []replicated {
	var out []replicated
	for _, d := range in.Deployments {
		out = append(out, replicated{object("Deployment", d.Namespace, d.Name), wanted(d.Spec.Replicas), matchLabels(d.Spec.Selector), &d.Spec.Template.Spec})
	}
	for _, st := range in.StatefulSets {
		out = append(out, replicated{object("StatefulSet", st.Namespace, st.Name), wanted(st.Spec.Replicas), matchLabels(st.Spec.Selector), &st.Spec.Template.Spec})
	}
	return out
}

// singleReplica flags Deployments set to one replica (or none). One a
// HorizontalPodAutoscaler scales is out of scope: the autoscaler, not the
// spec, decides its count.
func (s *scan) singleReplica() {
	scaled := map[subject]bool{}
	for _, h := range s.in.HorizontalPodAutoscalers {
		ref := h.Spec.ScaleTargetRef
		scaled[subject{kind: ref.Kind, namespace: h.Namespace, name: ref.Name}] = true
	}
	for _, d := range s.in.Deployments {
		if scaled[subject{kind: "Deployment", namespace: d.Namespace, name: d.Name}] {
			continue
		}
		s.evaluated(d.Namespace, "singleReplica")
		if n := wanted(d.Spec.Replicas); n <= 1 {
			s.flag(object("Deployment", d.Namespace, d.Name), "singleReplica", SeverityWarning,
				fmt.Sprintf("spec.replicas is %d, so there is no second replica to keep serving", n))
		}
	}
}

// disruptionBudgets flags multi-replica workloads no PodDisruptionBudget in
// their namespace selects. A budget is matched against the workload's
// selector labels, the labels every pod it owns must carry.
func (s *scan) disruptionBudgets() {
	type budget struct {
		namespace string
		selects   labels.Selector
	}
	var budgets []budget
	for _, pdb := range s.in.PodDisruptionBudgets {
		if pdb.Spec.Selector == nil {
			continue
		}
		if sel, err := metav1.LabelSelectorAsSelector(pdb.Spec.Selector); err == nil {
			budgets = append(budgets, budget{pdb.Namespace, sel})
		}
	}
	for _, w := range s.in.replicated() {
		if w.replicas <= 1 {
			continue
		}
		s.evaluated(w.at.namespace, "missingPDB")
		covered := false
		for _, b := range budgets {
			if b.namespace == w.at.namespace && b.selects.Matches(labels.Set(w.selector)) {
				covered = true
				break
			}
		}
		if !covered {
			s.flag(w.at, "missingPDB", SeverityWarning, fmt.Sprintf("%d replicas and no PodDisruptionBudget selecting them", w.replicas))
		}
	}
}

func (s *scan) topologySpread() {
	for _, w := range s.in.replicated() {
		if w.replicas <= 1 {
			continue
		}
		s.evaluated(w.at.namespace, "missingTopologySpread")
		if len(w.spec.TopologySpreadConstraints) == 0 {
			s.flag(w.at, "missingTopologySpread", SeverityWarning, fmt.Sprintf("%d replicas and no topology spread constraints", w.replicas))
		}
	}
}

// controllerIn returns obj's controller when it is the given apps kind.
func controllerIn(obj metav1.Object, kind string) *metav1.OwnerReference {
	ref := metav1.GetControllerOf(obj)
	if ref == nil || ref.Kind != kind || schema.FromAPIVersionAndKind(ref.APIVersion, ref.Kind).Group != "apps" {
		return nil
	}
	return ref
}

// colocatedReplicas flags a Deployment whose running pods, two or more, are
// all on one node. Pods are tied to their Deployment through the ReplicaSet
// by UID, so a stale or reused name never counts a stranger's pod. When a
// pod's ReplicaSet cannot be resolved in a namespace, that pod might belong
// to any Deployment there, so a Deployment not already seen on two nodes is
// left unjudged and the gap reported.
func (s *scan) colocatedReplicas() {
	sets := map[types.NamespacedName]*appsv1.ReplicaSet{}
	for _, rs := range s.in.ReplicaSets {
		sets[types.NamespacedName{Namespace: rs.Namespace, Name: rs.Name}] = rs
	}
	byUID := map[types.UID]*appsv1.Deployment{}
	for _, d := range s.in.Deployments {
		if d.UID != "" {
			byUID[d.UID] = d
		}
	}
	nodes := map[types.UID]map[string]int{} // deployment → node → running pods
	unresolved := map[string]bool{}         // namespaces with an unresolved pod
	for _, pod := range s.in.Pods {
		if pod.Status.Phase != corev1.PodRunning || pod.Spec.NodeName == "" || pod.DeletionTimestamp != nil {
			continue
		}
		ref := controllerIn(pod, "ReplicaSet")
		if ref == nil {
			continue
		}
		rs := sets[types.NamespacedName{Namespace: pod.Namespace, Name: ref.Name}]
		if ref.UID == "" || rs == nil || rs.UID != ref.UID {
			unresolved[pod.Namespace] = true
			continue
		}
		owner := controllerIn(rs, "Deployment")
		if owner == nil {
			continue
		}
		d := byUID[owner.UID]
		if d == nil || d.Name != owner.Name || d.Namespace != pod.Namespace {
			continue
		}
		if nodes[d.UID] == nil {
			nodes[d.UID] = map[string]int{}
		}
		nodes[d.UID][pod.Spec.NodeName]++
	}
	for _, d := range s.in.Deployments {
		if wanted(d.Spec.Replicas) <= 1 || d.UID == "" {
			continue
		}
		placed := nodes[d.UID]
		switch {
		case len(placed) >= 2:
			// Spread is proven; an unknown pod cannot undo it.
			s.evaluated(d.Namespace, "podHARisk")
			continue
		case unresolved[d.Namespace]:
			s.missing("replicaset-ownership")
			continue
		}
		for node, running := range placed {
			if running < 2 {
				break
			}
			s.evaluated(d.Namespace, "podHARisk")
			s.flag(object("Deployment", d.Namespace, d.Name), "podHARisk", SeverityWarning,
				fmt.Sprintf("all %d running pods are on node %s", running, node))
		}
	}
}

// rolloutRisk flags a rolling update allowed to take every replica down with
// no surge: maxSurge resolves to 0 and maxUnavailable to at least the
// replica count. Unset fields take the API defaults (25% each), which never
// do this; Recreate is full replacement on purpose and out of scope.
func (s *scan) rolloutRisk() {
	for _, d := range s.in.Deployments {
		n := wanted(d.Spec.Replicas)
		strategy := d.Spec.Strategy.Type
		if n < 2 || (strategy != "" && strategy != appsv1.RollingUpdateDeploymentStrategyType) {
			continue
		}
		s.evaluated(d.Namespace, "rolloutAvailabilityRisk")
		if msg, risky := rolloutDropsToZero(d.Spec.Strategy.RollingUpdate, n); risky {
			s.flag(object("Deployment", d.Namespace, d.Name), "rolloutAvailabilityRisk", SeverityWarning, msg)
		}
	}
}

// rolloutDropsToZero resolves the fenceposts as the Deployment controller
// does: surge rounds up, unavailability rounds down, and when both come to 0
// one pod may be unavailable after all.
func rolloutDropsToZero(ru *appsv1.RollingUpdateDeployment, replicas int32) (string, bool) {
	if ru == nil || ru.MaxSurge == nil || ru.MaxUnavailable == nil {
		return "", false
	}
	surge, err := intstr.GetScaledValueFromIntOrPercent(ru.MaxSurge, int(replicas), true)
	if err != nil {
		return "", false
	}
	down, err := intstr.GetScaledValueFromIntOrPercent(ru.MaxUnavailable, int(replicas), false)
	if err != nil {
		return "", false
	}
	if surge == 0 && down == 0 {
		down = 1
	}
	if surge != 0 || down < int(replicas) {
		return "", false
	}
	return fmt.Sprintf("maxUnavailable=%s with maxSurge=%s lets a rollout remove all %d old replicas before any new one is ready, so it can drop to zero available pods with nothing left to fall back on",
		ru.MaxUnavailable.String(), ru.MaxSurge.String(), replicas), true
}
