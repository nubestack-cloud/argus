package upgradeready

import (
	"cmp"
	"fmt"
	"slices"
	"strings"

	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
)

// drainable is a pod a node drain has to evict: running or about to,
// neither a mirror pod nor a DaemonSet's, which a drain leaves alone.
func drainable(p *corev1.Pod) bool {
	if p == nil || p.DeletionTimestamp != nil || p.Status.Phase == corev1.PodSucceeded || p.Status.Phase == corev1.PodFailed {
		return false
	}
	if p.Annotations[corev1.MirrorPodAnnotationKey] != "" {
		return false
	}
	ref := controllerOf(p)
	return ref == nil || ref.Kind != "DaemonSet"
}

func podReady(p *corev1.Pod) bool {
	i := slices.IndexFunc(p.Status.Conditions, func(c corev1.PodCondition) bool { return c.Type == corev1.PodReady })
	return i >= 0 && p.Status.Conditions[i].Status == corev1.ConditionTrue
}

// budgetState is what a PodDisruptionBudget's status says about evictions.
type budgetState int

const (
	budgetAllows budgetState = iota
	budgetBlocks
	budgetStale // the controller has not caught up; its numbers mean nothing yet
)

func stateOf(b *policyv1.PodDisruptionBudget) budgetState {
	st := b.Status
	switch {
	case b.DeletionTimestamp != nil:
		return budgetAllows
	case st.ObservedGeneration != b.Generation:
		return budgetStale
	case st.ExpectedPods > 0 && st.DisruptionsAllowed == 0 && st.CurrentHealthy >= st.ExpectedPods && st.DesiredHealthy >= st.ExpectedPods:
		return budgetBlocks
	}
	return budgetAllows
}

// covering is a budget and the drainable pods it selects.
type covering struct {
	budget *policyv1.PodDisruptionBudget
	pods   []*corev1.Pod
}

func (s *scan) drainFeasibility() Check {
	r := newReport("node-drain-feasibility", "Upgrade operations", "Node drain feasibility",
		"Live pods and PodDisruptionBudget configuration and status",
		"Nothing in the way of an ordinary node drain was found.").citing(docDrain)
	in := s.in
	if in.Pods == nil || in.PodDisruptionBudgets == nil {
		return r.unknown("Pods or PodDisruptionBudgets could not be read, so whether nodes can be drained is unknown.")
	}
	var pods []*corev1.Pod
	for _, p := range in.Pods {
		if drainable(p) {
			pods = append(pods, p)
		}
	}
	r.Inspected = len(pods)

	var covers []covering
	stale := 0
	for _, b := range in.PodDisruptionBudgets {
		// A budget being deleted may block for a moment, but reporting it
		// would turn a teardown into standing debt.
		if b == nil || b.DeletionTimestamp != nil {
			continue
		}
		sel, err := metav1.LabelSelectorAsSelector(b.Spec.Selector)
		if err != nil {
			stale++
			continue
		}
		c := covering{budget: b}
		healthy := 0
		for _, p := range pods {
			if p.Namespace == b.Namespace && sel.Matches(labels.Set(p.Labels)) {
				c.pods = append(c.pods, p)
				if podReady(p) {
					healthy++
				}
			}
		}
		if len(c.pods) == 0 {
			continue
		}
		// Overlap is judged on selectors alone, so even a stale budget
		// takes part in it.
		covers = append(covers, c)
		state := stateOf(b)
		if state == budgetStale {
			stale++
			continue
		}
		alwaysAllow := b.Spec.UnhealthyPodEvictionPolicy != nil && *b.Spec.UnhealthyPodEvictionPolicy == policyv1.AlwaysAllow
		if state != budgetBlocks && (b.Status.DisruptionsAllowed != 0 || (alwaysAllow && healthy == 0)) {
			continue
		}
		r.flag(LevelBlocker, "PodDisruptionBudget allows no evictions", budgetRef(b),
			live("status.disruptionsAllowed", fmt.Sprintf("0 across %d active pod(s)", len(c.pods))),
			"With the budget's status at zero disruptions allowed, an ordinary eviction-based drain cannot move these pods.",
			"Restore headroom, add replicas, or loosen minAvailable or maxUnavailable until at least one disruption is allowed, before draining.")
	}
	overlaps(r, covers)

	for _, p := range pods {
		if controllerOf(p) == nil {
			r.flag(LevelWarning, "Bare pod needs a forced drain", podRef(p.Namespace, p.Name), live("metadata.ownerReferences", "no controller owner"),
				"kubectl drain removes this pod only with --force, and nothing recreates it afterwards.",
				"Run it under a controller instead, or plan and approve a forced drain.")
		}
		var scratch []string
		for _, v := range p.Spec.Volumes {
			if v.EmptyDir != nil {
				scratch = append(scratch, v.Name)
			}
		}
		if len(scratch) > 0 {
			slices.Sort(scratch)
			r.flag(LevelReview, "Pod keeps node-local emptyDir data", podRef(p.Namespace, p.Name), live("spec.volumes[].emptyDir", strings.Join(scratch, ", ")),
				"kubectl drain needs --delete-emptydir-data for this pod, and the data is lost.",
				"Confirm the data can be thrown away, or move it to persistent storage, before draining.")
		}
	}
	if stale > 0 {
		r.caveat(fmt.Sprintf("%s stale or unreadable status.", count(stale, "PodDisruptionBudget has", "PodDisruptionBudgets have")))
	}
	return r.finish(func(n int) string {
		return count(n, "drain condition needs", "drain conditions need") + " action or an operator's decision."
	},
		"No drain risk was found, but not every PodDisruptionBudget could be judged.")
}

func budgetRef(b *policyv1.PodDisruptionBudget) *ResourceRef {
	return &ResourceRef{Group: "policy", Kind: "PodDisruptionBudget", Namespace: b.Namespace, Name: b.Name}
}

// overlaps flags each pair of budgets in one namespace selecting the same
// pods: the Eviction API refuses to evict a pod more than one budget covers.
func overlaps(r *report, covers []covering) {
	slices.SortFunc(covers, func(a, b covering) int {
		return cmp.Or(cmp.Compare(a.budget.Namespace, b.budget.Namespace), cmp.Compare(a.budget.Name, b.budget.Name))
	})
	for i, a := range covers {
		names := map[string]bool{}
		for _, p := range a.pods {
			names[p.Namespace+"/"+p.Name] = true
		}
		for _, b := range covers[i+1:] {
			if a.budget.Namespace != b.budget.Namespace {
				continue
			}
			var shared []string
			for _, p := range b.pods {
				if k := p.Namespace + "/" + p.Name; names[k] {
					shared = append(shared, k)
				}
			}
			if len(shared) == 0 {
				continue
			}
			slices.Sort(shared)
			r.flag(LevelBlocker, "Pod selected by more than one PodDisruptionBudget", budgetRef(a.budget),
				live("spec.selector", fmt.Sprintf("also overlaps %s/%s across %d active pod(s), including Pod %s", b.budget.Namespace, b.budget.Name, len(shared), shared[0])),
				"The Eviction API refuses to evict a pod more than one budget selects, so an ordinary drain stops on it.",
				"Narrow or remove one of the selectors so each pod has one budget, or finish the budget change in progress, before draining.")
		}
	}
}
