package schedexplain

import (
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"

	corev1 "k8s.io/api/core/v1"
)

// The scheduler says "N node(s) didn't match Pod's node affinity/selector"
// and never which label. The code below checks the pod's nodeSelector and
// required nodeAffinity against the nodes' labels to name the requirement and
// what the nodes have instead — "no node has kubernetes.io/arch=arm64; 6 have
// kubernetes.io/arch: [amd64]".

// placement is a pod's label-based placement: a nodeSelector, every entry of
// which a node must match, and required nodeAffinity terms, any one of which
// it must match.
type placement struct {
	selector map[string]string
	terms    []corev1.NodeSelectorTerm
}

// placementOf reads a pod's placement. A term with neither expressions nor
// fields matches no node at all in Kubernetes, but gives nothing to explain,
// so it is left out.
func placementOf(pod *corev1.Pod) placement {
	p := placement{selector: pod.Spec.NodeSelector}
	if a := pod.Spec.Affinity; a != nil && a.NodeAffinity != nil && a.NodeAffinity.RequiredDuringSchedulingIgnoredDuringExecution != nil {
		for _, t := range a.NodeAffinity.RequiredDuringSchedulingIgnoredDuringExecution.NodeSelectorTerms {
			if len(t.MatchExpressions)+len(t.MatchFields) > 0 {
				p.terms = append(p.terms, t)
			}
		}
	}
	return p
}

// holds evaluates one requirement against a value and whether it is set.
// Gt and Lt compare integers, and fail on a value that is not one.
func holds(r corev1.NodeSelectorRequirement, value string, set bool) bool {
	switch r.Operator {
	case corev1.NodeSelectorOpIn:
		return set && slices.Contains(r.Values, value)
	case corev1.NodeSelectorOpNotIn:
		return !set || !slices.Contains(r.Values, value)
	case corev1.NodeSelectorOpExists:
		return set
	case corev1.NodeSelectorOpDoesNotExist:
		return !set
	case corev1.NodeSelectorOpGt, corev1.NodeSelectorOpLt:
		if !set || len(r.Values) == 0 {
			return false
		}
		have, err1 := strconv.ParseInt(value, 10, 64)
		bound, err2 := strconv.ParseInt(r.Values[0], 10, 64)
		if err1 != nil || err2 != nil {
			return false
		}
		return r.Operator == corev1.NodeSelectorOpGt && have > bound || r.Operator == corev1.NodeSelectorOpLt && have < bound
	}
	return false
}

func labelHolds(r corev1.NodeSelectorRequirement, n *corev1.Node) bool {
	v, set := n.Labels[r.Key]
	return holds(r, v, set)
}

// fieldHolds evaluates a matchFields requirement; metadata.name is the only
// field Kubernetes supports there (it is how DaemonSet pods are pinned), and
// any other matches nothing, as in the scheduler.
func fieldHolds(r corev1.NodeSelectorRequirement, n *corev1.Node) bool {
	return r.Key == "metadata.name" && holds(r, n.Name, true)
}

func termHolds(t corev1.NodeSelectorTerm, n *corev1.Node) bool {
	for _, r := range t.MatchExpressions {
		if !labelHolds(r, n) {
			return false
		}
	}
	for _, r := range t.MatchFields {
		if !fieldHolds(r, n) {
			return false
		}
	}
	return true
}

func (p placement) affinityHolds(n *corev1.Node) bool {
	return len(p.terms) == 0 || slices.ContainsFunc(p.terms, func(t corev1.NodeSelectorTerm) bool { return termHolds(t, n) })
}

// unsatisfiable names each label requirement that no node meets, with what
// the nodes carry instead. Empty means every requirement is met by some
// node, so whatever stops the pod is elsewhere: taints, resources, or no
// single node meeting all of them at once.
func (p placement) unsatisfiable(nodes []*corev1.Node) []string {
	var out []string
	for _, key := range slices.Sorted(maps.Keys(p.selector)) {
		want := p.selector[key]
		if !slices.ContainsFunc(nodes, func(n *corev1.Node) bool { v, ok := n.Labels[key]; return ok && v == want }) {
			out = append(out, missingLabel(key, "="+want, nodes))
		}
	}
	if len(p.terms) == 0 || slices.ContainsFunc(nodes, p.affinityHolds) {
		return out
	}
	var affinity []string
	for _, t := range p.terms {
		for _, r := range t.MatchExpressions {
			if slices.ContainsFunc(nodes, func(n *corev1.Node) bool { return labelHolds(r, n) }) {
				continue
			}
			if msg := missingRequirement(r, nodes); !slices.Contains(affinity, msg) {
				affinity = append(affinity, msg)
			}
		}
	}
	if len(affinity) == 0 {
		// Each requirement is met somewhere, but never all of one term on
		// the same node.
		affinity = []string{"no single node meets every requirement of any one required nodeAffinity term"}
	}
	return append(out, affinity...)
}

// carried is the sorted distinct values nodes have for key, and how many
// nodes have it at all.
func carried(nodes []*corev1.Node, key string) (values []string, nodesWithKey int) {
	for _, n := range nodes {
		if v, ok := n.Labels[key]; ok {
			nodesWithKey++
			if !slices.Contains(values, v) {
				values = append(values, v)
			}
		}
	}
	slices.Sort(values)
	return values, nodesWithKey
}

// missingLabel explains a nodeSelector entry no node matches; want is "=v".
func missingLabel(key, want string, nodes []*corev1.Node) string {
	values, n := carried(nodes, key)
	if n == 0 {
		return fmt.Sprintf("no node has a %s label at all (the pod needs %s%s)", key, key, want)
	}
	return fmt.Sprintf("no node has %s%s; %d have %s: [%s]", key, want, n, key, strings.Join(values, ", "))
}

// missingRequirement explains an affinity requirement no node meets.
func missingRequirement(r corev1.NodeSelectorRequirement, nodes []*corev1.Node) string {
	list := "[" + strings.Join(r.Values, ", ") + "]"
	switch r.Operator {
	case corev1.NodeSelectorOpIn:
		values, n := carried(nodes, r.Key)
		if n == 0 {
			return fmt.Sprintf("no node has a %s label at all (the pod needs %s in %s)", r.Key, r.Key, list)
		}
		return fmt.Sprintf("no node has %s in %s; nodes have %s: [%s]", r.Key, list, r.Key, strings.Join(values, ", "))
	case corev1.NodeSelectorOpExists:
		return fmt.Sprintf("no node has a %s label at all (the pod needs it to exist)", r.Key)
	case corev1.NodeSelectorOpDoesNotExist:
		return fmt.Sprintf("every node has a %s label (the pod needs it absent)", r.Key)
	case corev1.NodeSelectorOpNotIn:
		return fmt.Sprintf("every node has %s in %s (the pod needs a node outside it)", r.Key, list)
	}
	return fmt.Sprintf("no node meets nodeAffinity %s %s %s", r.Key, r.Operator, list)
}

// missOn says why node n fails the placement, or "" when it passes, with the
// label key at fault when there is one. That is the first unmatched
// nodeSelector key in sorted order, or else the first unmet requirement of
// the only affinity term; with several terms ORed together no one
// requirement is the reason.
func (p placement) missOn(n *corev1.Node) (reason, key string) {
	for _, k := range slices.Sorted(maps.Keys(p.selector)) {
		if v, ok := n.Labels[k]; !ok || v != p.selector[k] {
			return fmt.Sprintf("node selector %s=%s not matched", k, p.selector[k]), k
		}
	}
	if p.affinityHolds(n) {
		return "", ""
	}
	if len(p.terms) == 1 {
		for _, r := range p.terms[0].MatchExpressions {
			if !labelHolds(r, n) {
				return fmt.Sprintf("required node affinity %s %s [%s] not matched", r.Key, r.Operator, strings.Join(r.Values, ", ")), r.Key
			}
		}
		for _, r := range p.terms[0].MatchFields {
			if !fieldHolds(r, n) {
				return fmt.Sprintf("required node affinity field %s %s [%s] not matched", r.Key, r.Operator, strings.Join(r.Values, ", ")), ""
			}
		}
	}
	return "required node affinity: no term matched", ""
}
