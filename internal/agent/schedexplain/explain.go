package schedexplain

import (
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
)

// Output caps. Examples bound the node names per reason group; groups and
// parsed clauses bound a pathological fleet (every node a distinct taint).
const (
	MaxExampleNodes = 50
	MaxNodeGroups   = 50
	MaxParsed       = 32
)

// Predicate names the per-node check that failed first.
const (
	PredicateUnschedulable = "unschedulable"
	PredicateTaint         = "taint"
	PredicateNodeAffinity  = "nodeAffinity"
	PredicateResources     = "resources"
	// PredicateNone: the node passed every check evaluated here; the blocker,
	// if any, is a predicate this package does not evaluate.
	PredicateNone = "none"
)

// Explanation is the answer to "why won't this pod schedule?".
type Explanation struct {
	Signature          string `json:"signature"`
	SimilarPendingPods int    `json:"similarPendingPods"`
	SchedulerMessage   string `json:"schedulerMessage,omitempty"`
	// SchedulerTotalNodes is the "M" of the scheduler's "N/M nodes are
	// available", 0 when the message has no such count.
	SchedulerTotalNodes int            `json:"schedulerTotalNodes,omitempty"`
	Parsed              []ParsedClause `json:"parsed"`
	// Nodes groups every observed node by the first predicate it fails, in
	// descending count order. Empty when no nodes were supplied — unknown,
	// not "no node blocks the pod".
	Nodes          []NodeGroup `json:"nodes"`
	NodesEvaluated int         `json:"nodesEvaluated"`
	// Unsatisfiable names label requirements no node satisfies at all.
	Unsatisfiable []string `json:"unsatisfiable,omitempty"`
	Verdict       string   `json:"verdict"`
	Truncated     bool     `json:"truncated,omitempty"`
	// AlreadyScheduled is set when the pod is bound to a node (spec.nodeName
	// set, or PodScheduled=True): whatever keeps it from running is not the
	// scheduler's doing, so no predicate is evaluated. NodeName is the node
	// it is bound to.
	AlreadyScheduled bool   `json:"alreadyScheduled,omitempty"`
	NodeName         string `json:"nodeName,omitempty"`
}

// ScheduledNode reports whether pod is already bound to a node, and which.
// PodScheduled=True without spec.nodeName (a binding the cache has not
// caught up with) counts as scheduled with an empty node name.
func ScheduledNode(pod *corev1.Pod) (string, bool) {
	if pod == nil {
		return "", false
	}
	if pod.Spec.NodeName != "" {
		return pod.Spec.NodeName, true
	}
	for _, c := range pod.Status.Conditions {
		if c.Type == corev1.PodScheduled && c.Status == corev1.ConditionTrue {
			return "", true
		}
	}
	return "", false
}

// alreadyScheduledVerdict is the verdict for a bound pod.
func alreadyScheduledVerdict(node string) string {
	if node == "" {
		return "Already scheduled; this is not a scheduling problem."
	}
	return fmt.Sprintf("Already scheduled to %s; this is not a scheduling problem.", node)
}

// ParsedClause is one classified clause of the scheduler's message.
type ParsedClause struct {
	Class     ReasonClass `json:"class"`
	NodeCount int         `json:"nodeCount,omitempty"`
	Detail    string      `json:"detail"`
}

// NodeGroup is the set of nodes failing for the same reason.
type NodeGroup struct {
	Predicate string   `json:"predicate"`
	Reason    string   `json:"reason"`
	Count     int      `json:"count"`
	Examples  []string `json:"examples"`
	Detail    string   `json:"detail,omitempty"`

	// resource fit bookkeeping for Detail
	resource corev1.ResourceName
	need     resource.Quantity
	mostFree *resource.Quantity
	// placement bookkeeping for Detail
	labelKey string
	values   map[string]int
	missing  int
}

// cordonTaint is the taint the node controller adds with spec.unschedulable;
// tolerating it (as DaemonSet pods do) is what lets a pod onto a cordoned node.
var cordonTaint = corev1.Taint{Key: corev1.TaintNodeUnschedulable, Effect: corev1.TaintEffectNoSchedule}

// Explain evaluates pod against every node and combines the result with the
// scheduler's own message. A pod that is already bound to a node is answered
// as such (AlreadyScheduled) without evaluating anything. For each node it reports the first failing
// predicate among: cordoned, untolerated NoSchedule/NoExecute taint,
// nodeSelector / required node affinity, insufficient resources (allocatable
// minus the requests of non-terminal pods bound to that node). scheduledPods
// may contain pods for any node; similarPending is the caller's count of
// pending pods sharing the pod's group fingerprint (see SimilarPending).
//
// This is a static evaluation from cached objects. Pod (anti-)affinity,
// topology spread, volume topology/binding, host ports and DRA are not
// evaluated here; the scheduler message is the authority for those.
func Explain(pod *corev1.Pod, nodes []*corev1.Node, scheduledPods []*corev1.Pod, schedulerMessage string, similarPending int) Explanation {
	out := Explanation{
		SimilarPendingPods: similarPending,
		SchedulerMessage:   schedulerMessage,
		Parsed:             []ParsedClause{},
		Nodes:              []NodeGroup{},
	}
	if pod == nil {
		out.Verdict = "no pod supplied"
		return out
	}
	out.Signature = Signature(pod)
	if node, ok := ScheduledNode(pod); ok {
		// A bound pod that is not running (ContainerCreating, a volume that
		// will not attach, an image that will not pull) is a kubelet-side
		// problem; evaluating predicates would blame the scheduler for it.
		out.AlreadyScheduled, out.NodeName = true, node
		out.SchedulerMessage = ""
		out.Verdict = alreadyScheduledVerdict(node)
		return out
	}

	total, reasons := ParseMessage(schedulerMessage)
	out.SchedulerTotalNodes = total
	for _, r := range reasons {
		if len(out.Parsed) >= MaxParsed {
			out.Truncated = true
			break
		}
		out.Parsed = append(out.Parsed, ParsedClause{Class: r.Class, NodeCount: r.NodeCount, Detail: r.Raw})
	}

	requests := PodRequests(pod)
	placement := placementOf(pod)
	used := usedByNode(scheduledPods)

	sorted := make([]*corev1.Node, 0, len(nodes))
	for _, n := range nodes {
		if n != nil {
			sorted = append(sorted, n)
		}
	}
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Name < sorted[j].Name })
	out.Unsatisfiable = placement.unsatisfiable(sorted)

	groups := map[string]*NodeGroup{}
	var order []string
	for _, node := range sorted {
		g := evaluateNode(pod, node, placement, requests, used[node.Name])
		key := g.Predicate + "\x00" + g.Reason
		existing, ok := groups[key]
		if !ok {
			existing = &NodeGroup{Predicate: g.Predicate, Reason: g.Reason, Examples: []string{}, resource: g.resource, need: g.need, labelKey: g.labelKey, values: map[string]int{}}
			groups[key] = existing
			order = append(order, key)
		}
		existing.Count++
		if len(existing.Examples) < MaxExampleNodes {
			existing.Examples = append(existing.Examples, node.Name)
		} else {
			out.Truncated = true
		}
		if g.mostFree != nil && (existing.mostFree == nil || g.mostFree.Cmp(*existing.mostFree) > 0) {
			q := g.mostFree.DeepCopy()
			existing.mostFree = &q
		}
		if g.labelKey != "" {
			if v, ok := node.Labels[g.labelKey]; ok {
				existing.values[v]++
			} else {
				existing.missing++
			}
		}
	}
	out.NodesEvaluated = len(sorted)

	for _, key := range order {
		g := groups[key]
		g.Detail = groupDetail(g)
		out.Nodes = append(out.Nodes, *g)
	}
	sort.SliceStable(out.Nodes, func(i, j int) bool {
		if out.Nodes[i].Count != out.Nodes[j].Count {
			return out.Nodes[i].Count > out.Nodes[j].Count
		}
		return out.Nodes[i].Reason < out.Nodes[j].Reason
	})
	if len(out.Nodes) > MaxNodeGroups {
		out.Nodes = out.Nodes[:MaxNodeGroups]
		out.Truncated = true
	}
	out.Verdict = verdict(out)
	return out
}

// evaluateNode returns the first failing predicate for one node.
func evaluateNode(pod *corev1.Pod, node *corev1.Node, place placement, requests, used corev1.ResourceList) NodeGroup {
	if node.Spec.Unschedulable && !tolerates(pod.Spec.Tolerations, cordonTaint) {
		return NodeGroup{Predicate: PredicateUnschedulable, Reason: "cordoned (spec.unschedulable)"}
	}
	taints := append([]corev1.Taint(nil), node.Spec.Taints...)
	sort.Slice(taints, func(i, j int) bool { return taints[i].ToString() < taints[j].ToString() })
	for _, t := range taints {
		if t.Effect != corev1.TaintEffectNoSchedule && t.Effect != corev1.TaintEffectNoExecute {
			continue
		}
		if !tolerates(pod.Spec.Tolerations, t) {
			return NodeGroup{Predicate: PredicateTaint, Reason: "untolerated taint " + t.ToString()}
		}
	}
	if reason, key := place.missOn(node); reason != "" {
		return NodeGroup{Predicate: PredicateNodeAffinity, Reason: reason, labelKey: key}
	}
	for _, name := range resourceOrder(requests) {
		need := requests[name]
		if need.Sign() <= 0 {
			continue
		}
		free := node.Status.Allocatable[name].DeepCopy()
		free.Sub(used[name])
		if need.Cmp(free) > 0 {
			return NodeGroup{Predicate: PredicateResources, Reason: "insufficient " + string(name), resource: name, need: need.DeepCopy(), mostFree: &free}
		}
	}
	return NodeGroup{Predicate: PredicateNone, Reason: "passes cordon, taint, affinity and resource checks"}
}

// resourceOrder checks cpu, memory and pods first (the common blockers, and
// a stable order for "first failing"), then everything else by name.
func resourceOrder(reqs corev1.ResourceList) []corev1.ResourceName {
	rank := map[corev1.ResourceName]int{corev1.ResourceCPU: 0, corev1.ResourceMemory: 1, corev1.ResourcePods: 2, corev1.ResourceEphemeralStorage: 3}
	names := make([]corev1.ResourceName, 0, len(reqs))
	for n := range reqs {
		names = append(names, n)
	}
	sort.Slice(names, func(i, j int) bool {
		ri, iok := rank[names[i]]
		rj, jok := rank[names[j]]
		switch {
		case iok && jok:
			return ri < rj
		case iok != jok:
			return iok
		}
		return names[i] < names[j]
	})
	return names
}

// usedByNode sums the requests of the non-terminal pods bound to each node.
// Terminating pods still hold their resources until they are gone.
func usedByNode(pods []*corev1.Pod) map[string]corev1.ResourceList {
	out := map[string]corev1.ResourceList{}
	for _, p := range pods {
		if p == nil || p.Spec.NodeName == "" || isTerminal(p) {
			continue
		}
		list, ok := out[p.Spec.NodeName]
		if !ok {
			list = corev1.ResourceList{}
			out[p.Spec.NodeName] = list
		}
		addResources(list, PodRequests(p))
	}
	return out
}

// tolerates mirrors the scheduler's toleration matching: an empty key with
// Exists matches every taint, an empty effect matches every effect, Equal
// (or omitted) compares values, Gt/Lt compare integers.
func tolerates(tolerations []corev1.Toleration, taint corev1.Taint) bool {
	for _, t := range tolerations {
		if t.Effect != "" && t.Effect != taint.Effect {
			continue
		}
		if t.Key != "" && t.Key != taint.Key {
			continue
		}
		switch t.Operator {
		case corev1.TolerationOpExists:
			return true
		case "", corev1.TolerationOpEqual:
			if t.Key != "" && t.Value == taint.Value {
				return true
			}
		case corev1.TolerationOpGt, corev1.TolerationOpLt:
			tv, err1 := strconv.ParseInt(t.Value, 10, 64)
			nv, err2 := strconv.ParseInt(taint.Value, 10, 64)
			if err1 == nil && err2 == nil && ((t.Operator == corev1.TolerationOpGt && nv > tv) || (t.Operator == corev1.TolerationOpLt && nv < tv)) {
				return true
			}
		}
	}
	return false
}

func groupDetail(g *NodeGroup) string {
	switch g.Predicate {
	case PredicateResources:
		most := "unknown"
		if g.mostFree != nil {
			most = formatQuantity(g.resource, *g.mostFree)
		}
		return fmt.Sprintf("needs %s, most free %s", formatQuantity(g.resource, g.need), most)
	case PredicateNodeAffinity:
		if g.labelKey == "" {
			return ""
		}
		vals := make([]string, 0, len(g.values))
		for v := range g.values {
			vals = append(vals, v)
		}
		sort.Strings(vals)
		var parts []string
		if len(vals) > 0 {
			if len(vals) > 10 {
				vals = append(vals[:10], "…")
			}
			parts = append(parts, fmt.Sprintf("these nodes have %s: [%s]", g.labelKey, strings.Join(vals, ", ")))
		}
		if g.missing > 0 {
			parts = append(parts, fmt.Sprintf("%d lack label %s", g.missing, g.labelKey))
		}
		return strings.Join(parts, "; ")
	}
	return ""
}

func verdict(e Explanation) string {
	if e.NodesEvaluated == 0 {
		return "No nodes were observed, so no per-node evaluation was possible; rely on the scheduler message."
	}
	passing := 0
	var blockers []string
	for _, g := range e.Nodes {
		if g.Predicate == PredicateNone {
			passing += g.Count
			continue
		}
		s := fmt.Sprintf("%d %s", g.Count, g.Reason)
		if g.Detail != "" {
			s += " (" + g.Detail + ")"
		}
		blockers = append(blockers, s)
	}
	var b strings.Builder
	if passing == 0 {
		fmt.Fprintf(&b, "0/%d nodes can run this pod: %s.", e.NodesEvaluated, strings.Join(blockers, "; "))
	} else {
		fmt.Fprintf(&b, "%d/%d nodes pass the cordon, taint, affinity and resource checks", passing, e.NodesEvaluated)
		if len(blockers) > 0 {
			fmt.Fprintf(&b, " (others: %s)", strings.Join(blockers, "; "))
		}
		b.WriteString("; the blocker is a predicate not evaluated here")
		if classes := unevaluatedClasses(e.Parsed); len(classes) > 0 {
			fmt.Fprintf(&b, " — the scheduler reports %s", strings.Join(classes, ", "))
		} else {
			b.WriteString(" (pod affinity/anti-affinity, topology spread, volumes, host ports), or capacity changed since the scheduler's last attempt")
		}
		b.WriteString(".")
	}
	if len(e.Unsatisfiable) > 0 {
		fmt.Fprintf(&b, " Unsatisfiable on every node: %s.", strings.Join(e.Unsatisfiable, "; "))
	}
	return b.String()
}

// unevaluatedClasses lists the scheduler-reported classes this package does
// not evaluate per node.
func unevaluatedClasses(parsed []ParsedClause) []string {
	seen := map[ReasonClass]bool{}
	var out []string
	for _, p := range parsed {
		switch p.Class {
		case PodAffinity, PodAntiAffinity, TopologySpread, VolumeNodeAffinity, VolumeBinding, VolumeCount, NoPorts, Other:
			if !seen[p.Class] {
				seen[p.Class] = true
				out = append(out, string(p.Class))
			}
		}
	}
	return out
}

// formatQuantity renders memory-like resources in binary units with one
// decimal ("2.1Gi"), cpu in cores or millicores, anything else as a count.
func formatQuantity(name corev1.ResourceName, q resource.Quantity) string {
	if q.Sign() < 0 {
		q = resource.Quantity{}
	}
	switch {
	case name == corev1.ResourceCPU:
		m := q.MilliValue()
		if m%1000 == 0 {
			return strconv.FormatInt(m/1000, 10)
		}
		return strconv.FormatInt(m, 10) + "m"
	case name == corev1.ResourceMemory || name == corev1.ResourceEphemeralStorage || strings.HasPrefix(string(name), corev1.ResourceHugePagesPrefix):
		return humanBytes(q.Value())
	default:
		return q.String()
	}
}

func humanBytes(v int64) string {
	units := []string{"", "Ki", "Mi", "Gi", "Ti", "Pi"}
	f := float64(v)
	i := 0
	for f >= 1024 && i < len(units)-1 {
		f /= 1024
		i++
	}
	if i == 0 {
		return strconv.FormatInt(v, 10)
	}
	if f == math.Trunc(f) {
		return strconv.FormatFloat(f, 'f', 0, 64) + units[i]
	}
	return strconv.FormatFloat(f, 'f', 1, 64) + units[i]
}

// Tolerates reports whether any of tolerations tolerates taint — exported for
// the Karpenter NodePool evaluation, which tests a pool's template taints the
// same way a node's are tested here.
func Tolerates(tolerations []corev1.Toleration, taint corev1.Taint) bool {
	return tolerates(tolerations, taint)
}
