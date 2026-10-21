// Package schedexplain answers "why won't this pod schedule?" from the
// scheduler's own message plus a static per-node evaluation of the
// predicates that can be checked from cached objects (cordon, taints, node
// selector/affinity, resource fit). It is pure: callers pass typed objects.
package schedexplain

import (
	"regexp"
	"strconv"
	"strings"
)

// ReasonClass classifies one clause of a FailedScheduling message.
type ReasonClass string

// What a node lacks, or the state it is in.
const (
	InsufficientResource ReasonClass = "InsufficientResource"
	NoPorts              ReasonClass = "NoPorts"
	NodeUnschedulable    ReasonClass = "NodeUnschedulable"
	UntoleratedTaint     ReasonClass = "UntoleratedTaint"
)

// What the pod's placement rules exclude.
const (
	NodeAffinitySelector ReasonClass = "NodeAffinitySelector"
	PodAffinity          ReasonClass = "PodAffinity"
	PodAntiAffinity      ReasonClass = "PodAntiAffinity"
	TopologySpread       ReasonClass = "TopologySpread"
)

// What the pod's volumes need.
const (
	VolumeBinding      ReasonClass = "VolumeBinding"
	VolumeCount        ReasonClass = "VolumeCount"
	VolumeNodeAffinity ReasonClass = "VolumeNodeAffinity"
)

// Other is a clause none of the above describes; its text is kept.
const Other ReasonClass = "Other"

// Reason is one classified clause, e.g. "3 Insufficient memory". NodeCount
// is the scheduler's own count for the clause (0 when it gave none).
type Reason struct {
	Class      ReasonClass `json:"class"`
	NodeCount  int         `json:"nodeCount,omitempty"`
	Resource   string      `json:"resource,omitempty"`
	TaintKey   string      `json:"taintKey,omitempty"`
	TaintValue string      `json:"taintValue,omitempty"`
	Raw        string      `json:"raw"`
}

var (
	// "0/5 nodes are available" — the second number is the cluster's node count.
	availableRE = regexp.MustCompile(`\d+/(\d+)\s+nodes? (?:are|is) available`)
	// A clause that starts with the number of nodes it applies to.
	countRE = regexp.MustCompile(`^(\d+)\s`)
	// "Insufficient nvidia.com/gpu" names the resource.
	resourceRE = regexp.MustCompile(`Insufficient\s+([\w./-]+)`)
	// "{dedicated: gpu}" is the taint an untolerated-taint clause names.
	taintRE = regexp.MustCompile(`\{([^}]*)\}`)
)

// ParseMessage reads a FailedScheduling event or PodScheduled=False message —
// "0/5 nodes are available: 2 Insufficient cpu, 3 node(s) had untolerated
// taint {dedicated: gpu}. preemption: ..." — into the cluster's node count
// and one Reason per clause. The preemption tail goes: it repeats the same
// verdict from the preemption plugin's side and would count nodes twice.
func ParseMessage(message string) (totalNodes int, reasons []Reason) {
	message = strings.TrimSpace(message)
	for _, tail := range []string{". preemption:", " preemption:"} {
		if i := strings.Index(message, tail); i >= 0 {
			message = message[:i]
			break
		}
	}
	if m := availableRE.FindStringSubmatch(message); m != nil {
		totalNodes, _ = strconv.Atoi(m[1])
	}
	if _, after, found := strings.Cut(message, ":"); found {
		message = after
	}
	for _, clause := range strings.Split(strings.TrimRight(strings.TrimSpace(message), "."), ", ") {
		if r, ok := classifyClause(clause); ok {
			reasons = append(reasons, r)
		}
	}
	return totalNodes, reasons
}

// tidy trims a clause of surrounding space and trailing commas and full stops.
func tidy(clause string) string {
	return strings.TrimSpace(strings.TrimRight(strings.TrimSpace(clause), ",."))
}

// taintIn reads the "{key: value}" an untolerated-taint clause names.
func taintIn(clause string) (key, value string) {
	m := taintRE.FindStringSubmatch(clause)
	if m == nil {
		return "", ""
	}
	key, value, _ = strings.Cut(m[1], ":")
	return strings.TrimSpace(key), strings.TrimSpace(value)
}

// lifecycleTaint is a taint Kubernetes manages to describe a node's own state
// — not ready, unreachable, cordoned, a control-plane node, a cloud node not
// yet initialised. A clause naming one is NodeUnschedulable, not a taint an
// operator placed.
func lifecycleTaint(key string) bool {
	for _, prefix := range []string{"node.kubernetes.io/", "node-role.kubernetes.io/", "node.cloudprovider.kubernetes.io/"} {
		if strings.HasPrefix(key, prefix) {
			return true
		}
	}
	return false
}

// clauseRules classify a clause, first match winning. Each test sees the
// clause as written and lowercased; "Insufficient" is matched as the
// scheduler capitalises it. Order matters where wordings overlap: volume node
// affinity before node affinity, anti-affinity before pod affinity, and a
// clause naming a lifecycle taint is reclassified below.
var clauseRules = []struct {
	class ReasonClass
	is    func(clause, lower string) bool
}{
	{InsufficientResource, func(c, _ string) bool { return strings.Contains(c, "Insufficient") }},
	{InsufficientResource, func(_, l string) bool { return strings.Contains(l, "too many pods") }},
	{UntoleratedTaint, func(_, l string) bool { return strings.Contains(l, "untolerated taint") }},
	{VolumeNodeAffinity, func(_, l string) bool { return strings.Contains(l, "volume node affinity") }},
	{PodAntiAffinity, func(_, l string) bool { return strings.Contains(l, "anti-affinity") }},
	{NodeAffinitySelector, func(_, l string) bool {
		return strings.Contains(l, "node affinity") || strings.Contains(l, "node selector")
	}},
	{PodAffinity, func(_, l string) bool { return strings.Contains(l, "pod affinity") }},
	{TopologySpread, func(_, l string) bool { return strings.Contains(l, "topology spread") }},
	{VolumeCount, func(_, l string) bool { return strings.Contains(l, "max volume count") }},
	{NoPorts, func(_, l string) bool { return strings.Contains(l, "free ports") }},
	{VolumeBinding, func(_, l string) bool {
		return strings.Contains(l, "unbound") && strings.Contains(l, "persistentvolumeclaim") || strings.Contains(l, "persistent volumes to bind")
	}},
	// Dynamic resource allocation's "no new claims to deallocate" says
	// nothing about placement; it is dropped.
	{"", func(_, l string) bool { return strings.Contains(l, "no new claims to deallocate") }},
	{NodeUnschedulable, func(_, l string) bool {
		return strings.Contains(l, "unschedulable") || strings.Contains(l, "were not ready")
	}},
}

func classifyClause(clause string) (Reason, bool) {
	clause = tidy(clause)
	if clause == "" {
		return Reason{}, false
	}
	r := Reason{Raw: clause, Class: Other}
	if m := countRE.FindStringSubmatch(clause); m != nil {
		r.NodeCount, _ = strconv.Atoi(m[1])
	}
	lower := strings.ToLower(clause)
	for _, rule := range clauseRules {
		if rule.is(clause, lower) {
			r.Class = rule.class
			break
		}
	}
	switch {
	case r.Class == "":
		return Reason{}, false
	case r.Class == InsufficientResource && strings.Contains(lower, "too many pods") && !strings.Contains(clause, "Insufficient"):
		r.Resource = "pods"
	case r.Class == InsufficientResource:
		if m := resourceRE.FindStringSubmatch(clause); m != nil {
			r.Resource = m[1]
		}
	case r.Class == UntoleratedTaint:
		r.TaintKey, r.TaintValue = taintIn(clause)
		if lifecycleTaint(r.TaintKey) {
			r.Class = NodeUnschedulable
		}
	}
	return r, true
}
