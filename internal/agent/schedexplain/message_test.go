package schedexplain

import (
	"fmt"
	"strings"
	"testing"
)

// brief renders a reason compactly: class, the node count, and the resource
// or taint it names.
func brief(r Reason) string {
	s := fmt.Sprintf("%s×%d", r.Class, r.NodeCount)
	if r.Resource != "" {
		s += " " + r.Resource
	}
	if r.TaintKey != "" || r.TaintValue != "" {
		s += " {" + r.TaintKey + "=" + r.TaintValue + "}"
	}
	return s
}

func TestParseMessage(t *testing.T) {
	cases := []struct {
		msg   string
		total int
		want  string // reasons joined with " | "
	}{
		// The preemption tail repeats the verdict and is not counted again.
		{"0/6 nodes are available: 1 node(s) had untolerated taint {node-role.kubernetes.io/control-plane: }, 5 Insufficient memory. preemption: 0/6 nodes are available: 6 No preemption victims found for incoming pod.",
			6, "NodeUnschedulable×1 {node-role.kubernetes.io/control-plane=} | InsufficientResource×5 memory"},
		{"0/4 nodes are available: 2 Insufficient nvidia.com/gpu, 2 node(s) had untolerated taint {team: ml}.",
			4, "InsufficientResource×2 nvidia.com/gpu | UntoleratedTaint×2 {team=ml}"},
		{"0/1 nodes are available: 1 Too many pods.", 1, "InsufficientResource×1 pods"},
		// A message that is one clause with no node list.
		{"pod has unbound immediate PersistentVolumeClaims. preemption: not eligible", 0, "VolumeBinding×0"},
		// Nothing to place on: no reasons, but the node count is real.
		{"0/2 nodes are available: no new claims to deallocate.", 2, ""},
		{"", 0, ""},
		{"  ", 0, ""},
	}
	for _, c := range cases {
		total, reasons := ParseMessage(c.msg)
		var got []string
		for _, r := range reasons {
			got = append(got, brief(r))
		}
		if total != c.total || strings.Join(got, " | ") != c.want {
			t.Errorf("%q:\n got  %d %s\n want %d %s", c.msg, total, strings.Join(got, " | "), c.total, c.want)
		}
	}
	// The clause text is kept as written, tidied of its trailing stop.
	if _, r := ParseMessage("0/2 nodes are available: 2 node(s) were unschedulable."); len(r) != 1 || r[0].Raw != "2 node(s) were unschedulable" {
		t.Errorf("raw = %+v", r)
	}
}

func TestClassifyClause(t *testing.T) {
	for clause, want := range map[string]string{
		"4 Insufficient cpu":                                           "InsufficientResource×4 cpu",
		"4 Insufficient ephemeral-storage":                             "InsufficientResource×4 ephemeral-storage",
		"4 Insufficient hugepages-2Mi":                                 "InsufficientResource×4 hugepages-2Mi",
		"4 node(s) didn't match Pod's node affinity/selector":          "NodeAffinitySelector×4",
		"4 node(s) didn't match node selector":                         "NodeAffinitySelector×4",
		"4 node(s) didn't match pod affinity rules":                    "PodAffinity×4",
		"4 node(s) didn't match pod anti-affinity rules":               "PodAntiAffinity×4",
		"4 node(s) didn't match pod topology spread constraints":       "TopologySpread×4",
		"4 node(s) had volume node affinity conflict":                  "VolumeNodeAffinity×4",
		"4 node(s) didn't find available persistent volumes to bind":   "VolumeBinding×4",
		"4 node(s) exceed max volume count":                            "VolumeCount×4",
		"4 node(s) didn't have free ports for the requested pod ports": "NoPorts×4",
		"4 node(s) were unschedulable":                                 "NodeUnschedulable×4",
		"4 node(s) were not ready":                                     "NodeUnschedulable×4",
		// Taints Kubernetes manages say what state the node is in.
		"4 node(s) had untolerated taint {node.kubernetes.io/unreachable: }":                     "NodeUnschedulable×4 {node.kubernetes.io/unreachable=}",
		"4 node(s) had untolerated taint {node.cloudprovider.kubernetes.io/uninitialized: true}": "NodeUnschedulable×4 {node.cloudprovider.kubernetes.io/uninitialized=true}",
		"4 node(s) had untolerated taint {spot}":                                                 "UntoleratedTaint×4 {spot=}",
		"4 node(s) had untolerated taint":                                                        "UntoleratedTaint×4",
		"4 node(s) failed some future plugin":                                                    "Other×4",
	} {
		r, ok := classifyClause(clause)
		if got := brief(r); !ok || got != want {
			t.Errorf("%q: %s (%v), want %s", clause, got, ok, want)
		}
	}
	for _, skip := range []string{"", " .", "no new claims to deallocate"} {
		if r, ok := classifyClause(skip); ok {
			t.Errorf("%q classified as %+v", skip, r)
		}
	}
}
