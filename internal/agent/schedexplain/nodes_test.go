package schedexplain

import (
	"slices"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// labelled makes nodes from "name k=v,k=v" specs.
func labelled(specs ...string) []*corev1.Node {
	var out []*corev1.Node
	for _, s := range specs {
		name, pairs, _ := strings.Cut(s, " ")
		labels := map[string]string{}
		for _, kv := range strings.Split(pairs, ",") {
			if k, v, ok := strings.Cut(kv, "="); ok {
				labels[k] = v
			}
		}
		out = append(out, &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: name, Labels: labels}})
	}
	return out
}

func req(key string, op corev1.NodeSelectorOperator, values ...string) corev1.NodeSelectorRequirement {
	return corev1.NodeSelectorRequirement{Key: key, Operator: op, Values: values}
}

func terms(ts ...[]corev1.NodeSelectorRequirement) []corev1.NodeSelectorTerm {
	var out []corev1.NodeSelectorTerm
	for _, t := range ts {
		out = append(out, corev1.NodeSelectorTerm{MatchExpressions: t})
	}
	return out
}

var x86 = labelled(
	"node-a kubernetes.io/arch=amd64,topology.kubernetes.io/zone=eu-west-2a,pool=general",
	"node-b kubernetes.io/arch=amd64,topology.kubernetes.io/zone=eu-west-2b,pool=general",
	"node-c kubernetes.io/arch=amd64,topology.kubernetes.io/zone=eu-west-2b,pool=batch",
)

func TestUnsatisfiable(t *testing.T) {
	cases := []struct {
		why  string
		p    placement
		want []string
	}{
		{"an arch no node has", placement{selector: map[string]string{"kubernetes.io/arch": "arm64"}},
			[]string{"no node has kubernetes.io/arch=arm64; 3 have kubernetes.io/arch: [amd64]"}},
		{"a label no node carries", placement{selector: map[string]string{"disktype": "nvme"}},
			[]string{"no node has a disktype label at all (the pod needs disktype=nvme)"}},
		{"met by one node is met", placement{selector: map[string]string{"pool": "batch"}}, nil},
		{"a zone nobody is in", placement{terms: terms([]corev1.NodeSelectorRequirement{req("topology.kubernetes.io/zone", corev1.NodeSelectorOpIn, "eu-west-2c")})},
			[]string{"no node has topology.kubernetes.io/zone in [eu-west-2c]; nodes have topology.kubernetes.io/zone: [eu-west-2a, eu-west-2b]"}},
		// Each requirement is met somewhere, never both on one node.
		{"a combination no node meets", placement{terms: terms([]corev1.NodeSelectorRequirement{
			req("pool", corev1.NodeSelectorOpIn, "batch"), req("topology.kubernetes.io/zone", corev1.NodeSelectorOpIn, "eu-west-2a")})},
			[]string{"no single node meets every requirement of any one required nodeAffinity term"}},
		// Any one term will do.
		{"one of two terms met", placement{terms: terms(
			[]corev1.NodeSelectorRequirement{req("gpu", corev1.NodeSelectorOpExists)},
			[]corev1.NodeSelectorRequirement{req("pool", corev1.NodeSelectorOpNotIn, "general")})}, nil},
		{"several unmet, each said once", placement{terms: terms(
			[]corev1.NodeSelectorRequirement{req("gpu", corev1.NodeSelectorOpExists)},
			[]corev1.NodeSelectorRequirement{req("gpu", corev1.NodeSelectorOpExists), req("kubernetes.io/arch", corev1.NodeSelectorOpDoesNotExist)})},
			[]string{"no node has a gpu label at all (the pod needs it to exist)", "every node has a kubernetes.io/arch label (the pod needs it absent)"}},
		{"NotIn every value present", placement{terms: terms([]corev1.NodeSelectorRequirement{req("pool", corev1.NodeSelectorOpNotIn, "general", "batch")})},
			[]string{"every node has pool in [general, batch] (the pod needs a node outside it)"}},
		{"selector and affinity both", placement{selector: map[string]string{"ssd": "true"}, terms: terms([]corev1.NodeSelectorRequirement{req("gpu", corev1.NodeSelectorOpIn, "a100")})},
			[]string{"no node has a ssd label at all (the pod needs ssd=true)", "no node has a gpu label at all (the pod needs gpu in [a100])"}},
	}
	for _, c := range cases {
		if got := c.p.unsatisfiable(x86); !slices.Equal(got, c.want) {
			t.Errorf("%s:\n got  %q\n want %q", c.why, got, c.want)
		}
	}
}

func TestHolds(t *testing.T) {
	cases := []struct {
		r     corev1.NodeSelectorRequirement
		value string
		set   bool
		want  bool
	}{
		{req("k", corev1.NodeSelectorOpIn, "a", "b"), "b", true, true},
		{req("k", corev1.NodeSelectorOpIn, "a"), "", false, false},
		{req("k", corev1.NodeSelectorOpNotIn, "a"), "", false, true},
		{req("k", corev1.NodeSelectorOpNotIn, "a"), "a", true, false},
		{req("k", corev1.NodeSelectorOpExists), "", true, true},
		{req("k", corev1.NodeSelectorOpDoesNotExist), "x", true, false},
		{req("k", corev1.NodeSelectorOpGt, "16"), "32", true, true},
		{req("k", corev1.NodeSelectorOpGt, "16"), "16", true, false},
		{req("k", corev1.NodeSelectorOpLt, "4"), "2", true, true},
		{req("k", corev1.NodeSelectorOpLt, "4"), "two", true, false},
		{req("k", corev1.NodeSelectorOpGt), "5", true, false},
		{req("k", "Matches", "x"), "x", true, false},
	}
	for _, c := range cases {
		if got := holds(c.r, c.value, c.set); got != c.want {
			t.Errorf("%s %s %v against %q (set=%v): %v", c.r.Key, c.r.Operator, c.r.Values, c.value, c.set, got)
		}
	}
}

func TestMissOn(t *testing.T) {
	nodeA := x86[0]
	pinned := placement{terms: []corev1.NodeSelectorTerm{{MatchFields: []corev1.NodeSelectorRequirement{req("metadata.name", corev1.NodeSelectorOpIn, "node-b")}}}}
	cases := []struct {
		p           placement
		reason, key string
	}{
		{placement{}, "", ""},
		{placement{selector: map[string]string{"pool": "general", "kubernetes.io/arch": "amd64"}}, "", ""},
		// The first unmatched selector key in sorted order.
		{placement{selector: map[string]string{"pool": "batch", "disk": "ssd"}}, "node selector disk=ssd not matched", "disk"},
		{placement{terms: terms([]corev1.NodeSelectorRequirement{req("pool", corev1.NodeSelectorOpIn, "general"), req("topology.kubernetes.io/zone", corev1.NodeSelectorOpIn, "eu-west-2b")})},
			"required node affinity topology.kubernetes.io/zone In [eu-west-2b] not matched", "topology.kubernetes.io/zone"},
		// A DaemonSet-style pin by name; any field but metadata.name never matches.
		{pinned, "required node affinity field metadata.name In [node-b] not matched", ""},
		{placement{terms: []corev1.NodeSelectorTerm{{MatchFields: []corev1.NodeSelectorRequirement{req("spec.nodeName", corev1.NodeSelectorOpIn, "node-a")}}}},
			"required node affinity field spec.nodeName In [node-a] not matched", ""},
		{placement{terms: terms([]corev1.NodeSelectorRequirement{req("gpu", corev1.NodeSelectorOpExists)}, []corev1.NodeSelectorRequirement{req("pool", corev1.NodeSelectorOpIn, "batch")})},
			"required node affinity: no term matched", ""},
	}
	for _, c := range cases {
		if reason, key := c.p.missOn(nodeA); reason != c.reason || key != c.key {
			t.Errorf("%+v: %q %q, want %q %q", c.p, reason, key, c.reason, c.key)
		}
	}
	if reason, _ := pinned.missOn(x86[1]); reason != "" {
		t.Errorf("node-b fails its own pin: %q", reason)
	}
}

// Empty terms carry nothing to explain and are dropped.
func TestPlacementOf(t *testing.T) {
	pod := &corev1.Pod{Spec: corev1.PodSpec{
		NodeSelector: map[string]string{"pool": "batch"},
		Affinity: &corev1.Affinity{NodeAffinity: &corev1.NodeAffinity{RequiredDuringSchedulingIgnoredDuringExecution: &corev1.NodeSelector{
			NodeSelectorTerms: []corev1.NodeSelectorTerm{{}, {MatchExpressions: []corev1.NodeSelectorRequirement{req("gpu", corev1.NodeSelectorOpExists)}}},
		}}},
	}}
	p := placementOf(pod)
	if p.selector["pool"] != "batch" || len(p.terms) != 1 || p.terms[0].MatchExpressions[0].Key != "gpu" {
		t.Errorf("placement = %+v", p)
	}
	if p := placementOf(&corev1.Pod{}); p.selector != nil || p.terms != nil {
		t.Errorf("bare pod = %+v", p)
	}
}
