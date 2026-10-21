// Package karpenter reads Karpenter's NodePools and NodeClaims from the
// agent's cache (CI-S9, PROJECT.md CI-P9 a and PG7): whether a pending pod
// could be placed by any pool, and each pool's capacity ledger. Pure: the
// caller supplies the objects. Every quantity Karpenter does not report is
// absent, never zero.
package karpenter

import (
	"fmt"
	"sort"
	"strings"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	"argus/internal/agent/schedexplain"
)

// PoolVerdict says whether one NodePool could launch a node for a pod.
type PoolVerdict struct {
	Pool   string `json:"pool"`
	Fits   bool   `json:"fits"`
	Reason string `json:"reason,omitempty"`
	Weight int64  `json:"weight,omitempty"`
}

type requirement struct {
	Key      string
	Operator string
	Values   []string
}

// wellKnown labels Karpenter sets from the instance type it picks, so a pool
// with no requirement on them can still satisfy a selector on them.
var wellKnown = map[string]bool{
	"topology.kubernetes.io/zone": true, "topology.kubernetes.io/region": true, "kubernetes.io/arch": true,
	"kubernetes.io/os": true, "node.kubernetes.io/instance-type": true, "karpenter.sh/capacity-type": true,
}

func poolRequirements(p *unstructured.Unstructured) []requirement {
	raw, _, _ := unstructured.NestedSlice(p.Object, "spec", "template", "spec", "requirements")
	var out []requirement
	for _, r := range raw {
		m, ok := r.(map[string]any)
		if !ok {
			continue
		}
		req := requirement{}
		req.Key, _ = m["key"].(string)
		req.Operator, _ = m["operator"].(string)
		if vs, ok := m["values"].([]any); ok {
			for _, v := range vs {
				if s, ok := v.(string); ok {
					req.Values = append(req.Values, s)
				}
			}
		}
		out = append(out, req)
	}
	return out
}

func poolTaints(p *unstructured.Unstructured) []corev1.Taint {
	raw, _, _ := unstructured.NestedSlice(p.Object, "spec", "template", "spec", "taints")
	var out []corev1.Taint
	for _, r := range raw {
		m, ok := r.(map[string]any)
		if !ok {
			continue
		}
		t := corev1.Taint{}
		t.Key, _ = m["key"].(string)
		v, _ := m["value"].(string)
		e, _ := m["effect"].(string)
		t.Value, t.Effect = v, corev1.TaintEffect(e)
		out = append(out, t)
	}
	return out
}

func contains(vs []string, s string) bool {
	for _, v := range vs {
		if v == s {
			return true
		}
	}
	return false
}

// canLabel reports whether pool can produce a node labelled key=value.
func canLabel(pool *unstructured.Unstructured, reqs []requirement, key, value string) (bool, string) {
	if lbl, _, _ := unstructured.NestedStringMap(pool.Object, "spec", "template", "metadata", "labels"); lbl != nil {
		if v, ok := lbl[key]; ok {
			if v == value {
				return true, ""
			}
			return false, fmt.Sprintf("its nodes are labelled %s=%s, not %s", key, v, value)
		}
	}
	for _, r := range reqs {
		if r.Key != key {
			continue
		}
		switch r.Operator {
		case "In":
			if !contains(r.Values, value) {
				return false, fmt.Sprintf("it allows %s only in [%s]", key, strings.Join(r.Values, ", "))
			}
		case "NotIn":
			if contains(r.Values, value) {
				return false, fmt.Sprintf("it excludes %s=%s", key, value)
			}
		case "DoesNotExist":
			return false, fmt.Sprintf("it requires %s to be absent", key)
		}
		return true, ""
	}
	if wellKnown[key] {
		return true, ""
	}
	return false, fmt.Sprintf("it never sets %s on its nodes", key)
}

func quantity(p *unstructured.Unstructured, path ...string) *resource.Quantity {
	s, found, _ := unstructured.NestedString(p.Object, path...)
	if !found {
		return nil
	}
	q, err := resource.ParseQuantity(s)
	if err != nil {
		return nil
	}
	return &q
}

// Evaluate tests every pool against pod's selector, required node affinity,
// tolerations and the pool's remaining limit, in Karpenter's weight order.
func Evaluate(pod *corev1.Pod, requests corev1.ResourceList, pools []*unstructured.Unstructured) []PoolVerdict {
	var out []PoolVerdict
	for _, pool := range pools {
		v := PoolVerdict{Pool: pool.GetName()}
		v.Weight, _, _ = unstructured.NestedInt64(pool.Object, "spec", "weight")
		v.Fits, v.Reason = fits(pod, requests, pool)
		out = append(out, v)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Weight > out[j].Weight })
	return out
}

func fits(pod *corev1.Pod, requests corev1.ResourceList, pool *unstructured.Unstructured) (bool, string) {
	reqs := poolRequirements(pool)
	for k, v := range pod.Spec.NodeSelector {
		if ok, why := canLabel(pool, reqs, k, v); !ok {
			return false, "nodeSelector " + k + "=" + v + ": " + why
		}
	}
	if aff := pod.Spec.Affinity; aff != nil && aff.NodeAffinity != nil && aff.NodeAffinity.RequiredDuringSchedulingIgnoredDuringExecution != nil {
		terms := aff.NodeAffinity.RequiredDuringSchedulingIgnoredDuringExecution.NodeSelectorTerms
		var firstWhy string
		ok := false
		for _, t := range terms {
			termOK := true
			for _, e := range t.MatchExpressions {
				if e.Operator != corev1.NodeSelectorOpIn || len(e.Values) == 0 {
					continue // other operators are left to the scheduler
				}
				any := false
				var why string
				for _, val := range e.Values {
					if okv, w := canLabel(pool, reqs, e.Key, val); okv {
						any = true
						break
					} else {
						why = w
					}
				}
				if !any {
					termOK = false
					if firstWhy == "" {
						firstWhy = "node affinity on " + e.Key + ": " + why
					}
					break
				}
			}
			if termOK {
				ok = true
				break
			}
		}
		if !ok && len(terms) > 0 {
			return false, firstWhy
		}
	}
	for _, t := range poolTaints(pool) {
		if t.Effect == corev1.TaintEffectPreferNoSchedule {
			continue
		}
		if !schedexplain.Tolerates(pod.Spec.Tolerations, t) {
			return false, fmt.Sprintf("its nodes carry taint %s=%s:%s, which the pod does not tolerate", t.Key, t.Value, t.Effect)
		}
	}
	for _, name := range []corev1.ResourceName{corev1.ResourceCPU, corev1.ResourceMemory} {
		limit := quantity(pool, "spec", "limits", string(name))
		used := quantity(pool, "status", "resources", string(name))
		want, has := requests[name]
		if limit == nil || used == nil || !has {
			continue
		}
		head := limit.DeepCopy()
		head.Sub(*used)
		if head.Cmp(want) < 0 {
			return false, fmt.Sprintf("its %s limit is reached: %s of %s provisioned, the pod asks for %s", name, used.String(), limit.String(), want.String())
		}
	}
	return true, ""
}

// Ledger is one pool's capacity.
type Ledger struct {
	Pool        string         `json:"pool"`
	LimitCPU    string         `json:"limitCpu,omitempty"`
	LimitMemory string         `json:"limitMemory,omitempty"`
	UsedCPU     string         `json:"provisionedCpu,omitempty"`
	UsedMemory  string         `json:"provisionedMemory,omitempty"`
	Nodes       *int64         `json:"nodes,omitempty"`
	Claims      map[string]int `json:"claims"`
}

// claimPhase is how far a NodeClaim has got: the furthest True condition.
func claimPhase(c *unstructured.Unstructured) string {
	if c.GetDeletionTimestamp() != nil {
		return "Terminating"
	}
	conds, _, _ := unstructured.NestedSlice(c.Object, "status", "conditions")
	state := map[string]string{}
	for _, x := range conds {
		if m, ok := x.(map[string]any); ok {
			t, _ := m["type"].(string)
			s, _ := m["status"].(string)
			state[t] = s
		}
	}
	for _, phase := range []string{"Ready", "Initialized", "Registered", "Launched"} {
		if state[phase] == "True" {
			return phase
		}
	}
	return "Pending"
}

// Ledgers is every pool's limit, what it has provisioned, and its claims by
// phase.
func Ledgers(pools, claims []*unstructured.Unstructured) []Ledger {
	byPool := map[string]map[string]int{}
	for _, c := range claims {
		p := c.GetLabels()["karpenter.sh/nodepool"]
		if byPool[p] == nil {
			byPool[p] = map[string]int{}
		}
		byPool[p][claimPhase(c)]++
	}
	var out []Ledger
	for _, p := range pools {
		l := Ledger{Pool: p.GetName(), Claims: byPool[p.GetName()]}
		if l.Claims == nil {
			l.Claims = map[string]int{}
		}
		str := func(path ...string) string {
			if q := quantity(p, path...); q != nil {
				return q.String()
			}
			return ""
		}
		l.LimitCPU, l.LimitMemory = str("spec", "limits", "cpu"), str("spec", "limits", "memory")
		l.UsedCPU, l.UsedMemory = str("status", "resources", "cpu"), str("status", "resources", "memory")
		if n := quantity(p, "status", "resources", "nodes"); n != nil {
			v := n.Value()
			l.Nodes = &v
		}
		out = append(out, l)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Pool < out[j].Pool })
	return out
}
