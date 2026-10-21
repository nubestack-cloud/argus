package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"

	"argus/internal/agent/rightsizing"
)

// ---------------------------------------------------------------- get_drain_impact
//
// What draining one node would do, from the object cache (PROJECT.md PG12):
// which pods are evicted and from which workloads, which workloads are left
// with no ready replica elsewhere, which PodDisruptionBudgets would hold the
// eviction, what emptyDir data goes with the pods, which pods have no
// controller to bring them back, and which stay (DaemonSet and static pods,
// which `kubectl drain` skips). Read-only: nothing is cordoned or evicted.

type drainWorkload struct {
	Kind      string `json:"kind"`
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
	Evicted   int    `json:"evicted"`
	// ReadyElsewhere counts this workload's Ready pods on other nodes. Zero
	// means the workload is unavailable until its replacements are Ready.
	ReadyElsewhere int `json:"readyElsewhere"`
}

type drainPDB struct {
	Namespace          string `json:"namespace"`
	Name               string `json:"name"`
	PodsOnNode         int    `json:"podsOnNode"`
	DisruptionsAllowed int32  `json:"disruptionsAllowed"`
	// Blocks is true when evicting every matching pod here would exceed what
	// the budget allows right now, so a drain waits on it.
	Blocks bool `json:"blocks"`
}

type drainPod struct {
	Namespace string   `json:"namespace"`
	Name      string   `json:"name"`
	EmptyDirs []string `json:"emptyDirs,omitempty"`
}

type drainImpactResult struct {
	insightMeta
	Node          string          `json:"node"`
	Unschedulable bool            `json:"unschedulable"`
	Evicted       int             `json:"evicted"`
	Workloads     []drainWorkload `json:"workloads"`
	Unavailable   []string        `json:"unavailable,omitempty"`
	PDBs          []drainPDB      `json:"pdbs,omitempty"`
	LosesData     []drainPod      `json:"emptyDirData,omitempty"`
	NotRecreated  []drainPod      `json:"noController,omitempty"`
	Stays         []string        `json:"stays,omitempty"`
}

func (e *ToolExecutor) getDrainImpact(_ context.Context, raw json.RawMessage) (json.RawMessage, bool, error) {
	c, err := e.cache()
	if err != nil {
		return nil, false, err
	}
	var a struct {
		Node string `json:"node"`
	}
	if err := decodeInsightArgs(raw, &a); err != nil {
		return nil, false, err
	}
	if a.Node == "" {
		return nil, false, fmt.Errorf("node is required")
	}
	node, ok, err := c.Node(a.Node)
	if err != nil {
		return nil, false, err
	}
	if !ok {
		return nil, false, notFoundError("Node", "", a.Node)
	}
	pods, err := c.Pods("")
	if err != nil {
		return nil, false, err
	}
	rss, _ := c.ReplicaSets("")
	pdbs, _ := c.PodDisruptionBudgets("")
	rsOwner := map[string]metav1.OwnerReference{}
	for _, rs := range rss {
		if ref := metav1.GetControllerOf(rs); ref != nil {
			rsOwner[rs.Namespace+"/"+rs.Name] = *ref
		}
	}
	r := drainImpact(a.Node, pods, rsOwner, pdbs)
	r.insightMeta = e.meta(kindPod, kindReplicaSet, [2]string{"policy", "PodDisruptionBudget"})
	r.Unschedulable = node.Spec.Unschedulable
	return marshalInsight(r)
}

// drainImpact is the pure half: pods are every pod in the cluster (for
// replicas elsewhere), rsOwner maps namespace/name of a ReplicaSet to its
// controller so a Deployment's pods are counted as the Deployment's.
func drainImpact(nodeName string, pods []*corev1.Pod, rsOwner map[string]metav1.OwnerReference, pdbs []*policyv1.PodDisruptionBudget) drainImpactResult {
	r := drainImpactResult{Node: nodeName, Workloads: []drainWorkload{}}
	workloadOf := func(p *corev1.Pod) (string, string, bool) {
		ref := metav1.GetControllerOf(p)
		if ref == nil {
			return "", "", false
		}
		if ref.Kind == "ReplicaSet" {
			if up, ok := rsOwner[p.Namespace+"/"+ref.Name]; ok {
				return up.Kind, up.Name, true
			}
		}
		return ref.Kind, ref.Name, true
	}
	live := func(p *corev1.Pod) bool {
		return p.Status.Phase != corev1.PodSucceeded && p.Status.Phase != corev1.PodFailed
	}

	byWorkload := map[string]*drainWorkload{}
	var evicted []*corev1.Pod
	for _, p := range pods {
		if p.Spec.NodeName != nodeName || !live(p) {
			continue
		}
		id := p.Namespace + "/" + p.Name
		if _, mirror := p.Annotations[corev1.MirrorPodAnnotationKey]; mirror {
			r.Stays = append(r.Stays, id+" (static pod)")
			continue
		}
		kind, name, controlled := workloadOf(p)
		if kind == "DaemonSet" {
			r.Stays = append(r.Stays, id+" (DaemonSet "+name+")")
			continue
		}
		evicted = append(evicted, p)
		if dirs := emptyDirs(p); len(dirs) > 0 {
			r.LosesData = append(r.LosesData, drainPod{Namespace: p.Namespace, Name: p.Name, EmptyDirs: dirs})
		}
		if !controlled {
			r.NotRecreated = append(r.NotRecreated, drainPod{Namespace: p.Namespace, Name: p.Name})
			continue
		}
		key := p.Namespace + "/" + kind + "/" + name
		w := byWorkload[key]
		if w == nil {
			w = &drainWorkload{Kind: kind, Namespace: p.Namespace, Name: name}
			byWorkload[key] = w
		}
		w.Evicted++
	}
	r.Evicted = len(evicted)

	for _, p := range pods {
		if p.Spec.NodeName == nodeName || !live(p) || !podReady(p) {
			continue
		}
		if kind, name, ok := workloadOf(p); ok {
			if w := byWorkload[p.Namespace+"/"+kind+"/"+name]; w != nil {
				w.ReadyElsewhere++
			}
		}
	}
	for _, w := range byWorkload {
		r.Workloads = append(r.Workloads, *w)
		if w.ReadyElsewhere == 0 {
			r.Unavailable = append(r.Unavailable, w.Kind+" "+w.Namespace+"/"+w.Name)
		}
	}
	sort.Slice(r.Workloads, func(i, j int) bool {
		a, b := r.Workloads[i], r.Workloads[j]
		if (a.ReadyElsewhere == 0) != (b.ReadyElsewhere == 0) {
			return a.ReadyElsewhere == 0
		}
		return a.Namespace+"/"+a.Name < b.Namespace+"/"+b.Name
	})
	sort.Strings(r.Unavailable)

	for _, pdb := range pdbs {
		sel, err := metav1.LabelSelectorAsSelector(pdb.Spec.Selector)
		if err != nil || sel.Empty() {
			continue
		}
		n := 0
		for _, p := range evicted {
			if p.Namespace == pdb.Namespace && sel.Matches(labels.Set(p.Labels)) {
				n++
			}
		}
		if n > 0 {
			r.PDBs = append(r.PDBs, drainPDB{Namespace: pdb.Namespace, Name: pdb.Name, PodsOnNode: n,
				DisruptionsAllowed: pdb.Status.DisruptionsAllowed, Blocks: int32(n) > pdb.Status.DisruptionsAllowed})
		}
	}
	sort.Slice(r.PDBs, func(i, j int) bool {
		return r.PDBs[i].Namespace+"/"+r.PDBs[i].Name < r.PDBs[j].Namespace+"/"+r.PDBs[j].Name
	})
	return r
}

func emptyDirs(p *corev1.Pod) []string {
	var out []string
	for _, v := range p.Spec.Volumes {
		if v.EmptyDir != nil {
			out = append(out, v.Name)
		}
	}
	return out
}

func podReady(p *corev1.Pod) bool {
	for _, c := range p.Status.Conditions {
		if c.Type == corev1.PodReady {
			return c.Status == corev1.ConditionTrue
		}
	}
	return false
}

// ---------------------------------------------------------------- get_rightsizing

type rightsizingResult struct {
	insightMeta
	*rightsizing.Result
}

// getRightsizing compares one namespace's container requests with their p95
// usage over a window (PROJECT.md PG8). Read-only, like every insight tool.
func (e *ToolExecutor) getRightsizing(ctx context.Context, raw json.RawMessage) (json.RawMessage, bool, error) {
	var a struct {
		Namespace  string `json:"namespace"`
		Workload   string `json:"workload"`
		WindowDays int    `json:"windowDays"`
	}
	if err := decodeInsightArgs(raw, &a); err != nil {
		return nil, false, err
	}
	if a.Namespace == "" {
		return nil, false, fmt.Errorf("namespace is required")
	}
	m := e.meta(kindPod, kindReplicaSet)
	if e.metricsProxy == nil {
		return marshalInsight(rightsizingResult{insightMeta: m, Result: &rightsizing.Result{Namespace: a.Namespace, Rows: []rightsizing.Row{},
			Reason: "this cluster has no Prometheus configured for its agent (metrics.prometheusService)"}})
	}
	c, err := e.cache()
	if err != nil {
		return nil, false, err
	}
	pods, err := c.Pods(a.Namespace)
	if err != nil {
		return nil, false, err
	}
	rss, _ := c.ReplicaSets(a.Namespace)
	rsOwner := map[string]metav1.OwnerReference{}
	for _, rs := range rss {
		if ref := metav1.GetControllerOf(rs); ref != nil {
			rsOwner[rs.Namespace+"/"+rs.Name] = *ref
		}
	}
	owner := func(p *corev1.Pod) (string, string) {
		ref := metav1.GetControllerOf(p)
		if ref == nil {
			return "Pod", p.Name
		}
		if ref.Kind == "ReplicaSet" {
			if up, ok := rsOwner[p.Namespace+"/"+ref.Name]; ok {
				return up.Kind, up.Name
			}
		}
		return ref.Kind, ref.Name
	}
	res := rightsizing.Compute(ctx, costQuerier{promQuerier{e}}, a.Namespace, time.Duration(a.WindowDays)*24*time.Hour, pods, owner)
	if a.Workload != "" {
		kept := res.Rows[:0]
		for _, r := range res.Rows {
			if r.Workload == a.Workload {
				kept = append(kept, r)
			}
		}
		res.Rows = kept
	}
	return marshalInsight(rightsizingResult{insightMeta: m, Result: res})
}
