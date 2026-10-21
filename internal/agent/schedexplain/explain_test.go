package schedexplain

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func testNode(name, cpu, mem string, labels map[string]string, taints ...corev1.Taint) *corev1.Node {
	return &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: name, Labels: labels},
		Spec:       corev1.NodeSpec{Taints: taints},
		Status: corev1.NodeStatus{Allocatable: corev1.ResourceList{
			corev1.ResourceCPU:    resource.MustParse(cpu),
			corev1.ResourceMemory: resource.MustParse(mem),
			corev1.ResourcePods:   resource.MustParse("110"),
		}},
	}
}

func boundPod(name, node, cpu, mem string) *corev1.Pod {
	p := testPod(name, cpu)
	p.Spec.NodeName = node
	p.Spec.Containers[0].Resources.Requests[corev1.ResourceMemory] = resource.MustParse(mem)
	p.Status.Phase = corev1.PodRunning
	return p
}

func memPod(mem string) *corev1.Pod {
	p := testPod("pending", "100m")
	p.Spec.Containers[0].Resources.Requests[corev1.ResourceMemory] = resource.MustParse(mem)
	return p
}

func groupByReason(e Explanation, reason string) *NodeGroup {
	for i := range e.Nodes {
		if e.Nodes[i].Reason == reason {
			return &e.Nodes[i]
		}
	}
	return nil
}

func TestExplainGroupsNodesByFirstFailingPredicate(t *testing.T) {
	gpu := corev1.Taint{Key: "gpu", Value: "true", Effect: corev1.TaintEffectNoSchedule}
	var nodes []*corev1.Node
	for i := 0; i < 6; i++ {
		nodes = append(nodes, testNode(fmt.Sprintf("gpu-%d", i), "8", "64Gi", nil, gpu))
	}
	var scheduled []*corev1.Pod
	for i, used := range []string{"6Gi", "5.9Gi", "7Gi"} {
		name := fmt.Sprintf("small-%d", i)
		nodes = append(nodes, testNode(name, "4", "8Gi", nil))
		q := resource.MustParse(used)
		scheduled = append(scheduled, boundPod("filler-"+name, name, "100m", q.String()))
	}
	// Terminal pods hold nothing: this node would otherwise look full.
	done := boundPod("done", "small-0", "100m", "8Gi")
	done.Status.Phase = corev1.PodSucceeded
	scheduled = append(scheduled, done)
	cordoned := testNode("cordoned", "8", "64Gi", nil)
	cordoned.Spec.Unschedulable = true
	nodes = append(nodes, cordoned)

	msg := "0/10 nodes are available: 1 node(s) were unschedulable, 3 Insufficient memory, 6 node(s) had untolerated taint {gpu: true}. preemption: 0/10 nodes are available: 10 No preemption victims found for incoming pod."
	e := Explain(memPod("4Gi"), nodes, scheduled, msg, 3)

	if e.NodesEvaluated != 10 || e.SimilarPendingPods != 3 || e.SchedulerTotalNodes != 10 {
		t.Fatalf("evaluated=%d similar=%d total=%d", e.NodesEvaluated, e.SimilarPendingPods, e.SchedulerTotalNodes)
	}
	if len(e.Parsed) != 3 || e.Parsed[2].Class != UntoleratedTaint || e.Parsed[2].NodeCount != 6 {
		t.Fatalf("parsed = %+v", e.Parsed)
	}
	if len(e.Nodes) != 3 {
		t.Fatalf("groups = %+v", e.Nodes)
	}
	taint := e.Nodes[0]
	if taint.Predicate != PredicateTaint || taint.Reason != "untolerated taint gpu=true:NoSchedule" || taint.Count != 6 || len(taint.Examples) != 6 {
		t.Fatalf("largest group = %+v", taint)
	}
	mem := groupByReason(e, "insufficient memory")
	if mem == nil || mem.Count != 3 || mem.Detail != "needs 4Gi, most free 2.1Gi" {
		t.Fatalf("memory group = %+v", mem)
	}
	if g := groupByReason(e, "cordoned (spec.unschedulable)"); g == nil || g.Count != 1 || g.Examples[0] != "cordoned" {
		t.Fatalf("cordon group = %+v", g)
	}
	if !strings.HasPrefix(e.Verdict, "0/10 nodes can run this pod: 6 untolerated taint gpu=true:NoSchedule; 3 insufficient memory (needs 4Gi, most free 2.1Gi); 1 cordoned") {
		t.Fatalf("verdict = %q", e.Verdict)
	}
	if e.Truncated {
		t.Fatal("nothing was capped")
	}
	if !strings.HasPrefix(e.Signature, "sha256:") {
		t.Fatalf("signature = %q", e.Signature)
	}
}

func TestExplainPassingNodesPointAtUnevaluatedPredicates(t *testing.T) {
	nodes := []*corev1.Node{testNode("a", "4", "8Gi", nil), testNode("b", "4", "8Gi", nil)}
	msg := "0/2 nodes are available: 2 node(s) didn't match pod anti-affinity rules."
	e := Explain(memPod("1Gi"), nodes, nil, msg, 1)
	if len(e.Nodes) != 1 || e.Nodes[0].Predicate != PredicateNone || e.Nodes[0].Count != 2 {
		t.Fatalf("groups = %+v", e.Nodes)
	}
	if !strings.Contains(e.Verdict, "2/2 nodes pass") || !strings.Contains(e.Verdict, "PodAntiAffinity") {
		t.Fatalf("verdict = %q", e.Verdict)
	}
	// Without a classifiable message the verdict lists what was not evaluated.
	e = Explain(memPod("1Gi"), nodes, nil, "", 1)
	if !strings.Contains(e.Verdict, "pod affinity/anti-affinity") {
		t.Fatalf("verdict = %q", e.Verdict)
	}
}

func TestExplainCordonToleratedByDaemonSetStylePod(t *testing.T) {
	n := testNode("a", "4", "8Gi", nil, corev1.Taint{Key: corev1.TaintNodeUnschedulable, Effect: corev1.TaintEffectNoSchedule})
	n.Spec.Unschedulable = true
	pod := memPod("1Gi")
	pod.Spec.Tolerations = []corev1.Toleration{{Key: corev1.TaintNodeUnschedulable, Operator: corev1.TolerationOpExists, Effect: corev1.TaintEffectNoSchedule}}
	e := Explain(pod, []*corev1.Node{n}, nil, "", 1)
	if e.Nodes[0].Predicate != PredicateNone {
		t.Fatalf("tolerated cordon should pass, got %+v", e.Nodes[0])
	}
}

func TestExplainPreferNoScheduleTaintDoesNotBlock(t *testing.T) {
	n := testNode("a", "4", "8Gi", nil, corev1.Taint{Key: "soft", Effect: corev1.TaintEffectPreferNoSchedule})
	if e := Explain(memPod("1Gi"), []*corev1.Node{n}, nil, "", 1); e.Nodes[0].Predicate != PredicateNone {
		t.Fatalf("PreferNoSchedule should not block, got %+v", e.Nodes[0])
	}
}

func TestExplainNodeAffinityGroupNamesLabelValues(t *testing.T) {
	nodes := []*corev1.Node{
		testNode("a", "4", "8Gi", map[string]string{"kubernetes.io/arch": "amd64"}),
		testNode("b", "4", "8Gi", map[string]string{"kubernetes.io/arch": "amd64"}),
		testNode("c", "4", "8Gi", nil),
	}
	pod := memPod("1Gi")
	pod.Spec.NodeSelector = map[string]string{"kubernetes.io/arch": "arm64"}
	e := Explain(pod, nodes, nil, "0/3 nodes are available: 3 node(s) didn't match Pod's node affinity/selector.", 1)
	if len(e.Nodes) != 1 {
		t.Fatalf("groups = %+v", e.Nodes)
	}
	g := e.Nodes[0]
	if g.Predicate != PredicateNodeAffinity || g.Reason != "node selector kubernetes.io/arch=arm64 not matched" || g.Count != 3 {
		t.Fatalf("group = %+v", g)
	}
	if g.Detail != "these nodes have kubernetes.io/arch: [amd64]; 1 lack label kubernetes.io/arch" {
		t.Fatalf("detail = %q", g.Detail)
	}
	if len(e.Unsatisfiable) != 1 || !strings.Contains(e.Verdict, "Unsatisfiable on every node: no node has kubernetes.io/arch=arm64") {
		t.Fatalf("unsatisfiable = %v verdict = %q", e.Unsatisfiable, e.Verdict)
	}
}

func TestExplainPodSlotsAndCPU(t *testing.T) {
	full := testNode("full", "4", "8Gi", nil)
	full.Status.Allocatable[corev1.ResourcePods] = resource.MustParse("1")
	busy := testNode("busy", "1", "8Gi", nil)
	scheduled := []*corev1.Pod{boundPod("x", "full", "10m", "1Mi"), boundPod("y", "busy", "750m", "1Mi")}
	pod := testPod("p", "500m")
	e := Explain(pod, []*corev1.Node{full, busy}, scheduled, "", 1)
	if g := groupByReason(e, "insufficient pods"); g == nil || g.Detail != "needs 1, most free 0" {
		t.Fatalf("pods group = %+v", g)
	}
	if g := groupByReason(e, "insufficient cpu"); g == nil || g.Detail != "needs 500m, most free 250m" {
		t.Fatalf("cpu group = %+v", g)
	}
}

func TestExplainExtendedResourceMissingFromNode(t *testing.T) {
	pod := testPod("p", "100m")
	pod.Spec.Containers[0].Resources.Requests["nvidia.com/gpu"] = resource.MustParse("1")
	e := Explain(pod, []*corev1.Node{testNode("a", "4", "8Gi", nil)}, nil, "", 1)
	if g := groupByReason(e, "insufficient nvidia.com/gpu"); g == nil || g.Detail != "needs 1, most free 0" {
		t.Fatalf("groups = %+v", e.Nodes)
	}
}

func TestExplainCapsExampleNodes(t *testing.T) {
	taint := corev1.Taint{Key: "x", Effect: corev1.TaintEffectNoExecute}
	var nodes []*corev1.Node
	for i := 0; i < MaxExampleNodes+7; i++ {
		nodes = append(nodes, testNode(fmt.Sprintf("n%03d", i), "4", "8Gi", nil, taint))
	}
	e := Explain(memPod("1Gi"), nodes, nil, "", 1)
	g := e.Nodes[0]
	if g.Count != MaxExampleNodes+7 || len(g.Examples) != MaxExampleNodes || !e.Truncated {
		t.Fatalf("count=%d examples=%d truncated=%v", g.Count, len(g.Examples), e.Truncated)
	}
	if g.Examples[0] != "n000" {
		t.Fatalf("examples not in name order: %v", g.Examples[:3])
	}
}

// No nodes means no evaluation, which must not read as "nothing blocks".
func TestExplainNoNodesIsUnknown(t *testing.T) {
	e := Explain(memPod("1Gi"), nil, nil, "0/3 nodes are available: 3 Insufficient cpu.", 2)
	if e.NodesEvaluated != 0 || len(e.Nodes) != 0 || !strings.Contains(e.Verdict, "No nodes were observed") {
		t.Fatalf("explanation = %+v", e)
	}
	if len(e.Parsed) != 1 {
		t.Fatalf("scheduler message should still be parsed: %+v", e.Parsed)
	}
}

func TestExplainJSONShape(t *testing.T) {
	e := Explain(memPod("1Gi"), []*corev1.Node{testNode("a", "4", "8Gi", nil)}, nil, "", 1)
	raw, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"signature", "similarPendingPods", "parsed", "nodes", "verdict", "nodesEvaluated"} {
		if _, ok := m[key]; !ok {
			t.Errorf("JSON missing %q: %s", key, raw)
		}
	}
	node := m["nodes"].([]any)[0].(map[string]any)
	for _, key := range []string{"predicate", "reason", "count", "examples"} {
		if _, ok := node[key]; !ok {
			t.Errorf("node group JSON missing %q: %v", key, node)
		}
	}
}

func TestTolerates(t *testing.T) {
	taint := corev1.Taint{Key: "dedicated", Value: "gpu", Effect: corev1.TaintEffectNoSchedule}
	cases := []struct {
		name string
		tol  corev1.Toleration
		want bool
	}{
		{"equal match", corev1.Toleration{Key: "dedicated", Operator: corev1.TolerationOpEqual, Value: "gpu", Effect: corev1.TaintEffectNoSchedule}, true},
		{"omitted operator is Equal", corev1.Toleration{Key: "dedicated", Value: "gpu"}, true},
		{"value mismatch", corev1.Toleration{Key: "dedicated", Value: "cpu"}, false},
		{"exists any value", corev1.Toleration{Key: "dedicated", Operator: corev1.TolerationOpExists}, true},
		{"empty key exists tolerates all", corev1.Toleration{Operator: corev1.TolerationOpExists}, true},
		{"effect mismatch", corev1.Toleration{Key: "dedicated", Operator: corev1.TolerationOpExists, Effect: corev1.TaintEffectNoExecute}, false},
		{"other key", corev1.Toleration{Key: "spot", Operator: corev1.TolerationOpExists}, false},
	}
	for _, c := range cases {
		if got := tolerates([]corev1.Toleration{c.tol}, taint); got != c.want {
			t.Errorf("%s: tolerates = %v, want %v", c.name, got, c.want)
		}
	}
	numeric := corev1.Taint{Key: "rank", Value: "5", Effect: corev1.TaintEffectNoSchedule}
	if !tolerates([]corev1.Toleration{{Key: "rank", Operator: corev1.TolerationOpGt, Value: "3"}}, numeric) {
		t.Error("Gt 3 should tolerate rank=5")
	}
	if tolerates([]corev1.Toleration{{Key: "rank", Operator: corev1.TolerationOpLt, Value: "3"}}, numeric) {
		t.Error("Lt 3 should not tolerate rank=5")
	}
}

func TestFormatQuantity(t *testing.T) {
	cases := []struct {
		name corev1.ResourceName
		q    string
		want string
	}{
		{corev1.ResourceMemory, "4Gi", "4Gi"},
		{corev1.ResourceMemory, "2254857830", "2.1Gi"},
		{corev1.ResourceMemory, "512", "512"},
		{corev1.ResourceMemory, "-1Gi", "0"},
		{corev1.ResourceCPU, "2", "2"},
		{corev1.ResourceCPU, "250m", "250m"},
		{corev1.ResourcePods, "3", "3"},
		{"hugepages-2Mi", "64Mi", "64Mi"},
	}
	for _, c := range cases {
		if got := formatQuantity(c.name, resource.MustParse(c.q)); got != c.want {
			t.Errorf("formatQuantity(%s, %s) = %q, want %q", c.name, c.q, got, c.want)
		}
	}
}

// The gwas-frontend pod on lab-dev: Pending, PodScheduled=True, bound to a
// node, its container waiting ContainerCreating on a volume that will not
// attach. Nothing about that is the scheduler's doing.
func TestExplainAlreadyScheduledPodIsNotASchedulingProblem(t *testing.T) {
	pod := testPod("gwas-frontend-5dc7fb87d4-b65jw", "100m")
	pod.Namespace = "apps"
	pod.Spec.NodeName = "lab-worker-pool-1"
	pod.Status = corev1.PodStatus{
		Phase: corev1.PodPending,
		Conditions: []corev1.PodCondition{
			{Type: corev1.PodScheduled, Status: corev1.ConditionTrue},
			{Type: corev1.PodReady, Status: corev1.ConditionFalse, Reason: "ContainersNotReady"},
		},
		ContainerStatuses: []corev1.ContainerStatus{{Name: "gwas-frontend",
			State: corev1.ContainerState{Waiting: &corev1.ContainerStateWaiting{Reason: "ContainerCreating"}}}},
	}
	// A cordoned node and a stale scheduler message would both produce a
	// scheduler-blaming verdict if predicates were evaluated.
	cordoned := testNode("lab-worker-pool-1", "4", "8Gi", nil)
	cordoned.Spec.Unschedulable = true
	e := Explain(pod, []*corev1.Node{cordoned}, nil, "0/3 nodes are available: 3 Insufficient cpu.", 0)

	if !e.AlreadyScheduled || e.NodeName != "lab-worker-pool-1" {
		t.Fatalf("AlreadyScheduled=%v NodeName=%q", e.AlreadyScheduled, e.NodeName)
	}
	if want := "Already scheduled to lab-worker-pool-1; this is not a scheduling problem."; e.Verdict != want {
		t.Errorf("Verdict = %q, want %q", e.Verdict, want)
	}
	if len(e.Nodes) != 0 || e.NodesEvaluated != 0 || len(e.Parsed) != 0 || e.SchedulerMessage != "" {
		t.Errorf("no predicate may be evaluated for a bound pod: %+v", e)
	}
	b, _ := json.Marshal(e)
	if !strings.Contains(string(b), `"alreadyScheduled":true`) || !strings.Contains(string(b), `"nodeName":"lab-worker-pool-1"`) {
		t.Errorf("JSON = %s", b)
	}

	// PodScheduled=True alone (binding not yet reflected in spec.nodeName).
	pod.Spec.NodeName = ""
	if e := Explain(pod, nil, nil, "", 0); !e.AlreadyScheduled || e.Verdict != "Already scheduled; this is not a scheduling problem." {
		t.Errorf("PodScheduled=True only: %+v", e)
	}
}
