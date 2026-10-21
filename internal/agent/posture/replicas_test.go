package posture

import (
	"slices"
	"strings"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	autoscalingv2 "k8s.io/api/autoscaling/v2"
	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
)

func TestSingleReplica(t *testing.T) {
	scaler := &autoscalingv2.HorizontalPodAutoscaler{ObjectMeta: meta("shop", "cart-hpa")}
	scaler.Spec.ScaleTargetRef = autoscalingv2.CrossVersionObjectReference{Kind: "Deployment", Name: "cart"}
	in := listedEverything()
	in.Deployments = []*appsv1.Deployment{
		deployment("shop", "cart", 1, tidySpec("api")),     // autoscaled: out of scope
		deployment("shop", "checkout", 1, tidySpec("api")), // fails
		deployment("shop", "parked", 0, tidySpec("api")),   // fails: no spare replica either
		deployment("shop", "catalog", 3, tidySpec("api")),
	}
	in.HorizontalPodAutoscalers = []*autoscalingv2.HorizontalPodAutoscaler{scaler}
	r := RunChecks(in)
	if got := findingNames(r.Findings, "singleReplica"); len(got) != 2 || !got["checkout"] || !got["parked"] {
		t.Errorf("flagged %v", got)
	}
	if c := r.CheckCounts["singleReplica"]; c != (CheckCount{Evaluated: 3, Passed: 1}) {
		t.Errorf("counts %+v: the autoscaled Deployment is neither pass nor fail", c)
	}

	in.HorizontalPodAutoscalers = nil
	r = RunChecks(in)
	if _, ran := r.CheckCounts["singleReplica"]; ran || !slices.Contains(r.MissingInputs, "horizontalpodautoscalers") {
		t.Error("without the autoscaler list the check must not run")
	}
}

func TestDisruptionBudgets(t *testing.T) {
	budget := func(ns string, sel *metav1.LabelSelector) *policyv1.PodDisruptionBudget {
		return &policyv1.PodDisruptionBudget{ObjectMeta: meta(ns, "budget"), Spec: policyv1.PodDisruptionBudgetSpec{Selector: sel}}
	}
	selects := func(app string) *metav1.LabelSelector {
		return &metav1.LabelSelector{MatchLabels: map[string]string{"app": app}}
	}
	for _, tc := range []struct {
		why     string
		budgets []*policyv1.PodDisruptionBudget
		fails   bool
	}{
		{"no budgets", []*policyv1.PodDisruptionBudget{}, true},
		{"a budget selecting it", []*policyv1.PodDisruptionBudget{budget("shop", selects("cart"))}, false},
		{"a budget selecting something else", []*policyv1.PodDisruptionBudget{budget("shop", selects("search"))}, true},
		{"a matching budget in another namespace", []*policyv1.PodDisruptionBudget{budget("staging", selects("cart"))}, true},
		{"an empty selector selects everything", []*policyv1.PodDisruptionBudget{budget("shop", &metav1.LabelSelector{})}, false},
		{"a budget with no selector selects nothing", []*policyv1.PodDisruptionBudget{budget("shop", nil)}, true},
		{"an expression selector", []*policyv1.PodDisruptionBudget{budget("shop", &metav1.LabelSelector{
			MatchExpressions: []metav1.LabelSelectorRequirement{{Key: "app", Operator: metav1.LabelSelectorOpIn, Values: []string{"cart", "search"}}},
		})}, false},
	} {
		in := listedEverything()
		in.Deployments = []*appsv1.Deployment{deployment("shop", "cart", 3, tidySpec("api")), deployment("shop", "solo", 1, tidySpec("api"))}
		in.StatefulSets = []*appsv1.StatefulSet{}
		in.PodDisruptionBudgets = tc.budgets
		r := RunChecks(in)
		got := findingNames(r.Findings, "missingPDB")
		if got["cart"] != tc.fails || got["solo"] || r.CheckCounts["missingPDB"].Evaluated != 1 {
			t.Errorf("%s: flagged %v, counts %+v", tc.why, got, r.CheckCounts["missingPDB"])
		}
	}
}

func TestTopologySpread(t *testing.T) {
	spread := tidySpec("db")
	spread.TopologySpreadConstraints = []corev1.TopologySpreadConstraint{{MaxSkew: 1, TopologyKey: "topology.kubernetes.io/zone", WhenUnsatisfiable: corev1.ScheduleAnyway}}
	in := listedEverything()
	in.Deployments = []*appsv1.Deployment{deployment("shop", "cart", 3, tidySpec("api")), deployment("shop", "solo", 1, tidySpec("api"))}
	in.StatefulSets = []*appsv1.StatefulSet{statefulSet("shop", "orders-db", 3, spread), statefulSet("shop", "cache", 2, tidySpec("redis"))}
	r := RunChecks(in)
	want := []string{"missingTopologySpread@Deployment/shop/cart", "missingTopologySpread@StatefulSet/shop/cache"}
	var got []string
	for _, f := range failing(r) {
		if strings.HasPrefix(f, "missingTopologySpread@") {
			got = append(got, f)
		}
	}
	if !slices.Equal(got, want) || r.CheckCounts["missingTopologySpread"].Evaluated != 3 {
		t.Errorf("flagged %v (counts %+v), want %v", got, r.CheckCounts["missingTopologySpread"], want)
	}
}

// fleet builds a Deployment with a ReplicaSet and running pods on the named
// nodes, all tied together by UID.
type fleet struct {
	deployments []*appsv1.Deployment
	sets        []*appsv1.ReplicaSet
	pods        []*corev1.Pod
}

func (f *fleet) deploy(ns, name string, replicas int32, nodes ...string) *fleet {
	d := deployment(ns, name, replicas, tidySpec("api"))
	d.UID = types.UID("uid-" + ns + "-" + name)
	rs := &appsv1.ReplicaSet{ObjectMeta: meta(ns, name+"-5f7c")}
	rs.UID = types.UID("uid-" + ns + "-" + rs.Name)
	owned(&rs.ObjectMeta, "Deployment", name, d.UID)
	f.deployments = append(f.deployments, d)
	f.sets = append(f.sets, rs)
	for i, node := range nodes {
		p := pod(ns, rs.Name+"-"+string(rune('a'+i)), nil, tidySpec("api"))
		p.Spec.NodeName = node
		owned(&p.ObjectMeta, "ReplicaSet", rs.Name, rs.UID)
		f.pods = append(f.pods, p)
	}
	return f
}

func (f *fleet) stray(ns, rsName string, uid types.UID, node string) *fleet {
	p := pod(ns, rsName+"-zz", nil, tidySpec("api"))
	p.Spec.NodeName = node
	owned(&p.ObjectMeta, "ReplicaSet", rsName, uid)
	f.pods = append(f.pods, p)
	return f
}

func (f *fleet) scan() *ScanResults {
	in := listedEverything()
	in.Deployments, in.ReplicaSets, in.Pods = f.deployments, f.sets, f.pods
	return RunChecks(in)
}

func TestColocatedReplicas(t *testing.T) {
	for _, tc := range []struct {
		why       string
		fleet     *fleet
		flagged   []string
		evaluated int
		gap       bool
	}{
		{"spread over two nodes", new(fleet).deploy("shop", "cart", 2, "n1", "n2"), nil, 1, false},
		{"both on one node", new(fleet).deploy("shop", "cart", 2, "n1", "n1"), []string{"cart"}, 1, false},
		{"only one pod running yet", new(fleet).deploy("shop", "cart", 2, "n1"), nil, 0, false},
		{"one replica wanted", new(fleet).deploy("shop", "cart", 1, "n1", "n1"), nil, 0, false},
		{"pending pods do not count", func() *fleet {
			f := new(fleet).deploy("shop", "cart", 3, "n1", "n1", "n2")
			f.pods[2].Status.Phase = corev1.PodPending
			return f
		}(), []string{"cart"}, 1, false},
		{"a terminating pod does not count", func() *fleet {
			f := new(fleet).deploy("shop", "cart", 3, "n1", "n1", "n2")
			f.pods[2].DeletionTimestamp = &metav1.Time{}
			return f
		}(), []string{"cart"}, 1, false},
		// A pod pointing at a ReplicaSet name with the wrong UID belongs to
		// something we cannot see; in its namespace co-location is unknown.
		{"an unresolved pod hides co-location", new(fleet).deploy("shop", "cart", 2, "n1", "n1").stray("shop", "cart-5f7c", "old-uid", "n2"), nil, 0, true},
		{"an unresolved pod cannot undo proven spread", new(fleet).deploy("shop", "cart", 2, "n1", "n2").stray("shop", "cart-5f7c", "old-uid", "n1"), nil, 1, false},
		{"an unresolved pod elsewhere changes nothing", new(fleet).deploy("shop", "cart", 2, "n1", "n1").stray("staging", "cart-5f7c", "old-uid", "n2"), []string{"cart"}, 1, false},
		{"two deployments judged apart", new(fleet).deploy("shop", "cart", 2, "n1", "n1").deploy("shop", "search", 2, "n1", "n2"), []string{"cart"}, 2, false},
	} {
		r := tc.fleet.scan()
		var got []string
		for name := range findingNames(r.Findings, "podHARisk") {
			got = append(got, name)
		}
		slices.Sort(got)
		if !slices.Equal(got, tc.flagged) || r.CheckCounts["podHARisk"].Evaluated != tc.evaluated || slices.Contains(r.MissingInputs, "replicaset-ownership") != tc.gap {
			t.Errorf("%s: flagged %v, counts %+v, missing %v", tc.why, got, r.CheckCounts["podHARisk"], r.MissingInputs)
		}
	}

	// A Deployment whose UID differs from what the ReplicaSet names (one
	// deleted and recreated under the same name) owns none of those pods.
	f := new(fleet).deploy("shop", "cart", 2, "n1", "n1")
	f.deployments[0].UID = "uid-recreated"
	if r := f.scan(); len(findingNames(r.Findings, "podHARisk")) != 0 {
		t.Error("pods of a previous incarnation were counted")
	}
}

func TestRolloutRisk(t *testing.T) {
	num, pct := intstr.FromInt32, intstr.FromString
	rolling := func(surge, down intstr.IntOrString) appsv1.DeploymentStrategy {
		return appsv1.DeploymentStrategy{Type: appsv1.RollingUpdateDeploymentStrategyType, RollingUpdate: &appsv1.RollingUpdateDeployment{MaxSurge: &surge, MaxUnavailable: &down}}
	}
	for _, tc := range []struct {
		why      string
		replicas int32
		strategy appsv1.DeploymentStrategy
		judged   bool
		risky    bool
	}{
		{"defaults", 4, appsv1.DeploymentStrategy{}, true, false},
		{"every replica may go, no surge", 4, rolling(num(0), num(4)), true, true},
		{"more than every replica", 4, rolling(num(0), num(9)), true, true},
		{"as percentages", 4, rolling(pct("0%"), pct("100%")), true, true},
		{"one surge pod saves it", 4, rolling(num(1), num(4)), true, false},
		{"a small percentage surge rounds up to one", 4, rolling(pct("1%"), pct("100%")), true, false},
		{"one replica kept", 4, rolling(num(0), num(3)), true, false},
		// 99% of 4 rounds down to 3, so one old replica stays.
		{"unavailability rounds down", 4, rolling(pct("0%"), pct("99%")), true, false},
		// Both zero would deadlock; the controller lets one go.
		{"both zero means one", 1, rolling(num(0), num(0)), false, false},
		{"both zero over two", 2, rolling(num(0), num(0)), true, false},
		{"one field unset", 4, appsv1.DeploymentStrategy{RollingUpdate: &appsv1.RollingUpdateDeployment{MaxUnavailable: ptr(num(4))}}, true, false},
		{"unparseable surge", 4, rolling(pct("lots"), pct("100%")), true, false},
		{"recreate is replacement on purpose", 4, appsv1.DeploymentStrategy{Type: appsv1.RecreateDeploymentStrategyType}, false, false},
		{"one replica has nothing to keep", 1, rolling(num(0), num(1)), false, false},
	} {
		d := deployment("shop", "cart", tc.replicas, tidySpec("api"))
		d.Spec.Strategy = tc.strategy
		in := listedEverything()
		in.Deployments = []*appsv1.Deployment{d}
		r := RunChecks(in)
		judged := r.CheckCounts["rolloutAvailabilityRisk"].Evaluated == 1
		f := findingFor(r, "rolloutAvailabilityRisk", "cart")
		if judged != tc.judged || (f != nil) != tc.risky {
			t.Errorf("%s: judged %v risky %v", tc.why, judged, f != nil)
		}
		if f != nil && !strings.Contains(f.Message, "zero available pods") {
			t.Errorf("%s: message %q", tc.why, f.Message)
		}
	}
}
