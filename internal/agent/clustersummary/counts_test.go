package clustersummary

import (
	"encoding/json"
	"strings"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func readyNode(name string, ready corev1.ConditionStatus, unschedulable bool) *corev1.Node {
	n := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: name}, Spec: corev1.NodeSpec{Unschedulable: unschedulable}}
	if ready != "" {
		n.Status.Conditions = []corev1.NodeCondition{{Type: corev1.NodeReady, Status: ready}}
	}
	return n
}

func TestCountsNodes(t *testing.T) {
	got := Counts(CountsInput{Nodes: []*corev1.Node{
		readyNode("ready", corev1.ConditionTrue, false),
		readyNode("cordoned", corev1.ConditionTrue, true),
		readyNode("notready", corev1.ConditionFalse, false),
		// NotReady wins over cordoned: the node is broken, not just drained.
		readyNode("notready-cordoned", corev1.ConditionFalse, true),
		readyNode("unknown", corev1.ConditionUnknown, false),
		readyNode("no-condition", "", false),
	}})
	want := NodeCount{Total: 6, Ready: 1, Cordoned: 1, NotReady: 4}
	if got.Nodes == nil || *got.Nodes != want {
		t.Fatalf("Nodes = %+v, want %+v", got.Nodes, want)
	}
}

func TestCountsWorkloadsAndPods(t *testing.T) {
	got := Counts(CountsInput{
		Pods: []*corev1.Pod{
			{Status: corev1.PodStatus{Phase: corev1.PodRunning}},
			{Status: corev1.PodStatus{Phase: corev1.PodRunning}},
			{Status: corev1.PodStatus{Phase: corev1.PodPending}},
			{Status: corev1.PodStatus{Phase: corev1.PodFailed}},
			{Status: corev1.PodStatus{Phase: corev1.PodSucceeded}},
			{Status: corev1.PodStatus{Phase: corev1.PodUnknown}},
		},
		Deployments: []*appsv1.Deployment{
			{Status: appsv1.DeploymentStatus{Replicas: 3, AvailableReplicas: 3}},
			{Status: appsv1.DeploymentStatus{Replicas: 3, AvailableReplicas: 1}},
			{Status: appsv1.DeploymentStatus{Replicas: 0}},
		},
		StatefulSets: []*appsv1.StatefulSet{
			{Status: appsv1.StatefulSetStatus{Replicas: 2, ReadyReplicas: 2}},
			{Status: appsv1.StatefulSetStatus{Replicas: 2, ReadyReplicas: 0}},
		},
		DaemonSets: []*appsv1.DaemonSet{
			{Status: appsv1.DaemonSetStatus{DesiredNumberScheduled: 4}},
			{Status: appsv1.DaemonSetStatus{DesiredNumberScheduled: 4, NumberUnavailable: 1}},
			{Status: appsv1.DaemonSetStatus{DesiredNumberScheduled: 0}},
		},
		Services:  []*corev1.Service{{}, {}},
		Ingresses: []*networkingv1.Ingress{{}},
	})
	if want := (PodCount{Total: 6, Running: 2, Pending: 1, Failed: 1, Succeeded: 1}); *got.Pods != want {
		t.Errorf("Pods = %+v, want %+v", *got.Pods, want)
	}
	if want := (ReplicaCount{Total: 3, Ready: 1, NotReady: 1, ScaledToZero: 1}); *got.Deployments != want {
		t.Errorf("Deployments = %+v, want %+v", *got.Deployments, want)
	}
	if want := (ReplicaCount{Total: 2, Ready: 1, NotReady: 1}); *got.StatefulSets != want {
		t.Errorf("StatefulSets = %+v, want %+v", *got.StatefulSets, want)
	}
	if want := (ReplicaCount{Total: 3, Ready: 1, NotReady: 1, ScaledToZero: 1}); *got.DaemonSets != want {
		t.Errorf("DaemonSets = %+v, want %+v", *got.DaemonSets, want)
	}
	if *got.Services != 2 || *got.Ingresses != 1 {
		t.Errorf("Services=%d Ingresses=%d", *got.Services, *got.Ingresses)
	}
}

func TestCountsJobsCronJobsPVCs(t *testing.T) {
	suspend := true
	got := Counts(CountsInput{
		Jobs: []*batchv1.Job{
			{Status: batchv1.JobStatus{Active: 1}},
			{Status: batchv1.JobStatus{Succeeded: 5, Conditions: []batchv1.JobCondition{{Type: batchv1.JobComplete, Status: corev1.ConditionTrue}}}},
			{Status: batchv1.JobStatus{Failed: 6, Conditions: []batchv1.JobCondition{{Type: batchv1.JobFailed, Status: corev1.ConditionTrue}}}},
		},
		CronJobs: []*batchv1.CronJob{
			{Spec: batchv1.CronJobSpec{Suspend: &suspend}, Status: batchv1.CronJobStatus{Active: []corev1.ObjectReference{{}}}},
			{Status: batchv1.CronJobStatus{Active: []corev1.ObjectReference{{}}}},
			{},
		},
		PVCs: []*corev1.PersistentVolumeClaim{
			{Status: corev1.PersistentVolumeClaimStatus{Phase: corev1.ClaimBound}},
			{Status: corev1.PersistentVolumeClaimStatus{Phase: corev1.ClaimPending}},
			{Status: corev1.PersistentVolumeClaimStatus{Phase: corev1.ClaimLost}},
		},
	})
	// Jobs are counted as jobs, not as the pods each one ran.
	if want := (JobCount{Total: 3, Active: 1, Succeeded: 1, Failed: 1}); *got.Jobs != want {
		t.Errorf("Jobs = %+v, want %+v", *got.Jobs, want)
	}
	if want := (CronJobCount{Total: 3, Active: 1, Suspended: 1}); *got.CronJobs != want {
		t.Errorf("CronJobs = %+v, want %+v", *got.CronJobs, want)
	}
	if want := (PVCCount{Total: 3, Bound: 1, Pending: 1, Unbound: 1}); *got.PVCs != want {
		t.Errorf("PVCs = %+v, want %+v", *got.PVCs, want)
	}
}

func TestCountsUnavailableKindIsOmittedNotZero(t *testing.T) {
	got := Counts(CountsInput{
		Unavailable: []string{KindNodes, KindConfigMaps, KindNodes},
	})
	if got.Nodes != nil || got.ConfigMaps != nil {
		t.Fatalf("unavailable kinds were counted: nodes=%+v configMaps=%v", got.Nodes, got.ConfigMaps)
	}
	if got.Pods == nil || got.Pods.Total != 0 {
		t.Fatalf("listed-but-empty pods = %+v, want an explicit zero", got.Pods)
	}
	encoded, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	s := string(encoded)
	if strings.Contains(s, `"nodes":`) || strings.Contains(s, `"configMaps":`) {
		t.Fatalf("JSON %s reports a count for an unavailable kind", s)
	}
	if !strings.Contains(s, `"unavailable":["configmaps","nodes"]`) {
		t.Fatalf("JSON %s does not name the unavailable kinds", s)
	}
	if !strings.Contains(s, `"services":0`) {
		t.Fatalf("JSON %s omits a measured zero", s)
	}
}

func TestBuildSummary(t *testing.T) {
	nodes := fleet("v1.30.1", "v1.31.0")
	nodes[0].Status.Conditions = []corev1.NodeCondition{{Type: corev1.NodeReady, Status: corev1.ConditionTrue}}
	deps := []*appsv1.Deployment{testDeployment("ns", "api", "api")}

	got := Build(SummaryInput{
		Counts:   CountsInput{Nodes: nodes, Deployments: deps},
		Coverage: &CoverageInput{Deployments: deps},
	})
	if got.ResourceCounts.Nodes.Total != 2 || got.ResourceCounts.Nodes.Ready != 1 {
		t.Fatalf("nodes = %+v", got.ResourceCounts.Nodes)
	}
	if got.NodeVersionSkew == nil || !got.NodeVersionSkew.Skewed {
		t.Fatalf("skew = %+v, want skewed", got.NodeVersionSkew)
	}
	if got.NetworkPolicyCoverage == nil || got.NetworkPolicyCoverage.TotalWorkloads != 1 {
		t.Fatalf("coverage = %+v", got.NetworkPolicyCoverage)
	}

	unknown := Build(SummaryInput{Counts: CountsInput{Unavailable: []string{KindNodes}}})
	if unknown.NodeVersionSkew != nil || unknown.NetworkPolicyCoverage != nil {
		t.Fatalf("summary invented figures it could not compute: %+v", unknown)
	}
}
