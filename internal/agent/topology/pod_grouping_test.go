package topology

import (
	"fmt"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func labelled(ns, name string, labels map[string]string, owners ...metav1.OwnerReference) *corev1.Pod {
	return &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name, Labels: labels, OwnerReferences: owners}}
}

func groupKeys(groups map[string]*PodGroup) map[string]int {
	out := map[string]int{}
	for k, g := range groups {
		out[k] = len(g.Pods)
	}
	return out
}

// Runs that share an app label still get a group each: merging two Workflow
// runs or two Job runs would show one run's failure as the other's.
func TestRunsGroupApartDespiteASharedAppLabel(t *testing.T) {
	pods := []*corev1.Pod{
		labelled("batch", "etl-0412-a", map[string]string{"app.kubernetes.io/name": "etl", "workflows.argoproj.io/workflow": "etl-0412"}),
		labelled("batch", "etl-0413-a", map[string]string{"app.kubernetes.io/name": "etl", "workflows.argoproj.io/workflow": "etl-0413"}),
		labelled("batch", "backup-1-x", map[string]string{"app": "backup", "job-name": "backup-1"}),
		labelled("batch", "backup-2-x", map[string]string{"app": "backup", "batch.kubernetes.io/job-name": "backup-2"}),
	}
	got := groupKeys(GroupPods(pods, BuildOptions{}, testNow))
	want := map[string]int{"batch/Workflow/etl-0412": 1, "batch/Workflow/etl-0413": 1, "batch/Job/backup-1": 1, "batch/Job/backup-2": 1}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("groups = %v, want %v", got, want)
	}
}

func TestPodGroupOfPrecedence(t *testing.T) {
	rs := controllerRef("apps/v1", "ReplicaSet", "cart-7d9")
	loose := metav1.OwnerReference{Kind: "ReplicaSet", Name: "someone-else"}
	cases := []struct {
		labels  map[string]string
		byOwner bool
		kind    string
		name    string
	}{
		{map[string]string{"job-name": "j", "workflows.argoproj.io/workflow": "w"}, false, "Workflow", "w"},
		{map[string]string{"job-name": "legacy", "batch.kubernetes.io/job-name": "current"}, false, "Job", "current"},
		{map[string]string{"app": "a", "job-name": "j"}, false, "Job", "j"},
		{map[string]string{"app": "a", "app.kubernetes.io/name": "n"}, false, "app", "n"},
		{map[string]string{"app": "a"}, false, "app", "a"},
		// Owner grouping skips the app labels but not the run labels.
		{map[string]string{"app.kubernetes.io/name": "n", "app": "a"}, true, "ReplicaSet", "cart-7d9"},
		{map[string]string{"app": "a", "job-name": "j"}, true, "Job", "j"},
		{nil, false, "ReplicaSet", "cart-7d9"},
	}
	for _, c := range cases {
		pod := labelled("shop", "cart-7d9-x1", c.labels, loose, rs)
		if kind, name := podGroupOf(pod, c.byOwner); kind != c.kind || name != c.name {
			t.Errorf("labels %v byOwner=%v: %s/%s, want %s/%s", c.labels, c.byOwner, kind, name, c.kind, c.name)
		}
	}
	// A non-controller owner does not make a pod part of its group.
	if kind, name := podGroupOf(labelled("shop", "debug", nil, loose), false); kind != "standalone" || name != "debug" {
		t.Errorf("lone pod = %s/%s", kind, name)
	}
}

func TestGroupPodsFiltersNamespacesAndTallies(t *testing.T) {
	failing := runningPod("prod", "web-2", "", map[string]string{"app": "web"})
	failing.Status.ContainerStatuses[0].Ready = false
	failing.Status.ContainerStatuses[0].State = corev1.ContainerState{Waiting: &corev1.ContainerStateWaiting{Reason: "CrashLoopBackOff"}}
	groups := GroupPods([]*corev1.Pod{
		runningPod("prod", "web-1", "", map[string]string{"app": "web"}),
		failing,
		runningPod("staging", "web-1", "", map[string]string{"app": "web"}),
	}, BuildOptions{Namespaces: []string{"prod"}}, testNow)
	if got := groupKeys(groups); len(got) != 1 || got["prod/app/web"] != 2 {
		t.Fatalf("groups = %v", got)
	}
	if c := groups["prod/app/web"].Counts; c != (podTally{Healthy: 1, Unhealthy: 1}) || c.status() != StatusUnhealthy {
		t.Errorf("tally = %+v (%s)", c, c.status())
	}
}

// A member's status is the pod's computed one, not its phase: the pod here
// reports Running while it crash-loops.
func TestGroupMembersCarryComputedStatus(t *testing.T) {
	pod := runningPod("prod", "api-1", "", nil)
	pod.Status.ContainerStatuses[0].Ready = false
	pod.Status.ContainerStatuses[0].RestartCount = 9
	pod.Status.ContainerStatuses[0].State = corev1.ContainerState{Waiting: &corev1.ContainerStateWaiting{Reason: "CrashLoopBackOff"}}
	g := &PodGroup{Key: "prod/Deployment/api", GroupName: "api", Namespace: "prod", Pods: []*corev1.Pod{pod}}
	g.Counts = tallyPods(g.Pods, testNow)

	n := newPodGroupNode(g, testNow)
	members := n.Summary["pods"].([]map[string]any)
	if len(members) != 1 || members[0]["status"] != string(StatusUnhealthy) || members[0]["statusReason"] != "CrashLoopBackOff" {
		t.Fatalf("members = %v", members)
	}
	if n.ID != "podgroup-prod-Deployment-api" || n.Status != StatusUnhealthy || n.StatusReason != "CrashLoopBackOff" || n.Summary["totalRestarts"] != int32(9) {
		t.Errorf("node = %s %s/%s restarts=%v", n.ID, n.Status, n.StatusReason, n.Summary["totalRestarts"])
	}
}

// The list is cut at the limit but sorted worst first, so the one failed pod
// of twenty is never the one dropped; the count still covers all twenty.
func TestGroupMemberListKeepsTheWorst(t *testing.T) {
	g := &PodGroup{Key: "prod/app/web", GroupName: "web", Namespace: "prod"}
	for i := range 20 {
		g.Pods = append(g.Pods, runningPod("prod", fmt.Sprintf("web-%02d", i), "", nil))
	}
	g.Pods[17].Status.Phase = corev1.PodFailed
	g.Counts = tallyPods(g.Pods, testNow)

	n := newPodGroupNode(g, testNow)
	members := n.Summary["pods"].([]map[string]any)
	if len(members) != podGroupListLimit || members[0]["name"] != "web-17" {
		t.Fatalf("listed %d, first %v", len(members), members[0])
	}
	if n.Summary["podCount"] != 20 || n.Summary["unhealthy"] != 1 || n.Summary["healthy"] != 19 {
		t.Errorf("summary = %v", n.Summary)
	}
}
