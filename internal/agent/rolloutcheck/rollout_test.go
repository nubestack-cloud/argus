package rolloutcheck

import (
	"strings"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
)

func i32(v int32) *int32 { return &v }

// dep is a settled three-replica Deployment at revision 4.
func dep(edit ...func(*appsv1.Deployment)) *appsv1.Deployment {
	d := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Namespace: "shop", Name: "web", UID: types.UID("dep-uid"), Generation: 7,
			Annotations: map[string]string{revisionAnnotation: "4"}},
		Spec: appsv1.DeploymentSpec{Replicas: i32(3)},
		Status: appsv1.DeploymentStatus{ObservedGeneration: 7, Replicas: 3, UpdatedReplicas: 3, ReadyReplicas: 3, AvailableReplicas: 3,
			Conditions: []appsv1.DeploymentCondition{{Type: appsv1.DeploymentProgressing, Status: corev1.ConditionTrue, Reason: "NewReplicaSetAvailable"}}},
	}
	for _, e := range edit {
		e(d)
	}
	return d
}

func rs(name, revision string) *appsv1.ReplicaSet {
	yes := true
	return &appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{Namespace: "shop", Name: name, Annotations: map[string]string{revisionAnnotation: revision},
		OwnerReferences: []metav1.OwnerReference{{Kind: "Deployment", Name: "web", UID: "dep-uid", Controller: &yes}}}}
}

func pod(name, owner string, readyNow bool, waiting string) *corev1.Pod {
	yes := true
	st := corev1.ConditionFalse
	if readyNow {
		st = corev1.ConditionTrue
	}
	p := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "shop", Name: name, OwnerReferences: []metav1.OwnerReference{{Kind: "ReplicaSet", Name: owner, Controller: &yes}}},
		Spec:   corev1.PodSpec{NodeName: "worker-1"},
		Status: corev1.PodStatus{Phase: corev1.PodPending, Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: st}}}}
	if waiting != "" {
		p.Status.ContainerStatuses = []corev1.ContainerStatus{{State: corev1.ContainerState{Waiting: &corev1.ContainerStateWaiting{Reason: waiting}}}}
	}
	return p
}

func strategy(surge, unavail intstr.IntOrString) func(*appsv1.Deployment) {
	return func(d *appsv1.Deployment) {
		d.Spec.Strategy = appsv1.DeploymentStrategy{Type: appsv1.RollingUpdateDeploymentStrategyType,
			RollingUpdate: &appsv1.RollingUpdateDeployment{MaxSurge: &surge, MaxUnavailable: &unavail}}
	}
}

func TestSettledRolloutReportsTheNextOne(t *testing.T) {
	r := Check(dep(), nil, nil)
	if r.Verdict != VerdictSafe || r.Progress.State != VerdictComplete || r.Strategy != "RollingUpdate" {
		t.Fatalf("got %+v", r)
	}
	// Default 25%/25% on 3 replicas: 0 down, 1 extra.
	if !strings.Contains(r.PolicyReason, "at least 3 of 3") {
		t.Errorf("reason = %q", r.PolicyReason)
	}
}

func TestStuckLeadsWithThePodsHoldingItUp(t *testing.T) {
	d := dep(func(d *appsv1.Deployment) {
		d.Annotations[revisionAnnotation] = "5"
		d.Status.UpdatedReplicas, d.Status.AvailableReplicas, d.Status.Replicas = 1, 2, 4
		d.Status.Conditions[0] = appsv1.DeploymentCondition{Type: appsv1.DeploymentProgressing, Status: corev1.ConditionFalse, Reason: "ProgressDeadlineExceeded", Message: "ReplicaSet web-new has timed out progressing."}
	})
	r := Check(d, []*appsv1.ReplicaSet{rs("web-old", "4"), rs("web-new", "5")},
		[]*corev1.Pod{pod("web-old-a", "web-old", true, ""), pod("web-new-a", "web-new", false, "ImagePullBackOff"), pod("web-new-b", "web-new", true, "")})
	if r.Verdict != VerdictStuck || r.Progress.NewReplicaSet != "web-new" || r.Progress.ConditionReason != "ProgressDeadlineExceeded" {
		t.Fatalf("got %+v", r)
	}
	if !strings.Contains(r.Reason, "ProgressDeadlineExceeded") || !strings.Contains(r.Reason, "ImagePullBackOff") {
		t.Errorf("reason = %q, want the controller's reason and what the pods wait on", r.Reason)
	}
	if len(r.Progress.NotReadyPods) != 1 || r.Progress.NotReadyPods[0].Name != "web-new-a" || r.Progress.NotReadyPods[0].Waiting != "ImagePullBackOff" {
		t.Errorf("pods = %+v (only the new revision's unready pod)", r.Progress.NotReadyPods)
	}
	// The next-rollout answer is still given, beside the live one.
	if r.PolicyVerdict != VerdictSafe {
		t.Errorf("policy = %s", r.PolicyVerdict)
	}
}

func TestLiveStates(t *testing.T) {
	cases := map[string]struct {
		d    *appsv1.Deployment
		want string
	}{
		"paused":                 {dep(func(d *appsv1.Deployment) { d.Spec.Paused = true }), VerdictPaused},
		"spec not yet observed":  {dep(func(d *appsv1.Deployment) { d.Generation = 8 }), VerdictInProgress},
		"old pods still running": {dep(func(d *appsv1.Deployment) { d.Status.Replicas = 4 }), VerdictInProgress},
		"not all available":      {dep(func(d *appsv1.Deployment) { d.Status.AvailableReplicas = 2 }), VerdictInProgress},
	}
	for name, c := range cases {
		if got := Check(c.d, nil, nil).Verdict; got != c.want {
			t.Errorf("%s: verdict %s, want %s", name, got, c.want)
		}
	}
}

func TestNextRolloutRisk(t *testing.T) {
	cases := []struct {
		name     string
		d        *appsv1.Deployment
		want     string
		remedied bool
	}{
		{"maxUnavailable covers every replica", dep(strategy(intstr.FromInt(0), intstr.FromInt(3))), VerdictAtRisk, true},
		{"100% unavailable", dep(strategy(intstr.FromString("25%"), intstr.FromString("100%"))), VerdictAtRisk, true},
		{"recreate", dep(func(d *appsv1.Deployment) {
			d.Spec.Strategy = appsv1.DeploymentStrategy{Type: appsv1.RecreateDeploymentStrategyType}
		}), VerdictAtRisk, true},
		// 0/0 is rejected by the API; the controller moves one at a time.
		{"surge only", dep(strategy(intstr.FromInt(1), intstr.FromInt(0))), VerdictSafe, false},
		{"one replica, defaults", dep(func(d *appsv1.Deployment) {
			d.Spec.Replicas = i32(1)
			d.Status = appsv1.DeploymentStatus{ObservedGeneration: 7, Replicas: 1, UpdatedReplicas: 1, ReadyReplicas: 1, AvailableReplicas: 1}
		}), VerdictNotApplicable, false},
		{"one replica, maxUnavailable 1", dep(func(d *appsv1.Deployment) {
			d.Spec.Replicas = i32(1)
			d.Status = appsv1.DeploymentStatus{ObservedGeneration: 7, Replicas: 1, UpdatedReplicas: 1, ReadyReplicas: 1, AvailableReplicas: 1}
		}, strategy(intstr.FromInt(0), intstr.FromInt(1))), VerdictAtRisk, true},
	}
	for _, c := range cases {
		r := Check(c.d, nil, nil)
		if r.PolicyVerdict != c.want || (c.remedied && (r.Risk == nil || r.Risk.Remediation == "")) {
			t.Errorf("%s: %s %+v", c.name, r.PolicyVerdict, r.Risk)
		}
	}
	one := Check(dep(func(d *appsv1.Deployment) {
		d.Spec.Replicas = i32(1)
		d.Status.AvailableReplicas, d.Status.Replicas, d.Status.UpdatedReplicas = 1, 1, 1
	}), nil, nil)
	if len(one.Notes) != 1 || one.Verdict != VerdictComplete {
		t.Errorf("a settled single replica reads complete, with the drain note: %+v", one)
	}
}

func TestScaledToZeroIsNotApplicable(t *testing.T) {
	r := Check(dep(func(d *appsv1.Deployment) {
		d.Spec.Replicas = i32(0)
		d.Status = appsv1.DeploymentStatus{ObservedGeneration: 7}
	}), nil, nil)
	if r.Verdict != VerdictNotApplicable || r.PolicyVerdict != VerdictNotApplicable {
		t.Fatalf("got %+v", r)
	}
}

func TestNewReplicaSetWithoutRevisionOnDeployment(t *testing.T) {
	d := dep(func(d *appsv1.Deployment) { d.Annotations = nil; d.Status.UpdatedReplicas = 1 })
	r := Check(d, []*appsv1.ReplicaSet{rs("web-a", "2"), rs("web-b", "10")}, nil)
	if r.Progress.NewReplicaSet != "web-b" {
		t.Fatalf("new = %s, want the highest revision", r.Progress.NewReplicaSet)
	}
}

// Owner references without the controller flag still link objects (live on
// a lab cluster: a stuck single-replica rollout whose references had none).
func TestOwnersWithoutTheControllerFlag(t *testing.T) {
	d := dep(func(d *appsv1.Deployment) { d.Status.UpdatedReplicas, d.Status.Replicas = 2, 4 })
	r := rs("web-new", "4")
	r.OwnerReferences[0].Controller = nil
	p := pod("web-new-a", "web-new", false, "ContainerCreating")
	p.OwnerReferences[0].Controller = nil
	got := Check(d, []*appsv1.ReplicaSet{r}, []*corev1.Pod{p})
	if got.Progress.NewReplicaSet != "web-new" || len(got.Progress.NotReadyPods) != 1 {
		t.Fatalf("got %+v", got.Progress)
	}
}
