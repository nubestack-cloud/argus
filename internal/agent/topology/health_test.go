package topology

import (
	"strconv"
	"strings"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	autoscalingv2 "k8s.io/api/autoscaling/v2"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// podStatus reads container state, not just the phase, and folds the
// unschedulable / stuck-terminating signals in as a floor.
func TestPodStatusInspectsContainers(t *testing.T) {
	crashloop := &corev1.Pod{Status: corev1.PodStatus{
		Phase: corev1.PodRunning,
		ContainerStatuses: []corev1.ContainerStatus{
			{State: corev1.ContainerState{Waiting: &corev1.ContainerStateWaiting{Reason: "CrashLoopBackOff"}}},
		},
	}}
	stuck := metav1.NewTime(testNow.Add(-11 * time.Minute))
	for _, tc := range []struct {
		name       string
		pod        *corev1.Pod
		want       HealthStatus
		wantReason string
	}{
		{"crashloop", crashloop, StatusUnhealthy, "CrashLoopBackOff"},
		{"ready", &corev1.Pod{Status: corev1.PodStatus{Phase: corev1.PodRunning, ContainerStatuses: []corev1.ContainerStatus{{Ready: true}}}}, StatusHealthy, ""},
		{"completed is neutral", &corev1.Pod{Status: corev1.PodStatus{Phase: corev1.PodSucceeded}}, StatusNeutral, "Completed"},
		{"unschedulable is degraded even when young", &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{CreationTimestamp: metav1.NewTime(testNow.Add(-time.Minute))},
			Status: corev1.PodStatus{
				Phase:      corev1.PodPending,
				Conditions: []corev1.PodCondition{{Type: corev1.PodScheduled, Status: corev1.ConditionFalse, Reason: corev1.PodReasonUnschedulable}},
			},
		}, StatusDegraded, "Unschedulable"},
		{"node lost is unknown", &corev1.Pod{Status: corev1.PodStatus{Phase: corev1.PodUnknown}}, StatusUnknown, ""},
		{"stuck terminating is degraded", &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{DeletionTimestamp: &stuck},
			Status:     corev1.PodStatus{Phase: corev1.PodRunning, ContainerStatuses: []corev1.ContainerStatus{{Ready: true}}},
		}, StatusDegraded, "StuckTerminating"},
		{"stuck terminating does not soften a crashloop", &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{DeletionTimestamp: &stuck},
			Status:     crashloop.Status,
		}, StatusUnhealthy, "CrashLoopBackOff"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, reason := podStatus(tc.pod, testNow)
			if got != tc.want || reason != tc.wantReason {
				t.Errorf("podStatus = %s/%q, want %s/%q", got, reason, tc.want, tc.wantReason)
			}
		})
	}
}

// The PodGroup counters bucket differently from node status: a completed pod
// counts healthy, an unknown one unhealthy.
func TestPodSummaryStatusBuckets(t *testing.T) {
	for _, tc := range []struct {
		name string
		pod  *corev1.Pod
		want HealthStatus
	}{
		{"crashloop", &corev1.Pod{Status: corev1.PodStatus{Phase: corev1.PodRunning, ContainerStatuses: []corev1.ContainerStatus{
			{State: corev1.ContainerState{Waiting: &corev1.ContainerStateWaiting{Reason: "CrashLoopBackOff"}}},
		}}}, StatusUnhealthy},
		{"completed", &corev1.Pod{Status: corev1.PodStatus{Phase: corev1.PodSucceeded}}, StatusHealthy},
		{"ready", &corev1.Pod{Status: corev1.PodStatus{Phase: corev1.PodRunning, ContainerStatuses: []corev1.ContainerStatus{{Ready: true}}}}, StatusHealthy},
		{"node lost", &corev1.Pod{Status: corev1.PodStatus{Phase: corev1.PodUnknown}}, StatusUnhealthy},
	} {
		if got := podSummaryStatus(tc.pod, testNow); got != tc.want {
			t.Errorf("%s: podSummaryStatus = %s, want %s", tc.name, got, tc.want)
		}
	}
}

func TestWorkloadStatusPVCAndJob(t *testing.T) {
	pending := &corev1.PersistentVolumeClaim{Status: corev1.PersistentVolumeClaimStatus{Phase: corev1.ClaimPending}}
	if got, _ := workloadStatus(pending, testNow); got != StatusNeutral {
		t.Errorf("pending PVC = %s, want neutral", got)
	}
	bound := &corev1.PersistentVolumeClaim{Status: corev1.PersistentVolumeClaimStatus{Phase: corev1.ClaimBound}}
	if got, _ := workloadStatus(bound, testNow); got != StatusHealthy {
		t.Errorf("bound PVC = %s, want healthy", got)
	}
	failed := &batchv1.Job{Status: batchv1.JobStatus{Conditions: []batchv1.JobCondition{{Type: batchv1.JobFailed, Status: corev1.ConditionTrue}}}}
	if got, reason := workloadStatus(failed, testNow); got != StatusUnhealthy || reason != "Failed" {
		t.Errorf("failed job = %s/%s, want unhealthy/Failed", got, reason)
	}
	complete := &batchv1.Job{Status: batchv1.JobStatus{Conditions: []batchv1.JobCondition{{Type: batchv1.JobComplete, Status: corev1.ConditionTrue}}}}
	if got, _ := workloadStatus(complete, testNow); got != StatusNeutral {
		t.Errorf("completed job = %s, want neutral", got)
	}
}

func TestNodeStatus(t *testing.T) {
	ready := &corev1.Node{Status: corev1.NodeStatus{Conditions: []corev1.NodeCondition{{Type: corev1.NodeReady, Status: corev1.ConditionTrue}}}}
	if got, _ := nodeStatus(ready); got != StatusHealthy {
		t.Errorf("ready node = %s, want healthy", got)
	}
	cordoned := ready.DeepCopy()
	cordoned.Spec.Unschedulable = true
	if got, reason := nodeStatus(cordoned); got != StatusDegraded || reason != "Cordoned" {
		t.Errorf("ready+cordoned node = %s/%s, want degraded/Cordoned", got, reason)
	}
	notReady := &corev1.Node{Status: corev1.NodeStatus{Conditions: []corev1.NodeCondition{{Type: corev1.NodeReady, Status: corev1.ConditionFalse}}}}
	if got, _ := nodeStatus(notReady); got != StatusUnhealthy {
		t.Errorf("not-ready node = %s, want unhealthy", got)
	}
}

func TestPVStatus(t *testing.T) {
	for phase, want := range map[corev1.PersistentVolumePhase]HealthStatus{
		corev1.VolumeBound: StatusHealthy, corev1.VolumeAvailable: StatusNeutral,
		corev1.VolumeReleased: StatusDegraded, corev1.VolumeFailed: StatusUnhealthy, "": StatusUnknown,
	} {
		if got, _ := pvStatus(&corev1.PersistentVolume{Status: corev1.PersistentVolumeStatus{Phase: phase}}); got != want {
			t.Errorf("PV %q = %s, want %s", phase, got, want)
		}
	}
}

// route builds an HTTPRoute at generation gen whose status has one parent
// per spec. A spec lists that parent's conditions as "Type=Status@observed",
// space separated; "" is a parent that has reported nothing.
func route(gen int64, specs ...string) *unstructured.Unstructured {
	parents := []any{}
	for _, spec := range specs {
		conds := []any{}
		for _, c := range strings.Fields(spec) {
			typ, rest, _ := strings.Cut(c, "=")
			status, at, _ := strings.Cut(rest, "@")
			observed, _ := strconv.ParseInt(at, 10, 64)
			conds = append(conds, map[string]any{"type": typ, "status": status, "observedGeneration": observed})
		}
		parents = append(parents, map[string]any{"conditions": conds})
	}
	return &unstructured.Unstructured{Object: map[string]any{
		"metadata": map[string]any{"generation": gen},
		"status":   map[string]any{"parents": parents},
	}}
}

// A route is healthy only when every parent has accepted the current spec
// and resolved its backends; a rejection everywhere is unhealthy; anything
// partial — one parent out of several, a stale or silent parent, refs not
// yet resolved — is degraded; and with no current evidence at all, unknown.
func TestRouteStatus(t *testing.T) {
	const ok = "Accepted=True@4 ResolvedRefs=True@4"
	for want, routes := range map[HealthStatus][]*unstructured.Unstructured{
		StatusHealthy:   {route(4, ok)},
		StatusUnhealthy: {route(4, "Accepted=False@4")},
		StatusDegraded: {
			// Being accepted says nothing about whether the backends exist.
			route(4, "Accepted=True@4 ResolvedRefs=False@4"),
			route(4, "Accepted=True@4"),
			route(4, ok, "Accepted=False@4"),
			// A parent that reported cannot vouch for one that has not, or
			// whose report predates the current spec.
			route(4, ok, ""),
			route(4, ok, "Accepted=False@2"),
			// Rejected once and unassessed elsewhere is not yet a total failure.
			route(4, "Accepted=False@4", ""),
		},
		StatusUnknown: {
			route(4),
			route(4, "Accepted=True@2 ResolvedRefs=True@2"),
		},
	} {
		for _, r := range routes {
			if got, _ := routeStatus(r); got != want {
				t.Errorf("%v: %s, want %s", r.Object["status"], got, want)
			}
		}
	}
}

func TestGatewayStatus(t *testing.T) {
	// A Gateway reports its own conditions, not per parent; reuse the route
	// spec syntax for the one list.
	gw := func(spec string) *unstructured.Unstructured {
		r := route(1, spec)
		conds := r.Object["status"].(map[string]any)["parents"].([]any)[0].(map[string]any)["conditions"]
		return &unstructured.Unstructured{Object: map[string]any{"status": map[string]any{"conditions": conds}}}
	}
	for spec, want := range map[string]HealthStatus{
		"Accepted=True@1 Programmed=True@1":  StatusHealthy,
		"Accepted=True@1 Programmed=False@1": StatusDegraded,
		"Accepted=False@1":                   StatusUnhealthy,
		"":                                   StatusUnknown,
	} {
		if got, _ := gatewayStatus(gw(spec)); got != want {
			t.Errorf("gateway %q: %s, want %s", spec, got, want)
		}
	}
}

func hpaWith(conds ...autoscalingv2.HorizontalPodAutoscalerCondition) *autoscalingv2.HorizontalPodAutoscaler {
	minReplicas := int32(1)
	return &autoscalingv2.HorizontalPodAutoscaler{
		ObjectMeta: metav1.ObjectMeta{Name: "web", Namespace: "prod"},
		Spec:       autoscalingv2.HorizontalPodAutoscalerSpec{MinReplicas: &minReplicas, MaxReplicas: 10},
		Status: autoscalingv2.HorizontalPodAutoscalerStatus{
			CurrentReplicas: 2,
			DesiredReplicas: 2,
			Conditions:      conds,
		},
	}
}

// An HPA is downgraded only on negative evidence: routine scaling is not a
// problem.
func TestHPAStatus(t *testing.T) {
	able := autoscalingv2.HorizontalPodAutoscalerCondition{Type: autoscalingv2.AbleToScale, Status: corev1.ConditionTrue}
	active := autoscalingv2.HorizontalPodAutoscalerCondition{Type: autoscalingv2.ScalingActive, Status: corev1.ConditionTrue}

	t.Run("cannot fetch metrics", func(t *testing.T) {
		hpa := hpaWith(able, autoscalingv2.HorizontalPodAutoscalerCondition{Type: autoscalingv2.ScalingActive, Status: corev1.ConditionFalse, Reason: "FailedGetResourceMetric"})
		if got, reason := hpaStatus(hpa); got != StatusUnhealthy || reason != "MetricsUnavailable" {
			t.Errorf("hpaStatus = %s/%s", got, reason)
		}
	})
	t.Run("cannot scale", func(t *testing.T) {
		hpa := hpaWith(autoscalingv2.HorizontalPodAutoscalerCondition{Type: autoscalingv2.AbleToScale, Status: corev1.ConditionFalse, Reason: "FailedGetScale"})
		if got, _ := hpaStatus(hpa); got != StatusUnhealthy {
			t.Errorf("hpaStatus = %s, want unhealthy", got)
		}
	})
	t.Run("healthy", func(t *testing.T) {
		if got, _ := hpaStatus(hpaWith(able, active)); got != StatusHealthy {
			t.Errorf("hpaStatus = %s, want healthy", got)
		}
	})
	t.Run("routine scaling is not a problem", func(t *testing.T) {
		hpa := hpaWith(able, active)
		hpa.Status.DesiredReplicas = 5
		if got, _ := hpaStatus(hpa); got == StatusUnhealthy || got == StatusDegraded {
			t.Errorf("hpaStatus = %s, want scaling not reported as a problem", got)
		}
	})
	t.Run("capped at max", func(t *testing.T) {
		hpa := hpaWith(able, active, autoscalingv2.HorizontalPodAutoscalerCondition{
			Type: autoscalingv2.ScalingLimited, Status: corev1.ConditionTrue, Reason: "TooManyReplicas",
		})
		if got, reason := hpaStatus(hpa); got != StatusDegraded || reason != "LimitedMax" {
			t.Errorf("hpaStatus = %s/%s, want degraded/LimitedMax", got, reason)
		}
	})
	t.Run("held at min is intentional", func(t *testing.T) {
		hpa := hpaWith(able, active, autoscalingv2.HorizontalPodAutoscalerCondition{
			Type: autoscalingv2.ScalingLimited, Status: corev1.ConditionTrue, Reason: "TooFewReplicas",
		})
		if got, _ := hpaStatus(hpa); got != StatusNeutral {
			t.Errorf("hpaStatus = %s, want neutral", got)
		}
	})
	t.Run("unreconciled says nothing", func(t *testing.T) {
		if got, _ := hpaStatus(hpaWith()); got != StatusUnknown {
			t.Errorf("hpaStatus = %s, want unknown", got)
		}
	})
	t.Run("deliberately idle", func(t *testing.T) {
		zero := int32(0)
		hpa := hpaWith(able, autoscalingv2.HorizontalPodAutoscalerCondition{Type: autoscalingv2.ScalingActive, Status: corev1.ConditionFalse, Reason: "ScalingDisabled"})
		hpa.Spec.MinReplicas = &zero
		hpa.Status.CurrentReplicas, hpa.Status.DesiredReplicas = 0, 0
		if got, _ := hpaStatus(hpa); got != StatusNeutral {
			t.Errorf("hpaStatus = %s, want neutral", got)
		}
	})
	t.Run("nil", func(t *testing.T) {
		if got, _ := hpaStatus(nil); got != StatusUnknown {
			t.Errorf("hpaStatus(nil) = %s, want unknown", got)
		}
	})
}

// A Deployment whose rollout has stalled (Progressing=False) while the old
// replicas keep serving grades Degraded on the map — the same word the object
// panel shows for it — not Healthy from the replica counts alone.
func TestWorkloadStatusStalledDeploymentIsDegraded(t *testing.T) {
	one := int32(1)
	d := &appsv1.Deployment{
		Spec: appsv1.DeploymentSpec{Replicas: &one},
		Status: appsv1.DeploymentStatus{ReadyReplicas: 1, AvailableReplicas: 1, Conditions: []appsv1.DeploymentCondition{
			{Type: appsv1.DeploymentProgressing, Status: corev1.ConditionFalse, Reason: "ProgressDeadlineExceeded"},
		}},
	}
	status, reason := workloadStatus(d, time.Now())
	if status != StatusDegraded || reason != "ProgressDeadlineExceeded" {
		t.Fatalf("got %s/%s, want degraded/ProgressDeadlineExceeded", status, reason)
	}
}
