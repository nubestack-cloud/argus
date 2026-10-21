package agent

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"testing"
	"time"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	appsv1 "k8s.io/api/apps/v1"
	autoscalingv2 "k8s.io/api/autoscaling/v2"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	k8sfake "k8s.io/client-go/kubernetes/fake"

	"argus/internal/objdiff"
	"argus/internal/tunnel"
)

var errAlwaysFails = errors.New("always fails")

func int32ptr(v int32) *int32 { return &v }
func boolptr(v bool) *bool    { return &v }

func TestCheckDeploymentReplicas_FiresWhenSustainedUnavailable(t *testing.T) {
	now := time.Now()
	dep := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "checkout", UID: "d-1"},
		Spec:       appsv1.DeploymentSpec{Replicas: int32ptr(3)},
		Status: appsv1.DeploymentStatus{
			ReadyReplicas: 1,
			Conditions: []appsv1.DeploymentCondition{
				{Type: appsv1.DeploymentAvailable, Status: corev1.ConditionFalse, Reason: "MinimumReplicasUnavailable", LastTransitionTime: metav1.NewTime(now.Add(-20 * time.Minute))},
			},
		},
	}
	clientset := k8sfake.NewSimpleClientset(dep)
	out, err := checkDeploymentReplicas(context.Background(), newSweepSnapshot(clientset), now, defaultSweepSustainedThreshold)
	if err != nil {
		t.Fatalf("checkDeploymentReplicas: %v", err)
	}
	if len(out) != 1 {
		t.Fatalf("got %d candidates, want 1: %+v", len(out), out)
	}
	if out[0].Reason != reasonDeploymentReplicasUnavailable {
		t.Errorf("Reason = %q, want %q", out[0].Reason, reasonDeploymentReplicasUnavailable)
	}
}

func TestCheckDeploymentReplicas_SkipsRecentTransition(t *testing.T) {
	now := time.Now()
	dep := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "checkout"},
		Spec:       appsv1.DeploymentSpec{Replicas: int32ptr(3)},
		Status: appsv1.DeploymentStatus{
			Conditions: []appsv1.DeploymentCondition{
				{Type: appsv1.DeploymentAvailable, Status: corev1.ConditionFalse, LastTransitionTime: metav1.NewTime(now.Add(-1 * time.Minute))},
			},
		},
	}
	out, err := checkDeploymentReplicas(context.Background(), newSweepSnapshot(k8sfake.NewSimpleClientset(dep)), now, defaultSweepSustainedThreshold)
	if err != nil {
		t.Fatalf("checkDeploymentReplicas: %v", err)
	}
	if len(out) != 0 {
		t.Fatalf("a Deployment unavailable for only 1 minute must not fire yet, got %+v", out)
	}
}

func TestCheckDeploymentReplicas_SkipsScaledToZero(t *testing.T) {
	now := time.Now()
	dep := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "paused"},
		Spec:       appsv1.DeploymentSpec{Replicas: int32ptr(0)},
		Status: appsv1.DeploymentStatus{
			Conditions: []appsv1.DeploymentCondition{
				{Type: appsv1.DeploymentAvailable, Status: corev1.ConditionFalse, LastTransitionTime: metav1.NewTime(now.Add(-time.Hour))},
			},
		},
	}
	out, err := checkDeploymentReplicas(context.Background(), newSweepSnapshot(k8sfake.NewSimpleClientset(dep)), now, defaultSweepSustainedThreshold)
	if err != nil {
		t.Fatalf("checkDeploymentReplicas: %v", err)
	}
	if len(out) != 0 {
		t.Fatalf("a deliberately-zero-replica Deployment must never fire, got %+v", out)
	}
}

func TestCheckDeploymentReplicas_SkipsAvailable(t *testing.T) {
	now := time.Now()
	dep := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "healthy"},
		Spec:       appsv1.DeploymentSpec{Replicas: int32ptr(3)},
		Status: appsv1.DeploymentStatus{
			ReadyReplicas: 3,
			Conditions: []appsv1.DeploymentCondition{
				{Type: appsv1.DeploymentAvailable, Status: corev1.ConditionTrue, LastTransitionTime: metav1.NewTime(now.Add(-time.Hour))},
			},
		},
	}
	out, err := checkDeploymentReplicas(context.Background(), newSweepSnapshot(k8sfake.NewSimpleClientset(dep)), now, defaultSweepSustainedThreshold)
	if err != nil {
		t.Fatalf("checkDeploymentReplicas: %v", err)
	}
	if len(out) != 0 {
		t.Fatalf("a healthy, Available=True Deployment must never fire, got %+v", out)
	}
}

func TestCheckStatefulSetReplicas(t *testing.T) {
	now := time.Now()
	old := &appsv1.StatefulSet{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "old-and-stuck", CreationTimestamp: metav1.NewTime(now.Add(-time.Hour))},
		Spec:       appsv1.StatefulSetSpec{Replicas: int32ptr(3)},
		Status:     appsv1.StatefulSetStatus{ReadyReplicas: 1},
	}
	young := &appsv1.StatefulSet{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "just-rolling-out", CreationTimestamp: metav1.NewTime(now.Add(-time.Minute))},
		Spec:       appsv1.StatefulSetSpec{Replicas: int32ptr(3)},
		Status:     appsv1.StatefulSetStatus{ReadyReplicas: 1},
	}
	healthy := &appsv1.StatefulSet{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "healthy", CreationTimestamp: metav1.NewTime(now.Add(-time.Hour))},
		Spec:       appsv1.StatefulSetSpec{Replicas: int32ptr(3)},
		Status:     appsv1.StatefulSetStatus{ReadyReplicas: 3},
	}

	out, err := checkStatefulSetReplicas(context.Background(), newSweepSnapshot(k8sfake.NewSimpleClientset(old, young, healthy)), now, defaultSweepSustainedThreshold)
	if err != nil {
		t.Fatalf("checkStatefulSetReplicas: %v", err)
	}
	// BOTH under-replicated sets are returned, regardless of object age. This
	// used to filter on `now - CreationTimestamp >= threshold`, which is not a
	// sustain check at all: any object older than the threshold passed it
	// trivially, so a normal rolling update of an old StatefulSet reported
	// instantly. The checker now reports what is true *now*, and runOneSweep
	// decides whether it has persisted long enough (see
	// TestRunOneSweepGatesCandidatesWithNoAuthoritativeTimestamp).
	names := map[string]bool{}
	for _, c := range out {
		names[c.Name] = true
		if !c.SustainedFrom.IsZero() {
			t.Errorf("%s: SustainedFrom = %v, want zero — StatefulSet has no authoritative timestamp, so the sustain gate must apply", c.Name, c.SustainedFrom)
		}
	}
	if len(out) != 2 || !names["old-and-stuck"] || !names["just-rolling-out"] {
		t.Fatalf("got %+v, want both under-replicated StatefulSets", out)
	}
	if names["healthy"] {
		t.Error("a fully-ready StatefulSet must never be a candidate")
	}
}

func TestCheckDaemonSetReplicas(t *testing.T) {
	now := time.Now()
	stuck := &appsv1.DaemonSet{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "stuck", CreationTimestamp: metav1.NewTime(now.Add(-time.Hour))},
		Status:     appsv1.DaemonSetStatus{DesiredNumberScheduled: 5, NumberReady: 2},
	}
	healthy := &appsv1.DaemonSet{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "healthy", CreationTimestamp: metav1.NewTime(now.Add(-time.Hour))},
		Status:     appsv1.DaemonSetStatus{DesiredNumberScheduled: 5, NumberReady: 5},
	}

	out, err := checkDaemonSetReplicas(context.Background(), newSweepSnapshot(k8sfake.NewSimpleClientset(stuck, healthy)), now, defaultSweepSustainedThreshold)
	if err != nil {
		t.Fatalf("checkDaemonSetReplicas: %v", err)
	}
	if len(out) != 1 || out[0].Name != "stuck" {
		t.Fatalf("got %+v, want exactly one candidate for 'stuck'", out)
	}
}

func TestCheckPVCPending(t *testing.T) {
	now := time.Now()
	stuck := &corev1.PersistentVolumeClaim{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "stuck-pvc", CreationTimestamp: metav1.NewTime(now.Add(-time.Hour))},
		Status:     corev1.PersistentVolumeClaimStatus{Phase: corev1.ClaimPending},
	}
	fresh := &corev1.PersistentVolumeClaim{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "fresh-pvc", CreationTimestamp: metav1.NewTime(now.Add(-time.Minute))},
		Status:     corev1.PersistentVolumeClaimStatus{Phase: corev1.ClaimPending},
	}
	bound := &corev1.PersistentVolumeClaim{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "bound-pvc", CreationTimestamp: metav1.NewTime(now.Add(-time.Hour))},
		Status:     corev1.PersistentVolumeClaimStatus{Phase: corev1.ClaimBound},
	}

	out, err := checkPVCPending(context.Background(), newSweepSnapshot(k8sfake.NewSimpleClientset(stuck, fresh, bound)), now, defaultSweepSustainedThreshold)
	if err != nil {
		t.Fatalf("checkPVCPending: %v", err)
	}
	if len(out) != 1 || out[0].Name != "stuck-pvc" {
		t.Fatalf("got %+v, want exactly one candidate for 'stuck-pvc'", out)
	}
	if out[0].Class != tunnel.FindingClassRisk || out[0].Impact != tunnel.FindingImpactPotential {
		t.Fatalf("unconsumed pending PVC evidence = %s/%s, want risk/potential", out[0].Class, out[0].Impact)
	}
}

func TestCheckFailedJobs(t *testing.T) {
	now := time.Now()
	failed := &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "failed-job"},
		Status: batchv1.JobStatus{
			Conditions: []batchv1.JobCondition{
				{Type: batchv1.JobFailed, Status: corev1.ConditionTrue, Reason: "BackoffLimitExceeded", LastTransitionTime: metav1.NewTime(now)},
			},
		},
	}
	succeeded := &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "succeeded-job"},
		Status: batchv1.JobStatus{
			Conditions: []batchv1.JobCondition{
				{Type: batchv1.JobComplete, Status: corev1.ConditionTrue, LastTransitionTime: metav1.NewTime(now)},
			},
		},
	}

	out, err := checkFailedJobs(context.Background(), newSweepSnapshot(k8sfake.NewSimpleClientset(failed, succeeded)), now, defaultSweepSustainedThreshold)
	if err != nil {
		t.Fatalf("checkFailedJobs: %v", err)
	}
	if len(out) != 1 || out[0].Name != "failed-job" {
		t.Fatalf("got %+v, want exactly one candidate for 'failed-job'", out)
	}
}

// Observed live (loop campaign 2026-10-13, S09): every failing CronJob run
// opened its own incident because the run carried no workload.
func TestCheckFailedJobsAttachesTheCronJob(t *testing.T) {
	now := time.Now()
	run := &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "report-29865460",
			OwnerReferences: []metav1.OwnerReference{{APIVersion: "batch/v1", Kind: "CronJob", Name: "report", Controller: boolPtr(true)}}},
		Status: batchv1.JobStatus{Conditions: []batchv1.JobCondition{
			{Type: batchv1.JobFailed, Status: corev1.ConditionTrue, Reason: "BackoffLimitExceeded", LastTransitionTime: metav1.NewTime(now)},
		}},
	}
	out, err := checkFailedJobs(context.Background(), newSweepSnapshot(k8sfake.NewSimpleClientset(run)), now, defaultSweepSustainedThreshold)
	if err != nil || len(out) != 1 {
		t.Fatalf("checkFailedJobs = %+v, %v", out, err)
	}
	if out[0].WorkloadGVK != "batch/v1/CronJob" || out[0].WorkloadName != "report" {
		t.Errorf("workload = (%q, %q), want the owning CronJob", out[0].WorkloadGVK, out[0].WorkloadName)
	}
}

func TestCheckNodeNotReady(t *testing.T) {
	now := time.Now()
	notReady := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: "node-down"},
		Status: corev1.NodeStatus{
			Conditions: []corev1.NodeCondition{
				{Type: corev1.NodeReady, Status: corev1.ConditionFalse, Reason: "KubeletNotReady", LastTransitionTime: metav1.NewTime(now.Add(-20 * time.Minute))},
			},
		},
	}
	ready := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: "node-up"},
		Status: corev1.NodeStatus{
			Conditions: []corev1.NodeCondition{
				{Type: corev1.NodeReady, Status: corev1.ConditionTrue, LastTransitionTime: metav1.NewTime(now.Add(-time.Hour))},
			},
		},
	}

	out, err := checkNodeNotReady(context.Background(), newSweepSnapshot(k8sfake.NewSimpleClientset(notReady, ready)), now, defaultSweepSustainedThreshold)
	if err != nil {
		t.Fatalf("checkNodeNotReady: %v", err)
	}
	if len(out) != 1 || out[0].Name != "node-down" {
		t.Fatalf("got %+v, want exactly one candidate for 'node-down'", out)
	}
	if out[0].Severity != "critical" {
		t.Errorf("Severity = %q, want %q (a NotReady node is fleet-wide blast radius)", out[0].Severity, "critical")
	}
}

func TestCheckNodePressureConditions_FiresPerPressureType(t *testing.T) {
	now := time.Now()
	memoryPressured := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: "node-under-memory-pressure"},
		Status: corev1.NodeStatus{
			Conditions: []corev1.NodeCondition{
				{Type: corev1.NodeReady, Status: corev1.ConditionTrue, LastTransitionTime: metav1.NewTime(now.Add(-time.Hour))},
				{Type: corev1.NodeMemoryPressure, Status: corev1.ConditionTrue, Reason: "KubeletHasInsufficientMemory", LastTransitionTime: metav1.NewTime(now.Add(-20 * time.Minute))},
			},
		},
	}
	diskAndPIDPressured := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: "node-under-disk-and-pid-pressure"},
		Status: corev1.NodeStatus{
			Conditions: []corev1.NodeCondition{
				{Type: corev1.NodeReady, Status: corev1.ConditionTrue, LastTransitionTime: metav1.NewTime(now.Add(-time.Hour))},
				{Type: corev1.NodeDiskPressure, Status: corev1.ConditionTrue, Reason: "KubeletHasDiskPressure", LastTransitionTime: metav1.NewTime(now.Add(-15 * time.Minute))},
				{Type: corev1.NodePIDPressure, Status: corev1.ConditionTrue, Reason: "KubeletHasInsufficientPID", LastTransitionTime: metav1.NewTime(now.Add(-30 * time.Minute))},
			},
		},
	}
	healthy := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: "healthy-node"},
		Status: corev1.NodeStatus{
			Conditions: []corev1.NodeCondition{
				{Type: corev1.NodeReady, Status: corev1.ConditionTrue, LastTransitionTime: metav1.NewTime(now.Add(-time.Hour))},
				{Type: corev1.NodeMemoryPressure, Status: corev1.ConditionFalse, LastTransitionTime: metav1.NewTime(now.Add(-time.Hour))},
				{Type: corev1.NodeDiskPressure, Status: corev1.ConditionFalse, LastTransitionTime: metav1.NewTime(now.Add(-time.Hour))},
				{Type: corev1.NodePIDPressure, Status: corev1.ConditionFalse, LastTransitionTime: metav1.NewTime(now.Add(-time.Hour))},
			},
		},
	}
	recentlyPressured := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: "just-started-memory-pressure"},
		Status: corev1.NodeStatus{
			Conditions: []corev1.NodeCondition{
				{Type: corev1.NodeMemoryPressure, Status: corev1.ConditionTrue, LastTransitionTime: metav1.NewTime(now.Add(-time.Minute))},
			},
		},
	}

	out, err := checkNodePressureConditions(context.Background(), newSweepSnapshot(k8sfake.NewSimpleClientset(memoryPressured, diskAndPIDPressured, healthy, recentlyPressured)), now, defaultSweepSustainedThreshold)
	if err != nil {
		t.Fatalf("checkNodePressureConditions: %v", err)
	}

	byNameReason := map[string]string{}
	for _, c := range out {
		byNameReason[c.Name+"/"+c.Reason] = c.Severity
	}

	if len(out) != 3 {
		t.Fatalf("got %d candidates, want exactly 3 (one memory, one disk, one PID): %+v", len(out), out)
	}
	wantReasons := []string{
		"node-under-memory-pressure/" + reasonNodeMemoryPressure,
		"node-under-disk-and-pid-pressure/" + reasonNodeDiskPressure,
		"node-under-disk-and-pid-pressure/" + reasonNodePIDPressure,
	}
	for _, key := range wantReasons {
		sev, ok := byNameReason[key]
		if !ok {
			t.Errorf("missing expected candidate %q, got %+v", key, out)
			continue
		}
		if sev != "high" {
			t.Errorf("%s: Severity = %q, want %q", key, sev, "high")
		}
	}
	if _, ok := byNameReason["healthy-node/"+reasonNodeMemoryPressure]; ok {
		t.Error("healthy node with all pressure conditions False must not fire")
	}
	if _, ok := byNameReason["just-started-memory-pressure/"+reasonNodeMemoryPressure]; ok {
		t.Error("a pressure condition that transitioned only 1 minute ago must not fire yet")
	}
}

func TestCheckHPAScalingBlocked(t *testing.T) {
	now := time.Now()
	blocked := &autoscalingv2.HorizontalPodAutoscaler{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "blocked-hpa"},
		Status: autoscalingv2.HorizontalPodAutoscalerStatus{
			Conditions: []autoscalingv2.HorizontalPodAutoscalerCondition{
				{Type: autoscalingv2.AbleToScale, Status: corev1.ConditionFalse, Reason: "FailedGetScale", LastTransitionTime: metav1.NewTime(now.Add(-20 * time.Minute))},
			},
		},
	}
	ok := &autoscalingv2.HorizontalPodAutoscaler{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "healthy-hpa"},
		Status: autoscalingv2.HorizontalPodAutoscalerStatus{
			Conditions: []autoscalingv2.HorizontalPodAutoscalerCondition{
				{Type: autoscalingv2.AbleToScale, Status: corev1.ConditionTrue, LastTransitionTime: metav1.NewTime(now.Add(-time.Hour))},
			},
		},
	}

	out, err := checkHPAScalingBlocked(context.Background(), newSweepSnapshot(k8sfake.NewSimpleClientset(blocked, ok)), now, defaultSweepSustainedThreshold)
	if err != nil {
		t.Fatalf("checkHPAScalingBlocked: %v", err)
	}
	if len(out) != 1 || out[0].Name != "blocked-hpa" {
		t.Fatalf("got %+v, want exactly one candidate for 'blocked-hpa'", out)
	}
}

func TestCheckServiceNoEndpoints(t *testing.T) {
	now := time.Now()
	broken := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "broken-svc", CreationTimestamp: metav1.NewTime(now.Add(-time.Hour))},
		Spec:       corev1.ServiceSpec{Selector: map[string]string{"app": "broken"}},
	}
	healthy := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "healthy-svc", CreationTimestamp: metav1.NewTime(now.Add(-time.Hour))},
		Spec:       corev1.ServiceSpec{Selector: map[string]string{"app": "healthy"}},
	}
	headless := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "headless-svc", CreationTimestamp: metav1.NewTime(now.Add(-time.Hour))},
		Spec:       corev1.ServiceSpec{Selector: nil},
	}
	healthySlice := &discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "healthy-svc-abcde", Labels: map[string]string{"kubernetes.io/service-name": "healthy-svc"}},
		Endpoints: []discoveryv1.Endpoint{
			{Addresses: []string{"10.0.0.1"}, Conditions: discoveryv1.EndpointConditions{Ready: boolptr(true)}},
		},
	}
	brokenSlice := &discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "broken-svc-abcde", Labels: map[string]string{"kubernetes.io/service-name": "broken-svc"}},
		Endpoints:  []discoveryv1.Endpoint{}, // no backing pods at all
	}

	objs := []runtime.Object{broken, healthy, headless, healthySlice, brokenSlice}
	out, err := checkServiceNoEndpoints(context.Background(), newSweepSnapshot(k8sfake.NewSimpleClientset(objs...)), now, defaultSweepSustainedThreshold)
	if err != nil {
		t.Fatalf("checkServiceNoEndpoints: %v", err)
	}
	if len(out) != 1 || out[0].Name != "broken-svc" {
		t.Fatalf("got %+v, want exactly one candidate for 'broken-svc' (healthy-svc has a ready endpoint, headless-svc has no selector)", out)
	}
	if !out[0].SustainedFrom.IsZero() {
		t.Error("Service has no authoritative 'empty since' timestamp, so SustainedFrom must be zero and the sustain gate must apply")
	}
	if out[0].Class != tunnel.FindingClassRisk || out[0].Impact != tunnel.FindingImpactPotential {
		t.Fatalf("empty Service evidence = %s/%s, want risk/potential until active impact is corroborated", out[0].Class, out[0].Impact)
	}
}

// TestCheckWebhookBackingServiceUnreachable is PROJECT.md B149's webhook-half
// regression test: a registered ValidatingWebhookConfiguration or
// MutatingWebhookConfiguration whose clientConfig.service has no ready
// endpoint must be flagged, generically, without naming any specific webhook.
func TestCheckWebhookBackingServiceUnreachable(t *testing.T) {
	now := time.Now()
	svcRef := func(ns, name string) *admissionregistrationv1.ServiceReference {
		return &admissionregistrationv1.ServiceReference{Namespace: ns, Name: name}
	}
	failPolicy := admissionregistrationv1.Fail
	ignorePolicy := admissionregistrationv1.Ignore

	brokenValidating := &admissionregistrationv1.ValidatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{Name: "broken-validating"},
		Webhooks: []admissionregistrationv1.ValidatingWebhook{{
			Name:          "broken.example.com",
			ClientConfig:  admissionregistrationv1.WebhookClientConfig{Service: svcRef("webhook-ns", "broken-svc")},
			FailurePolicy: &failPolicy,
		}},
	}
	healthyValidating := &admissionregistrationv1.ValidatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{Name: "healthy-validating"},
		Webhooks: []admissionregistrationv1.ValidatingWebhook{{
			Name:          "healthy.example.com",
			ClientConfig:  admissionregistrationv1.WebhookClientConfig{Service: svcRef("webhook-ns", "healthy-svc")},
			FailurePolicy: &failPolicy,
		}},
	}
	urlBasedValidating := &admissionregistrationv1.ValidatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{Name: "url-based-validating"},
		Webhooks: []admissionregistrationv1.ValidatingWebhook{{
			Name:         "external.example.com",
			ClientConfig: admissionregistrationv1.WebhookClientConfig{URL: strptrWebhook("https://example.com/admit")},
		}},
	}
	brokenMutating := &admissionregistrationv1.MutatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{Name: "broken-mutating"},
		Webhooks: []admissionregistrationv1.MutatingWebhook{{
			Name:          "broken-mutate.example.com",
			ClientConfig:  admissionregistrationv1.WebhookClientConfig{Service: svcRef("webhook-ns", "no-such-svc")},
			FailurePolicy: &ignorePolicy,
		}},
	}

	healthySvc := &corev1.Service{ObjectMeta: metav1.ObjectMeta{Namespace: "webhook-ns", Name: "healthy-svc"}}
	healthySlice := &discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{Namespace: "webhook-ns", Name: "healthy-svc-abcde", Labels: map[string]string{"kubernetes.io/service-name": "healthy-svc"}},
		Endpoints: []discoveryv1.Endpoint{
			{Addresses: []string{"10.0.0.1"}, Conditions: discoveryv1.EndpointConditions{Ready: boolptr(true)}},
		},
	}
	brokenSvc := &corev1.Service{ObjectMeta: metav1.ObjectMeta{Namespace: "webhook-ns", Name: "broken-svc"}}
	brokenSlice := &discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{Namespace: "webhook-ns", Name: "broken-svc-abcde", Labels: map[string]string{"kubernetes.io/service-name": "broken-svc"}},
		Endpoints:  []discoveryv1.Endpoint{},
	}

	objs := []runtime.Object{
		brokenValidating, healthyValidating, urlBasedValidating, brokenMutating,
		healthySvc, healthySlice, brokenSvc, brokenSlice,
	}
	out, err := checkWebhookBackingServiceUnreachable(context.Background(), newSweepSnapshot(k8sfake.NewSimpleClientset(objs...)), now, defaultSweepSustainedThreshold)
	if err != nil {
		t.Fatalf("checkWebhookBackingServiceUnreachable: %v", err)
	}
	if len(out) != 2 {
		t.Fatalf("got %d candidates, want exactly 2 (broken-validating: Service exists but no ready endpoint; broken-mutating: Service does not exist at all) — healthy-validating must not fire, url-based-validating has no Service to check: %+v", len(out), out)
	}

	byName := map[string]sweepCandidate{}
	for _, c := range out {
		byName[c.Name] = c
	}

	validatingCand, ok := byName["broken-validating"]
	if !ok {
		t.Fatal("no candidate for broken-validating")
	}
	if validatingCand.GVK != "admissionregistration.k8s.io/v1/ValidatingWebhookConfiguration" {
		t.Errorf("GVK = %q", validatingCand.GVK)
	}
	if validatingCand.Reason != reasonWebhookBackingServiceUnreachable {
		t.Errorf("Reason = %q, want %q", validatingCand.Reason, reasonWebhookBackingServiceUnreachable)
	}
	if !strings.Contains(validatingCand.Message, "no ready endpoints") || !strings.Contains(validatingCand.Message, "fails outright") {
		t.Errorf("message = %q, want it to name 'no ready endpoints' and the Fail-policy 'fails outright' consequence", validatingCand.Message)
	}

	mutatingCand, ok := byName["broken-mutating"]
	if !ok {
		t.Fatal("no candidate for broken-mutating")
	}
	if mutatingCand.GVK != "admissionregistration.k8s.io/v1/MutatingWebhookConfiguration" {
		t.Errorf("GVK = %q", mutatingCand.GVK)
	}
	if !strings.Contains(mutatingCand.Message, "does not exist") || !strings.Contains(mutatingCand.Message, "skips this webhook") {
		t.Errorf("message = %q, want it to name the missing Service and the Ignore-policy 'skips' consequence", mutatingCand.Message)
	}
}

func strptrWebhook(s string) *string { return &s }

// TestCheckServiceTargetPortUnresolved reproduces the exact EndpointSlice
// shapes observed live on rke2 (see the check's own doc comment): a named
// targetPort nothing declares leaves the endpoint READY with a nil port, so
// every other signal in this agent reads healthy while the Service blackholes.
func TestCheckServiceTargetPortUnresolved(t *testing.T) {
	now := time.Now()
	svc := func(name string, port corev1.ServicePort) *corev1.Service {
		return &corev1.Service{
			ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: name, CreationTimestamp: metav1.NewTime(now.Add(-time.Hour))},
			Spec:       corev1.ServiceSpec{Selector: map[string]string{"app": "web"}, Ports: []corev1.ServicePort{port}},
		}
	}
	slice := func(svcName string, ports []discoveryv1.EndpointPort, ready bool) *discoveryv1.EndpointSlice {
		return &discoveryv1.EndpointSlice{
			ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: svcName + "-abcde",
				Labels: map[string]string{"kubernetes.io/service-name": svcName}},
			Endpoints: []discoveryv1.Endpoint{
				{Addresses: []string{"10.0.0.1"}, Conditions: discoveryv1.EndpointConditions{Ready: boolptr(ready)}},
			},
			Ports: ports,
		}
	}
	strptr := func(s string) *string { return &s }
	i32 := func(i int32) *int32 { return &i }

	// The bug, in the shape a live cluster actually produces: ready endpoint,
	// and the slice's Ports is NIL. Read off rke2 with `-o yaml` after a first
	// version of this test asserted a nil-port ENTRY instead, passed, and then
	// detected nothing on the live cluster.
	namedBroken := svc("named-broken", corev1.ServicePort{Port: 80, TargetPort: intstr.FromString("nosuchport")})
	namedBrokenSlice := slice("named-broken", nil, true)

	// Defensive: the same conclusion must hold if a slice ever carries an
	// explicit entry with a nil port instead of omitting the list.
	nilEntry := svc("nil-port-entry", corev1.ServicePort{Port: 80, TargetPort: intstr.FromString("nosuchport")})
	nilEntrySlice := slice("nil-port-entry", []discoveryv1.EndpointPort{{Port: nil}}, true)

	// Multi-port: one named port resolves, the other does not. Only the broken
	// one may be named, or the message sends an operator to the wrong port.
	mixed := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "mixed", CreationTimestamp: metav1.NewTime(now.Add(-time.Hour))},
		Spec: corev1.ServiceSpec{Selector: map[string]string{"app": "web"}, Ports: []corev1.ServicePort{
			{Name: "http", Port: 80, TargetPort: intstr.FromString("http")},
			{Name: "metrics", Port: 9100, TargetPort: intstr.FromString("nometrics")},
		}},
	}

	// Numeric mismatch: equally broken in reality, deliberately NOT flagged —
	// containerPort declarations are informational, so this cannot be proven
	// from the API. Asserted so the deliberate omission cannot regress into an
	// accidental inclusion without this test failing.
	numeric := svc("numeric-mismatch", corev1.ServicePort{Port: 80, TargetPort: intstr.FromInt32(9090)})
	numericSlice := slice("numeric-mismatch", []discoveryv1.EndpointPort{{Port: i32(9090)}}, true)

	// Correct named port that DID resolve.
	ok := svc("resolves-fine", corev1.ServicePort{Name: "http", Port: 80, TargetPort: intstr.FromString("http")})
	okSlice := slice("resolves-fine", []discoveryv1.EndpointPort{{Name: strptr("http"), Port: i32(8080)}}, true)

	// Nothing ready behind it: checkServiceNoEndpoints' finding, not this one.
	// Two findings for one broken Service is the duplication this avoids.
	noEndpoints := svc("no-endpoints", corev1.ServicePort{Port: 80, TargetPort: intstr.FromString("nosuchport")})
	noEndpointsSlice := slice("no-endpoints", []discoveryv1.EndpointPort{{Port: nil}}, false)

	mixedSlice := slice("mixed", []discoveryv1.EndpointPort{{Name: strptr("http"), Port: i32(8080)}}, true)

	// A Service with no EndpointSlice at all: nothing to conclude from.
	fresh := svc("no-slices-yet", corev1.ServicePort{Port: 80, TargetPort: intstr.FromString("http")})

	out, err := checkServiceTargetPortUnresolved(context.Background(), newSweepSnapshot(
		k8sfake.NewSimpleClientset(namedBroken, namedBrokenSlice, nilEntry, nilEntrySlice,
			mixed, mixedSlice, numeric, numericSlice,
			ok, okSlice, noEndpoints, noEndpointsSlice, fresh)),
		now, defaultSweepSustainedThreshold)
	if err != nil {
		t.Fatalf("checkServiceTargetPortUnresolved: %v", err)
	}

	got := map[string]sweepCandidate{}
	for _, c := range out {
		got[c.Name] = c
	}
	want := []string{"named-broken", "nil-port-entry", "mixed"}
	if len(got) != len(want) {
		var names []string
		for n := range got {
			names = append(names, n)
		}
		sort.Strings(names)
		t.Fatalf("flagged %v, want exactly %v — numeric-mismatch is unprovable, resolves-fine is healthy, no-endpoints belongs to checkServiceNoEndpoints, no-slices-yet has nothing to conclude from", names, want)
	}
	for _, n := range want {
		if _, ok := got[n]; !ok {
			t.Fatalf("%s was not flagged; got %v", n, out)
		}
	}

	c := got["named-broken"]
	if c.Severity != "high" {
		t.Errorf("Severity = %q, want high — no traffic is served, same user-visible effect as ServiceNoEndpoints", c.Severity)
	}
	if !strings.Contains(c.Message, "nosuchport") {
		t.Errorf("message %q does not name the unresolved port, so an operator cannot act on it", c.Message)
	}
	if !c.SustainedFrom.IsZero() {
		t.Error("EndpointSlices carry no 'unresolved since' timestamp, so SustainedFrom must be zero and the sustain gate must apply")
	}

	// The mixed Service must name the broken port and NOT the working one.
	if m := got["mixed"].Message; !strings.Contains(m, "nometrics") || strings.Contains(m, `"http"`) {
		t.Errorf("mixed message = %q; must name the unresolved metrics port and not the healthy http one", m)
	}
}

func TestCheckIngressBackendMissing(t *testing.T) {
	now := time.Now()
	svcBackend := func(name string) networkingv1.IngressBackend {
		return networkingv1.IngressBackend{Service: &networkingv1.IngressServiceBackend{Name: name}}
	}
	ingress := func(name string, defaultBackend *networkingv1.IngressBackend, pathBackends ...networkingv1.IngressBackend) *networkingv1.Ingress {
		var paths []networkingv1.HTTPIngressPath
		for _, b := range pathBackends {
			paths = append(paths, networkingv1.HTTPIngressPath{Path: "/", Backend: b})
		}
		return &networkingv1.Ingress{
			ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: name, CreationTimestamp: metav1.NewTime(now.Add(-time.Hour))},
			Spec: networkingv1.IngressSpec{
				DefaultBackend: defaultBackend,
				Rules: []networkingv1.IngressRule{{
					IngressRuleValue: networkingv1.IngressRuleValue{HTTP: &networkingv1.HTTPIngressRuleValue{Paths: paths}},
				}},
			},
		}
	}
	realSvc := &corev1.Service{ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "real"}}
	// Same NAME, different namespace: an Ingress can only route to Services in
	// its own namespace, so this must not satisfy a reference from `default`.
	otherNS := &corev1.Service{ObjectMeta: metav1.ObjectMeta{Namespace: "other", Name: "elsewhere"}}

	healthy := ingress("healthy", nil, svcBackend("real"))
	brokenPath := ingress("broken-path", nil, svcBackend("gone"))
	// The easier of the two to forget, and it breaks every unmatched request.
	brokenDefault := ingress("broken-default", &networkingv1.IngressBackend{Service: &networkingv1.IngressServiceBackend{Name: "no-default"}}, svcBackend("real"))
	crossNamespace := ingress("cross-namespace", nil, svcBackend("elsewhere"))
	// One deleted Service behind three paths is ONE fault, not three.
	repeated := ingress("repeated", nil, svcBackend("gone"), svcBackend("gone"), svcBackend("gone"))
	// A `resource` backend points at a custom object this check cannot resolve;
	// guessing about it would manufacture a fault.
	resourceBackend := ingress("resource-backend", nil, networkingv1.IngressBackend{
		Resource: &corev1.TypedLocalObjectReference{Kind: "StorageBucket", Name: "static-assets"},
	})

	out, err := checkIngressBackendMissing(context.Background(), newSweepSnapshot(
		k8sfake.NewSimpleClientset(realSvc, otherNS, healthy, brokenPath, brokenDefault, crossNamespace, repeated, resourceBackend)),
		now, defaultSweepSustainedThreshold)
	if err != nil {
		t.Fatalf("checkIngressBackendMissing: %v", err)
	}

	got := map[string]sweepCandidate{}
	for _, c := range out {
		got[c.Name] = c
		if c.GVK != "networking.k8s.io/v1/Ingress" {
			t.Errorf("%s: GVK = %q, want networking.k8s.io/v1/Ingress", c.Name, c.GVK)
		}
	}
	want := []string{"broken-path", "broken-default", "cross-namespace", "repeated"}
	if len(got) != len(want) {
		var names []string
		for n := range got {
			names = append(names, n)
		}
		sort.Strings(names)
		t.Fatalf("flagged %v, want exactly %v — healthy resolves, and a resource backend is not a Service reference", names, want)
	}
	for _, n := range want {
		if _, ok := got[n]; !ok {
			t.Errorf("%s was not flagged", n)
		}
	}
	if m := got["repeated"].Message; strings.Count(m, "gone") != 1 {
		t.Errorf("message %q repeats the same missing Service — three paths behind one deleted Service is one fault", m)
	}
	if m := got["broken-default"].Message; !strings.Contains(m, "no-default") {
		t.Errorf("defaultBackend message %q does not name the missing Service", m)
	}
	if !got["broken-path"].SustainedFrom.IsZero() {
		t.Error("SustainedFrom must be zero so the sustain gate applies — otherwise a chart applying an Ingress moments before its Service reports a fault")
	}
}

// --- BACKLOG.md AN1 (issue-catalog ING-005): Ingress backend port mismatch ---

func TestCheckIngressBackendMissing_PortMismatch(t *testing.T) {
	now := time.Now()
	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "web"},
		Spec: corev1.ServiceSpec{Ports: []corev1.ServicePort{
			{Name: "http", Port: 80},
			{Port: 9090},
		}},
	}
	mkIngress := func(name string, backends ...networkingv1.IngressBackend) *networkingv1.Ingress {
		var paths []networkingv1.HTTPIngressPath
		for i, b := range backends {
			paths = append(paths, networkingv1.HTTPIngressPath{Path: fmt.Sprintf("/p%d", i), Backend: b})
		}
		return &networkingv1.Ingress{
			ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: name},
			Spec: networkingv1.IngressSpec{
				Rules: []networkingv1.IngressRule{{
					IngressRuleValue: networkingv1.IngressRuleValue{HTTP: &networkingv1.HTTPIngressRuleValue{Paths: paths}},
				}},
			},
		}
	}
	backend := func(port networkingv1.ServiceBackendPort) networkingv1.IngressBackend {
		return networkingv1.IngressBackend{Service: &networkingv1.IngressServiceBackend{Name: "web", Port: port}}
	}

	wrongName := mkIngress("wrong-name", backend(networkingv1.ServiceBackendPort{Name: "https"}))
	wrongNumber := mkIngress("wrong-number", backend(networkingv1.ServiceBackendPort{Number: 8080}))
	healthy := mkIngress("healthy",
		backend(networkingv1.ServiceBackendPort{Name: "http"}),
		backend(networkingv1.ServiceBackendPort{Number: 9090}),
		// No port specified at all: cannot occur on an object the API server
		// actually accepted, but must not be treated as a mismatch either —
		// there is nothing to compare against.
		backend(networkingv1.ServiceBackendPort{}),
	)
	// Both a missing Service AND a wrong port on the surviving one, on the
	// SAME Ingress — must produce TWO distinct candidates (different
	// Reasons), not one blended or dropped finding.
	both := mkIngress("both-faults",
		networkingv1.IngressBackend{Service: &networkingv1.IngressServiceBackend{Name: "gone"}},
		backend(networkingv1.ServiceBackendPort{Number: 12345}),
	)

	out, err := checkIngressBackendMissing(context.Background(), newSweepSnapshot(
		k8sfake.NewSimpleClientset(svc, wrongName, wrongNumber, healthy, both)),
		now, defaultSweepSustainedThreshold)
	if err != nil {
		t.Fatalf("checkIngressBackendMissing: %v", err)
	}

	byName := map[string][]sweepCandidate{}
	for _, c := range out {
		byName[c.Name] = append(byName[c.Name], c)
	}

	for _, name := range []string{"wrong-name", "wrong-number"} {
		cands := byName[name]
		if len(cands) != 1 {
			t.Fatalf("%s: got %d candidates, want 1: %+v", name, len(cands), cands)
		}
		if cands[0].Reason != reasonIngressBackendPortMismatch {
			t.Errorf("%s: Reason = %q, want %q", name, cands[0].Reason, reasonIngressBackendPortMismatch)
		}
		if cands[0].Severity != "high" {
			t.Errorf("%s: Severity = %q, want high — this is as broken as the missing-service case", name, cands[0].Severity)
		}
	}
	if len(byName["healthy"]) != 0 {
		t.Errorf("healthy Ingress (matching ports by name, by number, and unset) must not fire, got %+v", byName["healthy"])
	}

	bothCands := byName["both-faults"]
	if len(bothCands) != 2 {
		t.Fatalf("both-faults: got %d candidates, want 2 (one per Reason): %+v", len(bothCands), bothCands)
	}
	reasons := map[string]bool{}
	for _, c := range bothCands {
		reasons[c.Reason] = true
	}
	if !reasons[reasonIngressBackendMissing] || !reasons[reasonIngressBackendPortMismatch] {
		t.Errorf("both-faults: got reasons %v, want both %q and %q", reasons, reasonIngressBackendMissing, reasonIngressBackendPortMismatch)
	}
}

func TestIngressBackendPortMatches(t *testing.T) {
	ports := []corev1.ServicePort{{Name: "http", Port: 80}, {Port: 9090}}
	cases := []struct {
		name string
		port networkingv1.ServiceBackendPort
		want bool
	}{
		{"matches by name", networkingv1.ServiceBackendPort{Name: "http"}, true},
		{"matches by number", networkingv1.ServiceBackendPort{Number: 9090}, true},
		{"wrong name", networkingv1.ServiceBackendPort{Name: "grpc"}, false},
		{"wrong number", networkingv1.ServiceBackendPort{Number: 443}, false},
		{"neither set", networkingv1.ServiceBackendPort{}, true},
	}
	for _, tc := range cases {
		if got := ingressBackendPortMatches(tc.port, ports); got != tc.want {
			t.Errorf("%s: got %v, want %v", tc.name, got, tc.want)
		}
	}
}

// --- BACKLOG.md AX1 (issue-catalog ING-009): cross-Ingress host+path collision ---

func ingressWithHostPath(ns, name, host, path string, pathType networkingv1.PathType) *networkingv1.Ingress {
	return &networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name, UID: types.UID("uid-" + ns + "-" + name)},
		Spec: networkingv1.IngressSpec{
			Rules: []networkingv1.IngressRule{{
				Host: host,
				IngressRuleValue: networkingv1.IngressRuleValue{HTTP: &networkingv1.HTTPIngressRuleValue{
					Paths: []networkingv1.HTTPIngressPath{{
						Path:     path,
						PathType: &pathType,
						Backend:  networkingv1.IngressBackend{Service: &networkingv1.IngressServiceBackend{Name: "svc"}},
					}},
				}},
			}},
		},
	}
}

// TestCheckIngressHostPathCollision_DoesNotFireOnNestedPaths is the regression
// guard for the false positive this check shipped with.
//
// A root application on "/" plus sibling applications on sub-paths is the most
// common Ingress layout there is, and it is NOT ambiguous: the Ingress spec
// gives Exact precedence over Prefix where two paths match equally, and every
// real controller resolves nested prefixes by longest match (ingress-nginx
// orders location blocks by descending path length). The old segment-prefix
// predicate flagged all of it — measured on one live cluster on 2026-09-09 it
// had produced 18 incidents and 288 findings across two hosts, every one of
// them wrong, each telling an operator that a working configuration was
// broken.
//
// The shapes below are taken from that cluster rather than invented.
func TestCheckIngressHostPathCollision_DoesNotFireOnNestedPaths(t *testing.T) {
	const host = "apps.lab.example.org"
	for _, tc := range []struct {
		name string
		a, b *networkingv1.Ingress
	}{
		{
			"root and a sub-path",
			ingressWithHostPath("apps", "lab-mainpage", host, "/", networkingv1.PathTypePrefix),
			ingressWithHostPath("apps", "softpack-frontend", host, "/softpack", networkingv1.PathTypePrefix),
		},
		{
			"two distinct sub-paths",
			ingressWithHostPath("apps", "gwas", host, "/gwas", networkingv1.PathTypePrefix),
			ingressWithHostPath("apps", "scrna", host, "/scrna", networkingv1.PathTypePrefix),
		},
		{
			"trailing slash is not a different path — still nested, still fine",
			ingressWithHostPath("apps", "root", host, "/", networkingv1.PathTypePrefix),
			ingressWithHostPath("apps", "docs", host, "/documentation/docs/", networkingv1.PathTypePrefix),
		},
		{
			// ImplementationSpecific semantics belong to the controller
			// (commonly a regex, applied first-match rather than
			// longest-match), so ARGUS deliberately asserts nothing about it.
			"ImplementationSpecific is not judged",
			ingressWithHostPath("apps", "root", host, "/", networkingv1.PathTypePrefix),
			ingressWithHostPath("apps", "analytics", host, "/analytics(/|$)(.*)", networkingv1.PathTypeImplementationSpecific),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, err := checkIngressHostPathCollision(context.Background(), newSweepSnapshot(k8sfake.NewSimpleClientset(tc.a, tc.b)), time.Now(), time.Minute)
			if err != nil {
				t.Fatalf("checkIngressHostPathCollision: %v", err)
			}
			if len(out) != 0 {
				t.Fatalf("fired on %s — got %d candidate(s), want 0: %+v", tc.name, len(out), out)
			}
		})
	}
}

// TestCheckIngressHostPathCollision_FiresOnIdenticalPathAndType pins the case
// that IS genuinely ambiguous: nothing in the spec breaks a tie between two
// different Ingress objects claiming the same host and the same path with the
// same path type. ingress-nginx picks by oldest CreationTimestamp and logs a
// warning — an arbitrary choice, which is what this check exists to surface.
func TestCheckIngressHostPathCollision_FiresOnIdenticalPathAndType(t *testing.T) {
	const host = "apps.example.com"
	a := ingressWithHostPath("team-a", "api", host, "/api", networkingv1.PathTypePrefix)
	b := ingressWithHostPath("team-b", "api-legacy", host, "/api/", networkingv1.PathTypePrefix)

	out, err := checkIngressHostPathCollision(context.Background(), newSweepSnapshot(k8sfake.NewSimpleClientset(a, b)), time.Now(), time.Minute)
	if err != nil {
		t.Fatalf("checkIngressHostPathCollision: %v", err)
	}
	// "/api" and "/api/" are the same path spelled two ways — normalising them
	// is what keeps this from being a way to sneak past the check.
	if len(out) == 0 {
		t.Fatal("did not fire on two Ingresses claiming the same host and path")
	}
}

// TestCheckIngressHostPathCollision_ExactBeatsPrefixOnTheSamePath: the spec
// resolves this one, so it is not a fault.
func TestCheckIngressHostPathCollision_ExactBeatsPrefixOnTheSamePath(t *testing.T) {
	const host = "apps.example.com"
	a := ingressWithHostPath("team-a", "exact", host, "/api", networkingv1.PathTypeExact)
	b := ingressWithHostPath("team-b", "prefix", host, "/api", networkingv1.PathTypePrefix)

	out, err := checkIngressHostPathCollision(context.Background(), newSweepSnapshot(k8sfake.NewSimpleClientset(a, b)), time.Now(), time.Minute)
	if err != nil {
		t.Fatalf("checkIngressHostPathCollision: %v", err)
	}
	if len(out) != 0 {
		t.Fatalf("fired where the spec gives Exact precedence over Prefix — got %d candidate(s)", len(out))
	}
}

func TestCheckIngressHostPathCollision_Fires(t *testing.T) {
	now := time.Now()
	// Two DIFFERENT namespaces, same host, overlapping ("/" prefixes
	// everything) paths — the live-confirmed shape (CAPABILITIES.md §6bo): a
	// forgotten shared-domain Ingress left behind in another team's
	// namespace.
	a := ingressWithHostPath("team-a", "shop", "shop.example.com", "/", networkingv1.PathTypePrefix)
	b := ingressWithHostPath("team-b", "shop-legacy", "shop.example.com", "/", networkingv1.PathTypePrefix)
	unrelated := ingressWithHostPath("team-c", "other", "other.example.com", "/", networkingv1.PathTypePrefix)

	out, err := checkIngressHostPathCollision(context.Background(), newSweepSnapshot(k8sfake.NewSimpleClientset(a, b, unrelated)), now, defaultSweepSustainedThreshold)
	if err != nil {
		t.Fatalf("checkIngressHostPathCollision: %v", err)
	}
	got := map[string]sweepCandidate{}
	for _, c := range out {
		got[c.Namespace+"/"+c.Name] = c
	}
	if len(got) != 2 {
		t.Fatalf("got %d candidates, want 2 (both colliding Ingresses, symmetric): %+v", len(got), out)
	}
	if c, ok := got["team-a/shop"]; !ok {
		t.Error("team-a/shop was not flagged")
	} else if !strings.Contains(c.Message, "shop-legacy") {
		t.Errorf("message %q does not name the colliding partner", c.Message)
	} else if c.Reason != reasonIngressHostPathCollision {
		t.Errorf("Reason = %q, want %q", c.Reason, reasonIngressHostPathCollision)
	} else if c.Severity != "high" {
		t.Errorf("Severity = %q, want high", c.Severity)
	}
	if c, ok := got["team-b/shop-legacy"]; !ok {
		t.Error("team-b/shop-legacy was not flagged")
	} else if !strings.Contains(c.Message, "team-a/shop") {
		t.Errorf("message %q does not name the colliding partner", c.Message)
	}
	if _, ok := got["team-c/other"]; ok {
		t.Error("an Ingress on an unrelated host must not be flagged")
	}
}

func TestCheckIngressHostPathCollision_NonOverlappingPaths_DoesNotFire(t *testing.T) {
	now := time.Now()
	// Same host, but genuinely disjoint paths under it — two teams correctly
	// sharing one domain by path, not colliding.
	a := ingressWithHostPath("team-a", "checkout", "shop.example.com", "/checkout", networkingv1.PathTypePrefix)
	b := ingressWithHostPath("team-b", "blog", "shop.example.com", "/blog", networkingv1.PathTypePrefix)

	out, err := checkIngressHostPathCollision(context.Background(), newSweepSnapshot(k8sfake.NewSimpleClientset(a, b)), now, defaultSweepSustainedThreshold)
	if err != nil {
		t.Fatalf("checkIngressHostPathCollision: %v", err)
	}
	if len(out) != 0 {
		t.Fatalf("disjoint paths under the same host must not fire, got %+v", out)
	}
}

func TestCheckIngressHostPathCollision_ExactPathsDiffer_DoesNotFire(t *testing.T) {
	now := time.Now()
	// Exact routing does not do prefix matching — two Exact rules for
	// different literal paths never collide even though one string prefixes
	// the other.
	a := ingressWithHostPath("team-a", "foo", "shop.example.com", "/foo", networkingv1.PathTypeExact)
	b := ingressWithHostPath("team-b", "foobar", "shop.example.com", "/foo/bar", networkingv1.PathTypeExact)

	out, err := checkIngressHostPathCollision(context.Background(), newSweepSnapshot(k8sfake.NewSimpleClientset(a, b)), now, defaultSweepSustainedThreshold)
	if err != nil {
		t.Fatalf("checkIngressHostPathCollision: %v", err)
	}
	if len(out) != 0 {
		t.Fatalf("two distinct Exact paths must not fire even when one string-prefixes the other, got %+v", out)
	}
}

func TestCheckIngressHostPathCollision_SameIngressTwoPaths_DoesNotFire(t *testing.T) {
	now := time.Now()
	// Two overlapping paths on ONE Ingress object are that object's own
	// business, not a cross-Ingress collision.
	self := &networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "self"},
		Spec: networkingv1.IngressSpec{
			Rules: []networkingv1.IngressRule{{
				Host: "shop.example.com",
				IngressRuleValue: networkingv1.IngressRuleValue{HTTP: &networkingv1.HTTPIngressRuleValue{
					Paths: []networkingv1.HTTPIngressPath{
						{Path: "/", PathType: pathTypePtr(networkingv1.PathTypePrefix), Backend: networkingv1.IngressBackend{Service: &networkingv1.IngressServiceBackend{Name: "svc"}}},
						{Path: "/api", PathType: pathTypePtr(networkingv1.PathTypePrefix), Backend: networkingv1.IngressBackend{Service: &networkingv1.IngressServiceBackend{Name: "svc"}}},
					},
				}},
			}},
		},
	}

	out, err := checkIngressHostPathCollision(context.Background(), newSweepSnapshot(k8sfake.NewSimpleClientset(self)), now, defaultSweepSustainedThreshold)
	if err != nil {
		t.Fatalf("checkIngressHostPathCollision: %v", err)
	}
	if len(out) != 0 {
		t.Fatalf("two paths on the SAME Ingress must not self-collide, got %+v", out)
	}
}

func pathTypePtr(t networkingv1.PathType) *networkingv1.PathType { return &t }

func TestCheckIngressHostPathCollision_DifferentExplicitClasses_DoesNotFire(t *testing.T) {
	now := time.Now()
	// A supported, common multi-controller split (an internal-facing and an
	// external-facing controller both watching the same host/path) — not a
	// fault, and the exact scenario FAILURE_MODES.md's Ingress section
	// originally rejected this whole check over.
	internalClass, externalClass := "nginx-internal", "nginx-external"
	a := ingressWithHostPath("team-a", "internal", "shop.example.com", "/", networkingv1.PathTypePrefix)
	a.Spec.IngressClassName = &internalClass
	b := ingressWithHostPath("team-b", "external", "shop.example.com", "/", networkingv1.PathTypePrefix)
	b.Spec.IngressClassName = &externalClass

	out, err := checkIngressHostPathCollision(context.Background(), newSweepSnapshot(k8sfake.NewSimpleClientset(a, b)), now, defaultSweepSustainedThreshold)
	if err != nil {
		t.Fatalf("checkIngressHostPathCollision: %v", err)
	}
	if len(out) != 0 {
		t.Fatalf("two Ingresses with different EXPLICIT ingressClassName values must not fire (different controllers), got %+v", out)
	}
}

func TestCheckIngressHostPathCollision_SameExplicitClass_Fires(t *testing.T) {
	now := time.Now()
	sameClass := "nginx"
	a := ingressWithHostPath("team-a", "shop", "shop.example.com", "/", networkingv1.PathTypePrefix)
	a.Spec.IngressClassName = &sameClass
	b := ingressWithHostPath("team-b", "shop-legacy", "shop.example.com", "/", networkingv1.PathTypePrefix)
	b.Spec.IngressClassName = &sameClass

	out, err := checkIngressHostPathCollision(context.Background(), newSweepSnapshot(k8sfake.NewSimpleClientset(a, b)), now, defaultSweepSustainedThreshold)
	if err != nil {
		t.Fatalf("checkIngressHostPathCollision: %v", err)
	}
	if len(out) != 2 {
		t.Fatalf("two Ingresses naming the SAME class genuinely collide, got %d candidates: %+v", len(out), out)
	}
}

func TestIngressClassesCanCollide(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{
		{"", "", true},
		{"", "nginx", true},
		{"nginx", "", true},
		{"nginx", "nginx", true},
		{"nginx-internal", "nginx-external", false},
	}
	for _, tc := range cases {
		if got := ingressClassesCanCollide(tc.a, tc.b); got != tc.want {
			t.Errorf("ingressClassesCanCollide(%q, %q) = %v, want %v", tc.a, tc.b, got, tc.want)
		}
	}
}

// --- BACKLOG.md AK1 (issue-catalog STS-008): orphaned per-ordinal PVC ---

func TestCheckOrphanedPVC(t *testing.T) {
	now := time.Now()
	sts := &appsv1.StatefulSet{
		ObjectMeta: metav1.ObjectMeta{Namespace: "data", Name: "web"},
		Spec:       appsv1.StatefulSetSpec{Replicas: int32ptr(2)},
	}
	bound := func(name string) *corev1.PersistentVolumeClaim {
		return &corev1.PersistentVolumeClaim{
			ObjectMeta: metav1.ObjectMeta{Namespace: "data", Name: name},
			Status:     corev1.PersistentVolumeClaimStatus{Phase: corev1.ClaimBound},
		}
	}
	inRange := bound("storage-web-1")                   // ordinal 1 < replicas 2: still live
	orphaned := bound("storage-web-2")                  // ordinal 2 >= replicas 2, no Pod: orphaned
	stillReferenced := bound("storage-web-3")           // ordinal 3 >= replicas 2, but a Pod mounts it
	pendingOutOfRange := &corev1.PersistentVolumeClaim{ // ordinal 9 >= replicas 2, but not Bound
		ObjectMeta: metav1.ObjectMeta{Namespace: "data", Name: "storage-web-9"},
		Status:     corev1.PersistentVolumeClaimStatus{Phase: corev1.ClaimPending},
	}
	unrelated := bound("some-other-claim") // does not match the naming contract at all

	referencingPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "data", Name: "manual-debug-pod"},
		Spec: corev1.PodSpec{Volumes: []corev1.Volume{{
			Name: "data",
			VolumeSource: corev1.VolumeSource{PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{
				ClaimName: "storage-web-3",
			}},
		}}},
	}

	out, err := checkOrphanedPVC(context.Background(), newSweepSnapshot(
		k8sfake.NewSimpleClientset(sts, inRange, orphaned, stillReferenced, pendingOutOfRange, unrelated, referencingPod)),
		now, defaultSweepSustainedThreshold)
	if err != nil {
		t.Fatalf("checkOrphanedPVC: %v", err)
	}
	if len(out) != 1 {
		t.Fatalf("got %d candidates, want exactly 1 (storage-web-2): %+v", len(out), out)
	}
	c := out[0]
	if c.Name != "storage-web-2" {
		t.Errorf("flagged %q, want storage-web-2", c.Name)
	}
	if c.GVK != "v1/PersistentVolumeClaim" {
		t.Errorf("GVK = %q, want v1/PersistentVolumeClaim", c.GVK)
	}
	if c.Reason != reasonOrphanedPVC {
		t.Errorf("Reason = %q, want %q", c.Reason, reasonOrphanedPVC)
	}
	if c.Severity != "low" {
		t.Errorf("Severity = %q, want low — this wastes quota, it is not an active outage", c.Severity)
	}
	if c.RelatedWorkloadGVK != "apps/v1/StatefulSet" || c.RelatedWorkloadName != "web" {
		t.Errorf("RelatedWorkload not set to the owning StatefulSet: %+v", c)
	}
}

func TestCheckOrphanedPVC_NoStatefulSets_ReturnsEarly(t *testing.T) {
	now := time.Now()
	pvc := &corev1.PersistentVolumeClaim{
		ObjectMeta: metav1.ObjectMeta{Namespace: "data", Name: "storage-web-9"},
		Status:     corev1.PersistentVolumeClaimStatus{Phase: corev1.ClaimBound},
	}
	out, err := checkOrphanedPVC(context.Background(), newSweepSnapshot(k8sfake.NewSimpleClientset(pvc)), now, defaultSweepSustainedThreshold)
	if err != nil {
		t.Fatalf("checkOrphanedPVC: %v", err)
	}
	if len(out) != 0 {
		t.Fatalf("no StatefulSets in the cluster means nothing to be orphaned from, got %+v", out)
	}
}

func TestParseStatefulSetPVCTemplateName(t *testing.T) {
	cases := []struct {
		pvcName, stsName string
		wantOrdinal      int
		wantOK           bool
	}{
		{"data-web-0", "web", 0, true},
		{"data-web-12", "web", 12, true},
		// The template name itself contains the StatefulSet's name — the
		// split must still land at the rightmost occurrence, right before
		// the ordinal.
		{"web-data-web-3", "web", 3, true},
		{"unrelated-claim", "web", 0, false},
		{"web-0", "web", 0, false}, // empty template name: not how this naming contract is produced
		{"data-web-abc", "web", 0, false},
		{"data-other-0", "web", 0, false},
	}
	for _, tc := range cases {
		ordinal, ok := parseStatefulSetPVCTemplateName(tc.pvcName, tc.stsName)
		if ok != tc.wantOK || (ok && ordinal != tc.wantOrdinal) {
			t.Errorf("parseStatefulSetPVCTemplateName(%q, %q) = (%d, %v), want (%d, %v)",
				tc.pvcName, tc.stsName, ordinal, ok, tc.wantOrdinal, tc.wantOK)
		}
	}
}

// --- registration ---

func TestCheckOrphanedPVCIsRegistered(t *testing.T) {
	for _, c := range sweepCheckers {
		if c.name == "orphaned pvc" {
			return
		}
	}
	t.Fatal("checkOrphanedPVC is not registered in sweepCheckers, so no sweep would ever run it")
}

func TestCheckIngressHostPathCollisionIsRegistered(t *testing.T) {
	for _, c := range sweepCheckers {
		if c.name == "ingress host+path collision" {
			return
		}
	}
	t.Fatal("checkIngressHostPathCollision is not registered in sweepCheckers, so no sweep would ever run it")
}

func TestCheckWebhookBackingServiceUnreachableIsRegistered(t *testing.T) {
	for _, c := range sweepCheckers {
		if c.name == "webhook backing service unreachable" {
			return
		}
	}
	t.Fatal("checkWebhookBackingServiceUnreachable is not registered in sweepCheckers, so no sweep would ever run it")
}

// --- checkFieldOwnershipConflict (BACKLOG.md E10, "two owners of one field", DEPL-012) ---

// managedFieldsEntry builds one metav1.ManagedFieldsEntry from a raw fieldsV1
// JSON literal, matching the shape a real API server writes (and the same
// notation internal/objdiff/fieldowner_test.go's liveObject fixture uses).
func managedFieldsEntry(t *testing.T, manager, operation, fieldsV1JSON string) metav1.ManagedFieldsEntry {
	t.Helper()
	return metav1.ManagedFieldsEntry{
		Manager:   manager,
		Operation: metav1.ManagedFieldsOperationType(operation),
		FieldsV1:  &metav1.FieldsV1{Raw: []byte(fieldsV1JSON)},
	}
}

// argoTrackingID builds a self-referencing Argo CD tracking-id annotation
// value for a namespace/name apps/Deployment — see trackingIDSelfReferences'
// own doc comment for the "<app>:<group>/<Kind>:<ns>/<name>" format this
// must match exactly to be accepted.
func argoTrackingID(app, namespace, name string) string {
	return fmt.Sprintf("%s:apps/Deployment:%s/%s", app, namespace, name)
}

// fieldOwnershipFixture builds the HPA + Deployment pair every test below
// shares, parameterized only by which manager currently owns spec.replicas —
// modeling one sweep's snapshot. Matches the REAL shape live verification
// against a real Argo CD + HPA fixture on rke2 found (BACKLOG.md E10): at any
// one instant exactly ONE manager claims spec.replicas — argocd-controller
// via Apply/Update with no subresource, or kube-controller-manager via
// Update through the scale subresource — never both at once. currentOwner
// controls which one this snapshot shows; the caller drives
// checkFieldOwnershipConflict across several such snapshots to simulate
// successive sweeps.
func fieldOwnershipFixture(t *testing.T, currentOwner string) (*appsv1.Deployment, *autoscalingv2.HorizontalPodAutoscaler) {
	t.Helper()
	var fields []metav1.ManagedFieldsEntry
	switch currentOwner {
	case "argocd-controller":
		// Argo's claim on spec.replicas coexists with its claims on other
		// fields it always owns (template, selector, ...) — trimmed here to
		// just replicas since OwnersOf is only ever asked about that one path.
		fields = []metav1.ManagedFieldsEntry{
			managedFieldsEntry(t, "argocd-controller", "Apply", `{"f:spec":{"f:replicas":{},"f:template":{}}}`),
		}
	case "kube-controller-manager":
		// The real, live-confirmed shape: the HPA controller's write lands on
		// the scale SUBRESOURCE and claims ONLY replicas — argocd-controller's
		// own entry for this object still exists (see the comment above) but
		// its "f:replicas" key is gone, exactly as observed live.
		fields = []metav1.ManagedFieldsEntry{
			managedFieldsEntry(t, "argocd-controller", "Apply", `{"f:spec":{"f:template":{}}}`),
			managedFieldsEntry(t, "kube-controller-manager", "Update", `{"f:spec":{"f:replicas":{}}}`),
		}
	default:
		t.Fatalf("fieldOwnershipFixture: unhandled currentOwner %q", currentOwner)
	}
	dep := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:     "default",
			Name:          "checkout",
			UID:           "dep-1",
			Annotations:   map[string]string{"argocd.argoproj.io/tracking-id": argoTrackingID("checkout-app", "default", "checkout")},
			ManagedFields: fields,
		},
		Spec: appsv1.DeploymentSpec{Replicas: int32ptr(5)},
	}
	hpa := &autoscalingv2.HorizontalPodAutoscaler{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "checkout-hpa"},
		Spec: autoscalingv2.HorizontalPodAutoscalerSpec{
			ScaleTargetRef: autoscalingv2.CrossVersionObjectReference{Kind: "Deployment", APIVersion: "apps/v1", Name: "checkout"},
		},
	}
	return dep, hpa
}

// TestCheckFieldOwnershipConflict_RepeatedFlips_Fires is the positive case,
// and it drives THREE successive sweeps (argocd owns it, then the HPA takes
// over, then argocd reverts it back) because live verification proved a
// single snapshot can never show two managers claiming spec.replicas at
// once — see fieldOwnershipObservation's doc comment. Two flips
// (argocd->hpa, hpa->argocd) is the minimum that distinguishes a genuine
// fight from a one-time, unremarkable handover.
func TestCheckFieldOwnershipConflict_RepeatedFlips_Fires(t *testing.T) {
	resetFieldOwnershipHistoryForTest()
	now := time.Now()

	for i, owner := range []string{"argocd-controller", "kube-controller-manager", "argocd-controller"} {
		dep, hpa := fieldOwnershipFixture(t, owner)
		out, err := checkFieldOwnershipConflict(context.Background(), newSweepSnapshot(k8sfake.NewSimpleClientset(dep, hpa)), now, defaultSweepSustainedThreshold)
		if err != nil {
			t.Fatalf("sweep %d: checkFieldOwnershipConflict: %v", i, err)
		}
		if i < 2 {
			if len(out) != 0 {
				t.Fatalf("sweep %d (only %d flip(s) so far): got %d candidates, want 0 — a single handover is not proof of a fight: %+v", i, i, len(out), out)
			}
			continue
		}
		// Third sweep: argocd -> hpa -> argocd is two flips, meeting
		// minFieldOwnershipFlips.
		if len(out) != 1 {
			t.Fatalf("sweep %d: got %d candidates, want exactly 1: %+v", i, len(out), out)
		}
		c := out[0]
		if c.Reason != reasonFieldOwnershipConflict {
			t.Errorf("Reason = %q, want %q", c.Reason, reasonFieldOwnershipConflict)
		}
		if c.Name != "checkout" || c.Namespace != "default" {
			t.Errorf("flagged %s/%s, want default/checkout", c.Namespace, c.Name)
		}
		if c.Severity != "medium" {
			t.Errorf("Severity = %q, want medium", c.Severity)
		}
		if c.RelatedWorkloadGVK != "autoscaling/v2/HorizontalPodAutoscaler" || c.RelatedWorkloadName != "checkout-hpa" {
			t.Errorf("RelatedWorkload not set to the owning HPA: %+v", c)
		}
		for _, want := range []string{"argocd-controller", "kube-controller-manager", "spec.replicas", "checkout-hpa", "2 times"} {
			if !strings.Contains(c.Message, want) {
				t.Errorf("Message = %q, want it to mention %q", c.Message, want)
			}
		}
	}
}

// TestCheckFieldOwnershipConflict_SingleHandover_DoesNotFire pins the case
// minFieldOwnershipFlips exists for: the object is created by GitOps, and the
// HPA claims spec.replicas exactly once afterward and never gives it back
// (nothing else ever reclaims it). One flip is not evidence of a fight.
func TestCheckFieldOwnershipConflict_SingleHandover_DoesNotFire(t *testing.T) {
	resetFieldOwnershipHistoryForTest()
	now := time.Now()

	for _, owner := range []string{"argocd-controller", "kube-controller-manager", "kube-controller-manager", "kube-controller-manager"} {
		dep, hpa := fieldOwnershipFixture(t, owner)
		out, err := checkFieldOwnershipConflict(context.Background(), newSweepSnapshot(k8sfake.NewSimpleClientset(dep, hpa)), now, defaultSweepSustainedThreshold)
		if err != nil {
			t.Fatalf("checkFieldOwnershipConflict: %v", err)
		}
		if len(out) != 0 {
			t.Fatalf("one handover that then stays put is not a conflict, however many further sweeps confirm it stayed put — got %+v", out)
		}
	}
}

func TestCheckFieldOwnershipConflict_HPAOnly_NoGitOpsOwnership_DoesNotFire(t *testing.T) {
	resetFieldOwnershipHistoryForTest()
	now := time.Now()
	// No GitOps annotation/label at all — a plain, unmanaged Deployment that
	// only the HPA controller has ever written spec.replicas on. The single
	// (real) common healthy case this check must not flag, run across
	// several sweeps to confirm it never accumulates a false conflict.
	dep := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      "checkout",
			ManagedFields: []metav1.ManagedFieldsEntry{
				managedFieldsEntry(t, "kube-controller-manager", "Update", `{"f:spec":{"f:replicas":{}}}`),
			},
		},
		Spec: appsv1.DeploymentSpec{Replicas: int32ptr(5)},
	}
	hpa := &autoscalingv2.HorizontalPodAutoscaler{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "checkout-hpa"},
		Spec: autoscalingv2.HorizontalPodAutoscalerSpec{
			ScaleTargetRef: autoscalingv2.CrossVersionObjectReference{Kind: "Deployment", APIVersion: "apps/v1", Name: "checkout"},
		},
	}
	for i := 0; i < 3; i++ {
		out, err := checkFieldOwnershipConflict(context.Background(), newSweepSnapshot(k8sfake.NewSimpleClientset(dep, hpa)), now, defaultSweepSustainedThreshold)
		if err != nil {
			t.Fatalf("checkFieldOwnershipConflict: %v", err)
		}
		if len(out) != 0 {
			t.Fatalf("sweep %d: no GitOps ownership at all means no reconciler to fight the HPA — got %+v", i, out)
		}
	}
}

func TestCheckFieldOwnershipConflict_GitOpsOnly_NoHPA_DoesNotFire(t *testing.T) {
	resetFieldOwnershipHistoryForTest()
	now := time.Now()
	// Argo-managed, and managedFields even shows a second manager once
	// touching the object — but no HorizontalPodAutoscaler exists in the
	// cluster at all, so there is nothing to fight over spec.replicas.
	dep := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:   "default",
			Name:        "checkout",
			Annotations: map[string]string{"argocd.argoproj.io/tracking-id": argoTrackingID("checkout-app", "default", "checkout")},
			ManagedFields: []metav1.ManagedFieldsEntry{
				managedFieldsEntry(t, "argocd-controller", "Apply", `{"f:spec":{"f:replicas":{}}}`),
				managedFieldsEntry(t, "hand-edit", "Update", `{"f:metadata":{"f:annotations":{}}}`),
			},
		},
		Spec: appsv1.DeploymentSpec{Replicas: int32ptr(5)},
	}
	out, err := checkFieldOwnershipConflict(context.Background(), newSweepSnapshot(k8sfake.NewSimpleClientset(dep)), now, defaultSweepSustainedThreshold)
	if err != nil {
		t.Fatalf("checkFieldOwnershipConflict: %v", err)
	}
	if len(out) != 0 {
		t.Fatalf("no HPA in the cluster at all means nothing scales this Deployment — got %+v", out)
	}
}

func TestCheckFieldOwnershipConflict_BothManageObjectButDifferentFields_DoesNotFire(t *testing.T) {
	resetFieldOwnershipHistoryForTest()
	now := time.Now()
	// GitOps and the HPA both genuinely touch this object across every
	// sweep — but GitOps only ever claims metadata.annotations, never
	// spec.replicas, so the SAME manager (kube-controller-manager) owns
	// spec.replicas every single time: Flips never leaves 0. This is the
	// case the doc comment calls out explicitly: object-level co-management
	// is common and not itself a fault.
	dep := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:   "default",
			Name:        "checkout",
			Annotations: map[string]string{"argocd.argoproj.io/tracking-id": argoTrackingID("checkout-app", "default", "checkout")},
			ManagedFields: []metav1.ManagedFieldsEntry{
				managedFieldsEntry(t, "argocd-controller", "Apply", `{"f:metadata":{"f:annotations":{"f:argocd.argoproj.io/tracking-id":{}}}}`),
				managedFieldsEntry(t, "kube-controller-manager", "Update", `{"f:spec":{"f:replicas":{}}}`),
			},
		},
		Spec: appsv1.DeploymentSpec{Replicas: int32ptr(5)},
	}
	hpa := &autoscalingv2.HorizontalPodAutoscaler{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "checkout-hpa"},
		Spec: autoscalingv2.HorizontalPodAutoscalerSpec{
			ScaleTargetRef: autoscalingv2.CrossVersionObjectReference{Kind: "Deployment", APIVersion: "apps/v1", Name: "checkout"},
		},
	}
	for i := 0; i < 3; i++ {
		out, err := checkFieldOwnershipConflict(context.Background(), newSweepSnapshot(k8sfake.NewSimpleClientset(dep, hpa)), now, defaultSweepSustainedThreshold)
		if err != nil {
			t.Fatalf("checkFieldOwnershipConflict: %v", err)
		}
		if len(out) != 0 {
			t.Fatalf("sweep %d: GitOps and the HPA touch different fields, not the same one — this must not fire: got %+v", i, out)
		}
	}
}

func TestManagedFieldsToOwnershipObject_RoundTripsThroughOwnersOf(t *testing.T) {
	fields := []metav1.ManagedFieldsEntry{
		managedFieldsEntry(t, "argocd-controller", "Apply", `{"f:spec":{"f:replicas":{}}}`),
	}
	obj := managedFieldsToOwnershipObject(fields)
	owners := objdiff.OwnersOf(obj, "spec.replicas")
	if len(owners) != 1 || owners[0].Manager != "argocd-controller" {
		t.Fatalf("OwnersOf on the converted object = %+v, want exactly argocd-controller", owners)
	}
}

func TestCurrentFieldManager(t *testing.T) {
	owners := []objdiff.FieldOwner{
		{Manager: "argus-remediate", Exact: true},
		{Manager: "argocd-controller", Exact: true},
	}
	if got := currentFieldManager(owners, argusRemediateFieldManager); got != "argocd-controller" {
		t.Fatalf("currentFieldManager = %q, want argocd-controller (argus-remediate skipped)", got)
	}
	if got := currentFieldManager(nil, argusRemediateFieldManager); got != "" {
		t.Fatalf("currentFieldManager(nil) = %q, want empty", got)
	}
	onlyArgus := []objdiff.FieldOwner{{Manager: "argus-remediate", Exact: true}}
	if got := currentFieldManager(onlyArgus, argusRemediateFieldManager); got != "" {
		t.Fatalf("currentFieldManager with only ARGUS's own manager = %q, want empty", got)
	}
}

func TestCheckFieldOwnershipConflictIsRegistered(t *testing.T) {
	for _, c := range sweepCheckers {
		if c.name == "hpa/gitops field ownership conflict" {
			return
		}
	}
	t.Fatal("checkFieldOwnershipConflict is not registered in sweepCheckers, so no sweep would ever run it")
}

func TestRunOneSweep_OneCheckFailingDoesNotBlockOthers(t *testing.T) {
	// Regression guard for runOneSweep's own documented contract: swap in a
	// checker that always errors alongside one that always succeeds, and
	// confirm the successful one's candidate still gets sent.
	original := sweepCheckers
	defer func() { sweepCheckers = original }()

	findingCh := make(chan tunnel.Finding, 2)
	sweepCheckers = []sweepChecker{
		{"always fails", func(ctx context.Context, snap *sweepSnapshot, now time.Time, sustainedThreshold time.Duration) ([]sweepCandidate, error) {
			return nil, errAlwaysFails
		}},
		{"always succeeds", func(ctx context.Context, snap *sweepSnapshot, now time.Time, sustainedThreshold time.Duration) ([]sweepCandidate, error) {
			// SustainedFrom set: this test is about one checker's error not
			// blocking another's result, so it must not also be gated by the
			// sustain logic (which would need two sweeps to emit anything).
			return []sweepCandidate{{GVK: "v1/Pod", Namespace: "default", Name: "x", Reason: "TestReason",
				Severity: "medium", SustainedFrom: now, OccurredAt: now}}, nil
		}},
	}

	runOneSweep(context.Background(), k8sfake.NewSimpleClientset(), nil, findingCh, map[string]time.Time{}, map[string]time.Time{}, defaultFindingResendCooldown, defaultSweepSustainedThreshold, defaultTestCheckerTimeout, nil)

	select {
	case f := <-findingCh:
		if f.Reason != "TestReason" {
			t.Errorf("Reason = %q, want %q", f.Reason, "TestReason")
		}
	default:
		t.Fatal("the succeeding checker's candidate should still have been sent despite the other checker's error")
	}
}

// --- Regression tests for three real bugs found in code review, 2026-08-21 ---

// TestRunOneSweepGatesCandidatesWithNoAuthoritativeTimestamp is the fix for the
// worst of them: three checks compared defaultSweepSustainedThreshold against the
// *object's* creation time, which any object older than the threshold satisfies
// trivially. A month-old StatefulSet going 2/3-ready during a normal rolling
// update was reported immediately as a "high" severity problem.
//
// A candidate with no SustainedFrom must now be observed for at least the
// threshold before it is reported.
func TestRunOneSweepGatesCandidatesWithNoAuthoritativeTimestamp(t *testing.T) {
	original := sweepCheckers
	defer func() { sweepCheckers = original }()

	// A checker that always reports the same problem, with no authoritative
	// "since when" — exactly the StatefulSet/DaemonSet/Service shape.
	sweepCheckers = []sweepChecker{{"transient", func(_ context.Context, _ *sweepSnapshot, now time.Time, _ time.Duration) ([]sweepCandidate, error) {
		return []sweepCandidate{{
			GVK: "apps/v1/StatefulSet", Namespace: "default", Name: "db",
			Reason: reasonStatefulSetReplicasUnavailable, Severity: "high", OccurredAt: now,
		}}, nil
	}}}

	findingCh := make(chan tunnel.Finding, 4)
	lastSent := map[string]time.Time{}
	firstObserved := map[string]time.Time{}
	cs := k8sfake.NewSimpleClientset()

	// First sweep: seen for the first time, so nothing is reported.
	runOneSweep(context.Background(), cs, nil, findingCh, lastSent, firstObserved, defaultFindingResendCooldown, defaultSweepSustainedThreshold, defaultTestCheckerTimeout, nil)
	if len(findingCh) != 0 {
		t.Fatalf("first observation must not report; got %d findings", len(findingCh))
	}
	if len(firstObserved) != 1 {
		t.Fatalf("first sweep should record one observation, got %d", len(firstObserved))
	}

	// Backdate the observation past the threshold, simulating the problem
	// persisting across sweeps, and sweep again.
	for fp := range firstObserved {
		firstObserved[fp] = time.Now().Add(-defaultSweepSustainedThreshold - time.Minute)
	}
	runOneSweep(context.Background(), cs, nil, findingCh, lastSent, firstObserved, defaultFindingResendCooldown, defaultSweepSustainedThreshold, defaultTestCheckerTimeout, nil)
	if len(findingCh) != 1 {
		t.Fatalf("a problem observed for longer than the threshold must report; got %d findings", len(findingCh))
	}
}

// A problem that clears must have its clock forgotten, so a later brief blip
// isn't reported instantly on the strength of a months-old observation.
func TestRunOneSweepForgetsClearedProblems(t *testing.T) {
	original := sweepCheckers
	defer func() { sweepCheckers = original }()

	reporting := true
	sweepCheckers = []sweepChecker{{"flaky", func(_ context.Context, _ *sweepSnapshot, now time.Time, _ time.Duration) ([]sweepCandidate, error) {
		if !reporting {
			return nil, nil
		}
		return []sweepCandidate{{
			GVK: "apps/v1/DaemonSet", Namespace: "default", Name: "agent",
			Reason: reasonDaemonSetReplicasUnavailable, Severity: "high", OccurredAt: now,
		}}, nil
	}}}

	findingCh := make(chan tunnel.Finding, 4)
	firstObserved := map[string]time.Time{}
	cs := k8sfake.NewSimpleClientset()

	runOneSweep(context.Background(), cs, nil, findingCh, map[string]time.Time{}, firstObserved, defaultFindingResendCooldown, defaultSweepSustainedThreshold, defaultTestCheckerTimeout, nil)
	if len(firstObserved) != 1 {
		t.Fatalf("expected the problem to be recorded, got %d", len(firstObserved))
	}

	reporting = false // the problem clears
	runOneSweep(context.Background(), cs, nil, findingCh, map[string]time.Time{}, firstObserved, defaultFindingResendCooldown, defaultSweepSustainedThreshold, defaultTestCheckerTimeout, nil)
	if len(firstObserved) != 0 {
		t.Errorf("a cleared problem must be pruned so its clock restarts on recurrence, still tracking %d", len(firstObserved))
	}
}

// TestCheckFailedJobsIgnoresOldFailures is the fix for an unbounded re-report
// loop. A failed Job persists until deleted (no TTL controller by default), so
// re-reporting it on every sweep forever meant that once an operator resolved
// the incident, the next sweep opened a brand-new one — the hub only correlates
// into incidents that are not already Resolved/Dismissed. That produced a fresh,
// unresolvable incident every few minutes indefinitely, and a fresh paid
// investigation each time under auto-analysis.
func TestCheckFailedJobsIgnoresOldFailures(t *testing.T) {
	now := time.Now()
	recent := &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "recent-failure"},
		Status: batchv1.JobStatus{Conditions: []batchv1.JobCondition{
			{Type: batchv1.JobFailed, Status: corev1.ConditionTrue, Reason: "BackoffLimitExceeded",
				LastTransitionTime: metav1.NewTime(now.Add(-5 * time.Minute))},
		}},
	}
	ancient := &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "ancient-failure"},
		Status: batchv1.JobStatus{Conditions: []batchv1.JobCondition{
			{Type: batchv1.JobFailed, Status: corev1.ConditionTrue, Reason: "BackoffLimitExceeded",
				LastTransitionTime: metav1.NewTime(now.Add(-72 * time.Hour))},
		}},
	}

	out, err := checkFailedJobs(context.Background(), newSweepSnapshot(k8sfake.NewSimpleClientset(recent, ancient)), now, defaultSweepSustainedThreshold)
	if err != nil {
		t.Fatalf("checkFailedJobs: %v", err)
	}
	if len(out) != 1 || out[0].Name != "recent-failure" {
		t.Fatalf("got %+v, want only the recent failure — an old one is not news and re-reporting it forever creates unresolvable incidents", out)
	}
	// Terminal and authoritative: no sustain wait should apply.
	if out[0].SustainedFrom.IsZero() {
		t.Error("a failed Job's transition time is authoritative, so SustainedFrom must be set")
	}
}

// TestCheckNodeNotReadyReportsMissingReadyCondition covers a branch that could
// never fire: it set transitionedAt = now and then required
// now-transitionedAt >= threshold, i.e. 0 >= 10m. The doc comment claimed a
// node with no Ready condition was treated as NotReady; in fact it was silently
// skipped on every sweep.
func TestCheckNodeNotReadyReportsMissingReadyCondition(t *testing.T) {
	now := time.Now()
	noCondition := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "silent-node"}}

	out, err := checkNodeNotReady(context.Background(), newSweepSnapshot(k8sfake.NewSimpleClientset(noCondition)), now, defaultSweepSustainedThreshold)
	if err != nil {
		t.Fatalf("checkNodeNotReady: %v", err)
	}
	if len(out) != 1 || out[0].Name != "silent-node" {
		t.Fatalf("a Node reporting no Ready condition must be a candidate, got %+v", out)
	}
	// Left to the observation gate, since the node told us nothing about when.
	if !out[0].SustainedFrom.IsZero() {
		t.Error("with no Ready condition there is no authoritative timestamp, so SustainedFrom must be zero")
	}
	// And the message must not claim a duration we never measured.
	if strings.Contains(out[0].Message, "has been NotReady for") {
		t.Errorf("message invents a duration it cannot know: %q", out[0].Message)
	}
	if out[0].OccurredAt.IsZero() {
		t.Error("OccurredAt must always carry a real timestamp")
	}
}

// TestCheckHPAScalingInactive covers the failure the AbleToScale-only check
// missed entirely, found by pointing a real HPA at a real cluster: an
// autoscaler that can reach its target perfectly well but cannot compute a
// desired replica count, so it silently does nothing. Real conditions observed
// were AbleToScale=True/SucceededGetScale alongside
// ScalingActive=False/FailedGetResourceMetric.
func TestCheckHPAScalingInactive(t *testing.T) {
	now := time.Now()
	hpa := func(name, reason string, status corev1.ConditionStatus, age time.Duration) *autoscalingv2.HorizontalPodAutoscaler {
		return &autoscalingv2.HorizontalPodAutoscaler{
			ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: name},
			Status: autoscalingv2.HorizontalPodAutoscalerStatus{
				Conditions: []autoscalingv2.HorizontalPodAutoscalerCondition{
					// AbleToScale True throughout: this is precisely the case
					// where the old check found nothing wrong.
					{Type: autoscalingv2.AbleToScale, Status: corev1.ConditionTrue, Reason: "SucceededGetScale", LastTransitionTime: metav1.NewTime(now.Add(-time.Hour))},
					{Type: autoscalingv2.ScalingActive, Status: status, Reason: reason, LastTransitionTime: metav1.NewTime(now.Add(-age))},
				},
			},
		}
	}

	inert := hpa("no-cpu-request", "FailedGetResourceMetric", corev1.ConditionFalse, 20*time.Minute)
	// A deliberately disabled autoscaler is a choice, not a fault.
	disabled := hpa("scaled-to-zero", "ScalingDisabled", corev1.ConditionFalse, 20*time.Minute)
	fresh := hpa("just-started", "FailedGetResourceMetric", corev1.ConditionFalse, time.Minute)
	healthy := hpa("working", "ValidMetricFound", corev1.ConditionTrue, time.Hour)

	out, err := checkHPAScalingBlocked(context.Background(), newSweepSnapshot(
		k8sfake.NewSimpleClientset(inert, disabled, fresh, healthy)), now, defaultSweepSustainedThreshold)
	if err != nil {
		t.Fatalf("checkHPAScalingBlocked: %v", err)
	}
	if len(out) != 1 {
		t.Fatalf("got %d candidates %+v, want exactly 1 (only the inert HPA)", len(out), out)
	}
	if out[0].Name != "no-cpu-request" {
		t.Errorf("Name = %q, want no-cpu-request", out[0].Name)
	}
	if out[0].Reason != reasonHPAMetricsUnavailable {
		t.Errorf("Reason = %q, want %q — an inert autoscaler is a different problem from one that lost its target",
			out[0].Reason, reasonHPAMetricsUnavailable)
	}
	if !strings.Contains(out[0].Message, "FailedGetResourceMetric") {
		t.Errorf("Message should carry the API server's own reason, got %q", out[0].Message)
	}
}

// TestCheckHPAOnlyOneCandidatePerHPA guards the deduplication decision: an HPA
// that is BOTH unable to reach its target and unable to compute a metric is one
// broken autoscaler, not two incidents.
func TestCheckHPAOnlyOneCandidatePerHPA(t *testing.T) {
	now := time.Now()
	doublyBroken := &autoscalingv2.HorizontalPodAutoscaler{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "very-broken"},
		Status: autoscalingv2.HorizontalPodAutoscalerStatus{
			Conditions: []autoscalingv2.HorizontalPodAutoscalerCondition{
				{Type: autoscalingv2.AbleToScale, Status: corev1.ConditionFalse, Reason: "FailedGetScale", LastTransitionTime: metav1.NewTime(now.Add(-time.Hour))},
				{Type: autoscalingv2.ScalingActive, Status: corev1.ConditionFalse, Reason: "FailedGetResourceMetric", LastTransitionTime: metav1.NewTime(now.Add(-time.Hour))},
			},
		},
	}
	out, err := checkHPAScalingBlocked(context.Background(), newSweepSnapshot(k8sfake.NewSimpleClientset(doublyBroken)), now, defaultSweepSustainedThreshold)
	if err != nil {
		t.Fatalf("checkHPAScalingBlocked: %v", err)
	}
	if len(out) != 1 {
		t.Fatalf("got %d candidates, want 1 — one broken HPA must not become two incidents", len(out))
	}
	// The unreachable target is the more severe fact, so it wins.
	if out[0].Reason != reasonHPAScalingBlocked {
		t.Errorf("Reason = %q, want %q (a lost target subsumes an inert metric)", out[0].Reason, reasonHPAScalingBlocked)
	}
}

// TestCheckPodPendingTimeoutCatchesAStuckForeverPod is the periodic backstop
// added after a live cluster proved the watch-based check (pod_conditions_
// detector.go's checkPendingTimeout) can miss a Pod entirely, not just
// slowly: a Pod requesting more than any node can ever satisfy sat Pending
// for over 6 minutes on a real 5-node cluster with zero PendingTimeout
// finding, because the scheduler's repeated retries never repatched a
// PodScheduled condition whose reason/message never changed — so the Pod
// received exactly one watch delivery (its own creation) in its entire life.
func TestCheckPodPendingTimeoutCatchesAStuckForeverPod(t *testing.T) {
	now := time.Now()
	stuckForever := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "stuck-forever", Namespace: "apps", CreationTimestamp: metav1.NewTime(now.Add(-20 * time.Minute))},
		Status:     corev1.PodStatus{Phase: corev1.PodPending},
	}
	tooYoung := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "just-created", Namespace: "apps", CreationTimestamp: metav1.NewTime(now.Add(-30 * time.Second))},
		Status:     corev1.PodStatus{Phase: corev1.PodPending},
	}
	running := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "healthy", Namespace: "apps", CreationTimestamp: metav1.NewTime(now.Add(-time.Hour))},
		Status:     corev1.PodStatus{Phase: corev1.PodRunning},
	}

	out, err := checkPodPendingTimeout(context.Background(), newSweepSnapshot(k8sfake.NewSimpleClientset(stuckForever, tooYoung, running)), now, defaultSweepSustainedThreshold)
	if err != nil {
		t.Fatalf("checkPodPendingTimeout: %v", err)
	}
	if len(out) != 1 || out[0].Name != "stuck-forever" {
		t.Fatalf("got %+v, want exactly one candidate for stuck-forever", out)
	}
	if out[0].Reason != reasonPendingTimeout {
		t.Errorf("Reason = %q, want %q — must match the watch-based check's reason so both paths land on the same incident", out[0].Reason, reasonPendingTimeout)
	}
	if out[0].GVK != "v1/Pod" {
		t.Errorf("GVK = %q, want v1/Pod", out[0].GVK)
	}
}

// TestCheckPodPendingTimeoutResolvesWorkload confirms this sweep checker
// also resolves and carries workload identity (BACKLOG.md's A3, migration
// 000042) — the same replica-level correlation the watch-based checks get,
// so a permanently-stuck pod caught only by this backstop still groups with
// its siblings.
func TestCheckPodPendingTimeoutResolvesWorkload(t *testing.T) {
	now := time.Now()
	rs := &appsv1.ReplicaSet{
		ObjectMeta: metav1.ObjectMeta{
			Name: "web-7d9c8f6b5", Namespace: "apps",
			OwnerReferences: []metav1.OwnerReference{
				{APIVersion: "apps/v1", Kind: "Deployment", Name: "web", Controller: boolPtr(true)},
			},
		},
	}
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: "web-7d9c8f6b5-x8k2q", Namespace: "apps", CreationTimestamp: metav1.NewTime(now.Add(-20 * time.Minute)),
			OwnerReferences: []metav1.OwnerReference{
				{APIVersion: "apps/v1", Kind: "ReplicaSet", Name: "web-7d9c8f6b5", Controller: boolPtr(true)},
			},
		},
		Status: corev1.PodStatus{Phase: corev1.PodPending},
	}

	out, err := checkPodPendingTimeout(context.Background(), newSweepSnapshot(k8sfake.NewSimpleClientset(pod, rs)), now, defaultSweepSustainedThreshold)
	if err != nil {
		t.Fatalf("checkPodPendingTimeout: %v", err)
	}
	if len(out) != 1 {
		t.Fatalf("got %+v, want exactly one candidate", out)
	}
	if out[0].WorkloadGVK != "apps/v1/Deployment" || out[0].WorkloadName != "web" {
		t.Errorf("WorkloadGVK/WorkloadName = %q/%q, want %q/%q", out[0].WorkloadGVK, out[0].WorkloadName, "apps/v1/Deployment", "web")
	}
}

// TestCheckPodPendingTimeoutCarriesPodPriority guards
// internal/importance's workload-criticality factor's ONLY agent-side sweep
// source: this Pod's own resolved spec.priority must land on the
// sweepCandidate unchanged, and a Pod with no resolved priority (the
// common case — most Pods carry none) must come through as nil, never a
// fabricated zero.
func TestCheckPodPendingTimeoutCarriesPodPriority(t *testing.T) {
	now := time.Now()
	withPriority := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "critical-pod", Namespace: "apps", CreationTimestamp: metav1.NewTime(now.Add(-20 * time.Minute))},
		Spec:       corev1.PodSpec{Priority: int32Ptr(2000000000)},
		Status:     corev1.PodStatus{Phase: corev1.PodPending},
	}
	withoutPriority := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "ordinary-pod", Namespace: "apps", CreationTimestamp: metav1.NewTime(now.Add(-20 * time.Minute))},
		Status:     corev1.PodStatus{Phase: corev1.PodPending},
	}

	out, err := checkPodPendingTimeout(context.Background(), newSweepSnapshot(k8sfake.NewSimpleClientset(withPriority, withoutPriority)), now, defaultSweepSustainedThreshold)
	if err != nil {
		t.Fatalf("checkPodPendingTimeout: %v", err)
	}
	if len(out) != 2 {
		t.Fatalf("got %+v, want exactly two candidates", out)
	}
	for _, c := range out {
		switch c.Name {
		case "critical-pod":
			if c.PodPriority == nil || *c.PodPriority != 2000000000 {
				t.Errorf("critical-pod PodPriority = %v, want 2000000000", c.PodPriority)
			}
		case "ordinary-pod":
			if c.PodPriority != nil {
				t.Errorf("ordinary-pod PodPriority = %v, want nil (unresolved, not zero)", *c.PodPriority)
			}
		}
	}
}

// TestCheckPodPendingTimeoutFingerprintMatchesWatchBasedCheck guards the
// property that makes the backstop safe to add without doubling incidents:
// whichever path fires first must produce the SAME fingerprint, so a Pod
// whose status happens to transition (the common case, caught fast by the
// watch) and a Pod that never does (the pathological case, caught by this
// sweep) both attach to one incident rather than opening two for one Pod.
func TestCheckPodPendingTimeoutFingerprintMatchesWatchBasedCheck(t *testing.T) {
	now := time.Now()
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "web-abc123", Namespace: "apps", CreationTimestamp: metav1.NewTime(now.Add(-time.Hour))},
		Status:     corev1.PodStatus{Phase: corev1.PodPending},
	}
	out, err := checkPodPendingTimeout(context.Background(), newSweepSnapshot(k8sfake.NewSimpleClientset(pod)), now, defaultSweepSustainedThreshold)
	if err != nil || len(out) != 1 {
		t.Fatalf("checkPodPendingTimeout: %v, %+v", err, out)
	}
	sweepFP := candidateFingerprint(out[0])
	watchFP := computeFingerprint("apps", "Pod", "web-abc123", reasonPendingTimeout)
	if sweepFP != watchFP {
		t.Errorf("sweep fingerprint %q != watch-based fingerprint %q — the two paths would open separate incidents for the same pod", sweepFP, watchFP)
	}
}

// --- ReplicaFailure: the only durable signal for a controller that cannot
// create pods (quota, LimitRange, a rejecting webhook, Pod Security, an
// unsatisfiable node selector). The Warning Event carrying the same text is
// discarded by detector.go's staleEventThreshold once the controller stops
// retrying, so past that point these tests cover the only path that reports the
// fault at all. ---

// quotaRejection is the API server's own text for the most common cause, kept
// verbatim so the assertions below prove the operator-actionable part (which
// quota, which resource) survives into the finding's message.
const quotaRejection = `pods "web-7d9c8f6b5-x" is forbidden: exceeded quota: compute-resources, requested: requests.cpu=1, used: requests.cpu=4, limited: requests.cpu=4`

func deploymentReplicaFailureCond(status corev1.ConditionStatus, reason, message string, transitioned time.Time) appsv1.DeploymentCondition {
	c := appsv1.DeploymentCondition{Type: appsv1.DeploymentReplicaFailure, Status: status, Reason: reason, Message: message}
	if !transitioned.IsZero() {
		c.LastTransitionTime = metav1.NewTime(transitioned)
	}
	return c
}

func TestCheckReplicaFailure(t *testing.T) {
	now := time.Now()
	longAgo := now.Add(-2 * time.Hour)
	available := func(status corev1.ConditionStatus) appsv1.DeploymentCondition {
		return appsv1.DeploymentCondition{Type: appsv1.DeploymentAvailable, Status: status, LastTransitionTime: metav1.NewTime(longAgo)}
	}
	deployment := func(name string, desired, ready int32, conds ...appsv1.DeploymentCondition) *appsv1.Deployment {
		return &appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: name, CreationTimestamp: metav1.NewTime(now.Add(-24 * time.Hour))},
			Spec:       appsv1.DeploymentSpec{Replicas: int32ptr(desired)},
			Status:     appsv1.DeploymentStatus{ReadyReplicas: ready, Conditions: conds},
		}
	}

	cases := []struct {
		name string
		objs []runtime.Object
		// want is the set of object names expected to fire, so a case that
		// asserts silence is written the same way as one that asserts a finding.
		want []string
		// wantZeroSustainedFrom asserts the candidate deferred to
		// sustainedLongEnough's observed-duration gate instead of claiming a
		// cluster timestamp it never had.
		wantZeroSustainedFrom bool
	}{
		{
			// The whole reason this check exists: a 3→4 scale-up refused by a
			// full quota keeps minimum availability, so Available stays True and
			// checkDeploymentReplicas is silent by construction.
			name: "sustained, and Available is still True — the case nothing else reports",
			objs: []runtime.Object{deployment("blocked-scale-up", 4, 3,
				available(corev1.ConditionTrue),
				deploymentReplicaFailureCond(corev1.ConditionTrue, "FailedCreate", quotaRejection, longAgo))},
			want: []string{"blocked-scale-up"},
		},
		{
			name: "present but too recent — an ordinary rollout hiccup is not news",
			objs: []runtime.Object{deployment("just-blocked", 4, 3,
				available(corev1.ConditionTrue),
				deploymentReplicaFailureCond(corev1.ConditionTrue, "FailedCreate", quotaRejection, now.Add(-30*time.Second)))},
		},
		{
			name: "condition absent entirely",
			objs: []runtime.Object{deployment("no-condition", 3, 3, available(corev1.ConditionTrue))},
		},
		{
			// The controller REMOVES the condition when the failure clears, so a
			// False one is the residue of a fixed problem, not a fault.
			name: "present but False",
			objs: []runtime.Object{deployment("recovered", 3, 3, available(corev1.ConditionTrue),
				deploymentReplicaFailureCond(corev1.ConditionFalse, "FailedCreate", quotaRejection, longAgo))},
		},
		{
			name: "healthy workload, no conditions at all",
			objs: []runtime.Object{deployment("healthy", 3, 3)},
		},
		{
			// Deliberately NOT skipped the way checkDeploymentReplicas skips a
			// zero-replica Deployment: Available=False at zero replicas is a
			// choice somebody made, but a refused DELETE call is not.
			name: "scaled to zero with a FailedDelete still fires",
			objs: []runtime.Object{deployment("wont-die", 0, 2,
				deploymentReplicaFailureCond(corev1.ConditionTrue, "FailedDelete", `pods "wont-die-abc" is forbidden by webhook "deny-delete"`, now.Add(-time.Hour)))},
			want: []string{"wont-die"},
		},
		{
			name: "no transition time: reported, but with the observed-duration gate left to apply",
			objs: []runtime.Object{deployment("no-timestamp", 3, 0,
				deploymentReplicaFailureCond(corev1.ConditionTrue, "FailedCreate", quotaRejection, time.Time{}))},
			want:                  []string{"no-timestamp"},
			wantZeroSustainedFrom: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, err := checkReplicaFailure(context.Background(), newSweepSnapshot(k8sfake.NewSimpleClientset(tc.objs...)), now, defaultSweepSustainedThreshold)
			if err != nil {
				t.Fatalf("checkReplicaFailure: %v", err)
			}
			var got []string
			for _, c := range out {
				got = append(got, c.Name)
				if c.Reason != reasonDeploymentReplicaFailure {
					t.Errorf("Reason = %q, want %q", c.Reason, reasonDeploymentReplicaFailure)
				}
				if c.GVK != "apps/v1/Deployment" {
					t.Errorf("GVK = %q, want apps/v1/Deployment", c.GVK)
				}
				if c.OccurredAt.IsZero() {
					t.Error("OccurredAt must always carry a real timestamp")
				}
				if tc.wantZeroSustainedFrom && !c.SustainedFrom.IsZero() {
					t.Errorf("SustainedFrom = %v, want zero — the condition carried no transition time, so the sustain gate must apply", c.SustainedFrom)
				}
				if !tc.wantZeroSustainedFrom && c.SustainedFrom.IsZero() {
					t.Error("SustainedFrom must be the condition's own LastTransitionTime, not first observation")
				}
			}
			sort.Strings(got)
			want := append([]string(nil), tc.want...)
			sort.Strings(want)
			if strings.Join(got, ",") != strings.Join(want, ",") {
				t.Fatalf("fired for %v, want %v", got, want)
			}
		})
	}
}

// TestCheckReplicaFailureMessageNamesTheCause is the point of the whole check: a
// finding that says "pods are not being created" is a page with no next step,
// while one quoting the condition's Reason and Message names the quota. It also
// pins the Available state into the message, which is what lets this finding
// stand on its own where it shares an incident with checkDeploymentReplicas'.
func TestCheckReplicaFailureMessageNamesTheCause(t *testing.T) {
	now := time.Now()
	transitioned := now.Add(-90 * time.Minute)
	dep := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "web", UID: "d-1", ResourceVersion: "42"},
		Spec:       appsv1.DeploymentSpec{Replicas: int32ptr(4)},
		Status: appsv1.DeploymentStatus{
			ReadyReplicas: 3,
			Conditions: []appsv1.DeploymentCondition{
				{Type: appsv1.DeploymentAvailable, Status: corev1.ConditionTrue, LastTransitionTime: metav1.NewTime(now.Add(-24 * time.Hour))},
				deploymentReplicaFailureCond(corev1.ConditionTrue, "FailedCreate", quotaRejection, transitioned),
			},
		},
	}

	out, err := checkReplicaFailure(context.Background(), newSweepSnapshot(k8sfake.NewSimpleClientset(dep)), now, defaultSweepSustainedThreshold)
	if err != nil || len(out) != 1 {
		t.Fatalf("checkReplicaFailure: %v, %+v", err, out)
	}
	c := out[0]
	for _, want := range []string{"FailedCreate", "exceeded quota: compute-resources", "3/4 replicas ready", "Available=True"} {
		if !strings.Contains(c.Message, want) {
			t.Errorf("message %q does not contain %q", c.Message, want)
		}
	}
	if !c.SustainedFrom.Equal(transitioned) {
		t.Errorf("SustainedFrom = %v, want the condition's LastTransitionTime %v", c.SustainedFrom, transitioned)
	}
	// "high", not "medium": see the check's own severity note. A medium sits
	// below the default auto-analysis severities, which would reproduce the
	// silence this check exists to end.
	if c.Severity != "high" {
		t.Errorf("Severity = %q, want high", c.Severity)
	}
	if c.UID != "d-1" || c.ResourceVersion != "42" {
		t.Errorf("UID/ResourceVersion = %q/%q, want d-1/42", c.UID, c.ResourceVersion)
	}
}

// TestCheckReplicaFailureDoesNotDoubleReportDeploymentAndReplicaSet covers the
// dedup rule. The Deployment controller copies its ReplicaSet's ReplicaFailure
// condition upward, so one refused create is visible on two objects with two
// different hub object keys — and object-level correlation (migration 000036)
// cannot merge those, so it would be two incidents for one fault (BACKLOG.md
// A1). The ReplicaSet is therefore suppressed when its owner carries the
// condition, and only then.
func TestCheckReplicaFailureDoesNotDoubleReportDeploymentAndReplicaSet(t *testing.T) {
	now := time.Now()
	longAgo := now.Add(-2 * time.Hour)
	rsCond := appsv1.ReplicaSetCondition{
		Type: appsv1.ReplicaSetReplicaFailure, Status: corev1.ConditionTrue,
		Reason: "FailedCreate", Message: quotaRejection, LastTransitionTime: metav1.NewTime(longAgo),
	}
	deployment := func(name string, withCondition bool) *appsv1.Deployment {
		d := &appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: name},
			Spec:       appsv1.DeploymentSpec{Replicas: int32ptr(4)},
			Status:     appsv1.DeploymentStatus{ReadyReplicas: 3},
		}
		if withCondition {
			d.Status.Conditions = []appsv1.DeploymentCondition{
				deploymentReplicaFailureCond(corev1.ConditionTrue, "FailedCreate", quotaRejection, longAgo)}
		}
		return d
	}
	replicaSet := func(name, ownerDeployment string, controller bool) *appsv1.ReplicaSet {
		rs := &appsv1.ReplicaSet{
			ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: name},
			Spec:       appsv1.ReplicaSetSpec{Replicas: int32ptr(4)},
			Status:     appsv1.ReplicaSetStatus{ReadyReplicas: 3, Conditions: []appsv1.ReplicaSetCondition{rsCond}},
		}
		if ownerDeployment != "" {
			rs.OwnerReferences = []metav1.OwnerReference{
				{APIVersion: "apps/v1", Kind: "Deployment", Name: ownerDeployment, Controller: boolptr(controller)}}
		}
		return rs
	}

	cases := []struct {
		name string
		objs []runtime.Object
		want []string
	}{
		{
			name: "the owner mirrors the condition: only the Deployment is reported",
			objs: []runtime.Object{deployment("web", true), replicaSet("web-7d9c8f6b5", "web", true)},
			want: []string{"web"},
		},
		{
			// A wedged or absent deployment controller: the mirror never
			// happens, so the ReplicaSet is the only object carrying the fault.
			// Suppressing on "an owner exists" rather than "the owner carries
			// it" would lose this entirely.
			name: "the owner does not mirror it: the ReplicaSet is the only signal",
			objs: []runtime.Object{deployment("web", false), replicaSet("web-7d9c8f6b5", "web", true)},
			want: []string{"web-7d9c8f6b5"},
		},
		{
			name: "a bare ReplicaSet with no Deployment above it",
			objs: []runtime.Object{replicaSet("standalone", "", false)},
			want: []string{"standalone"},
		},
		{
			// A merely-decorative ownerReference must not be able to silence a
			// real fault, which is why controllerDeploymentName filters on
			// Controller==true.
			name: "a non-controlling ownerReference does not suppress",
			objs: []runtime.Object{deployment("web", true), replicaSet("web-7d9c8f6b5", "web", false)},
			want: []string{"web", "web-7d9c8f6b5"},
		},
		{
			name: "a ReplicaSet whose condition is too recent stays quiet like any other",
			objs: []runtime.Object{&appsv1.ReplicaSet{
				ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "fresh"},
				Spec:       appsv1.ReplicaSetSpec{Replicas: int32ptr(4)},
				Status: appsv1.ReplicaSetStatus{ReadyReplicas: 3, Conditions: []appsv1.ReplicaSetCondition{{
					Type: appsv1.ReplicaSetReplicaFailure, Status: corev1.ConditionTrue, Reason: "FailedCreate",
					Message: quotaRejection, LastTransitionTime: metav1.NewTime(now.Add(-time.Minute))}}},
			}},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, err := checkReplicaFailure(context.Background(), newSweepSnapshot(k8sfake.NewSimpleClientset(tc.objs...)), now, defaultSweepSustainedThreshold)
			if err != nil {
				t.Fatalf("checkReplicaFailure: %v", err)
			}
			var got []string
			for _, c := range out {
				got = append(got, c.Name)
				switch c.GVK {
				case "apps/v1/Deployment":
					if c.Reason != reasonDeploymentReplicaFailure {
						t.Errorf("%s: Reason = %q, want %q", c.Name, c.Reason, reasonDeploymentReplicaFailure)
					}
				case "apps/v1/ReplicaSet":
					if c.Reason != reasonReplicaSetReplicaFailure {
						t.Errorf("%s: Reason = %q, want %q", c.Name, c.Reason, reasonReplicaSetReplicaFailure)
					}
					if !strings.Contains(c.Message, "exceeded quota: compute-resources") {
						t.Errorf("%s: message %q does not name the cause", c.Name, c.Message)
					}
				default:
					t.Errorf("%s: unexpected GVK %q", c.Name, c.GVK)
				}
			}
			sort.Strings(got)
			want := append([]string(nil), tc.want...)
			sort.Strings(want)
			if strings.Join(got, ",") != strings.Join(want, ",") {
				t.Fatalf("fired for %v, want %v", got, want)
			}
		})
	}
}

// TestCheckReplicaFailureAndUnavailableShareOneIncident pins the other half of
// the dedup decision: a Deployment that is BOTH unavailable and blocked from
// creating pods produces two candidates, and that is intended — they are two
// different facts (impact and cause), and both carry the same hub object key, so
// internal/gateway/finding.go's objectCorrelationKey folds them into one
// incident. Suppressing one was rejected because ReplicaFailure also covers
// FailedDelete, which would then hide an unrelated real outage.
func TestCheckReplicaFailureAndUnavailableShareOneIncident(t *testing.T) {
	now := time.Now()
	longAgo := now.Add(-2 * time.Hour)
	dep := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "web"},
		Spec:       appsv1.DeploymentSpec{Replicas: int32ptr(3)},
		Status: appsv1.DeploymentStatus{
			ReadyReplicas: 0,
			Conditions: []appsv1.DeploymentCondition{
				{Type: appsv1.DeploymentAvailable, Status: corev1.ConditionFalse, Reason: "MinimumReplicasUnavailable",
					Message: "Deployment does not have minimum availability.", LastTransitionTime: metav1.NewTime(longAgo)},
				deploymentReplicaFailureCond(corev1.ConditionTrue, "FailedCreate", quotaRejection, longAgo),
			},
		},
	}
	cs := k8sfake.NewSimpleClientset(dep)

	failure, err := checkReplicaFailure(context.Background(), newSweepSnapshot(cs), now, defaultSweepSustainedThreshold)
	if err != nil || len(failure) != 1 {
		t.Fatalf("checkReplicaFailure: %v, %+v", err, failure)
	}
	unavailable, err := checkDeploymentReplicas(context.Background(), newSweepSnapshot(cs), now, defaultSweepSustainedThreshold)
	if err != nil || len(unavailable) != 1 {
		t.Fatalf("checkDeploymentReplicas: %v, %+v", err, unavailable)
	}

	// Distinct fingerprints (so neither suppresses the other's cooldown) but the
	// same object identity, which is what the hub correlates on.
	if candidateFingerprint(failure[0]) == candidateFingerprint(unavailable[0]) {
		t.Error("the two checks must not share a fingerprint — one would silence the other under the resend cooldown")
	}
	if failure[0].GVK != unavailable[0].GVK || failure[0].Namespace != unavailable[0].Namespace || failure[0].Name != unavailable[0].Name {
		t.Errorf("both findings must name the same object so object-level correlation folds them into one incident: %s/%s/%s vs %s/%s/%s",
			failure[0].GVK, failure[0].Namespace, failure[0].Name, unavailable[0].GVK, unavailable[0].Namespace, unavailable[0].Name)
	}
	// The impact is visible in the cause's own message, so the ReplicaFailure
	// finding is actionable even read alone.
	if !strings.Contains(failure[0].Message, "Available=False") {
		t.Errorf("message %q does not say the workload is below minimum availability", failure[0].Message)
	}
}

// TestCheckReplicaFailureIsRegistered guards the one mistake that would make all
// of the above dead code: a checker that exists, is tested, and is never run.
func TestCheckReplicaFailureIsRegistered(t *testing.T) {
	for _, c := range sweepCheckers {
		if c.name == "replica failure condition" {
			return
		}
	}
	t.Fatal("checkReplicaFailure is not registered in sweepCheckers, so no sweep would ever run it")
}

// --- PROJECT.md P19: per-checker deadlines ---

// TestRunOneSweep_TimeoutIsRecordedAgainstTheNamedChecker is P19's whole
// acceptance in one test: a checker that never answers is cut off at its own
// deadline, is named as having timed out, does NOT appear in the aggregate
// error that decides whether this detector looks dead, and does not stop the
// checkers behind it from running and sending findings.
func TestRunOneSweep_TimeoutIsRecordedAgainstTheNamedChecker(t *testing.T) {
	original := sweepCheckers
	defer func() { sweepCheckers = original }()

	entered := make(chan struct{}, 1)
	findingCh := make(chan tunnel.Finding, 2)
	sweepCheckers = []sweepChecker{
		{"hangs forever", func(ctx context.Context, snap *sweepSnapshot, now time.Time, _ time.Duration) ([]sweepCandidate, error) {
			// Exactly the shape of a half-reachable API server: the call is
			// accepted and then never answered. Before P19 this blocked the
			// pass on the agent's lifetime context, i.e. forever.
			entered <- struct{}{}
			<-ctx.Done()
			return nil, ctx.Err()
		}},
		{"runs behind it", func(ctx context.Context, snap *sweepSnapshot, now time.Time, _ time.Duration) ([]sweepCandidate, error) {
			return []sweepCandidate{{GVK: "v1/Pod", Namespace: "default", Name: "behind", Reason: "TestReason",
				Severity: "medium", SustainedFrom: now, OccurredAt: now}}, nil
		}},
	}

	const timeout = 50 * time.Millisecond
	timedOut, err := runOneSweep(context.Background(), k8sfake.NewSimpleClientset(), nil, findingCh,
		map[string]time.Time{}, map[string]time.Time{}, defaultFindingResendCooldown, defaultSweepSustainedThreshold, timeout, nil)

	select {
	case <-entered:
	default:
		t.Fatal("the hanging checker never ran")
	}
	if err != nil {
		t.Fatalf("a timed-out checker must not be folded into the aggregate error, got %v", err)
	}
	if len(timedOut) != 1 || timedOut[0] != "hangs forever" {
		t.Fatalf("timedOut = %v, want exactly [hangs forever]", timedOut)
	}

	select {
	case f := <-findingCh:
		if f.Reason != "TestReason" {
			t.Errorf("Reason = %q, want %q", f.Reason, "TestReason")
		}
	default:
		t.Fatal("the checker behind the hanging one should still have run and sent its candidate")
	}

	// And the detector-health surface names it, distinguishably from a
	// failure, on BOTH surfaces: the dedicated TimedOutChecks field a hub
	// that understands it reads, and the stable Error prefix a hub that
	// predates that field has always had (PROJECT.md P19 and its residual).
	var state detectorRunState
	state.recordCheckerTimeout(timedOut, timeout, time.Now())
	got := state.snapshot()
	if len(got.TimedOutChecks) != 1 || got.TimedOutChecks[0] != "hangs forever" {
		t.Errorf("TimedOutChecks = %v, want exactly [hangs forever] — the named-field answer is what makes this distinguishable without parsing Error", got.TimedOutChecks)
	}
	if !strings.HasPrefix(got.Error, sweepCheckerTimeoutPrefix) {
		t.Errorf("Error = %q, want it to start with %q so a consumer can tell a timeout from a failure", got.Error, sweepCheckerTimeoutPrefix)
	}
	if !strings.Contains(got.Error, "hangs forever") {
		t.Errorf("Error = %q, want it to name the checker that timed out", got.Error)
	}
	if got.ErrorAt.IsZero() {
		t.Error("ErrorAt must be set so an operator can see when the timeout happened")
	}
	// recordCheckerTimeout alone never advances LastSuccessAt: it records
	// only what did not answer. Whether the pass counts as a success is the
	// sweep loop's own decision, made once it knows whether any checker
	// actually FAILED — see TestSweepPassWithATimeoutStillAdvancesLastSuccess.
	if !got.LastSuccessAt.IsZero() {
		t.Error("recordCheckerTimeout must not advance LastSuccessAt by itself — that is runSweepDetector's call to make")
	}
}

// TestSweepPassWithATimeoutStillAdvancesLastSuccess is PROJECT.md P19's
// residual, stated as a test: the wire must distinguish "one check timed
// out" from "the sweep failed", and LastSuccessAt must mean something
// defensible in both.
//
// Before TimedOutChecks existed there was one field for both facts, so the
// only safe reading of LastSuccessAt was the strict one ("every checker
// succeeded") — and a single slow List on a large cluster froze it for as
// long as that List stayed slow, making a detector that was running fine
// and reporting findings the whole time look, hub-side, like one that had
// not run since. This asserts the three outcomes of a pass are now three
// distinct wire states.
func TestSweepPassWithATimeoutStillAdvancesLastSuccess(t *testing.T) {
	now := time.Now()

	t.Run("clean pass: success advances, nothing named", func(t *testing.T) {
		var state detectorRunState
		recordSweepPassOutcome(&state, nil, nil, 30*time.Second, now)
		got := state.snapshot()
		if got.LastSuccessAt.IsZero() {
			t.Error("a clean pass must advance LastSuccessAt")
		}
		if len(got.TimedOutChecks) != 0 {
			t.Errorf("TimedOutChecks = %v, want empty on a clean pass", got.TimedOutChecks)
		}
		if got.Error != "" {
			t.Errorf("Error = %q, want empty on a clean pass", got.Error)
		}
	})

	t.Run("timed-out pass: success advances AND the check is named", func(t *testing.T) {
		var state detectorRunState
		recordSweepPassOutcome(&state, []string{"service no endpoints"}, nil, 30*time.Second, now)
		got := state.snapshot()
		if !got.LastSuccessAt.Equal(now) {
			t.Errorf("LastSuccessAt = %v, want %v — the pass ran and no checker failed, which is exactly what this field now means", got.LastSuccessAt, now)
		}
		if len(got.TimedOutChecks) != 1 || got.TimedOutChecks[0] != "service no endpoints" {
			t.Errorf("TimedOutChecks = %v, want [service no endpoints] — otherwise an advancing LastSuccessAt would be claiming a completeness the pass did not have", got.TimedOutChecks)
		}
		if !strings.HasPrefix(got.Error, sweepCheckerTimeoutPrefix) {
			t.Errorf("Error = %q, want the stable timeout prefix kept for a hub that predates TimedOutChecks", got.Error)
		}
	})

	t.Run("failed pass: success does NOT advance", func(t *testing.T) {
		var state detectorRunState
		recordSweepPassOutcome(&state, nil, errors.New("pods is forbidden"), 30*time.Second, now)
		got := state.snapshot()
		if !got.LastSuccessAt.IsZero() {
			t.Error("a pass with a FAILING checker must not advance LastSuccessAt — a denied read is a standing fault, not an incomplete answer")
		}
		if got.Error != "pods is forbidden" {
			t.Errorf("Error = %q, want the hard failure to win the Error field", got.Error)
		}
		if len(got.TimedOutChecks) != 0 {
			t.Errorf("TimedOutChecks = %v, want empty — nothing timed out in this pass", got.TimedOutChecks)
		}
	})

	t.Run("a clean pass clears what the previous pass named", func(t *testing.T) {
		var state detectorRunState
		recordSweepPassOutcome(&state, []string{"pvc pending"}, nil, 30*time.Second, now)
		recordSweepPassOutcome(&state, nil, nil, 30*time.Second, now.Add(time.Minute))
		got := state.snapshot()
		if len(got.TimedOutChecks) != 0 {
			t.Errorf("TimedOutChecks = %v, want empty — this field answers \"is a check hanging right now\", not \"did one ever hang\"", got.TimedOutChecks)
		}
		if got.Error == "" {
			t.Error("Error must NOT be cleared by a later pass — that is the opposite contract, and an operator needs \"this happened at T\" to stay visible")
		}
	})
}

// TestRunOneSweep_ShutdownIsNotReportedAsATimeout guards the one case that must
// NOT be reported as a checker timeout: the agent's own context being
// cancelled on shutdown cancels every checker too, and recording that as
// "this check is too slow" would put a permanent, false capacity claim on
// the last thing the agent ever reported.
func TestRunOneSweep_ShutdownIsNotReportedAsATimeout(t *testing.T) {
	original := sweepCheckers
	defer func() { sweepCheckers = original }()

	sweepCheckers = []sweepChecker{
		{"blocks until shutdown", func(ctx context.Context, snap *sweepSnapshot, now time.Time, _ time.Duration) ([]sweepCandidate, error) {
			<-ctx.Done()
			return nil, ctx.Err()
		}},
	}

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(20 * time.Millisecond)
		cancel()
	}()
	timedOut, err := runOneSweep(ctx, k8sfake.NewSimpleClientset(), nil, make(chan tunnel.Finding, 1),
		map[string]time.Time{}, map[string]time.Time{}, defaultFindingResendCooldown, defaultSweepSustainedThreshold, time.Minute, nil)
	if len(timedOut) != 0 {
		t.Fatalf("a shutdown cancellation must not be reported as a checker timeout, got %v", timedOut)
	}
	if err == nil {
		t.Fatal("the cancelled checker's error should still reach the aggregate error")
	}
}

func TestSweepCheckerTimeout_ClampsToTheInterval(t *testing.T) {
	cases := []struct {
		interval time.Duration
		want     time.Duration
	}{
		{DefaultSweepInterval, 30 * time.Second}, // 5m/10, at the upper clamp
		{time.Hour, maxSweepCheckerTimeout},      // a long interval must not hand out a long deadline
		{30 * time.Second, minSweepCheckerTimeout},
		{time.Second, minSweepCheckerTimeout}, // never below what a real list needs
		{100 * time.Second, 10 * time.Second}, // in between: a tenth of the interval
	}
	for _, c := range cases {
		if got := sweepCheckerTimeout(c.interval); got != c.want {
			t.Errorf("sweepCheckerTimeout(%s) = %s, want %s", c.interval, got, c.want)
		}
	}
}
