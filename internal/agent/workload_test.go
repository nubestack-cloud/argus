package agent

import (
	"context"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sfake "k8s.io/client-go/kubernetes/fake"
)

func TestResolveWorkloadFromOwnerRefs_NoOwner(t *testing.T) {
	gvk, name, ok := resolveWorkloadFromOwnerRefs(context.Background(), k8sfake.NewSimpleClientset(), "default", nil)
	if ok {
		t.Errorf("a bare pod with no owner references resolved to (%q, %q), want ok=false", gvk, name)
	}
}

// TestResolveWorkloadFromOwnerRefs_DirectOwner covers StatefulSet/DaemonSet/
// Job-owned pods, whose own OwnerReferences already name the real workload
// directly — no extra API call needed, and none should happen (the fake
// clientset has nothing seeded, so a call would 404 and this would fall
// through to the "resolved" branch incorrectly if the direct-owner shortcut
// were broken).
func TestResolveWorkloadFromOwnerRefs_DirectOwner(t *testing.T) {
	refs := []metav1.OwnerReference{
		{APIVersion: "apps/v1", Kind: "StatefulSet", Name: "cache", Controller: boolPtr(true)},
	}
	gvk, name, ok := resolveWorkloadFromOwnerRefs(context.Background(), k8sfake.NewSimpleClientset(), "default", refs)
	if !ok {
		t.Fatal("expected ok=true for a directly-owned pod")
	}
	if gvk != "apps/v1/StatefulSet" || name != "cache" {
		t.Errorf("resolved to (%q, %q), want (%q, %q)", gvk, name, "apps/v1/StatefulSet", "cache")
	}
}

// TestResolveWorkloadFromOwnerRefs_ThroughReplicaSet is the common
// Deployment-managed case: the pod's own owner reference names the
// ReplicaSet, and resolving further requires one GET of that ReplicaSet to
// read ITS owner reference (the Deployment).
func TestResolveWorkloadFromOwnerRefs_ThroughReplicaSet(t *testing.T) {
	rs := &appsv1.ReplicaSet{
		ObjectMeta: metav1.ObjectMeta{
			Name: "payments-7d9c8f6b5", Namespace: "default",
			OwnerReferences: []metav1.OwnerReference{
				{APIVersion: "apps/v1", Kind: "Deployment", Name: "payments", Controller: boolPtr(true)},
			},
		},
	}
	clientset := k8sfake.NewSimpleClientset(rs)
	refs := []metav1.OwnerReference{
		{APIVersion: "apps/v1", Kind: "ReplicaSet", Name: "payments-7d9c8f6b5", Controller: boolPtr(true)},
	}
	gvk, name, ok := resolveWorkloadFromOwnerRefs(context.Background(), clientset, "default", refs)
	if !ok {
		t.Fatal("expected ok=true")
	}
	if gvk != "apps/v1/Deployment" || name != "payments" {
		t.Errorf("resolved to (%q, %q), want (%q, %q) — should have walked past the ReplicaSet to its Deployment", gvk, name, "apps/v1/Deployment", "payments")
	}
}

// TestResolveWorkloadFromOwnerRefs_BareReplicaSet covers a ReplicaSet with
// no owner of its own (not Deployment-managed) — the ReplicaSet itself is
// the workload identity, a coarser but still valid correlation key.
func TestResolveWorkloadFromOwnerRefs_BareReplicaSet(t *testing.T) {
	rs := &appsv1.ReplicaSet{
		ObjectMeta: metav1.ObjectMeta{Name: "manual-rs", Namespace: "default"},
	}
	clientset := k8sfake.NewSimpleClientset(rs)
	refs := []metav1.OwnerReference{
		{APIVersion: "apps/v1", Kind: "ReplicaSet", Name: "manual-rs", Controller: boolPtr(true)},
	}
	gvk, name, ok := resolveWorkloadFromOwnerRefs(context.Background(), clientset, "default", refs)
	if !ok {
		t.Fatal("expected ok=true")
	}
	if gvk != "apps/v1/ReplicaSet" || name != "manual-rs" {
		t.Errorf("resolved to (%q, %q), want (%q, %q)", gvk, name, "apps/v1/ReplicaSet", "manual-rs")
	}
}

// TestResolveWorkloadFromOwnerRefs_DeletedReplicaSet covers the ReplicaSet
// GET failing (already deleted) — falls back to the ReplicaSet's own
// identity rather than dropping workload correlation for this Finding
// entirely.
func TestResolveWorkloadFromOwnerRefs_DeletedReplicaSet(t *testing.T) {
	clientset := k8sfake.NewSimpleClientset() // nothing seeded — the Get 404s
	refs := []metav1.OwnerReference{
		{APIVersion: "apps/v1", Kind: "ReplicaSet", Name: "gone-rs", Controller: boolPtr(true)},
	}
	gvk, name, ok := resolveWorkloadFromOwnerRefs(context.Background(), clientset, "default", refs)
	if !ok {
		t.Fatal("expected ok=true (fall back to the ReplicaSet itself)")
	}
	if gvk != "apps/v1/ReplicaSet" || name != "gone-rs" {
		t.Errorf("resolved to (%q, %q), want (%q, %q)", gvk, name, "apps/v1/ReplicaSet", "gone-rs")
	}
}

func TestResolveWorkloadForInvolvedObject_NonPodKindSkipped(t *testing.T) {
	ev := &corev1.Event{
		InvolvedObject: corev1.ObjectReference{Kind: "PersistentVolumeClaim", Name: "data", Namespace: "default"},
	}
	_, _, priority, ok := resolveWorkloadForInvolvedObject(context.Background(), k8sfake.NewSimpleClientset(), ev)
	if ok {
		t.Error("a non-Pod involved object must never resolve a workload — only Pods have replica siblings to correlate against")
	}
	if priority != nil {
		t.Errorf("priority = %v, want nil for a non-Pod involved object", *priority)
	}
}

func TestResolveWorkloadForInvolvedObject_ResolvesThroughPod(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: "payments-7d9c8f6b5-x8k2q", Namespace: "default",
			OwnerReferences: []metav1.OwnerReference{
				{APIVersion: "apps/v1", Kind: "ReplicaSet", Name: "payments-7d9c8f6b5", Controller: boolPtr(true)},
			},
		},
		Spec: corev1.PodSpec{Priority: int32Ptr(1000)},
	}
	rs := &appsv1.ReplicaSet{
		ObjectMeta: metav1.ObjectMeta{
			Name: "payments-7d9c8f6b5", Namespace: "default",
			OwnerReferences: []metav1.OwnerReference{
				{APIVersion: "apps/v1", Kind: "Deployment", Name: "payments", Controller: boolPtr(true)},
			},
		},
	}
	clientset := k8sfake.NewSimpleClientset(pod, rs)
	ev := &corev1.Event{
		InvolvedObject: corev1.ObjectReference{Kind: "Pod", Name: "payments-7d9c8f6b5-x8k2q", Namespace: "default"},
	}
	gvk, name, priority, ok := resolveWorkloadForInvolvedObject(context.Background(), clientset, ev)
	if !ok {
		t.Fatal("expected ok=true")
	}
	if gvk != "apps/v1/Deployment" || name != "payments" {
		t.Errorf("resolved to (%q, %q), want (%q, %q)", gvk, name, "apps/v1/Deployment", "payments")
	}
	if priority == nil || *priority != 1000 {
		t.Errorf("priority = %v, want 1000 (the Pod's own resolved spec.priority)", priority)
	}
}

func TestResolveWorkloadForInvolvedObject_PodGoneIsNotAnError(t *testing.T) {
	ev := &corev1.Event{
		InvolvedObject: corev1.ObjectReference{Kind: "Pod", Name: "already-deleted", Namespace: "default"},
	}
	_, _, priority, ok := resolveWorkloadForInvolvedObject(context.Background(), k8sfake.NewSimpleClientset(), ev)
	if ok {
		t.Error("a Pod that no longer exists must resolve ok=false, not panic or error the caller out of sending the Finding")
	}
	if priority != nil {
		t.Errorf("priority = %v, want nil — the Get failed, so nothing was ever read", *priority)
	}
}

func boolPtr(b bool) *bool { return &b }

// Observed live (loop campaign 2026-10-13): a ReplicaSet's FailedCreate opened
// an incident beside its Deployment's, and each CronJob run opened another.
func TestResolveWorkloadForInvolvedObject_ReplicaSetAndJob(t *testing.T) {
	rs := &appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{Name: "web-5d9", Namespace: "default",
		OwnerReferences: []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "Deployment", Name: "web", Controller: boolPtr(true)}}}}
	runJob := &batchv1.Job{ObjectMeta: metav1.ObjectMeta{Name: "report-29865420", Namespace: "default",
		OwnerReferences: []metav1.OwnerReference{{APIVersion: "batch/v1", Kind: "CronJob", Name: "report", Controller: boolPtr(true)}}}}
	bareJob := &batchv1.Job{ObjectMeta: metav1.ObjectMeta{Name: "migrate", Namespace: "default"}}
	cs := k8sfake.NewSimpleClientset(rs, runJob, bareJob)
	for _, tc := range []struct {
		kind, name, wantGVK, wantName string
		wantOK                        bool
	}{
		{"ReplicaSet", "web-5d9", "apps/v1/Deployment", "web", true},
		{"Job", "report-29865420", "batch/v1/CronJob", "report", true},
		{"Job", "migrate", "", "", false},
	} {
		ev := &corev1.Event{InvolvedObject: corev1.ObjectReference{Kind: tc.kind, Name: tc.name, Namespace: "default"}}
		gvk, name, _, ok := resolveWorkloadForInvolvedObject(context.Background(), cs, ev)
		if ok != tc.wantOK || gvk != tc.wantGVK || name != tc.wantName {
			t.Errorf("%s/%s resolved to (%q, %q, %v), want (%q, %q, %v)", tc.kind, tc.name, gvk, name, ok, tc.wantGVK, tc.wantName, tc.wantOK)
		}
	}
}
