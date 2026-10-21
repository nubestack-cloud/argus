package agent

import (
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestDrainBlockers(t *testing.T) {
	yes := true
	owned := func(kind string) []metav1.OwnerReference {
		return []metav1.OwnerReference{{Kind: kind, Name: "x", Controller: &yes}}
	}
	scratch := []corev1.Volume{{Name: "cache", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}}}}
	pods := []corev1.Pod{
		{ObjectMeta: metav1.ObjectMeta{Namespace: "a", Name: "web", OwnerReferences: owned("ReplicaSet")}, Status: corev1.PodStatus{Phase: corev1.PodRunning}},
		{ObjectMeta: metav1.ObjectMeta{Namespace: "a", Name: "ds", OwnerReferences: owned("DaemonSet")}, Status: corev1.PodStatus{Phase: corev1.PodRunning}},
		{ObjectMeta: metav1.ObjectMeta{Namespace: "a", Name: "done"}, Status: corev1.PodStatus{Phase: corev1.PodSucceeded}},
		{ObjectMeta: metav1.ObjectMeta{Namespace: "a", Name: "cache", OwnerReferences: owned("StatefulSet")}, Spec: corev1.PodSpec{Volumes: scratch}, Status: corev1.PodStatus{Phase: corev1.PodRunning}},
	}
	// DaemonSet and finished pods never block; emptyDir data does unless allowed.
	if got := drainBlockers(pods, false); len(got) != 1 || !strings.Contains(got[0], "a/cache has emptyDir data") {
		t.Fatalf("blockers = %v, want only the emptyDir pod", got)
	}
	if got := drainBlockers(pods, true); len(got) != 0 {
		t.Fatalf("with deleteEmptyDirData the drain may start, got %v", got)
	}
	// A pod with no controller would not come back: always refused.
	bare := append(pods, corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "a", Name: "bare"}, Status: corev1.PodStatus{Phase: corev1.PodRunning}})
	if got := drainBlockers(bare, true); len(got) != 1 || !strings.Contains(got[0], "a/bare has no controller") {
		t.Fatalf("blockers = %v, want the bare pod", got)
	}
}
