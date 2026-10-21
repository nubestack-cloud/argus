package agent

import (
	"context"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sfake "k8s.io/client-go/kubernetes/fake"
)

// appsReplicaSet builds a bare ReplicaSet named rsName, controlled by a
// Deployment named deploymentName — the shape
// resolveWorkloadFromOwnerRefs' "through a ReplicaSet" hop needs to find
// when it GETs the ReplicaSet a Pod's own OwnerReferences named.
func appsReplicaSet(rsName, deploymentName string) appsv1.ReplicaSet {
	return appsv1.ReplicaSet{
		ObjectMeta: metav1.ObjectMeta{
			Name: rsName, Namespace: "apps",
			OwnerReferences: []metav1.OwnerReference{
				{APIVersion: "apps/v1", Kind: "Deployment", Name: deploymentName, Controller: boolPtr(true)},
			},
		},
	}
}

// TestResolveRelatedWorkloadForPVC_NoMountingPod covers CAPABILITIES.md §5's
// exact measured case: a PVC stuck Pending (WaitForFirstConsumer) with no
// Pod ever created that references it. There is genuinely nothing to
// correlate against, and this must degrade to ok=false rather than error.
func TestResolveRelatedWorkloadForPVC_NoMountingPod(t *testing.T) {
	clientset := k8sfake.NewSimpleClientset()
	gvk, name, ok := resolveRelatedWorkloadForPVC(context.Background(), clientset, "apps", "spack-cache")
	if ok {
		t.Errorf("resolveRelatedWorkloadForPVC with no mounting pod = (%q, %q, true), want ok=false", gvk, name)
	}
}

// TestResolveRelatedWorkloadForPVC_MountingPodOwnedByDeployment is the other
// half of the same measured case: a Pod that DOES exist, is owned (via a
// ReplicaSet) by a Deployment, and mounts the PVC by name.
func TestResolveRelatedWorkloadForPVC_MountingPodOwnedByDeployment(t *testing.T) {
	clientset := k8sfake.NewSimpleClientset(
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name: "softpack-frontend-abc123", Namespace: "apps",
				OwnerReferences: []metav1.OwnerReference{
					{APIVersion: "apps/v1", Kind: "ReplicaSet", Name: "softpack-frontend-abc", Controller: boolPtr(true)},
				},
			},
			Spec: corev1.PodSpec{
				Volumes: []corev1.Volume{
					{Name: "cache", VolumeSource: corev1.VolumeSource{
						PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: "spack-cache"},
					}},
				},
			},
		},
	)
	// resolveWorkloadFromOwnerRefs walks past the ReplicaSet to its own
	// owning Deployment when one exists — seed it so the "through a
	// ReplicaSet" hop (already tested in workload_test.go) resolves cleanly
	// here too.
	rs := appsReplicaSet("softpack-frontend-abc", "softpack-frontend")
	if _, err := clientset.AppsV1().ReplicaSets("apps").Create(context.Background(), &rs, metav1.CreateOptions{}); err != nil {
		t.Fatalf("seed replicaset: %v", err)
	}

	gvk, name, ok := resolveRelatedWorkloadForPVC(context.Background(), clientset, "apps", "spack-cache")
	if !ok {
		t.Fatal("expected ok=true for a PVC mounted by a Pod owned by a Deployment")
	}
	if gvk != "apps/v1/Deployment" || name != "softpack-frontend" {
		t.Errorf("resolved to (%q, %q), want (%q, %q)", gvk, name, "apps/v1/Deployment", "softpack-frontend")
	}
}

// TestResolveRelatedWorkloadForPVC_IgnoresOtherNamespacesAndClaims checks the
// match is scoped to the exact namespace+claimName, not every Pod/volume.
func TestResolveRelatedWorkloadForPVC_IgnoresOtherNamespacesAndClaims(t *testing.T) {
	clientset := k8sfake.NewSimpleClientset(
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "other-claim-pod", Namespace: "apps"},
			Spec: corev1.PodSpec{Volumes: []corev1.Volume{
				{Name: "v", VolumeSource: corev1.VolumeSource{
					PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: "unrelated-claim"},
				}},
			}},
		},
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "wrong-namespace-pod", Namespace: "other-ns"},
			Spec: corev1.PodSpec{Volumes: []corev1.Volume{
				{Name: "v", VolumeSource: corev1.VolumeSource{
					PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: "spack-cache"},
				}},
			}},
		},
	)
	if _, _, ok := resolveRelatedWorkloadForPVC(context.Background(), clientset, "apps", "spack-cache"); ok {
		t.Error("expected ok=false: no pod in namespace 'apps' actually mounts claim 'spack-cache'")
	}
}

// TestResolveRelatedWorkloadForSelector_MatchesBySelectorNotEndpoints covers
// the selector-based half: a Service's selector matching a Pod that is
// itself unready (or has no ready endpoint yet) still resolves — this
// function does its own label match, it does not depend on EndpointSlices
// having already recorded the Pod.
func TestResolveRelatedWorkloadForSelector_MatchesBySelectorNotEndpoints(t *testing.T) {
	clientset := k8sfake.NewSimpleClientset(
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name: "web-1", Namespace: "apps", Labels: map[string]string{"app": "web"},
				OwnerReferences: []metav1.OwnerReference{
					{APIVersion: "apps/v1", Kind: "StatefulSet", Name: "web", Controller: boolPtr(true)},
				},
			},
		},
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "unrelated", Namespace: "apps", Labels: map[string]string{"app": "other"}},
		},
	)
	gvk, name, ok := resolveRelatedWorkloadForSelector(context.Background(), clientset, "apps", map[string]string{"app": "web"})
	if !ok {
		t.Fatal("expected ok=true for a selector matching one Pod owned by a StatefulSet")
	}
	if gvk != "apps/v1/StatefulSet" || name != "web" {
		t.Errorf("resolved to (%q, %q), want (%q, %q)", gvk, name, "apps/v1/StatefulSet", "web")
	}
}

// TestResolveRelatedWorkloadForSelector_EmptySelectorIsNoOp guards the case
// checkServiceNoEndpoints already filters out before calling this (a
// selector-less Service) — this function must not treat "no selector" as
// "match everything".
func TestResolveRelatedWorkloadForSelector_EmptySelectorIsNoOp(t *testing.T) {
	clientset := k8sfake.NewSimpleClientset(
		&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "any-pod", Namespace: "apps", Labels: map[string]string{"app": "whatever"}}},
	)
	if _, _, ok := resolveRelatedWorkloadForSelector(context.Background(), clientset, "apps", nil); ok {
		t.Error("expected ok=false for an empty selector — must not match every Pod in the namespace")
	}
}

// TestResolveRelatedWorkloadForSelector_NoMatch is the genuine
// misconfiguration case (a selector matching zero Pods at all) — there is
// no Pod to correlate against, so this must degrade to ok=false rather than
// error.
func TestResolveRelatedWorkloadForSelector_NoMatch(t *testing.T) {
	clientset := k8sfake.NewSimpleClientset()
	if _, _, ok := resolveRelatedWorkloadForSelector(context.Background(), clientset, "apps", map[string]string{"app": "nonexistent"}); ok {
		t.Error("expected ok=false: selector matches no Pods")
	}
}

func TestRelatedWorkloadDescription(t *testing.T) {
	if got := relatedWorkloadDescription("", ""); got != "" {
		t.Errorf("relatedWorkloadDescription(\"\", \"\") = %q, want \"\"", got)
	}
	got := relatedWorkloadDescription("apps/v1/Deployment", "softpack-frontend")
	want := " (likely related to apps/v1/Deployment softpack-frontend)"
	if got != want {
		t.Errorf("relatedWorkloadDescription(...) = %q, want %q", got, want)
	}
}
