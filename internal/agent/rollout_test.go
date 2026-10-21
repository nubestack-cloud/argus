package agent

import (
	"context"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	k8sfake "k8s.io/client-go/kubernetes/fake"

	"argus/internal/tunnel"
)

func deployWithProgressing(status corev1.ConditionStatus, reason string) *appsv1.Deployment {
	return &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Name: "web", Namespace: "default", Generation: 2},
		Status: appsv1.DeploymentStatus{ObservedGeneration: 2, Conditions: []appsv1.DeploymentCondition{
			{Type: appsv1.DeploymentProgressing, Status: status, Reason: reason},
		}},
	}
}

func startedPod(age time.Duration, now time.Time) *corev1.Pod {
	t := metav1.NewTime(now.Add(-age))
	return &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "web-1", Namespace: "default"}, Status: corev1.PodStatus{StartTime: &t}}
}

// PROJECT.md IN2: a normal rollout's new pods failing readiness while they
// start opened 15 incidents on rke2 (2026-10-13).
func TestDuringRollout(t *testing.T) {
	now := time.Now()
	unhealthy := &corev1.Event{Reason: "Unhealthy", InvolvedObject: corev1.ObjectReference{Kind: "Pod", Name: "web-1", Namespace: "default"}}
	backoff := &corev1.Event{Reason: "BackOff", InvolvedObject: corev1.ObjectReference{Kind: "Pod", Name: "web-1", Namespace: "default"}}
	sts := &appsv1.StatefulSet{ObjectMeta: metav1.ObjectMeta{Name: "db", Namespace: "default"},
		Status: appsv1.StatefulSetStatus{CurrentRevision: "db-1", UpdateRevision: "db-2"}}
	for _, tc := range []struct {
		name string
		ev   *corev1.Event
		pod  *corev1.Pod
		obj  any
		gvk  string
		wl   string
		want bool
	}{
		{"new pod, Deployment mid-rollout", unhealthy, startedPod(time.Minute, now), deployWithProgressing(corev1.ConditionTrue, "ReplicaSetUpdated"), "apps/v1/Deployment", "web", true},
		{"rollout finished", unhealthy, startedPod(time.Minute, now), deployWithProgressing(corev1.ConditionTrue, "NewReplicaSetAvailable"), "apps/v1/Deployment", "web", false},
		{"rollout past its deadline", unhealthy, startedPod(time.Minute, now), deployWithProgressing(corev1.ConditionFalse, "ProgressDeadlineExceeded"), "apps/v1/Deployment", "web", false},
		{"old pod, whatever the Deployment does", unhealthy, startedPod(time.Hour, now), deployWithProgressing(corev1.ConditionTrue, "ReplicaSetUpdated"), "apps/v1/Deployment", "web", false},
		{"a crash is a fault during a rollout too", backoff, startedPod(time.Minute, now), deployWithProgressing(corev1.ConditionTrue, "ReplicaSetUpdated"), "apps/v1/Deployment", "web", false},
		{"StatefulSet mid-update", unhealthy, startedPod(time.Minute, now), sts, "apps/v1/StatefulSet", "db", true},
		{"no workload", unhealthy, startedPod(time.Minute, now), nil, "", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			objs := []runtime.Object{tc.pod}
			if tc.obj != nil {
				objs = append(objs, tc.obj.(runtime.Object))
			}
			cs := k8sfake.NewSimpleClientset(objs...)
			if got := duringRollout(context.Background(), cs, tc.ev, tc.gvk, tc.wl, now); got != tc.want {
				t.Errorf("duringRollout = %v, want %v", got, tc.want)
			}
		})
	}
}

// PROJECT.md IN3: what a Pending pod is waiting on, and nothing for a running
// one (its faults are its own).
func TestPodDependencies(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "shop", Name: "web-1"},
		Spec: corev1.PodSpec{
			Volumes: []corev1.Volume{
				{Name: "data", VolumeSource: corev1.VolumeSource{PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: "data"}}},
				{Name: "tls", VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{SecretName: "tls"}}},
			},
			Containers: []corev1.Container{{Name: "app",
				EnvFrom: []corev1.EnvFromSource{{ConfigMapRef: &corev1.ConfigMapEnvSource{LocalObjectReference: corev1.LocalObjectReference{Name: "settings"}}}},
				Env:     []corev1.EnvVar{{Name: "K", ValueFrom: &corev1.EnvVarSource{ConfigMapKeyRef: &corev1.ConfigMapKeySelector{LocalObjectReference: corev1.LocalObjectReference{Name: "settings"}, Key: "k"}}}},
			}},
		},
		Status: corev1.PodStatus{Phase: corev1.PodPending},
	}
	got := podDependencies(pod)
	if len(got) != 3 || got[0].Kind != "PersistentVolumeClaim" || got[1].Kind != "Secret" || got[2].Name != "settings" {
		t.Fatalf("dependencies = %+v, want the PVC, the Secret and the ConfigMap once", got)
	}
	pod.Status.Phase = corev1.PodRunning
	if got := podDependencies(pod); got != nil {
		t.Errorf("a running pod listed dependencies: %+v", got)
	}
}

// PROJECT.md IN1: a pod names its node only when the node is not Ready.
func TestUnreadyNode(t *testing.T) {
	ready := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "ok"}, Status: corev1.NodeStatus{Conditions: []corev1.NodeCondition{{Type: corev1.NodeReady, Status: corev1.ConditionTrue}}}}
	down := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "down"}, Status: corev1.NodeStatus{Conditions: []corev1.NodeCondition{{Type: corev1.NodeReady, Status: corev1.ConditionUnknown}}}}
	cs := k8sfake.NewSimpleClientset(ready, down)
	if _, ok := unreadyNode(context.Background(), cs, &corev1.Pod{Spec: corev1.PodSpec{NodeName: "ok"}}); ok {
		t.Error("a Ready node was named")
	}
	if r, ok := unreadyNode(context.Background(), cs, &corev1.Pod{Spec: corev1.PodSpec{NodeName: "down"}}); !ok || r.Kind != "Node" || r.Name != "down" {
		t.Errorf("an unready node was not named: %+v %v", r, ok)
	}
}

// PROJECT.md IN5: a Certificate and an ExternalSecret name the Secret they
// produce; anything else names nothing.
func TestProducedReferences(t *testing.T) {
	obj := func(apiVersion, kind string, spec map[string]any) *unstructured.Unstructured {
		return &unstructured.Unstructured{Object: map[string]any{
			"apiVersion": apiVersion, "kind": kind,
			"metadata": map[string]any{"name": "web", "namespace": "shop"}, "spec": spec,
		}}
	}
	cert := producedReferences(obj("cert-manager.io/v1", "Certificate", map[string]any{"secretName": "web-tls"}))
	if len(cert) != 1 || cert[0].Name != "web-tls" || cert[0].Role != tunnel.ReferenceRoleProduces {
		t.Errorf("Certificate: %+v", cert)
	}
	es := producedReferences(obj("external-secrets.io/v1beta1", "ExternalSecret", map[string]any{}))
	if len(es) != 1 || es[0].Name != "web" {
		t.Errorf("ExternalSecret with no target name should produce a Secret of its own name: %+v", es)
	}
	if got := producedReferences(obj("apps/v1", "Deployment", map[string]any{})); got != nil {
		t.Errorf("a Deployment produced %+v", got)
	}
}
