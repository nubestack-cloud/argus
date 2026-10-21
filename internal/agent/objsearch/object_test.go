package objsearch

import (
	"reflect"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
)

func TestObjectFromTyped_IdentityImagesAndNoBody(t *testing.T) {
	three := int32(3)
	d := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "shop", Name: "payments",
			Labels:      map[string]string{"app": "payments"},
			Annotations: map[string]string{"note": "searchable-annotation"},
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: &three,
			Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{
				InitContainers: []corev1.Container{{Name: "init", Image: "migrate:v1"}},
				Containers:     []corev1.Container{{Name: "app", Image: "payments:v2", Env: []corev1.EnvVar{{Name: "TOKEN", Value: "sha256:abc"}}}},
			}},
		},
		Status: appsv1.DeploymentStatus{ReadyReplicas: 2},
	}
	o, ok := ObjectFromTyped(d, "Deployment", "apps")
	if !ok {
		t.Fatal("ObjectFromTyped failed")
	}
	want := Object{
		Kind: "Deployment", APIGroup: "apps", Namespace: "shop", Name: "payments",
		Labels: map[string]string{"app": "payments"},
		Images: []string{"payments:v2", "migrate:v1"},
		Status: "2/3 ready",
	}
	if !reflect.DeepEqual(o, want) {
		t.Fatalf("object = %+v, want %+v", o, want)
	}
	// Annotations and env are not searchable.
	for _, q := range []string{"searchable-annotation", "sha256"} {
		if _, _, ok := match(Parse(q), o); ok {
			t.Fatalf("%q matched object body content", q)
		}
	}
}

func TestTypedStatus(t *testing.T) {
	suspended := true
	cases := []struct {
		name string
		obj  runtime.Object
		kind string
		want string
	}{
		{"crashloop pod", &corev1.Pod{Status: corev1.PodStatus{Phase: corev1.PodRunning, ContainerStatuses: []corev1.ContainerStatus{{State: corev1.ContainerState{Waiting: &corev1.ContainerStateWaiting{Reason: "CrashLoopBackOff"}}}}}}, "Pod", "CrashLoopBackOff"},
		{"oom pod", &corev1.Pod{Status: corev1.PodStatus{Phase: corev1.PodRunning, ContainerStatuses: []corev1.ContainerStatus{{State: corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{Reason: "OOMKilled"}}}}}}, "Pod", "OOMKilled"},
		{"evicted pod", &corev1.Pod{Status: corev1.PodStatus{Phase: corev1.PodFailed, Reason: "Evicted"}}, "Pod", "Evicted"},
		{"running pod", &corev1.Pod{Status: corev1.PodStatus{Phase: corev1.PodRunning}}, "Pod", "Running"},
		{"daemonset", &appsv1.DaemonSet{Status: appsv1.DaemonSetStatus{NumberReady: 2, DesiredNumberScheduled: 3}}, "DaemonSet", "2/3 ready"},
		{"failed job", &batchv1.Job{Status: batchv1.JobStatus{Conditions: []batchv1.JobCondition{{Type: batchv1.JobFailed, Status: corev1.ConditionTrue}}}}, "Job", "Failed"},
		{"running job", &batchv1.Job{Status: batchv1.JobStatus{Active: 1}}, "Job", "Running"},
		{"suspended cronjob", &batchv1.CronJob{Spec: batchv1.CronJobSpec{Suspend: &suspended}}, "CronJob", "Suspended"},
		{"cordoned node", &corev1.Node{Spec: corev1.NodeSpec{Unschedulable: true}, Status: corev1.NodeStatus{Conditions: []corev1.NodeCondition{{Type: corev1.NodeReady, Status: corev1.ConditionTrue}}}}, "Node", "Ready,SchedulingDisabled"},
		{"node without ready", &corev1.Node{}, "Node", "Unknown"},
		{"pvc", &corev1.PersistentVolumeClaim{Status: corev1.PersistentVolumeClaimStatus{Phase: corev1.ClaimPending}}, "PersistentVolumeClaim", "Pending"},
		{"configmap", &corev1.ConfigMap{}, "ConfigMap", ""},
	}
	for _, tc := range cases {
		o, ok := ObjectFromTyped(tc.obj, tc.kind, "")
		if !ok || o.Status != tc.want {
			t.Errorf("%s: status = %q, want %q", tc.name, o.Status, tc.want)
		}
	}

	now := metav1.Now()
	o, _ := ObjectFromTyped(&corev1.Pod{ObjectMeta: metav1.ObjectMeta{DeletionTimestamp: &now}, Status: corev1.PodStatus{Phase: corev1.PodRunning}}, "Pod", "")
	if o.Status != "Terminating" {
		t.Errorf("deleting pod status = %q", o.Status)
	}
}

func TestObjectFromUnstructured(t *testing.T) {
	u := &unstructured.Unstructured{Object: map[string]any{
		"metadata": map[string]any{"name": "web", "namespace": "argocd", "labels": map[string]any{"team": "a"}},
		"spec": map[string]any{"template": map[string]any{"spec": map[string]any{
			"containers": []any{map[string]any{"name": "c", "image": "web:v3"}},
		}}},
		"status": map[string]any{"health": map[string]any{"status": "Degraded"}, "sync": map[string]any{"status": "OutOfSync"}},
	}}
	o := ObjectFromUnstructured(u, "Application", "argoproj.io")
	want := Object{
		Kind: "Application", APIGroup: "argoproj.io", Namespace: "argocd", Name: "web",
		Labels: map[string]string{"team": "a"}, Images: []string{"web:v3"}, Status: "Degraded/OutOfSync",
	}
	if !reflect.DeepEqual(o, want) {
		t.Fatalf("object = %+v, want %+v", o, want)
	}

	for _, tc := range []struct {
		status map[string]any
		want   string
	}{
		{map[string]any{"conditions": []any{map[string]any{"type": "Ready", "status": "False", "reason": "ArtifactFailed"}}}, "NotReady: ArtifactFailed"},
		{map[string]any{"conditions": []any{map[string]any{"type": "Ready", "status": "True"}}}, "Ready"},
		{map[string]any{"phase": "Bound"}, "Bound"},
		{map[string]any{}, ""},
	} {
		u := &unstructured.Unstructured{Object: map[string]any{"metadata": map[string]any{"name": "x"}, "status": tc.status}}
		if got := ObjectFromUnstructured(u, "Thing", "example.com").Status; got != tc.want {
			t.Errorf("status %v = %q, want %q", tc.status, got, tc.want)
		}
	}
}
