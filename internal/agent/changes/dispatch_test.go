package changes

import (
	"slices"
	"strings"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	autoscalingv2 "k8s.io/api/autoscaling/v2"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
)

// has reports a diff with a change at path.
func has(d *DiffInfo, path string) bool {
	if d == nil {
		return false
	}
	_, ok := changeAt(d.Fields, path)
	return ok
}

// object is an unstructured object of apiVersion/kind named demo in ns ml,
// with the given top-level fields.
func object(apiVersion, kind string, fields map[string]any) *unstructured.Unstructured {
	u := &unstructured.Unstructured{Object: map[string]any{}}
	for k, v := range fields {
		u.Object[k] = v
	}
	u.SetAPIVersion(apiVersion)
	u.SetKind(kind)
	u.SetNamespace("ml")
	u.SetName("demo")
	u.SetResourceVersion("1")
	return u
}

func toUnstructured(t *testing.T, obj runtime.Object, apiVersion, kind string) *unstructured.Unstructured {
	t.Helper()
	m, err := runtime.DefaultUnstructuredConverter.ToUnstructured(obj)
	if err != nil {
		t.Fatal(err)
	}
	u := &unstructured.Unstructured{Object: m}
	u.SetAPIVersion(apiVersion)
	u.SetKind(kind)
	return u
}

// A kind name is not an identity: the core Job keeps its differ whether it
// arrives typed or unstructured, while a CRD reusing the name gets the
// generic one, and two groups are never diffed as one object.
func TestComputeDiffDispatchesByGroup(t *testing.T) {
	was := &batchv1.Job{Status: batchv1.JobStatus{Active: 1}}
	is := was.DeepCopy()
	is.Status.Active = 3
	uWas, uIs := toUnstructured(t, was, "batch/v1", "Job"), toUnstructured(t, is, "batch/v1", "Job")
	for name, d := range map[string]*DiffInfo{
		"typed":        ComputeDiff("Job", was, is),
		"unstructured": ComputeDiff("Job", uWas, uIs),
		"entry point":  ComputeDiffFromUnstructured("Job", uWas, uIs),
	} {
		if !has(d, "status.active") {
			t.Errorf("core Job %s: %+v", name, d)
		}
	}

	for _, c := range []struct {
		apiVersion, kind string
		was, is          map[string]any
	}{
		{"batch.volcano.sh/v1alpha1", "Job", map[string]any{"status": map[string]any{"state": map[string]any{"phase": "Pending"}}},
			map[string]any{"status": map[string]any{"state": map[string]any{"phase": "Running"}}}},
		{"networking.istio.io/v1", "Gateway", map[string]any{"spec": map[string]any{"servers": []any{}}},
			map[string]any{"spec": map[string]any{"servers": []any{map[string]any{"hosts": []any{"*"}}}}}},
	} {
		a, b := object(c.apiVersion, c.kind, c.was), object(c.apiVersion, c.kind, c.is)
		if d := ComputeDiff(c.kind, a, b); !has(d, "resource") {
			t.Errorf("%s %s used a curated differ: %+v", c.apiVersion, c.kind, d)
		}
	}

	// The audited group of a CRD kind keeps its curated differ.
	a := object("argoproj.io/v1alpha1", "Application", map[string]any{"status": map[string]any{"health": map[string]any{"status": "Healthy"}}})
	b := object("argoproj.io/v1alpha1", "Application", map[string]any{"status": map[string]any{"health": map[string]any{"status": "Degraded"}}})
	if d := ComputeDiff("Application", a, b); !has(d, "status.health.status") {
		t.Errorf("Argo Application: %+v", d)
	}
	other := object("apps.example.org/v1", "Application", map[string]any{"status": map[string]any{"ready": true}})
	if d := ComputeDiff("Application", other, b); d != nil {
		t.Errorf("two groups diffed as one object: %+v", d)
	}
}

// The generic differ reports spec generation moves and condition flips,
// otherwise only that something moved — never a value from the body — and
// nothing at all for reconcile bookkeeping.
func TestGenericDiffer(t *testing.T) {
	widget := func(status map[string]any) *unstructured.Unstructured {
		u := object("example.io/v1", "Widget", map[string]any{"status": status})
		u.SetGeneration(4)
		return u
	}
	ready := func(status, reason, at string) map[string]any {
		return map[string]any{"type": "Ready", "status": status, "reason": reason, "lastTransitionTime": at}
	}

	same := widget(map[string]any{"observedGeneration": int64(4), "conditions": []any{ready("True", "Up", "2026-09-01T08:00:00Z")}})
	touched := widget(map[string]any{"observedGeneration": int64(4), "conditions": []any{ready("True", "Up", "2026-09-01T08:05:00Z")}})
	touched.SetResourceVersion("2")
	if d := ComputeDiff("Widget", same, touched); d != nil {
		t.Errorf("bookkeeping only: %+v", d)
	}

	flipped := widget(map[string]any{"conditions": []any{ready("False", "Degraded", "2026-09-01T08:05:00Z")}})
	if d := ComputeDiff("Widget", same, flipped); d == nil || !slices.Equal(pathsOf(d.Fields), []string{"status.conditions[Ready]"}) {
		t.Errorf("condition flip: %+v", d)
	}

	moved := widget(map[string]any{"address": "10.42.0.1"})
	moved2 := widget(map[string]any{"address": "10.42.0.2"})
	d := ComputeDiff("Widget", moved, moved2)
	if !has(d, "resource") || strings.Contains(d.Summary+d.Fields[0].NewValue.(string), "10.42.0.2") {
		t.Errorf("arbitrary status: %+v", d)
	}
}

// Distinct status/reason pairs never encode alike, whatever characters they
// hold, and the encoding never carries a raw NUL (jsonb cannot store one).
func TestConditionSignalEncoding(t *testing.T) {
	cond := func(status, reason string) *unstructured.Unstructured {
		return object("example.io/v1", "Widget", map[string]any{"status": map[string]any{
			"conditions": []any{map[string]any{"type": "Ready", "status": status, "reason": reason}},
		}})
	}
	for _, p := range [][4]string{
		{"x\x00y", "z", "x", "y\x00z"},
		{"x:y", "z", "x", "y:z"},
		{`x":"y`, "z", "x", `y":"z`},
		{"True", "\x00", "True", `\x00`},
		{"False", "Init", "True", "Init"},
		{"True", "Init", "True", "Done"},
	} {
		a, b := cond(p[0], p[1]), cond(p[2], p[3])
		for _, u := range []*unstructured.Unstructured{a, b} {
			if strings.ContainsRune(genericConditionSignalMap(u.Object, "status", "conditions")["Ready"], 0) {
				t.Errorf("%q: raw NUL in signal", p)
			}
		}
		d := ComputeDiffFromUnstructured("Widget", a, b)
		if d == nil || len(d.Fields) != 1 || d.Fields[0].OldValue == d.Fields[0].NewValue {
			t.Errorf("%q: %+v", p, d)
		}
	}
	if d := ComputeDiffFromUnstructured("Widget", cond("True", "Up"), cond("True", "Up")); d != nil {
		t.Errorf("unchanged: %+v", d)
	}
}

func TestNoiseOnlyUpdatesAreDropped(t *testing.T) {
	t0 := metav1.NewTime(time.Date(2026, 9, 1, 8, 0, 0, 0, time.UTC))
	t1 := metav1.NewTime(t0.Add(30 * time.Second))

	pod := &corev1.Pod{Status: corev1.PodStatus{Phase: corev1.PodRunning, Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue, LastProbeTime: t0}}}}
	probed := pod.DeepCopy()
	probed.Status.Conditions[0].LastProbeTime = t1

	node := &corev1.Node{Status: corev1.NodeStatus{Conditions: []corev1.NodeCondition{
		{Type: corev1.NodeReady, Status: corev1.ConditionTrue, LastHeartbeatTime: t0}, {Type: corev1.NodeDiskPressure, Status: corev1.ConditionFalse, LastHeartbeatTime: t0},
	}}}
	beat := node.DeepCopy()
	for i := range beat.Status.Conditions {
		beat.Status.Conditions[i].LastHeartbeatTime = t1
	}

	svc := &corev1.Service{Spec: corev1.ServiceSpec{ClusterIP: "10.43.9.9", Ports: []corev1.ServicePort{{Port: 6379}}}}
	managed := svc.DeepCopy()
	managed.ManagedFields = []metav1.ManagedFieldsEntry{{Manager: "kubectl", Operation: metav1.ManagedFieldsOperationApply}}
	managed.ResourceVersion = "9"

	for kind, pair := range map[string][2]any{"Pod": {pod, probed}, "Node": {node, beat}, "Service": {svc, managed}} {
		if d := ComputeDiff(kind, pair[0], pair[1]); d != nil {
			t.Errorf("%s: %+v", kind, d)
		}
	}
}

// A pod is followed only for phase, node and restarts going up.
func TestPodTracksPhaseNodeAndRestarts(t *testing.T) {
	was := &corev1.Pod{Status: corev1.PodStatus{Phase: corev1.PodPending, ContainerStatuses: []corev1.ContainerStatus{{Name: "app", RestartCount: 4}}}}
	ignored := was.DeepCopy()
	ignored.Status.PodIP = "10.42.7.7"
	ignored.Status.ContainerStatuses[0].State.Waiting = &corev1.ContainerStateWaiting{Reason: "CrashLoopBackOff"}
	fewer := was.DeepCopy()
	fewer.Status.ContainerStatuses[0].RestartCount = 1
	for _, is := range []*corev1.Pod{ignored, fewer} {
		if d := ComputeDiff("Pod", was, is); d != nil {
			t.Errorf("untracked change reported: %+v", d)
		}
	}
	moved := was.DeepCopy()
	moved.Status.Phase, moved.Spec.NodeName = corev1.PodRunning, "worker-4"
	moved.Status.ContainerStatuses[0].RestartCount = 5
	d := ComputeDiff("Pod", was, moved)
	if d == nil || !slices.Equal(pathsOf(d.Fields), []string{"status.phase", "status.containerStatuses[*].restartCount", "spec.nodeName"}) {
		t.Errorf("pod = %+v", d)
	}
}

// Each kind's signals that its counts alone would hide.
func TestKindSignals(t *testing.T) {
	node := &corev1.Node{Status: corev1.NodeStatus{
		Conditions:  []corev1.NodeCondition{{Type: corev1.NodeReady, Status: corev1.ConditionTrue}, {Type: corev1.NodePIDPressure, Status: corev1.ConditionFalse}},
		NodeInfo:    corev1.NodeSystemInfo{KubeletVersion: "v1.31.2"},
		Allocatable: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("8"), corev1.ResourcePods: resource.MustParse("110")},
	}}
	node2 := node.DeepCopy()
	node2.Spec.Unschedulable = true
	node2.Status.Conditions[1].Status = corev1.ConditionTrue
	node2.Status.NodeInfo.KubeletVersion = "v1.31.4"
	node2.Status.Allocatable[corev1.ResourcePods] = resource.MustParse("58")

	hpa := &autoscalingv2.HorizontalPodAutoscaler{Status: autoscalingv2.HorizontalPodAutoscalerStatus{
		Conditions: []autoscalingv2.HorizontalPodAutoscalerCondition{{Type: autoscalingv2.AbleToScale, Status: corev1.ConditionTrue}}}}
	hpa2 := hpa.DeepCopy()
	hpa2.Status.Conditions[0].Status = corev1.ConditionFalse

	dep := &appsv1.Deployment{Status: appsv1.DeploymentStatus{Conditions: []appsv1.DeploymentCondition{{Type: appsv1.DeploymentProgressing, Status: corev1.ConditionTrue}}}}
	dep2 := dep.DeepCopy()
	dep2.Status.Conditions[0].Status = corev1.ConditionFalse

	rs := &appsv1.ReplicaSet{}
	rs2 := &appsv1.ReplicaSet{Status: appsv1.ReplicaSetStatus{Conditions: []appsv1.ReplicaSetCondition{{Type: appsv1.ReplicaSetReplicaFailure, Status: corev1.ConditionTrue}}}}

	pvc := &corev1.PersistentVolumeClaim{Status: corev1.PersistentVolumeClaimStatus{Phase: corev1.ClaimPending}}
	pvc2 := &corev1.PersistentVolumeClaim{Spec: corev1.PersistentVolumeClaimSpec{VolumeName: "pvc-77"}, Status: corev1.PersistentVolumeClaimStatus{Phase: corev1.ClaimBound}}

	ds := &appsv1.DaemonSet{Spec: appsv1.DaemonSetSpec{Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{Containers: []corev1.Container{{
		Name: "node-exporter", LivenessProbe: &corev1.Probe{PeriodSeconds: 30}}}}}}}
	ds2 := ds.DeepCopy()
	ds2.Status.NumberMisscheduled = 2
	ds2.Spec.Template.Spec.Containers[0].LivenessProbe.PeriodSeconds = 10

	stalled := func(s string) *unstructured.Unstructured {
		return &unstructured.Unstructured{Object: map[string]any{"status": map[string]any{"conditions": []any{map[string]any{"type": "Stalled", "status": s}}}}}
	}
	images := func(img ...any) *unstructured.Unstructured {
		return &unstructured.Unstructured{Object: map[string]any{"status": map[string]any{
			"sync": map[string]any{"status": "Synced"}, "health": map[string]any{"status": "Healthy"}, "summary": map[string]any{"images": img},
		}}}
	}
	class := func(accepted string) *unstructured.Unstructured {
		return &unstructured.Unstructured{Object: map[string]any{"spec": map[string]any{"controllerName": "example.org/gw"},
			"status": map[string]any{"conditions": []any{map[string]any{"type": "Accepted", "status": accepted}}}}}
	}
	grant := func(to ...any) *unstructured.Unstructured {
		return &unstructured.Unstructured{Object: map[string]any{"spec": map[string]any{"from": []any{}, "to": to}}}
	}
	svcRef := map[string]any{"group": "", "kind": "Service"}

	for _, c := range []struct {
		kind    string
		was, is any
		paths   []string
	}{
		{"Node", node, node2, []string{"spec.unschedulable", "status.conditions[PIDPressure]", "status.nodeInfo.kubeletVersion", "status.allocatable.pods"}},
		{"HorizontalPodAutoscaler", hpa, hpa2, []string{"status.conditions[AbleToScale]"}},
		{"Deployment", dep, dep2, []string{"status.conditions[Progressing]"}},
		{"ReplicaSet", rs, rs2, []string{"status.conditions[ReplicaFailure]"}},
		{"PersistentVolumeClaim", pvc, pvc2, []string{"status.phase", "spec.volumeName"}},
		{"DaemonSet", ds, ds2, []string{"spec.template.spec.containers[node-exporter].livenessProbe", "status.numberMisscheduled"}},
		{"Kustomization", stalled("False"), stalled("True"), []string{"status.conditions[Stalled]"}},
		// Synced and Healthy throughout, but new images went out.
		{"Application", images("web:1.1"), images("web:1.2"), []string{"status.summary.images"}},
		{"GatewayClass", class("True"), class("False"), []string{"status.conditions.Accepted"}},
		{"ReferenceGrant", grant(svcRef), grant(svcRef, svcRef), []string{"spec.to"}},
	} {
		if d := ComputeDiff(c.kind, c.was, c.is); d == nil || !slices.Equal(pathsOf(d.Fields), c.paths) {
			t.Errorf("%s: %+v, want %v", c.kind, d, c.paths)
		}
	}
}

// A route's conditions are followed per parent, and a parent is a Gateway
// listener: one route can attach through several of them.
func TestRouteConditionsPerParent(t *testing.T) {
	parent := func(gw, listener, programmed string) any {
		return map[string]any{
			"parentRef":  map[string]any{"group": "gateway.networking.k8s.io", "kind": "Gateway", "namespace": "edge", "name": gw, "sectionName": listener},
			"conditions": []any{map[string]any{"type": "Accepted", "status": "True"}, map[string]any{"type": "Programmed", "status": programmed}},
		}
	}
	route := func(parents ...any) *unstructured.Unstructured {
		return &unstructured.Unstructured{Object: map[string]any{"status": map[string]any{"parents": parents}}}
	}
	d := ComputeDiff("HTTPRoute", route(parent("public", "http", "True"), parent("public", "https", "False")),
		route(parent("public", "http", "True"), parent("public", "https", "True")))
	if d == nil || !slices.Equal(pathsOf(d.Fields), []string{"status.parents[gateway.networking.k8s.io/Gateway/edge/public/https/0].conditions[Programmed]"}) {
		t.Errorf("listener flip = %+v", d)
	}
	// One parent replaced by another of the same count still shows.
	if d := ComputeDiff("HTTPRoute", route(parent("public", "", "True")), route(parent("internal", "", "True"))); d == nil {
		t.Error("a swapped parent was missed")
	}
}

// Argo CD writes a top-level `operation` that bumps generation on every
// reconcile; with spec unchanged that is not a change worth recording.
func TestGenerationBumpWithoutSpecChangeIsNotAChange(t *testing.T) {
	app := func(gen int64, rev, project string) *unstructured.Unstructured {
		u := object("argoproj.io/v1alpha1", "Application", map[string]any{
			"spec":      map[string]any{"project": project},
			"operation": map[string]any{"sync": map[string]any{"revision": rev}},
		})
		u.SetGeneration(gen)
		return u
	}
	if ev, ok := BuildEvent("Application", "argoproj.io", OpUpdate, app(10, "a1", "default"), app(11, "b2", "default"), time.Now()); ok {
		t.Fatalf("operation-only generation bump recorded: %+v", ev)
	}
	if _, ok := BuildEvent("Application", "argoproj.io", OpUpdate, app(11, "b2", "default"), app(12, "b2", "payments"), time.Now()); !ok {
		t.Fatal("a real spec change was dropped")
	}
}
