package posture

import (
	"slices"
	"strings"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

func ptr[T any](v T) *T { return &v }

func meta(ns, name string) metav1.ObjectMeta { return metav1.ObjectMeta{Namespace: ns, Name: name} }

// sized is a container's requests and limits with every value set.
func sized() corev1.ResourceRequirements {
	l := corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("200m"), corev1.ResourceMemory: resource.MustParse("256Mi")}
	return corev1.ResourceRequirements{Requests: l, Limits: l.DeepCopy()}
}

// tidy is a container no pod-template check objects to.
func tidy(name string) corev1.Container {
	probe := &corev1.Probe{ProbeHandler: corev1.ProbeHandler{HTTPGet: &corev1.HTTPGetAction{Path: "/healthz"}}}
	return corev1.Container{
		Name: name, Image: "registry.example.org/billing/" + name + ":4.2.0",
		ReadinessProbe: probe, LivenessProbe: probe,
		Resources: sized(),
		SecurityContext: &corev1.SecurityContext{
			RunAsNonRoot: ptr(true), AllowPrivilegeEscalation: ptr(false), ReadOnlyRootFilesystem: ptr(true),
		},
	}
}

// tidySpec is a pod spec no pod-template check objects to.
func tidySpec(containers ...string) corev1.PodSpec {
	spec := corev1.PodSpec{AutomountServiceAccountToken: ptr(false)}
	for _, c := range containers {
		spec.Containers = append(spec.Containers, tidy(c))
	}
	return spec
}

func deployment(ns, name string, replicas int32, spec corev1.PodSpec) *appsv1.Deployment {
	labels := map[string]string{"app": name}
	return &appsv1.Deployment{
		ObjectMeta: meta(ns, name),
		Spec: appsv1.DeploymentSpec{
			Replicas: ptr(replicas),
			Selector: &metav1.LabelSelector{MatchLabels: labels},
			Template: corev1.PodTemplateSpec{ObjectMeta: metav1.ObjectMeta{Labels: labels}, Spec: spec},
		},
	}
}

func statefulSet(ns, name string, replicas int32, spec corev1.PodSpec) *appsv1.StatefulSet {
	labels := map[string]string{"app": name}
	return &appsv1.StatefulSet{
		ObjectMeta: meta(ns, name),
		Spec: appsv1.StatefulSetSpec{
			Replicas: ptr(replicas),
			Selector: &metav1.LabelSelector{MatchLabels: labels},
			Template: corev1.PodTemplateSpec{ObjectMeta: metav1.ObjectMeta{Labels: labels}, Spec: spec},
		},
	}
}

func pod(ns, name string, labels map[string]string, spec corev1.PodSpec) *corev1.Pod {
	p := &corev1.Pod{ObjectMeta: meta(ns, name), Spec: spec}
	p.Labels = labels
	p.Status.Phase = corev1.PodRunning
	return p
}

// listedEverything is an input with every inventory listed and empty, so
// nothing is reported missing and every check family runs.
func listedEverything() *CheckInput {
	return &CheckInput{
		Pods: []*corev1.Pod{}, Deployments: []*appsv1.Deployment{}, ReplicaSets: []*appsv1.ReplicaSet{},
		StatefulSets: []*appsv1.StatefulSet{}, DaemonSets: []*appsv1.DaemonSet{},
		ServiceAccounts: []*corev1.ServiceAccount{}, LimitRanges: []*corev1.LimitRange{},
	}
}

// failing lists "check@Kind/namespace/name" for every counted finding,
// sorted.
func failing(r *ScanResults) []string {
	var out []string
	for _, f := range r.Findings {
		if !f.Excepted {
			out = append(out, f.CheckID+"@"+f.Kind+"/"+f.Namespace+"/"+f.Name)
		}
	}
	slices.Sort(out)
	return out
}

// checksFailing lists the distinct check IDs that failed, sorted.
func checksFailing(r *ScanResults) []string {
	var out []string
	for _, f := range r.Findings {
		if !slices.Contains(out, f.CheckID) {
			out = append(out, f.CheckID)
		}
	}
	slices.Sort(out)
	return out
}

func findingFor(r *ScanResults, checkID, name string) *Finding {
	for i, f := range r.Findings {
		if f.CheckID == checkID && f.Name == name {
			return &r.Findings[i]
		}
	}
	return nil
}

// findingNames is the set of object names check failed on.
func findingNames(findings []Finding, checkID string) map[string]bool {
	out := map[string]bool{}
	for _, f := range findings {
		if f.CheckID == checkID {
			out[f.Name] = true
		}
	}
	return out
}

func contains(s, sub string) bool { return strings.Contains(s, sub) }

// owned marks child as controlled by an apps/v1 parent.
func owned(child *metav1.ObjectMeta, kind, name string, uid types.UID) {
	child.OwnerReferences = append(child.OwnerReferences, metav1.OwnerReference{
		APIVersion: "apps/v1", Kind: kind, Name: name, UID: uid, Controller: ptr(true),
	})
}

func deletedAgo(m *metav1.ObjectMeta, d time.Duration, finalizers ...string) {
	at := metav1.NewTime(time.Now().Add(-d))
	m.DeletionTimestamp = &at
	m.Finalizers = finalizers
}
