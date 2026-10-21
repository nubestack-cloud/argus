package objsearch

import (
	"fmt"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
)

// ObjectFromTyped builds the searchable Object for a typed cache object.
// kind and group come from the caller because informer objects carry no
// TypeMeta. ok is false when obj has no ObjectMeta.
func ObjectFromTyped(obj runtime.Object, kind, group string) (Object, bool) {
	m, err := meta.Accessor(obj)
	if err != nil {
		return Object{}, false
	}
	o := Object{
		Kind:      kind,
		APIGroup:  group,
		Namespace: m.GetNamespace(),
		Name:      m.GetName(),
		Labels:    m.GetLabels(),
		Images:    imagesForTyped(obj),
		Status:    typedStatus(obj),
	}
	if m.GetDeletionTimestamp() != nil {
		o.Status = "Terminating"
	}
	return o, true
}

// ObjectFromUnstructured builds the searchable Object for a dynamic cache
// object.
func ObjectFromUnstructured(u *unstructured.Unstructured, kind, group string) Object {
	if u == nil {
		return Object{Kind: kind, APIGroup: group}
	}
	o := Object{
		Kind:      kind,
		APIGroup:  group,
		Namespace: u.GetNamespace(),
		Name:      u.GetName(),
		Labels:    u.GetLabels(),
		Images:    imagesFromUnstructured(u),
		Status:    unstructuredStatus(u),
	}
	if u.GetDeletionTimestamp() != nil {
		o.Status = "Terminating"
	}
	return o
}

func imagesForTyped(obj runtime.Object) []string {
	var spec *corev1.PodSpec
	switch o := obj.(type) {
	case *corev1.Pod:
		spec = &o.Spec
	case *appsv1.Deployment:
		spec = &o.Spec.Template.Spec
	case *appsv1.StatefulSet:
		spec = &o.Spec.Template.Spec
	case *appsv1.DaemonSet:
		spec = &o.Spec.Template.Spec
	case *appsv1.ReplicaSet:
		spec = &o.Spec.Template.Spec
	case *batchv1.Job:
		spec = &o.Spec.Template.Spec
	case *batchv1.CronJob:
		spec = &o.Spec.JobTemplate.Spec.Template.Spec
	default:
		return nil
	}
	// Regular, init and ephemeral containers alike: an image is searchable
	// wherever in the pod it runs.
	var out []string
	keep := func(img string) {
		if img != "" {
			out = append(out, img)
		}
	}
	for _, c := range spec.Containers {
		keep(c.Image)
	}
	for _, c := range spec.InitContainers {
		keep(c.Image)
	}
	for _, c := range spec.EphemeralContainers {
		keep(c.Image)
	}
	return out
}

// imagesFromUnstructured reads container images from a custom resource
// shaped like a workload: a pod template at spec.template.spec, or failing
// that a pod spec directly at spec. Any other shape has none.
func imagesFromUnstructured(u *unstructured.Unstructured) []string {
	for _, path := range [][]string{{"spec", "template", "spec"}, {"spec"}} {
		// No copy: search scans the whole cache on every query.
		v, _, _ := unstructured.NestedFieldNoCopy(u.Object, path...)
		spec, ok := v.(map[string]any)
		if !ok {
			continue
		}
		var out []string
		for _, field := range []string{"containers", "initContainers"} {
			list, _ := spec[field].([]any)
			for _, item := range list {
				if c, ok := item.(map[string]any); ok {
					if img, _ := c["image"].(string); img != "" {
						out = append(out, img)
					}
				}
			}
		}
		if len(out) > 0 {
			return out
		}
	}
	return nil
}

// typedStatus is a short, kubectl-like health word for the hit row. ""
// means the kind has no status worth showing — not that it is healthy.
func typedStatus(obj runtime.Object) string {
	switch o := obj.(type) {
	case *corev1.Pod:
		return podStatus(o)
	case *appsv1.Deployment:
		return fmt.Sprintf("%d/%d ready", o.Status.ReadyReplicas, desired(o.Spec.Replicas))
	case *appsv1.StatefulSet:
		return fmt.Sprintf("%d/%d ready", o.Status.ReadyReplicas, desired(o.Spec.Replicas))
	case *appsv1.ReplicaSet:
		return fmt.Sprintf("%d/%d ready", o.Status.ReadyReplicas, desired(o.Spec.Replicas))
	case *appsv1.DaemonSet:
		return fmt.Sprintf("%d/%d ready", o.Status.NumberReady, o.Status.DesiredNumberScheduled)
	case *batchv1.Job:
		return jobStatus(o)
	case *batchv1.CronJob:
		if o.Spec.Suspend != nil && *o.Spec.Suspend {
			return "Suspended"
		}
		return fmt.Sprintf("%d active", len(o.Status.Active))
	case *corev1.Node:
		return nodeStatus(o)
	case *corev1.PersistentVolumeClaim:
		return string(o.Status.Phase)
	case *corev1.PersistentVolume:
		return string(o.Status.Phase)
	case *corev1.Namespace:
		return string(o.Status.Phase)
	case *corev1.Service:
		return string(o.Spec.Type)
	}
	return ""
}

func desired(replicas *int32) int32 {
	if replicas == nil {
		return 1
	}
	return *replicas
}

// podStatus prefers a container's waiting/terminated reason (CrashLoopBackOff,
// ImagePullBackOff, OOMKilled) over the phase, as kubectl does.
func podStatus(p *corev1.Pod) string {
	for _, statuses := range [][]corev1.ContainerStatus{p.Status.InitContainerStatuses, p.Status.ContainerStatuses} {
		for _, cs := range statuses {
			if w := cs.State.Waiting; w != nil && w.Reason != "" && w.Reason != "ContainerCreating" && w.Reason != "PodInitializing" {
				return w.Reason
			}
			if t := cs.State.Terminated; t != nil && t.Reason != "" && t.Reason != "Completed" {
				return t.Reason
			}
		}
	}
	if p.Status.Reason != "" {
		return p.Status.Reason
	}
	return string(p.Status.Phase)
}

func jobStatus(j *batchv1.Job) string {
	for _, c := range j.Status.Conditions {
		if c.Status != corev1.ConditionTrue {
			continue
		}
		switch c.Type {
		case batchv1.JobComplete:
			return "Complete"
		case batchv1.JobFailed:
			return "Failed"
		case batchv1.JobSuspended:
			return "Suspended"
		}
	}
	if j.Status.Active > 0 {
		return "Running"
	}
	return "Pending"
}

func nodeStatus(n *corev1.Node) string {
	status := "Unknown"
	for _, c := range n.Status.Conditions {
		if c.Type == corev1.NodeReady {
			if c.Status == corev1.ConditionTrue {
				status = "Ready"
			} else {
				status = "NotReady"
			}
		}
	}
	if n.Spec.Unschedulable {
		status += ",SchedulingDisabled"
	}
	return status
}

// unstructuredStatus covers the common custom-resource shapes: Argo-style
// health/sync, a Ready condition, then status.phase.
func unstructuredStatus(u *unstructured.Unstructured) string {
	if health, _, _ := unstructured.NestedString(u.Object, "status", "health", "status"); health != "" {
		if sync, _, _ := unstructured.NestedString(u.Object, "status", "sync", "status"); sync != "" {
			return health + "/" + sync
		}
		return health
	}
	conditions, _, _ := unstructured.NestedSlice(u.Object, "status", "conditions")
	for _, c := range conditions {
		cm, ok := c.(map[string]any)
		if !ok || cm["type"] != "Ready" {
			continue
		}
		switch cm["status"] {
		case "True":
			return "Ready"
		case "False":
			if reason, _ := cm["reason"].(string); reason != "" {
				return "NotReady: " + reason
			}
			return "NotReady"
		default:
			return "Unknown"
		}
	}
	phase, _, _ := unstructured.NestedString(u.Object, "status", "phase")
	return phase
}
