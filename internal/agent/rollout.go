package agent

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/client-go/kubernetes"

	"argus/internal/tunnel"
)

// startupProbeReasons are the Warning reasons that, during a rollout, are the
// rollout working rather than a fault: new pods refusing readiness while they
// start. Only probe failures: a crash or an image that will not pull is a
// fault whether or not a rollout is in progress.
var startupProbeReasons = map[string]bool{"Unhealthy": true}

// rolloutPodMaxAge bounds "a pod starting up". A pod older than this failing
// its probe is not starting, whatever its workload is doing.
const rolloutPodMaxAge = 10 * time.Minute

// duringRollout reports whether a probe-failure event belongs to a rollout
// still in progress: the pod is young and its owning workload has not finished
// rolling out. Such a finding is kept but not promoted (Impact none): a
// normal rollout opened 15 incidents in one minute on rke2 (2026-10-13,
// PROJECT.md IN2). A rollout that never completes is not hidden: a
// Deployment past its progress deadline is no longer "in progress" (and the
// rollout-stalled rules report it), and a StatefulSet or DaemonSet stuck
// mid-update is reported by its own rollout-stalled rule.
//
// Any read failure answers false, so the finding promotes as before.
func duringRollout(ctx context.Context, clientset kubernetes.Interface, ev *corev1.Event, workloadGVK, workloadName string, now time.Time) bool {
	if !startupProbeReasons[ev.Reason] || ev.InvolvedObject.Kind != "Pod" || workloadName == "" {
		return false
	}
	pod, err := clientset.CoreV1().Pods(ev.InvolvedObject.Namespace).Get(ctx, ev.InvolvedObject.Name, metav1.GetOptions{})
	if err != nil || pod.Status.StartTime == nil || now.Sub(pod.Status.StartTime.Time) > rolloutPodMaxAge {
		return false
	}
	ns := ev.InvolvedObject.Namespace
	switch {
	case strings.HasSuffix(workloadGVK, "/Deployment"):
		d, err := clientset.AppsV1().Deployments(ns).Get(ctx, workloadName, metav1.GetOptions{})
		return err == nil && deploymentRollingOut(d)
	case strings.HasSuffix(workloadGVK, "/StatefulSet"):
		s, err := clientset.AppsV1().StatefulSets(ns).Get(ctx, workloadName, metav1.GetOptions{})
		return err == nil && s.Status.UpdateRevision != "" && s.Status.CurrentRevision != s.Status.UpdateRevision
	case strings.HasSuffix(workloadGVK, "/DaemonSet"):
		ds, err := clientset.AppsV1().DaemonSets(ns).Get(ctx, workloadName, metav1.GetOptions{})
		return err == nil && ds.Status.UpdatedNumberScheduled < ds.Status.DesiredNumberScheduled
	}
	return false
}

// deploymentRollingOut: the Deployment controller says a rollout is under way
// and within its progress deadline. Progressing=True with reason
// NewReplicaSetAvailable means the rollout finished; Progressing=False
// (ProgressDeadlineExceeded) means it failed. Either is "not in progress".
func deploymentRollingOut(d *appsv1.Deployment) bool {
	if d.Generation > d.Status.ObservedGeneration {
		return true // the controller has not even seen the new spec yet
	}
	for _, c := range d.Status.Conditions {
		if c.Type == appsv1.DeploymentProgressing {
			return c.Status == corev1.ConditionTrue && c.Reason != "NewReplicaSetAvailable"
		}
	}
	return false
}

// podDependencies lists what a Pod that has not started is waiting on: the
// PVCs, ConfigMaps and Secrets its spec names. Only while the Pod is Pending.
// A running pod's fault is its own, and listing its references would let an
// unrelated incident on a ConfigMap absorb it (PROJECT.md IN3). The hub joins
// a finding carrying these to an open incident on any of them, and the
// reverse, so a PVC that cannot bind and the pod waiting on it are one
// incident.
func podDependencies(pod *corev1.Pod) []tunnel.ObjectReference {
	if pod == nil || pod.Status.Phase != corev1.PodPending {
		return nil
	}
	seen := map[tunnel.ObjectReference]bool{}
	var out []tunnel.ObjectReference
	add := func(kind, name string) {
		if name == "" {
			return
		}
		r := tunnel.ObjectReference{Kind: kind, Namespace: pod.Namespace, Name: name}
		if !seen[r] {
			seen[r] = true
			out = append(out, r)
		}
	}
	for _, v := range pod.Spec.Volumes {
		switch {
		case v.PersistentVolumeClaim != nil:
			add("PersistentVolumeClaim", v.PersistentVolumeClaim.ClaimName)
		case v.ConfigMap != nil:
			add("ConfigMap", v.ConfigMap.Name)
		case v.Secret != nil:
			add("Secret", v.Secret.SecretName)
		case v.Projected != nil:
			for _, s := range v.Projected.Sources {
				if s.ConfigMap != nil {
					add("ConfigMap", s.ConfigMap.Name)
				}
				if s.Secret != nil {
					add("Secret", s.Secret.Name)
				}
			}
		}
	}
	for _, s := range pod.Spec.ImagePullSecrets {
		add("Secret", s.Name)
	}
	containers := append(append([]corev1.Container{}, pod.Spec.InitContainers...), pod.Spec.Containers...)
	for _, c := range containers {
		for _, e := range c.EnvFrom {
			if e.ConfigMapRef != nil {
				add("ConfigMap", e.ConfigMapRef.Name)
			}
			if e.SecretRef != nil {
				add("Secret", e.SecretRef.Name)
			}
		}
		for _, e := range c.Env {
			if e.ValueFrom == nil {
				continue
			}
			if e.ValueFrom.ConfigMapKeyRef != nil {
				add("ConfigMap", e.ValueFrom.ConfigMapKeyRef.Name)
			}
			if e.ValueFrom.SecretKeyRef != nil {
				add("Secret", e.ValueFrom.SecretKeyRef.Name)
			}
		}
	}
	return out
}

// unreadyNode names the pod's node when that node is not Ready, so every pod
// a node outage touches joins one incident (PROJECT.md IN1): Kubernetes emits
// NodeNotReady on each pod, and each pod's workload used to get an incident of
// its own (28 on lab-dev in one blip, 2026-10-13). Any read failure, or a
// Ready node, adds nothing.
func unreadyNode(ctx context.Context, clientset kubernetes.Interface, pod *corev1.Pod) (tunnel.ObjectReference, bool) {
	if pod.Spec.NodeName == "" {
		return tunnel.ObjectReference{}, false
	}
	node, err := clientset.CoreV1().Nodes().Get(ctx, pod.Spec.NodeName, metav1.GetOptions{})
	if err != nil {
		return tunnel.ObjectReference{}, false
	}
	for _, c := range node.Status.Conditions {
		if c.Type == corev1.NodeReady && c.Status == corev1.ConditionTrue {
			return tunnel.ObjectReference{}, false
		}
	}
	return tunnel.ObjectReference{Kind: "Node", Name: node.Name}, true
}

// producedReferences names what an object creates and keeps, read from its
// spec: a cert-manager Certificate's Secret (spec.secretName), an
// external-secrets ExternalSecret's target Secret (spec.target.name, or the
// object's own name when unset). Marked as produced, so the hub joins a pod
// waiting on that Secret to the producer's incident (PROJECT.md IN5). The
// Secret itself is never read.
func producedReferences(obj *unstructured.Unstructured) []tunnel.ObjectReference {
	if obj == nil {
		return nil
	}
	gv := obj.GroupVersionKind()
	var name string
	switch {
	case gv.Group == "cert-manager.io" && gv.Kind == "Certificate":
		name, _, _ = unstructured.NestedString(obj.Object, "spec", "secretName")
	case gv.Group == "external-secrets.io" && gv.Kind == "ExternalSecret":
		name, _, _ = unstructured.NestedString(obj.Object, "spec", "target", "name")
		if name == "" {
			name = obj.GetName()
		}
	}
	if name == "" {
		return nil
	}
	return []tunnel.ObjectReference{{Kind: "Secret", Namespace: obj.GetNamespace(), Name: name, Role: tunnel.ReferenceRoleProduces}}
}

// hpaMetricsAPIService names the aggregated metrics API an autoscaler's
// metrics failure depends on, when that API is not Available — the fan-in
// cause behind every autoscaler's FailedGetResourceMetric (PROJECT.md IN5).
// Named only when it is down, like unreadyNode, so the hub can treat it as
// the shared fault. Any read failure names nothing.
func hpaMetricsAPIService(ctx context.Context, clientset kubernetes.Interface, reason string) (tunnel.ObjectReference, bool) {
	var api string
	switch reason {
	case "FailedGetResourceMetric", "FailedComputeMetricsReplicas":
		api = "v1beta1.metrics.k8s.io"
	case "FailedGetPodsMetric", "FailedGetObjectMetric":
		api = "v1beta1.custom.metrics.k8s.io"
	case "FailedGetExternalMetric":
		api = "v1beta1.external.metrics.k8s.io"
	default:
		return tunnel.ObjectReference{}, false
	}
	raw, err := clientset.Discovery().RESTClient().Get().AbsPath("/apis/apiregistration.k8s.io/v1/apiservices/" + api).DoRaw(ctx)
	if err != nil {
		return tunnel.ObjectReference{}, false
	}
	var svc struct {
		Status struct {
			Conditions []struct{ Type, Status string } `json:"conditions"`
		} `json:"status"`
	}
	if json.Unmarshal(raw, &svc) != nil {
		return tunnel.ObjectReference{}, false
	}
	for _, c := range svc.Status.Conditions {
		if c.Type == "Available" && c.Status == "True" {
			return tunnel.ObjectReference{}, false
		}
	}
	return tunnel.ObjectReference{Kind: "APIService", Name: api}, true
}
