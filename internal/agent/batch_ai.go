package agent

import (
	"context"
	"fmt"
	"strings"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
)

// Health for batch and AI workloads (PROJECT.md PG20). The generic condition
// reader already notices a CRD reporting Ready=False; these readings say WHICH
// part failed and why, in each controller's own terms: a JobSet's failed
// replicated job, a Ray job or service that failed, a KServe inference
// service whose predictor is not ready, a KEDA scaler that cannot read its
// metric, a Kueue workload evicted for not becoming ready. Each kind is
// optional: a cluster without the CRD, or without the read grant, is skipped.

type batchAISource struct {
	gvr   schema.GroupVersionResource
	gvk   string
	judge func(obj *unstructured.Unstructured) (reason, message string, ok bool)
}

// conditionOf returns the condition of type t, if present.
func conditionOf(obj *unstructured.Unstructured, t string) (status, reason, message string, found bool) {
	conds, _, _ := unstructured.NestedSlice(obj.Object, "status", "conditions")
	for _, c := range conds {
		m, ok := c.(map[string]any)
		if !ok || m["type"] != t {
			continue
		}
		status, _ = m["status"].(string)
		reason, _ = m["reason"].(string)
		message, _ = m["message"].(string)
		return status, reason, message, true
	}
	return "", "", "", false
}

func clip(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > 300 {
		return s[:300] + "…"
	}
	return s
}

var batchAISources = []batchAISource{
	{
		gvr: schema.GroupVersionResource{Group: "jobset.x-k8s.io", Version: "v1alpha2", Resource: "jobsets"}, gvk: "jobset.x-k8s.io/v1alpha2/JobSet",
		judge: func(o *unstructured.Unstructured) (string, string, bool) {
			if st, reason, msg, ok := conditionOf(o, "Failed"); ok && st == "True" {
				return "JobSetFailed", fmt.Sprintf("JobSet %s/%s failed (%s): %s", o.GetNamespace(), o.GetName(), reason, clip(msg)), true
			}
			return "", "", false
		},
	},
	{
		gvr: schema.GroupVersionResource{Group: "ray.io", Version: "v1", Resource: "rayjobs"}, gvk: "ray.io/v1/RayJob",
		judge: func(o *unstructured.Unstructured) (string, string, bool) {
			js, _, _ := unstructured.NestedString(o.Object, "status", "jobStatus")
			ds, _, _ := unstructured.NestedString(o.Object, "status", "jobDeploymentStatus")
			if js == "FAILED" || ds == "Failed" {
				msg, _, _ := unstructured.NestedString(o.Object, "status", "message")
				return "RayJobFailed", fmt.Sprintf("RayJob %s/%s failed (job %s, deployment %s): %s", o.GetNamespace(), o.GetName(), js, ds, clip(msg)), true
			}
			return "", "", false
		},
	},
	{
		gvr: schema.GroupVersionResource{Group: "ray.io", Version: "v1", Resource: "rayservices"}, gvk: "ray.io/v1/RayService",
		judge: func(o *unstructured.Unstructured) (string, string, bool) {
			if st, reason, msg, ok := conditionOf(o, "Ready"); ok && st == "False" {
				return "RayServiceNotReady", fmt.Sprintf("RayService %s/%s is not ready (%s): %s", o.GetNamespace(), o.GetName(), reason, clip(msg)), true
			}
			return "", "", false
		},
	},
	{
		gvr: schema.GroupVersionResource{Group: "ray.io", Version: "v1", Resource: "rayclusters"}, gvk: "ray.io/v1/RayCluster",
		judge: func(o *unstructured.Unstructured) (string, string, bool) {
			if st, _, _ := unstructured.NestedString(o.Object, "status", "state"); st == "failed" {
				reason, _, _ := unstructured.NestedString(o.Object, "status", "reason")
				return "RayClusterFailed", fmt.Sprintf("RayCluster %s/%s is in state failed: %s", o.GetNamespace(), o.GetName(), clip(reason)), true
			}
			return "", "", false
		},
	},
	{
		gvr: schema.GroupVersionResource{Group: "serving.kserve.io", Version: "v1beta1", Resource: "inferenceservices"}, gvk: "serving.kserve.io/v1beta1/InferenceService",
		judge: func(o *unstructured.Unstructured) (string, string, bool) {
			st, reason, msg, ok := conditionOf(o, "Ready")
			if !ok || st != "False" {
				return "", "", false
			}
			// Name the component that is holding it back when KServe says so.
			for _, part := range []string{"PredictorReady", "TransformerReady", "ExplainerReady", "IngressReady"} {
				if ps, pr, pm, found := conditionOf(o, part); found && ps == "False" {
					return "InferenceServiceNotReady", fmt.Sprintf("InferenceService %s/%s is not ready: %s is False (%s): %s", o.GetNamespace(), o.GetName(), part, pr, clip(pm)), true
				}
			}
			return "InferenceServiceNotReady", fmt.Sprintf("InferenceService %s/%s is not ready (%s): %s", o.GetNamespace(), o.GetName(), reason, clip(msg)), true
		},
	},
	{
		gvr: schema.GroupVersionResource{Group: "keda.sh", Version: "v1alpha1", Resource: "scaledobjects"}, gvk: "keda.sh/v1alpha1/ScaledObject",
		judge: func(o *unstructured.Unstructured) (string, string, bool) {
			if st, reason, msg, ok := conditionOf(o, "Ready"); ok && st == "False" {
				return "ScaledObjectNotReady", fmt.Sprintf("KEDA ScaledObject %s/%s cannot scale (%s): %s", o.GetNamespace(), o.GetName(), reason, clip(msg)), true
			}
			if st, _, msg, ok := conditionOf(o, "Fallback"); ok && st == "True" {
				return "ScaledObjectFallback", fmt.Sprintf("KEDA ScaledObject %s/%s is using its fallback replica count because its scaler is failing: %s", o.GetNamespace(), o.GetName(), clip(msg)), true
			}
			return "", "", false
		},
	},
	{
		gvr: schema.GroupVersionResource{Group: "kueue.x-k8s.io", Version: "v1beta1", Resource: "workloads"}, gvk: "kueue.x-k8s.io/v1beta1/Workload",
		judge: func(o *unstructured.Unstructured) (string, string, bool) {
			// Evicted for not becoming ready (waitForPodsReady) is a fault;
			// eviction for preemption is how Kueue shares capacity and is not.
			if st, reason, msg, ok := conditionOf(o, "Evicted"); ok && st == "True" && reason == "PodsReadyTimeout" {
				return "KueueWorkloadEvicted", fmt.Sprintf("Kueue Workload %s/%s was evicted because its pods did not become ready in time: %s", o.GetNamespace(), o.GetName(), clip(msg)), true
			}
			return "", "", false
		},
	},
}

func checkBatchAIWorkloads(ctx context.Context, dyn dynamic.Interface, now time.Time, _ time.Duration) ([]sweepCandidate, error) {
	var out []sweepCandidate
	for _, src := range batchAISources {
		list, err := dyn.Resource(src.gvr).Namespace(metav1.NamespaceAll).List(ctx, sweepListOptions)
		if err != nil {
			if meta.IsNoMatchError(err) || apierrors.IsNotFound(err) || apierrors.IsForbidden(err) {
				continue
			}
			return out, err
		}
		for i := range list.Items {
			obj := &list.Items[i]
			reason, msg, ok := src.judge(obj)
			if !ok {
				continue
			}
			out = append(out, sweepCandidate{
				GVK: src.gvk, Namespace: obj.GetNamespace(), Name: obj.GetName(), UID: string(obj.GetUID()), ResourceVersion: obj.GetResourceVersion(),
				Reason: reason, Message: msg, Severity: "high", Class: "fault", Confidence: "verified", Impact: "degraded", OccurredAt: now,
			})
		}
	}
	return out, nil
}
