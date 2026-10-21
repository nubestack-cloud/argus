package agent

// Resolves the workload that owns a Pod, for replica-level correlation
// (BACKLOG.md's A3, migration 000042, internal/replicagroup) — deliberately
// a much narrower, cheaper walk than internal/agent/tools.go's
// ownerChainUpNodes (get_owner_chain): that function walks arbitrarily deep
// across all eight supportedGVKs kinds and returns a full ancestor list for
// an investigation's evidence trail, paid for once per analysis. This runs
// on the detection hot path, for every Finding a Pod produces, so it does
// exactly one thing — "what's the top real controller" — with at most one
// extra API call, not a general-purpose graph walk.

import (
	"context"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes"
)

// resolveWorkloadFromOwnerRefs returns the GVK and name of the workload a
// Pod (or any object) with these OwnerReferences belongs to, walking at
// most one hop past an intermediate ReplicaSet to reach the Deployment it
// belongs to — the overwhelmingly common case for a Deployment-managed Pod,
// whose own OwnerReferences name the ReplicaSet, not the Deployment.
// StatefulSet/DaemonSet/Job-owned pods need no extra call: their
// OwnerReferences already name the real workload directly.
//
// Returns ok=false when refs is empty (a bare Pod with no controller —
// there is no "workload" to correlate by; object-level correlation already
// handles it correctly on its own).
//
// A Pod has at most one controller reference in practice (Kubernetes
// enforces at most one OwnerReference with Controller=true per object), but
// this takes refs[0] unconditionally rather than filtering for
// Controller==true — a Pod with a single owner reference that happens not
// to have the Controller flag set is still, for this purpose, "the thing
// that owns this pod," and refusing to resolve it over a flag this code
// doesn't otherwise depend on would silently lose correlation for no real
// benefit.
func resolveWorkloadFromOwnerRefs(ctx context.Context, clientset kubernetes.Interface, namespace string, refs []metav1.OwnerReference) (gvk, name string, ok bool) {
	if len(refs) == 0 {
		return "", "", false
	}
	ref := refs[0]
	if ref.Kind != "ReplicaSet" {
		return formatGVK(schema.FromAPIVersionAndKind(ref.APIVersion, ref.Kind)), ref.Name, true
	}

	rs, err := clientset.AppsV1().ReplicaSets(namespace).Get(ctx, ref.Name, metav1.GetOptions{})
	if err != nil {
		// Already deleted, or a transient API error — the ReplicaSet itself
		// is still a valid, if coarser, workload identity: pods of the SAME
		// ReplicaSet still correlate together, just not further up to their
		// Deployment. Better than dropping workload correlation for this
		// Finding entirely over a lookup that failed.
		return formatGVK(schema.FromAPIVersionAndKind(ref.APIVersion, ref.Kind)), ref.Name, true
	}
	for _, rsRef := range rs.GetOwnerReferences() {
		return formatGVK(schema.FromAPIVersionAndKind(rsRef.APIVersion, rsRef.Kind)), rsRef.Name, true
	}
	// A bare ReplicaSet, not owned by a Deployment — its own identity is the
	// workload.
	return formatGVK(schema.FromAPIVersionAndKind(ref.APIVersion, ref.Kind)), ref.Name, true
}

// resolveWorkloadForInvolvedObject resolves a Warning event's involved
// object's owning workload, when that object is a Pod — the only kind
// detector.go's event-watch needs this for, since Pods are the only kind
// whose sibling replicas can legitimately produce the "N incidents for one
// fault" duplication this exists to fix (a Service/PVC/Node/HPA is already
// a single object with no siblings to correlate against).
//
// Also returns that same Pod's own resolved spec.priority (see
// tunnel.Finding.PodPriority's own doc comment) — this call already pays for
// the one GET that has the full Pod object in hand, so reading
// pod.Spec.Priority off it costs nothing further. Deliberately NOT gated by
// ok: ok is about whether a WORKLOAD could be resolved (it is false for a
// bare Pod with no controller), which says nothing about whether the Pod
// itself carries a resolved priority — the two are independent facts about
// the same object. priority is nil only when the Pod's own Kind isn't "Pod"
// (nothing was ever fetched), the GET itself failed, or the fetched Pod's
// spec.priority itself is unset.
//
// Costs one extra GET (the Pod itself — a Kubernetes Event's InvolvedObject
// is a bare corev1.ObjectReference with no OwnerReferences of its own) plus
// resolveWorkloadFromOwnerRefs' own possible second GET. Paid only once per
// (fingerprint, resend-cooldown window), not per raw event: detector.go's
// handleWatchedEvent calls this only after shouldSend's dedup check already
// passed, matching the rate this agent already sends Findings at.
//
// A ReplicaSet's or a Job's own events resolve too: a ReplicaSet that cannot
// create pods (FailedCreate: a missing ServiceAccount or PriorityClass, a
// quota, a LimitRange) belongs to its Deployment's incident, and each run of
// a failing CronJob to the CronJob's. Without this the ReplicaSet opened an
// incident of its own beside the Deployment's, one fault twice (observed
// live, loop campaign 2026-10-13, S22/S24/S25/S41), and every CronJob run
// opened another.
func resolveWorkloadForInvolvedObject(ctx context.Context, clientset kubernetes.Interface, ev *corev1.Event) (gvk, name string, priority *int32, ok bool) {
	switch ev.InvolvedObject.Kind {
	case "ReplicaSet":
		apiVersion := ev.InvolvedObject.APIVersion
		if apiVersion == "" {
			apiVersion = "apps/v1"
		}
		gvk, name, ok = resolveWorkloadFromOwnerRefs(ctx, clientset, ev.InvolvedObject.Namespace,
			[]metav1.OwnerReference{{APIVersion: apiVersion, Kind: "ReplicaSet", Name: ev.InvolvedObject.Name}})
		return gvk, name, nil, ok
	case "Job":
		job, err := clientset.BatchV1().Jobs(ev.InvolvedObject.Namespace).Get(ctx, ev.InvolvedObject.Name, metav1.GetOptions{})
		if err != nil {
			return "", "", nil, false
		}
		if owner := metav1.GetControllerOf(job); owner != nil && owner.Kind == "CronJob" {
			return formatGVK(schema.FromAPIVersionAndKind(owner.APIVersion, owner.Kind)), owner.Name, nil, true
		}
		return "", "", nil, false // a bare Job is its own identity already
	}
	if ev.InvolvedObject.Kind != "Pod" {
		return "", "", nil, false
	}
	pod, err := clientset.CoreV1().Pods(ev.InvolvedObject.Namespace).Get(ctx, ev.InvolvedObject.Name, metav1.GetOptions{})
	if err != nil {
		// Pod already gone by the time this cooldown-gated lookup runs, or a
		// transient API error — not worth failing the Finding over; it's
		// still sent, just without workload correlation.
		return "", "", nil, false
	}
	gvk, name, ok = resolveWorkloadFromOwnerRefs(ctx, clientset, ev.InvolvedObject.Namespace, pod.GetOwnerReferences())
	return gvk, name, pod.Spec.Priority, ok
}
