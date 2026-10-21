package agent

import (
	"fmt"
	"time"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// stateFacts are short factual sentences about an object's state, computed
// from the object alone, that an investigation most often gets wrong when it
// has to infer them (PROJECT.md IN7): that it is being deleted, who manages
// it, and — the one that matters most — whether its health condition has
// been False since it was created. A workload that never worked is usually
// misconfigured; one that worked and broke usually regressed on a change.
// Sentences, not interpretations: the model draws the conclusion.
func stateFacts(obj *unstructured.Unstructured, now time.Time) []string {
	var facts []string
	created := obj.GetCreationTimestamp().Time
	if dt := obj.GetDeletionTimestamp(); dt != nil {
		facts = append(facts, fmt.Sprintf("Marked for deletion %s ago and still present (finalizers: %v).", roundAge(now.Sub(dt.Time)), obj.GetFinalizers()))
	}
	if obj.GetKind() == "Namespace" {
		if phase, _, _ := unstructured.NestedString(obj.Object, "status", "phase"); phase == "Terminating" {
			facts = append(facts, "This namespace is terminating; objects in it are being deleted.")
		}
	}
	ann, labels := obj.GetAnnotations(), obj.GetLabels()
	switch {
	case ann["meta.helm.sh/release-name"] != "":
		facts = append(facts, fmt.Sprintf("Managed by Helm release %s/%s; a change made directly is undone by the next upgrade.", ann["meta.helm.sh/release-namespace"], ann["meta.helm.sh/release-name"]))
	case labels["argocd.argoproj.io/instance"] != "" || ann["argocd.argoproj.io/tracking-id"] != "":
		facts = append(facts, "Managed by Argo CD; a change made directly is reverted at the next sync.")
	case labels["kustomize.toolkit.fluxcd.io/name"] != "" || labels["helm.toolkit.fluxcd.io/name"] != "":
		facts = append(facts, "Managed by Flux; a change made directly is reverted at the next reconcile.")
	}
	conds, _, _ := unstructured.NestedSlice(obj.Object, "status", "conditions")
	for _, raw := range conds {
		c, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		typ, _ := c["type"].(string)
		if typ != "Ready" && typ != "Available" {
			continue
		}
		if status, _ := c["status"].(string); status != "False" {
			continue
		}
		since, err := time.Parse(time.RFC3339, fmt.Sprint(c["lastTransitionTime"]))
		if err != nil || created.IsZero() {
			continue
		}
		if since.Sub(created) < 2*time.Minute {
			facts = append(facts, fmt.Sprintf("Its %s condition has been False since it was created %s ago: it has never been healthy.", typ, roundAge(now.Sub(created))))
		} else {
			facts = append(facts, fmt.Sprintf("Its %s condition turned False %s ago, %s after it was created: it was healthy before.", typ, roundAge(now.Sub(since)), roundAge(since.Sub(created))))
		}
	}
	return facts
}

func roundAge(d time.Duration) string {
	switch {
	case d >= 48*time.Hour:
		return fmt.Sprintf("%dd", int(d.Hours()/24))
	case d >= time.Hour:
		return fmt.Sprintf("%dh", int(d.Hours()))
	default:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	}
}
