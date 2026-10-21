package changes

import (
	"fmt"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"
)

// BuildEvent turns one object-cache notification into a ChangeEvent.
// op is OpAdd, OpUpdate or OpDelete; oldObj is nil for an add and newObj nil
// for a delete (a cache.DeletedFinalStateUnknown tombstone is unwrapped).
//
// ok is false when the kind is not tracked (Classify), the object carries no
// metadata, or an update changed no tracked field. For an update whose
// differ found nothing but whose metadata.generation moved, the event
// carries a single metadata.generation change, so spec edits the differs do
// not specifically track still appear. Pods are exempt: their differ's
// three fields are the whole contract.
func BuildEvent(kind, apiGroup, op string, oldObj, newObj any, observedAt time.Time) (ChangeEvent, bool) {
	if !Classify(kind, apiGroup) {
		return ChangeEvent{}, false
	}
	oldObj = unwrapTombstone(oldObj)
	newObj = unwrapTombstone(newObj)

	subject := newObj
	if op == OpDelete || subject == nil {
		subject = oldObj
	}
	if subject == nil {
		return ChangeEvent{}, false
	}
	m, err := meta.Accessor(subject)
	if err != nil {
		return ChangeEvent{}, false
	}

	ev := ChangeEvent{
		ObservedAt: observedAt.UTC(),
		Kind:       kind,
		APIGroup:   apiGroup,
		Namespace:  m.GetNamespace(),
		Name:       m.GetName(),
		UID:        string(m.GetUID()),
		Op:         op,
	}
	if owner := primaryOwner(m.GetOwnerReferences()); owner != nil {
		ev.OwnerKind = owner.Kind
		ev.OwnerName = owner.Name
	}

	switch op {
	case OpAdd:
		ev.Summary = "created"
		return ev, true
	case OpDelete:
		ev.Summary = "deleted"
		return ev, true
	case OpUpdate:
	default:
		return ChangeEvent{}, false
	}

	if oldObj == nil || newObj == nil {
		return ChangeEvent{}, false
	}
	if diff := ComputeDiff(kind, oldObj, newObj); diff != nil {
		ev.Fields = diff.Fields
		ev.Summary = diff.Summary
		return ev, true
	}
	if kind == "Pod" {
		return ChangeEvent{}, false
	}
	oldGen, newGen := generation(oldObj), generation(newObj)
	if oldGen == newGen || oldGen <= 0 || newGen <= 0 || !generationBumpIsSpecChange(kind, oldObj, newObj) {
		return ChangeEvent{}, false
	}
	ev.Fields = []FieldChange{{Path: "metadata.generation", OldValue: oldGen, NewValue: newGen}}
	ev.Summary = fmt.Sprintf("spec changed (gen %d→%d, fields not specifically tracked)", oldGen, newGen)
	return ev, true
}

func unwrapTombstone(obj any) any {
	if t, ok := obj.(cache.DeletedFinalStateUnknown); ok {
		return t.Obj
	}
	if t, ok := obj.(*cache.DeletedFinalStateUnknown); ok && t != nil {
		return t.Obj
	}
	return obj
}

// primaryOwner prefers the controller reference, else the first owner.
func primaryOwner(refs []metav1.OwnerReference) *metav1.OwnerReference {
	for i := range refs {
		if refs[i].Controller != nil && *refs[i].Controller {
			return &refs[i]
		}
	}
	if len(refs) > 0 {
		return &refs[0]
	}
	return nil
}

func generation(obj any) int64 {
	m, err := meta.Accessor(obj)
	if err != nil {
		return 0
	}
	return m.GetGeneration()
}

// generationBumpIsSpecChange filters the one known false positive: the
// Deployment API bumps generation for top-level annotation edits because
// those annotations are copied to ReplicaSets.
//
// For CRD objects the same applies more widely: a controller writing any
// non-status top-level field (Argo CD's `operation`) bumps generation on
// every reconcile, so only a bump whose spec actually differs counts.
func generationBumpIsSpecChange(kind string, oldObj, newObj any) bool {
	if oldU, ok := oldObj.(*unstructured.Unstructured); ok {
		if newU, ok := newObj.(*unstructured.Unstructured); ok {
			return !apiequality.Semantic.DeepEqual(oldU.Object["spec"], newU.Object["spec"])
		}
	}
	if kind != "Deployment" {
		return true
	}
	oldDep, oldOK := oldObj.(*appsv1.Deployment)
	newDep, newOK := newObj.(*appsv1.Deployment)
	if !oldOK || !newOK {
		return true
	}
	return !apiequality.Semantic.DeepEqual(oldDep.Spec, newDep.Spec)
}
