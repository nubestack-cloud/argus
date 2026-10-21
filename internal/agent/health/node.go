package health

import (
	"cmp"

	corev1 "k8s.io/api/core/v1"
)

// NodeHealth is one node's health signals, more than a Level since callers
// show them one by one; NodeVerdict reduces them to a Level.
type NodeHealth struct {
	Ready         bool
	Unschedulable bool
	Pressures     []string // MemoryPressure, DiskPressure, PIDPressure — those that are True
	Version       string   // the kubelet's
	Reason        string   // the Ready condition's message, when not ready
	// ReadyKnown is false when there is no Ready condition at all: the
	// kubelet has never reported, which is not the same as being down.
	ReadyKnown bool
}

// pressureConditions are the node pressures NodeHealth reports, in order.
var pressureConditions = []corev1.NodeConditionType{corev1.NodeMemoryPressure, corev1.NodeDiskPressure, corev1.NodePIDPressure}

// Node reads a node's conditions and spec.
func Node(node *corev1.Node) NodeHealth {
	h := NodeHealth{Unschedulable: node.Spec.Unschedulable, Version: node.Status.NodeInfo.KubeletVersion}
	under := map[corev1.NodeConditionType]bool{}
	for _, c := range node.Status.Conditions {
		if c.Type == corev1.NodeReady {
			h.ReadyKnown, h.Ready = true, c.Status == corev1.ConditionTrue
			if !h.Ready {
				h.Reason = cmp.Or(c.Message, h.Reason)
			}
			continue
		}
		if c.Status == corev1.ConditionTrue {
			under[c.Type] = true
		}
	}
	for _, p := range pressureConditions {
		if under[p] {
			h.Pressures = append(h.Pressures, string(p))
		}
	}
	return h
}

// NodeVerdict grades a node:
//
//	no Ready condition   → unknown   (kubelet never reported)
//	Ready != True        → unhealthy (NotReady)
//	cordoned             → degraded  (lost scheduling capacity)
//	any pressure         → degraded  (the first pressure is the reason)
//	otherwise            → healthy
func NodeVerdict(node *corev1.Node) Verdict {
	h := Node(node)
	switch {
	case !h.ReadyKnown:
		return Verdict{Level: LevelUnknown}
	case !h.Ready:
		return Verdict{Level: LevelUnhealthy, Reason: "NotReady", Message: h.Reason}
	case h.Unschedulable:
		return Verdict{Level: LevelDegraded, Reason: "Cordoned"}
	case len(h.Pressures) > 0:
		return Verdict{Level: LevelDegraded, Reason: h.Pressures[0]}
	}
	return Verdict{Level: LevelHealthy}
}
