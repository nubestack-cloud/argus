package topology

import (
	"fmt"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// IsMapped reports whether the relationship graph draws kind (any accepted
// spelling) in apiGroup, and returns the canonical kind and its group. An
// empty apiGroup means "the kind's built-in group".
func IsMapped(kind, apiGroup string) (canonical NodeKind, group string, ok bool) {
	k, known := normalizeKind(kind)
	if !known || k == KindPodGroup {
		return "", "", false
	}
	if apiGroup != "" && !strings.EqualFold(apiGroup, builtinGroups[k]) {
		return "", "", false
	}
	return k, builtinGroups[k], true
}

// IsClusterScoped reports whether a mapped kind has no namespace.
func IsClusterScoped(kind NodeKind) bool { return clusterScopedKinds[kind] }

// UnmappedNote is the note an unmapped neighbourhood carries.
func UnmappedNote(kind string) string {
	return fmt.Sprintf("Relationships for %s are not mapped yet.", kind)
}

// ObjectNode is one object for UnmappedNeighborhood: its kind and group
// (which the cached object may not carry in TypeMeta) and the object itself
// (typed or *unstructured.Unstructured).
type ObjectNode struct {
	Kind     string
	APIGroup string
	Obj      metav1.Object
}

// UnmappedNodeID is the node ID for an object of any kind. A kind the graph
// maps keeps its usual ID, so an owner such as an Ingress joins up with the
// IDs a mapped neighbourhood would use; any other kind is qualified by its
// group so two CRDs that share a kind name cannot collide.
func UnmappedNodeID(kind, group, namespace, name string) string {
	if k, _, ok := IsMapped(kind, group); ok {
		if clusterScopedKinds[k] {
			namespace = ""
		}
		return buildNodeID(k, namespace, name)
	}
	qualified := strings.ToLower(kind)
	if group != "" {
		qualified += "." + strings.ToLower(group)
	}
	return qualified + "/" + namespace + "/" + name
}

// UnmappedNeighborhood is the neighbourhood of an object whose kind the
// relationship graph does not map (a CRD, or a built-in kind the builder does
// not draw): the object as root, plus what generic metadata can link without
// per-kind knowledge — the owners its ownerReferences name, and the objects
// whose ownerReferences (or, for a GitOps application, whose managed-resource
// list) name it, all joined by owns edges. Unmapped and Note are always set:
// the kind's own relationships (an Application's source repository, a
// Certificate's Secret) are not drawn. Nodes are capped at
// MaxNeighborhoodNodes, root first.
func UnmappedNeighborhood(root ObjectNode, owners, owned []ObjectNode, now time.Time) *Subgraph {
	r := root.Obj
	sub := &Subgraph{
		Root:     Ref{Kind: root.Kind, APIGroup: root.APIGroup, Namespace: r.GetNamespace(), Name: r.GetName()},
		Nodes:    []Node{},
		Edges:    []Edge{},
		Unmapped: true,
		Note:     UnmappedNote(root.Kind),
	}
	seen := map[string]bool{}
	add := func(o ObjectNode) (string, bool) {
		id := UnmappedNodeID(o.Kind, o.APIGroup, o.Obj.GetNamespace(), o.Obj.GetName())
		if seen[id] {
			return id, true
		}
		if len(sub.Nodes) >= MaxNeighborhoodNodes {
			sub.Truncated = true
			return "", false
		}
		seen[id] = true
		status, reason := objectStatus(o.Obj, now)
		sub.Nodes = append(sub.Nodes, Node{
			ID: id, Kind: NodeKind(o.Kind), APIGroup: o.APIGroup, Namespace: o.Obj.GetNamespace(), Name: o.Obj.GetName(),
			Status: status, StatusReason: reason, Labels: o.Obj.GetLabels(),
		})
		return id, true
	}
	rootID, _ := add(root)
	edgeSeen := map[string]bool{}
	edge := func(source, target string) {
		id := source + "-" + string(EdgeOwns) + "-" + target
		if source == target || edgeSeen[id] {
			return
		}
		if len(sub.Edges) >= MaxNeighborhoodEdges {
			sub.Truncated = true
			return
		}
		edgeSeen[id] = true
		sub.Edges = append(sub.Edges, Edge{ID: id, Source: source, Target: target, Type: EdgeOwns})
	}
	for _, o := range owners {
		if id, ok := add(o); ok {
			edge(id, rootID)
		}
	}
	for _, o := range owned {
		if id, ok := add(o); ok {
			edge(rootID, id)
		}
	}
	return sub
}

// objectStatus grades any object: the typed graders for the kinds they
// know, and for anything else the two status conventions CRDs share — a
// health.status word (Argo CD) or a Ready condition (cert-manager, Flux and
// most controllers). Without either it is unknown, never healthy by default.
func objectStatus(obj metav1.Object, now time.Time) (HealthStatus, string) {
	switch o := obj.(type) {
	case *corev1.Pod:
		return podStatus(o, now)
	case *unstructured.Unstructured:
		return unstructuredStatus(o)
	}
	if s, reason := workloadStatus(obj, now); s != StatusUnknown {
		return s, reason
	}
	return StatusUnknown, ""
}

func unstructuredStatus(u *unstructured.Unstructured) (HealthStatus, string) {
	if h, ok, _ := unstructured.NestedString(u.Object, "status", "health", "status"); ok && h != "" {
		switch h {
		case "Healthy":
			return StatusHealthy, h
		case "Progressing":
			return StatusDegraded, h
		case "Degraded", "Missing":
			return StatusUnhealthy, h
		case "Suspended":
			return StatusNeutral, h
		default:
			return StatusUnknown, h
		}
	}
	conds, _, _ := unstructured.NestedSlice(u.Object, "status", "conditions")
	for _, c := range conds {
		m, ok := c.(map[string]any)
		if !ok || m["type"] != "Ready" {
			continue
		}
		reason, _ := m["reason"].(string)
		switch m["status"] {
		case "True":
			return StatusHealthy, reason
		case "False":
			return StatusUnhealthy, reason
		default:
			return StatusUnknown, reason
		}
	}
	return StatusUnknown, ""
}
