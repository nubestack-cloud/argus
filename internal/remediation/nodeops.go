package remediation

import "fmt"

// CordonNode and DrainNode (PROJECT.md PG15): the two things an operator
// does to a node that is failing or about to be replaced. Both target a v1
// Node and nothing else, and both need the remediate chart's separate node
// opt-in (remediate.nodeOps.enabled), because their RBAC cannot be narrowed
// by name: `patch nodes` reaches every node, and `create pods/eviction`
// reaches every pod.
//
// CordonNode sets spec.unschedulable, either way, so it is its own undo: the
// rollback of a cordon is a CordonNode with Unschedulable=false.
//
// DrainNode cordons, then evicts every pod on the node through the eviction
// API — so PodDisruptionBudgets hold, and a budget that would be broken
// refuses the eviction rather than being overridden — skipping DaemonSet and
// static (mirror) pods, exactly as `kubectl drain --ignore-daemonsets` does.
// It refuses outright, before evicting anything, if any pod on the node has no
// controller (it would not come back), and refuses a pod with emptyDir data
// unless DeleteEmptyDirData was set. It is not reversible: evicted pods are
// recreated elsewhere by their controllers, not put back; its undo is an
// uncordon, proposed separately.

// CordonNodeParams says which way the node's schedulability goes.
type CordonNodeParams struct {
	Unschedulable bool `json:"unschedulable"`
}

func (CordonNodeParams) actionType() ActionType { return ActionCordonNode }

// DrainNodeParams bounds a drain.
type DrainNodeParams struct {
	// DeleteEmptyDirData permits evicting pods whose emptyDir volumes hold
	// data that is lost with them. Off, such a pod refuses the drain.
	DeleteEmptyDirData bool `json:"deleteEmptyDirData"`
}

func (DrainNodeParams) actionType() ActionType { return ActionDrainNode }

const nodeGVK = "v1/Node"

// NodeActionPermitted refuses a node action against anything but a Node.
func NodeActionPermitted(action ActionType, gvk string) error {
	if gvk != nodeGVK {
		return fmt.Errorf("%s may only target a Node (%s), not %s", action, nodeGVK, gvk)
	}
	return nil
}
