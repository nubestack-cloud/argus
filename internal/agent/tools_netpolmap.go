package agent

import (
	"context"
	"encoding/json"
	"fmt"

	"argus/internal/agent/netpolmap"
)

// ---------------------------------------------------------------- get_network_policy_map

// networkPolicyMapResult is get_network_policy_map's answer: with a
// namespace, that namespace's map; without, the per-namespace index the
// picker reads.
type networkPolicyMapResult struct {
	insightStamp
	*netpolmap.Map
	Namespaces []netpolmap.IndexRow `json:"namespaces,omitempty"`
	// Note is the scope every answer carries: what enforces policy and what
	// this does not read.
	Note string `json:"note"`
}

const networkPolicyMapNote = "Predicted from NetworkPolicy objects; Cilium and Calico policies are not read."

// getNetworkPolicyMap serves the cluster page's Network policy tab
// (internal/agent/netpolmap). Inventory, like get_namespace_topology: on the
// inspect allowlist, not offered to the model.
//
// Pods, Namespaces and NetworkPolicies must be readable or the call fails:
// without them "no policy selects this" would read as "open to everything",
// a claim the agent cannot make. ReplicaSets, Jobs and Nodes only add
// detail (a pod's Deployment, a node behind an address) and degrade to less
// of it, with the gap in coverage.
func (e *ToolExecutor) getNetworkPolicyMap(_ context.Context, raw json.RawMessage) (json.RawMessage, bool, error) {
	c, err := e.cache()
	if err != nil {
		return nil, false, err
	}
	var a struct {
		Namespace string `json:"namespace"`
	}
	if err := decodeInsightArgs(raw, &a); err != nil {
		return nil, false, err
	}
	var in netpolmap.Input
	if in.Pods, err = c.Pods(""); err != nil {
		return nil, false, fmt.Errorf("pods are not readable, so the policy map cannot be drawn: %w", err)
	}
	if in.Namespaces, err = c.Namespaces(); err != nil {
		return nil, false, fmt.Errorf("namespaces are not readable, so namespace selectors cannot be resolved: %w", err)
	}
	if in.Policies, err = c.NetworkPolicies(""); err != nil {
		return nil, false, fmt.Errorf("NetworkPolicies are not readable, so what they allow cannot be shown: %w", err)
	}
	in.ReplicaSets, _ = c.ReplicaSets("")
	in.Jobs, _ = c.Jobs("")
	in.Nodes, _ = c.Nodes()

	res := networkPolicyMapResult{
		insightStamp: stampOf(e.meta(kindPod, kindNamespace, kindNetworkPolicy, kindReplicaSet, [2]string{"batch", "Job"}, [2]string{"", "Node"})),
		Note:         networkPolicyMapNote,
	}
	if a.Namespace == "" {
		res.Namespaces = netpolmap.Index(in)
		if res.Namespaces == nil {
			res.Namespaces = []netpolmap.IndexRow{}
		}
		return marshalInsight(res)
	}
	m := netpolmap.Build(in, a.Namespace)
	res.Map = &m
	return marshalInsight(res)
}
