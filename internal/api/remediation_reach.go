package api

import (
	"fmt"

	"argus/internal/remediation"
	"argus/internal/tunnel"
)

// remediationAgentBlockedReason answers "may this plan execute on this cluster
// right now" for the one precondition every in-place plan shares and no
// policy gate covers: a live connection from the cluster's separately-deployed
// remediation agent (argus-remediate, PROJECT.md E11). The investigation
// agent is deliberately incapable of writing, so without a remediate (or a
// pre-E11 combined) connection, approving an in-place plan can only fail at
// the dry run — after a human has made the decision and clicked.
//
// Empty means "not blocked by this". Always empty for OpenPR, which changes a
// repository and never touches the cluster.
//
// The sentence names the cluster by its display name (falling back to the id
// only when it has none) because it is shown to a person beside the Approve
// button, the preview error and the approve refusal — one wording for all
// three, so the three can never disagree about why.
//
// Like gateway.IsConnected this is a point-in-time read: an agent that
// connects a moment later makes a stale "blocked" answer wrong in the safe
// direction, and one that disconnects a moment later is still caught by the
// dry run's own not-connected error.
func (s *Server) remediationAgentBlockedReason(actionType remediation.ActionType, clusterID, clusterName string) string {
	if actionType == remediation.ActionOpenPR {
		return ""
	}
	if s.gw != nil && s.gw.IsConnectedForRole(clusterID, tunnel.RoleRemediate) {
		return ""
	}
	return remediationAgentMissingSentence(clusterID, clusterName)
}

// remediationAgentMissingSentence is the wording itself, split out so it is
// testable without a gateway.
func remediationAgentMissingSentence(clusterID, clusterName string) string {
	name := nameOrID(clusterName, clusterID)
	return fmt.Sprintf("%s has no remediation agent connected, so ARGUS cannot change anything on it. "+
		"Remediation is opt-in per cluster (the argus-agent chart's remediate.enabled); the investigation agent there can only read.", name)
}
