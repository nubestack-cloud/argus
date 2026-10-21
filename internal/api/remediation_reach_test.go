package api

import (
	"strings"
	"testing"

	"argus/internal/gateway"
	"argus/internal/remediation"
)

// The "may this plan execute" gate for a cluster with no remediation agent:
// an in-place plan is blocked with a sentence naming the cluster by its
// display name; an OpenPR plan never is, because it does not touch the
// cluster.
func TestRemediationAgentBlockedReason(t *testing.T) {
	s := &Server{gw: gateway.NewGateway(nil, nil, nil)} // nothing ever connected

	got := s.remediationAgentBlockedReason(remediation.ActionDeleteResource, "cl_01abc", "lab-dev")
	if got == "" {
		t.Fatal("an in-place plan on a cluster with no remediation agent must be blocked")
	}
	if !strings.HasPrefix(got, "lab-dev has no remediation agent connected") {
		t.Errorf("reason should lead with the cluster's display name, got %q", got)
	}
	if strings.Contains(got, "cl_01abc") {
		t.Errorf("reason should not show the raw cluster id when a name exists, got %q", got)
	}

	if got := s.remediationAgentBlockedReason(remediation.ActionOpenPR, "cl_01abc", "lab-dev"); got != "" {
		t.Errorf("an OpenPR plan changes a repository, not the cluster — must never be blocked by this, got %q", got)
	}
}

func TestRemediationAgentMissingSentenceFallsBackToID(t *testing.T) {
	got := remediationAgentMissingSentence("cl_01abc", "")
	if !strings.HasPrefix(got, "cl_01abc has no remediation agent connected") {
		t.Errorf("with no display name the id is the only name there is, got %q", got)
	}
}
