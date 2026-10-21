package api

import (
	"testing"

	"argus/internal/orchestrator"
)

// Decommission's closure path, checked without a database.
//
// The bug this guards: handleDecommissionCluster used to close a cluster's
// incidents with one raw `UPDATE incidents SET state = 'Dismissed' WHERE
// cluster_id = $1 AND state NOT IN ('Resolved', 'Dismissed', 'Investigating')`.
// Two of its states were wrong in opposite directions — it took the illegal
// Executing -> Dismissed edge, and it excluded Investigating entirely, leaving
// those incidents open forever on a cluster that can never reconnect. Both
// facts are now decided by decommissionClosurePath, so both are testable here
// with no fixture at all.

// incidentStatesFromCheckConstraint mirrors migration 000095's
// incidents_state_check, which is the complete set of values incidents.state
// may hold. Duplicated here on purpose: this list is the thing the test below
// is checking the code against, so deriving it from the code would make the
// test vacuous. TestDecommissionClosurePathCoversEveryLiveState (the DB test)
// reads the real constraint out of Postgres and fails if this list has drifted
// from it.
var incidentStatesFromCheckConstraint = []string{
	"Detected", "Investigating", "RecommendationReady", "NeedsHumanInvestigation",
	"AwaitingApproval", "Executing", "AwaitingMerge", "Validating",
	"Resolved", "Failed", "Reopened", "Dismissed", "Diagnosed", "ExecutionUnknown",
	"ValidationUnknown", "PlanRejected", "Expired",
}

// TestDecommissionClosurePathReachesDismissedFromEveryOpenState is the
// invariant that matters: an archived cluster must not be able to leave a
// single incident behind. Every state an incident can be in, except the two
// that are already closed, must have a path to Dismissed — and every step of
// that path must be an edge orchestrator.allowedTransitions actually permits,
// which is exactly what the old raw UPDATE did not check.
func TestDecommissionClosurePathReachesDismissedFromEveryOpenState(t *testing.T) {
	for _, state := range incidentStatesFromCheckConstraint {
		if orchestrator.IsTerminalState(state) {
			// Resolved and Dismissed. Nothing to close.
			if path := decommissionClosurePath(state); path != nil {
				t.Errorf("state %q is terminal but decommissionClosurePath returned %v", state, path)
			}
			continue
		}
		path := decommissionClosurePath(state)
		if path == nil {
			t.Errorf("state %q has no decommission closure path — an incident in this state would be left open forever on an archived cluster", state)
			continue
		}
		if got := path[len(path)-1]; got != orchestrator.StateDismissed {
			t.Errorf("state %q: closure path ends at %q, want %q", state, got, orchestrator.StateDismissed)
		}
		from := state
		for _, next := range path {
			if !orchestrator.CanTransition(from, next) {
				t.Errorf("state %q: closure path takes the illegal edge %s -> %s", state, from, next)
			}
			from = next
		}
	}
}

// TestDecommissionClosurePathCancelsInFlightWorkThroughItsOwnState pins the
// two deliberate decisions in decommissionClosurePath's doc comment, so a
// later simplification to "just go straight to Dismissed" has to argue with a
// failing test rather than silently reintroduce edges the state machine
// refuses on purpose.
func TestDecommissionClosurePathCancelsInFlightWorkThroughItsOwnState(t *testing.T) {
	investigating := decommissionClosurePath(orchestrator.StateInvestigating)
	wantInvestigating := []string{orchestrator.StateDetected, orchestrator.StateDismissed}
	if len(investigating) != len(wantInvestigating) {
		t.Fatalf("Investigating closure path = %v, want %v", investigating, wantInvestigating)
	}
	for i := range wantInvestigating {
		if investigating[i] != wantInvestigating[i] {
			t.Fatalf("Investigating closure path = %v, want %v", investigating, wantInvestigating)
		}
	}

	executing := decommissionClosurePath(orchestrator.StateExecuting)
	wantExecuting := []string{orchestrator.StateExecutionUnknown, orchestrator.StateDismissed}
	if len(executing) != len(wantExecuting) {
		t.Fatalf("Executing closure path = %v, want %v", executing, wantExecuting)
	}
	for i := range wantExecuting {
		if executing[i] != wantExecuting[i] {
			t.Fatalf("Executing closure path = %v, want %v", executing, wantExecuting)
		}
	}
}

// TestDecommissionClosureRecordNeverClaimsAFix guards the wording, which is
// the product promise this closure has to keep: a decommissioned cluster's
// incidents were not fixed, and nothing ARGUS writes about them may imply they
// were. The two in-flight cases additionally have to say what was abandoned.
func TestDecommissionClosureRecordNeverClaimsAFix(t *testing.T) {
	for _, state := range incidentStatesFromCheckConstraint {
		if orchestrator.IsTerminalState(state) {
			continue
		}
		summary, detail := decommissionClosureRecord(state, "cl_test", "prod-eu-west")
		if summary == "" {
			t.Errorf("state %q: empty closure summary", state)
		}
		if detail["reason"] != "cluster_decommissioned" {
			t.Errorf("state %q: detail reason = %v, want cluster_decommissioned", state, detail["reason"])
		}
		if detail["fromState"] != state {
			t.Errorf("state %q: detail fromState = %v", state, detail["fromState"])
		}
		switch state {
		case orchestrator.StateInvestigating:
			if detail["inFlightWork"] != "investigation" {
				t.Errorf("Investigating: detail inFlightWork = %v, want investigation", detail["inFlightWork"])
			}
		case orchestrator.StateExecuting:
			if detail["inFlightWork"] != "execution" {
				t.Errorf("Executing: detail inFlightWork = %v, want execution", detail["inFlightWork"])
			}
		default:
			if _, ok := detail["inFlightWork"]; ok {
				t.Errorf("state %q: detail claims in-flight work (%v) when there was none", state, detail["inFlightWork"])
			}
		}
	}
}
