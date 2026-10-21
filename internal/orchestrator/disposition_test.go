package orchestrator

import (
	"strings"
	"testing"

	"argus/internal/fleetgroup"
)

// The review's finding 9, as tests. The bug it names is not "Diagnosed is in
// the wrong bucket" — it is that there was only one bucketing available, the
// state machine's own terminality, and it cannot answer the question every
// counter, filter and tab in the product was asking it. These tests pin the
// two questions apart and keep them apart.

// TestDiagnosedIsFinishedWithoutBeingClosed is the finding stated as the exact
// contradiction that produced it: StateDiagnosed's doc comment called it
// terminal, allowedTransitions gave it three outgoing edges, and every counter
// in the codebase treated it as open. On the development database that was six
// completed diagnoses sitting in the open queue with nothing explaining why
// they never moved.
//
// All three observations were correct. Diagnosed is finished (ARGUS will not
// act again on its own), not closed (the fault is still live), and it requires
// action (a person applies the guidance, or closes the incident). Only
// "terminal" was wrong, and only because it was being used to mean "finished".
func TestDiagnosedIsFinishedWithoutBeingClosed(t *testing.T) {
	if IsTerminalState(StateDiagnosed) {
		t.Error("IsTerminalState(Diagnosed) = true — it has outgoing edges (re-analyse, resolve, dismiss); the doc comment that called it terminal was what was wrong")
	}
	if IsClosed(StateDiagnosed) {
		t.Error("IsClosed(Diagnosed) = true — the investigation finished, the fault did not. Closing it here would report a live fault as handled")
	}
	if !RequiresAction(StateDiagnosed) {
		t.Error("RequiresAction(Diagnosed) = false — nothing in ARGUS will move this incident again; the guidance is the fix and a person has to apply it")
	}
}

// TestRequiresActionIsNotTheComplementOfClosed is the substance of the change:
// if the two definitions agreed everywhere, renaming the counter would have
// been decoration. They disagree on exactly the states where another writer
// owns the next move — and those are the states an operator scanning a queue
// can do nothing useful about.
func TestRequiresActionIsNotTheComplementOfClosed(t *testing.T) {
	for _, state := range []string{StateInvestigating, StateExecuting, StateValidating, StateAwaitingMerge} {
		if IsClosed(state) {
			t.Errorf("IsClosed(%q) = true, want false — it is open, it is just not anybody's queue item", state)
		}
		if RequiresAction(state) {
			t.Errorf("RequiresAction(%q) = true, want false — an analysis, an execution, a grace period or a pull-request review owns the next move here; asking an operator to act is asking them to race another writer", state)
		}
	}
}

// TestPlanRejectedIsOpenAndOnAHuman is the review's finding 6 from the other
// side. A rejection used to land in Dismissed, which is closed, so the fault
// left the queue while it was still live in the cluster. Whatever else changes,
// the state a refusal produces must not be closed and must not be quiet.
func TestPlanRejectedIsOpenAndOnAHuman(t *testing.T) {
	if IsClosed(StatePlanRejected) {
		t.Error("IsClosed(PlanRejected) = true — 'this fix is unsafe' is not 'this fault no longer matters'; that conflation is the bug")
	}
	if !RequiresAction(StatePlanRejected) {
		t.Error("RequiresAction(PlanRejected) = false — a refused plan leaves the fault unchanged and the next move with a person")
	}
	if IsTerminalState(StatePlanRejected) {
		t.Error("IsTerminalState(PlanRejected) = true — re-analyse, propose at the source, resolve and dismiss are all real exits")
	}
}

// TestEveryStateHasADisposition is the guard that stops this drifting the way
// the thing it replaced did. DispositionOf falls back to RequiresAction so an
// unclassified state surfaces to a human rather than disappearing from every
// queue — but a real state reaching that fallback is a bug, not a design, and
// silently relying on it is how "Diagnosed is terminal" survived for months.
func TestEveryStateHasADisposition(t *testing.T) {
	for state := range allowedTransitions {
		if _, ok := stateDisposition[state]; !ok {
			t.Errorf("state %q has transitions but no disposition — classify it in requiresActionStates, inProgressStates or closedStates", state)
		}
	}
	for state := range stateDisposition {
		if _, ok := allowedTransitions[state]; !ok {
			t.Errorf("state %q has a disposition but no entry in allowedTransitions — one of the two tables has a state the other has never heard of", state)
		}
	}
	// No state may be classified twice: the three slices are built into one
	// map, so a duplicate would silently take whichever wrote last.
	seen := map[string]int{}
	for _, group := range [][]string{requiresActionStates, inProgressStates, closedStates} {
		for _, state := range group {
			seen[state]++
		}
	}
	for state, n := range seen {
		if n != 1 {
			t.Errorf("state %q appears in %d disposition groups, want exactly 1", state, n)
		}
	}
}

// TestClosedDispositionMatchesTerminality: today the two coincide, and that is
// worth asserting precisely BECAUSE they are not derived from each other. If a
// future state is terminal but not closed (or closed but has edges), this test
// failing is the prompt to decide which is intended rather than to discover it
// from a wrong number on a dashboard.
func TestClosedDispositionMatchesTerminality(t *testing.T) {
	// StateExpired is the deliberate divergence, in the OPPOSITE direction
	// from Diagnosed's (finished-but-open, above): closed (it is nobody's
	// queue item) but NOT state-machine-terminal (it has one real edge, to
	// Detected, for a genuine recurrence — see StateExpired's own doc
	// comment). Diagnosed already established that terminality and
	// disposition are two different questions; this is the other
	// combination the same argument allows.
	deliberateDivergence := map[string]bool{StateExpired: true}
	for _, state := range allKnownStates {
		if deliberateDivergence[state] {
			continue
		}
		if IsClosed(state) != IsTerminalState(state) {
			t.Errorf("state %q: IsClosed = %v but IsTerminalState = %v — they have coincided so far; if this divergence is deliberate, say so here",
				state, IsClosed(state), IsTerminalState(state))
		}
	}
}

// TestClosedDispositionMatchesCorrelation: "may a recurring finding re-attach
// to this incident?" (internal/fleetgroup) is a genuinely different question
// from "is this incident's lifecycle over?", and they are answered by two
// tables in two packages. They must agree, because a finding re-attaching to a
// closed incident — or opening a new incident alongside an open one — are both
// real bugs, and neither would announce itself.
func TestClosedDispositionMatchesCorrelation(t *testing.T) {
	// StateExpired is PROJECT.md T2's own deliberate exception, and it is
	// exactly the point of the state: closed for queue/disposition
	// purposes (IsClosed = true — an aged-out incident is nobody's queue
	// item), but deliberately NOT closed for correlation purposes
	// (fleetgroup.IsClosedState = false) — a recurring Finding must still
	// be able to re-attach to it (internal/gateway/finding.go's
	// handleFinding), which is what "a recurrence can reopen an expired
	// incident" means concretely. Every other state must still agree; this
	// is the one place lifecycle and correlation are allowed to answer
	// differently, and it is allowed for the same reason Diagnosed was
	// allowed to answer terminality/disposition differently.
	deliberateDivergence := map[string]bool{StateExpired: true}
	for _, state := range allKnownStates {
		if deliberateDivergence[state] {
			if !IsClosed(state) || fleetgroup.IsClosedState(state) {
				t.Errorf("state %q: expected the deliberate divergence (orchestrator.IsClosed = true, fleetgroup.IsClosedState = false), got IsClosed = %v, fleetgroup.IsClosedState = %v",
					state, IsClosed(state), fleetgroup.IsClosedState(state))
			}
			continue
		}
		if IsClosed(state) != fleetgroup.IsClosedState(state) {
			t.Errorf("state %q: orchestrator.IsClosed = %v but fleetgroup.IsClosedState = %v — correlation and the lifecycle disagree about whether this incident is finished",
				state, IsClosed(state), fleetgroup.IsClosedState(state))
		}
	}
}

// TestRequiresActionStateSQLIsAWellFormedInList checks the one thing a string
// rendered into SQL has to be checked for. Every element is a constant declared
// in state.go, so there is no injection surface here — but a typo, a stray
// quote or an empty set would produce a query that either fails at runtime or,
// worse, silently matches nothing and reports an empty queue.
func TestRequiresActionStateSQLIsAWellFormedInList(t *testing.T) {
	got := RequiresActionStateSQL()
	if !strings.HasPrefix(got, "(") || !strings.HasSuffix(got, ")") {
		t.Fatalf("RequiresActionStateSQL() = %q, want a parenthesised IN-list", got)
	}
	inner := strings.TrimSuffix(strings.TrimPrefix(got, "("), ")")
	parts := strings.Split(inner, ", ")
	if len(parts) != len(requiresActionStates) {
		t.Fatalf("RequiresActionStateSQL() rendered %d entries, want %d: %q", len(parts), len(requiresActionStates), got)
	}
	for i, part := range parts {
		want := "'" + requiresActionStates[i] + "'"
		if part != want {
			t.Errorf("entry %d = %q, want %q", i, part, want)
		}
		if strings.Count(part, "'") != 2 {
			t.Errorf("entry %d = %q contains an unbalanced quote", i, part)
		}
	}
}
