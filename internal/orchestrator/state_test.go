package orchestrator

import (
	"testing"

	"argus/internal/fleetgroup"
)

// allKnownStates is every state constant this package defines. AwaitingMerge was
// listed here as a non-state for months — present in incidents.state's CHECK
// constraint since migration 000005, with no Go constant and no code path — and
// is now real, so it moved into the list proper. Used by the tests below to
// assert exhaustively over the whole state space rather than a hand-picked
// subset, so adding a state constant without giving it edges shows up here.
var allKnownStates = []string{
	StateDetected,
	StateInvestigating,
	StateRecommendationReady,
	StateNeedsHumanInvestigation,
	StateAwaitingApproval,
	StateAwaitingMerge,
	StateExecuting,
	StateValidating,
	StateFailed,
	StateExecutionUnknown,
	StateResolved,
	StateReopened,
	StateDismissed,
	StateDiagnosed,
	StateValidationUnknown,
	StatePlanRejected,
	StateExpired,
}

// TestTerminalStatesAreTrulyTerminal is the headline regression test for
// this package's central bug: SetState used to be a bare UPDATE with no look
// at the current state, so an approver's rejection (AwaitingApproval ->
// Dismissed) could be silently erased by anyone holding incident:reanalyse —
// the incident walked back to Investigating, got a fresh plan, and a
// different approver could execute it. Dismissed is terminal per
// lld/08-remediation-contracts.md §2; Resolved is terminal in this
// implementation (see allowedTransitions' doc comment). NOTHING may leave
// either, including a self-transition.
func TestTerminalStatesAreTrulyTerminal(t *testing.T) {
	for _, terminal := range []string{StateDismissed, StateResolved} {
		if !IsTerminalState(terminal) {
			t.Errorf("IsTerminalState(%q) = false, want true", terminal)
		}
		for _, to := range allKnownStates {
			if CanTransition(terminal, to) {
				t.Errorf("CanTransition(%q, %q) = true, want false — %q is terminal and must have no outgoing edge whatsoever",
					terminal, to, terminal)
			}
		}
	}
}

// TestDismissedCannotBeReanalysed is the same guarantee stated as the exact
// attack the bug report describes, so a future reader sees the concrete case
// and not just the general rule.
func TestDismissedCannotBeReanalysed(t *testing.T) {
	if CanTransition(StateDismissed, StateInvestigating) {
		t.Error("a Dismissed incident must not be re-analysable: an approver's rejection is final, and walking it back to Investigating is how a rejected plan got silently resurrected")
	}
	if CanTransition(StateDismissed, StateAwaitingApproval) {
		t.Error("a Dismissed incident must not be pushed back into the approval queue")
	}
}

// TestExecutingCannotBeReanalysed covers the second, worse half of the same
// bug: while an incident is Executing, a signed plan is in flight over the
// tunnel (internal/execution, between recordExecutingTransition
// and recordExecutionOutcome). A concurrent re-analyze used to move it to
// AwaitingApproval with a NEW plan, which the approve-and-execute path then
// happily executed — two concurrent mutations against the same workload.
// Executing may only ever advance to the three states recordExecutionOutcome
// writes: Validating (succeeded), Failed (a definite failure), or
// ExecutionUnknown (BACKLOG.md C8/BUGS.md 104 — a mutating call whose own
// result was indeterminate and a follow-up verify could not confidently
// resolve either way).
func TestExecutingCannotBeReanalysed(t *testing.T) {
	if CanTransition(StateExecuting, StateInvestigating) {
		t.Error("an Executing incident must not be re-analysable: a plan is in flight over the tunnel, and a second plan approved against the same workload is exactly what lld/08 §6's per-target lock exists to prevent")
	}
	if CanTransition(StateExecuting, StateAwaitingApproval) {
		t.Error("an Executing incident must not fall back to AwaitingApproval: that is precisely the state the approve-and-execute path checks for before signing and dispatching a second plan")
	}

	wantOnly := map[string]bool{StateValidating: true, StateFailed: true, StateExecutionUnknown: true}
	for _, to := range allKnownStates {
		got := CanTransition(StateExecuting, to)
		if got != wantOnly[to] {
			t.Errorf("CanTransition(Executing, %q) = %v, want %v — Executing advances only to Validating, Failed, or ExecutionUnknown (recordExecutionOutcome)", to, got, wantOnly[to])
		}
	}
}

// TestReanalysisReachableFromEveryOpenState pins the OTHER half of the fix:
// the transition table must not have over-corrected. MarkInvestigating is
// invoked by internal/api/analyze.go and internal/autoanalyze on an incident
// in whatever state it happens to be in, and re-analysis is a real,
// already-exposed capability (incident:reanalyse). Every state that isn't
// terminal and isn't Executing must still accept it — a guard that only
// allowed Detected -> Investigating would break re-analysis of a stale
// RecommendationReady, a NeedsHumanInvestigation, a pending AwaitingMerge whose
// pull request turned out wrong, a Failed execution or a Reopened symptom, all of
// which are legitimate today.
func TestReanalysisReachableFromEveryOpenState(t *testing.T) {
	// StateExpired joins the blocked set deliberately: it is closed, like
	// Dismissed/Resolved, and the ordinary reanalyse capability must not
	// reopen a closed incident. The ONLY path back from Expired is a real
	// recurrence (a Finding re-attaching via handleFinding, which calls
	// SetState directly to Detected — see StateExpired's own doc comment),
	// not a human clicking reanalyse on an incident nobody is looking at.
	blocked := map[string]bool{StateExecuting: true, StateDismissed: true, StateResolved: true, StateExpired: true}
	for _, from := range allKnownStates {
		want := !blocked[from]
		if got := CanTransition(from, StateInvestigating); got != want {
			t.Errorf("CanTransition(%q, Investigating) = %v, want %v", from, got, want)
		}
	}
}

// TestEveryTransitionThisCodebaseMakesIsLegal enumerates every state write
// any caller in the repository actually performs, with its call site, and
// asserts the table permits it. This is the test that catches an
// over-restrictive table breaking a live code path — the failure mode the
// fix had to avoid — rather than the under-restrictive one the other tests
// cover.
func TestEveryTransitionThisCodebaseMakesIsLegal(t *testing.T) {
	cases := []struct {
		from, to, caller string
	}{
		{StateDetected, StateInvestigating, "internal/api/analyze.go handleAnalyzeIncident, internal/autoanalyze investigateOne (MarkInvestigating)"},
		{StateInvestigating, StateInvestigating, "two concurrent analyze requests on one incident, second MarkInvestigating"},
		// AutoApprove is deliberately absent as a destination of its own: it
		// routes to AwaitingApproval, exactly like NeedsApproval. The old
		// Investigating -> RecommendationReady row asserted the bug this
		// codebase fixed, and it kept the dead edge alive.
		{StateInvestigating, StateNeedsHumanInvestigation, "ApplyAnalysisResult, partial/no-plan/Blocked"},
		{StateInvestigating, StateAwaitingApproval, "ApplyAnalysisResult, gate outcome NeedsApproval or AutoApprove"},
		{StateAwaitingApproval, StateAwaitingMerge, "handleOpenRepositoryChange, once the pull request is open"},
		{StateDetected, StateAwaitingMerge, "handleOpenRepositoryChange on an un-analysed incident — GITOPS_TEST_PLAN Phase 10 found the PR opening while the incident stayed Detected"},
		{StateNeedsHumanInvestigation, StateAwaitingMerge, "handleOpenRepositoryChange after a person worked out what the model could not"},
		{StateFailed, StateAwaitingMerge, "handleOpenRepositoryChange after an in-place execution failed and the source is the remaining option"},
		{StateReopened, StateAwaitingMerge, "handleOpenRepositoryChange after an in-place fix did not hold"},
		{StateRecommendationReady, StateInvestigating, "re-analyze a stale recommendation"},
		{StateNeedsHumanInvestigation, StateInvestigating, "re-analyze after a bound-hit investigation"},
		{StateAwaitingApproval, StateInvestigating, "re-analyze a pending plan (produces the newer plan approvals.go's LATERAL join already anticipates)"},
		{StateAwaitingApproval, StateExecuting, "internal/execution recordExecutingTransition"},
		{StateAwaitingApproval, StateDismissed, "internal/api/approvals.go handleRejectIncident"},
		{StateExecuting, StateValidating, "internal/execution recordExecutionOutcome, outcome succeeded"},
		{StateExecuting, StateFailed, "internal/execution recordExecutionOutcome, outcome failed"},
		{StateValidating, StateResolved, "orchestrator/validation.go ValidationSweeper"},
		{StateValidating, StateReopened, "internal/gateway/finding.go handleFinding, symptom recurred"},
		{StateValidating, StateInvestigating, "re-analyze a fix an operator doesn't believe held"},
		{StateFailed, StateInvestigating, "re-analyze after a failed execution"},
		{StateReopened, StateInvestigating, "re-analyze a recurrence"},
	}
	for _, c := range cases {
		if !CanTransition(c.from, c.to) {
			t.Errorf("CanTransition(%q, %q) = false, want true — this transition is performed live by %s", c.from, c.to, c.caller)
		}
	}
}

// TestUnknownStatesCannotTransition covers the fail-closed property: a state
// the table has no entry for — a corrupted value, a wrong case, an empty
// string — can go nowhere at all, rather than defaulting to permissive.
//
// AwaitingMerge used to be the headline example here, being permitted by
// incidents.state's CHECK constraint while having no Go constant. It is now a
// real state with real edges, so it moved to the transition tests above; the
// wrong-case "awaitingMerge" takes its place, since a case slip is the realistic
// way a legal-looking value reaches this function.
func TestUnknownStatesCannotTransition(t *testing.T) {
	for _, from := range []string{"awaitingMerge", "", "dismissed", "Bogus"} {
		for _, to := range allKnownStates {
			if CanTransition(from, to) {
				t.Errorf("CanTransition(%q, %q) = true, want false — an unrecognized state must fail closed", from, to)
			}
		}
		if !IsTerminalState(from) {
			t.Errorf("IsTerminalState(%q) = false, want true — a state with no edges is terminal by definition", from)
		}
	}
}

// TestAllowedTransitionsOnlyNamesRealStates guards against a typo in the
// table itself: every key and every destination must be one of this
// package's own state constants, which in turn mirror incidents.state's
// CHECK constraint. A misspelled destination would otherwise sit there
// permitting a transition to a value the database would reject at UPDATE
// time — a much more confusing failure than a rejected transition.
func TestAllowedTransitionsOnlyNamesRealStates(t *testing.T) {
	known := map[string]bool{}
	for _, s := range allKnownStates {
		known[s] = true
	}
	for from, tos := range allowedTransitions {
		if !known[from] {
			t.Errorf("allowedTransitions has an entry for %q, which is not one of this package's state constants", from)
		}
		for _, to := range tos {
			if !known[to] {
				t.Errorf("allowedTransitions[%q] permits a transition to %q, which is not one of this package's state constants", from, to)
			}
		}
	}
	// Every state constant must appear as a key, so "terminal on purpose"
	// is always an explicit empty edge set rather than an accidental
	// omission.
	for _, s := range allKnownStates {
		if _, ok := allowedTransitions[s]; !ok {
			t.Errorf("allowedTransitions has no entry for state %q — add its edges, or an explicit empty set if it is terminal", s)
		}
	}
}

// TestHumanTriageTransitions covers the close-out edges added when it became
// clear an operator had no way to close an incident at all: the only exits
// from the open set ran through the remediation path, so a problem fixed by
// hand left its incident open forever (WORKLOG §88).
func TestHumanTriageTransitions(t *testing.T) {
	// Every state a human can reasonably close from must reach BOTH terminal
	// verdicts — "I fixed it" and "this needs no action" are both ordinary.
	closable := []string{
		StateDetected,
		StateRecommendationReady,
		StateNeedsHumanInvestigation,
		StateAwaitingApproval,
		StateFailed,
		StateExecutionUnknown,
		StateReopened,
		StateValidating,
	}
	for _, from := range closable {
		for _, to := range []string{StateResolved, StateDismissed} {
			if !CanTransition(from, to) {
				t.Errorf("CanTransition(%q, %q) = false; an operator must be able to close an incident from %q", from, to, from)
			}
		}
	}

	// Investigating is deliberately excluded: the running investigation writes
	// its own outcome transition, and letting a human close the incident
	// underneath it would make that write fail on a state that moved
	// mid-analysis.
	for _, to := range []string{StateResolved, StateDismissed} {
		if CanTransition(StateInvestigating, to) {
			t.Errorf("CanTransition(Investigating, %q) = true; closing mid-investigation must stay disallowed", to)
		}
	}

	// Both verdicts stay terminal — nothing reopens a closed incident.
	for _, from := range []string{StateResolved, StateDismissed} {
		for _, to := range []string{StateInvestigating, StateDetected, StateResolved, StateDismissed, StateReopened} {
			if CanTransition(from, to) {
				t.Errorf("CanTransition(%q, %q) = true; closed incidents must be terminal", from, to)
			}
		}
	}
}

// The reason AwaitingMerge exists at all: an incident whose fix is a pending
// pull request must be structurally unable to reach Executing.
//
// Before this state, such an incident stayed in AwaitingApproval and was kept
// out of the in-place channel by remediation_recommendations.superseded_at — a
// nullable column on another table, which the approve handler checked and the
// unattended sweeper's candidate query did not. The sweeper would have executed
// a plan the approve handler refuses, with no human present, and on the live run
// that produced this test that plan would have set a working image back to a
// broken tag. This asserts the property is now carried by the state machine
// rather than by every query author remembering a join.
func TestAwaitingMergeCanNeverReachExecuting(t *testing.T) {
	if CanTransition(StateAwaitingMerge, StateExecuting) {
		t.Fatal("AwaitingMerge -> Executing is allowed. The whole point of this state is that an incident whose fix is a pending pull request cannot be executed in place — a plan derived from the cluster as it was before the fix can mean the OPPOSITE once the fix lands")
	}
	// And the transition in has to work, or nothing ever reaches the state.
	if !CanTransition(StateAwaitingApproval, StateAwaitingMerge) {
		t.Error("AwaitingApproval -> AwaitingMerge is refused, so opening a pull request could never move the incident out of the approval queue")
	}
	// Not terminal: a person must be able to close it, and a re-analysis must be
	// able to reclaim it. A terminal state here would strand every PR-fixed
	// incident permanently.
	if IsTerminalState(StateAwaitingMerge) {
		t.Error("AwaitingMerge is terminal — every incident fixed by a pull request would be stranded with no way to close it")
	}
	for _, to := range []string{StateResolved, StateDismissed, StateInvestigating, StateAwaitingApproval} {
		if !CanTransition(StateAwaitingMerge, to) {
			t.Errorf("AwaitingMerge -> %s is refused; a pending pull request must still be closable, dismissable, re-analysable, and returnable to the queue if the PR is closed unmerged", to)
		}
	}
}

// TestAwaitingMergeCanReachValidating asserts the edge MergeSweeper
// (mergewatch.go) needs: once a pull request has merged and the GitOps
// controller has synced past it, the incident must be able to advance to
// Validating, where ValidationSweeper's existing Resolved/Reopened
// machinery takes over. This used to be refused on purpose — see
// StateAwaitingMerge's own doc comment for why "Validating" specifically
// was the wrong state to enter on recurrence WHILE still AwaitingMerge — but
// that reasoning is about entering it on recurrence, not about ever
// reaching it at all once the fix has actually landed.
func TestAwaitingMergeCanReachValidating(t *testing.T) {
	if !CanTransition(StateAwaitingMerge, StateValidating) {
		t.Fatal("AwaitingMerge -> Validating is refused, so a merged and synced pull request could never hand off to the same recurrence check an in-place fix gets")
	}
	// Still refused the other way: entering AwaitingMerge from Validating
	// would mean proposing a pull request while something is mid-watch,
	// which TestAwaitingMergeIsUnreachableFromStatesAnotherWriterOwns already
	// covers — asserted again here as the property this test is the mirror
	// of, so the two are read together.
	if CanTransition(StateValidating, StateAwaitingMerge) {
		t.Error("Validating -> AwaitingMerge is allowed — a repository change proposed while a fix is being watched would abandon that watch silently")
	}
}

// AwaitingMerge is an OPEN state. Getting this wrong in the other direction
// would be quiet and bad: correlation matches against open incidents, so if
// AwaitingMerge counted as closed, a recurrence of the same symptom would open a
// SECOND incident instead of re-attaching, and the fleet group would shrink as
// though the problem had gone away while a pull request was still pending.
func TestAwaitingMergeIsAnOpenState(t *testing.T) {
	if fleetgroup.IsClosedState(StateAwaitingMerge) {
		t.Fatal("AwaitingMerge counts as closed — a recurrence would open a duplicate incident rather than re-attaching, and fleet correlation would treat the problem as gone while the fix is still unmerged")
	}
}

// RecommendationReady must stay unreachable. It is the fossil of a real bug: an
// AutoApprove verdict used to land here, and this state has no edge to Executing
// or AwaitingApproval, so the safest class of plan became the only class nobody
// could act on. Advance was fixed; this asserts the state machine cannot walk
// back into it, which is stronger than trusting Advance never to return it.
func TestRecommendationReadyIsUnreachable(t *testing.T) {
	for _, from := range allKnownStates {
		if CanTransition(from, StateRecommendationReady) {
			t.Errorf("CanTransition(%q, RecommendationReady) = true — nothing may enter this state. It has no path to approval or execution, so an incident landing here is stranded with its plan unactionable", from)
		}
	}
	// Still has exits, so a row written before the fix is not stranded forever.
	if IsTerminalState(StateRecommendationReady) {
		t.Error("RecommendationReady is terminal — any historical incident sitting in it could never be closed")
	}
}

// The three states that must NOT reach AwaitingMerge, each for its own reason.
// Asserted because the permissive direction is the easy mistake: a repository
// change is a reasonable thing to propose from most states, so "just allow it
// everywhere" is tempting and would clobber a state another writer owns.
func TestAwaitingMergeIsUnreachableFromStatesAnotherWriterOwns(t *testing.T) {
	for _, tc := range []struct{ from, why string }{
		{StateInvestigating, "an analysis is in flight and writes its own outcome transition when it finishes; moving the incident underneath it would make that write fail on a state that changed mid-analysis"},
		{StateExecuting, "a mutation is in flight against the cluster and its outcome transition owns the state"},
		{StateValidating, "something is being watched, and the validation sweeper's recurrence check is better informed than a state change made while it runs"},
	} {
		if CanTransition(tc.from, StateAwaitingMerge) {
			t.Errorf("CanTransition(%s, AwaitingMerge) = true, want false — %s", tc.from, tc.why)
		}
	}
}
