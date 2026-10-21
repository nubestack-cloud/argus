package orchestrator

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// The bug these cover, in one sentence: ValidationSweeper started every
// candidate at targetState = Resolved and, when the assertion could not be
// MADE, changed only the sentence attached to it before committing Resolved
// anyway.
//
// So a cluster that was merely unreachable produced the product's strongest
// claim — "we verified this fix worked" — from its weakest possible input, and
// the resulting row is afterwards indistinguishable from a genuinely verified
// one. These assert the rule that replaces it: **Resolved requires a positive
// assertion.**
//
// Pure, because the judgement is now pure (decideValidationOutcome). The
// end-to-end version, which is what actually fails against the old code, is in
// validation_inconclusive_db_test.go.

var errUnreachable = errors.New("cluster cl_x is not connected")

func baseEvidence() validationEvidence {
	return validationEvidence{
		route:           "inPlace",
		grace:           validationGracePeriod,
		sinceFixLanded:  validationGracePeriod + time.Minute,
		verifierPresent: true,
	}
}

// TestUnmadeAssertionNeverResolves is the headline regression guard. Every
// shape of "we could not tell" must leave Validating alone, never Resolved.
func TestUnmadeAssertionNeverResolves(t *testing.T) {
	cases := []struct {
		name string
		mut  func(*validationEvidence)
		why  string
	}{
		{
			name: "field re-read failed and this incident has no rule to re-run",
			mut: func(e *validationEvidence) {
				e.appliedErr = errUnreachable
			},
			why: "the exact live shape: an unreachable cluster, an incident opened by a hand-written checker, and nothing whatsoever was asserted",
		},
		{
			name: "field re-read failed and the rule re-run failed too",
			mut: func(e *validationEvidence) {
				e.appliedErr = errUnreachable
				e.ruleEvaluated, e.ruleErr = true, errors.New("tunnel closed")
			},
			why: "two failed assertions are not one successful one",
		},
		{
			name: "action type has no modelled field to re-read",
			mut: func(e *validationEvidence) {
				e.appliedErr = errors.New("execution exec_1 recorded no single applied value to re-check")
			},
			why: "a permanent gap in what ARGUS can assert is still a gap; it is not evidence the fix worked",
		},
		{
			name: "merged pull request could not be re-read",
			mut: func(e *validationEvidence) {
				e.route = "pullRequest"
				e.appliedErr = errUnreachable
			},
			why: "the PR route has no second source of evidence at all, so an unmade assertion there is the whole answer",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := baseEvidence()
			tc.mut(&e)
			got := decideValidationOutcome(e)
			if got.TargetState == StateResolved {
				t.Fatalf("resolved on an assertion that was never made — %s\nevidence recorded: %s", tc.why, got.Evidence)
			}
			if got.TargetState != "" {
				t.Fatalf("TargetState = %q, want \"\" (stay in Validating and retry) while inside the retry window", got.TargetState)
			}
			if got.TargetState == StateReopened {
				t.Fatal("reopened on an error — manufacturing a recurrence out of an unreachable cluster is the mirror of the bug, not a fix for it")
			}
		})
	}
}

// TestUnmadeAssertionIsBoundedThenExplicit: retrying forever would be its own
// kind of silence, so the wait is bounded and its destination is a state that
// says what happened.
func TestUnmadeAssertionIsBoundedThenExplicit(t *testing.T) {
	e := baseEvidence()
	e.appliedErr = errUnreachable

	// Just inside the window: still trying.
	e.sinceFixLanded = e.grace + validationAssertionDeadline - time.Second
	if got := decideValidationOutcome(e); got.TargetState != "" {
		t.Errorf("TargetState = %q one second before the deadline, want \"\" (keep retrying)", got.TargetState)
	}

	// Past it: an explicit outcome, not a quiet resolve and not an endless wait.
	e.sinceFixLanded = e.grace + validationAssertionDeadline + time.Second
	got := decideValidationOutcome(e)
	if got.TargetState != StateValidationUnknown {
		t.Fatalf("TargetState = %q past the deadline, want %q", got.TargetState, StateValidationUnknown)
	}
	if !strings.Contains(got.Evidence, "cannot tell") {
		t.Errorf("the recorded evidence must say plainly that ARGUS could not tell, got: %s", got.Evidence)
	}
	if !CanTransition(StateValidating, StateValidationUnknown) {
		t.Error("Validating -> ValidationUnknown is not a legal transition, so the sweeper could never actually take this decision")
	}
}

// TestPositiveAssertionsStillResolve: the fix must not turn every validation
// into "we could not tell". Either assertion, on its own, is enough — see
// decideValidationOutcome's doc comment for why requiring both would trade one
// untruth for another.
func TestPositiveAssertionsStillResolve(t *testing.T) {
	cases := []struct {
		name     string
		mut      func(*validationEvidence)
		wantSays string
	}{
		{
			name:     "the applied change is still on the object",
			mut:      func(e *validationEvidence) { e.appliedHeld, e.appliedDetail = true, "replicas is still \"3\"" },
			wantSays: "the change still holds",
		},
		{
			name: "the original condition was re-checked and no longer holds",
			mut: func(e *validationEvidence) {
				e.appliedHeld = true
				e.ruleEvaluated, e.ruleDetail = true, "no container is OOMKilled"
			},
			// The stronger claim leads when both are available — the field
			// assertion can pass while the symptom persists, so it must not be
			// the sentence an operator reads when something better exists.
			wantSays: "confirmed it no longer holds",
		},
		{
			name: "the rule confirms the symptom is gone even though the field could not be re-read",
			mut: func(e *validationEvidence) {
				e.appliedErr = errors.New("execution exec_1 recorded no single applied value to re-check")
				e.ruleEvaluated, e.ruleDetail = true, "no container is OOMKilled"
			},
			wantSays: "confirmed it no longer holds",
		},
		{
			name: "the field holds even though the rule could not be re-run",
			mut: func(e *validationEvidence) {
				e.appliedHeld, e.appliedDetail = true, "replicas is still \"3\""
				e.ruleEvaluated, e.ruleErr = true, errors.New("tunnel closed")
			},
			wantSays: "the change still holds",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := baseEvidence()
			tc.mut(&e)
			got := decideValidationOutcome(e)
			if got.TargetState != StateResolved {
				t.Fatalf("TargetState = %q, want %q — a positive assertion was made and must still close the incident\nevidence: %s", got.TargetState, StateResolved, got.Evidence)
			}
			if !strings.Contains(got.Evidence, tc.wantSays) {
				t.Errorf("evidence should say %q, got: %s", tc.wantSays, got.Evidence)
			}
		})
	}
}

// TestPartialEvidenceIsRecordedNotHidden: when one assertion succeeded and the
// other could not be made, the incident resolves — but the record has to say
// how much was actually checked, or the honest claim becomes indistinguishable
// from the complete one.
func TestPartialEvidenceIsRecordedNotHidden(t *testing.T) {
	e := baseEvidence()
	e.appliedHeld, e.appliedDetail = true, "replicas is still \"3\""
	e.ruleEvaluated, e.ruleErr = true, errors.New("tunnel closed")
	got := decideValidationOutcome(e)
	if !strings.Contains(got.Evidence, "could not be re-run") {
		t.Errorf("a failed rule re-check must appear in the evidence even when the incident resolves, got: %s", got.Evidence)
	}

	e = baseEvidence()
	e.appliedErr = errors.New("execution exec_1 recorded no single applied value to re-check")
	e.ruleEvaluated, e.ruleDetail = true, "no container is OOMKilled"
	got = decideValidationOutcome(e)
	if !strings.Contains(got.Evidence, "could not itself be re-read") {
		t.Errorf("a failed field re-read must appear in the evidence even when the rule re-check resolves it, got: %s", got.Evidence)
	}
}

// TestDecisiveNegativesAreUnchanged: this fix must not weaken any of the three
// existing paths to Reopened. Each is real evidence the fix did not work, and
// each still outranks everything else.
func TestDecisiveNegativesAreUnchanged(t *testing.T) {
	cases := []struct {
		name string
		mut  func(*validationEvidence)
	}{
		{"a sibling on the same workload is still failing", func(e *validationEvidence) {
			e.siblingFailing, e.siblingDetail = true, "incident inc_2 (OOMKilled) on the same workload"
		}},
		{"the applied change was reverted", func(e *validationEvidence) {
			e.appliedDetail = "ARGUS set it to \"3\" and it is now \"1\""
		}},
		{"the original condition still fires", func(e *validationEvidence) {
			e.appliedHeld = true
			e.ruleEvaluated, e.ruleFires, e.ruleDetail = true, true, "container app is OOMKilled"
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := baseEvidence()
			tc.mut(&e)
			if got := decideValidationOutcome(e); got.TargetState != StateReopened {
				t.Errorf("TargetState = %q, want %q — this is real evidence the fix did not work", got.TargetState, StateReopened)
			}
		})
	}

	// And a sibling failure stays decisive even when nothing else could be
	// asserted: it is a local query, so an unreachable cluster does not
	// invalidate it.
	e := baseEvidence()
	e.siblingFailing, e.siblingDetail = true, "incident inc_2 on the same workload"
	e.appliedErr = errUnreachable
	if got := decideValidationOutcome(e); got.TargetState != StateReopened {
		t.Errorf("TargetState = %q, want %q — siblingStillFailing does not depend on the cluster being reachable", got.TargetState, StateReopened)
	}
}

// TestNilVerifierEscapeHatchIsPreserved: NewValidationSweeper documents nil as
// the pre-V1 behaviour for a hub with no tunnel. Changing it here would strand
// every incident on such a hub, which is a different failure, not a fix — so
// this fix deliberately leaves it alone, and this test says so out loud.
func TestNilVerifierEscapeHatchIsPreserved(t *testing.T) {
	e := baseEvidence()
	e.verifierPresent = false
	got := decideValidationOutcome(e)
	if got.TargetState != StateResolved {
		t.Fatalf("TargetState = %q, want %q — a hub with no verifier wired must behave exactly as it did before BACKLOG.md V1", got.TargetState, StateResolved)
	}
	if !strings.Contains(got.Evidence, "no recurrence") {
		t.Errorf("the nil-verifier close must still say it rests on absence of recurrence, got: %s", got.Evidence)
	}
}

// TestValidationUnknownAsksForAttention: an inconclusive outcome that nobody is
// told about is the same silence in a new state name.
func TestValidationUnknownAsksForAttention(t *testing.T) {
	if !notifiableStates[StateValidationUnknown] {
		t.Error("ValidationUnknown is not in notifiableStates — an incident that quietly stopped being validated is exactly what an operator never goes looking for")
	}
	if IsTerminalState(StateValidationUnknown) {
		t.Error("ValidationUnknown must not be terminal: a human has to be able to re-investigate, route to a pull request, or close it out")
	}
	for _, exit := range []string{StateInvestigating, StateAwaitingMerge, StateResolved, StateDismissed} {
		if !CanTransition(StateValidationUnknown, exit) {
			t.Errorf("CanTransition(%q, %q) = false — its exits must mirror ExecutionUnknown's", StateValidationUnknown, exit)
		}
	}
}
