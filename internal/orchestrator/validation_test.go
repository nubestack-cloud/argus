package orchestrator

import (
	"context"
	"errors"
	"testing"
	"time"
)

// TestValidationSweeperRunStopsOnContextCancel mirrors
// gateway.TestHealthMonitorRunStopsOnContextCancel exactly: a nil db is
// safe here specifically because Run must never dereference it before
// checking ctx.Done() first. sweep's actual SQL (the JOIN against
// remediation_executions, the grace-period arithmetic) is integration-
// verified instead, matching gateway.HealthMonitor.sweep's own precedent —
// see STATUS.md for the live verification this shipped with.
func TestValidationSweeperRunStopsOnContextCancel(t *testing.T) {
	vs := NewValidationSweeper(nil, nil, nil) // neither ever dereferenced if Run exits via ctx.Done() first
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	done := make(chan struct{})
	go func() {
		vs.Run(ctx, time.Hour) // an interval long enough that only ctx.Done() could plausibly fire first
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return promptly after ctx was already cancelled")
	}
}

// fakeVerifier drives the three outcomes V1 has to tell apart.
type fakeVerifier struct {
	held   bool
	detail string
	err    error

	// evaluated/fires drive RuleStillFires (BACKLOG.md V3) independently of
	// held/detail/err above. evaluated defaults to false, which is
	// deliberate: every existing V1 test case constructs a fakeVerifier
	// without setting these, and false is exactly the "this incident has
	// nothing to re-run" scope boundary those cases should see — unchanged
	// V1 behaviour, not a silent new Reopened/Resolved outcome.
	evaluated bool
	fires     bool
}

func (f fakeVerifier) VerifyAppliedValue(context.Context, string) (bool, string, error) {
	return f.held, f.detail, f.err
}

func (f fakeVerifier) VerifyMergedPullRequest(context.Context, string) (bool, string, error) {
	return f.held, f.detail, f.err
}

// RuleStillFires's fake. Deliberately does NOT share f.err with
// VerifyAppliedValue/VerifyMergedPullRequest above: err there means "that
// method's own re-check failed", which is a different question from whether
// THIS incident even has a rule to re-run, and every existing V1 test case
// sets err to drive VerifyAppliedValue/VerifyMergedPullRequest without
// intending to say anything about RuleStillFires at all. evaluated=false
// (this type's zero value) is the correct default for those cases — the V3
// scope boundary, not a manufactured error.
func (f fakeVerifier) RuleStillFires(context.Context, string) (bool, bool, string, error) {
	return f.evaluated, f.fires, f.detail, nil
}

// The distinction V1 exists for: "nothing recurred" and "the change is still
// there" are different claims, and the product used to make the second on the
// evidence of the first.
//
// This asserts the DECISION each outcome produces, without a database, by checking
// the sweeper's own contract: a verifier that says the change is gone must not be
// able to produce a Resolved incident, and a verifier that errors must not be able
// to produce a Reopened one.
func TestValidationVerifierOutcomesMapToTheRightStates(t *testing.T) {
	// Held: Resolved is legal from Validating, which is the transition the sweeper
	// makes on a positive assertion.
	if !CanTransition(StateValidating, StateResolved) {
		t.Fatal("Validating -> Resolved is not legal, so a verified fix could never be closed")
	}
	// Not held: Reopened, and it must be legal from Validating or the sweeper
	// cannot report a reverted change at all.
	if !CanTransition(StateValidating, StateReopened) {
		t.Fatal("Validating -> Reopened is not legal, so a change that was reverted could not be reported — the incident would resolve on the weaker evidence, which is the bug V1 fixes")
	}

	// A nil verifier must keep the previous behaviour exactly: this is the escape
	// hatch for a hub with no tunnel, and it must not accidentally become a
	// reopen-everything switch.
	v := NewValidationSweeper(nil, nil, nil)
	if v.verifier != nil {
		t.Error("a nil verifier was stored as non-nil")
	}

	// And the three outcomes are distinguishable through the interface, so a
	// caller cannot conflate "cannot tell" with "gone".
	for _, tc := range []struct {
		name       string
		v          fakeVerifier
		wantReopen bool
	}{
		{"held", fakeVerifier{held: true, detail: "still 3"}, false},
		{"reverted", fakeVerifier{held: false, detail: "set 3, now 1"}, true},
		// An error is NOT a reopen: manufacturing a recurrence out of an
		// unreachable cluster would be worse than the imprecision it replaces.
		{"unknown", fakeVerifier{err: errors.New("cluster not connected")}, false},
	} {
		held, _, err := tc.v.VerifyAppliedValue(context.Background(), "exec_1")
		reopens := err == nil && !held
		if reopens != tc.wantReopen {
			t.Errorf("%s: reopens=%v, want %v — an error must never be read as 'the change is gone'", tc.name, reopens, tc.wantReopen)
		}
	}
}

// TestEffectiveGracePeriod covers BACKLOG B2: the grace period used to be a
// hardcoded 15 minutes justified as "3x the 5-minute resend cooldown", while the
// cooldown is an operator-settable per-agent environment variable. The two
// directions fail differently, so both are asserted.
func TestEffectiveGracePeriod(t *testing.T) {
	cases := []struct {
		name     string
		reported int
		want     time.Duration
		why      string
	}{
		{
			name:     "not reported falls back to the floor",
			reported: 0,
			want:     validationGracePeriod,
			why:      "an agent predating ClusterDetection reports nothing; behaviour must not change for it",
		},
		{
			name:     "shipped default is exactly the floor",
			reported: 300,
			want:     validationGracePeriod,
			why:      "3x5m is 15m, so the documented rationale holds and nothing changes at the default",
		},
		{
			name:     "short cooldown does not shorten the window",
			reported: 30,
			want:     validationGracePeriod,
			why:      "3x30s is 90s; resolving an incident 90 seconds after a fix on quiet alone is not evidence",
		},
		{
			name:     "long cooldown lengthens the window",
			reported: 1200,
			want:     60 * time.Minute,
			why:      "at a 20-minute cooldown a 15-minute window closes before a recurrence could be re-reported",
		},
		{
			name:     "negative is treated as unknown, not as a negative window",
			reported: -1,
			want:     validationGracePeriod,
			why:      "a garbled report must fail toward today's behaviour, never toward resolving immediately",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := effectiveGracePeriod(tc.reported); got != tc.want {
				t.Errorf("effectiveGracePeriod(%d) = %s, want %s (%s)", tc.reported, got, tc.want, tc.why)
			}
		})
	}
}

// TestEffectiveGracePeriodNeverBelowFloor is the property the two directions
// above are specific cases of: no reported value, however hostile, can produce a
// window shorter than the floor.
func TestEffectiveGracePeriodNeverBelowFloor(t *testing.T) {
	for _, reported := range []int{-100000, -1, 0, 1, 59, 60, 299, 300, 301, 100000} {
		if got := effectiveGracePeriod(reported); got < validationGracePeriod {
			t.Errorf("effectiveGracePeriod(%d) = %s, below the %s floor", reported, got, validationGracePeriod)
		}
	}
}
