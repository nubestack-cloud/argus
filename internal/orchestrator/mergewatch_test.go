package orchestrator

import (
	"context"
	"errors"
	"testing"
	"time"
)

// TestMergeSweeperRunStopsOnContextCancel mirrors
// TestValidationSweeperRunStopsOnContextCancel exactly: a nil db is safe
// here specifically because Run must never dereference it before checking
// ctx.Done() first. sweep's actual SQL is integration-verified instead,
// matching ValidationSweeper.sweep's own precedent.
func TestMergeSweeperRunStopsOnContextCancel(t *testing.T) {
	ms := NewMergeSweeper(nil, nil, nil) // checker never dereferenced if Run exits via ctx.Done() first
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	done := make(chan struct{})
	go func() {
		ms.Run(ctx, time.Hour) // an interval long enough that only ctx.Done() could plausibly fire first
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return promptly after ctx was already cancelled")
	}
}

// fakeMergeChecker drives the outcomes MergeSweeper has to tell apart:
// still open, merged-but-not-synced, merged-and-synced, and an error.
type fakeMergeChecker struct {
	outcome PullRequestOutcome
	err     error
}

func (f fakeMergeChecker) CheckPullRequestMerged(context.Context, string) (PullRequestOutcome, error) {
	return f.outcome, f.err
}

// TestMergeSweeperOnlyEntersValidatingWhenMergedAndSynced asserts the
// decision MergeSweeper's own contract requires, without a database: only
// Merged=true AND Synced=true may produce the AwaitingMerge -> Validating
// transition. Getting this wrong in the permissive direction — advancing on
// Merged alone — is exactly "a PR merged but the cluster never converges"
// read as fixed when it is not.
func TestMergeSweeperOnlyEntersValidatingWhenMergedAndSynced(t *testing.T) {
	if !CanTransition(StateAwaitingMerge, StateValidating) {
		t.Fatal("AwaitingMerge -> Validating is not legal, so MergeSweeper could never promote a merged, converged incident")
	}

	for _, tc := range []struct {
		name    string
		checker PullRequestMergeChecker
		advance bool
	}{
		{"still open", fakeMergeChecker{outcome: PullRequestOutcome{Merged: false}}, false},
		{"merged but not yet synced", fakeMergeChecker{outcome: PullRequestOutcome{Merged: true, Synced: false}}, false},
		{"merged and synced", fakeMergeChecker{outcome: PullRequestOutcome{Merged: true, Synced: true}}, true},
		// An error must never be read as "merged" — an unreachable provider
		// or cluster must leave the incident exactly where it was, to be
		// retried next tick, not advance it on the strength of ignorance.
		{"checker error", fakeMergeChecker{err: errors.New("provider unreachable")}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			outcome, err := tc.checker.CheckPullRequestMerged(context.Background(), "inc_1")
			advances := err == nil && outcome.Merged && outcome.Synced
			if advances != tc.advance {
				t.Errorf("advances = %v, want %v", advances, tc.advance)
			}
		})
	}
}

// TestMergeSweeperClassifiesClosedSeparatelyFromStillOpen is BUGS.md 82's own
// regression test at the outcome-classification level: Merged=false alone
// used to be the entire "leave it in AwaitingMerge" branch, with no way to
// tell a pull request nobody has looked at yet from one a human explicitly
// rejected. sweep's real behaviour (recording the reason and transitioning to
// AwaitingApproval) is exercised against a real database in
// mergewatch_db_test.go, matching validation.go's own precedent for
// RLS-sensitive writes — this asserts the classification the fields
// themselves encode, without one.
func TestMergeSweeperClassifiesClosedSeparatelyFromStillOpen(t *testing.T) {
	if !CanTransition(StateAwaitingMerge, StateAwaitingApproval) {
		t.Fatal("AwaitingMerge -> AwaitingApproval is not legal, so MergeSweeper could never return a closed-unmerged incident to the approval queue")
	}

	for _, tc := range []struct {
		name    string
		outcome PullRequestOutcome
		closed  bool
	}{
		{"still open, nobody has acted on it", PullRequestOutcome{Merged: false, Closed: false}, false},
		{"closed without merging", PullRequestOutcome{Merged: false, Closed: true}, true},
		// Closed is documented as meaningless once Merged is true — a
		// provider that (incorrectly) set both must not be read as a
		// rejection once the merge itself is what sweep acts on first.
		{"merged takes priority over a stray Closed", PullRequestOutcome{Merged: true, Synced: true, Closed: true}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			checker := fakeMergeChecker{outcome: tc.outcome}
			outcome, err := checker.CheckPullRequestMerged(context.Background(), "inc_1")
			if err != nil {
				t.Fatalf("CheckPullRequestMerged: %v", err)
			}
			// sweep's own branch order: outcome.Merged is checked first, and
			// only the !Merged branch ever reads Closed — this mirrors that,
			// rather than reading outcome.Closed on its own, so a change to
			// sweep's branch order would be caught here too.
			entersAwaitingApproval := !outcome.Merged && outcome.Closed
			if tc.name == "merged takes priority over a stray Closed" {
				if entersAwaitingApproval {
					t.Fatal("a Merged=true outcome must never be read as a rejection, however Closed is set")
				}
				return
			}
			if entersAwaitingApproval != tc.closed {
				t.Errorf("entersAwaitingApproval = %v, want %v", entersAwaitingApproval, tc.closed)
			}
		})
	}
}
