package autoanalyze

import (
	"context"
	"testing"
	"time"

	"argus/internal/llm"
	"argus/internal/settings"
)

// This file proves BACKLOG.md C11's second half for the unattended
// (autoanalyze) backend: boundedInvestigationContext (autoanalyze.go) is
// the fix for a real gap found while implementing C11 — investigateOne
// used to hand every CallToolWithRetry call the poller's own long-lived,
// no-deadline ctx, so a hung tool call could always spend its FULL
// toolCallTimeout+resultGraceWindow, and a retry its full budget again,
// no matter how much of THIS investigation's own configured time limit was
// already gone. internal/api/analyze.go's manual/api-backend path already
// closed this gap (its workCtx); these tests are the unattended path's
// equivalent proof, at the level of the pure function that computes the
// deadline rather than a full DB-backed investigation.

// ptrSeconds builds the *int settings.Config.AnalysisTimeLimitSeconds wants.
// (This comment used to point at a `deref` helper in autoanalyze.go as the
// string-pointer equivalent; that function had no callers in this package —
// production or test — and was removed.)
func ptrSeconds(n int) *int { return &n }

// TestBoundedInvestigationContext_ShrinksWithConfiguredTimeLimit proves the
// core C11 claim: a SHORT operator-configured analysis time limit produces
// a ctx whose absolute deadline is correspondingly SHORT — not the
// poller's original unbounded ctx, and not always internal/llm.DefaultTimeLimit's
// 3-minute default regardless of configuration.
func TestBoundedInvestigationContext_ShrinksWithConfiguredTimeLimit(t *testing.T) {
	start := time.Now()
	cfg := settings.Config{AnalysisTimeLimitSeconds: ptrSeconds(5)}

	ctx, cancel := boundedInvestigationContext(context.Background(), cfg)
	defer cancel()

	deadline, ok := ctx.Deadline()
	if !ok {
		t.Fatalf("boundedInvestigationContext returned a ctx with no deadline at all")
	}

	// Expected: 5s (the configured limit) + investigationCommitMargin (3m).
	wantRemaining := 5*time.Second + investigationCommitMargin
	gotRemaining := deadline.Sub(start)

	// A couple hundred ms of slack for test scheduling jitter — this is
	// checking minutes-scale arithmetic, not sub-second timing precision.
	if diff := gotRemaining - wantRemaining; diff > 2*time.Second || diff < -2*time.Second {
		t.Errorf("derived ctx deadline is %v from now, want ~%v (5s configured limit + %v commit margin) — got a %v discrepancy",
			gotRemaining, wantRemaining, investigationCommitMargin, diff)
	}

	// The specific regression this test guards: a 5s configured limit must
	// NOT produce anywhere near internal/llm.DefaultTimeLimit's (3 minutes)
	// worth of extra headroom — that would mean the configured value was
	// silently ignored and the hardcoded default used instead.
	wantIfDefaultUsedInstead := llm.DefaultTimeLimit + investigationCommitMargin
	if gotRemaining > wantIfDefaultUsedInstead-1*time.Minute {
		t.Errorf("derived ctx deadline (%v from now) is suspiciously close to what DefaultTimeLimit (%v) would have produced (%v) — the configured 5s limit looks like it was ignored",
			gotRemaining, llm.DefaultTimeLimit, wantIfDefaultUsedInstead)
	}
}

// TestBoundedInvestigationContext_NilConfigUsesDefaultTimeLimit proves the
// fallback half: an org with no AnalysisTimeLimitSeconds override (nil,
// the ordinary case) still gets a real, bounded deadline — derived from
// internal/llm.DefaultTimeLimit, not an unbounded ctx and not zero.
func TestBoundedInvestigationContext_NilConfigUsesDefaultTimeLimit(t *testing.T) {
	start := time.Now()
	ctx, cancel := boundedInvestigationContext(context.Background(), settings.Config{})
	defer cancel()

	deadline, ok := ctx.Deadline()
	if !ok {
		t.Fatalf("boundedInvestigationContext returned a ctx with no deadline at all")
	}

	want := llm.DefaultTimeLimit + investigationCommitMargin
	got := deadline.Sub(start)
	if diff := got - want; diff > 2*time.Second || diff < -2*time.Second {
		t.Errorf("derived ctx deadline is %v from now, want ~%v (DefaultTimeLimit + commit margin)", got, want)
	}
}

// TestBoundedInvestigationContext_NeverLoosensAnAlreadyTighterParent proves
// this function only ever TIGHTENS the deadline a caller already has, the
// same context.WithTimeout composition CallToolWithRetry's own retry-skip
// behavior depends on (see tools_retry_outer_context_test.go and
// tools.go's CallToolWithRetry doc comment): if the parent ctx passed in
// already has a nearer deadline than timeLimit+investigationCommitMargin
// would produce on its own, the derived ctx must still respect the
// parent's nearer one, not silently extend it.
func TestBoundedInvestigationContext_NeverLoosensAnAlreadyTighterParent(t *testing.T) {
	parent, cancelParent := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancelParent()

	// A generous configured limit — if this function extended the parent's
	// deadline instead of intersecting with it, ctx.Deadline() below would
	// reflect minutes, not milliseconds.
	ctx, cancel := boundedInvestigationContext(parent, settings.Config{AnalysisTimeLimitSeconds: ptrSeconds(600)})
	defer cancel()

	select {
	case <-ctx.Done():
		// Correct: the parent's 50ms deadline governs.
	case <-time.After(1 * time.Second):
		t.Errorf("ctx was not Done within 1s — the parent's 50ms deadline should still bound it regardless of the 600s configured limit")
	}
}
