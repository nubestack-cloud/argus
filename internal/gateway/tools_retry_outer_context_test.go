package gateway

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"argus/internal/events"
)

// TestCallToolWithRetry_TooShortOuterDeadlineDefeatsRetry is a regression
// test for the exact subtlety BUGS.md 115's fix in
// internal/api/routing.go's gatherOwnershipFacts had to avoid: a naive
// "just swap CallTool for CallToolWithRetry" edit, if the call site keeps
// wrapping the call in its OWN context.WithTimeout sized for a single
// attempt (the old ownershipLookupTimeout, 15s — well under
// toolCallTimeout+resultGraceWindow's ~35s worst case for one attempt),
// does not actually retry anything.
//
// callToolAttemptWithGrace's very first line checks ctx.Err() (tools.go).
// The first attempt's own timeout+grace wait is NOT bound by that outer
// context for its grace half (that half is a raw time.After, unconditional
// by design — see callToolAttemptWithGrace's doc comment), so a
// single-attempt-sized outer deadline has always already elapsed by the
// time the first attempt gives up. CallToolWithRetry then calls
// callToolAttemptWithGrace a second time with that same, already-expired
// outer context, which returns immediately via the ctx.Err() check without
// ever sending a second ToolRequest — a "retry" that never resends.
//
// This is why routing.go's real fix does NOT keep wrapping the
// CallToolWithRetry call in a context.WithTimeout(ctx, ownershipLookupTimeout)
// the way the old single-shot CallTool call did — it uses
// context.WithoutCancel(ctx) with no additional deadline layered on top,
// letting CallToolWithRetry's own internal bounds (toolCallTimeout,
// resultGraceWindow, the retry budget) be the only thing bounding the call.
// TestCallToolWithRetry_TimeoutThenSucceedsOnRetry (above, in
// tools_retry_test.go) is the companion positive case: a sufficiently large
// outer deadline (there, an ordinary 5s) lets the exact same swallow-then-
// retry scenario actually succeed.
func TestCallToolWithRetry_TooShortOuterDeadlineDefeatsRetry(t *testing.T) {
	shrinkRetryTimings(t, 150*time.Millisecond, 100*time.Millisecond)

	ca, err := NewEphemeralDevCA()
	if err != nil {
		t.Fatalf("new dev CA: %v", err)
	}
	gw := NewGateway(nil, ca, events.NewBus())
	const clusterID = "cl_test_retry_short_outer_deadline"
	addr := newTestGateway(t, gw, ca, clusterID)

	executor := newEventExecutor(t, "ns-short-outer", "ShouldNeverBeReturned")
	conn := dialTestAgent(t, addr, ca, clusterID)
	waitForConnRegistered(t, gw, clusterID)

	var reqCount int32
	// swallow=1: the first ToolRequest is read but never answered — the
	// same "stall bad enough that even the grace window finds nothing"
	// shape TestCallToolWithRetry_TimeoutThenSucceedsOnRetry uses. If a
	// retry actually reached the agent, this counting loop would answer it
	// correctly and promptly.
	go countingToolAgent(conn, executor, &reqCount, 0, 1)

	// 100ms: shorter than toolCallTimeout (150ms) alone, let alone
	// toolCallTimeout+resultGraceWindow (250ms) — deliberately mirroring the
	// real production ratio this bug had (ownershipLookupTimeout=15s <
	// toolCallTimeout=30s < toolCallTimeout+resultGraceWindow=35s).
	outerCtx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	start := time.Now()
	_, callErr := gw.CallToolWithRetry(outerCtx, clusterID, "get_events", mustJSON(t, map[string]string{"namespace": "ns-short-outer"}))
	elapsed := time.Since(start)

	if callErr == nil {
		t.Fatalf("CallToolWithRetry succeeded — want it to fail, since the agent never answered either attempt")
	}
	// The whole call must still take roughly as long as the first attempt's
	// own timeout+grace (250ms) — the outer deadline expiring early must not
	// make it return instantly with a bare "context deadline exceeded" from
	// the outer context alone, or this test would not actually be exercising
	// the first attempt's real timeout+grace wait.
	if elapsed < 200*time.Millisecond {
		t.Errorf("CallToolWithRetry returned after only %v — want it to have run the first attempt's full timeout+grace wait (~250ms) before giving up", elapsed)
	}
	if n := atomic.LoadInt32(&reqCount); n != 1 {
		t.Errorf("agent received %d ToolRequests, want exactly 1 — an outer deadline sized for only one attempt must make the retry a no-op (no second ToolRequest ever sent), which is exactly the trap a naive CallTool->CallToolWithRetry swap falls into if it keeps the old single-attempt outer timeout", n)
	}
}
