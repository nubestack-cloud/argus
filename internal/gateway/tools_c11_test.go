package gateway

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"argus/internal/events"
)

// This file proves BACKLOG.md C11's first half ("cut the per-call timeout
// hard, using the real measured latency distribution") against the real
// TCP+mTLS harness this package's other tool-call tests already use
// (newTestGateway/dialTestAgent/waitForConnRegistered/countingToolAgent/
// mustJSON, all from tools_retry_test.go).
//
// The real numbers behind the new value (see toolCallTimeout's own doc
// comment in tools.go for the full derivation from the live mcp_tool_calls
// table, measured 2026-09-02): of 1,473 successful calls, p50=10ms,
// p90=21ms, p99=621ms — but the same table's tail has real, non-retried
// single-attempt successes up to 28.4s (all four calls above 5s traced to
// one correlated ~30-minute slow-cluster window on one real cluster). 12s
// was chosen to sit comfortably above the ordinary tail (up to ~6.5s) while
// deliberately NOT chasing that one correlated outlier window, which would
// have meant barely cutting the old 30s at all.

// TestToolCallTimeoutDefault_IsTwelveSecondsNotThirty is a direct pin on
// the production default: BACKLOG.md C11 replaced the old 30s judgment
// call with 12s, derived from the real distribution above. This guards
// against a future edit silently reverting toolCallTimeout to 30s (or to
// any other value) without updating the reasoning that justifies it.
func TestToolCallTimeoutDefault_IsTwelveSecondsNotThirty(t *testing.T) {
	if toolCallTimeout != 12*time.Second {
		t.Errorf("toolCallTimeout = %v, want 12s (BACKLOG.md C11's data-derived cut from the old 30s)", toolCallTimeout)
	}
	if toolCallTimeout == 30*time.Second {
		t.Errorf("toolCallTimeout is still the old 30s value — C11's cut was not actually applied")
	}
}

// TestCallToolWithRetry_SlowButGenuinelySuccessfulCallStillSucceeds is the
// test the failure-only case above must be paired with: proof that cutting
// toolCallTimeout down did NOT turn a call that is merely slow — far
// slower than any typical case, but still well inside the new budget —
// into a false failure. This runs against the REAL, unshrunk production
// toolCallTimeout/resultGraceWindow specifically because the claim being
// tested is about those exact production values' safety margin, not about
// timeout/retry mechanics in the abstract (those are covered elsewhere in
// this package using shrunk timings for speed).
//
// 9s stands in for the measured tail's genuine, non-retried single-attempt
// successes (list_repo_files at 6.5s was the largest one NOT traced to the
// one correlated slow-cluster window) — comfortably past old p50 (10ms)
// and p99 (621ms), comfortably under the new 12s cutoff, with real margin
// on both sides.
func TestCallToolWithRetry_SlowButGenuinelySuccessfulCallStillSucceeds(t *testing.T) {
	if testing.Short() {
		t.Skip("exercises the real, unshrunk production toolCallTimeout — this test takes ~9s")
	}

	ca, err := NewEphemeralDevCA()
	if err != nil {
		t.Fatalf("new dev CA: %v", err)
	}
	gw := NewGateway(nil, ca, events.NewBus())
	const clusterID = "cl_test_c11_slow_success"
	addr := newTestGateway(t, gw, ca, clusterID)

	executor := newEventExecutor(t, "ns-c11-slow", "SlowButRealAnswer")
	conn := dialTestAgent(t, addr, ca, clusterID)
	waitForConnRegistered(t, gw, clusterID)

	var reqCount int32
	// 9s: past old p50/p99, under the new 12s toolCallTimeout, with no
	// swallowed attempts — a real, single, slow-but-successful response.
	go countingToolAgent(conn, executor, &reqCount, 9*time.Second, 0)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	start := time.Now()
	data, err := gw.CallToolWithRetry(ctx, clusterID, "get_events", mustJSON(t, map[string]string{"namespace": "ns-c11-slow"}))
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("CallToolWithRetry: want the slow-but-real result accepted, got error: %v", err)
	}
	if got := decodeEventReason(t, data); got != "SlowButRealAnswer" {
		t.Errorf("result reason = %q, want %q", got, "SlowButRealAnswer")
	}
	if elapsed < 9*time.Second {
		t.Errorf("CallToolWithRetry returned after only %v — want it to have actually waited out the agent's real 9s delay", elapsed)
	}
	// Must complete well under toolCallTimeout+resultGraceWindow (17s) —
	// i.e. via the ORDINARY primary wait, not via a retry or a grace-window
	// rescue, which would mean the primary wait had already given up on a
	// call that was, in fact, still going to succeed.
	if elapsed > 15*time.Second {
		t.Errorf("CallToolWithRetry took %v — want it well under toolCallTimeout+resultGraceWindow (17s), succeeding on the ordinary primary wait", elapsed)
	}
	if n := atomic.LoadInt32(&reqCount); n != 1 {
		t.Errorf("agent received %d ToolRequests, want exactly 1 — a call that was always going to succeed must not cost a retry", n)
	}
}

// TestCallToolWithRetry_InvestigationRemainingTimeShrinksRetryUnderNewDefault
// is the composition check BACKLOG.md C11 explicitly calls for: prove the
// new, shorter toolCallTimeout and the "retry is bounded by the
// investigation's own remaining time" mechanism (ctx propagation — see
// CallToolWithRetry's doc comment) don't silently defeat each other, using
// timings SCALED to the new 12s:5s (toolCallTimeout:resultGraceWindow)
// ratio rather than the old 30s:5s one
// tools_retry_outer_context_test.go's TestCallToolWithRetry_TooShortOuterDeadlineDefeatsRetry
// already covers.
//
// A caller derives its ctx from the INVESTIGATION's own remaining time
// (internal/api/analyze.go's workCtx, internal/autoanalyze's toolCtx —
// BACKLOG.md C11's second half) — never from a timeout sized for one
// attempt. This test proves both ends of that: an outer deadline with
// AMPLE investigation time left lets a swallowed-then-retried call still
// succeed (the retry is not wrongly skipped just because SOME outer
// deadline exists), while an outer deadline that has already elapsed by
// the time the retry would fire defeats it cleanly (no second ToolRequest
// ever sent) — exactly the property that makes "aware of the
// investigation's remaining time" true rather than aspirational.
func TestCallToolWithRetry_InvestigationRemainingTimeShrinksRetryUnderNewDefault(t *testing.T) {
	// 240ms:100ms preserves the real 12s:5s ratio (2.4) at test speed.
	shrinkRetryTimings(t, 240*time.Millisecond, 100*time.Millisecond)

	ca, err := NewEphemeralDevCA()
	if err != nil {
		t.Fatalf("new dev CA: %v", err)
	}
	gw := NewGateway(nil, ca, events.NewBus())

	t.Run("ample investigation time left: retry still succeeds", func(t *testing.T) {
		const clusterID = "cl_test_c11_ample_time"
		addr := newTestGateway(t, gw, ca, clusterID)
		executor := newEventExecutor(t, "ns-c11-ample", "AmpleTimeRetryAnswer")
		conn := dialTestAgent(t, addr, ca, clusterID)
		waitForConnRegistered(t, gw, clusterID)

		var reqCount int32
		// swallow=1: first attempt never answered (full timeout+grace,
		// 340ms); the retry (second request) is answered immediately.
		go countingToolAgent(conn, executor, &reqCount, 0, 1)

		// An "investigation" with 5s of its own budget left — vastly more
		// than one attempt's worst case (340ms) — modeling a real
		// investigation early in its own timeLimit, not near the end of it.
		investigationCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		data, err := gw.CallToolWithRetry(investigationCtx, clusterID, "get_events", mustJSON(t, map[string]string{"namespace": "ns-c11-ample"}))
		if err != nil {
			t.Fatalf("CallToolWithRetry: want the retry's correct result, got error: %v", err)
		}
		if got := decodeEventReason(t, data); got != "AmpleTimeRetryAnswer" {
			t.Errorf("result reason = %q, want %q", got, "AmpleTimeRetryAnswer")
		}
		if n := atomic.LoadInt32(&reqCount); n != 2 {
			t.Errorf("agent received %d ToolRequests, want exactly 2 (plenty of investigation time left, so the retry must actually fire)", n)
		}
	})

	t.Run("investigation time already exhausted: retry is skipped, not attempted", func(t *testing.T) {
		const clusterID = "cl_test_c11_no_time_left"
		addr := newTestGateway(t, gw, ca, clusterID)
		executor := newEventExecutor(t, "ns-c11-none", "ShouldNeverBeReturned")
		conn := dialTestAgent(t, addr, ca, clusterID)
		waitForConnRegistered(t, gw, clusterID)

		var reqCount int32
		// swallow=1: only matters if a request actually reaches the agent
		// twice — if the retry is correctly skipped, this agent only ever
		// sees (and never answers) the first one.
		go countingToolAgent(conn, executor, &reqCount, 0, 1)

		// An "investigation" ctx that expires DURING the first attempt's
		// grace wait (240ms primary + 100ms grace = 340ms total) but well
		// after its primary wait alone (240ms) — modeling an investigation
		// that is almost entirely out of its own time budget when this call
		// starts, with just enough left for one attempt to run its course
		// but not enough for a second.
		investigationCtx, cancel := context.WithTimeout(context.Background(), 310*time.Millisecond)
		defer cancel()

		start := time.Now()
		_, callErr := gw.CallToolWithRetry(investigationCtx, clusterID, "get_events", mustJSON(t, map[string]string{"namespace": "ns-c11-none"}))
		elapsed := time.Since(start)

		if callErr == nil {
			t.Fatalf("CallToolWithRetry succeeded — want it to fail, since the agent never answered the one request it should have received")
		}
		// Must still run the first attempt's real timeout+grace (~340ms) —
		// proving this returned via the first attempt's OWN wait, not via
		// the outer ctx alone reporting "already done" instantly.
		if elapsed < 300*time.Millisecond {
			t.Errorf("CallToolWithRetry returned after only %v — want it to have run the first attempt's full timeout+grace wait (~340ms) before giving up", elapsed)
		}
		if n := atomic.LoadInt32(&reqCount); n != 1 {
			t.Errorf("agent received %d ToolRequests, want exactly 1 — an investigation with no time left for a retry must not send a second, doomed ToolRequest", n)
		}
	})
}
