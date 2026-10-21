package gateway

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"argus/internal/events"
)

// This file proves CallToolWithGrace (tools.go) — BACKLOG.md C8's fix for
// BUGS.md 104's "a mutating tunnel call has no 'we don't actually know'
// outcome" gap — against the same real TCP+mTLS harness
// tunnel_roundtrip_test.go/tools_retry_test.go already established
// (newTestGateway, dialTestAgent, waitForConnRegistered, countingToolAgent,
// newEventExecutor, mustJSON, shrinkRetryTimings, all reused unmodified).
//
// Two properties matter here, and neither is proven by the existing
// CallToolWithRetry tests: (1) a late-but-real result is still accepted
// within the grace window even for the method a MUTATING call site uses,
// and (2) this method NEVER sends a second ToolRequest, unlike
// CallToolWithRetry — which is the whole reason a mutating call site can
// use it safely at all (resending a mutation risks double-applying it).

// TestCallToolWithGrace_LateResultAcceptedNoRetry is the direct analogue of
// TestCallToolWithRetry_LateResultAcceptedWithinGraceWindow: the agent's
// answer is correct but delayed past toolCallTimeout by a slow transport,
// not lost. CallToolWithGrace must still accept it — proving the grace
// half of the fix reaches a mutating call site exactly as it already
// reaches the read-only investigation loop.
func TestCallToolWithGrace_LateResultAcceptedNoRetry(t *testing.T) {
	shrinkRetryTimings(t, 150*time.Millisecond, 200*time.Millisecond)

	ca, err := NewEphemeralDevCA()
	if err != nil {
		t.Fatalf("new dev CA: %v", err)
	}
	gw := NewGateway(nil, ca, events.NewBus())
	const clusterID = "cl_test_grace_only_accept"
	addr := newTestGateway(t, gw, ca, clusterID)

	executor := newEventExecutor(t, "ns-grace-only", "GraceOnlyAnswer")
	conn := dialTestAgent(t, addr, ca, clusterID)
	waitForConnRegistered(t, gw, clusterID)

	var reqCount int32
	// 280ms: past toolCallTimeout (150ms) but well inside
	// toolCallTimeout+resultGraceWindow (350ms) — a late, not a missing,
	// answer.
	go countingToolAgent(conn, executor, &reqCount, 280*time.Millisecond, 0)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	start := time.Now()
	data, err := gw.CallToolWithGrace(ctx, clusterID, "get_events", mustJSON(t, map[string]string{"namespace": "ns-grace-only"}))
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("CallToolWithGrace: want the late-but-correct result accepted, got error: %v", err)
	}
	if got := decodeEventReason(t, data); got != "GraceOnlyAnswer" {
		t.Errorf("result reason = %q, want %q", got, "GraceOnlyAnswer")
	}
	if elapsed > 1*time.Second {
		t.Errorf("CallToolWithGrace took %v — the grace window is bounded at 200ms past the 150ms timeout", elapsed)
	}
	if n := atomic.LoadInt32(&reqCount); n != 1 {
		t.Errorf("agent received %d ToolRequests, want exactly 1 — CallToolWithGrace must never send a second request, unlike CallToolWithRetry", n)
	}
}

// TestCallToolWithGrace_NeverRetriesEvenAfterGraceExpires is the property
// that makes CallToolWithGrace safe for a mutating call site at all: when
// nothing arrives even after the grace window, it gives up — it does NOT
// fall back to CallToolWithRetry's one-retry behavior, because resending a
// mutating ToolRequest risks double-applying the change. Exactly one
// ToolRequest must ever reach the agent, and the returned error must wrap
// gateway.ErrIndeterminate — the caller (executeApprovedPlan) needs that to
// tell this case apart from an explicit ToolResult.Error.
func TestCallToolWithGrace_NeverRetriesEvenAfterGraceExpires(t *testing.T) {
	shrinkRetryTimings(t, 100*time.Millisecond, 100*time.Millisecond)

	ca, err := NewEphemeralDevCA()
	if err != nil {
		t.Fatalf("new dev CA: %v", err)
	}
	gw := NewGateway(nil, ca, events.NewBus())
	const clusterID = "cl_test_grace_only_giveup"
	addr := newTestGateway(t, gw, ca, clusterID)

	executor := newEventExecutor(t, "ns-grace-giveup", "NeverSent")
	conn := dialTestAgent(t, addr, ca, clusterID)
	waitForConnRegistered(t, gw, clusterID)

	var reqCount int32
	// swallow a large number: nothing this call could possibly send ever
	// gets answered.
	go countingToolAgent(conn, executor, &reqCount, 0, 1000)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	start := time.Now()
	_, err = gw.CallToolWithGrace(ctx, clusterID, "patch_resource_limits", mustJSON(t, map[string]string{"namespace": "ns-grace-giveup"}))
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("CallToolWithGrace against an agent that never answers: want an error, got nil")
	}
	if !errors.Is(err, ErrIndeterminate) {
		t.Errorf("CallToolWithGrace error = %v, want it to wrap ErrIndeterminate — the caller must be able to tell this apart from a definite failure", err)
	}
	// Bounded at roughly timeout+grace = 200ms. Generous upper bound to
	// absorb scheduler jitter, but nowhere near the 5s outer context.
	if elapsed > 2*time.Second {
		t.Errorf("CallToolWithGrace took %v — want bounded at roughly toolCallTimeout+resultGraceWindow (200ms), well under the 5s outer deadline", elapsed)
	}
	if n := atomic.LoadInt32(&reqCount); n != 1 {
		t.Errorf("agent received %d ToolRequests, want exactly 1 — CallToolWithGrace must never retry a mutating call", n)
	}
}

// TestCallToolWithGrace_DisconnectWrapsErrIndeterminate is BUGS.md 104's own
// reproduction shape at unit-test scale: the connection dies mid-call
// (markClosed fires) before toolCallTimeout even elapses, not after a slow
// transport. This is the case CallToolWithGrace's own doc comment says it
// canNOT catch by listening longer — there is no live connection left to
// listen on — so the assertion here is narrower and more important than
// "it succeeds": the error must still classify as ErrIndeterminate (not a
// definite failure), and it must return promptly rather than waiting out
// toolCallTimeout, so internal/api/remediation_exec.go's
// resolveIndeterminateOutcome gets a chance to verify the real outcome
// instead of the connection drop being reported as a plain, unclassified
// failure.
func TestCallToolWithGrace_DisconnectWrapsErrIndeterminate(t *testing.T) {
	ca, err := NewEphemeralDevCA()
	if err != nil {
		t.Fatalf("new dev CA: %v", err)
	}
	gw := NewGateway(nil, ca, events.NewBus())
	const clusterID = "cl_test_grace_disconnect"
	addr := newTestGateway(t, gw, ca, clusterID)

	conn := dialTestAgent(t, addr, ca, clusterID)
	waitForConnRegistered(t, gw, clusterID)
	go dropConnectionOnFirstRequest(conn)

	start := time.Now()
	_, err = gw.CallToolWithGrace(context.Background(), clusterID, "scale_deployment", mustJSON(t, map[string]string{"namespace": "default"}))
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("CallToolWithGrace against a connection that dropped mid-call: want error, got nil")
	}
	if !errors.Is(err, ErrIndeterminate) {
		t.Errorf("CallToolWithGrace error = %v, want it to wrap ErrIndeterminate", err)
	}
	if !strings.Contains(err.Error(), "disconnected") {
		t.Errorf("CallToolWithGrace error = %q, want it to mention the disconnect", err.Error())
	}
	if elapsed > 5*time.Second {
		t.Errorf("CallToolWithGrace took %v to notice the dropped connection — want well under toolCallTimeout (30s)", elapsed)
	}
}

// TestCallTool_ToolErrorDoesNotWrapErrIndeterminate proves the other half
// of the classification: an explicit ToolResult.Error (the agent ran the
// tool and it failed, over a connection that stayed up) is a DEFINITE
// failure, never ErrIndeterminate — the mutation demonstrably did not
// apply, so recordExecutionOutcome's ordinary "failed" handling is exactly
// correct for it, and resolveIndeterminateOutcome must never be triggered
// by it.
func TestCallTool_ToolErrorDoesNotWrapErrIndeterminate(t *testing.T) {
	ca, err := NewEphemeralDevCA()
	if err != nil {
		t.Fatalf("new dev CA: %v", err)
	}
	gw := NewGateway(nil, ca, events.NewBus())
	const clusterID = "cl_test_toolerr_definite"
	addr := newTestGateway(t, gw, ca, clusterID)

	executor := newEventExecutor(t, "ns-toolerr", "unused")
	conn := dialTestAgent(t, addr, ca, clusterID)
	waitForConnRegistered(t, gw, clusterID)
	go respondToToolRequests(conn, executor, 0)

	_, err = gw.CallToolWithGrace(context.Background(), clusterID, "delete_everything", nil)
	if err == nil {
		t.Fatal("CallToolWithGrace with an unknown tool name: want error, got nil")
	}
	if errors.Is(err, ErrIndeterminate) {
		t.Errorf("CallToolWithGrace error = %v, want a DEFINITE failure (no ErrIndeterminate wrap) — the agent answered over a live connection", err)
	}
	if !strings.Contains(err.Error(), "unknown tool") {
		t.Errorf("CallToolWithGrace error = %q, want it to mention the unknown-tool failure the agent reported", err.Error())
	}
}
