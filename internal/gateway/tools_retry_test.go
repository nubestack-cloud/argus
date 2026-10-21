package gateway

import (
	"context"
	"encoding/json"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	k8sfake "k8s.io/client-go/kubernetes/fake"
	k8sscheme "k8s.io/client-go/kubernetes/scheme"

	"argus/internal/agent"
	"argus/internal/events"
	"argus/internal/tunnel"
)

// This file proves CallToolWithRetry (tools.go) — BACKLOG.md C5's fix for
// BUGS.md 96 — against the same real TCP+mTLS harness
// tunnel_roundtrip_test.go already established (newTestGateway,
// dialTestAgent, waitForConnRegistered, mustJSON, all reused unmodified from
// that file). CallTool itself, and every one of its own tests above, is
// completely untouched by this fix — these tests only exercise the new
// method.
//
// toolCallTimeout and resultGraceWindow are package vars specifically so
// these tests don't need to wait out the real 30s/5s production values —
// each test below shrinks them and restores the originals via t.Cleanup.
// None of these tests use t.Parallel(), matching this package's existing
// tests, since they mutate those shared package vars.

// shrinkRetryTimings overrides toolCallTimeout/resultGraceWindow for the
// duration of one test and restores the real values afterward.
func shrinkRetryTimings(t *testing.T, callTimeout, graceWindow time.Duration) {
	t.Helper()
	origTimeout, origGrace := toolCallTimeout, resultGraceWindow
	toolCallTimeout, resultGraceWindow = callTimeout, graceWindow
	t.Cleanup(func() { toolCallTimeout, resultGraceWindow = origTimeout, origGrace })
}

// newEventExecutor builds a real agent.ToolExecutor (fake-clientset-backed,
// same as tunnel_roundtrip_test.go) seeded with one Event a get_events call
// against namespace ns can retrieve — enough to prove a returned result is
// the REAL, correct answer and not a fabricated stand-in.
func newEventExecutor(t *testing.T, ns, reason string) *agent.ToolExecutor {
	t.Helper()
	typed := k8sfake.NewSimpleClientset(&corev1.Event{
		ObjectMeta:     metav1.ObjectMeta{Name: "ev1", Namespace: ns},
		InvolvedObject: corev1.ObjectReference{Kind: "Pod", Name: "web-1"},
		Reason:         reason,
	})
	dyn := dynamicfake.NewSimpleDynamicClient(k8sscheme.Scheme)
	return agent.NewToolExecutorForTest(typed, dyn)
}

// countingToolAgent is the test's stand-in agent-side loop: it counts every
// ToolRequest it decodes into reqCount, and for every one PAST the first
// `swallow` of them, executes it for real (executor.Execute — the real
// agent tool logic, fake-clientset-backed) after sleeping `delay`, then
// sends back the resulting ToolResult. The first `swallow` requests are
// read and counted but never answered at all — simulating exactly BUGS.md
// 96's transport stall, where the agent computed a correct answer that
// never arrived at the hub in time, not an agent that failed or was
// unreachable.
func countingToolAgent(conn net.Conn, executor *agent.ToolExecutor, reqCount *int32, delay time.Duration, swallow int32) {
	dec := json.NewDecoder(conn)
	enc := json.NewEncoder(conn)
	var writeMu sync.Mutex

	for {
		var msg tunnel.ServerMessage
		if err := dec.Decode(&msg); err != nil {
			return
		}
		if msg.ToolRequest == nil {
			continue
		}
		req := *msg.ToolRequest
		n := atomic.AddInt32(reqCount, 1)
		if n <= swallow {
			continue
		}
		go func() {
			if delay > 0 {
				time.Sleep(delay)
			}
			data, truncated, err := executor.Execute(context.Background(), req.Tool, req.Args)
			result := tunnel.ToolResult{CorrelationID: req.CorrelationID, Truncated: truncated}
			if err != nil {
				result.Error = err.Error()
			} else {
				result.Data = data
			}
			writeMu.Lock()
			defer writeMu.Unlock()
			_ = enc.Encode(tunnel.ClientMessage{ToolResult: &result})
		}()
	}
}

func decodeEventReason(t *testing.T, data json.RawMessage) string {
	t.Helper()
	var results []map[string]any
	if err := json.Unmarshal(data, &results); err != nil {
		t.Fatalf("decode result: %v (raw: %s)", err, data)
	}
	if len(results) != 1 {
		t.Fatalf("got %d results, want exactly 1: %+v", len(results), results)
	}
	reason, _ := results[0]["reason"].(string)
	return reason
}

// TestCallToolWithRetry_LateResultAcceptedWithinGraceWindow is the direct
// reproduction of BUGS.md 96 at unit-test scale: the agent's answer is
// correct, but delivery is delayed (by the fake "transport") past
// toolCallTimeout. Before this fix that result would be silently discarded
// (server.go's "unknown/expired correlation id" branch) and the caller
// would see a timeout error despite the agent having done everything right.
// This asserts the grace window catches it instead — AND that catching it
// costs no retry (exactly one ToolRequest reaches the agent), since a late
// arrival needs no new request at all.
func TestCallToolWithRetry_LateResultAcceptedWithinGraceWindow(t *testing.T) {
	shrinkRetryTimings(t, 150*time.Millisecond, 200*time.Millisecond)

	ca, err := NewEphemeralDevCA()
	if err != nil {
		t.Fatalf("new dev CA: %v", err)
	}
	gw := NewGateway(nil, ca, events.NewBus())
	const clusterID = "cl_test_grace_accept"
	addr := newTestGateway(t, gw, ca, clusterID)

	executor := newEventExecutor(t, "ns-grace", "GraceWindowAnswer")
	conn := dialTestAgent(t, addr, ca, clusterID)
	waitForConnRegistered(t, gw, clusterID)

	var reqCount int32
	// 280ms: past toolCallTimeout (150ms) but well inside
	// toolCallTimeout+resultGraceWindow (350ms) — the agent's answer is
	// "late," not "missing."
	go countingToolAgent(conn, executor, &reqCount, 280*time.Millisecond, 0)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	start := time.Now()
	data, err := gw.CallToolWithRetry(ctx, clusterID, "get_events", mustJSON(t, map[string]string{"namespace": "ns-grace"}))
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("CallToolWithRetry: want the late-but-correct result accepted, got error: %v", err)
	}
	if got := decodeEventReason(t, data); got != "GraceWindowAnswer" {
		t.Errorf("result reason = %q, want %q", got, "GraceWindowAnswer")
	}
	if elapsed > 1*time.Second {
		t.Errorf("CallToolWithRetry took %v — the grace window is bounded at 200ms past the 150ms timeout, this should not be anywhere near 1s", elapsed)
	}
	if n := atomic.LoadInt32(&reqCount); n != 1 {
		t.Errorf("agent received %d ToolRequests, want exactly 1 — accepting a late result must not cost a retry", n)
	}
}

// TestCallToolWithRetry_TimeoutThenSucceedsOnRetry proves the other half of
// the fix: when NO result — late or otherwise — shows up even after the
// grace window, CallToolWithRetry sends exactly one fresh ToolRequest (a
// retry) before giving up, and a real, correct result on that retry
// produces a correct, non-partial outcome rather than a hard failure.
func TestCallToolWithRetry_TimeoutThenSucceedsOnRetry(t *testing.T) {
	shrinkRetryTimings(t, 150*time.Millisecond, 200*time.Millisecond)

	ca, err := NewEphemeralDevCA()
	if err != nil {
		t.Fatalf("new dev CA: %v", err)
	}
	gw := NewGateway(nil, ca, events.NewBus())
	const clusterID = "cl_test_retry_succeeds"
	addr := newTestGateway(t, gw, ca, clusterID)

	executor := newEventExecutor(t, "ns-retry", "RetryAnswer")
	conn := dialTestAgent(t, addr, ca, clusterID)
	waitForConnRegistered(t, gw, clusterID)

	var reqCount int32
	// swallow=1: the FIRST ToolRequest (the original attempt) is read and
	// counted but never answered at all — simulating a stall bad enough
	// that even the grace window finds nothing. The retry's request (the
	// second one this loop sees) is answered immediately and correctly.
	go countingToolAgent(conn, executor, &reqCount, 0, 1)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	start := time.Now()
	data, err := gw.CallToolWithRetry(ctx, clusterID, "get_events", mustJSON(t, map[string]string{"namespace": "ns-retry"}))
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("CallToolWithRetry: want the retry's correct result, got error: %v", err)
	}
	if got := decodeEventReason(t, data); got != "RetryAnswer" {
		t.Errorf("result reason = %q, want %q", got, "RetryAnswer")
	}
	// The first attempt must run its full course (timeout + grace, 350ms)
	// before the retry is even sent — this is a real bound, not slack.
	if elapsed < 300*time.Millisecond {
		t.Errorf("CallToolWithRetry returned after only %v — want it to have actually waited out the first attempt's timeout+grace before retrying", elapsed)
	}
	if elapsed > 2*time.Second {
		t.Errorf("CallToolWithRetry took %v — should succeed shortly after the retry, nowhere near the 5s outer context deadline", elapsed)
	}
	if n := atomic.LoadInt32(&reqCount); n != 2 {
		t.Errorf("agent received %d ToolRequests, want exactly 2 (the original attempt plus one retry)", n)
	}
}

// TestCallToolWithRetry_NormalCaseUnchanged proves this fix changes nothing
// about the ordinary, non-stalled path: a prompt, correct first answer is
// returned immediately, with no retry spent and no grace wait incurred —
// using the REAL production toolCallTimeout/resultGraceWindow values
// (deliberately not shrunk) specifically to prove the fast path never
// touches either bound.
func TestCallToolWithRetry_NormalCaseUnchanged(t *testing.T) {
	ca, err := NewEphemeralDevCA()
	if err != nil {
		t.Fatalf("new dev CA: %v", err)
	}
	gw := NewGateway(nil, ca, events.NewBus())
	const clusterID = "cl_test_retry_normal"
	addr := newTestGateway(t, gw, ca, clusterID)

	executor := newEventExecutor(t, "ns-normal", "NormalAnswer")
	conn := dialTestAgent(t, addr, ca, clusterID)
	waitForConnRegistered(t, gw, clusterID)

	var reqCount int32
	go countingToolAgent(conn, executor, &reqCount, 0, 0)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	start := time.Now()
	data, err := gw.CallToolWithRetry(ctx, clusterID, "get_events", mustJSON(t, map[string]string{"namespace": "ns-normal"}))
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("CallToolWithRetry: %v", err)
	}
	if got := decodeEventReason(t, data); got != "NormalAnswer" {
		t.Errorf("result reason = %q, want %q", got, "NormalAnswer")
	}
	if elapsed > 2*time.Second {
		t.Errorf("CallToolWithRetry took %v for a normal, immediately-answered call — want near-instant", elapsed)
	}
	if n := atomic.LoadInt32(&reqCount); n != 1 {
		t.Errorf("agent received %d ToolRequests, want exactly 1 — a normal successful call must never retry", n)
	}
}

// TestCallToolWithRetry_DeadAgentEventuallyGivesUp is the "does this
// actually bound itself" proof BACKLOG.md C5 explicitly calls for: an agent
// that never answers at all (not stalled-then-recovers, genuinely
// unresponsive for the whole call) must still fail in bounded time — at
// most one retry, never an unbounded or ever-growing retry loop — well
// before the caller's own, much longer context deadline.
func TestCallToolWithRetry_DeadAgentEventuallyGivesUp(t *testing.T) {
	shrinkRetryTimings(t, 100*time.Millisecond, 100*time.Millisecond)

	ca, err := NewEphemeralDevCA()
	if err != nil {
		t.Fatalf("new dev CA: %v", err)
	}
	gw := NewGateway(nil, ca, events.NewBus())
	const clusterID = "cl_test_retry_dead"
	addr := newTestGateway(t, gw, ca, clusterID)

	executor := newEventExecutor(t, "ns-dead", "NeverSent")
	conn := dialTestAgent(t, addr, ca, clusterID)
	waitForConnRegistered(t, gw, clusterID)

	var reqCount int32
	// swallow a large number: every request this call (and its one retry)
	// could possibly send goes unanswered — a genuinely dead agent, not a
	// transient blip.
	go countingToolAgent(conn, executor, &reqCount, 0, 1000)

	// A generous outer deadline standing in for cmd/cli-runner's real 180s
	// investigation budget — the whole point of this test is that
	// CallToolWithRetry gives up long before this fires, not because of it.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	start := time.Now()
	_, err = gw.CallToolWithRetry(ctx, clusterID, "get_events", mustJSON(t, map[string]string{"namespace": "ns-dead"}))
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("CallToolWithRetry against a genuinely dead agent: want an error, got nil")
	}
	// Bounded at roughly 2 attempts * (timeout+grace) = 400ms. Generous
	// upper bound to absorb scheduler jitter, but must be nowhere near the
	// 10s outer context — that gap is exactly what proves this gives up on
	// its own rather than riding the caller's deadline out.
	if elapsed > 3*time.Second {
		t.Errorf("CallToolWithRetry against a dead agent took %v — want well under the 10s outer deadline, bounded by (timeout+grace)*(1+one retry)", elapsed)
	}
	if n := atomic.LoadInt32(&reqCount); n != 2 {
		t.Errorf("agent received %d ToolRequests, want exactly 2 (the original attempt plus exactly one retry, never more)", n)
	}
}

// TestCallToolWithRetry_BudgetExhaustedAcrossCallsToSameCluster proves
// takeRetryBudget's fleet-safety property directly: retries are capped per
// CLUSTER across an entire rolling window, not just per call — so several
// calls against one struggling cluster cannot each independently claim
// "one retry is fine" and collectively pile up far more retry traffic than
// the cap allows during a real prolonged outage.
func TestCallToolWithRetry_BudgetExhaustedAcrossCallsToSameCluster(t *testing.T) {
	shrinkRetryTimings(t, 60*time.Millisecond, 60*time.Millisecond)

	ca, err := NewEphemeralDevCA()
	if err != nil {
		t.Fatalf("new dev CA: %v", err)
	}
	gw := NewGateway(nil, ca, events.NewBus())
	const clusterID = "cl_test_retry_budget"
	addr := newTestGateway(t, gw, ca, clusterID)

	executor := newEventExecutor(t, "ns-budget", "NeverSent")
	conn := dialTestAgent(t, addr, ca, clusterID)
	waitForConnRegistered(t, gw, clusterID)

	var reqCount int32
	go countingToolAgent(conn, executor, &reqCount, 0, 100000)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	// maxToolRetriesPerClusterWindow (3) + 2 more calls: the first 3 should
	// each still get their one retry (2 requests apiece); the last 2 should
	// get only their original attempt (budget exhausted, 1 request each).
	const numCalls = maxToolRetriesPerClusterWindow + 2
	for i := 0; i < numCalls; i++ {
		if _, err := gw.CallToolWithRetry(ctx, clusterID, "get_events", mustJSON(t, map[string]string{"namespace": "ns-budget"})); err == nil {
			t.Fatalf("call %d: want an error against a dead agent, got nil", i)
		}
	}

	want := int32(2*maxToolRetriesPerClusterWindow + (numCalls - maxToolRetriesPerClusterWindow))
	if got := atomic.LoadInt32(&reqCount); got != want {
		t.Errorf("total ToolRequests across %d calls = %d, want %d (the first %d calls retried once each, the rest got no retry — budget exhausted)",
			numCalls, got, want, maxToolRetriesPerClusterWindow)
	}
}

// TestTakeRetryBudget_WindowResetsOverTime is a focused unit test of
// takeRetryBudget itself, bypassing the network harness entirely: it proves
// the per-cluster budget actually refills once toolRetryBudgetWindow has
// elapsed, using Gateway.now (a test-only override, mirroring
// internal/mcp.Store's own clock-injection convention) rather than a real
// 5-minute sleep.
func TestTakeRetryBudget_WindowResetsOverTime(t *testing.T) {
	ca, err := NewEphemeralDevCA()
	if err != nil {
		t.Fatalf("new dev CA: %v", err)
	}
	gw := NewGateway(nil, ca, events.NewBus())

	now := time.Now()
	gw.now = func() time.Time { return now }

	const clusterID = "cl_test_budget_window"
	for i := 0; i < maxToolRetriesPerClusterWindow; i++ {
		if !gw.takeRetryBudget(clusterID) {
			t.Fatalf("takeRetryBudget call %d: want true (budget not yet exhausted), got false", i)
		}
	}
	if gw.takeRetryBudget(clusterID) {
		t.Fatal("takeRetryBudget after the window's cap was reached: want false, got true")
	}

	// Advance the injected clock past toolRetryBudgetWindow — the counter
	// must reset rather than staying exhausted forever.
	now = now.Add(toolRetryBudgetWindow + time.Second)
	if !gw.takeRetryBudget(clusterID) {
		t.Fatal("takeRetryBudget after the window elapsed: want true (budget refilled), got false")
	}
}
