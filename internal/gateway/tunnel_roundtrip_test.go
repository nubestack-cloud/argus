package gateway

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
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

// This file proves the actual ToolRequest/ToolResult wire plumbing this
// increment adds — CallTool, the connection registry, and the
// ToolResult-correlation half of serveClientMessages — round-trips over a
// REAL TCP+mTLS connection, using the real internal/gateway
// connection-handling code on the hub side and a real agent.ToolExecutor
// (internal/agent) on the other, backed by k8s.io/client-go's fake
// clientsets in place of the live cluster this sandbox doesn't have.
//
// One deliberate scope decision, stated once here rather than repeated in
// every test: these tests call Gateway.serveClientMessages directly with a
// fixed clusterID, bypassing handleConn's cert-serial-to-cluster-ID
// Postgres lookup (lookupClusterBySerial) and never send a Heartbeat or
// InventoryDelta message, so no test in this file touches a database.
// That lookup, and the Heartbeat/InventoryDelta/Finding handlers,
// are unchanged by this increment and already exercised (STATUS.md's
// "verified live" entries) — this file's job is the new mechanism only.
// Correspondingly, the "agent side" of each connection here is a minimal,
// hand-rolled loop (respondToToolRequests, below) speaking the real
// tunnel.ServerMessage/ClientMessage wire types and calling the real,
// unmodified agent.ToolExecutor.Execute — not the literal
// internal/agent.runTunnelSession, which unconditionally sends an initial
// InventoryDelta that this DB-free setup has nothing to dispatch it to.
// internal/agent's own tests (client_test.go, tools_test.go) already cover
// runTunnelSession's Heartbeat/Finding/ToolRequest wiring and every tool's
// executor logic in isolation; this file's addition is the round trip
// across a real connection plus the hub-side registry/correlation/timeout
// mechanics that only exist once both sides are talking to each other.

// newTestGateway starts a real TLS listener secured by ca, whose Accept
// loop calls gw.serveClientMessages directly under the given fixed
// clusterID for every connection it accepts — standing in for handleConn's
// full prologue (see this file's package doc comment for why). Returns the
// listener's address; the listener and every future connection made against
// it are torn down via t.Cleanup.
func newTestGateway(t *testing.T, gw *Gateway, ca *DevCA, clusterID string) string {
	t.Helper()

	certPEM, keyPEM, err := ca.IssueServerCert([]string{"127.0.0.1"}, time.Hour)
	if err != nil {
		t.Fatalf("issue gateway server cert: %v", err)
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("load gateway server cert: %v", err)
	}

	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    ca.ClientCAPool(),
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				tlsConn, ok := conn.(*tls.Conn)
				if !ok {
					return
				}
				if err := tlsConn.Handshake(); err != nil {
					return
				}
				_ = gw.serveClientMessages(context.Background(), clusterID, conn)
			}(conn)
		}
	}()

	return ln.Addr().String()
}

// dialTestAgent dials addr with a real client leaf certificate issued by ca
// (via the same agent.GenerateKeyAndCSR + DevCA.SignCSR path the real agent
// enrollment flow uses), completing a real mTLS handshake against the
// gateway's server certificate.
func dialTestAgent(t *testing.T, addr string, ca *DevCA, commonName string) net.Conn {
	t.Helper()

	keyPEM, csrPEM, err := agent.GenerateKeyAndCSR(commonName)
	if err != nil {
		t.Fatalf("generate agent key/csr: %v", err)
	}
	certPEM, _, err := ca.SignCSR(csrPEM, time.Hour)
	if err != nil {
		t.Fatalf("sign agent csr: %v", err)
	}
	cert, err := tls.X509KeyPair([]byte(certPEM), keyPEM)
	if err != nil {
		t.Fatalf("load agent cert/key: %v", err)
	}

	rootPool := x509.NewCertPool()
	if !rootPool.AppendCertsFromPEM(ca.RootCertPEM()) {
		t.Fatal("failed to add dev CA root cert to pool")
	}

	conn, err := tls.Dial("tcp", addr, &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      rootPool,
		ServerName:   "127.0.0.1",
		MinVersion:   tls.VersionTLS12,
	})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	return conn
}

// respondToToolRequests is the test's stand-in agent-side loop: for every
// ToolRequest decoded off conn, run it against executor (real
// agent.ToolExecutor.Execute, fake-clientset-backed) and encode the
// resulting ToolResult back, each in its own goroutine (mirroring
// internal/agent/client.go's runTunnelSession — a slow tool call must never
// block reading the next request) with writes serialized through writeMu
// (the same single-writer discipline runTunnelSession's own doc comment
// requires). perToolDelay, if non-zero, is slept before executing —
// used to encourage out-of-order completion in the concurrency test below.
func respondToToolRequests(conn net.Conn, executor *agent.ToolExecutor, perToolDelay time.Duration) {
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
		go func() {
			if perToolDelay > 0 {
				time.Sleep(perToolDelay)
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

// dropConnectionOnFirstRequest waits for exactly one ToolRequest to arrive
// and then closes conn without ever sending a ToolResult — simulating an
// agent that vanishes mid-call, for TestCallTool_ConnectionDropsMidCall.
func dropConnectionOnFirstRequest(conn net.Conn) {
	var msg tunnel.ServerMessage
	_ = json.NewDecoder(conn).Decode(&msg)
	conn.Close()
}

// waitForConnRegistered blocks until clusterID shows up in the gateway's
// connection registry (or fails the test after 2s). Needed because dialing
// only guarantees the CLIENT side of the mTLS handshake has completed —
// the server's Accept goroutine still has to finish its own Handshake()
// call and reach registerConn before CallTool has anything to find, and
// nothing about tls.Dial returning synchronizes with that.
func waitForConnRegistered(t *testing.T, gw *Gateway, clusterID string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if _, ok := gw.getConn(clusterID, tunnel.RoleInvestigate); ok {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("cluster %s never registered in the gateway's connection registry", clusterID)
}

func mustJSON(t *testing.T, v any) json.RawMessage {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal args: %v", err)
	}
	return b
}

func TestCallTool_RoundTrip_BasicSuccess(t *testing.T) {
	ca, err := NewEphemeralDevCA()
	if err != nil {
		t.Fatalf("new dev CA: %v", err)
	}
	gw := NewGateway(nil, ca, events.NewBus())
	const clusterID = "cl_test_basic"
	addr := newTestGateway(t, gw, ca, clusterID)

	typed := k8sfake.NewSimpleClientset(&corev1.Event{
		ObjectMeta:     metav1.ObjectMeta{Name: "ev1", Namespace: "ns-basic"},
		InvolvedObject: corev1.ObjectReference{Kind: "Pod", Name: "web-1"},
		Reason:         "FailedScheduling",
	})
	dyn := dynamicfake.NewSimpleDynamicClient(k8sscheme.Scheme)
	executor := agent.NewToolExecutorForTest(typed, dyn)

	conn := dialTestAgent(t, addr, ca, clusterID)
	waitForConnRegistered(t, gw, clusterID)
	go respondToToolRequests(conn, executor, 0)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	data, err := gw.CallTool(ctx, clusterID, "get_events", mustJSON(t, map[string]string{"namespace": "ns-basic"}))
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}

	var results []map[string]any
	if err := json.Unmarshal(data, &results); err != nil {
		t.Fatalf("decode CallTool result: %v (raw: %s)", err, data)
	}
	if len(results) != 1 || results[0]["reason"] != "FailedScheduling" {
		t.Fatalf("CallTool get_events result = %+v, want exactly the seeded FailedScheduling event", results)
	}
}

func TestCallTool_RoundTrip_ToolErrorSurfacesCleanly(t *testing.T) {
	ca, err := NewEphemeralDevCA()
	if err != nil {
		t.Fatalf("new dev CA: %v", err)
	}
	gw := NewGateway(nil, ca, events.NewBus())
	const clusterID = "cl_test_toolerr"
	addr := newTestGateway(t, gw, ca, clusterID)

	executor := agent.NewToolExecutorForTest(k8sfake.NewSimpleClientset(), dynamicfake.NewSimpleDynamicClient(k8sscheme.Scheme))
	conn := dialTestAgent(t, addr, ca, clusterID)
	waitForConnRegistered(t, gw, clusterID)
	go respondToToolRequests(conn, executor, 0)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err = gw.CallTool(ctx, clusterID, "delete_everything", nil)
	if err == nil {
		t.Fatal("CallTool with an unknown tool name: want error, got nil")
	}
	if !strings.Contains(err.Error(), "unknown tool") {
		t.Errorf("CallTool error = %q, want it to mention the unknown-tool failure the agent reported", err.Error())
	}
}

func TestCallTool_ClusterNotConnected(t *testing.T) {
	ca, err := NewEphemeralDevCA()
	if err != nil {
		t.Fatalf("new dev CA: %v", err)
	}
	gw := NewGateway(nil, ca, events.NewBus())

	start := time.Now()
	_, err = gw.CallTool(context.Background(), "cluster-that-never-connected", "get_events", nil)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("CallTool against a never-connected cluster: want error, got nil")
	}
	if elapsed > 2*time.Second {
		t.Errorf("CallTool against a disconnected cluster took %v — must fail immediately, not wait toolCallTimeout out", elapsed)
	}
}

func TestCallTool_ConnectionDropsMidCall(t *testing.T) {
	ca, err := NewEphemeralDevCA()
	if err != nil {
		t.Fatalf("new dev CA: %v", err)
	}
	gw := NewGateway(nil, ca, events.NewBus())
	const clusterID = "cl_test_dropmidcall"
	addr := newTestGateway(t, gw, ca, clusterID)

	conn := dialTestAgent(t, addr, ca, clusterID)
	waitForConnRegistered(t, gw, clusterID)
	go dropConnectionOnFirstRequest(conn)

	start := time.Now()
	_, err = gw.CallTool(context.Background(), clusterID, "get_events", mustJSON(t, map[string]string{"namespace": "default"}))
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("CallTool against a connection that dropped mid-call: want error, got nil")
	}
	if !strings.Contains(err.Error(), "disconnected") {
		t.Errorf("CallTool error = %q, want it to mention the disconnect", err.Error())
	}
	if elapsed > 5*time.Second {
		t.Errorf("CallTool took %v to notice the dropped connection — want well under toolCallTimeout (30s), since the disconnect should unblock it immediately", elapsed)
	}
}

func TestCallTool_ContextCancellation(t *testing.T) {
	ca, err := NewEphemeralDevCA()
	if err != nil {
		t.Fatalf("new dev CA: %v", err)
	}
	gw := NewGateway(nil, ca, events.NewBus())
	const clusterID = "cl_test_ctxcancel"
	addr := newTestGateway(t, gw, ca, clusterID)

	conn := dialTestAgent(t, addr, ca, clusterID)
	waitForConnRegistered(t, gw, clusterID)
	// An agent that receives the request but simply never answers, and
	// keeps the connection open (unlike dropConnectionOnFirstRequest) — the
	// only thing that should end this call is the caller's own context.
	go func() {
		var msg tunnel.ServerMessage
		_ = json.NewDecoder(conn).Decode(&msg)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()

	start := time.Now()
	_, err = gw.CallTool(ctx, clusterID, "get_events", mustJSON(t, map[string]string{"namespace": "default"}))
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("CallTool with an expired context and an unresponsive agent: want error, got nil")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("CallTool error = %v, want it to wrap context.DeadlineExceeded", err)
	}
	if elapsed > 2*time.Second {
		t.Errorf("CallTool took %v to respect its caller's ~150ms context deadline", elapsed)
	}
}

func TestCallTool_ConcurrentCallsCorrelateCorrectly(t *testing.T) {
	ca, err := NewEphemeralDevCA()
	if err != nil {
		t.Fatalf("new dev CA: %v", err)
	}
	gw := NewGateway(nil, ca, events.NewBus())
	const clusterID = "cl_test_concurrent"
	addr := newTestGateway(t, gw, ca, clusterID)

	const n = 5
	var seedEvents []corev1.Event
	for i := 0; i < n; i++ {
		seedEvents = append(seedEvents, corev1.Event{
			ObjectMeta:     metav1.ObjectMeta{Name: fmt.Sprintf("ev%d", i), Namespace: fmt.Sprintf("ns-%d", i)},
			InvolvedObject: corev1.ObjectReference{Kind: "Pod", Name: fmt.Sprintf("pod-%d", i)},
			Reason:         fmt.Sprintf("reason-%d", i),
		})
	}
	typed := k8sfake.NewSimpleClientset()
	for i := range seedEvents {
		if _, err := typed.CoreV1().Events(seedEvents[i].Namespace).Create(context.Background(), &seedEvents[i], metav1.CreateOptions{}); err != nil {
			t.Fatalf("seed event %d: %v", i, err)
		}
	}
	executor := agent.NewToolExecutorForTest(typed, dynamicfake.NewSimpleDynamicClient(k8sscheme.Scheme))

	conn := dialTestAgent(t, addr, ca, clusterID)
	waitForConnRegistered(t, gw, clusterID)
	// Staggered, inverted delay: the LAST request issued gets the SHORTEST
	// delay, so if correlation were broken (e.g. results delivered to
	// whichever caller happens to be waiting rather than the one that
	// matches CorrelationID), out-of-order completion would surface it.
	go respondToToolRequestsWithPerNamespaceDelay(conn, executor, n)

	var wg sync.WaitGroup
	errs := make([]error, n)
	got := make([]string, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			data, err := gw.CallTool(ctx, clusterID, "get_events", mustJSON(t, map[string]string{"namespace": fmt.Sprintf("ns-%d", i)}))
			if err != nil {
				errs[i] = err
				return
			}
			var results []map[string]any
			if err := json.Unmarshal(data, &results); err != nil {
				errs[i] = err
				return
			}
			if len(results) != 1 {
				errs[i] = fmt.Errorf("got %d results, want 1: %+v", len(results), results)
				return
			}
			got[i], _ = results[0]["reason"].(string)
		}(i)
	}
	wg.Wait()

	for i := 0; i < n; i++ {
		if errs[i] != nil {
			t.Errorf("call %d: %v", i, errs[i])
			continue
		}
		want := fmt.Sprintf("reason-%d", i)
		if got[i] != want {
			t.Errorf("call %d: got reason %q, want %q — a correlation mismatch under concurrency", i, got[i], want)
		}
	}
}

// TestCallTool_HighConcurrencyNeverDropsAFastResponse is the regression test
// for a real bug found live (not in a test), documented in WORKLOG.md §114
// and in CallTool's own "register before send" doc comment: the old code sent the
// ToolRequest and only registered the pending channel afterward, inside
// what was then the first step of awaitResult. Under enough concurrent
// callers contending on the same connection's writeMu/pendingMu, a fast
// enough agent response could round-trip back and be read by
// serveClientMessages BEFORE the caller had registered anything to receive
// it — silently dropped by deliver, with the caller then blocking for the
// full timeout on a call the agent had, in reality, already answered
// correctly.
//
// This reproduces it directly: many concurrent CallTool calls against one
// connection, answered by respondToToolRequests with NO artificial delay
// (0, unlike TestCallTool_ConcurrentCallsCorrelateCorrectly's staggered
// version, which exists to catch a DIFFERENT bug — misrouting by position
// instead of by id — and whose smallest injected delay, 15ms, is itself
// orders of magnitude larger than the register-after-send window this test
// targets, which is why it never caught this one). Each call carries its
// own SHORT per-call context deadline rather than relying on
// toolCallTimeout's real 30s, so a reintroduced regression fails this test
// in well under a second instead of 30s per dropped call. The race is
// timing-dependent, not guaranteed on every single call, which is exactly
// why this drives enough concurrent load (both a high fan-out and several
// repeated rounds) to make a reintroduced ordering bug fail reliably rather
// than only occasionally — the real incident this guards against took just
// 2-3 concurrent investigations against one cluster to reproduce.
func TestCallTool_HighConcurrencyNeverDropsAFastResponse(t *testing.T) {
	ca, err := NewEphemeralDevCA()
	if err != nil {
		t.Fatalf("new dev CA: %v", err)
	}
	gw := NewGateway(nil, ca, events.NewBus())
	const clusterID = "cl_test_high_concurrency"
	addr := newTestGateway(t, gw, ca, clusterID)

	const perRound = 40
	const rounds = 5

	var seedEvents []corev1.Event
	for i := 0; i < perRound; i++ {
		seedEvents = append(seedEvents, corev1.Event{
			ObjectMeta:     metav1.ObjectMeta{Name: fmt.Sprintf("ev%d", i), Namespace: fmt.Sprintf("ns-%d", i)},
			InvolvedObject: corev1.ObjectReference{Kind: "Pod", Name: fmt.Sprintf("pod-%d", i)},
			Reason:         fmt.Sprintf("reason-%d", i),
		})
	}
	typed := k8sfake.NewSimpleClientset()
	for i := range seedEvents {
		if _, err := typed.CoreV1().Events(seedEvents[i].Namespace).Create(context.Background(), &seedEvents[i], metav1.CreateOptions{}); err != nil {
			t.Fatalf("seed event %d: %v", i, err)
		}
	}
	executor := agent.NewToolExecutorForTest(typed, dynamicfake.NewSimpleDynamicClient(k8sscheme.Scheme))

	conn := dialTestAgent(t, addr, ca, clusterID)
	waitForConnRegistered(t, gw, clusterID)
	go respondToToolRequests(conn, executor, 0) // no artificial delay — respond as fast as possible

	for round := 0; round < rounds; round++ {
		var wg sync.WaitGroup
		errs := make([]error, perRound)
		for i := 0; i < perRound; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				// Short deadline, deliberately: a dropped response should
				// surface fast, not after the real 30s toolCallTimeout.
				ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
				defer cancel()
				_, err := gw.CallTool(ctx, clusterID, "get_events", mustJSON(t, map[string]string{"namespace": fmt.Sprintf("ns-%d", i)}))
				errs[i] = err
			}(i)
		}
		wg.Wait()

		for i, err := range errs {
			if err != nil {
				t.Fatalf("round %d, call %d: %v (a fast agent response was dropped because the pending channel wasn't registered before the request was sent)", round, i, err)
			}
		}
	}
}

// TestDisconnect_ClosesLiveConnection proves Gateway.Disconnect actually
// severs an already-open tunnel connection — the gap this increment closes:
// previously, only a *reconnect* attempt from a decommissioned cluster was
// refused (lookupClusterBySerial's clusterState check in server.go); a
// connection that was already live when the cluster was decommissioned kept
// running until it happened to drop on its own. This asserts all three
// observable consequences of a real close: the agent side's read
// eventually errors, the connection disappears from the gateway's registry,
// and a subsequent CallTool fails immediately rather than hanging.
func TestDisconnect_ClosesLiveConnection(t *testing.T) {
	ca, err := NewEphemeralDevCA()
	if err != nil {
		t.Fatalf("new dev CA: %v", err)
	}
	gw := NewGateway(nil, ca, events.NewBus())
	const clusterID = "cl_test_disconnect"
	addr := newTestGateway(t, gw, ca, clusterID)

	conn := dialTestAgent(t, addr, ca, clusterID)
	waitForConnRegistered(t, gw, clusterID)

	if ok := gw.Disconnect(clusterID); !ok {
		t.Fatal("Disconnect on a live connection: want true (a connection was found and closed), got false")
	}

	// Reading from the AGENT side must now observe the hub side closing —
	// proof this actually closed the underlying transport (making
	// serveClientMessages' scanner.Scan() read loop return), not just
	// deleted a registry entry the agent-side connection would never
	// notice.
	if err := conn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}
	buf := make([]byte, 1)
	if _, err := conn.Read(buf); err == nil {
		t.Fatal("read from the agent side after Disconnect: want an error (connection closed by the hub), got none")
	}

	// The registry entry should also be gone shortly after — serveClientMessages'
	// deferred cleanup (unregisterConn/markClosed) runs once its read loop
	// notices the close, which races this test's own observation above, so
	// poll briefly rather than asserting instantaneously.
	deadline := time.Now().Add(2 * time.Second)
	for {
		if _, ok := gw.getConn(clusterID, tunnel.RoleInvestigate); !ok {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("cluster still registered in the connection registry 2s after Disconnect")
		}
		time.Sleep(5 * time.Millisecond)
	}

	// A CallTool against this now-disconnected cluster must behave exactly
	// like CallTool against one that never connected at all — fail fast,
	// not hang until toolCallTimeout.
	start := time.Now()
	if _, err := gw.CallTool(context.Background(), clusterID, "get_events", nil); err == nil {
		t.Fatal("CallTool after Disconnect: want error, got nil")
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("CallTool after Disconnect took %v — want an immediate failure, not a wait", elapsed)
	}
}

// TestDisconnect_UnknownClusterIsNoop covers the ordinary case
// handleDecommissionCluster hits far more often than a live tunnel actually
// being open at decommission time: a cluster with no registered connection
// at all. Disconnect must report that plainly (false, no panic/error) rather
// than assume its caller already checked IsConnected first.
func TestDisconnect_UnknownClusterIsNoop(t *testing.T) {
	ca, err := NewEphemeralDevCA()
	if err != nil {
		t.Fatalf("new dev CA: %v", err)
	}
	gw := NewGateway(nil, ca, events.NewBus())

	if ok := gw.Disconnect("cluster-that-never-connected"); ok {
		t.Fatal("Disconnect on a cluster with no live connection: want false, got true")
	}
}

// respondToToolRequestsWithPerNamespaceDelay is respondToToolRequests with
// a delay derived from the request's own namespace argument, so responses
// to concurrently-issued calls complete in a scrambled order rather than
// FIFO — the scenario that would actually expose a correlation-by-position
// bug instead of a correlation-by-ID one.
func respondToToolRequestsWithPerNamespaceDelay(conn net.Conn, executor *agent.ToolExecutor, n int) {
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
		go func() {
			var args struct {
				Namespace string `json:"namespace"`
			}
			_ = json.Unmarshal(req.Args, &args)
			var idx int
			_, _ = fmt.Sscanf(args.Namespace, "ns-%d", &idx)
			// Reverse order: namespace ns-0 (likely issued first) waits
			// longest, ns-(n-1) (likely issued last) returns first.
			time.Sleep(time.Duration(n-idx) * 15 * time.Millisecond)

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
