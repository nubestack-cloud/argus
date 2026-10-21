package gateway

import (
	"context"
	"encoding/json"
	"net"
	"testing"
	"time"

	"argus/internal/tunnel"
)

// shutdown_test.go covers the tunnel half of PROJECT.md B162's graceful
// shutdown. No live cluster and no database: a Gateway with an ephemeral dev
// CA can listen and accept for real, which is everything Shutdown has to act
// on.

// freeLocalAddr reserves a loopback port and releases it, so the listener
// under test can bind a port this test knows the number of (ListenAndServeTLS
// takes an address rather than returning one).
func freeLocalAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve a port: %v", err)
	}
	addr := ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatalf("release the reserved port: %v", err)
	}
	return addr
}

// TestShutdownStopsAcceptingAndReturnsCleanly is the property the drain in
// cmd/hub/main.go depends on: Shutdown closes the listener, ListenAndServeTLS
// returns nil (a closed listener is not an error — the accept loop's own
// net.ErrClosed check), and nothing can connect afterwards.
func TestShutdownStopsAcceptingAndReturnsCleanly(t *testing.T) {
	ca, err := NewEphemeralDevCA()
	if err != nil {
		t.Fatalf("NewEphemeralDevCA: %v", err)
	}
	g := NewGateway(nil, ca, nil)

	addr := freeLocalAddr(t)
	served := make(chan error, 1)
	go func() { served <- g.ListenAndServeTLS(addr, []string{"localhost", "127.0.0.1"}) }()

	// Wait until it is actually accepting. A bare TCP dial is enough — the
	// mTLS handshake would need a client cert this test has no reason to
	// issue, and what is being proved here is only that accept is live.
	if !dialSucceedsWithin(addr, 3*time.Second) {
		t.Fatal("tunnel listener never started accepting")
	}

	if closed := g.Shutdown(context.Background()); closed != 0 {
		t.Errorf("Shutdown reported %d agent connection(s) closed, want 0 — none were registered", closed)
	}

	select {
	case err := <-served:
		if err != nil {
			t.Errorf("ListenAndServeTLS returned %v after Shutdown, want nil — a deliberately closed listener is not a failure, and cmd/hub's goroutine treats a non-nil error here as fatal", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("ListenAndServeTLS did not return after Shutdown — the accept loop is not watching its listener being closed")
	}

	if dialSucceedsWithin(addr, 250*time.Millisecond) {
		t.Error("the tunnel port still accepts connections after Shutdown")
	}
}

// TestShutdownClosesRegisteredAgentConnections proves the part that matters to
// an enrolled cluster: an open tunnel is closed, so the agent learns at once
// that this hub is gone and redials (internal/agent's serveTunnelForever
// treats a session ending as routine and backs off), rather than holding a
// socket to a dead process.
func TestShutdownClosesRegisteredAgentConnections(t *testing.T) {
	g := NewGateway(nil, nil, nil)

	hubSide, agentSide := net.Pipe()
	defer agentSide.Close()
	g.registerConn("cl_test", newAgentConn("cl_test", tunnel.RoleAll, hubSide, json.NewEncoder(hubSide)))

	if closed := g.Shutdown(context.Background()); closed != 1 {
		t.Errorf("Shutdown reported %d agent connection(s) closed, want 1", closed)
	}

	// The agent's end of a closed pipe reads io.EOF / io.ErrClosedPipe
	// immediately, which is exactly the signal its reconnect loop acts on.
	_ = agentSide.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1)
	if _, err := agentSide.Read(buf); err == nil {
		t.Error("the agent side of the tunnel is still readable after Shutdown — the connection was not closed")
	}
}

// TestShutdownBeforeListenPreventsServing closes the startup race: a SIGTERM
// that lands while the process is still coming up must not leave a tunnel
// listener accepting for the lifetime of a hub that has already decided to
// stop.
func TestShutdownBeforeListenPreventsServing(t *testing.T) {
	ca, err := NewEphemeralDevCA()
	if err != nil {
		t.Fatalf("NewEphemeralDevCA: %v", err)
	}
	g := NewGateway(nil, ca, nil)
	g.Shutdown(context.Background())

	addr := freeLocalAddr(t)
	served := make(chan error, 1)
	go func() { served <- g.ListenAndServeTLS(addr, []string{"localhost", "127.0.0.1"}) }()

	select {
	case err := <-served:
		if err != nil {
			t.Errorf("ListenAndServeTLS after Shutdown returned %v, want nil", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("ListenAndServeTLS kept serving after Shutdown had already been called")
	}
	if dialSucceedsWithin(addr, 250*time.Millisecond) {
		t.Error("the tunnel port accepts connections although Shutdown preceded the listen")
	}
}

func dialSucceedsWithin(addr string, d time.Duration) bool {
	deadline := time.Now().Add(d)
	for {
		conn, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(10 * time.Millisecond)
	}
}
