package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"argus/internal/events"
)

// ws_shutdown_test.go covers the half of PROJECT.md B162's drain that
// http.Server.Shutdown structurally cannot do: a /ws/events connection is
// HIJACKED, so Shutdown neither waits for it nor closes it. Without an
// explicit drain, the "graceful" HTTP shutdown returns while every browser
// feed is still attached and the process exit then drops them mid-frame.
//
// These tests drive serveWSClient directly rather than going through
// handleWSEvents, which would need a ticket issuer, a grants table and a
// database to resolve scope against — none of which this behaviour depends on.

// wsDrainTestServer upgrades one connection and hands it to serveWSClient,
// exactly as handleWSEvents does after its auth checks.
func wsDrainTestServer(t *testing.T, s *Server) (*websocket.Conn, func()) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := wsUpgrader.Upgrade(w, r, nil)
		if err != nil {
			t.Errorf("upgrade: %v", err)
			return
		}
		s.serveWSClient(conn, "usr_test", wsEventScope{incidents: true, clusters: true})
	}))
	client, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(srv.URL, "http"), nil)
	if err != nil {
		srv.Close()
		t.Fatalf("dial: %v", err)
	}
	return client, func() {
		_ = client.Close()
		srv.Close()
	}
}

// TestDrainWebSocketsSendsGoingAwayAndWaits is the behaviour an operator sees
// during a rollout: the browser is told 1001 "going away" — a normal closure
// it reconnects from on its own schedule — rather than having its socket
// vanish (which surfaces as a 1006 abnormal closure). DrainWebSockets must
// also WAIT for the connection's goroutine, so the process does not exit while
// that close frame is still queued.
func TestDrainWebSocketsSendsGoingAwayAndWaits(t *testing.T) {
	s := &Server{events: events.NewBus(), wsDrain: make(chan struct{})}
	client, cleanup := wsDrainTestServer(t, s)
	defer cleanup()

	// Wait until the server side has registered, so the assertion below is
	// about a drained connection rather than a race with the upgrade.
	deadline := time.Now().Add(2 * time.Second)
	for s.wsOpen.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if s.wsOpen.Load() != 1 {
		t.Fatalf("wsOpen = %d after connect, want 1", s.wsOpen.Load())
	}

	readResult := make(chan error, 1)
	go func() {
		for {
			if _, _, err := client.ReadMessage(); err != nil {
				readResult <- err
				return
			}
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	open, drained := s.DrainWebSockets(ctx)
	if open != 1 {
		t.Errorf("DrainWebSockets reported %d open connection(s), want 1", open)
	}
	if !drained {
		t.Error("DrainWebSockets reported the drain as incomplete, want it to have waited for the connection's goroutine")
	}
	if left := s.wsOpen.Load(); left != 0 {
		t.Errorf("wsOpen = %d after a completed drain, want 0 — DrainWebSockets returned before the connection's goroutine finished", left)
	}

	select {
	case err := <-readResult:
		if !websocket.IsCloseError(err, websocket.CloseGoingAway) {
			t.Errorf("client saw %v, want a 1001 going-away close — an abnormal closure (1006) is what an undrained process exit produces", err)
		}
	case <-time.After(5 * time.Second):
		t.Error("client never saw a close frame")
	}
}

// TestWSConnectDuringDrainClosesImmediately covers the race the drain cannot
// prevent, only handle: a connection accepted between DrainWebSockets closing
// the channel and the handler goroutine being scheduled. It must be told to go
// away rather than left attached to a hub that is about to exit.
func TestWSConnectDuringDrainClosesImmediately(t *testing.T) {
	s := &Server{events: events.NewBus(), wsDrain: make(chan struct{})}
	if open, drained := s.DrainWebSockets(context.Background()); open != 0 || !drained {
		t.Fatalf("pre-drain = (%d, %t), want (0, true)", open, drained)
	}

	client, cleanup := wsDrainTestServer(t, s)
	defer cleanup()

	_ = client.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, _, err := client.ReadMessage()
	if !websocket.IsCloseError(err, websocket.CloseGoingAway) {
		t.Errorf("client connecting mid-drain saw %v, want a 1001 going-away close", err)
	}
}

// TestNewWSUpgradeRefusedWhileDraining pins the front door: once the hub is
// draining, a new feed is refused with a 503 BEFORE the connect ticket is
// redeemed (a ticket is single-use, so redeeming one on a hub that is about to
// close the socket would force the client to mint another before it could
// reconnect). This Server has no ticket issuer at all, so a check ordered
// after redemption would panic here rather than answer.
func TestNewWSUpgradeRefusedWhileDraining(t *testing.T) {
	s := &Server{events: events.NewBus(), wsDrain: make(chan struct{})}
	s.BeginShutdown()

	rec := httptest.NewRecorder()
	s.handleWSEvents(rec, httptest.NewRequest(http.MethodGet, "/ws/events?ticket=whatever", nil))

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("GET /ws/events while draining = %d, want %d", rec.Code, http.StatusServiceUnavailable)
	}
}
