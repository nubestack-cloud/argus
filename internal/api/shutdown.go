// shutdown.go is the hub's half of PROJECT.md B162's graceful-shutdown path:
// the in-process state that makes a SIGTERM a *drain* rather than a severing.
// cmd/hub/main.go owns the ordering (readiness off, HTTP drain, WebSocket
// drain, workers, tunnel, database); this file owns the two pieces of that
// sequence that have to live next to the handlers they affect.
//
//  1. shuttingDown, read by handleReadyz (server.go). Flipping it is what
//     takes this hub out of a Service's endpoints BEFORE anything stops
//     accepting, so the last requests routed here are ones it can still
//     finish. handleHealthz deliberately does NOT read it: liveness must stay
//     green for the whole drain, or kubelet kills the process mid-flight and
//     the drain was pointless.
//
//  2. The WebSocket drain. net/http's Server.Shutdown does not wait for —
//     and cannot close — a HIJACKED connection, which is exactly what every
//     GET /ws/events is after wsUpgrader.Upgrade. Without this, an HTTP
//     "graceful" shutdown returns immediately while every live browser feed
//     is still attached, and the process exit then drops them as an abrupt
//     TCP close (the browser reports a 1006 abnormal closure). So each
//     connection's own goroutine selects on wsDrain and sends a real 1001
//     "going away" close frame itself — never a second goroutine writing to
//     someone else's conn, which gorilla/websocket's single-concurrent-writer
//     rule forbids (see serveWSClient's writeMu-free single-writer shape).
package api

import (
	"context"
	"log/slog"
	"time"
)

// BeginShutdown marks this hub as draining: /readyz starts answering 503 and
// new WebSocket upgrades are refused, while every already-accepted request
// keeps being served and /healthz keeps answering 200.
//
// Idempotent, and safe on a bare &Server{} (this package's test convention).
func (s *Server) BeginShutdown() {
	s.shuttingDown.Store(true)
}

// IsShuttingDown reports whether BeginShutdown has been called.
func (s *Server) IsShuttingDown() bool {
	return s.shuttingDown.Load()
}

// DrainWebSockets closes every live /ws/events connection with a 1001 "going
// away" close frame and waits for their goroutines to finish, bounded by ctx.
// Returns the number of connections that were still open when the drain
// started, and whether every one of them finished before ctx expired.
//
// Called AFTER the HTTP drain, not with it: an in-flight REST request may
// still publish an event onto the bus, and a browser that is about to be told
// "going away" should see that last event rather than a closed socket.
//
// Idempotent. A Server built as a bare struct literal has no wsDrain channel
// and no registered connections, so this is a no-op there rather than a
// close-of-nil-channel panic.
func (s *Server) DrainWebSockets(ctx context.Context) (open int, drained bool) {
	if s.wsDrain == nil {
		return 0, true
	}
	s.wsDrainOnce.Do(func() { close(s.wsDrain) })

	open = int(s.wsOpen.Load())
	done := make(chan struct{})
	go func() {
		s.wsActive.Wait()
		close(done)
	}()
	select {
	case <-done:
		return open, true
	case <-ctx.Done():
		logger.WarnContext(ctx, "WebSocket connections did not close within the drain window", slog.Int64("open", s.wsOpen.Load()))
		return open, false
	}
}

// wsDrainClosed reports whether the WebSocket drain has begun. serveWSClient
// checks it once at connect time to cover the (small) race where a connection
// is accepted between DrainWebSockets closing the channel and the handler
// reaching its select loop.
func (s *Server) wsDrainClosed() bool {
	if s.wsDrain == nil {
		return false
	}
	select {
	case <-s.wsDrain:
		return true
	default:
		return false
	}
}

// DefaultShutdownGrace is how long cmd/hub/main.go gives each phase of the
// drain by default. Exported so the chart's terminationGracePeriodSeconds and
// this value cannot drift apart silently — see
// deploy/helm/argus-hub/templates/deployment.yaml, which sets a grace period
// comfortably larger than the worst-case total.
const DefaultShutdownGrace = 15 * time.Second
