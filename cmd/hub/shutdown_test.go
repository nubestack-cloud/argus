package main

import (
	"context"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"argus/internal/api"
	"argus/internal/gateway"
)

// shutdown_test.go proves the ORDER of PROJECT.md B162's drain, which is the
// load-bearing part of it. Each phase depends on the ones after it still being
// up, so a drain whose phases are individually correct but ordered wrongly
// severs exactly what it was written to protect:
//
//   - an in-flight HTTP request that is cancelled by the worker phase learns
//     nothing from the API having been "drained" first;
//   - a background sweeper whose cluster tunnel is already gone cannot finish
//     the work the drain waited for.
//
// No live cluster and no database: an http.Server with a slow handler and a
// Gateway with an ephemeral dev CA reproduce both dependencies for real.

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

func TestDrainHubDrainsInOrder(t *testing.T) {
	t.Setenv("ARGUS_SHUTDOWN_READINESS_DELAY_SECONDS", "0") // nothing is watching endpoints in a unit test
	t.Setenv("ARGUS_SHUTDOWN_GRACE_SECONDS", "10")

	// --- the tunnel, phase 5 ---
	ca, err := gateway.NewEphemeralDevCA()
	if err != nil {
		t.Fatalf("NewEphemeralDevCA: %v", err)
	}
	gw := gateway.NewGateway(nil, ca, nil)
	tunnelAddr := freeLocalAddr(t)
	go func() {
		if err := gw.ListenAndServeTLS(tunnelAddr, []string{"localhost", "127.0.0.1"}); err != nil {
			t.Errorf("tunnel listener: %v", err)
		}
	}()
	if !dialSucceedsWithin(tunnelAddr, 3*time.Second) {
		t.Fatal("tunnel listener never came up")
	}

	// --- a background worker, phase 4 ---
	workerCtx, stopWorkers := context.WithCancel(context.Background())
	var workers sync.WaitGroup
	var tunnelReachableWhenWorkerStopped atomic.Bool
	startWorker(&workers, "ordering probe", func() {
		<-workerCtx.Done()
		// A real sweeper finishing its last iteration may still need its
		// cluster's tunnel, so the tunnel must not be gone yet.
		if conn, err := net.DialTimeout("tcp", tunnelAddr, time.Second); err == nil {
			tunnelReachableWhenWorkerStopped.Store(true)
			_ = conn.Close()
		}
	})

	// --- an in-flight HTTP request, phase 2 ---
	var workerStoppedDuringRequest atomic.Bool
	apiAddr := freeLocalAddr(t)
	inFlight := make(chan struct{})
	mux := http.NewServeMux()
	mux.HandleFunc("/slow", func(w http.ResponseWriter, _ *http.Request) {
		close(inFlight)
		time.Sleep(300 * time.Millisecond)
		// The workers this request might depend on must still be running.
		if workerCtx.Err() != nil {
			workerStoppedDuringRequest.Store(true)
		}
		w.WriteHeader(http.StatusOK)
	})
	httpSrv := &http.Server{Addr: apiAddr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = httpSrv.ListenAndServe() }()
	if !dialSucceedsWithin(apiAddr, 3*time.Second) {
		t.Fatal("API listener never came up")
	}

	status := make(chan int, 1)
	go func() {
		resp, err := http.Get("http://" + apiAddr + "/slow")
		if err != nil {
			status <- 0
			return
		}
		defer resp.Body.Close()
		status <- resp.StatusCode
	}()
	<-inFlight // the handler is running; now signal shutdown

	// --- a late listener, phase 5: the MCP listener's stand-in ---
	lateCtx, stopLate := context.WithCancel(context.Background())
	var lateListeners sync.WaitGroup
	var workersStoppedBeforeLateListener atomic.Bool
	startWorker(&lateListeners, "late listener probe", func() {
		<-lateCtx.Done()
		// A worker-driven investigation calls tools back through the MCP
		// listener, so the workers must already be done by the time it goes.
		if workerCtx.Err() != nil {
			workersStoppedBeforeLateListener.Store(true)
		}
	})

	srv := &api.Server{} // BeginShutdown/DrainWebSockets are both zero-value-safe
	done := make(chan struct{})
	go func() {
		drainHub(hubDrain{
			httpSrv:           httpSrv,
			srv:               srv,
			gw:                gw,
			stopWorkers:       stopWorkers,
			workers:           &workers,
			stopLateListeners: stopLate,
			lateListeners:     &lateListeners,
		})
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("drainHub did not finish")
	}

	// Phase 1: readiness must have been flipped, or nothing was taken out of
	// the Service's endpoints before the listener stopped accepting.
	if !srv.IsShuttingDown() {
		t.Error("IsShuttingDown() = false after drainHub — /readyz would still have reported this hub as ready throughout the drain")
	}
	// Phase 2: the in-flight request finished rather than being severed.
	select {
	case code := <-status:
		if code != http.StatusOK {
			t.Errorf("in-flight request finished with status %d, want 200 — the HTTP phase severed it instead of draining it", code)
		}
	case <-time.After(5 * time.Second):
		t.Error("in-flight request never completed")
	}
	if workerStoppedDuringRequest.Load() {
		t.Error("the background workers were cancelled while an HTTP request was still in flight — the worker phase must come AFTER the HTTP phase, because a request may be using them")
	}
	// Phase 5 after phase 4, for the MCP listener as well as the tunnel.
	if !workersStoppedBeforeLateListener.Load() {
		t.Error("the MCP listener was stopped before the workers had finished — a worker-driven investigation calls its tools back through that listener, so it has to outlive the worker phase")
	}
	if !tunnelReachableWhenWorkerStopped.Load() {
		t.Error("the tunnel listener was already closed when the worker phase ran — the tunnel must close LAST, because a sweeper's final iteration may still need it")
	}
	// ...and the tunnel really is closed by the end.
	if dialSucceedsWithin(tunnelAddr, 250*time.Millisecond) {
		t.Error("the tunnel listener is still accepting after drainHub returned")
	}
	// The API listener too.
	if dialSucceedsWithin(apiAddr, 250*time.Millisecond) {
		t.Error("the API listener is still accepting after drainHub returned")
	}
}

// TestDrainHubBoundsASlowRequest pins the other half of phase 2: a request
// that will not finish must not be able to outlast the pod's termination grace
// period, or kubelet SIGKILLs the process and every other phase is skipped. A
// hung investigation request is the realistic case.
func TestDrainHubBoundsASlowRequest(t *testing.T) {
	t.Setenv("ARGUS_SHUTDOWN_READINESS_DELAY_SECONDS", "0")
	t.Setenv("ARGUS_SHUTDOWN_GRACE_SECONDS", "1")

	apiAddr := freeLocalAddr(t)
	inFlight := make(chan struct{})
	release := make(chan struct{})
	mux := http.NewServeMux()
	mux.HandleFunc("/hang", func(w http.ResponseWriter, _ *http.Request) {
		close(inFlight)
		<-release // never released before the drain has given up on it
		w.WriteHeader(http.StatusOK)
	})
	httpSrv := &http.Server{Addr: apiAddr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = httpSrv.ListenAndServe() }()
	if !dialSucceedsWithin(apiAddr, 3*time.Second) {
		t.Fatal("API listener never came up")
	}
	go func() {
		resp, err := http.Get("http://" + apiAddr + "/hang")
		if err == nil {
			_ = resp.Body.Close()
		}
	}()
	<-inFlight
	defer close(release)

	var workers sync.WaitGroup
	_, stopWorkers := context.WithCancel(context.Background())
	started := time.Now()
	drainHub(hubDrain{
		httpSrv:     httpSrv,
		srv:         &api.Server{},
		gw:          gateway.NewGateway(nil, nil, nil),
		stopWorkers: stopWorkers,
		workers:     &workers,
	})
	elapsed := time.Since(started)

	// One second of HTTP grace, plus the WebSocket and tunnel phases' own
	// short constants. Generous upper bound: what this asserts is that the
	// drain ENDS, not how fast.
	if elapsed > 15*time.Second {
		t.Errorf("drainHub took %s against a request that never finishes — the HTTP phase must be bounded by ARGUS_SHUTDOWN_GRACE_SECONDS", elapsed)
	}
}
