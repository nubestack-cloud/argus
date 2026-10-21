package main

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// A worker run under runExclusive must give its lock connection back when it
// stops. It used to close the connection without releasing it, so the pool
// still counted it as acquired and the hub's deferred pool.Close() waited
// forever: every shutdown hung until the kubelet killed the pod, about a
// minute later, and the replacement hub (and every agent's reconnect) waited
// with it.
func TestRunExclusiveReleasesItsConnectionSoThePoolCanClose(t *testing.T) {
	conn := os.Getenv("ARGUS_TEST_DATABASE_URL")
	if conn == "" {
		t.Skip("ARGUS_TEST_DATABASE_URL not set; skipping the DB-backed runExclusive test")
	}
	pool, err := pgxpool.New(context.Background(), conn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	ran := make(chan struct{})
	done := make(chan struct{})
	go func() {
		// A key no real sweeper uses.
		runExclusive(ctx, pool, 990001, "test worker", func() { close(ran); <-ctx.Done() })
		close(done)
	}()
	select {
	case <-ran:
	case <-time.After(10 * time.Second):
		t.Fatal("the worker never ran: the advisory lock was not acquired")
	}
	cancel()
	<-done

	closed := make(chan struct{})
	go func() { pool.Close(); close(closed) }()
	select {
	case <-closed:
	case <-time.After(5 * time.Second):
		t.Fatal("pool.Close() is still waiting: runExclusive did not release its connection")
	}
}
