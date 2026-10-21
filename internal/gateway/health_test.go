package gateway

import (
	"context"
	"regexp"
	"strings"
	"testing"
	"time"
)

// TestHealthThresholds guards the two wall-clock thresholds against
// accidental drift from lld/03-agent-protocol.md §7's spec (30s heartbeat
// interval; Degraded at 2 missed / Disconnected at 5 missed, cumulative) —
// no DB needed, this is pure arithmetic.
//
// This test only means anything because sweep's SQL now READS these
// constants (see degradeStaleActiveSQL/disconnectStaleSQL). It used to
// hardcode `interval '75 seconds'` / `interval '150 seconds'` instead, which
// left both constants unreferenced by any non-test code — so this test
// asserted on two numbers the running behaviour never consulted, and would
// have gone on passing while the real thresholds diverged from §7.
// TestDemotionSQLUsesThresholdParameters below keeps that from silently
// coming back.
func TestHealthThresholds(t *testing.T) {
	if degradedThreshold != 75*time.Second {
		t.Errorf("degradedThreshold = %v, want 75s (§7: 2 missed heartbeats at a 30s interval, midpoint of the stated 60-90s jitter range)", degradedThreshold)
	}
	if disconnectedThreshold != 150*time.Second {
		t.Errorf("disconnectedThreshold = %v, want 150s (§7: 5 missed heartbeats x 30s)", disconnectedThreshold)
	}
	if disconnectedThreshold <= degradedThreshold {
		t.Errorf("disconnectedThreshold (%v) must be greater than degradedThreshold (%v) or a cluster could never pass through Degraded on its way to Disconnected", disconnectedThreshold, degradedThreshold)
	}
}

// TestDemotionSQLUsesThresholdParameters is the drift guard that makes
// TestHealthThresholds above load-bearing: each demotion statement must take
// its threshold as a bind parameter, and must not carry a hardcoded seconds
// interval that could disagree with the constant. Without this, someone could
// re-inline `interval '75 seconds'` tomorrow and every test here would still
// pass while the behaviour silently detached from the spec again.
func TestDemotionSQLUsesThresholdParameters(t *testing.T) {
	// Any interval literal with a number in it — `interval '75 seconds'`,
	// `interval '2 minutes'` — is the thing that must not come back. The
	// parameterized form the two statements use is `$1 * interval '1
	// second'`, whose literal is a bare unit multiplied by a bind parameter,
	// so it is matched and excluded explicitly rather than by hoping the
	// pattern misses it.
	numericInterval := regexp.MustCompile(`interval\s+'\s*\d+`)

	for name, sql := range map[string]string{
		"degradeStaleActiveSQL": degradeStaleActiveSQL,
		"disconnectStaleSQL":    disconnectStaleSQL,
	} {
		if !strings.Contains(sql, `$1 * interval '1 second'`) {
			t.Errorf("%s does not take its threshold as a bind parameter — it must read the value from degradedThreshold/disconnectedThreshold, not restate it in SQL", name)
		}
		withoutParameterized := strings.ReplaceAll(sql, `$1 * interval '1 second'`, "")
		if loc := numericInterval.FindString(withoutParameterized); loc != "" {
			t.Errorf("%s contains a hardcoded interval literal (%q) — a threshold spelled out in SQL can drift from the Go constant TestHealthThresholds guards", name, loc)
		}
	}
}

// TestHealthMonitorRunStopsOnContextCancel verifies Run's control flow
// without a database: with ctx already cancelled before Run is even called,
// and interval set far longer than the test timeout, Run must return via the
// ctx.Done() case and must never reach the ticker case (which would call
// sweep and dereference the nil db below). This is the one piece of Run's
// behaviour that's meaningfully testable without a live Postgres — the
// sweep's SQL thresholds themselves are integration-verified instead (see
// STATUS.md).
func TestHealthMonitorRunStopsOnContextCancel(t *testing.T) {
	hm := NewHealthMonitor(nil, nil) // neither ever dereferenced if Run exits via ctx.Done() first

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	done := make(chan struct{})
	go func() {
		hm.Run(ctx, time.Hour) // long enough that the ticker case can't fire first
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return promptly after its context was cancelled")
	}
}
