package gateway

// PROJECT.md T11's finding-ingestion and queue-depth metrics, proven to
// actually move — not just registered — against a real tunnel connection.
// Reuses the exact slow-model-ask infrastructure
// finding_heartbeat_concurrency_test.go's own BUGS.md 131 regression already
// established (slowCompleter, newTestGateway, dialTestAgent), because a
// controllable delay on the Finding-processing path is exactly what's needed
// to observe metrics.FindingProcessingInflight rise above zero while a
// Finding is in flight and fall back afterward.

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"argus/internal/data"
	"argus/internal/dbtest"
	"argus/internal/events"
	"argus/internal/metrics"
	"argus/internal/tunnel"
)

// gaugeValue scrapes DefaultRegistry for one bare (no-label) gauge's current
// value, or 0 if absent.
func gaugeValue(t *testing.T, name string) float64 {
	t.Helper()
	var buf strings.Builder
	metrics.DefaultRegistry.WriteExposition(&buf)
	want := name + " "
	for _, line := range strings.Split(buf.String(), "\n") {
		if strings.HasPrefix(line, want) {
			var v float64
			if _, err := fmt.Sscanf(strings.TrimPrefix(line, want), "%g", &v); err != nil {
				t.Fatalf("parse gauge line %q: %v", line, err)
			}
			return v
		}
	}
	return 0
}

func counterValue(t *testing.T, name string, labels map[string]string) float64 {
	t.Helper()
	var buf strings.Builder
	metrics.DefaultRegistry.WriteExposition(&buf)
	parts := make([]string, 0, len(labels))
	for k, v := range labels {
		parts = append(parts, fmt.Sprintf(`%s="%s"`, k, v))
	}
	want := fmt.Sprintf("%s{%s} ", name, strings.Join(parts, ","))
	for _, line := range strings.Split(buf.String(), "\n") {
		if strings.HasPrefix(line, want) {
			var v float64
			if _, err := fmt.Sscanf(strings.TrimPrefix(line, want), "%g", &v); err != nil {
				t.Fatalf("parse counter line %q: %v", line, err)
			}
			return v
		}
	}
	return 0
}

// TestFindingProcessingInflight_RisesWhileProcessingAndFallsAfter proves
// argus_finding_processing_inflight is a real, moving gauge: it must be
// above zero while a deliberately slow Finding is still being processed,
// and must return to exactly what it was before once processing finishes —
// never left stuck high, which would itself misrepresent a healthy gateway
// as permanently backed up.
func TestFindingProcessingInflight_RisesWhileProcessingAndFallsAfter(t *testing.T) {
	pool := testPool(t)
	tenantID, clusterID, _, fixture := correlationCluster(t, pool)
	kind, condType := "InflightMetricRegressionKind", "Ready"
	fixture.Cleanup(pool, correlationSetScope(tenantID, clusterID), []dbtest.TableDelete{
		{Table: "clusters", SQL: `DELETE FROM clusters WHERE id = $1`, Args: []any{clusterID}},
	})

	ca, err := NewEphemeralDevCA()
	if err != nil {
		t.Fatalf("new dev CA: %v", err)
	}

	const delay = 500 * time.Millisecond
	completer := slowCompleter{delay: delay, text: "False", model: "inflight-test-model", done: make(chan struct{}), started: make(chan struct{})}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if _, err := pool.Exec(ctx, `DELETE FROM condition_polarity WHERE kind = $1 AND condition_type = $2`, kind, condType); err != nil {
			t.Errorf("cleanup condition_polarity row: %v", err)
		}
	})
	// Registered LAST among this test's own cleanups, so — t.Cleanup runs
	// LIFO — it runs FIRST, before either delete above. That ordering is
	// the actual fix for BUGS.md/PROJECT.md B191's leak: a prior version of
	// this test could fail (t.Fatalf) on the "did the gauge rise" check
	// while processFindingAsync's background goroutine was still inside
	// slowCompleter's sleep, and t.Fatalf aborts the test body immediately —
	// none of the code below the failing assertion runs, including the
	// `<-completer.done` wait the happy path relies on. The clusters-row
	// delete then ran while that goroutine was still going to write its
	// condition_polarity row later, and on an unluckier timing could race a
	// findings-table write against the same cluster row. Waiting here,
	// unconditionally, in a cleanup of its own, means every exit path from
	// this test — pass or any failure — blocks until the background
	// goroutine has actually finished before any row it touched gets
	// deleted out from under it.
	t.Cleanup(func() {
		select {
		case <-completer.done:
		case <-time.After(delay + 5*time.Second):
			t.Errorf("background finding processing never completed its model ask before cleanup ran")
			return
		}
		// Matches the same post-Complete grace the happy path below waits
		// out: handleFinding still has DB work left (here, the
		// condition_polarity write) after the completer answers, and the
		// deletes registered above must not run until that has landed.
		time.Sleep(250 * time.Millisecond)
	})

	gw := NewGateway(&data.DB{Pool: pool}, ca, events.NewBus())
	gw.LLM = completer

	addr := newTestGateway(t, gw, ca, clusterID)
	conn := dialTestAgent(t, addr, ca, clusterID)
	waitForConnRegistered(t, gw, clusterID)

	before := gaugeValue(t, "argus_finding_processing_inflight")

	enc := json.NewEncoder(conn)
	findingMsg := tunnel.ClientMessage{
		Finding: &tunnel.Finding{
			DetectorID:             "k8s-sweep",
			Fingerprint:            "fp-inflight-metric-regression",
			GVK:                    "example.com/v1/" + kind,
			ObjectName:             "obj-1",
			Reason:                 "GenericConditionAnomaly:" + condType,
			Message:                "Ready reads False, differing from this object's peers",
			Severity:               "high",
			OccurredAt:             time.Now(),
			ConditionType:          condType,
			ConditionObservedValue: "True",
			ConditionSampleCount:   1,
		},
	}
	if err := enc.Encode(findingMsg); err != nil {
		t.Fatalf("send finding: %v", err)
	}

	// Wait for the slow completer to actually be entered, rather than
	// polling the gauge against a wall-clock deadline: processFindingAsync
	// increments metrics.FindingProcessingInflight synchronously, several
	// calls up the same goroutine's stack, strictly before handleFinding
	// can reach the polarity gate that calls Complete. Once started is
	// closed, the Inc is guaranteed to have already happened — no sleep
	// loop, and no "did the goroutine even get scheduled yet" race.
	select {
	case <-completer.started:
	case <-time.After(5 * time.Second):
		t.Fatalf("background finding processing never reached the model ask")
	}
	if got := gaugeValue(t, "argus_finding_processing_inflight"); got <= before {
		t.Fatalf("argus_finding_processing_inflight = %v, want > its pre-send value (%v), once the delayed Finding's model ask had definitely started", got, before)
	}

	select {
	case <-completer.done:
	case <-time.After(delay + 5*time.Second):
		t.Fatalf("background finding processing never completed its model ask")
	}
	// A little slack past the model ask returning, matching
	// finding_heartbeat_concurrency_test.go's own precedent: handleFinding
	// still has DB work left after the completer answers, and the gauge
	// only falls once processFindingAsync's goroutine actually returns.
	time.Sleep(250 * time.Millisecond)

	after := gaugeValue(t, "argus_finding_processing_inflight")
	if after != before {
		t.Fatalf("argus_finding_processing_inflight = %v after processing finished, want back to its pre-send value %v — it must not stay stuck high", after, before)
	}
}

// TestFindingsProcessedTotal_MovesOnDroppedPolarityHealthy proves
// argus_findings_processed_total actually increments for a real disposition
// (a Finding the polarity gate confidently resolves as healthy and drops in
// full), not merely that the metric is registered.
func TestFindingsProcessedTotal_MovesOnDroppedPolarityHealthy(t *testing.T) {
	pool := testPool(t)
	tenantID, clusterID, _, fixture := correlationCluster(t, pool)
	kind, condType := "ProcessedTotalRegressionKind", "Ready"
	fixture.Cleanup(pool, correlationSetScope(tenantID, clusterID), []dbtest.TableDelete{
		{Table: "clusters", SQL: `DELETE FROM clusters WHERE id = $1`, Args: []any{clusterID}},
	})

	ca, err := NewEphemeralDevCA()
	if err != nil {
		t.Fatalf("new dev CA: %v", err)
	}

	completer := slowCompleter{delay: 0, text: "False", model: "processed-total-test-model", done: make(chan struct{})}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if _, err := pool.Exec(ctx, `DELETE FROM condition_polarity WHERE kind = $1 AND condition_type = $2`, kind, condType); err != nil {
			t.Errorf("cleanup condition_polarity row: %v", err)
		}
	})

	gw := NewGateway(&data.DB{Pool: pool}, ca, events.NewBus())
	gw.LLM = completer

	addr := newTestGateway(t, gw, ca, clusterID)
	conn := dialTestAgent(t, addr, ca, clusterID)
	waitForConnRegistered(t, gw, clusterID)

	before := counterValue(t, "argus_findings_processed_total", map[string]string{"outcome": "dropped_polarity_healthy"})

	enc := json.NewEncoder(conn)
	findingMsg := tunnel.ClientMessage{
		Finding: &tunnel.Finding{
			DetectorID:             "k8s-sweep",
			Fingerprint:            "fp-processed-total-regression",
			GVK:                    "example.com/v1/" + kind,
			ObjectName:             "obj-1",
			Reason:                 "GenericConditionAnomaly:" + condType,
			Message:                "Ready reads False, differing from this object's peers",
			Severity:               "high",
			OccurredAt:             time.Now(),
			ConditionType:          condType,
			ConditionObservedValue: "True",
			ConditionSampleCount:   1,
		},
	}
	if err := enc.Encode(findingMsg); err != nil {
		t.Fatalf("send finding: %v", err)
	}

	select {
	case <-completer.done:
	case <-time.After(5 * time.Second):
		t.Fatalf("background finding processing never completed its model ask")
	}
	time.Sleep(250 * time.Millisecond)

	after := counterValue(t, "argus_findings_processed_total", map[string]string{"outcome": "dropped_polarity_healthy"})
	if after != before+1 {
		t.Fatalf(`argus_findings_processed_total{outcome="dropped_polarity_healthy"} went from %v to %v, want exactly +1`, before, after)
	}
}
