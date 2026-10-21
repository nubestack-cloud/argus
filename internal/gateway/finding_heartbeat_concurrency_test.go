package gateway

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"argus/internal/data"
	"argus/internal/dbtest"
	"argus/internal/events"
	"argus/internal/llm"
	"argus/internal/tunnel"
)

// slowCompleter is an llm.Completer that sleeps before answering, then
// signals done — standing in for BUGS.md 131's real-world trigger: a
// condition-polarity model ask (applyConditionPolarityGate ->
// internal/conditionpolarity.Resolve -> askModelPolarity) whose actual
// latency, measured on the flapping cluster, was a few seconds per
// never-before-seen (Kind, ConditionType) pair — dominated by spawning
// cmd/cli-runner's `claude` subprocess, not by anything wrong with the
// answer itself. This fake reproduces the SHAPE of that cost (a real,
// multi-second block on the call path) without needing a live model or
// cli-runner in the test.
//
// done is closed exactly once, after Complete returns, purely so the test
// can deterministically wait for the background Finding-processing goroutine
// (dispatched by processFindingAsync, never awaited by the test's own main
// flow) to fully finish before its t.Cleanup steps run — without that wait,
// a still-sleeping goroutine from THIS test can outlive it and commit a
// findings/condition_polarity row after cleanup already ran, corrupting a
// LATER test's cleanup with a stale FK reference. Not a hypothetical: this
// is exactly what happened while writing this test.
//
// started, if non-nil, is closed the instant Complete is entered, before
// the sleep. processFindingAsync increments
// metrics.FindingProcessingInflight synchronously, several calls up the
// same goroutine's stack, before handleFinding ever reaches the polarity
// gate that calls Complete — so a reader that has observed started closed
// is guaranteed the Inc already happened, with no polling or wall-clock
// margin required. finding_metrics_test.go's inflight test uses this
// instead of sleep-polling for the gauge to rise.
type slowCompleter struct {
	delay       time.Duration
	text, model string
	done        chan struct{}
	started     chan struct{}
}

func (s slowCompleter) Complete(_ context.Context, _, _ string) (llm.Result, error) {
	if s.started != nil {
		close(s.started)
	}
	time.Sleep(s.delay)
	close(s.done)
	return llm.Result{Text: s.text, Model: s.model}, nil
}

// TestServeClientMessages_SlowFindingDoesNotStallHeartbeat is the regression
// lock for BUGS.md 131's actual root cause. Measured live against
// `rke2 (personal test)` (a Rancher-managed cluster reporting dozens of
// generic, custom Conditions — Cluster/Project/ClusterRepo/Issuer/etc. — that
// internal/agent's generic-condition-anomaly detector flags one at a time):
// three real Active->Degraded->Disconnected flaps, each while the agent's own
// heartbeat send/ack log showed a perfectly healthy, unbroken 30s cadence and
// the gateway's own tunnel-connect log showed the SAME TCP connection open
// throughout (no redial on either side). The actual mechanism, confirmed by
// docker logs compose-hub-api-1 (BUGS.md 131's evidence section): a burst of
// GenericConditionAnomaly Findings, each needing a synchronous model ask
// that (at the time) failed after ~3-4s per pair with cmd/cli-runner
// uncredentialed, and — even once credentialed and succeeding — still cost
// ~2.5-3s per never-before-cached pair (confirmed against condition_polarity
// rows' own updated_at spacing). Because handleFinding ran INLINE on
// serveClientMessages' single per-connection read loop (before this fix),
// the SAME loop that must also dequeue this cluster's next Heartbeat message
// off the wire fell behind by minutes, so clusters.last_heartbeat_at went
// stale past health.go's disconnectedThreshold even though the agent process
// itself never stopped sending heartbeats and never restarted.
//
// This test proves the fix (processFindingAsync, dispatched from
// serveClientMessages' Finding case): a Finding whose polarity gate needs a
// slow model ask no longer blocks this connection's Heartbeat from being
// processed and acknowledged promptly, and the slow Finding still completes
// and gets cached rather than being silently dropped.
func TestServeClientMessages_SlowFindingDoesNotStallHeartbeat(t *testing.T) {
	pool := testPool(t)
	tenantID, clusterID, _, fixture := correlationCluster(t, pool)
	// The slow completer answers "False" — read by conditionpolarity.Resolve
	// as a confident-healthy verdict — so applyConditionPolarityGate drops
	// this Finding in full before handleFinding ever opens a transaction: no
	// findings row, no incident. Only the throwaway cluster itself needs
	// cleanup.
	fixture.Cleanup(pool, correlationSetScope(tenantID, clusterID), []dbtest.TableDelete{
		{Table: "clusters", SQL: `DELETE FROM clusters WHERE id = $1`, Args: []any{clusterID}},
	})

	ca, err := NewEphemeralDevCA()
	if err != nil {
		t.Fatalf("new dev CA: %v", err)
	}

	// The slow completer's delay must be comfortably longer than how long
	// we're willing to wait for the Heartbeat to land, and comfortably
	// shorter than the test's own overall timeout — 3s hits both: BUGS.md
	// 131's own measured per-pair cost (both the failing-CLI ~3-4s figure
	// and the succeeding-CLI ~2.5-3s figure) lands right around there.
	const slowAskDelay = 3 * time.Second
	kind, condType := "ConcurrencyRegressionKind", "Ready"
	completer := slowCompleter{delay: slowAskDelay, text: "False", model: "slow-test-model", done: make(chan struct{})}

	// Registered FIRST among this test's own cleanups, which — t.Cleanup
	// runs LIFO — means it runs LAST, well after the background Finding
	// goroutine (waited-for below, near the end of this test) has already
	// finished touching the DB.
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

	enc := json.NewEncoder(conn)

	// A GenericConditionAnomaly Finding with too few live peers
	// (ConditionSampleCount well below minStatisticalSampleCount) to resolve
	// statistically, on a (Kind, ConditionType) pair never seen before —
	// forcing applyConditionPolarityGate down Mechanism 2 (ask the model),
	// exactly BUGS.md 131's trigger shape.
	findingMsg := tunnel.ClientMessage{
		Finding: &tunnel.Finding{
			DetectorID:             "k8s-sweep",
			Fingerprint:            "fp-concurrency-regression",
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

	// Sent immediately after, on the SAME connection, with nothing waiting
	// for the Finding's ack first — matching how internal/agent/client.go's
	// runTunnelSession actually interleaves these (a Finding send never
	// waits for its own ack before the next select iteration can send a
	// Heartbeat).
	heartbeatMsg := tunnel.ClientMessage{
		Heartbeat: &tunnel.Heartbeat{AgentVersion: "test-agent", CertExpiresAt: time.Now().Add(time.Hour)},
	}
	if err := enc.Encode(heartbeatMsg); err != nil {
		t.Fatalf("send heartbeat: %v", err)
	}

	// However this test concludes, don't let the test function return (and
	// so run any t.Cleanup step) until the background Finding-processing
	// goroutine has actually finished asking the (fake) model — see
	// slowCompleter's own doc comment for why this matters. Runs even if a
	// later t.Fatalf below Goexits this goroutine, since defers still run
	// during that unwind.
	defer func() {
		select {
		case <-completer.done:
		case <-time.After(slowAskDelay + 5*time.Second):
			t.Errorf("background finding processing never completed its model ask within %s of being sent", slowAskDelay+5*time.Second)
		}
		// A little slack past the model ask itself returning: handleFinding
		// still has to upsert condition_polarity and run the correlation
		// insert in a second transaction before it's truly done touching
		// the DB (the actual FK-safety property this defer exists for).
		time.Sleep(250 * time.Millisecond)
	}()

	// The actual assertion: last_heartbeat_at must land well before
	// slowAskDelay elapses. Before this fix, handleFinding's synchronous
	// model ask ran first (FIFO on the same read goroutine) and the
	// Heartbeat sitting right behind it on the wire wasn't even READ, let
	// alone processed, until the Finding's handler returned — so this
	// would have taken >= slowAskDelay, not "well under it".
	//
	// clusters has FORCE ROW LEVEL SECURITY, and this pool's role (argus_app,
	// same as testPool's every other caller) sees nothing at all unless
	// app.tenant_id/app.accessible_cluster_ids are set on the connection
	// first — see internal/data.SetRequestScope and this package's own
	// "ARGUS dev Postgres access" lesson: a bare SELECT against this pool
	// silently returns zero rows rather than erroring, which would make
	// this assertion pass or fail for the wrong reason entirely.
	readLastHeartbeatAt := func() (time.Time, error) {
		ctx := context.Background()
		tx, err := pool.Begin(ctx)
		if err != nil {
			return time.Time{}, err
		}
		defer tx.Rollback(ctx) //nolint:errcheck
		if err := data.SetRequestScope(ctx, tx, tenantID, []string{clusterID}); err != nil {
			return time.Time{}, err
		}
		var v time.Time
		err = tx.QueryRow(ctx, `SELECT last_heartbeat_at FROM clusters WHERE id = $1`, clusterID).Scan(&v)
		return v, err
	}

	deadline := time.Now().Add(slowAskDelay - 500*time.Millisecond)
	var lastHeartbeatAt *time.Time
	for time.Now().Before(deadline) {
		v, err := readLastHeartbeatAt()
		if err == nil && !v.IsZero() {
			lastHeartbeatAt = &v
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if lastHeartbeatAt == nil {
		t.Fatalf("clusters.last_heartbeat_at was not set within %s of sending the heartbeat — the Heartbeat appears to have been stalled behind the slow Finding (BUGS.md 131's exact regression)", slowAskDelay-500*time.Millisecond)
	}

	// Secondary assertion: the slow Finding was DEFERRED, not dropped — it
	// must still complete and cache a verdict shortly after slowAskDelay
	// elapses. This guards against a "fix" that would make BUGS.md 131 go
	// away by silently discarding the very Findings the polarity gate
	// exists to classify.
	<-completer.done
	cacheDeadline := time.Now().Add(3 * time.Second)
	var cached bool
	for time.Now().Before(cacheDeadline) {
		var source string
		err := pool.QueryRow(context.Background(), `SELECT source FROM condition_polarity WHERE kind = $1 AND condition_type = $2`, kind, condType).Scan(&source)
		if err == nil && source == "model" {
			cached = true
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !cached {
		t.Fatalf("the deferred Finding's polarity ask completed but never got cached in condition_polarity — it looks dropped, not just decoupled from heartbeat timing")
	}
}
