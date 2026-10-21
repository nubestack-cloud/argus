package gateway

// PROJECT.md B176's residual, hub side: at the agent's 5,000-finding
// capacity bound the loss was loud in that pod's log and reached nobody.
// The agent now reports its queue depth and running discard total on every
// heartbeat (tunnel.Heartbeat.FindingQueue) and handleHeartbeat stores them
// on the clusters row (migration 000118), which is what the cluster detail
// route serves.
//
// Both directions of the absent case are asserted here, because getting one
// of them wrong is what would make the whole signal untrustworthy: an agent
// that predates the field must leave NULL, never a zero that reads as "this
// agent has never dropped a finding".

import (
	"context"
	"testing"

	"argus/internal/data"
	"argus/internal/tunnel"
)

func TestHandleHeartbeatStoresFindingQueueStatus(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	tenantID, clusterID, fixture := timelineTestCluster(t, pool)
	// Nothing but the cluster row: a heartbeat writes no findings,
	// incidents or timeline events, so those tables are declared at zero
	// rather than left untracked (dbtest refuses a delete for a table the
	// fixture never counted).
	fixture.Created("findings", 0)
	fixture.Created("incidents", 0)
	fixture.Created("timeline_events", 0)
	timelineCleanup(fixture, pool, tenantID, clusterID)

	g := &Gateway{db: &data.DB{Pool: pool}}

	readQueue := func(t *testing.T) (pending, dropped, capacity *int) {
		t.Helper()
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatalf("begin: %v", err)
		}
		defer tx.Rollback(ctx) //nolint:errcheck
		if err := data.SetRequestScope(ctx, tx, tenantID, []string{clusterID}); err != nil {
			t.Fatalf("set request scope: %v", err)
		}
		if err := tx.QueryRow(ctx,
			`SELECT finding_queue_pending, finding_queue_dropped, finding_queue_capacity FROM clusters WHERE id = $1`,
			clusterID).Scan(&pending, &dropped, &capacity); err != nil {
			t.Fatalf("read finding queue columns: %v", err)
		}
		return pending, dropped, capacity
	}

	// An agent that predates the field: three NULLs, which is "we do not
	// know", not "nothing has been dropped".
	if err := g.handleHeartbeat(ctx, clusterID, &tunnel.Heartbeat{AgentVersion: "0.0.1-old"}); err != nil {
		t.Fatalf("handleHeartbeat (old agent): %v", err)
	}
	if pending, dropped, capacity := readQueue(t); pending != nil || dropped != nil || capacity != nil {
		t.Fatalf("an agent reporting no finding-queue status stored %v/%v/%v, want all NULL — a zero here would tell an operator this agent has never lost a finding, which nobody asked it", pending, dropped, capacity)
	}

	// An agent that does report it, and is losing findings.
	if err := g.handleHeartbeat(ctx, clusterID, &tunnel.Heartbeat{
		AgentVersion: tunnel.AgentBuildVersion,
		FindingQueue: &tunnel.FindingQueueStatus{Pending: 4998, Dropped: 137, Capacity: 5000},
	}); err != nil {
		t.Fatalf("handleHeartbeat (reporting agent): %v", err)
	}
	pending, dropped, capacity := readQueue(t)
	if pending == nil || dropped == nil || capacity == nil {
		t.Fatalf("stored %v/%v/%v, want all three present", pending, dropped, capacity)
	}
	if *pending != 4998 || *dropped != 137 || *capacity != 5000 {
		t.Fatalf("stored pending=%d dropped=%d capacity=%d, want 4998/137/5000", *pending, *dropped, *capacity)
	}

	// And an agent that restarts (counter back to zero) stores a real zero,
	// distinguishable from the NULL above.
	if err := g.handleHeartbeat(ctx, clusterID, &tunnel.Heartbeat{
		AgentVersion: tunnel.AgentBuildVersion,
		FindingQueue: &tunnel.FindingQueueStatus{Pending: 0, Dropped: 0, Capacity: 5000},
	}); err != nil {
		t.Fatalf("handleHeartbeat (restarted agent): %v", err)
	}
	pending, dropped, _ = readQueue(t)
	if pending == nil || dropped == nil || *pending != 0 || *dropped != 0 {
		t.Fatalf("stored pending=%v dropped=%v, want a real 0 for each — a restarted agent genuinely has an empty queue and a reset counter, and that is a different answer from NULL", pending, dropped)
	}
}
