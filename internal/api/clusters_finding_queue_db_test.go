package api

// PROJECT.md B176's residual, at the API layer: the agent's cap-triggered
// finding loss has to reach an operator, and the hub's only way to say so is
// this route. Proven against a REAL clusters row rather than a mocked DB,
// because the whole contract is about the difference between a stored NULL
// and a stored 0 — which is exactly the distinction a mock is most likely to
// paper over.

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"argus/internal/data"
)

func setClusterFindingQueue(t *testing.T, pool *pgxpool.Pool, tenantID, clusterID string, pending, dropped, capacity *int) {
	t.Helper()
	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if err := data.SetRequestScope(ctx, tx, tenantID, []string{clusterID}); err != nil {
		t.Fatalf("set request scope: %v", err)
	}
	if _, err := tx.Exec(ctx,
		`UPDATE clusters SET finding_queue_pending = $2, finding_queue_dropped = $3, finding_queue_capacity = $4 WHERE id = $1`,
		clusterID, pending, dropped, capacity); err != nil {
		t.Fatalf("update finding queue columns: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit: %v", err)
	}
}

func TestHandleGetClusterReportsFindingQueueLoss(t *testing.T) {
	pool := authTestPool(t)
	ctx := context.Background()
	tenantID, err := singleOrgIDForTest(ctx, pool)
	if err != nil {
		t.Fatalf("resolve tenant: %v", err)
	}
	clusterID := clusterGroupTestCluster(t, pool, tenantID)
	s := &Server{db: &data.DB{Pool: pool}}

	// An agent that does not report it (every build before
	// tunnel.Heartbeat.FindingQueue, and any cluster that has not
	// heartbeated since). The field must be null, not an object of zeroes —
	// "we do not know" is not "nothing has been dropped".
	body := getClusterViaHandler(t, s, pool, tenantID, clusterID)
	if fq, present := body["findingQueue"]; !present {
		t.Error(`the response has no "findingQueue" key at all; it must be present and null, so a client can tell "unknown" from a field it forgot to read`)
	} else if fq != nil {
		t.Errorf(`body["findingQueue"] = %v, want null for an agent that does not report it — an object of zeroes here would tell an operator this cluster has lost nothing`, fq)
	}

	// An agent that is losing findings right now.
	pending, dropped, capacity := 4998, 137, 5000
	setClusterFindingQueue(t, pool, tenantID, clusterID, &pending, &dropped, &capacity)

	body = getClusterViaHandler(t, s, pool, tenantID, clusterID)
	fq, ok := body["findingQueue"].(map[string]any)
	if !ok {
		t.Fatalf(`body["findingQueue"] = %v (%T), want an object`, body["findingQueue"], body["findingQueue"])
	}
	for field, want := range map[string]float64{"pending": 4998, "dropped": 137, "capacity": 5000} {
		if got, _ := fq[field].(float64); got != want {
			t.Errorf(`findingQueue[%q] = %v, want %v`, field, fq[field], want)
		}
	}
}
