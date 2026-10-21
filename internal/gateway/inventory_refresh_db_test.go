package gateway

// inventory_refresh_db_test.go is the hub half of PROJECT.md B177. The agent
// half (internal/agent/client_facts_refresh_test.go) proves a connected agent
// re-sends its ClusterFacts without reconnecting; this proves the hub adopts
// the newer payload wholesale on the SAME connection — a second
// InventoryDelta is not a no-op, does not merge with the first, and advances
// cluster_facts.updated_at, which is the freshness stamp the API now serves
// beside the facts themselves (internal/api's handleGetCluster).
//
// Skips cleanly with no ARGUS_TEST_DATABASE_URL, like every *_db_test.go in
// this package. Point it at argus_app, not postgres: postgres carries
// rolbypassrls, which makes every RLS assertion in this package vacuous.

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"argus/internal/data"
	"argus/internal/dbtest"
	"argus/internal/domain"
	"argus/internal/tunnel"
)

// inventoryRefreshCluster inserts a throwaway Active cluster and registers
// cleanup for it and the cluster_facts row handleInventoryDelta writes under
// it. Uses internal/dbtest rather than hand-written DELETEs — see
// CLAUDE.md's own warning about why that package exists.
func inventoryRefreshCluster(t *testing.T, pool *pgxpool.Pool) (tenantID, clusterID string, fixture *dbtest.Fixture) {
	t.Helper()
	ctx := context.Background()
	clusterID = domain.NewID(domain.PrefixCluster)

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin setup: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	tenantID, err = data.SingleOrganisationID(ctx, tx)
	if err != nil {
		t.Fatalf("resolve organisation: %v", err)
	}
	if err := data.SetRequestScope(ctx, tx, tenantID, []string{clusterID}); err != nil {
		t.Fatalf("set request scope: %v", err)
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO clusters (id, tenant_id, display_name, state, shard_id, cluster_fingerprint)
		 VALUES ($1, $2, $3, 'Active', 'shard-test', $4)`,
		clusterID, tenantID, "inventory-refresh-test-"+clusterID, "fp-"+clusterID); err != nil {
		t.Fatalf("insert cluster: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit setup: %v", err)
	}

	fixture = dbtest.New(t)
	fixture.OwnsCluster(tenantID, clusterID)
	fixture.Created("clusters", 1)
	return tenantID, clusterID, fixture
}

// inventoryRefreshCleanup is registered once the caller knows how many
// cluster_facts rows its production-code calls actually produced — the
// fixture insists on that pairing rather than guessing.
func inventoryRefreshCleanup(fixture *dbtest.Fixture, pool *pgxpool.Pool, tenantID, clusterID string) {
	fixture.Cleanup(pool, func(ctx context.Context, tx pgx.Tx) error {
		return data.SetRequestScope(ctx, tx, tenantID, []string{clusterID})
	}, []dbtest.TableDelete{
		{Table: "cluster_facts", SQL: `DELETE FROM cluster_facts WHERE cluster_id = $1`, Args: []any{clusterID}},
		{Table: "clusters", SQL: `DELETE FROM clusters WHERE id = $1`, Args: []any{clusterID}},
	})
}

// readStoredFacts returns the stored facts payload and the moment the hub
// last wrote it.
func readStoredFacts(t *testing.T, pool *pgxpool.Pool, tenantID, clusterID string) (tunnel.ClusterFacts, time.Time) {
	t.Helper()
	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin read: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if err := data.SetRequestScope(ctx, tx, tenantID, []string{clusterID}); err != nil {
		t.Fatalf("set request scope: %v", err)
	}
	var raw []byte
	var updatedAt time.Time
	if err := tx.QueryRow(ctx, `SELECT facts, updated_at FROM cluster_facts WHERE cluster_id = $1`, clusterID).Scan(&raw, &updatedAt); err != nil {
		t.Fatalf("read cluster_facts: %v", err)
	}
	var facts tunnel.ClusterFacts
	if err := json.Unmarshal(raw, &facts); err != nil {
		t.Fatalf("decode stored facts: %v", err)
	}
	return facts, updatedAt
}

// TestHandleInventoryDeltaAdoptsARefreshOnTheSameConnection is B177's hub-side
// acceptance: the operator-visible facts the hub reports must come from the
// agent's LATEST payload, not its first. The second delta below is what a
// connected agent now sends every agent.factsRefreshInterval — a detector
// that has since succeeded, and a read RBAC has since revoked.
func TestHandleInventoryDeltaAdoptsARefreshOnTheSameConnection(t *testing.T) {
	pool := testPool(t)
	tenantID, clusterID, fixture := inventoryRefreshCluster(t, pool)
	// One row, however many deltas arrive: the upsert is keyed on
	// cluster_id, which is exactly why a refresh cannot become a second,
	// competing source of facts.
	fixture.Created("cluster_facts", 1)
	inventoryRefreshCleanup(fixture, pool, tenantID, clusterID)
	g := &Gateway{db: &data.DB{Pool: pool}}
	ctx := context.Background()

	// What a session's first InventoryDelta looks like: the snapshot is taken
	// before the sweep detector's first tick, so it has nothing to report and
	// nothing is denied.
	connect := tunnel.ClusterFacts{
		KubernetesVersion: "v1.34.0",
		NodeCount:         1,
		Nodes:             []tunnel.NodeStatus{{Name: "node-a", Ready: true}},
		Reachable:         true,
		Detectors:         &tunnel.ClusterDetectors{},
	}
	if err := g.handleInventoryDelta(ctx, clusterID, &tunnel.InventoryDelta{Facts: connect, FullResync: true}); err != nil {
		t.Fatalf("handleInventoryDelta (connect): %v", err)
	}
	stored, firstUpdatedAt := readStoredFacts(t, pool, tenantID, clusterID)
	if !stored.Detectors.Sweep.LastSuccessAt.IsZero() || len(stored.Detectors.Sweep.DeniedReads) != 0 {
		t.Fatalf("connect-time facts should report nothing observed and nothing denied, got %+v", stored.Detectors.Sweep)
	}

	swept := time.Now().UTC().Truncate(time.Second)
	refresh := connect
	refresh.Detectors = &tunnel.ClusterDetectors{
		Sweep: tunnel.DetectorStatus{LastSuccessAt: swept, DeniedReads: []string{"ingresses"}},
	}
	if err := g.handleInventoryDelta(ctx, clusterID, &tunnel.InventoryDelta{Facts: refresh, FullResync: true}); err != nil {
		t.Fatalf("handleInventoryDelta (refresh): %v", err)
	}

	stored, secondUpdatedAt := readStoredFacts(t, pool, tenantID, clusterID)
	if got := stored.Detectors.Sweep.LastSuccessAt; !got.Equal(swept) {
		t.Errorf("stored sweep LastSuccessAt = %v, want %v — the hub kept the connect-time snapshot", got, swept)
	}
	if got := stored.Detectors.Sweep.DeniedReads; len(got) != 1 || got[0] != "ingresses" {
		t.Errorf("stored sweep DeniedReads = %v, want [ingresses] — an operator is still being told nothing is blocked", got)
	}
	if !secondUpdatedAt.After(firstUpdatedAt) {
		t.Errorf("cluster_facts.updated_at did not advance (%v -> %v); it is what the API serves as factsUpdatedAt, so a stale snapshot would read as a fresh one", firstUpdatedAt, secondUpdatedAt)
	}
}
