package gateway

// PROJECT.md T1's fourth named importance factor, workload criticality:
// migration 000111's incidents.pod_priority column must be written from
// tunnel.Finding.PodPriority at incident-open time, through the real
// ingestion entry point ((g *Gateway).handleFinding) under RLS, and it must
// come through as NULL — never a fabricated 0 — for a Finding whose object
// isn't a Pod (the same "absent means unknown" contract
// ClusterRemediation/ClusterDetectors already document in
// internal/tunnel/protocol.go, and internal/importance.Factors.
// WorkloadCriticality's own doc comment restates for this exact column).
//
// Not provable in pure Go: what's being tested is which SQL statement
// writes the column, under RLS, through handleFinding — the same reasoning
// opening_rule_db_test.go gives for testing BUGS.md 94 the same way. Uses
// finding_db_test.go's testPool harness (argus_app, not the superuser).

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"argus/internal/data"
	"argus/internal/dbtest"
	"argus/internal/domain"
	"argus/internal/tunnel"
)

func podPriorityTestCluster(t *testing.T, pool *pgxpool.Pool) (tenantID, clusterID string, fixture *dbtest.Fixture) {
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
	fixture = dbtest.New(t)
	fixture.OwnsCluster(tenantID, clusterID)
	if _, err := tx.Exec(ctx,
		`INSERT INTO clusters (id, tenant_id, display_name, state, shard_id, cluster_fingerprint)
		 VALUES ($1, $2, $3, 'Active', 'shard-test', $4)`,
		clusterID, tenantID, "podpriority-test-"+clusterID, "fp-"+clusterID); err != nil {
		t.Fatalf("insert cluster: %v", err)
	}
	fixture.Created("clusters", 1)
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit setup: %v", err)
	}
	return tenantID, clusterID, fixture
}

func podPriorityCleanup(fixture *dbtest.Fixture, pool *pgxpool.Pool, tenantID, clusterID string) {
	fixture.Cleanup(pool, func(ctx context.Context, tx pgx.Tx) error {
		return data.SetRequestScope(ctx, tx, tenantID, []string{clusterID})
	}, []dbtest.TableDelete{
		{Table: "timeline_events", SQL: `DELETE FROM timeline_events WHERE cluster_id = $1`, Args: []any{clusterID}},
		{Table: "findings", SQL: `DELETE FROM findings WHERE cluster_id = $1`, Args: []any{clusterID}},
		{Table: "incidents", SQL: `DELETE FROM incidents WHERE cluster_id = $1`, Args: []any{clusterID}},
		{Table: "clusters", SQL: `DELETE FROM clusters WHERE id = $1`, Args: []any{clusterID}},
	})
}

func podPriorityFor(t *testing.T, pool *pgxpool.Pool, tenantID, clusterID, objectKey string) *int32 {
	t.Helper()
	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin lookup: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if err := data.SetRequestScope(ctx, tx, tenantID, []string{clusterID}); err != nil {
		t.Fatalf("scope: %v", err)
	}
	rows, err := tx.Query(ctx, `SELECT pod_priority FROM incidents WHERE cluster_id = $1 AND object_key = $2`, clusterID, objectKey)
	if err != nil {
		t.Fatalf("query incidents: %v", err)
	}
	defer rows.Close()
	var podPriority *int32
	found := 0
	for rows.Next() {
		found++
		if err := rows.Scan(&podPriority); err != nil {
			t.Fatalf("scan incident: %v", err)
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate incidents: %v", err)
	}
	if found != 1 {
		t.Fatalf("found %d incidents for object %s, want exactly 1", found, objectKey)
	}
	return podPriority
}

func int32Ptr(v int32) *int32 { return &v }

// TestHandleFinding_PersistsPodPriorityAtIncidentCreation is the first half
// of the acceptance proof: a Pod Finding carrying a resolved priority must
// land on incidents.pod_priority, through the real ingestion path.
func TestHandleFinding_PersistsPodPriorityAtIncidentCreation(t *testing.T) {
	pool := testPool(t)
	tenantID, clusterID, fixture := podPriorityTestCluster(t, pool)
	fixture.Created("incidents", 1)
	fixture.Created("findings", 1)
	fixture.Created("timeline_events", 1)
	podPriorityCleanup(fixture, pool, tenantID, clusterID)
	g := &Gateway{db: &data.DB{Pool: pool}}
	ctx := context.Background()

	const (
		gvk       = "v1/Pod"
		namespace = "argus-podpriority-test"
		name      = "critical-pod"
	)
	objectKey := gvk + "|" + namespace + "|" + name

	f := &tunnel.Finding{
		DetectorID:      "k8s-pod-conditions",
		DetectorVersion: "v1",
		Fingerprint:     "test-fp-podpriority-1",
		GVK:             gvk,
		Namespace:       namespace,
		ObjectName:      name,
		ObjectUID:       "uid-podpriority-1",
		ResourceVersion: "1",
		Reason:          "OOMKilled",
		Message:         "container was OOMKilled",
		OccurrenceCount: 1,
		Severity:        "high",
		OccurredAt:      time.Now(),
		PodPriority:     int32Ptr(2000000000),
	}
	if err := g.handleFinding(ctx, clusterID, f); err != nil {
		t.Fatalf("handleFinding: %v", err)
	}

	got := podPriorityFor(t, pool, tenantID, clusterID, objectKey)
	if got == nil || *got != 2000000000 {
		gotStr := "NULL"
		if got != nil {
			gotStr = "not NULL"
		}
		t.Fatalf("pod_priority = %s, want 2000000000", gotStr)
	}
}

// TestHandleFinding_NonPodFindingLeavesPodPriorityNull is the second half:
// a Finding whose object isn't a Pod (a Service here) must never persist a
// fabricated 0 — NULL, meaning "unknown", is the only honest value.
func TestHandleFinding_NonPodFindingLeavesPodPriorityNull(t *testing.T) {
	pool := testPool(t)
	tenantID, clusterID, fixture := podPriorityTestCluster(t, pool)
	fixture.Created("incidents", 1)
	fixture.Created("findings", 1)
	fixture.Created("timeline_events", 1)
	podPriorityCleanup(fixture, pool, tenantID, clusterID)
	g := &Gateway{db: &data.DB{Pool: pool}}
	ctx := context.Background()

	const (
		gvk       = "v1/Service"
		namespace = "argus-podpriority-test"
		name      = "checkout-svc"
	)
	objectKey := gvk + "|" + namespace + "|" + name

	// A Service Finding never carries PodPriority (the agent only sets it
	// for a "v1/Pod" GVK) — this Finding leaves it at its Go zero value,
	// nil, exactly as an agent producing this Finding would.
	f := &tunnel.Finding{
		DetectorID:      "k8s-sweep",
		DetectorVersion: "v1",
		Fingerprint:     "test-fp-podpriority-2",
		GVK:             gvk,
		Namespace:       namespace,
		ObjectName:      name,
		ObjectUID:       "uid-podpriority-2",
		ResourceVersion: "1",
		Reason:          "ServiceNoEndpoints",
		Message:         "service has no endpoints",
		OccurrenceCount: 1,
		Severity:        "high",
		OccurredAt:      time.Now(),
	}
	if err := g.handleFinding(ctx, clusterID, f); err != nil {
		t.Fatalf("handleFinding: %v", err)
	}

	got := podPriorityFor(t, pool, tenantID, clusterID, objectKey)
	if got != nil {
		t.Fatalf("pod_priority = %d, want NULL — this Finding's object is a Service, not a Pod", *got)
	}
}
