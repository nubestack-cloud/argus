package gateway

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

// BACKLOG.md AZ1 / item #13's regression test.
//
// Live on rke2 (CAPABILITIES.md §6br, DEPL-017): a Recreate-strategy rollout's
// Warning events resolved workloadKey via a live Get of the Pod
// (internal/agent/workload.go's resolveWorkloadForInvolvedObject) that can
// fail on the FIRST Finding for a pod — the pod already gone (the old,
// terminating replica) or a transient API error (workload.go's own comments
// name both) — and, unlike an object with genuinely no owning workload, that
// null was never revisited: incidents.workload_key is written once, at
// INSERT, and correlationIdentity's "workload" tier looks up ONLY by
// workload_key, so a LATER Finding for the very same pod that DOES resolve a
// workload cannot find the incident that first Finding opened (it has
// workload_key = NULL, and the lookup is `WHERE workload_key = $2`) — and
// opens a SECOND incident for the exact same object instead, the opposite of
// what this whole mechanism exists to prevent.
//
// Uses finding_db_test.go's testPool harness (argus_app, not the superuser),
// and calls the real (g *Gateway).handleFinding twice, in the order the live
// case produced: resolution-failed first, resolution-succeeded second.
// workloadBackfillTestCluster inserts a throwaway cluster and returns a
// dbtest.Fixture the caller must finish tracking and clean up itself: the
// findings/incidents/timeline_events rows this fixture's cluster ends up with
// are produced by production code (handleFinding) called from the test body,
// not known until after that runs — see this package's other _db_test.go
// files for the same shape and CLAUDE.md-adjacent task notes on why Cleanup
// is deliberately NOT called here.
func workloadBackfillTestCluster(t *testing.T, pool *pgxpool.Pool) (tenantID, clusterID string, fixture *dbtest.Fixture) {
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
		clusterID, tenantID, "workloadbackfill-test-"+clusterID, "fp-"+clusterID); err != nil {
		t.Fatalf("insert cluster: %v", err)
	}
	fixture.Created("clusters", 1)
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit setup: %v", err)
	}
	return tenantID, clusterID, fixture
}

// workloadBackfillCleanup registers this fixture's cleanup, once the caller
// knows exactly how many findings/incidents/timeline_events rows its own
// handleFinding calls produced.
func workloadBackfillCleanup(fixture *dbtest.Fixture, pool *pgxpool.Pool, tenantID, clusterID string) {
	fixture.Cleanup(pool, func(ctx context.Context, tx pgx.Tx) error {
		return data.SetRequestScope(ctx, tx, tenantID, []string{clusterID})
	}, []dbtest.TableDelete{
		{Table: "timeline_events", SQL: `DELETE FROM timeline_events WHERE cluster_id = $1`, Args: []any{clusterID}},
		{Table: "findings", SQL: `DELETE FROM findings WHERE cluster_id = $1`, Args: []any{clusterID}},
		{Table: "incidents", SQL: `DELETE FROM incidents WHERE cluster_id = $1`, Args: []any{clusterID}},
		{Table: "clusters", SQL: `DELETE FROM clusters WHERE id = $1`, Args: []any{clusterID}},
	})
}

// workloadBackfillFor reads back the incident(s) for this test's object, with
// the column the bug is about.
func workloadBackfillFor(t *testing.T, pool *pgxpool.Pool, tenantID, clusterID, objectKey string) (ids []string, workloadKeys []*string) {
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
	rows, err := tx.Query(ctx,
		`SELECT id, workload_key FROM incidents WHERE cluster_id = $1 AND object_key = $2 ORDER BY first_seen`,
		clusterID, objectKey)
	if err != nil {
		t.Fatalf("query incidents: %v", err)
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		var wk *string
		if err := rows.Scan(&id, &wk); err != nil {
			t.Fatalf("scan incident: %v", err)
		}
		ids = append(ids, id)
		workloadKeys = append(workloadKeys, wk)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate incidents: %v", err)
	}
	return ids, workloadKeys
}

func TestAZ1_LaterResolvedWorkloadKeyJoinsTheSameIncidentAndBackfills(t *testing.T) {
	pool := testPool(t)
	tenantID, clusterID, fixture := workloadBackfillTestCluster(t, pool)
	// One incident (both handleFinding calls correlate into it: the second
	// finds the first via AZ1's own object-tier fallback), one findings row
	// per handleFinding call, and exactly one IncidentOpened timeline row —
	// the second call never changes incident state, so it writes no
	// timeline_events row of its own.
	fixture.Created("incidents", 1)
	fixture.Created("findings", 2)
	fixture.Created("timeline_events", 1)
	workloadBackfillCleanup(fixture, pool, tenantID, clusterID)
	g := &Gateway{db: &data.DB{Pool: pool}}
	ctx := context.Background()

	const (
		podGVK    = "v1/Pod"
		namespace = "argus-az1-test"
		podName   = "depl17-recreate-abc123"
		reason    = "Unhealthy"
		workload  = "apps/v1/Deployment|argus-az1-test|depl17-recreate"
	)
	objectKey := podGVK + "|" + namespace + "|" + podName

	// 1. The Warning event's FIRST Finding: the agent's live Get of the Pod
	//    failed (workload.go's resolveWorkloadForInvolvedObject returns
	//    ok=false on a not-yet-gettable or already-gone Pod, or a transient
	//    API error) — WorkloadName comes back empty, exactly like a bare Pod
	//    with no controller would, even though this Pod has one.
	unresolved := &tunnel.Finding{
		DetectorID:      "k8s-warning-events",
		DetectorVersion: "v1",
		Fingerprint:     "test-fp-az1-unresolved",
		GVK:             podGVK,
		Namespace:       namespace,
		ObjectName:      podName,
		ObjectUID:       "uid-az1",
		ResourceVersion: "1",
		Reason:          reason,
		Message:         "Readiness probe failed",
		OccurrenceCount: 1,
		Severity:        "high",
		OccurredAt:      time.Now(),
		// WorkloadGVK/WorkloadName deliberately left empty.
	}
	if err := g.handleFinding(ctx, clusterID, unresolved); err != nil {
		t.Fatalf("handleFinding(unresolved): %v", err)
	}

	ids, workloadKeys := workloadBackfillFor(t, pool, tenantID, clusterID, objectKey)
	if len(ids) != 1 {
		t.Fatalf("after the first finding: found %d incidents for object %s, want exactly 1", len(ids), objectKey)
	}
	firstIncidentID := ids[0]
	if workloadKeys[0] != nil {
		t.Fatalf("incident %s has workload_key = %q after a resolution-failed finding, want NULL", firstIncidentID, *workloadKeys[0])
	}

	// 2. The SAME warning recurs 5s later (the readiness probe keeps failing).
	//    This time the agent's retry succeeds — the exact scenario the item's
	//    own text argues for: "a Pod's OwnerReferences never change, so there
	//    is no staleness risk to retrying."
	resolved := &tunnel.Finding{
		DetectorID:      "k8s-warning-events",
		DetectorVersion: "v1",
		Fingerprint:     "test-fp-az1-resolved",
		GVK:             podGVK,
		Namespace:       namespace,
		ObjectName:      podName,
		ObjectUID:       "uid-az1",
		ResourceVersion: "2",
		Reason:          reason,
		Message:         "Readiness probe failed",
		OccurrenceCount: 1,
		Severity:        "high",
		OccurredAt:      time.Now(),
		WorkloadGVK:     "apps/v1/Deployment",
		WorkloadName:    "depl17-recreate",
	}
	if err := g.handleFinding(ctx, clusterID, resolved); err != nil {
		t.Fatalf("handleFinding(resolved): %v", err)
	}

	ids, workloadKeys = workloadBackfillFor(t, pool, tenantID, clusterID, objectKey)
	if len(ids) != 1 {
		t.Fatalf("after the second finding: found %d incidents for object %s, want exactly 1 — a later Finding whose workload resolution SUCCEEDED must join the SAME pod's already-open incident, not open a duplicate (ids=%v)", len(ids), objectKey, ids)
	}
	if ids[0] != firstIncidentID {
		t.Fatalf("the resolved finding opened a DIFFERENT incident (%s, was %s) for the same pod object — correlation must never duplicate an incident for the exact same object", ids[0], firstIncidentID)
	}
	if workloadKeys[0] == nil || *workloadKeys[0] != workload {
		got := "NULL"
		if workloadKeys[0] != nil {
			got = *workloadKeys[0]
		}
		t.Fatalf("incident %s has workload_key = %s, want %q — a later finding that successfully resolves the workload must backfill it, since a Pod's OwnerReferences never change once set (BACKLOG.md AZ1)", firstIncidentID, got, workload)
	}
}

// The other half of the decision: an incident that ALREADY has a workload_key
// keeps it — this is a backfill of an empty slot, never an overwrite (mirrors
// BUGS.md 94's opening_rule_id discipline). Also a regression guard for the
// UNCHANGED, correct behaviour this fix must not disturb: A3a's display-only
// per-pod grouping was superseded (BACKLOG.md's own §14.4 table) by keying
// correlation on workload ALONE, so two DIFFERENT pods that both resolve the
// SAME workload from the start correctly MERGE into one incident — this
// fallback only ever reaches an object-tier match for THIS finding's own
// object_key, so it can never be what causes (or prevents) that merge.
func TestAZ1_ExistingWorkloadKeyIsNeverOverwritten(t *testing.T) {
	pool := testPool(t)
	tenantID, clusterID, fixture := workloadBackfillTestCluster(t, pool)
	// One incident (pod A opens it, pod B's shared workload merges into it,
	// pod A's later finding stays on it too), three findings rows (one per
	// handleFinding call below), and exactly one IncidentOpened timeline row
	// — none of the later calls change incident state.
	fixture.Created("incidents", 1)
	fixture.Created("findings", 3)
	fixture.Created("timeline_events", 1)
	workloadBackfillCleanup(fixture, pool, tenantID, clusterID)
	g := &Gateway{db: &data.DB{Pool: pool}}
	ctx := context.Background()

	const (
		podGVK    = "v1/Pod"
		namespace = "argus-az1-test"
		reason    = "Unhealthy"
		workload  = "apps/v1/Deployment|argus-az1-test|web"
	)

	finding := func(podName, fingerprint, workloadGVK, workloadName string) *tunnel.Finding {
		return &tunnel.Finding{
			DetectorID:      "k8s-warning-events",
			DetectorVersion: "v1",
			Fingerprint:     fingerprint,
			GVK:             podGVK,
			Namespace:       namespace,
			ObjectName:      podName,
			ObjectUID:       "uid-az1-" + podName,
			ResourceVersion: "1",
			Reason:          reason,
			Message:         "Readiness probe failed",
			OccurrenceCount: 1,
			Severity:        "high",
			OccurredAt:      time.Now(),
			WorkloadGVK:     workloadGVK,
			WorkloadName:    workloadName,
		}
	}

	// Pod A resolves its workload correctly from the start.
	if err := g.handleFinding(ctx, clusterID, finding("web-aaa", "test-fp-az1-siba", "apps/v1/Deployment", "web")); err != nil {
		t.Fatalf("handleFinding(pod A): %v", err)
	}
	// A second, DIFFERENT pod of the SAME workload, also resolved from the
	// start: workload-tier correlation (A3a, superseded) means this is
	// EXPECTED to join pod A's incident rather than open its own — unrelated
	// to this fix, and asserted here only so a future change to that
	// behaviour is caught by the right test rather than this one.
	if err := g.handleFinding(ctx, clusterID, finding("web-bbb", "test-fp-az1-sibb", "apps/v1/Deployment", "web")); err != nil {
		t.Fatalf("handleFinding(pod B): %v", err)
	}

	idsA, wkA := workloadBackfillFor(t, pool, tenantID, clusterID, podGVK+"|"+namespace+"|web-aaa")
	if len(idsA) != 1 {
		t.Fatalf("want exactly one incident for pod A, got %d", len(idsA))
	}
	if wkA[0] == nil || *wkA[0] != workload {
		t.Fatalf("pod A's workload_key = %v, want %q", wkA[0], workload)
	}

	// A later finding on pod A, resolving to a DIFFERENT-looking workload
	// value (not a scenario a real Pod can produce — its OwnerReferences
	// never change — but the invariant must hold regardless of why the
	// value differs), must never overwrite the first. Only an empty slot is
	// ever filled.
	if err := g.handleFinding(ctx, clusterID, finding("web-aaa", "test-fp-az1-siba2", "apps/v1/Deployment", "web-should-never-appear")); err != nil {
		t.Fatalf("handleFinding(pod A again): %v", err)
	}
	idsA2, wkA2 := workloadBackfillFor(t, pool, tenantID, clusterID, podGVK+"|"+namespace+"|web-aaa")
	if len(idsA2) != 1 || idsA2[0] != idsA[0] {
		t.Fatalf("pod A's recurring finding must stay on its own incident (%v), got %v", idsA, idsA2)
	}
	if wkA2[0] == nil || *wkA2[0] != workload {
		t.Fatalf("pod A's workload_key changed to %v after a later finding — an existing value must never be overwritten", wkA2[0])
	}
}
