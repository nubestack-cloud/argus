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

// fleetGroupTestCluster mirrors objectGroupTestCluster/correlationCluster's
// own throwaway-cluster shape (each of this package's DB test files keeps its
// own copy rather than sharing one — see objectGroupTestCluster's own doc
// comment for why). Returns a dbtest.Fixture the caller must finish tracking
// and clean up itself via fleetGroupCleanup, once it knows how many
// findings/incidents/timeline_events rows its own handleFinding calls
// produced.
func fleetGroupTestCluster(t *testing.T, pool *pgxpool.Pool) (tenantID, clusterID string, fixture *dbtest.Fixture) {
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
		clusterID, tenantID, "fleetgroup-test-"+clusterID, "fp-"+clusterID); err != nil {
		t.Fatalf("insert cluster: %v", err)
	}
	fixture.Created("clusters", 1)
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit setup: %v", err)
	}
	return tenantID, clusterID, fixture
}

// fleetGroupCleanup registers this fixture's cleanup once the caller knows
// exactly how many findings/incidents/timeline_events rows its own
// handleFinding calls produced.
func fleetGroupCleanup(fixture *dbtest.Fixture, pool *pgxpool.Pool, tenantID, clusterID string) {
	fixture.Cleanup(pool, func(ctx context.Context, tx pgx.Tx) error {
		return data.SetRequestScope(ctx, tx, tenantID, []string{clusterID})
	}, []dbtest.TableDelete{
		{Table: "timeline_events", SQL: `DELETE FROM timeline_events WHERE cluster_id = $1`, Args: []any{clusterID}},
		{Table: "findings", SQL: `DELETE FROM findings WHERE cluster_id = $1`, Args: []any{clusterID}},
		{Table: "incidents", SQL: `DELETE FROM incidents WHERE cluster_id = $1`, Args: []any{clusterID}},
		{Table: "clusters", SQL: `DELETE FROM clusters WHERE id = $1`, Args: []any{clusterID}},
	})
}

func fleetGroupIDForFingerprint(t *testing.T, pool *pgxpool.Pool, tenantID, clusterID, fingerprint string) (id string, fleetGroupID *string) {
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
	if err := tx.QueryRow(ctx,
		`SELECT id, fleet_group_id FROM incidents WHERE cluster_id = $1 AND fingerprint = $2`,
		clusterID, fingerprint).Scan(&id, &fleetGroupID); err != nil {
		t.Fatalf("look up incident for fingerprint %s on cluster %s: %v", fingerprint, clusterID, err)
	}
	return id, fleetGroupID
}

// TestBug98_FleetGroupFormsAcrossClusters is the regression test for BUGS.md
// 98: internal/gateway.handleFinding narrowed its transaction's RLS scope to
// the ONE cluster a finding arrived from (data.SetRequestScope(ctx, tx,
// tenantID, []string{clusterID})) and then called fleetgroup.Recompute in
// that SAME transaction — but Recompute's whole job is a cross-cluster query
// with no cluster_id predicate at all. Under RLS that query could
// structurally never see a second cluster's row, so incidents.fleet_group_id
// could never actually be set by the real ingestion path, no matter how
// perfectly two clusters' incidents matched.
//
// This calls the REAL (g *Gateway).handleFinding, unmodified, on two
// DIFFERENT throwaway clusters — the same production entry point the mTLS
// tunnel calls for every Finding — rather than calling
// fleetgroup.Recompute directly, which would prove nothing about this bug
// (fleetgroup_test.go's own unit tests already cover Recompute's decision
// logic in isolation; what was broken is the SCOPE Recompute is called
// under, from its one real caller).
//
// Run as argus_app (ARGUS_TEST_DATABASE_URL), never as the postgres
// superuser — running as postgres bypasses RLS entirely and would make this
// exact bug invisible, since the narrow-scope query would then see every
// cluster regardless of app.accessible_cluster_ids.
func TestBug98_FleetGroupFormsAcrossClusters(t *testing.T) {
	pool := testPool(t)
	tenantID, clusterA, fixtureA := fleetGroupTestCluster(t, pool)
	tenantIDB, clusterB, fixtureB := fleetGroupTestCluster(t, pool)
	// Each cluster's own handleFinding call opens its own incident (fleet
	// grouping is display-only — it never merges incidents across
	// clusters), so one incident, one IncidentOpened event, and one findings
	// row per cluster.
	fixtureA.Created("incidents", 1)
	fixtureA.Created("findings", 1)
	fixtureA.Created("timeline_events", 1)
	fleetGroupCleanup(fixtureA, pool, tenantID, clusterA)
	fixtureB.Created("incidents", 1)
	fixtureB.Created("findings", 1)
	fixtureB.Created("timeline_events", 1)
	fleetGroupCleanup(fixtureB, pool, tenantIDB, clusterB)
	g := &Gateway{db: &data.DB{Pool: pool}}
	ctx := context.Background()

	// computeFingerprint (internal/agent/detector.go) is
	// sha256(namespace, kind, name, reason), deliberately excluding cluster
	// identity — the real precondition for fleet grouping is the identical
	// namespace/object/reason firing on two different clusters, which is
	// exactly BUGS.md 98's live-reproduced scenario (a ResourceQuota fault
	// applied to the same namespace/name on two real clusters at once). This
	// test doesn't need the real hash function, just a fingerprint string
	// that's byte-identical across both calls.
	const sharedFingerprint = "test-fp-bug98-shared"

	findingFor := func(clusterID string) *tunnel.Finding {
		return &tunnel.Finding{
			DetectorID:      "k8s-sweep",
			DetectorVersion: "v1",
			Fingerprint:     sharedFingerprint,
			GVK:             "apps/v1/Deployment",
			Namespace:       "argus-e9-test-batch",
			ObjectName:      "web-fleet",
			ObjectUID:       "uid-" + clusterID,
			ResourceVersion: "1",
			Reason:          "ResourceQuotaExceeded",
			Message:         "Deployment cannot roll out: namespace ResourceQuota exceeded",
			OccurrenceCount: 1,
			Severity:        "high",
			OccurredAt:      time.Now(),
		}
	}

	if err := g.handleFinding(ctx, clusterA, findingFor(clusterA)); err != nil {
		t.Fatalf("handleFinding(cluster A): %v", err)
	}

	// Before the second cluster's finding arrives, cluster A's own incident
	// must NOT be grouped yet — N=1 distinct cluster is not a fleet-wide
	// issue (fleetgroup.decideGroupID's own documented judgement call).
	_, groupBefore := fleetGroupIDForFingerprint(t, pool, tenantID, clusterA, sharedFingerprint)
	if groupBefore != nil {
		t.Fatalf("cluster A's incident carries fleet_group_id = %q before a second cluster ever reported this fingerprint, want NULL", *groupBefore)
	}

	if err := g.handleFinding(ctx, clusterB, findingFor(clusterB)); err != nil {
		t.Fatalf("handleFinding(cluster B): %v", err)
	}

	incidentA, groupA := fleetGroupIDForFingerprint(t, pool, tenantID, clusterA, sharedFingerprint)
	incidentB, groupB := fleetGroupIDForFingerprint(t, pool, tenantID, clusterB, sharedFingerprint)

	if incidentA == incidentB {
		t.Fatalf("cluster A and cluster B findings opened the SAME incident (%s) — fleet grouping must stay display-only, never merge incidents across clusters", incidentA)
	}
	// THE ACTUAL BUG-98 DELIVERABLE. Before the fix, both of these were nil:
	// fleetgroup.Recompute's cross-cluster query, run under a transaction
	// whose RLS scope was narrowed to the ONE cluster the finding arrived
	// from, could never see the sibling cluster's row, so
	// distinctClusterCount could never reach 2 and fleet_group_id was never
	// assigned.
	if groupA == nil {
		t.Fatal("cluster A's incident has no fleet_group_id after a second cluster reported the identical fingerprint — BUGS.md 98's RLS-scoping bug is present")
	}
	if groupB == nil {
		t.Fatal("cluster B's incident has no fleet_group_id — BUGS.md 98's RLS-scoping bug is present")
	}
	if *groupA != *groupB {
		t.Fatalf("cluster A fleet_group_id = %q, cluster B fleet_group_id = %q, want equal — both clusters' incidents share one fingerprint and must join the same fleet group", *groupA, *groupB)
	}

	// The widen-for-Recompute fix must never rewrite WHICH cluster an
	// incident belongs to — fleetgroup.Recompute's UPDATE only ever sets
	// fleet_group_id, and cluster_id must stay exactly what each incident
	// was opened with. Not expected to ever fail given Recompute's own SQL,
	// but this is the one place a genuine cross-cluster write mistake (as
	// opposed to a cross-cluster READ, which is what fleet grouping
	// intentionally allows) would show up.
	ctxCheck := context.Background()
	assertOwnCluster := func(clusterID, incidentID string) {
		t.Helper()
		tx, err := pool.Begin(ctxCheck)
		if err != nil {
			t.Fatalf("begin cluster-check tx: %v", err)
		}
		defer tx.Rollback(ctxCheck) //nolint:errcheck
		if err := data.SetRequestScope(ctxCheck, tx, tenantID, []string{clusterID}); err != nil {
			t.Fatalf("scope: %v", err)
		}
		var gotCluster string
		if err := tx.QueryRow(ctxCheck, `SELECT cluster_id FROM incidents WHERE id = $1`, incidentID).Scan(&gotCluster); err != nil {
			t.Fatalf("read incident %s under cluster %s's own narrow scope: %v (the widen-for-Recompute fix must not have moved this row to another cluster)", incidentID, clusterID, err)
		}
		if gotCluster != clusterID {
			t.Fatalf("incident %s has cluster_id = %q, want %q — a fleet-group recompute must never repoint an incident at a different cluster", incidentID, gotCluster, clusterID)
		}
	}
	assertOwnCluster(clusterA, incidentA)
	assertOwnCluster(clusterB, incidentB)
}

// TestFleetGroupFormsOnANonOpeningSymptom is the regression test for the
// read/write asymmetry PROJECT.md E16's measurement turned up in
// fleetgroup.Recompute: its SELECT resolves a fingerprint's open incidents
// through `findings` (deliberately — see the comment on that query for why
// incidents.fingerprint is the wrong column once migration 000036 lets one
// incident collect several symptoms), but its UPDATE still keyed on
// `WHERE fingerprint = $1`. So a fingerprint arriving as a SECOND symptom
// counted toward distinctClusterCount and could mint a group id that was then
// written to nothing at all.
//
// The shape here is the one measured live on the dev incident table: on each
// of two clusters, an incident is opened by symptom A on some object, and the
// SHARED symptom B then arrives on that same object and attaches to the
// existing incident (object-tier correlation, migration 000036). Neither
// incident's own fingerprint column is ever B, so before the fix both stayed
// ungrouped no matter how perfectly B matched across the fleet.
//
// Run as argus_app (ARGUS_TEST_DATABASE_URL), never the postgres superuser —
// same reason TestBug98_FleetGroupFormsAcrossClusters gives.
func TestFleetGroupFormsOnANonOpeningSymptom(t *testing.T) {
	pool := testPool(t)
	tenantID, clusterA, fixtureA := fleetGroupTestCluster(t, pool)
	tenantIDB, clusterB, fixtureB := fleetGroupTestCluster(t, pool)
	// Two findings per cluster, both about the same object, so object-tier
	// correlation folds them onto ONE incident per cluster.
	fixtureA.Created("incidents", 1)
	fixtureA.Created("findings", 2)
	fixtureA.Created("timeline_events", 1)
	fleetGroupCleanup(fixtureA, pool, tenantID, clusterA)
	fixtureB.Created("incidents", 1)
	fixtureB.Created("findings", 2)
	fixtureB.Created("timeline_events", 1)
	fleetGroupCleanup(fixtureB, pool, tenantIDB, clusterB)
	g := &Gateway{db: &data.DB{Pool: pool}}
	ctx := context.Background()

	// The opening fingerprint is DIFFERENT on each cluster, so it can never
	// form a fleet group of its own — otherwise the incidents would already
	// carry a group id from their own fingerprint column and this test would
	// pass without exercising the non-opening-symptom path at all.
	openingFingerprintFor := map[string]string{
		clusterA: "test-fp-e16-opening-a",
		clusterB: "test-fp-e16-opening-b",
	}
	const sharedFingerprint = "test-fp-e16-shared"

	// Same GVK/namespace/object on both clusters: objectCorrelationKey is
	// gvk|namespace|object_name, so the second finding attaches to the
	// incident the first one opened rather than starting its own.
	findingFor := func(fingerprint, reason string) *tunnel.Finding {
		return &tunnel.Finding{
			DetectorID:      "k8s-sweep",
			DetectorVersion: "v1",
			Fingerprint:     fingerprint,
			GVK:             "apps/v1/Deployment",
			Namespace:       "argus-e16-test",
			ObjectName:      "web-fleet",
			ObjectUID:       "uid-e16",
			ResourceVersion: "1",
			Reason:          reason,
			Message:         "fleet-wide symptom for E16 regression",
			OccurrenceCount: 1,
			Severity:        "high",
			OccurredAt:      time.Now(),
		}
	}

	tenantFor := map[string]string{clusterA: tenantID, clusterB: tenantIDB}
	for _, clusterID := range []string{clusterA, clusterB} {
		if err := g.handleFinding(ctx, clusterID, findingFor(openingFingerprintFor[clusterID], "DeploymentReplicasUnavailable")); err != nil {
			t.Fatalf("handleFinding(opening symptom, cluster %s): %v", clusterID, err)
		}
	}
	// Precondition: neither incident is grouped yet. Each opening fingerprint
	// exists on exactly one cluster, so N=1 and fleet_group_id stays NULL.
	for _, clusterID := range []string{clusterA, clusterB} {
		if _, g := fleetGroupIDForFingerprint(t, pool, tenantFor[clusterID], clusterID, openingFingerprintFor[clusterID]); g != nil {
			t.Fatalf("cluster %s is already grouped (%q) before the shared symptom arrived — this test would not exercise the non-opening-symptom path", clusterID, *g)
		}
	}
	for _, clusterID := range []string{clusterA, clusterB} {
		if err := g.handleFinding(ctx, clusterID, findingFor(sharedFingerprint, "FailedMount")); err != nil {
			t.Fatalf("handleFinding(shared symptom, cluster %s): %v", clusterID, err)
		}
	}

	// Look the incidents up by their OPENING fingerprint — that is what each
	// incident's own fingerprint column holds. The whole point is that the
	// group they must now carry was decided by a DIFFERENT fingerprint.
	incidentA, groupA := fleetGroupIDForFingerprint(t, pool, tenantID, clusterA, openingFingerprintFor[clusterA])
	incidentB, groupB := fleetGroupIDForFingerprint(t, pool, tenantIDB, clusterB, openingFingerprintFor[clusterB])
	if incidentA == incidentB {
		t.Fatalf("both clusters' findings landed on one incident (%s) — fleet grouping must stay display-only", incidentA)
	}
	if groupA == nil || groupB == nil {
		t.Fatalf("fleet_group_id: cluster A = %v, cluster B = %v, want both set — a fingerprint that arrives as a non-opening symptom must still place its incidents in a fleet group (Recompute's UPDATE must reach the same rows its SELECT counted)", groupA, groupB)
	}
	if *groupA != *groupB {
		t.Fatalf("cluster A fleet_group_id = %q, cluster B = %q, want equal", *groupA, *groupB)
	}

	// Each incident must still hold exactly the two findings it was sent, and
	// still be its own incident on its own cluster: grouping is display-only
	// and must never have merged or moved anything.
	assertFindingCount := func(tenant, clusterID, incidentID string, want int) {
		t.Helper()
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatalf("begin finding-count tx: %v", err)
		}
		defer tx.Rollback(ctx) //nolint:errcheck
		if err := data.SetRequestScope(ctx, tx, tenant, []string{clusterID}); err != nil {
			t.Fatalf("scope: %v", err)
		}
		var got int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM findings WHERE incident_id = $1`, incidentID).Scan(&got); err != nil {
			t.Fatalf("count findings for incident %s: %v", incidentID, err)
		}
		if got != want {
			t.Fatalf("incident %s holds %d findings, want %d — fleet grouping must not change which incident a finding attaches to", incidentID, got, want)
		}
	}
	assertFindingCount(tenantID, clusterA, incidentA, 2)
	assertFindingCount(tenantIDB, clusterB, incidentB, 2)
}
