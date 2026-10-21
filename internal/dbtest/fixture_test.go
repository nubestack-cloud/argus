package dbtest

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"argus/internal/data"
	"argus/internal/domain"
)

// testPool matches every other package's own DB-backed test convention
// (e.g. internal/autoanalyze/autoanalyze_db_test.go's testPool): a real
// Postgres behind ARGUS_TEST_DATABASE_URL, argus_app so this runs under the
// same FORCE ROW LEVEL SECURITY the hub itself does, skipped cleanly when
// unset.
func testPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	connString := os.Getenv("ARGUS_TEST_DATABASE_URL")
	if connString == "" {
		t.Skip("ARGUS_TEST_DATABASE_URL not set; skipping DB-backed dbtest tests")
	}
	pool, err := pgxpool.New(context.Background(), connString)
	if err != nil {
		t.Fatalf("connect to test database: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

// newOrg creates a real, throwaway organisation for one test and returns
// its id — the same "fresh tenant per test" precedent
// autoanalyze_db_test.go's setupStarvationFixture already established, kept
// here rather than deleted at the end of THIS test, deliberately: this test
// exists to prove Fixture.Cleanup's OWN correctness, so its setup must not
// itself depend on the mechanism under test.
func newOrg(t *testing.T, pool *pgxpool.Pool, name string) string {
	t.Helper()
	ctx := context.Background()
	id := domain.NewID(domain.PrefixOrganisation)
	if _, err := pool.Exec(ctx, `INSERT INTO organisations (id, name) VALUES ($1, $2)`, id, name); err != nil {
		t.Fatalf("insert throwaway organisation: %v", err)
	}
	t.Cleanup(func() {
		if _, err := pool.Exec(context.Background(), `DELETE FROM organisations WHERE id = $1`, id); err != nil {
			t.Errorf("cleanup: delete throwaway organisation: %v", err)
		}
	})
	return id
}

// countClusters reads through a scoped transaction, not the bare pool — a
// fresh connection has no app.tenant_id set, and incidents/clusters'
// FORCE ROW LEVEL SECURITY silently returns zero rows for that, which would
// make every assertion below pass whether the rows actually exist or not.
func countClusters(t *testing.T, pool *pgxpool.Pool, tenantID string) int {
	t.Helper()
	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("count clusters: begin: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if err := data.SetRequestScope(ctx, tx, tenantID, nil); err != nil {
		t.Fatalf("count clusters: set scope: %v", err)
	}
	var n int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM clusters WHERE tenant_id = $1`, tenantID).Scan(&n); err != nil {
		t.Fatalf("count clusters: %v", err)
	}
	return n
}

func scopeSetter(tenantID string, clusterIDs []string) func(ctx context.Context, tx pgx.Tx) error {
	return func(ctx context.Context, tx pgx.Tx) error {
		return data.SetRequestScope(ctx, tx, tenantID, clusterIDs)
	}
}

// fakeTB records whether Errorf/Fatalf was called instead of actually
// failing a test — t.Run cannot express "this subtest is SUPPOSED to fail"
// without that failure cascading into the whole package's exit code, so the
// three tests below call runCleanup directly with this instead of going
// through a real t.Run.
type fakeTB struct {
	t       *testing.T // for Helper() and Cleanup() only — never Errorf/Fatalf
	failed  bool
	message string
}

func (f *fakeTB) Helper() { f.t.Helper() }
func (f *fakeTB) Cleanup(fn func()) {
	f.t.Helper()
	f.t.Cleanup(fn)
}
func (f *fakeTB) Errorf(format string, args ...any) {
	f.failed = true
	f.message = fmt.Sprintf(format, args...)
}
func (f *fakeTB) Fatalf(format string, args ...any) {
	f.failed = true
	f.message = fmt.Sprintf(format, args...)
}

// TestFixtureCleanup_HappyPath is the baseline: create exactly N rows,
// delete exactly N, commit — the ordinary case every existing fixture in
// this repo already gets right most of the time.
func TestFixtureCleanup_HappyPath(t *testing.T) {
	pool := testPool(t)
	tenantID := newOrg(t, pool, "dbtest-happy-path")
	ctx := context.Background()

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	if err := data.SetRequestScope(ctx, tx, tenantID, nil); err != nil {
		t.Fatalf("set scope: %v", err)
	}
	clusterID := domain.NewID(domain.PrefixCluster)
	if _, err := tx.Exec(ctx,
		`INSERT INTO clusters (id, tenant_id, display_name, state, shard_id, cluster_fingerprint)
		 VALUES ($1, $2, $3, 'Active', 'shard-test', $4)`,
		clusterID, tenantID, "dbtest-happy-"+clusterID, "fp-"+clusterID); err != nil {
		t.Fatalf("insert cluster: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit: %v", err)
	}

	f := New(t)
	f.Created("clusters", 1)
	f.Cleanup(pool, scopeSetter(tenantID, nil), []TableDelete{
		{Table: "clusters", SQL: `DELETE FROM clusters WHERE tenant_id = $1`, Args: []any{tenantID}},
	})

	// Cleanup runs via t.Cleanup, after this test function returns — so
	// assert the row is STILL there right now (proves the test itself, not
	// the mechanism, isn't racing ahead of cleanup).
	if got := countClusters(t, pool, tenantID); got != 1 {
		t.Fatalf("expected the cluster to still exist before cleanup runs, got count=%d", got)
	}
}

// TestFixtureCleanup_OverDeletionRefused reproduces the exact shape that
// destroyed ~1,000 incidents: a delete predicate that matches MORE rows
// than this fixture created (here, simulated by creating one cluster but
// deleting with a predicate that also matches a second, "pre-existing" one
// under the same tenant — standing in for a shared/reused scope value in
// the real bug). Must fail loudly AND leave both clusters in place —
// rolled back, not committed.
func TestFixtureCleanup_OverDeletionRefused(t *testing.T) {
	pool := testPool(t)
	tenantID := newOrg(t, pool, "dbtest-over-deletion")
	ctx := context.Background()

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	if err := data.SetRequestScope(ctx, tx, tenantID, nil); err != nil {
		t.Fatalf("set scope: %v", err)
	}
	// TWO clusters share this tenant — standing in for "real, unrelated
	// data happens to share the scope value this fixture's delete uses."
	// Only one of them is what THIS fixture tracks as its own.
	fixtureClusterID := domain.NewID(domain.PrefixCluster)
	unrelatedClusterID := domain.NewID(domain.PrefixCluster)
	for _, id := range []string{fixtureClusterID, unrelatedClusterID} {
		if _, err := tx.Exec(ctx,
			`INSERT INTO clusters (id, tenant_id, display_name, state, shard_id, cluster_fingerprint)
			 VALUES ($1, $2, $3, 'Active', 'shard-test', $4)`,
			id, tenantID, "dbtest-over-"+id, "fp-"+id); err != nil {
			t.Fatalf("insert cluster: %v", err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit: %v", err)
	}
	// The "unrelated" row is cleaned up directly, bypassing the fixture
	// under test entirely — this test's own responsibility, not Fixture's.
	t.Cleanup(func() {
		deleteScopedCluster(t, pool, tenantID, unrelatedClusterID)
	})

	fake := &fakeTB{t: t}
	runCleanup(fake, pool, scopeSetter(tenantID, nil), []TableDelete{
		// tenant-scoped, matching BOTH clusters — the exact over-broad
		// predicate shape the real bug had.
		{Table: "clusters", SQL: `DELETE FROM clusters WHERE tenant_id = $1`, Args: []any{tenantID}},
	}, map[string]int{"clusters": 1}) // this fixture believes it made exactly one row
	if !fake.failed {
		t.Fatal("expected runCleanup to fail (2 rows deleted, 1 expected) — over-deletion was not caught")
	}
	t.Logf("runCleanup correctly refused: %s", fake.message)

	if got := countClusters(t, pool, tenantID); got != 2 {
		t.Fatalf("expected BOTH clusters to still exist (delete must be rolled back, not committed), got count=%d", got)
	}
	// The refused delete rolled back, so the fixture's own cluster genuinely
	// survives — this test's own job to clean up what it proved still
	// exists, same as the "unrelated" row above. Scoped, for the same
	// RLS reason countClusters is.
	deleteScopedCluster(t, pool, tenantID, fixtureClusterID)
}

// deleteScopedCluster removes one cluster through a scoped transaction —
// FORCE ROW LEVEL SECURITY makes an unscoped pool.Exec a silent no-op here,
// which would leak exactly the row this helper exists to clean up.
func deleteScopedCluster(t *testing.T, pool *pgxpool.Pool, tenantID, clusterID string) {
	t.Helper()
	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Errorf("cleanup: begin: %v", err)
		return
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if err := data.SetRequestScope(ctx, tx, tenantID, nil); err != nil {
		t.Errorf("cleanup: set scope: %v", err)
		return
	}
	if _, err := tx.Exec(ctx, `DELETE FROM clusters WHERE id = $1`, clusterID); err != nil {
		t.Errorf("cleanup: delete cluster: %v", err)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		t.Errorf("cleanup: commit: %v", err)
	}
}

// TestFixtureCleanup_UnderDeletionRefused reproduces f28RegistryFixture's
// shape: a delete predicate that matches FEWER rows than this fixture
// created (here, simulated with a predicate on a value the insert never
// actually used — standing in for RLS silently returning zero rows against
// an unset/wrong scope). Must fail loudly AND leave the fixture's own row
// in place — rolled back, so the failure is visible rather than a silent
// leak.
func TestFixtureCleanup_UnderDeletionRefused(t *testing.T) {
	pool := testPool(t)
	tenantID := newOrg(t, pool, "dbtest-under-deletion")
	ctx := context.Background()

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	if err := data.SetRequestScope(ctx, tx, tenantID, nil); err != nil {
		t.Fatalf("set scope: %v", err)
	}
	clusterID := domain.NewID(domain.PrefixCluster)
	if _, err := tx.Exec(ctx,
		`INSERT INTO clusters (id, tenant_id, display_name, state, shard_id, cluster_fingerprint)
		 VALUES ($1, $2, $3, 'Active', 'shard-test', $4)`,
		clusterID, tenantID, "dbtest-under-"+clusterID, "fp-"+clusterID); err != nil {
		t.Fatalf("insert cluster: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit: %v", err)
	}
	t.Cleanup(func() {
		deleteScopedCluster(t, pool, tenantID, clusterID)
	})

	fake := &fakeTB{t: t}
	runCleanup(fake, pool, scopeSetter(tenantID, nil), []TableDelete{
		// A never-used id — matches nothing, exactly like RLS silently
		// returning zero rows for a wrong/unset scope.
		{Table: "clusters", SQL: `DELETE FROM clusters WHERE id = $1`, Args: []any{domain.NewID(domain.PrefixCluster)}},
	}, map[string]int{"clusters": 1})
	if !fake.failed {
		t.Fatal("expected runCleanup to fail (0 rows deleted, 1 expected) — under-deletion was not caught")
	}
	t.Logf("runCleanup correctly refused: %s", fake.message)

	if got := countClusters(t, pool, tenantID); got != 1 {
		t.Fatalf("expected the fixture's own cluster to still exist (rolled back, not silently leaked with no signal), got count=%d", got)
	}
}

// TestFixtureCleanup_UntrackedTableRefused pins the pairing check: a
// delete for a table Created was never called for is refused before any
// SQL runs for it, independent of the over/under-count checks above.
func TestFixtureCleanup_UntrackedTableRefused(t *testing.T) {
	pool := testPool(t)
	tenantID := newOrg(t, pool, "dbtest-untracked-table")

	fake := &fakeTB{t: t}
	// Deliberately an empty counts map — no Created("clusters", ...) call.
	runCleanup(fake, pool, scopeSetter(tenantID, nil), []TableDelete{
		{Table: "clusters", SQL: `DELETE FROM clusters WHERE tenant_id = $1`, Args: []any{tenantID}},
	}, map[string]int{})
	if !fake.failed {
		t.Fatal("expected runCleanup to fail — a delete for a table never passed to Created must be refused")
	}
	t.Logf("runCleanup correctly refused: %s", fake.message)
}

// TestAssertNoClusterResidue_ReportsATableNoDeleteListNamed is the residue
// check's own proof, and it is written against the exact failure it exists
// for: a fixture that deletes everything it knows it created, and leaves
// behind a row in a table it was never told about because PRODUCT code, not
// the fixture, wrote it. Here that second table is incidents, standing in
// for the real ones (incident_tolerations, remediation_recommendations,
// incident_notifications) that leaked under PROJECT.md B175.
func TestAssertNoClusterResidue_ReportsATableNoDeleteListNamed(t *testing.T) {
	pool := testPool(t)
	tenantID := newOrg(t, pool, "dbtest-residue")
	ctx := context.Background()

	clusterID := domain.NewID(domain.PrefixCluster)
	incidentID := domain.NewID(domain.PrefixIncident)
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	if err := data.SetRequestScope(ctx, tx, tenantID, []string{clusterID}); err != nil {
		t.Fatalf("set scope: %v", err)
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO clusters (id, tenant_id, display_name, state, shard_id, cluster_fingerprint)
		 VALUES ($1, $2, $3, 'Active', 'shard-test', $4)`,
		clusterID, tenantID, "dbtest-residue-"+clusterID, "fp-"+clusterID); err != nil {
		t.Fatalf("insert cluster: %v", err)
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO incidents (id, tenant_id, cluster_id, fingerprint, severity, state, first_seen, last_seen, occurrence_count)
		 VALUES ($1, $2, $3, $4, 'high', 'Detected', now(), now(), 1)`,
		incidentID, tenantID, clusterID, "fp-residue-"+incidentID); err != nil {
		t.Fatalf("insert incident: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit: %v", err)
	}
	// Belt and braces: remove both rows whatever this test concludes, so a
	// test about leaking cannot itself leak.
	t.Cleanup(func() {
		cleanupTx, err := pool.Begin(context.Background())
		if err != nil {
			t.Errorf("final cleanup: begin: %v", err)
			return
		}
		defer cleanupTx.Rollback(context.Background()) //nolint:errcheck
		if err := data.SetRequestScope(context.Background(), cleanupTx, tenantID, []string{clusterID}); err != nil {
			t.Errorf("final cleanup: scope: %v", err)
			return
		}
		for _, stmt := range []string{
			`DELETE FROM incidents WHERE cluster_id = $1`,
			`DELETE FROM clusters WHERE id = $1`,
		} {
			if _, err := cleanupTx.Exec(context.Background(), stmt, clusterID); err != nil {
				t.Errorf("final cleanup %q: %v", stmt, err)
				return
			}
		}
		if err := cleanupTx.Commit(context.Background()); err != nil {
			t.Errorf("final cleanup: commit: %v", err)
		}
	})

	// The incident is still there, so the check must say so and must name
	// the table — "something leaked" with no table name would leave the
	// reader doing exactly the manual row-counting this replaces.
	dirty := &fakeTB{t: t}
	AssertNoClusterResidue(dirty, pool, tenantID, clusterID)
	if !dirty.failed {
		t.Fatal("residue check passed while an incident row for the throwaway cluster was still present — this is the exact miss it exists to catch")
	}
	if !strings.Contains(dirty.message, "incidents") || !strings.Contains(dirty.message, clusterID) {
		t.Errorf("residue message names neither the table nor the cluster: %q", dirty.message)
	}

	// Remove it, and the same check must go quiet. A check that always
	// fails is as useless as one that never does.
	removeTx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin removal: %v", err)
	}
	if err := data.SetRequestScope(ctx, removeTx, tenantID, []string{clusterID}); err != nil {
		t.Fatalf("removal scope: %v", err)
	}
	if _, err := removeTx.Exec(ctx, `DELETE FROM incidents WHERE cluster_id = $1`, clusterID); err != nil {
		t.Fatalf("remove incident: %v", err)
	}
	if err := removeTx.Commit(ctx); err != nil {
		t.Fatalf("commit removal: %v", err)
	}
	clean := &fakeTB{t: t}
	AssertNoClusterResidue(clean, pool, tenantID, clusterID)
	if clean.failed {
		// clusters itself is still present here deliberately, so this also
		// pins that the check counts the CLUSTER row too.
		if !strings.Contains(clean.message, "clusters") {
			t.Errorf("residue check failed for something other than the still-present cluster row: %q", clean.message)
		}
	} else {
		t.Error("residue check passed while the throwaway cluster row itself was still present — a leaked cluster is the one thing that shows up as fleet")
	}
}

// TestAssertNoClusterResidue_RefusesAnEmptyClusterID pins the degenerate
// case: scanning for rows owned by "" would match nothing on every table and
// report clean forever, which is worse than no check at all.
func TestAssertNoClusterResidue_RefusesAnEmptyClusterID(t *testing.T) {
	pool := testPool(t)
	fake := &fakeTB{t: t}
	AssertNoClusterResidue(fake, pool, "org_whatever", "")
	if !fake.failed {
		t.Fatal("an empty cluster id was accepted")
	}
}
