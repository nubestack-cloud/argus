package dbtest

// Residue detection: the half of the leak problem a delete list cannot see.
//
// Fixture.Cleanup can only check the tables a fixture was told about. Every
// leak found under PROJECT.md B175 was a table nobody thought to name —
// incident_tolerations written by orchestrator's auto-suppression during a
// close, remediation_recommendations written by ApplyAnalysisResult,
// incident_notifications written by a notifiable state hop. Product code
// writes those; the fixture never mentions them, so a delete list assembled
// by reading the fixture's own INSERTs is wrong by construction, and stays
// wrong until somebody counts rows in the development database by hand.
//
// AssertNoClusterResidue closes that by asking the catalogue instead of the
// author: every base table in the public schema that has a cluster_id
// column, plus clusters itself, must hold zero rows for a throwaway cluster
// once the test is finished. The list cannot drift, because a migration that
// adds a cluster-scoped table adds it to this check on the same day.

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"argus/internal/data"
)

// clusterScopedTablesSQL lists the public base tables carrying a cluster_id
// column. Partition children are excluded (pg_inherits) so a partitioned
// table such as findings is reported once, under its parent name, rather
// than once per month.
const clusterScopedTablesSQL = `
SELECT c.relname
  FROM pg_class c
  JOIN pg_namespace n ON n.oid = c.relnamespace
  JOIN pg_attribute a ON a.attrelid = c.oid
                     AND a.attname = 'cluster_id'
                     AND a.attnum > 0
                     AND NOT a.attisdropped
 WHERE n.nspname = 'public'
   AND c.relkind IN ('r', 'p')
   AND c.relname <> ALL ($1::text[])
   AND NOT EXISTS (SELECT 1 FROM pg_inherits i WHERE i.inhrelid = c.oid)
 ORDER BY c.relname`

// residueExemptTables are the cluster-scoped tables a fixture is NOT
// expected to clean up, and must not be told to.
//
// audit_events is a hash chain: every row carries the hash of its
// predecessor, and `argusctl audit verify` re-verifies the whole chain
// straight against Postgres. Deleting a test's rows out of the middle of it
// would break verification for every row after them — the audit trail's
// tamper-evidence is doing exactly what it is for. Test-written audit rows
// are the accepted cost of that property, so they are exempt here rather
// than quietly deleted somewhere else.
var residueExemptTables = []string{"audit_events"}

// AssertNoClusterResidue fails t if anything in the database still belongs
// to clusterID. Call it at the very end of a fixture's cleanup, after the
// deletes have COMMITTED — it reads in its own transaction, so an uncommitted
// delete would not be visible to it and it would report residue that is
// about to disappear.
//
// It scopes itself to (tenantID, [clusterID]) rather than taking a caller's
// scope callback, deliberately. Several policies — incident_notifications'
// is one — have no "empty accessible_cluster_ids means tenant-wide" escape
// hatch, so a tenant-wide scope makes their rows invisible rather than
// absent, and an invisible row counts as zero. A check that reports "clean"
// because it cannot see is worse than no check.
//
// Cleaning up is still the fixture's job; this only refuses to let a fixture
// believe it has done so. What it reports is the table and the row count, so
// the fix is always "add this table to the delete list", never a hunt.
func AssertNoClusterResidue(t TB, pool *pgxpool.Pool, tenantID, clusterID string) {
	t.Helper()
	if clusterID == "" {
		t.Errorf("dbtest: AssertNoClusterResidue called with an empty cluster id — that would scan for rows nothing can own and always pass")
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Errorf("dbtest residue check: begin transaction: %v", err)
		return
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if err := data.SetRequestScope(ctx, tx, tenantID, []string{clusterID}); err != nil {
		t.Errorf("dbtest residue check: set scope: %v", err)
		return
	}

	tables, err := clusterScopedTables(ctx, tx)
	if err != nil {
		t.Errorf("dbtest residue check: list cluster-scoped tables: %v", err)
		return
	}

	// clusters itself keys on id, not cluster_id, so it is checked
	// separately — and it is the one that matters most, because a throwaway
	// cluster left behind is a cluster the product reports as fleet.
	type residue struct {
		table string
		rows  int
	}
	var found []residue
	var rows int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM clusters WHERE id = $1`, clusterID).Scan(&rows); err != nil {
		t.Errorf("dbtest residue check: count clusters: %v", err)
		return
	}
	if rows > 0 {
		found = append(found, residue{"clusters", rows})
	}
	for _, table := range tables {
		// table comes from pg_class, never from a caller, so it cannot be
		// anything but an existing relation name; quoted anyway so a name
		// needing quoting does not turn into a syntax error years from now.
		if err := tx.QueryRow(ctx,
			fmt.Sprintf(`SELECT count(*) FROM %s WHERE cluster_id = $1`, pgx.Identifier{table}.Sanitize()),
			clusterID).Scan(&rows); err != nil {
			t.Errorf("dbtest residue check: count %s: %v", table, err)
			return
		}
		if rows > 0 {
			found = append(found, residue{table, rows})
		}
	}

	for _, r := range found {
		t.Errorf("dbtest residue check: %d row(s) for throwaway cluster %s still in %s after cleanup — this fixture's delete list does not cover that table, and every run of this test leaks %d more row(s) into whatever database it ran against",
			r.rows, clusterID, r.table, r.rows)
	}
}

func clusterScopedTables(ctx context.Context, tx pgx.Tx) ([]string, error) {
	rows, err := tx.Query(ctx, clusterScopedTablesSQL, residueExemptTables)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		out = append(out, name)
	}
	return out, rows.Err()
}
