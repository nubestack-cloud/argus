// Package dbtest gives every DB-backed test fixture in this repo one shared
// way to clean up after itself, so the two known shapes of cleanup bug
// become structurally impossible to reintroduce rather than something each
// fixture author has to get right by hand:
//
//   - Over-deletion: a scoping value (typically tenant_id or cluster_id)
//     that turns out to match far more than this fixture's own rows — a
//     reused, shared, or accidentally-empty scope — deletes real, unrelated
//     data. Found live 2026-09-05 in internal/autoanalyze/autoanalyze_db_test.go:
//     two cleanups ran `DELETE FROM incidents WHERE tenant_id = $1`, and in
//     this project's single-tenant dev database that predicate can match
//     the entire table if tenantID is ever anything other than a genuinely
//     fresh id — which destroyed roughly 1,000 incidents and 335 analyses,
//     the measurement baseline several PROJECT.md figures were quoted from.
//   - Under-deletion: a scoping value that matches NOTHING — most commonly
//     because FORCE ROW LEVEL SECURITY silently returns zero rows for an
//     unset or wrongly-scoped session variable, which is not an error —
//     leaks the fixture's own throwaway rows into the database forever.
//     Found live 2026-09-05 in internal/api/repo_tools_registry_db_test.go's
//     f28RegistryFixture (see its own doc comment for the full account):
//     every run leaked one cluster and one incident, 22 of the development
//     database's 37 open incidents by the time it was caught.
//
// Both shapes are caught the same way: a Fixture tracks exactly how many
// rows it inserted into each table, and its Cleanup runs the caller's
// delete statements inside ONE transaction, requires every one of them to
// affect EXACTLY the tracked count for its table, and rolls back — not
// commits — the instant one doesn't match. That is the load-bearing
// property: checking the count after an already-committed delete only
// reports the damage; checking it before commit refuses to let the damage
// happen at all.
package dbtest

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// TB is the subset of testing.TB Fixture needs. Declared as an interface,
// not *testing.T directly, so this package's own tests can verify Cleanup's
// failure behavior with a fake that records a failure instead of one that
// actually fails — a real *testing.T satisfies this interface without any
// change at call sites.
type TB interface {
	Helper()
	Errorf(format string, args ...any)
	Fatalf(format string, args ...any)
	Cleanup(func())
}

// Fixture is one test's ledger of exactly which rows it created, by table.
// Zero value is not usable — construct with New.
type Fixture struct {
	t      TB
	counts map[string]int

	// ownedTenant/ownedCluster are set by OwnsCluster and drive the
	// post-cleanup residue check. Empty means the fixture did not opt in.
	ownedTenant  string
	ownedCluster string
}

// OwnsCluster declares that clusterID is a throwaway cluster this fixture
// created and that nothing outside this fixture owns anything on it. Cleanup
// then finishes by asserting — through AssertNoClusterResidue, against the
// catalogue rather than against a hand-written list — that no table anywhere
// still holds a row for it.
//
// This is the half Created/TableDelete cannot cover. Those check the tables
// the fixture NAMED; the leaks found under PROJECT.md B175 were all tables
// it did not, because product code wrote them: an auto-suppression
// toleration during a close, a recommendation during ApplyAnalysisResult, a
// notification on a notifiable state hop. A fixture that exercises real
// product code cannot know that list by reading its own INSERTs, so it
// should not have to.
//
// Call it on any fixture whose rows all hang off one throwaway cluster.
func (f *Fixture) OwnsCluster(tenantID, clusterID string) {
	f.t.Helper()
	f.ownedTenant, f.ownedCluster = tenantID, clusterID
}

// New returns an empty Fixture bound to t. Call Created immediately after
// every insert the fixture makes, then register cleanup with Cleanup.
func New(t TB) *Fixture {
	t.Helper()
	return &Fixture{t: t, counts: make(map[string]int)}
}

// Created records that this fixture just inserted n rows into table — call
// it right after every INSERT (n=1 for a single-row insert, or the real
// count for a batch). table must be the exact name used in the
// corresponding TableDelete passed to Cleanup; Cleanup fails loudly if a
// table it was asked to delete from was never Created against, since that
// means either the fixture over-counted or the delete list names a table
// this fixture never actually populated.
func (f *Fixture) Created(table string, n int) {
	f.t.Helper()
	if n < 0 {
		f.t.Fatalf("dbtest: Created(%q, %d) — negative count makes no sense", table, n)
	}
	f.counts[table] += n
}

// TableDelete is one cleanup statement Cleanup will run, paired with the
// table name Created tracked counts under. SQL is the full DELETE statement
// (whatever scoping predicate the fixture's own inserts used — tenant_id,
// cluster_id, an explicit id list, anything), Args are its parameters in
// order.
type TableDelete struct {
	Table string
	SQL   string
	Args  []any
}

// Cleanup registers a t.Cleanup that runs runCleanup against pool. See
// runCleanup for what it actually checks; split out so this package's own
// tests can call runCleanup directly, synchronously, with a fake TB —
// registering through t.Cleanup makes a failure impossible to observe
// without the failure itself cascading into the calling test's result.
func (f *Fixture) Cleanup(pool *pgxpool.Pool, setScope func(ctx context.Context, tx pgx.Tx) error, deletes []TableDelete) {
	f.t.Helper()
	counts := f.counts
	t := f.t
	f.t.Cleanup(func() {
		runCleanup(t, pool, setScope, deletes, counts)
		// After the deletes have committed, not before — the residue check
		// reads in its own transaction and would otherwise be looking at
		// rows this cleanup is about to remove. Runs even when runCleanup
		// failed, because a refused cleanup is precisely the case where
		// something has been left behind and saying so is the point.
		if cluster := f.ownedCluster; cluster != "" {
			AssertNoClusterResidue(t, pool, f.ownedTenant, cluster)
		}
	})
}

// runCleanup does the actual work: in one transaction, optionally apply
// scope via setScope (typically data.SetRequestScope; nil if the deletes
// need none), run every delete in order, and require each one's affected
// row count to equal exactly what counts recorded for its table. Any
// mismatch — in either direction — fails loudly via t.Errorf naming the
// exact table, the count expected vs. actual, and which direction of bug it
// matches, and the transaction is rolled back rather than committed, so a
// wrong delete never actually takes effect. A table named in deletes with
// no matching entry in counts, or vice versa, is also a hard failure —
// that pairing omission is exactly how a fixture silently drifts out of
// sync with its own cleanup.
func runCleanup(t TB, pool *pgxpool.Pool, setScope func(ctx context.Context, tx pgx.Tx) error, deletes []TableDelete, counts map[string]int) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Errorf("dbtest cleanup: begin transaction: %v", err)
		return
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback(ctx)
		}
	}()

	if setScope != nil {
		if err := setScope(ctx, tx); err != nil {
			t.Errorf("dbtest cleanup: set scope: %v", err)
			return
		}
	}

	seen := make(map[string]bool, len(deletes))
	for _, d := range deletes {
		seen[d.Table] = true
		want, tracked := counts[d.Table]
		if !tracked {
			t.Errorf("dbtest cleanup: delete for table %q has no matching Created(%q, ...) call — a fixture that deletes from a table it never tracked cannot know whether the delete was correctly scoped", d.Table, d.Table)
			return
		}
		tag, err := tx.Exec(ctx, d.SQL, d.Args...)
		if err != nil {
			t.Errorf("dbtest cleanup: %s: %v", d.SQL, err)
			return
		}
		got := int(tag.RowsAffected())
		if got != want {
			direction := "MORE than expected — this predicate matched rows the fixture did not create, and would have deleted real data"
			if got < want {
				direction = "FEWER than expected — this predicate missed rows the fixture DID create, which leaks them permanently"
			}
			t.Errorf("dbtest cleanup: DELETE FROM %s affected %d row(s), want exactly %d (%s). Refusing to commit — the transaction is rolled back, so nothing was actually deleted. SQL: %s",
				d.Table, got, want, direction, d.SQL)
			return
		}
	}
	for table := range counts {
		if !seen[table] {
			t.Errorf("dbtest cleanup: Created(%q, ...) was called but no delete for it was ever run — this fixture's own rows in that table were never cleaned up", table)
			return
		}
	}

	if err := tx.Commit(ctx); err != nil {
		t.Errorf("dbtest cleanup: commit: %v", err)
		return
	}
	committed = true
}
