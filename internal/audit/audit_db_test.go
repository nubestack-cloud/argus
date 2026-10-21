package audit

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"argus/internal/data"
	"argus/internal/domain"
)

// chainTip's tiebreaker bug is a property of a SQL ORDER BY, so showing it
// fixed needs real rows in a real table: two audit_events sharing one
// occurred_at, which is only possible to arrange by inserting them directly
// (RecordEvent stamps its own time.Now()). Gated behind
// ARGUS_TEST_DATABASE_URL exactly like internal/authz/session_test.go and
// internal/orchestrator/db_test.go — no test database means a clean skip.
//
// Everything below runs inside a transaction that is never committed, so
// these crafted rows never join a real audit chain. That matters more here
// than anywhere else in this codebase: audit_events is append-only and
// hash-chained, and leaving a hand-built row behind would make `argusctl
// audit verify` report the real log as tampered from then on.
func testPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	connString := os.Getenv("ARGUS_TEST_DATABASE_URL")
	if connString == "" {
		t.Skip("ARGUS_TEST_DATABASE_URL not set; skipping DB-backed chain-tip test (see this file's doc comment)")
	}
	pool, err := pgxpool.New(context.Background(), connString)
	if err != nil {
		t.Fatalf("connect to test database: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

// TestChainTipBreaksTimestampTiesByID is the regression test for a forked
// hash chain. Two audit_events rows can genuinely share an occurred_at —
// RecordEvent truncates to Postgres's microsecond resolution, and a
// backwards wall-clock step can produce one outright — and the verifier
// (internal/argusctl/audit.go's LoadAuditEvents) walks the chain in
// (occurred_at ASC, id ASC). With `ORDER BY occurred_at DESC` alone, this
// query was free to return either tied row, so the next insert could chain
// from a row the verifier does not consider the last one: the chain forks,
// and `argusctl audit verify` reports an untampered log as tampered.
//
// Both insertion orders are exercised. That is the point: with no
// tiebreaker, Postgres returns tied rows in whatever order it scans them, so
// a test that only ever inserted them one way round could pass by accident.
// The tie must be broken by id, never by physical row order.
func TestChainTipBreaksTimestampTiesByID(t *testing.T) {
	pool := testPool(t)

	for _, insertHigherIDFirst := range []bool{false, true} {
		name := "lower id inserted first"
		if insertHigherIDFirst {
			name = "higher id inserted first"
		}
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			tx, err := pool.Begin(ctx)
			if err != nil {
				t.Fatalf("begin: %v", err)
			}
			defer tx.Rollback(ctx) //nolint:errcheck

			tenantID, err := data.SingleOrganisationID(ctx, tx)
			if err != nil {
				t.Fatalf("resolve organisation: %v", err)
			}
			if err := data.SetRequestScope(ctx, tx, tenantID, nil); err != nil {
				t.Fatalf("set request scope: %v", err)
			}

			// Later than every row already in the table, so these two are
			// unambiguously the end of the chain whatever the database
			// already holds.
			var latest *time.Time
			if err := tx.QueryRow(ctx, `SELECT max(occurred_at) FROM audit_events`).Scan(&latest); err != nil {
				t.Fatalf("read latest occurred_at: %v", err)
			}
			tieTime := time.Now().UTC().Truncate(time.Microsecond)
			if latest != nil && !latest.Before(tieTime) {
				tieTime = latest.Add(time.Second)
			}

			// Two ids, sorted rather than assumed to come out of
			// domain.NewID in order: within one millisecond a ULID's entropy
			// is crypto/rand, not monotonic, so two consecutive NewID calls
			// land in random relative order about half the time. (That fact
			// is precisely why nextOccurredAt exists — see its doc comment.)
			lowerID, higherID := domain.NewID(domain.PrefixAuditEvent), domain.NewID(domain.PrefixAuditEvent)
			if lowerID > higherID {
				lowerID, higherID = higherID, lowerID
			}

			insert := func(id, hash string) {
				if _, err := tx.Exec(ctx,
					`INSERT INTO audit_events (id, tenant_id, outcome, occurred_at, prev_hash, hash)
					 VALUES ($1, $2, 'success', $3, $4, $5)`,
					id, tenantID, tieTime, GenesisPrevHash, hash); err != nil {
					t.Fatalf("insert crafted audit event %s: %v", id, err)
				}
			}
			if insertHigherIDFirst {
				insert(higherID, "hash-of-the-higher-id-row")
				insert(lowerID, "hash-of-the-lower-id-row")
			} else {
				insert(lowerID, "hash-of-the-lower-id-row")
				insert(higherID, "hash-of-the-higher-id-row")
			}

			got, gotOccurredAt, err := chainTip(ctx, tx)
			if err != nil {
				t.Fatalf("chainTip: %v", err)
			}
			if !gotOccurredAt.Equal(tieTime) {
				t.Errorf("chainTip returned occurred_at %v, want the tied rows' %v — RecordEvent needs the tip's timestamp to keep the chain strictly increasing", gotOccurredAt, tieTime)
			}
			if got != "hash-of-the-higher-id-row" {
				t.Errorf("chainTip = %q, want the higher id's hash — with two rows sharing an occurred_at, the tip must be decided by id, not by which row the scan reached first", got)
			}

			// The invariant that actually matters, stated directly: the row
			// this query calls "the tip" and the row the verifier calls "the
			// last row" (it walks occurred_at ASC, id ASC — see
			// internal/argusctl/audit.go's LoadAuditEvents) must be the same
			// row. If these two ever disagree, the chain forks on the next
			// insert.
			var verifierLastHash string
			rows, err := tx.Query(ctx, `SELECT hash FROM audit_events ORDER BY occurred_at ASC, id ASC`)
			if err != nil {
				t.Fatalf("walk the chain the way the verifier does: %v", err)
			}
			for rows.Next() {
				if err := rows.Scan(&verifierLastHash); err != nil {
					rows.Close()
					t.Fatalf("scan walked row: %v", err)
				}
			}
			rows.Close()
			if err := rows.Err(); err != nil {
				t.Fatalf("walk the chain: %v", err)
			}
			if got != verifierLastHash {
				t.Errorf("chainTip = %q but the verifier's own (occurred_at ASC, id ASC) walk ends at %q — the two orderings must agree, or every subsequent insert chains from the wrong row", got, verifierLastHash)
			}
		})
	}
}

// TestChainTipOnAnEmptyChainIsGenesis covers the other branch: with no rows
// at all, the tip is the documented genesis sentinel rather than an error.
// Exercised against a real (non-empty) table by deleting everything inside a
// transaction that is rolled back, since that is the only way to observe the
// empty case without an empty database.
func TestChainTipOnAnEmptyChainIsGenesis(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	tenantID, err := data.SingleOrganisationID(ctx, tx)
	if err != nil {
		t.Fatalf("resolve organisation: %v", err)
	}
	if err := data.SetRequestScope(ctx, tx, tenantID, nil); err != nil {
		t.Fatalf("set request scope: %v", err)
	}
	if _, err := tx.Exec(ctx, `DELETE FROM audit_events`); err != nil {
		t.Fatalf("empty the chain inside the rolled-back transaction: %v", err)
	}

	got, gotOccurredAt, err := chainTip(ctx, tx)
	if err != nil {
		t.Fatalf("chainTip on an empty chain: %v", err)
	}
	if got != GenesisPrevHash {
		t.Errorf("chainTip on an empty chain = %q, want GenesisPrevHash %q", got, GenesisPrevHash)
	}
	if !gotOccurredAt.IsZero() {
		t.Errorf("chainTip on an empty chain returned occurred_at %v, want the zero time (there is no tip to stay ahead of)", gotOccurredAt)
	}
}

// TestRecordEventStaysAheadOfTheChainTip is the end-to-end regression test
// for bug 3, asserted exactly the way the verifier checks it: walk the table
// in (occurred_at ASC, id ASC) — internal/argusctl/audit.go's
// LoadAuditEvents' own order — and confirm every row's prev_hash really is
// the previous row's hash.
//
// The scenario is the backwards-wall-clock case from the bug report, set up
// by planting a tip row an hour AHEAD of the current clock (equivalently:
// the clock stepped back an hour after that row was written — an NTP
// correction, a VM suspend/resume). Before the fix, RecordEvent stamped the
// new rows with a plain time.Now(), so they sorted BEFORE the row they chain
// from, and the verifier's walk hit a prev_hash mismatch on its very first
// row: an untampered log reported as tampered. Note this is not fixed by
// making the tip query's ordering mirror the verifier's — that makes the two
// agree on which row is last, but says nothing about whether either agrees
// with the order the rows were written in.
//
// Three appended events rather than one, so the assertion covers the chain
// continuing correctly from the clamped timestamp, not just the first row
// after it.
func TestRecordEventStaysAheadOfTheChainTip(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	// Rolled back: this appends real, correctly-hashed rows, but a test has
	// no business permanently extending the audit log.
	defer tx.Rollback(ctx) //nolint:errcheck

	tenantID, err := data.SingleOrganisationID(ctx, tx)
	if err != nil {
		t.Fatalf("resolve organisation: %v", err)
	}
	if err := data.SetRequestScope(ctx, tx, tenantID, nil); err != nil {
		t.Fatalf("set request scope: %v", err)
	}
	// Start from an empty chain inside this transaction, so the walk below
	// covers exactly the rows this test controls and inherits no
	// pre-existing inconsistency from whatever database it's pointed at.
	if _, err := tx.Exec(ctx, `DELETE FROM audit_events`); err != nil {
		t.Fatalf("empty the chain inside the rolled-back transaction: %v", err)
	}

	const tipHash = "hash-of-the-row-written-before-the-clock-stepped-back"
	tipOccurredAt := time.Now().UTC().Add(time.Hour).Truncate(time.Microsecond)
	if _, err := tx.Exec(ctx,
		`INSERT INTO audit_events (id, tenant_id, outcome, occurred_at, prev_hash, hash)
		 VALUES ($1, $2, 'success', $3, $4, $5)`,
		domain.NewID(domain.PrefixAuditEvent), tenantID, tipOccurredAt, GenesisPrevHash, tipHash); err != nil {
		t.Fatalf("plant the chain tip: %v", err)
	}

	const appended = 3
	for i := 0; i < appended; i++ {
		if err := RecordEvent(ctx, tx, Event{TenantID: tenantID, Outcome: OutcomeSuccess}); err != nil {
			t.Fatalf("RecordEvent %d: %v", i, err)
		}
	}

	rows, err := tx.Query(ctx,
		`SELECT id, occurred_at, prev_hash, hash FROM audit_events ORDER BY occurred_at ASC, id ASC`)
	if err != nil {
		t.Fatalf("walk the chain the way the verifier does: %v", err)
	}
	defer rows.Close()

	expectedPrev := GenesisPrevHash
	var lastOccurredAt time.Time
	n := 0
	for rows.Next() {
		var id, prevHash, hash string
		var occurredAt time.Time
		if err := rows.Scan(&id, &occurredAt, &prevHash, &hash); err != nil {
			t.Fatalf("scan walked row: %v", err)
		}
		if prevHash != expectedPrev {
			t.Fatalf("row %d (%s): prev_hash = %q, want %q — walking the chain in the verifier's own order must reproduce every link, or `argusctl audit verify` reports this untampered log as tampered",
				n, id, prevHash, expectedPrev)
		}
		if n > 0 && !occurredAt.After(lastOccurredAt) {
			t.Fatalf("row %d (%s): occurred_at %v does not strictly follow the previous row's %v — equal or regressing timestamps hand the chain's order to random ULID entropy",
				n, id, occurredAt, lastOccurredAt)
		}
		expectedPrev = hash
		lastOccurredAt = occurredAt
		n++
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("walk the chain: %v", err)
	}
	if want := appended + 1; n != want {
		t.Errorf("walked %d rows, want %d", n, want)
	}
}

// TestNextOccurredAt is the DB-free half of the same guarantee.
func TestNextOccurredAt(t *testing.T) {
	tip := time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC)

	// The ordinary case: real time is comfortably ahead of the tip, so it's
	// used as-is (truncated to Postgres's microsecond resolution).
	now := tip.Add(5 * time.Second).Add(1234 * time.Nanosecond)
	if got, want := nextOccurredAt(now, tip), tip.Add(5*time.Second).Add(time.Microsecond); !got.Equal(want) {
		t.Errorf("nextOccurredAt(now ahead of tip) = %v, want %v (now, truncated to microseconds)", got, want)
	}

	// Same microsecond as the tip: must be pushed one microsecond past it,
	// never left equal — a tie hands the chain's order to random ULID
	// entropy.
	if got, want := nextOccurredAt(tip, tip), tip.Add(time.Microsecond); !got.Equal(want) {
		t.Errorf("nextOccurredAt(now == tip) = %v, want %v", got, want)
	}

	// A backwards wall-clock step (NTP correction, VM suspend/resume): the
	// chain must still move forward.
	if got, want := nextOccurredAt(tip.Add(-time.Hour), tip), tip.Add(time.Microsecond); !got.Equal(want) {
		t.Errorf("nextOccurredAt(now behind tip) = %v, want %v", got, want)
	}

	// An empty chain (zero tip) must not clamp anything.
	if got := nextOccurredAt(now, time.Time{}); !got.Equal(now.UTC().Truncate(time.Microsecond)) {
		t.Errorf("nextOccurredAt with no tip = %v, want now truncated (%v)", got, now.UTC().Truncate(time.Microsecond))
	}
}
