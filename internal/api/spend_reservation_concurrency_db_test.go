package api

import (
	"context"
	"os"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"argus/internal/data"
	"argus/internal/dbtest"
	"argus/internal/domain"
	"argus/internal/settings"
)

// spendReservationTestPool matches every other DB-backed test fixture in
// this codebase (orchestrator/db_test.go's testPool, analyze_detach_db_test.go's
// analyzeDetachTestPool): a real Postgres behind ARGUS_TEST_DATABASE_URL, as
// argus_app so this runs under the same FORCE ROW LEVEL SECURITY the hub
// itself does, skipped cleanly when unset.
func spendReservationTestPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	connString := os.Getenv("ARGUS_TEST_DATABASE_URL")
	if connString == "" {
		t.Skip("ARGUS_TEST_DATABASE_URL not set; skipping PROJECT.md T10 spend-reservation concurrency test")
	}
	pool, err := pgxpool.New(context.Background(), connString)
	if err != nil {
		t.Fatalf("connect to test database: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

// TestReserveSpend_ConcurrentInvestigationsNeverCollectivelyExceedCeiling is
// PROJECT.md T10 / lld/01-threat-model.md T12, SR-13's own acceptance test:
// "concurrent investigations cannot collectively exceed the daily ceiling."
//
// A SEQUENTIAL test cannot prove this — calling ReserveSpend twice in a row
// on one goroutine never exercises the actual race, which only exists
// between two callers whose transactions overlap in time. This test launches
// concurrentReservationAttempts goroutines, each on its OWN pgxpool
// connection/transaction (mirroring internal/autoanalyze's investigateOne,
// which opens one transaction per incident and runs several concurrently via
// runWaves), all racing to reserve against the SAME tenant+day ceiling at
// the same moment.
//
// The ceiling and per-reservation cost are chosen so the answer is exact,
// not just "roughly under budget": ceilingUSD is precisely
// admissibleReservations * perReservationUSD, and the check inside
// ReserveSpend is "would this reservation take the total OVER the ceiling"
// (strictly greater than) — so exactly admissibleReservations reservations
// must succeed and every other concurrent attempt must be refused,
// REGARDLESS of goroutine scheduling order. Before this task's fix (a bare
// read-then-write with no lock), running this with GOMAXPROCS > 1 and a real
// Postgres reliably let MORE than admissibleReservations succeed, because
// two goroutines could both read the same "nothing reserved yet" total
// before either had written its own row — this test is written so it would
// fail exactly that way if ReserveSpend's advisory-lock serialization were
// ever removed or narrowed.
func TestReserveSpend_ConcurrentInvestigationsNeverCollectivelyExceedCeiling(t *testing.T) {
	pool := spendReservationTestPool(t)
	ctx := context.Background()

	tenantID := resolveTenantIDForTest(t, pool)

	const (
		concurrentReservationAttempts = 20
		admissibleReservations        = 5
		perReservationUSD             = 0.06                                       // 1 iteration * 60,000 tokens/iteration @ $1/M
		ceilingUSD                    = admissibleReservations * perReservationUSD // 0.30
	)

	ceiling := ceilingUSD
	maxIterations := 1
	cfg := settings.Config{
		PricePerMillionInputTokens:  floatPtr(1),
		PricePerMillionCachedTokens: floatPtr(1),
		PricePerMillionOutputTokens: floatPtr(1),
		DailySpendCeilingUsd:        &ceiling,
		AnalysisMaxIterations:       &maxIterations,
		// LLMProviderKind left empty: NormalizeProviderKind("") ==
		// ProviderKindAPI, so ActiveProviderSpendCountable() is true and a
		// reservation is actually attempted rather than short-circuited.
	}
	if got := projectedInvestigationCostUSD(cfg); got != perReservationUSD {
		t.Fatalf("projectedInvestigationCostUSD = %v, want %v — this test's admissibleReservations math assumes this exact figure; fix the test's cfg before trusting the rest of it", got, perReservationUSD)
	}

	clusterID := domain.NewID(domain.PrefixCluster)
	incidentIDs := make([]string, concurrentReservationAttempts)
	for i := range incidentIDs {
		incidentIDs[i] = domain.NewID(domain.PrefixIncident)
	}

	var (
		wg          sync.WaitGroup
		successes   int64
		reservedIDs = make([]string, concurrentReservationAttempts)
	)
	start := make(chan struct{})
	for i := 0; i < concurrentReservationAttempts; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start // release every goroutine at once, for maximum overlap

			tx, err := pool.Begin(ctx)
			if err != nil {
				t.Errorf("goroutine %d: begin: %v", i, err)
				return
			}
			defer tx.Rollback(ctx) //nolint:errcheck

			if err := data.SetRequestScope(ctx, tx, tenantID, []string{clusterID}); err != nil {
				t.Errorf("goroutine %d: set request scope: %v", i, err)
				return
			}

			reservation, ok, err := ReserveSpend(ctx, tx, cfg, tenantID, incidentIDs[i], clusterID)
			if err != nil {
				t.Errorf("goroutine %d: ReserveSpend: %v", i, err)
				return
			}
			if !ok {
				// Refused — exactly what must happen once the ceiling's
				// headroom is spent. Nothing to commit.
				return
			}
			if !reservation.Active {
				t.Errorf("goroutine %d: ReserveSpend ok=true but reservation.Active=false — a real ceiling is configured, this must have written a row", i)
				return
			}
			if err := tx.Commit(ctx); err != nil {
				t.Errorf("goroutine %d: commit: %v", i, err)
				return
			}
			reservedIDs[i] = reservation.ID
			atomic.AddInt64(&successes, 1)
		}(i)
	}
	close(start)
	wg.Wait()

	// Collect the reservation ids this run actually created, for cleanup and
	// for the DB-side sum check below.
	var createdIDs []string
	for _, id := range reservedIDs {
		if id != "" {
			createdIDs = append(createdIDs, id)
		}
	}
	fx := dbtest.New(t)
	fx.Created("spend_reservations", len(createdIDs))
	fx.Cleanup(pool,
		func(ctx context.Context, tx pgx.Tx) error {
			return data.SetRequestScope(ctx, tx, tenantID, []string{clusterID})
		},
		[]dbtest.TableDelete{{
			Table: "spend_reservations",
			SQL:   `DELETE FROM spend_reservations WHERE id = ANY($1)`,
			Args:  []any{createdIDs},
		}},
	)

	// The headline assertion: THE ACTUAL INVARIANT, not just a proxy for it.
	// Read back every reservation this run created and sum reserved_usd —
	// the same figure a concurrent ReserveSpend call would have computed —
	// and assert it never exceeds the ceiling, independent of how many
	// individual goroutines happened to succeed.
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin verification transaction: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if err := data.SetRequestScope(ctx, tx, tenantID, []string{clusterID}); err != nil {
		t.Fatalf("set request scope: %v", err)
	}
	var totalReservedUSD float64
	var rowCount int
	if err := tx.QueryRow(ctx,
		`SELECT COALESCE(SUM(reserved_usd), 0)::float8, COUNT(*) FROM spend_reservations WHERE id = ANY($1)`,
		createdIDs,
	).Scan(&totalReservedUSD, &rowCount); err != nil {
		t.Fatalf("sum reserved rows: %v", err)
	}

	successCount := int(atomic.LoadInt64(&successes))
	if successCount != rowCount {
		t.Fatalf("goroutines reporting success = %d, rows actually persisted = %d — these must agree", successCount, rowCount)
	}

	t.Logf("%d goroutines attempted a reservation concurrently against a $%.2f ceiling (each reservation projected at $%.2f); %d succeeded, %d were refused; total reserved = $%.2f",
		concurrentReservationAttempts, ceilingUSD, perReservationUSD, successCount, concurrentReservationAttempts-successCount, totalReservedUSD)

	if totalReservedUSD > ceilingUSD+1e-9 {
		t.Fatalf("THE INVARIANT THIS TASK EXISTS TO PROVE FAILED: total reserved $%.4f exceeds the $%.4f daily ceiling after %d concurrent reservation attempts — the check-then-act race is not actually closed", totalReservedUSD, ceilingUSD, concurrentReservationAttempts)
	}

	// Not just "under the ceiling" but EXACTLY admissibleReservations,
	// because this test's numbers were chosen to make that the only
	// possible correct answer, from any goroutine interleaving, once the
	// race is actually closed. A weaker outcome here (fewer succeeding than
	// the ceiling allows) would itself indicate a bug — reservations
	// serializing correctly but rejecting attempts that should have fit.
	if successCount != admissibleReservations {
		t.Fatalf("successful reservations = %d, want exactly %d — %d concurrent attempts against a $%.2f ceiling sized for exactly %d $%.2f reservations must admit exactly that many, never more (the race) and never fewer (an over-conservative bug)",
			successCount, admissibleReservations, concurrentReservationAttempts, ceilingUSD, admissibleReservations, perReservationUSD)
	}
}

// resolveTenantIDForTest reads the shared dev tenant the same way
// orchestrator/db_test.go's testIncident and analyze_detach_db_test.go's
// analyzeDetachTestIncident already do (data.SingleOrganisationID) — this
// test creates no organisation of its own because spend_reservations.tenant_id
// carries a real foreign key to organisations(id), and every row this test
// writes is cleaned up by exact id, never by tenant_id (see the dbtest.Fixture
// use above), so sharing the tenant cannot leak into or be perturbed by
// unrelated data the way a tenant_id-wide DELETE would risk.
func resolveTenantIDForTest(t *testing.T, pool *pgxpool.Pool) string {
	t.Helper()
	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("resolve tenant: begin: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	tenantID, err := data.SingleOrganisationID(ctx, tx)
	if err != nil {
		t.Fatalf("resolve organisation: %v", err)
	}
	return tenantID
}
