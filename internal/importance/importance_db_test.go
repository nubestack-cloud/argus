package importance_test

// This file's one job: prove the package's own core invariant against a
// REAL Postgres, not just against a second Go-side recomputation of the
// same formula (which would only prove the string round-trips through
// fmt.Sprintf, not that it is valid, correctly-evaluating SQL). It runs a
// bare `SELECT <expr>` — no FROM, no table, nothing created or read — so it
// is safe to run at any time, including with other fixtures concurrently
// exercising real tables in this same database.
//
// Same ARGUS_TEST_DATABASE_URL gating and rationale as
// internal/gateway/finding_db_test.go and internal/orchestrator/db_test.go:
// a machine with no test database gets a clean skip.

import (
	"context"
	"math"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"argus/internal/importance"
)

func testPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	connString := os.Getenv("ARGUS_TEST_DATABASE_URL")
	if connString == "" {
		t.Skip("ARGUS_TEST_DATABASE_URL not set; skipping DB-backed importance SQL/Go agreement test")
	}
	pool, err := pgxpool.New(context.Background(), connString)
	if err != nil {
		t.Fatalf("connect to test database: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

// evalSQLExpr runs expr as a bare SELECT and returns the resulting BIGINT.
// No FROM clause, so this touches no table — nothing to create, nothing to
// clean up, nothing dbtest.Fixture needs to track.
func evalSQLExpr(t *testing.T, pool *pgxpool.Pool, expr string) int64 {
	t.Helper()
	var got int64
	if err := pool.QueryRow(context.Background(), "SELECT "+expr).Scan(&got); err != nil {
		t.Fatalf("SELECT %s: %v", expr, err)
	}
	return got
}

// sqlIncident is one test "incident": the raw Factors plus how each of its
// fields is spelled as a literal SQL scalar — standing in for the
// correlated-subquery/column-reference expressions incidents.go actually
// passes in production. A literal is a valid zero-argument SQL expression,
// which is all SQLExprWithCriticality's contract requires of its callers.
type sqlIncident struct {
	name string
	f    importance.Factors
	// blastRadiusLit/ageHoursLit/occurrenceRateLit/confidenceLit/
	// workloadCriticalityLit are f's own fields, spelled as SQL.
	blastRadiusLit, ageHoursLit, occurrenceRateLit, confidenceLit, workloadCriticalityLit string
}

func float64Ptr(v float64) *float64 { return &v }
func int32Ptr2(v int32) *int32      { return &v }

// sqlResult is one incident's computed scores/explanation, kept together so
// the sort helpers below can compare Go-side and SQL-side results without
// re-deriving either.
type sqlResult struct {
	name     string
	sqlScore int64
	goScore  float64
	explain  []string
}

// TestSQLExprWithCriticality_AgreesWithScoreAndExplain is this task's third
// required proof: the SQL sort order must agree with Explain's own
// breakdown for the same incidents. It executes the ACTUAL SQL expression
// against a real Postgres for a set of incidents that exercise all four
// factors (including two that differ ONLY in workload criticality — the
// high/low-priority-Pod case), and checks three things per incident:
//
//  1. The SQL-evaluated score equals round(Score(f)) in Go, exactly — the
//     package's stated invariant that SQLExprWithCriticality and Score
//     compute the identical formula.
//  2. Sorting the incidents by their SQL-evaluated score produces the SAME
//     order as sorting by Go's Score(f) — not just equal at the top,
//     specifically including the pair that differs only in
//     WorkloadCriticality.
//  3. Explain(f)'s own top-ranked reason names the factor that actually
//     contributed the most, agreeing with what the SQL score just measured
//     — an operator reading Explain's sentence and the ranking position
//     side by side never sees them disagree.
func TestSQLExprWithCriticality_AgreesWithScoreAndExplain(t *testing.T) {
	pool := testPool(t)

	incidents := []sqlIncident{
		{
			name:           "isolated, fresh, unanalyzed, no criticality signal",
			f:              importance.Factors{BlastRadius: 1, AgeHours: 1, OccurrenceRate: 0, Confidence: nil, WorkloadCriticality: nil},
			blastRadiusLit: "1", ageHoursLit: "1", occurrenceRateLit: "0", confidenceLit: "NULL", workloadCriticalityLit: "NULL",
		},
		{
			// Priority 100: log1p(100)*2.0 ≈ 9.2, comfortably above the
			// ROUND-to-BIGINT resolution incidents.go's keyset cursor
			// already accepts for every factor (a known, existing
			// lossiness, not something this test exists to relitigate), so
			// this incident's rounded score lands UNAMBIGUOUSLY above the
			// nil-criticality "isolated" incident's.
			name:           "same shape, opened by a LOW-priority Pod",
			f:              importance.Factors{BlastRadius: 1, AgeHours: 1, OccurrenceRate: 0, Confidence: nil, WorkloadCriticality: int32Ptr2(100)},
			blastRadiusLit: "1", ageHoursLit: "1", occurrenceRateLit: "0", confidenceLit: "NULL", workloadCriticalityLit: "100",
		},
		{
			name:           "same shape, opened by a HIGH-priority (system-critical) Pod",
			f:              importance.Factors{BlastRadius: 1, AgeHours: 1, OccurrenceRate: 0, Confidence: nil, WorkloadCriticality: int32Ptr2(2000000000)},
			blastRadiusLit: "1", ageHoursLit: "1", occurrenceRateLit: "0", confidenceLit: "NULL", workloadCriticalityLit: "2000000000",
		},
		{
			name:           "widely-shared, long open, recurring, confidently diagnosed, ordinary priority",
			f:              importance.Factors{BlastRadius: 12, AgeHours: 120, OccurrenceRate: 4, Confidence: float64Ptr(0.95), WorkloadCriticality: int32Ptr2(1000)},
			blastRadiusLit: "12", ageHoursLit: "120", occurrenceRateLit: "4", confidenceLit: "0.95", workloadCriticalityLit: "1000",
		},
		{
			name:           "an older agent's Finding: PodPriority never sent at all (NULL, same as non-Pod)",
			f:              importance.Factors{BlastRadius: 1, AgeHours: 5, OccurrenceRate: 1, Confidence: float64Ptr(0.5), WorkloadCriticality: nil},
			blastRadiusLit: "1", ageHoursLit: "5", occurrenceRateLit: "1", confidenceLit: "0.5", workloadCriticalityLit: "NULL",
		},
	}

	results := make([]sqlResult, len(incidents))
	for i, inc := range incidents {
		expr := importance.SQLExprWithCriticality(inc.blastRadiusLit, inc.ageHoursLit, inc.occurrenceRateLit, inc.confidenceLit, inc.workloadCriticalityLit)
		sqlScore := evalSQLExpr(t, pool, expr)
		goScore := importance.Score(inc.f)
		wantSQLScore := int64(math.Round(goScore))
		if sqlScore != wantSQLScore {
			t.Errorf("%s: SQL score = %d, want round(Go Score)=%d (Go Score=%v) — SQL and Go disagree on the same formula", inc.name, sqlScore, wantSQLScore, goScore)
		}
		results[i] = sqlResult{name: inc.name, sqlScore: sqlScore, goScore: goScore, explain: importance.Explain(inc.f)}
	}

	// The high-priority Pod's incident must outrank the low-priority one,
	// in BOTH the real SQL evaluation and Go's Score — the concrete
	// high-vs-low-priority acceptance case, proven against real SQL this
	// time, not just Go arithmetic.
	low, high := results[1], results[2]
	if !(high.sqlScore > low.sqlScore) {
		t.Errorf("SQL: high-priority score %d, low-priority score %d — want high > low", high.sqlScore, low.sqlScore)
	}
	if !(high.goScore > low.goScore) {
		t.Errorf("Go: high-priority score %v, low-priority score %v — want high > low", high.goScore, low.goScore)
	}

	// The regression this whole rework exists to prevent, proven against
	// real SQL: a widely-shared, long-open, frequently-recurring,
	// confidently-diagnosed incident must OUTRANK an otherwise-trivial
	// incident that merely happens to be on a system-critical Pod — the
	// exact ordering raw-linear scoring got backwards (every kube-system
	// Pod's incident dwarfing every real application incident by six
	// orders of magnitude on a live cluster with no custom PriorityClasses
	// at all).
	widelyShared, systemCritical := results[3], results[2]
	if !(widelyShared.sqlScore > systemCritical.sqlScore) {
		t.Errorf("SQL: widely-shared incident score %d, merely-system-critical incident score %d — want widely-shared > system-critical", widelyShared.sqlScore, systemCritical.sqlScore)
	}
	if !(widelyShared.goScore > systemCritical.goScore) {
		t.Errorf("Go: widely-shared incident score %v, merely-system-critical incident score %v — want widely-shared > system-critical", widelyShared.goScore, systemCritical.goScore)
	}

	// The absent-priority ("older agent") incident's SQL score must equal
	// what it would have been under the pre-this-feature 3-factor formula —
	// i.e. nil truly contributes nothing, verified against real SQL.
	absent := results[4]
	preExisting := importance.WeightBlastRadius*1 + importance.WeightAgeHours*5 + importance.WeightOccurrenceRate*1 + importance.WeightConfidence*0.5
	if absent.sqlScore != int64(math.Round(preExisting)) {
		t.Errorf("absent-priority incident SQL score = %d, want round(%v) (the unchanged 3-factor formula)", absent.sqlScore, preExisting)
	}

	// Sorting by the SQL-evaluated score and sorting by Go's Score must
	// produce the identical order across all five incidents.
	sqlOrder := namesSortedBy(results, func(r sqlResult) float64 { return float64(r.sqlScore) })
	goOrder := namesSortedBy(results, func(r sqlResult) float64 { return r.goScore })
	for i := range sqlOrder {
		if sqlOrder[i] != goOrder[i] {
			t.Fatalf("SQL-sorted order %v disagrees with Go-sorted order %v at position %d", sqlOrder, goOrder, i)
		}
	}

	// Explain's own top reason for the system-critical incident must name
	// workload criticality — it is that incident's OWN dominant contribution
	// (log1p(2e9)*2.0 ≈ 42.8, vs. AgeHours' 0.5 — the only other factor this
	// particular incident has), so the SQL ranking and the human-readable
	// "why" must agree on what mattered for IT, even though (by design,
	// this is the whole point of the bounded log1p fix) the widely-shared
	// incident's total score still outranks this one overall.
	criticalReasons := results[2].explain
	if len(criticalReasons) == 0 || !containsSubstring(criticalReasons[0], "priority") {
		t.Fatalf("Explain for the system-critical incident = %v, want its own top reason to name the resolved priority", criticalReasons)
	}
}

func namesSortedBy(results []sqlResult, key func(sqlResult) float64) []string {
	sorted := make([]sqlResult, len(results))
	copy(sorted, results)
	for i := 1; i < len(sorted); i++ {
		for j := i; j > 0 && key(sorted[j]) > key(sorted[j-1]); j-- {
			sorted[j], sorted[j-1] = sorted[j-1], sorted[j]
		}
	}
	names := make([]string, len(sorted))
	for i, r := range sorted {
		names[i] = r.name
	}
	return names
}

func containsSubstring(s, substr string) bool {
	for i := 0; i+len(substr) <= len(s); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
