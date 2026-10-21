package api

// PROJECT.md T11's analysis-cost metric, proven against the real
// PersistAnalysis contract rather than merely against Counter's own
// already-unit-tested arithmetic (internal/metrics' own tests cover that):
// this replicates the EXACT expression handleAnalyzeIncident uses right
// after its PersistAnalysis call —
// metrics.AnalysisCostUSDTotal.Add(costUSD, "manual", costBasisOrDefault(result.CostBasis))
// — against a real row PersistAnalysis just wrote, so a future change to
// what PersistAnalysis returns or how costBasisOrDefault normalizes a basis
// would break this test the same way it would break the real handler.
//
// AnalysisDurationSeconds (the OTHER T11 metric this file's package adds) is
// not given an equivalent DB test: it wraps the live llm.Investigator.Investigate
// call inside handleAnalyzeIncident/autoanalyze.investigateOne, and this
// package's own existing DB tests (analyze_detach_db_test.go and siblings)
// exercise PersistAnalysis directly rather than that full HTTP-handler-plus-
// investigation-loop path, which would need a fake llm.Investigator wired
// through a fully-constructed *Server — disproportionate machinery this
// task did not build. metrics.AnalysisDurationSeconds.Observe's own
// mechanics (bucket placement, sum/count) are covered by
// internal/metrics/metrics_test.go instead. Flagged here rather than left
// silent.

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"argus/internal/data"
	"argus/internal/domain"
	"argus/internal/llm"
	"argus/internal/metrics"
)

func costCounterValue(t *testing.T, trigger, costBasis string) float64 {
	t.Helper()
	var buf strings.Builder
	metrics.DefaultRegistry.WriteExposition(&buf)
	want := `argus_analysis_cost_usd_total{trigger="` + trigger + `",cost_basis="` + costBasis + `"} `
	for _, line := range strings.Split(buf.String(), "\n") {
		if strings.HasPrefix(line, want) {
			var v float64
			if _, err := fmt.Sscanf(strings.TrimPrefix(line, want), "%g", &v); err != nil {
				t.Fatalf("parse counter line %q: %v", line, err)
			}
			return v
		}
	}
	return 0
}

func TestAnalysisCostMetric_MatchesPersistAnalysisReturnValue(t *testing.T) {
	pool := analyzeDetachTestPool(t)
	tenantID, clusterID, incidentID := analyzeDetachTestIncident(t, pool)
	ctx := context.Background()

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if err := data.SetRequestScope(ctx, tx, tenantID, []string{clusterID}); err != nil {
		t.Fatalf("set request scope: %v", err)
	}

	// A subscription-basis result carries its own CostUSD/CostBasis
	// verbatim through PersistAnalysis (see that function's own "two cost
	// paths" comment) — a fixed, known, non-zero figure this test can
	// assert an EXACT delta against, unlike the metered/derive-from-tokens
	// path a zero-token fake result would trivially satisfy with 0.
	confidence := 0.9
	result := llm.Investigation{
		Model:      "test-model",
		Status:     "complete",
		RootCause:  &llm.RootCause{Statement: "T11 cost-metric regression test root cause"},
		Confidence: &confidence,
		CostBasis:  llm.CostBasisSubscription,
		CostUSD:    3.5,
	}

	before := costCounterValue(t, "manual", llm.CostBasisSubscription)

	analysisID := domain.NewID(domain.PrefixAnalysis)
	costUSD, err := PersistAnalysis(ctx, tx, tenantID, analysisID, incidentID, clusterID, result, time.Now(), TriggeredByManual)
	if err != nil {
		t.Fatalf("PersistAnalysis: %v", err)
	}
	if costUSD != 3.5 {
		t.Fatalf("PersistAnalysis returned costUSD=%v for a subscription-basis result, want 3.5 verbatim", costUSD)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit: %v", err)
	}

	// The exact expression handleAnalyzeIncident runs right after its own
	// PersistAnalysis call — see this file's own doc comment.
	metrics.AnalysisCostUSDTotal.Add(costUSD, "manual", costBasisOrDefault(result.CostBasis))

	after := costCounterValue(t, "manual", llm.CostBasisSubscription)
	if after != before+3.5 {
		t.Fatalf(`argus_analysis_cost_usd_total{trigger="manual",cost_basis="subscription"} went from %v to %v, want exactly +3.5`, before, after)
	}
}
