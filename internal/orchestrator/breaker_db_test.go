package orchestrator

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"argus/internal/data"
	"argus/internal/dbtest"
	"argus/internal/domain"
)

// The circuit breaker's real behaviour is a property of live Postgres, not of Go:
// the counting query spans two tables with a UNION, the trip is guarded by a
// partial unique index, and the whole thing runs under FORCE ROW LEVEL SECURITY.
// None of that is exercised by a unit test with no database — and the B2 bug this
// session (an RLS-emptied LEFT JOIN that compiled, ran, and silently did nothing)
// is exactly why the counting query needs to be run against real policies rather
// than reviewed.
//
// Uses the same ARGUS_TEST_DATABASE_URL harness as db_test.go, under argus_app
// rather than the superuser, so these see the same RLS the hub does.

// breakerFixture inserts a throwaway cluster plus a recommendation to hang
// executions off, and returns a *dbtest.Fixture tracking the deterministic
// part of what it created (clusters/incidents/analyses/
// remediation_recommendations). It does NOT call Cleanup itself: six test
// functions share this fixture, each adding a different, test-specific
// number of remediation_executions rows (via addExecution) and 0 or 1
// circuit_breaker_trips row (via CheckBreaker, through checkBreakerIn) —
// only the calling test knows those counts, so only it can call
// fixture.Cleanup.
func breakerFixture(t *testing.T, pool *pgxpool.Pool) (fixture *dbtest.Fixture, tenantID, clusterID, incidentID, recID string) {
	t.Helper()
	ctx := context.Background()

	clusterID = domain.NewID(domain.PrefixCluster)
	incidentID = domain.NewID(domain.PrefixIncident)
	recID = domain.NewID(domain.PrefixPlan)

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
		clusterID, tenantID, "breaker-test-"+clusterID, "fp-"+clusterID); err != nil {
		t.Fatalf("insert cluster: %v", err)
	}
	fixture.Created("clusters", 1)
	now := time.Now()
	if _, err := tx.Exec(ctx,
		`INSERT INTO incidents (id, tenant_id, cluster_id, fingerprint, severity, state, first_seen, last_seen, occurrence_count)
		 VALUES ($1, $2, $3, $4, 'high', 'Validating', $5, $5, 1)`,
		incidentID, tenantID, clusterID, "test-breaker-"+incidentID, now); err != nil {
		t.Fatalf("insert incident: %v", err)
	}
	fixture.Created("incidents", 1)

	analysisID := domain.NewID(domain.PrefixAnalysis)
	if _, err := tx.Exec(ctx,
		`INSERT INTO analyses
		   (id, tenant_id, incident_id, cluster_id, prompt_version, model, causal_chain,
		    iterations, duration_ms, tokens_billed_in, tokens_cache_read, tokens_out, cost_usd)
		 VALUES ($1, $2, $3, $4, 'test', 'test-model', '[]'::jsonb, 1, 1, 0, 0, 0, 0)`,
		analysisID, tenantID, incidentID, clusterID); err != nil {
		t.Fatalf("insert analysis: %v", err)
	}
	fixture.Created("analyses", 1)
	if _, err := tx.Exec(ctx,
		`INSERT INTO remediation_recommendations
		   (id, incident_id, tenant_id, cluster_id, analysis_id, action_type, target_gvk,
		    target_namespace, target_name, params, reversible, risk_level, gate_outcome, gate_reason)
		 VALUES ($1, $2, $3, $4, $5, 'ScaleDeployment', 'apps/v1/Deployment',
		         'default', 'breaker-test', '{}'::jsonb, true, 'low', 'AutoApprove', 'test')`,
		recID, incidentID, tenantID, clusterID, analysisID); err != nil {
		t.Fatalf("insert recommendation: %v", err)
	}
	fixture.Created("remediation_recommendations", 1)
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit setup: %v", err)
	}

	return fixture, tenantID, clusterID, incidentID, recID
}

// cleanupBreakerFixture runs fixture.Cleanup with the full delete list every
// test built on breakerFixture needs — the caller must have already tracked
// the test-specific remediation_executions/circuit_breaker_trips counts via
// fixture.Created before calling this.
func cleanupBreakerFixture(fixture *dbtest.Fixture, pool *pgxpool.Pool, tenantID, clusterID string) {
	fixture.Cleanup(pool, func(ctx context.Context, tx pgx.Tx) error {
		return data.SetRequestScope(ctx, tx, tenantID, []string{clusterID})
	}, []dbtest.TableDelete{
		{Table: "circuit_breaker_trips", SQL: `DELETE FROM circuit_breaker_trips WHERE cluster_id = $1`, Args: []any{clusterID}},
		{Table: "remediation_executions", SQL: `DELETE FROM remediation_executions WHERE cluster_id = $1`, Args: []any{clusterID}},
		{Table: "remediation_recommendations", SQL: `DELETE FROM remediation_recommendations WHERE cluster_id = $1`, Args: []any{clusterID}},
		// BUGS.md 119: same delete-order footgun as clearDemoData — this
		// fixture doesn't insert evidence/analysis_embeddings today, but
		// clearing them before analyses matches every other fixture in
		// this package. Tracked at 0 below (see each test's own
		// fixture.Created calls).
		{Table: "evidence", SQL: `DELETE FROM evidence WHERE analysis_id IN (SELECT id FROM analyses WHERE cluster_id = $1)`, Args: []any{clusterID}},
		{Table: "analysis_embeddings", SQL: `DELETE FROM analysis_embeddings WHERE analysis_id IN (SELECT id FROM analyses WHERE cluster_id = $1)`, Args: []any{clusterID}},
		{Table: "analyses", SQL: `DELETE FROM analyses WHERE cluster_id = $1`, Args: []any{clusterID}},
		{Table: "incidents", SQL: `DELETE FROM incidents WHERE cluster_id = $1`, Args: []any{clusterID}},
		{Table: "clusters", SQL: `DELETE FROM clusters WHERE id = $1`, Args: []any{clusterID}},
	})
}

func addExecution(t *testing.T, pool *pgxpool.Pool, tenantID, clusterID, incidentID, recID, outcome string, age time.Duration) {
	t.Helper()
	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if err := data.SetRequestScope(ctx, tx, tenantID, []string{clusterID}); err != nil {
		t.Fatalf("scope: %v", err)
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO remediation_executions
		   (id, recommendation_id, incident_id, tenant_id, cluster_id, outcome, executed_at)
		 VALUES ($1, $2, $3, $4, $5, $6, now() - $7::interval)`,
		domain.NewID(domain.PrefixExecution), recID, incidentID, tenantID, clusterID, outcome,
		age.String()); err != nil {
		t.Fatalf("insert %s execution: %v", outcome, err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit: %v", err)
	}
}

// setIncidentState moves an incident directly, bypassing SetState's transition
// table on purpose: these tests need a Reopened row to count, not a legal path to
// one, and SetState's rules are covered by state_test.go.
func setIncidentState(t *testing.T, pool *pgxpool.Pool, tenantID, clusterID, incidentID, state string) {
	t.Helper()
	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if err := data.SetRequestScope(ctx, tx, tenantID, []string{clusterID}); err != nil {
		t.Fatalf("scope: %v", err)
	}
	if _, err := tx.Exec(ctx, `UPDATE incidents SET state = $2 WHERE id = $1`, incidentID, state); err != nil {
		t.Fatalf("set state %s: %v", state, err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit: %v", err)
	}
}

func checkBreakerIn(t *testing.T, pool *pgxpool.Pool, tenantID, clusterID string, limits BreakerLimits) BreakerDecision {
	t.Helper()
	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if err := data.SetRequestScope(ctx, tx, tenantID, []string{clusterID}); err != nil {
		t.Fatalf("scope: %v", err)
	}
	got, err := CheckBreaker(ctx, tx, tenantID, clusterID, limits)
	if err != nil {
		t.Fatalf("CheckBreaker: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit: %v", err)
	}
	return got
}

// TestBreakerTripsOnFailedExecutions is the core path: failures accumulate, the
// breaker trips at the threshold, and it STAYS tripped.
func TestBreakerTripsOnFailedExecutions(t *testing.T) {
	pool := testPool(t)
	fixture, tenantID, clusterID, incidentID, recID := breakerFixture(t, pool)

	// A high fleet-wide limit so this test is only about the per-cluster breaker;
	// the dev database contains real executions from other work, which is exactly
	// why the fleet-wide count cannot be assumed to start at zero.
	limits := BreakerLimits{Enabled: true, MaxPerCluster: 2, MaxFleetWide: 100000, Window: time.Hour}

	if got := checkBreakerIn(t, pool, tenantID, clusterID, limits); !got.Allowed {
		t.Fatalf("a clean cluster was refused: %s", got.Reason)
	}

	addExecution(t, pool, tenantID, clusterID, incidentID, recID, "failed", time.Minute)
	if got := checkBreakerIn(t, pool, tenantID, clusterID, limits); !got.Allowed {
		t.Fatalf("one failure of a permitted two tripped the breaker: %s", got.Reason)
	}

	addExecution(t, pool, tenantID, clusterID, incidentID, recID, "failed", 2*time.Minute)
	got := checkBreakerIn(t, pool, tenantID, clusterID, limits)
	if got.Allowed {
		t.Fatal("two failures against a limit of two did not trip the breaker")
	}
	if !got.TrippedNow {
		t.Error("TrippedNow = false on the evaluation that crossed the threshold")
	}

	// Still refused on a later evaluation, and NOT reported as newly tripped — a
	// standing trip must be honoured without re-announcing itself every sweep.
	again := checkBreakerIn(t, pool, tenantID, clusterID, limits)
	if again.Allowed {
		t.Error("the breaker re-closed on its own; reset is supposed to be manual")
	}
	if again.TrippedNow {
		t.Error("TrippedNow = true for an already-open trip — the caller would log the trip line on every sweep")
	}

	// Exactly one open trip, however many times it was evaluated. This is the
	// partial unique index doing its job.
	var open int
	tx, _ := pool.Begin(context.Background())
	defer tx.Rollback(context.Background()) //nolint:errcheck
	_ = data.SetRequestScope(context.Background(), tx, tenantID, []string{clusterID})
	if err := tx.QueryRow(context.Background(),
		`SELECT count(*) FROM circuit_breaker_trips WHERE cluster_id = $1 AND reset_at IS NULL`,
		clusterID).Scan(&open); err != nil {
		t.Fatalf("count open trips: %v", err)
	}
	if open != 1 {
		t.Errorf("open trips = %d, want exactly 1 — repeated evaluation must not accumulate rows", open)
	}

	// Two failed executions, and the trip that crossed the threshold.
	fixture.Created("remediation_executions", 2)
	fixture.Created("circuit_breaker_trips", 1)
	fixture.Created("evidence", 0)
	fixture.Created("analysis_embeddings", 0)
	cleanupBreakerFixture(fixture, pool, tenantID, clusterID)
}

// TestBreakerIgnoresOutcomesOutsideTheWindow: the window has to actually bound the
// count, or a breaker becomes a permanent record of every failure an installation
// has ever had.
func TestBreakerIgnoresOutcomesOutsideTheWindow(t *testing.T) {
	pool := testPool(t)
	fixture, tenantID, clusterID, incidentID, recID := breakerFixture(t, pool)
	limits := BreakerLimits{Enabled: true, MaxPerCluster: 2, MaxFleetWide: 100000, Window: 10 * time.Minute}

	addExecution(t, pool, tenantID, clusterID, incidentID, recID, "failed", 2*time.Hour)
	addExecution(t, pool, tenantID, clusterID, incidentID, recID, "failed", 3*time.Hour)
	addExecution(t, pool, tenantID, clusterID, incidentID, recID, "failed", 90*time.Minute)

	if got := checkBreakerIn(t, pool, tenantID, clusterID, limits); !got.Allowed {
		t.Fatalf("three failures all older than the 10-minute window tripped the breaker: %s", got.Reason)
	}

	// Three failed executions, all outside the window, so the breaker never trips.
	fixture.Created("remediation_executions", 3)
	fixture.Created("circuit_breaker_trips", 0)
	fixture.Created("evidence", 0)
	fixture.Created("analysis_embeddings", 0)
	cleanupBreakerFixture(fixture, pool, tenantID, clusterID)
}

// TestBreakerCountsARevertedFixAsBad is the outcome only V1 made observable: the
// API call succeeded and the change did not hold. A breaker that watched only for
// errors would sit closed straight through this.
func TestBreakerCountsARevertedFixAsBad(t *testing.T) {
	pool := testPool(t)
	fixture, tenantID, clusterID, incidentID, recID := breakerFixture(t, pool)
	limits := BreakerLimits{Enabled: true, MaxPerCluster: 1, MaxFleetWide: 100000, Window: time.Hour}

	// A SUCCEEDED execution, on an incident that is Reopened.
	addExecution(t, pool, tenantID, clusterID, incidentID, recID, "succeeded", time.Minute)

	setIncidentState(t, pool, tenantID, clusterID, incidentID, "Reopened")

	got := checkBreakerIn(t, pool, tenantID, clusterID, limits)
	if got.Allowed {
		t.Fatal("a successful execution whose incident then reopened was not counted as a bad outcome — this is the failure mode the breaker exists for, and the one an error-only breaker misses")
	}

	// One reverted-fix execution, and the single evaluation that crossed the
	// MaxPerCluster: 1 threshold.
	fixture.Created("remediation_executions", 1)
	fixture.Created("circuit_breaker_trips", 1)
	fixture.Created("evidence", 0)
	fixture.Created("analysis_embeddings", 0)
	cleanupBreakerFixture(fixture, pool, tenantID, clusterID)
}

// TestBreakerCountsARevertedIncidentOnce covers the DISTINCT on the reverted-fix
// half only.
//
// Three SUCCESSFUL executions on one Reopened incident describe a single state —
// "this incident's fix did not hold" — read through a JOIN that yields three rows
// for it. Counting those rows would be counting a join artifact. Note the contrast
// with TestBreakerCountsEachFailedExecution: three FAILED executions on one
// incident are three real events and do count three times.
func TestBreakerCountsARevertedIncidentOnce(t *testing.T) {
	pool := testPool(t)
	fixture, tenantID, clusterID, incidentID, recID := breakerFixture(t, pool)

	setIncidentState(t, pool, tenantID, clusterID, incidentID, "Reopened")

	// Three successful-then-reverted attempts on ONE incident.
	for i := 0; i < 3; i++ {
		addExecution(t, pool, tenantID, clusterID, incidentID, recID, "succeeded", time.Duration(i+1)*time.Minute)
	}

	limits := BreakerLimits{Enabled: true, MaxPerCluster: 2, MaxFleetWide: 100000, Window: time.Hour}
	if got := checkBreakerIn(t, pool, tenantID, clusterID, limits); !got.Allowed {
		t.Fatalf("three reverted attempts on ONE incident counted as more than one bad outcome against a limit of two: %s", got.Reason)
	}

	// Three executions, but DISTINCT-on-incident means one bad outcome — below
	// the MaxPerCluster: 2 threshold, so the breaker never trips.
	fixture.Created("remediation_executions", 3)
	fixture.Created("circuit_breaker_trips", 0)
	fixture.Created("evidence", 0)
	fixture.Created("analysis_embeddings", 0)
	cleanupBreakerFixture(fixture, pool, tenantID, clusterID)
}

// TestBreakerCountsEachFailedExecution is the other side of the asymmetry, and the
// case a dedupe-everything implementation got wrong: a stuck retry loop on ONE
// incident must trip the breaker. It is the most likely real failure and the least
// likely to resolve itself, and a breaker that deduplicated it by incident would
// let it spin at the volume cap indefinitely.
func TestBreakerCountsEachFailedExecution(t *testing.T) {
	pool := testPool(t)
	fixture, tenantID, clusterID, incidentID, recID := breakerFixture(t, pool)
	limits := BreakerLimits{Enabled: true, MaxPerCluster: 3, MaxFleetWide: 100000, Window: time.Hour}

	for i := 1; i <= 2; i++ {
		addExecution(t, pool, tenantID, clusterID, incidentID, recID, "failed", time.Duration(i)*time.Minute)
	}
	if got := checkBreakerIn(t, pool, tenantID, clusterID, limits); !got.Allowed {
		t.Fatalf("two failures against a limit of three tripped early: %s", got.Reason)
	}

	addExecution(t, pool, tenantID, clusterID, incidentID, recID, "failed", 3*time.Minute)
	got := checkBreakerIn(t, pool, tenantID, clusterID, limits)
	if got.Allowed {
		t.Fatal("three failed executions on ONE incident did not trip a limit of three — a stuck retry loop would spin at the volume cap forever")
	}
	if !got.TrippedNow {
		t.Error("TrippedNow = false on the evaluation that crossed the threshold")
	}

	// Three failed executions, and the trip that crossed the threshold.
	fixture.Created("remediation_executions", 3)
	fixture.Created("circuit_breaker_trips", 1)
	fixture.Created("evidence", 0)
	fixture.Created("analysis_embeddings", 0)
	cleanupBreakerFixture(fixture, pool, tenantID, clusterID)
}

// TestBreakerCountsAFailureAndARevertSeparately: an incident that both failed once
// and had a separate successful-then-reverted fix has had two different things go
// wrong. An earlier UNION-based count collapsed them into one.
func TestBreakerCountsAFailureAndARevertSeparately(t *testing.T) {
	pool := testPool(t)
	fixture, tenantID, clusterID, incidentID, recID := breakerFixture(t, pool)
	limits := BreakerLimits{Enabled: true, MaxPerCluster: 2, MaxFleetWide: 100000, Window: time.Hour}

	addExecution(t, pool, tenantID, clusterID, incidentID, recID, "failed", time.Minute)
	addExecution(t, pool, tenantID, clusterID, incidentID, recID, "succeeded", 2*time.Minute)
	setIncidentState(t, pool, tenantID, clusterID, incidentID, "Reopened")

	if got := checkBreakerIn(t, pool, tenantID, clusterID, limits); got.Allowed {
		t.Fatal("one failed execution plus one reverted fix on the same incident counted as fewer than two bad outcomes")
	}

	// One failed execution plus one reverted fix — two distinct bad outcomes,
	// crossing the MaxPerCluster: 2 threshold on this one evaluation.
	fixture.Created("remediation_executions", 2)
	fixture.Created("circuit_breaker_trips", 1)
	fixture.Created("evidence", 0)
	fixture.Created("analysis_embeddings", 0)
	cleanupBreakerFixture(fixture, pool, tenantID, clusterID)
}
