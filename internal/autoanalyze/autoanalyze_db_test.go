package autoanalyze

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"argus/internal/data"
	"argus/internal/dbtest"
	"argus/internal/domain"
)

// testPool connects to a real Postgres for the one property this package's
// other, deliberately DB-free tests cannot exercise: that candidateQuery's
// own SQL, not just selectEligible's Go-side filtering, keeps a genuinely
// dispatchable incident from being starved out by rows that can never be
// dispatched (BUGS.md 120). Same precedent as
// internal/orchestrator/db_test.go's testPool: a real Postgres behind
// ARGUS_TEST_DATABASE_URL, argus_app (not the postgres superuser) so this runs
// under the same FORCE ROW LEVEL SECURITY the hub itself does, and a clean
// skip on a machine with no test database rather than a failure.
//
//	export ARGUS_TEST_DATABASE_URL="postgres://argus_app:dev-local-password@localhost:5432/argus?sslmode=disable"
func testPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	connString := os.Getenv("ARGUS_TEST_DATABASE_URL")
	if connString == "" {
		t.Skip("ARGUS_TEST_DATABASE_URL not set; skipping DB-backed autoanalyze tests (see this file's doc comment)")
	}
	pool, err := pgxpool.New(context.Background(), connString)
	if err != nil {
		t.Fatalf("connect to test database: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

// starvedFixture is one starvation-shape test's input: a cluster in some
// permanently- or temporarily-unreachable state, and one open incident on it
// that predates every other row in the fixture (so, pre-fix, it would win a
// candidate slot ahead of the genuinely fresh incident every time).
type starvedFixture struct {
	clusterState     string
	lastHeartbeatAgo time.Duration // 0 means NULL (never heartbeated)
	archived         bool
}

// setupStarvationFixture builds the exact shape BUGS.md 120 was found with —
// N incidents that are eligible by every OTHER filter (no analysis yet, an
// actionable incident state, never auto-analysis-attempted) but whose
// clusters will never dispatch again, plus one incident that is genuinely
// fresh and dispatchable — under a throwaway ORGANISATION of its own.
//
// A dedicated tenant, not just a dedicated cluster (contrast
// internal/orchestrator/db_test.go's testIncident, which reuses whatever
// tenant SingleOrganisationID resolves to): candidateQuery has no cluster_id
// or incident_id filter of its own — it is a per-tenant sweep over the whole
// incidents table — and this repo's own incidents/findings tables carry only
// a tenant-wide RLS policy (migration 000013's own comment: permissive
// policies OR together, so a narrowed app.accessible_cluster_ids does NOT
// narrow incidents visibility). Running this test against the shared dev
// tenant would mean asserting a small LIMIT against however many real
// incidents that deployment happens to have accumulated — exactly the kind of
// non-deterministic, environment-dependent test this fix's own bug was found
// by accident, not by design. A fresh tenant makes the fixture the ONLY thing
// candidateQuery can see.
func setupStarvationFixture(t *testing.T, pool *pgxpool.Pool, stale []starvedFixture) (tenantID, freshIncidentID string, clusterIDs []string) {
	t.Helper()
	ctx := context.Background()

	tenantID = domain.NewID(domain.PrefixOrganisation)
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin setup transaction: %v", err)
	}
	// organisations carries no RLS (see internal/data/org.go's
	// SingleOrganisationID, which reads it BEFORE any scope is set) — no
	// SetRequestScope call is needed, or possible, before this insert.
	if _, err := tx.Exec(ctx, `INSERT INTO organisations (id, name) VALUES ($1, $2)`, tenantID, "autoanalyze-starvation-test"); err != nil {
		tx.Rollback(ctx) //nolint:errcheck
		t.Fatalf("insert throwaway organisation: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit organisation insert: %v", err)
	}

	// BUGS.md: this cleanup used to run `DELETE FROM incidents WHERE
	// tenant_id = $1` directly — safe only as long as tenantID is always a
	// genuinely fresh id, an invariant enforced by nothing but discipline.
	// In this project's single-tenant dev database that predicate matches
	// the ENTIRE incidents table the moment that invariant slips, which is
	// exactly what happened: ~1,000 incidents and 335 analyses destroyed in
	// one run. dbtest.Fixture makes that structurally impossible instead of
	// merely avoided: it tracks exactly how many rows this fixture inserts
	// per table and refuses to commit a delete that doesn't affect exactly
	// that count, in either direction.
	fixture := dbtest.New(t)
	t.Cleanup(func() {
		// organisations has no RLS, so this plain delete needs no scope —
		// and it must run AFTER dbtest.Fixture's own cleanup (registered
		// below, so it runs first — t.Cleanup is LIFO), since clusters
		// carries a foreign key to organisations.
		if _, err := pool.Exec(context.Background(), `DELETE FROM organisations WHERE id = $1`, tenantID); err != nil {
			t.Errorf("cleanup: delete organisation: %v", err)
		}
	})
	fixture.Cleanup(pool, func(ctx context.Context, tx pgx.Tx) error {
		return data.SetRequestScope(ctx, tx, tenantID, nil)
	}, []dbtest.TableDelete{
		{Table: "incidents", SQL: `DELETE FROM incidents WHERE tenant_id = $1`, Args: []any{tenantID}},
		{Table: "clusters", SQL: `DELETE FROM clusters WHERE tenant_id = $1`, Args: []any{tenantID}},
	})

	tx, err = pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin fixture transaction: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if err := data.SetRequestScope(ctx, tx, tenantID, nil); err != nil {
		t.Fatalf("set request scope: %v", err)
	}

	ancientFirstSeen := time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC) // guaranteed older than anything else in the table, real dev data included
	now := time.Now()

	insertCluster := func(state string, lastHeartbeat *time.Time, archivedAt *time.Time) string {
		clusterID := domain.NewID(domain.PrefixCluster)
		if _, err := tx.Exec(ctx,
			`INSERT INTO clusters (id, tenant_id, display_name, state, shard_id, cluster_fingerprint, last_heartbeat_at, archived_at)
			 VALUES ($1, $2, $3, $4, 'shard-test', $5, $6, $7)`,
			clusterID, tenantID, "starvation-test-"+clusterID, state, "fp-"+clusterID, lastHeartbeat, archivedAt); err != nil {
			t.Fatalf("insert cluster in state %s: %v", state, err)
		}
		fixture.Created("clusters", 1)
		clusterIDs = append(clusterIDs, clusterID)
		return clusterID
	}
	insertIncident := func(clusterID string, firstSeen time.Time) string {
		incidentID := domain.NewID(domain.PrefixIncident)
		if _, err := tx.Exec(ctx,
			`INSERT INTO incidents (id, tenant_id, cluster_id, fingerprint, severity, state, first_seen, last_seen, occurrence_count)
			 VALUES ($1, $2, $3, $4, 'critical', 'Detected', $5, $5, 1)`,
			incidentID, tenantID, clusterID, "fp-"+incidentID, firstSeen); err != nil {
			t.Fatalf("insert incident on cluster %s: %v", clusterID, err)
		}
		fixture.Created("incidents", 1)
		return incidentID
	}

	for _, f := range stale {
		var lastHeartbeat *time.Time
		if f.lastHeartbeatAgo > 0 {
			t := now.Add(-f.lastHeartbeatAgo)
			lastHeartbeat = &t
		}
		var archivedAt *time.Time
		if f.archived {
			t := now.Add(-24 * time.Hour)
			archivedAt = &t
		}
		clusterID := insertCluster(f.clusterState, lastHeartbeat, archivedAt)
		insertIncident(clusterID, ancientFirstSeen)
	}

	freshClusterID := insertCluster("Active", &now, nil)
	freshIncidentID = insertIncident(freshClusterID, now)

	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit fixture: %v", err)
	}
	return tenantID, freshIncidentID, clusterIDs
}

// runCandidateQuery runs the real, production candidateQuery (not a
// reimplementation) scoped to tenantID, and returns the selected incident
// ids — exactly what collectEligible itself scans, minus the Go-side
// selectEligible filtering this test isn't exercising.
//
// severities is candidateQuery's $3 — the ORDER BY priority key added for
// BACKLOG.md C12 (see that query's own doc comment). Every pre-existing
// caller below passes the full four-value set, which makes $3's ordering
// term true for every row and so degrades to the query's original
// first_seen-only ordering exactly — those tests predate severity
// prioritization and assert on plain age ordering, so their fixtures (all
// severity 'critical') must keep sorting that way.
func runCandidateQuery(t *testing.T, pool *pgxpool.Pool, tenantID string, limit int, severities []string) []string {
	t.Helper()
	var ids []string
	for _, c := range runCandidateQueryFull(t, pool, tenantID, limit, severities) {
		ids = append(ids, c.ID)
	}
	return ids
}

// runCandidateQueryFull is runCandidateQuery's full-row counterpart —
// needed by TestCandidateQueryPrioritizesEligibleSeverityOverBacklog below,
// which must inspect Severity (to feed selectEligible/logSeveritySkip for
// real, on real rows) rather than just IDs.
func runCandidateQueryFull(t *testing.T, pool *pgxpool.Pool, tenantID string, limit int, severities []string) []incidentCandidate {
	t.Helper()
	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin query transaction: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if err := data.SetRequestScope(ctx, tx, tenantID, nil); err != nil {
		t.Fatalf("set request scope: %v", err)
	}
	rows, err := tx.Query(ctx, candidateQuery, limit, staleUnreachableClusterAge.Seconds(), severities)
	if err != nil {
		t.Fatalf("run candidateQuery: %v", err)
	}
	defer rows.Close()
	var out []incidentCandidate
	for rows.Next() {
		var c incidentCandidate
		if err := rows.Scan(&c.ID, &c.ClusterID, &c.Fingerprint, &c.Severity, &c.OccurrenceCount, &c.ObjectKey, &c.FleetGroupID, &c.WorkloadKey, &c.HasAnalysis, &c.AutoAnalysisAttempts); err != nil {
			t.Fatalf("scan candidate: %v", err)
		}
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate candidates: %v", err)
	}
	return out
}

// TestCandidateQuerySelectsFreshIncidentOverStarvedOnes is BUGS.md 120's live
// reproduction, cut down to a deterministic fixture: five incidents whose
// clusters will never dispatch again (two Archived, one Rejected, two
// Disconnected well past staleUnreachableClusterAge) — each older, by
// first_seen, than anything else in the table — plus one fresh incident on a
// currently-Active cluster.
//
// Pre-fix (no clusters JOIN/predicate at all), a LIMIT of 3 would return
// three of the five ancient, permanently-undispatchable rows and NEVER the
// fresh one — the exact shape found live on this repo's own dev stack: 112+
// rows dating back to March, re-fetched every sweep, with the genuinely
// analysable incident never even reaching selectEligible. Post-fix, the five
// stale rows are excluded by the query itself, so the fresh incident is the
// only row left and appears well within the same LIMIT.
func TestCandidateQuerySelectsFreshIncidentOverStarvedOnes(t *testing.T) {
	pool := testPool(t)
	tenantID, freshIncidentID, _ := setupStarvationFixture(t, pool, []starvedFixture{
		{clusterState: "Archived", archived: true},
		{clusterState: "Archived", archived: true},
		{clusterState: "Rejected"},
		{clusterState: "Disconnected", lastHeartbeatAgo: 2 * staleUnreachableClusterAge},
		{clusterState: "Disconnected", lastHeartbeatAgo: 2 * staleUnreachableClusterAge},
	})

	got := runCandidateQuery(t, pool, tenantID, 3, []string{"low", "medium", "high", "critical"}) // fewer slots than stale rows: pre-fix, none of them would be enough to expose the fresh one

	if len(got) != 1 || got[0] != freshIncidentID {
		t.Fatalf("candidateQuery returned %v, want exactly [%s] — a permanently-unreachable cluster's incident won a candidate slot ahead of a genuinely dispatchable one", got, freshIncidentID)
	}
}

// TestCandidateQueryHasAnalysisIsScopedToTheCurrentOpenCycle is PROJECT.md
// B144's own follow-on regression test (migration 000098). Found live
// 2026-09-06 re-verifying B144 itself: orchestrator.SetState correctly
// incremented auto_analysis_reopen_count and reset auto_analysis_attempted_at
// to NULL on a Reopened transition (b144v2-444e47 fixture), re-admitting the
// incident past candidateQuery's own SQL WHERE clause — and it STILL never
// got automatically re-analyzed, because HasAnalysis used to mean "has ANY
// analyses row, ever," true for essentially every Reopened incident (it
// needed an analysis to produce the plan that was executed and later
// reopened). The fix scopes HasAnalysis to analyses recorded AFTER the
// incident's own reopened_at.
func TestCandidateQueryHasAnalysisIsScopedToTheCurrentOpenCycle(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()

	tenantID := domain.NewID(domain.PrefixOrganisation)
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO organisations (id, name) VALUES ($1, $2)`, tenantID, "autoanalyze-reopen-test"); err != nil {
		tx.Rollback(ctx) //nolint:errcheck
		t.Fatalf("insert throwaway organisation: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit organisation insert: %v", err)
	}

	fixture := dbtest.New(t)
	t.Cleanup(func() {
		if _, err := pool.Exec(context.Background(), `DELETE FROM organisations WHERE id = $1`, tenantID); err != nil {
			t.Errorf("cleanup: delete organisation: %v", err)
		}
	})
	fixture.Cleanup(pool, func(ctx context.Context, tx pgx.Tx) error {
		return data.SetRequestScope(ctx, tx, tenantID, nil)
	}, []dbtest.TableDelete{
		{Table: "analyses", SQL: `DELETE FROM analyses WHERE tenant_id = $1`, Args: []any{tenantID}},
		{Table: "incidents", SQL: `DELETE FROM incidents WHERE tenant_id = $1`, Args: []any{tenantID}},
		{Table: "clusters", SQL: `DELETE FROM clusters WHERE tenant_id = $1`, Args: []any{tenantID}},
	})

	tx, err = pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin fixture transaction: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if err := data.SetRequestScope(ctx, tx, tenantID, nil); err != nil {
		t.Fatalf("set request scope: %v", err)
	}

	clusterID := domain.NewID(domain.PrefixCluster)
	if _, err := tx.Exec(ctx,
		`INSERT INTO clusters (id, tenant_id, display_name, state, shard_id, cluster_fingerprint, last_heartbeat_at)
		 VALUES ($1, $2, $3, 'Active', 'shard-test', $4, now())`,
		clusterID, tenantID, "reopen-test-"+clusterID, "fp-"+clusterID); err != nil {
		t.Fatalf("insert cluster: %v", err)
	}
	fixture.Created("clusters", 1)

	incidentID := domain.NewID(domain.PrefixIncident)
	reopenedAt := time.Now().Add(-time.Hour)
	if _, err := tx.Exec(ctx,
		`INSERT INTO incidents (id, tenant_id, cluster_id, fingerprint, severity, state, first_seen, last_seen, occurrence_count, reopened_at)
		 VALUES ($1, $2, $3, $4, 'critical', 'Reopened', $5, now(), 1, $6)`,
		incidentID, tenantID, clusterID, "fp-"+incidentID, reopenedAt.Add(-2*time.Hour), reopenedAt); err != nil {
		t.Fatalf("insert incident: %v", err)
	}
	fixture.Created("incidents", 1)

	preReopenAnalysisID := domain.NewID(domain.PrefixAnalysis)
	if _, err := tx.Exec(ctx,
		`INSERT INTO analyses (id, tenant_id, incident_id, cluster_id, prompt_version, model, causal_chain,
		    iterations, duration_ms, tokens_billed_in, tokens_cache_read, tokens_out, cost_usd, created_at)
		 VALUES ($1,$2,$3,$4,'test','test-model','[]'::jsonb,1,1,0,0,0,0,$5)`,
		preReopenAnalysisID, tenantID, incidentID, clusterID, reopenedAt.Add(-30*time.Minute)); err != nil {
		t.Fatalf("insert pre-reopen analysis: %v", err)
	}
	fixture.Created("analyses", 1)

	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit fixture: %v", err)
	}

	candidates := runCandidateQueryFull(t, pool, tenantID, 10, []string{"critical"})
	if len(candidates) != 1 || candidates[0].ID != incidentID {
		t.Fatalf("candidateQuery = %v, want exactly [%s]", candidates, incidentID)
	}
	if candidates[0].HasAnalysis {
		t.Error("HasAnalysis = true, want false — the only analysis on record predates this incident's most recent reopen (reopened_at), so it must not count against a fresh automatic re-analysis; this is exactly the bug that left a reopened incident permanently un-re-analyzed")
	}

	// A FRESH analysis, recorded after the reopen, must flip HasAnalysis to
	// true — the incident genuinely has been re-analyzed for this cycle now.
	tx2, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer tx2.Rollback(ctx) //nolint:errcheck
	if err := data.SetRequestScope(ctx, tx2, tenantID, nil); err != nil {
		t.Fatalf("set request scope: %v", err)
	}
	postReopenAnalysisID := domain.NewID(domain.PrefixAnalysis)
	if _, err := tx2.Exec(ctx,
		`INSERT INTO analyses (id, tenant_id, incident_id, cluster_id, prompt_version, model, causal_chain,
		    iterations, duration_ms, tokens_billed_in, tokens_cache_read, tokens_out, cost_usd, created_at)
		 VALUES ($1,$2,$3,$4,'test','test-model','[]'::jsonb,1,1,0,0,0,0, now())`,
		postReopenAnalysisID, tenantID, incidentID, clusterID); err != nil {
		t.Fatalf("insert post-reopen analysis: %v", err)
	}
	fixture.Created("analyses", 1)
	if err := tx2.Commit(ctx); err != nil {
		t.Fatalf("commit: %v", err)
	}

	candidates = runCandidateQueryFull(t, pool, tenantID, 10, []string{"critical"})
	if len(candidates) != 1 || candidates[0].ID != incidentID {
		t.Fatalf("candidateQuery = %v, want exactly [%s]", candidates, incidentID)
	}
	if !candidates[0].HasAnalysis {
		t.Error("HasAnalysis = false, want true — a fresh analysis recorded AFTER reopened_at must count as already-analyzed-this-cycle")
	}
}

// TestCandidateQueryStillIncludesRecentlyDisconnectedCluster guards the other
// direction of the same fix: a cluster that has been Disconnected for only a
// few seconds — well within a routine restart or network blip — must NOT be
// excluded, or a cluster that merely blipped would lose its incident's
// candidacy exactly as permanently as one that is truly gone.
func TestCandidateQueryStillIncludesRecentlyDisconnectedCluster(t *testing.T) {
	pool := testPool(t)
	tenantID, freshIncidentID, clusterIDs := setupStarvationFixture(t, pool, nil)
	_ = clusterIDs

	// Reuse the fresh incident's own cluster, but flip it to Disconnected
	// moments ago rather than adding a new fixture row, to keep this test
	// isolated to the one behaviour it checks.
	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin update transaction: %v", err)
	}
	if err := data.SetRequestScope(ctx, tx, tenantID, nil); err != nil {
		t.Fatalf("set request scope: %v", err)
	}
	if _, err := tx.Exec(ctx,
		`UPDATE clusters SET state = 'Disconnected', last_heartbeat_at = now() - interval '5 seconds' WHERE tenant_id = $1`,
		tenantID); err != nil {
		t.Fatalf("demote cluster to recently-disconnected: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit demotion: %v", err)
	}

	got := runCandidateQuery(t, pool, tenantID, 10, []string{"low", "medium", "high", "critical"})
	if len(got) != 1 || got[0] != freshIncidentID {
		t.Fatalf("candidateQuery returned %v, want exactly [%s] — a cluster disconnected for only seconds must remain eligible, not be treated the same as one gone for good", got, freshIncidentID)
	}
}

// setupSeverityBacklogFixture builds BACKLOG.md C12's own measured shape,
// scaled down to a deterministic fixture: N old incidents whose severities
// do NOT match the configured set (so they are eligible by every OTHER
// filter — actionable state, never attempted — but not by severity), plus
// one incident, newer than all of them, whose severity DOES match. Every
// cluster is Active with a fresh heartbeat, deliberately isolating this
// fix from BUGS.md 120's cluster-state starvation fix (already proven
// separately above) — the only variable here is severity and age.
func setupSeverityBacklogFixture(t *testing.T, pool *pgxpool.Pool, backlogSeverities []string, eligibleSeverity string) (tenantID, eligibleIncidentID string) {
	t.Helper()
	ctx := context.Background()

	tenantID = domain.NewID(domain.PrefixOrganisation)
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin setup transaction: %v", err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO organisations (id, name) VALUES ($1, $2)`, tenantID, "autoanalyze-severity-backlog-test"); err != nil {
		tx.Rollback(ctx) //nolint:errcheck
		t.Fatalf("insert throwaway organisation: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit organisation insert: %v", err)
	}

	// See setupStarvationFixture's own comment: dbtest.Fixture makes the
	// over/under-deletion bug shape structurally impossible instead of
	// merely avoided.
	fixture := dbtest.New(t)
	t.Cleanup(func() {
		if _, err := pool.Exec(context.Background(), `DELETE FROM organisations WHERE id = $1`, tenantID); err != nil {
			t.Errorf("cleanup: delete organisation: %v", err)
		}
	})
	fixture.Cleanup(pool, func(ctx context.Context, tx pgx.Tx) error {
		return data.SetRequestScope(ctx, tx, tenantID, nil)
	}, []dbtest.TableDelete{
		{Table: "incidents", SQL: `DELETE FROM incidents WHERE tenant_id = $1`, Args: []any{tenantID}},
		{Table: "clusters", SQL: `DELETE FROM clusters WHERE tenant_id = $1`, Args: []any{tenantID}},
	})

	tx, err = pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin fixture transaction: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if err := data.SetRequestScope(ctx, tx, tenantID, nil); err != nil {
		t.Fatalf("set request scope: %v", err)
	}

	ancientFirstSeen := time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)
	now := time.Now()

	insertCluster := func() string {
		clusterID := domain.NewID(domain.PrefixCluster)
		if _, err := tx.Exec(ctx,
			`INSERT INTO clusters (id, tenant_id, display_name, state, shard_id, cluster_fingerprint, last_heartbeat_at)
			 VALUES ($1, $2, $3, 'Active', 'shard-test', $4, $5)`,
			clusterID, tenantID, "severity-backlog-test-"+clusterID, "fp-"+clusterID, now); err != nil {
			t.Fatalf("insert cluster: %v", err)
		}
		fixture.Created("clusters", 1)
		return clusterID
	}
	insertIncident := func(severity string, firstSeen time.Time) string {
		clusterID := insertCluster()
		incidentID := domain.NewID(domain.PrefixIncident)
		if _, err := tx.Exec(ctx,
			`INSERT INTO incidents (id, tenant_id, cluster_id, fingerprint, severity, state, first_seen, last_seen, occurrence_count)
			 VALUES ($1, $2, $3, $4, $5, 'Detected', $6, $6, 1)`,
			incidentID, tenantID, clusterID, "fp-"+incidentID, severity, firstSeen); err != nil {
			t.Fatalf("insert incident with severity %s: %v", severity, err)
		}
		fixture.Created("incidents", 1)
		return incidentID
	}

	for _, sev := range backlogSeverities {
		insertIncident(sev, ancientFirstSeen)
	}
	eligibleIncidentID = insertIncident(eligibleSeverity, now)

	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit fixture: %v", err)
	}
	return tenantID, eligibleIncidentID
}

// TestCandidateQueryPrioritizesEligibleSeverityOverBacklog is BACKLOG.md
// C12's own starvation fix, proven end to end against a real database:
// measured live on this repo's dev stack, 74% of the oldest 50 candidate
// rows were severity-ineligible chaff that will never be marked attempted
// and so never leave candidateQuery's WHERE clause — meaning a genuinely
// eligible, freshly-detected incident could sit below the LIMIT cutoff
// indefinitely behind an arbitrarily large low/medium backlog.
//
// Five old (first_seen 2000-01-01) low/medium incidents stand in for that
// backlog; one high incident, newer than all of them, stands in for the
// incident automatic investigation exists to catch. A LIMIT smaller than
// the backlog size (3 < 5) is the exact shape that would have failed
// pre-fix: without the severity priority ordering, first_seen ASC alone
// would fill every slot with backlog rows and never return the eligible
// one at all.
func TestCandidateQueryPrioritizesEligibleSeverityOverBacklog(t *testing.T) {
	pool := testPool(t)
	backlog := []string{"low", "medium", "low", "medium", "low"}
	tenantID, eligibleID := setupSeverityBacklogFixture(t, pool, backlog, "high")

	got := runCandidateQueryFull(t, pool, tenantID, 3, []string{"high", "critical"})
	if len(got) != 3 {
		t.Fatalf("candidateQuery returned %d rows, want 3 (the LIMIT)", len(got))
	}
	if got[0].ID != eligibleID || got[0].Severity != "high" {
		t.Fatalf("candidateQuery's first row = %+v, want the eligible high incident (%s) to sort first regardless of age — this is the starvation fix itself", got[0], eligibleID)
	}
	for _, c := range got[1:] {
		if c.ID == eligibleID {
			t.Fatalf("eligible incident %s appeared twice in %+v", eligibleID, got)
		}
	}

	// Now run the exact same selectEligible this candidate query's caller
	// (collectEligible) runs on these real rows, with a real, dedup ing
	// logSeveritySkip callback — proving BACKLOG.md C12's OTHER named
	// defect (the bare `continue`, now a real log line) fires for real,
	// severity-ineligible rows read from a real database, not just a
	// synthetic fixture.
	var logged []string
	logSkip := func(incidentID, severity string) {
		logged = append(logged, incidentID+":"+severity)
	}
	eligible, _ := selectEligible(got, []string{"high", "critical"}, func(string) bool { return true }, logSkip)
	if len(eligible) != 1 || eligible[0].ID != eligibleID {
		t.Fatalf("selectEligible(candidateQuery's own real rows) = %+v, want exactly the one eligible incident", eligible)
	}
	if len(logged) != 2 {
		t.Fatalf("logSeveritySkip calls = %v, want exactly 2 (the two backlog rows that made it into this LIMIT-3 batch alongside the eligible one)", logged)
	}
	for _, l := range logged {
		if !strings.HasSuffix(l, ":low") && !strings.HasSuffix(l, ":medium") {
			t.Errorf("unexpected logSeveritySkip call %q — every logged skip in this fixture must be a low or medium backlog row", l)
		}
	}
}
