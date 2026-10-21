package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"argus/internal/data"
	"argus/internal/dbtest"
	"argus/internal/domain"
)

// timelineExecTrackedFixture is timelineExecFixture's own setup (see that
// function's doc comment for the shape), but for the tests that need PER-TEST
// dbtest.Fixture tracking, since each drives a different amount of production
// code on top of the same fixture rows. In this package that is now
// handleRejectIncident alone: PROJECT.md P23 moved recordExecutingTransition
// and recordExecutionOutcome — and their two tests — to internal/execution,
// which carries its own copy of this fixture for the same reason
// timelineEventTypesFor already gave for not sharing internal/orchestrator's
// equivalent (two packages' test binaries do not share a build). Every OTHER
// caller of timelineExecFixture in this package (approvals_openpr_trace_db_test.go,
// execution_recovery_db_test.go, pr_verify_files_db_test.go,
// remediation_concurrency_db_test.go, incident_disposition_db_test.go) uses
// the plain, self-contained-cleanup version instead — a fourteen-call-site
// blast radius outside this migration's scope, so timelineExecFixture itself
// is deliberately left untouched.
//
// The returned *dbtest.Fixture already tracks the four deterministic rows
// this setup itself inserts (clusters/incidents/analyses/
// remediation_recommendations) but does NOT call Cleanup — each of this
// file's three tests must finish tracking the variable-count tables
// (timeline_events/remediation_approval_decisions/remediation_executions/
// remediation_execution_attempts) with fixture.Created(...) and then call
// fixture.Cleanup(pool, timelineExecSetScope(...), timelineExecDeletes(...))
// itself before returning/ending.
func timelineExecTrackedFixture(t *testing.T, pool *pgxpool.Pool) (tenantID, clusterID, incidentID, planID string, fixture *dbtest.Fixture) {
	t.Helper()
	ctx := context.Background()

	clusterID = domain.NewID(domain.PrefixCluster)
	incidentID = domain.NewID(domain.PrefixIncident)
	analysisID := domain.NewID(domain.PrefixAnalysis)
	planID = domain.NewID(domain.PrefixPlan)

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
		t.Fatalf("scope: %v", err)
	}

	if _, err := tx.Exec(ctx,
		`INSERT INTO clusters (id, tenant_id, display_name, state, shard_id, cluster_fingerprint)
		 VALUES ($1, $2, $3, 'Active', 'shard-test', $4)`,
		clusterID, tenantID, "timeline-exec-test-"+clusterID, "fp-"+clusterID); err != nil {
		t.Fatalf("insert cluster: %v", err)
	}
	now := time.Now()
	if _, err := tx.Exec(ctx,
		`INSERT INTO incidents (id, tenant_id, cluster_id, fingerprint, severity, state, first_seen, last_seen, occurrence_count)
		 VALUES ($1, $2, $3, $4, 'high', 'AwaitingApproval', $5, $5, 1)`,
		incidentID, tenantID, clusterID, "test-timeline-exec-"+incidentID, now); err != nil {
		t.Fatalf("insert incident: %v", err)
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO analyses (id, tenant_id, incident_id, cluster_id, prompt_version, model,
		    causal_chain, iterations, duration_ms, tokens_billed_in, tokens_cache_read, tokens_out, cost_usd)
		 VALUES ($1,$2,$3,$4,'test','test-model','[]'::jsonb,1,1,0,0,0,0)`,
		analysisID, tenantID, incidentID, clusterID); err != nil {
		t.Fatalf("insert analysis: %v", err)
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO remediation_recommendations (
		   id, incident_id, tenant_id, cluster_id, analysis_id, action_type,
		   target_gvk, target_namespace, target_name, params, reversible, risk_level,
		   gate_outcome, gate_reason
		 ) VALUES ($1,$2,$3,$4,$5,'ScaleDeployment','apps/v1/Deployment','ns','web','{"replicas":3}'::jsonb,true,'low','NeedsApproval','test')`,
		planID, incidentID, tenantID, clusterID, analysisID); err != nil {
		t.Fatalf("insert recommendation: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit setup: %v", err)
	}

	fixture = dbtest.New(t)
	fixture.Created("clusters", 1)
	fixture.Created("incidents", 1)
	fixture.Created("analyses", 1)
	fixture.Created("remediation_recommendations", 1)
	// Every row this fixture and the production code driven on top of it
	// produces belongs to this one throwaway cluster, so the catalogue-driven
	// residue check applies and will name any table a caller's counts miss.
	fixture.OwnsCluster(tenantID, clusterID)
	return tenantID, clusterID, incidentID, planID, fixture
}

// timelineExecDeletes is the cleanup statement list every
// timelineExecTrackedFixture caller uses — every table the fixture setup OR
// the production code driven on top of it could touch, so callers only need
// to get the Created(...) counts right, not the delete list itself.
func timelineExecDeletes(clusterID string) []dbtest.TableDelete {
	return []dbtest.TableDelete{
		{Table: "timeline_events", SQL: `DELETE FROM timeline_events WHERE cluster_id = $1`, Args: []any{clusterID}},
		// Before remediation_executions and remediation_recommendations: an
		// attempt row references the recommendation (migration 000093)
		// exactly as an execution row does.
		{Table: "remediation_execution_attempts", SQL: `DELETE FROM remediation_execution_attempts WHERE cluster_id = $1`, Args: []any{clusterID}},
		{Table: "remediation_executions", SQL: `DELETE FROM remediation_executions WHERE cluster_id = $1`, Args: []any{clusterID}},
		{Table: "remediation_approval_decisions", SQL: `DELETE FROM remediation_approval_decisions WHERE cluster_id = $1`, Args: []any{clusterID}},
		{Table: "remediation_recommendations", SQL: `DELETE FROM remediation_recommendations WHERE cluster_id = $1`, Args: []any{clusterID}},
		// BUGS.md 119: same delete-order footgun as clearDemoData — this
		// fixture doesn't insert evidence/analysis_embeddings today, but
		// clearing them before analyses matches every other fixture in this
		// package.
		{Table: "evidence", SQL: `DELETE FROM evidence WHERE analysis_id IN (SELECT id FROM analyses WHERE cluster_id = $1)`, Args: []any{clusterID}},
		{Table: "analysis_embeddings", SQL: `DELETE FROM analysis_embeddings WHERE analysis_id IN (SELECT id FROM analyses WHERE cluster_id = $1)`, Args: []any{clusterID}},
		{Table: "analyses", SQL: `DELETE FROM analyses WHERE cluster_id = $1`, Args: []any{clusterID}},
		// PROJECT.md B175: written by PRODUCT code on a hop into a notifiable
		// state, never by this fixture, so it was absent from a list built by
		// reading the fixture's own INSERTs — and leaked once per run.
		{Table: "incident_notifications", SQL: `DELETE FROM incident_notifications WHERE cluster_id = $1`, Args: []any{clusterID}},
		{Table: "incidents", SQL: `DELETE FROM incidents WHERE cluster_id = $1`, Args: []any{clusterID}},
		{Table: "clusters", SQL: `DELETE FROM clusters WHERE id = $1`, Args: []any{clusterID}},
	}
}

// timelineExecSetScope is the setScope callback every
// timelineExecTrackedFixture caller's Cleanup uses.
func timelineExecSetScope(tenantID, clusterID string) func(ctx context.Context, tx pgx.Tx) error {
	return func(ctx context.Context, tx pgx.Tx) error {
		return data.SetRequestScope(ctx, tx, tenantID, []string{clusterID})
	}
}

// timelineExecFixture is the plain, self-contained-cleanup fixture used by
// this package's OTHER *_db_test.go files (approvals_openpr_trace_db_test.go,
// execution_recovery_db_test.go, pr_verify_files_db_test.go,
// remediation_concurrency_db_test.go, incident_disposition_db_test.go — 14
// call sites) that each drive exactly one, already-known amount of production
// code on top of it. Deliberately NOT migrated to dbtest.Fixture here: each of
// those 14 call sites would need its own audited Created(...) count, which is
// a fourteen-call-site blast radius outside this task's scope (four named
// files). Left exactly as it was before this migration.
func timelineExecFixture(t *testing.T, pool *pgxpool.Pool) (tenantID, clusterID, incidentID, planID string) {
	t.Helper()
	ctx := context.Background()

	clusterID = domain.NewID(domain.PrefixCluster)
	incidentID = domain.NewID(domain.PrefixIncident)
	analysisID := domain.NewID(domain.PrefixAnalysis)
	planID = domain.NewID(domain.PrefixPlan)

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
		t.Fatalf("scope: %v", err)
	}

	if _, err := tx.Exec(ctx,
		`INSERT INTO clusters (id, tenant_id, display_name, state, shard_id, cluster_fingerprint)
		 VALUES ($1, $2, $3, 'Active', 'shard-test', $4)`,
		clusterID, tenantID, "timeline-exec-test-"+clusterID, "fp-"+clusterID); err != nil {
		t.Fatalf("insert cluster: %v", err)
	}
	now := time.Now()
	if _, err := tx.Exec(ctx,
		`INSERT INTO incidents (id, tenant_id, cluster_id, fingerprint, severity, state, first_seen, last_seen, occurrence_count)
		 VALUES ($1, $2, $3, $4, 'high', 'AwaitingApproval', $5, $5, 1)`,
		incidentID, tenantID, clusterID, "test-timeline-exec-"+incidentID, now); err != nil {
		t.Fatalf("insert incident: %v", err)
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO analyses (id, tenant_id, incident_id, cluster_id, prompt_version, model,
		    causal_chain, iterations, duration_ms, tokens_billed_in, tokens_cache_read, tokens_out, cost_usd)
		 VALUES ($1,$2,$3,$4,'test','test-model','[]'::jsonb,1,1,0,0,0,0)`,
		analysisID, tenantID, incidentID, clusterID); err != nil {
		t.Fatalf("insert analysis: %v", err)
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO remediation_recommendations (
		   id, incident_id, tenant_id, cluster_id, analysis_id, action_type,
		   target_gvk, target_namespace, target_name, params, reversible, risk_level,
		   gate_outcome, gate_reason
		 ) VALUES ($1,$2,$3,$4,$5,'ScaleDeployment','apps/v1/Deployment','ns','web','{"replicas":3}'::jsonb,true,'low','NeedsApproval','test')`,
		planID, incidentID, tenantID, clusterID, analysisID); err != nil {
		t.Fatalf("insert recommendation: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit setup: %v", err)
	}

	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Errorf("cleanup: begin: %v", err)
			return
		}
		defer tx.Rollback(ctx) //nolint:errcheck
		if err := data.SetRequestScope(ctx, tx, tenantID, []string{clusterID}); err != nil {
			t.Errorf("cleanup: scope: %v", err)
			return
		}
		for _, stmt := range []string{
			`DELETE FROM timeline_events WHERE cluster_id = $1`,
			// Before remediation_executions and remediation_recommendations:
			// an attempt row references the recommendation (migration 000093)
			// exactly as an execution row does.
			`DELETE FROM remediation_execution_attempts WHERE cluster_id = $1`,
			`DELETE FROM remediation_executions WHERE cluster_id = $1`,
			`DELETE FROM remediation_approval_decisions WHERE cluster_id = $1`,
			`DELETE FROM remediation_recommendations WHERE cluster_id = $1`,
			// BUGS.md 119: same delete-order footgun as clearDemoData — this
			// fixture doesn't insert evidence/analysis_embeddings today, but
			// clearing them before analyses matches every other fixture in
			// this package.
			`DELETE FROM evidence WHERE analysis_id IN (SELECT id FROM analyses WHERE cluster_id = $1)`,
			`DELETE FROM analysis_embeddings WHERE analysis_id IN (SELECT id FROM analyses WHERE cluster_id = $1)`,
			`DELETE FROM analyses WHERE cluster_id = $1`,
			// PROJECT.md B175: see timelineExecDeletes' own note — a
			// notifiable state hop writes this and the fixture never does.
			`DELETE FROM incident_notifications WHERE cluster_id = $1`,
			`DELETE FROM incidents WHERE cluster_id = $1`,
			`DELETE FROM clusters WHERE id = $1`,
		} {
			if _, err := tx.Exec(ctx, stmt, clusterID); err != nil {
				t.Errorf("cleanup %q: %v", stmt, err)
			}
		}
		if err := tx.Commit(ctx); err != nil {
			t.Errorf("cleanup: commit: %v", err)
			return
		}
		// This fixture is not count-tracked (see its doc comment above for
		// why), so nothing here checks that the list above is complete. The
		// residue check does, from the catalogue: 14 call sites drive
		// different amounts of production code on top of this one fixture,
		// and any of them can reach a table the list does not name — which
		// is how incident_notifications leaked (PROJECT.md B175).
		dbtest.AssertNoClusterResidue(t, pool, tenantID, clusterID)
	})
	return tenantID, clusterID, incidentID, planID
}

// timelineEventTypesFor reads back every timeline_events row for one
// incident, in a fresh, correctly-scoped transaction — used by both this
// file's tests and mirrors internal/orchestrator's own readTimelineEvents
// helper (kept separate rather than shared: the two packages' test binaries
// don't share a build).
func timelineEventTypesFor(t *testing.T, pool *pgxpool.Pool, tenantID, clusterID, incidentID string) []string {
	t.Helper()
	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin verify tx: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if err := data.SetRequestScope(ctx, tx, tenantID, []string{clusterID}); err != nil {
		t.Fatalf("scope: %v", err)
	}
	rows, err := tx.Query(ctx, `SELECT event_type FROM timeline_events WHERE incident_id = $1 ORDER BY occurred_at ASC, id ASC`, incidentID)
	if err != nil {
		t.Fatalf("query timeline_events: %v", err)
	}
	defer rows.Close()
	var types []string
	for rows.Next() {
		var eventType string
		if err := rows.Scan(&eventType); err != nil {
			t.Fatalf("scan: %v", err)
		}
		types = append(types, eventType)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate: %v", err)
	}
	return types
}

// TestHandleRejectIncidentWritesApprovalRejectedEvent is BACKLOG.md B1's
// acceptance test for the approval-decision transition on the rejection
// path — handleRejectIncident, unlike the in-place execution path above,
// runs inside the caller's own already-open, already-scoped transaction
// (rc.Tx), matching every other real HTTP handler in this package.
func TestHandleRejectIncidentWritesApprovalRejectedEvent(t *testing.T) {
	pool := authTestPool(t)
	tenantID, clusterID, incidentID, _, fixture := timelineExecTrackedFixture(t, pool)

	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin request tx: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if err := data.SetRequestScope(ctx, tx, tenantID, []string{clusterID}); err != nil {
		t.Fatalf("scope: %v", err)
	}

	s := &Server{}
	rc := &requestContext{Tx: tx, TenantID: tenantID, UserID: "usr_test"}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/incidents/"+incidentID+"/reject", strings.NewReader(`{"reason":"not a real fix"}`))
	req.SetPathValue("id", incidentID)
	rec := httptest.NewRecorder()

	s.handleRejectIncident(rec, req, rc)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body: %s)", rec.Code, rec.Body.String())
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit: %v", err)
	}

	// handleRejectIncident writes exactly 1 remediation_approval_decisions row
	// and 1 timeline_events row (ApprovalRejected) — no execution/attempt rows
	// on this path at all.
	fixture.Created("remediation_approval_decisions", 1)
	fixture.Created("remediation_execution_attempts", 0)
	fixture.Created("remediation_executions", 0)
	fixture.Created("timeline_events", 1)
	fixture.Created("evidence", 0)
	fixture.Created("analysis_embeddings", 0)
	fixture.Created("incident_notifications", 0)
	fixture.Cleanup(pool, timelineExecSetScope(tenantID, clusterID), timelineExecDeletes(clusterID))

	got := timelineEventTypesFor(t, pool, tenantID, clusterID, incidentID)
	if len(got) != 1 || got[0] != "ApprovalRejected" {
		t.Fatalf("timeline event types = %v, want exactly [\"ApprovalRejected\"]", got)
	}
}
