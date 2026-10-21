package api

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"argus/internal/data"
	"argus/internal/dbtest"
	"argus/internal/domain"
	"argus/internal/orchestrator"
)

// BUGS.md 100 regression: maxUnattendedPlanAge (10 minutes) is shorter than
// validationGracePeriod's 15-minute floor, so a BatchExecution wave-2 member
// that is correctly held while wave 1 validates has always already aged out
// of unattendedCandidateQuery's `r.created_at >= $2` bound by the time wave 1
// releases it — every time, not just under contention (see BUGS.md 100's own
// live timeline: wave 2 created at 07:18:42Z, aged out at 07:28:42Z, wave 1
// didn't release it until 07:37:17Z).
//
// The fix exempts a plan already carrying a wave_number > 1 membership in
// unattended_batch_members from the age bound, on the theory that its age
// there is time spent waiting on this feature's OWN gate
// (orchestrator.BatchMembership), not evidence the diagnosis is stale — see
// unattendedCandidateQuery's own comment. These tests go straight at the SQL,
// the same way collectUnattended itself calls it, rather than through the
// full sweep (which needs a live gateway connection this package's other
// unattended tests don't set up).

// unattendedBatchAgeFixture builds one AwaitingApproval incident with a real,
// auto-approved, undecided remediation_recommendations row backdated well
// past maxUnattendedPlanAge — the exact shape unattendedCandidateQuery scans.
// namespace defaults to "default" (the caller passes the matching allowlist).
func unattendedBatchAgeFixture(t *testing.T, pool *pgxpool.Pool, createdAt time.Time) (tenantID, clusterID, incidentID, planID string) {
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
		clusterID, tenantID, "unattended-batch-age-test-"+clusterID, "fp-"+clusterID); err != nil {
		t.Fatalf("insert cluster: %v", err)
	}
	fixture := dbtest.New(t)
	fixture.Created("clusters", 1)
	if _, err := tx.Exec(ctx,
		`INSERT INTO incidents (id, tenant_id, cluster_id, fingerprint, severity, state, first_seen, last_seen, occurrence_count)
		 VALUES ($1, $2, $3, $4, 'high', 'AwaitingApproval', $5, $5, 1)`,
		incidentID, tenantID, clusterID, "test-unattended-batch-age-"+incidentID, createdAt); err != nil {
		t.Fatalf("insert incident: %v", err)
	}
	fixture.Created("incidents", 1)
	if _, err := tx.Exec(ctx,
		`INSERT INTO analyses (id, tenant_id, incident_id, cluster_id, prompt_version, model,
		    causal_chain, iterations, duration_ms, tokens_billed_in, tokens_cache_read, tokens_out, cost_usd)
		 VALUES ($1,$2,$3,$4,'test','test-model','[]'::jsonb,1,1,0,0,0,0)`,
		analysisID, tenantID, incidentID, clusterID); err != nil {
		t.Fatalf("insert analysis: %v", err)
	}
	fixture.Created("analyses", 1)
	// AutoApprove, no decision, not superseded, in the "default" namespace —
	// every OTHER candidacy requirement satisfied, so created_at is the only
	// variable under test.
	if _, err := tx.Exec(ctx,
		`INSERT INTO remediation_recommendations (
		   id, incident_id, tenant_id, cluster_id, analysis_id, action_type,
		   target_gvk, target_namespace, target_name, params, reversible, risk_level,
		   gate_outcome, gate_reason, created_at
		 ) VALUES ($1,$2,$3,$4,$5,'ScaleDeployment','apps/v1/Deployment','default','web','{"replicas":3}'::jsonb,true,'low','AutoApprove','test',$6)`,
		planID, incidentID, tenantID, clusterID, analysisID, createdAt); err != nil {
		t.Fatalf("insert recommendation: %v", err)
	}
	fixture.Created("remediation_recommendations", 1)
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit setup: %v", err)
	}

	// dbtest.Fixture (BUGS.md, 2026-09-05): see its own doc comment.
	// unattended_batch_members carries no row from THIS fixture's own setup
	// (insertReleasedBatchMembership, called separately by the tests that need
	// one, tracks and cleans up its own row against its own fresh batchID) —
	// Created 0 here so a fixture that later gains one without updating this
	// count is still caught rather than silently under-deleted.
	fixture.Created("unattended_batch_members", 0)
	fixture.Created("evidence", 0)
	fixture.Created("analysis_embeddings", 0)
	fixture.Cleanup(pool, func(ctx context.Context, tx pgx.Tx) error {
		return data.SetRequestScope(ctx, tx, tenantID, []string{clusterID})
	}, []dbtest.TableDelete{
		{Table: "unattended_batch_members", SQL: `DELETE FROM unattended_batch_members WHERE incident_id = $1`, Args: []any{incidentID}},
		{Table: "remediation_recommendations", SQL: `DELETE FROM remediation_recommendations WHERE cluster_id = $1`, Args: []any{clusterID}},
		{Table: "evidence", SQL: `DELETE FROM evidence WHERE analysis_id IN (SELECT id FROM analyses WHERE cluster_id = $1)`, Args: []any{clusterID}},
		{Table: "analysis_embeddings", SQL: `DELETE FROM analysis_embeddings WHERE analysis_id IN (SELECT id FROM analyses WHERE cluster_id = $1)`, Args: []any{clusterID}},
		{Table: "analyses", SQL: `DELETE FROM analyses WHERE cluster_id = $1`, Args: []any{clusterID}},
		{Table: "incidents", SQL: `DELETE FROM incidents WHERE cluster_id = $1`, Args: []any{clusterID}},
		{Table: "clusters", SQL: `DELETE FROM clusters WHERE id = $1`, Args: []any{clusterID}},
	})
	return tenantID, clusterID, incidentID, planID
}

// insertReleasedBatchMembership records incidentID as a member of a
// brand-new, already-`released` batch at the given wave number — the durable
// state ResolveBatchGating leaves behind, reproduced directly here since this
// test is about unattendedCandidateQuery's SQL, not about
// orchestrator.ResolveBatchGating itself (that mechanism has its own
// exhaustive coverage in internal/orchestrator/batch_db_test.go).
func insertReleasedBatchMembership(t *testing.T, pool *pgxpool.Pool, tenantID, clusterID, incidentID, actionType string, waveNumber int) {
	t.Helper()
	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin batch setup: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if err := data.SetRequestScope(ctx, tx, tenantID, []string{clusterID}); err != nil {
		t.Fatalf("scope: %v", err)
	}

	batchID := domain.NewID(domain.PrefixUnattendedBatch)
	fleetGroupID := "fg-" + incidentID
	if _, err := tx.Exec(ctx,
		`INSERT INTO unattended_batches (id, tenant_id, fleet_group_id, action_type, status, wave1_size, total_size, created_at, updated_at, resolved_at)
		 VALUES ($1, $2, $3, $4, 'released', 1, 2, now(), now(), now())`,
		batchID, tenantID, fleetGroupID, actionType); err != nil {
		t.Fatalf("insert released batch: %v", err)
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO unattended_batch_members (id, batch_id, tenant_id, cluster_id, incident_id, wave_number)
		 VALUES ($1, $2, $3, $4, $5, $6)`,
		domain.NewID(domain.PrefixUnattendedBatchMember), batchID, tenantID, clusterID, incidentID, waveNumber); err != nil {
		t.Fatalf("insert batch member: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit batch setup: %v", err)
	}
	batchFixture := dbtest.New(t)
	batchFixture.Created("unattended_batches", 1)
	batchFixture.Created("unattended_batch_members", 1)
	batchFixture.Cleanup(pool, func(ctx context.Context, tx pgx.Tx) error {
		return data.SetRequestScope(ctx, tx, tenantID, []string{clusterID})
	}, []dbtest.TableDelete{
		{Table: "unattended_batch_members", SQL: `DELETE FROM unattended_batch_members WHERE batch_id = $1`, Args: []any{batchID}},
		{Table: "unattended_batches", SQL: `DELETE FROM unattended_batches WHERE id = $1`, Args: []any{batchID}},
	})
}

// runUnattendedCandidateQuery runs the exact query/params collectUnattended
// uses and reports whether incidentID came back.
func candidateQueryReturns(t *testing.T, pool *pgxpool.Pool, tenantID, incidentID string) bool {
	t.Helper()
	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin query tx: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	// Fleet-wide, matching collectUnattended's own scope: the sweeper has no
	// single cluster to scope to.
	if err := data.SetRequestScope(ctx, tx, tenantID, nil); err != nil {
		t.Fatalf("scope: %v", err)
	}

	// PROJECT.md T14: the namespace allowlist is no longer a query parameter —
	// filtering moved to Go in collectUnattended (see unattendedCandidateQuery's
	// own comment) — so this helper, which goes straight at the SQL the same way
	// collectUnattended itself does, no longer passes one either.
	rows, err := tx.Query(ctx, unattendedCandidateQuery,
		orchestrator.StateAwaitingApproval, time.Now().Add(-maxUnattendedPlanAge))
	if err != nil {
		t.Fatalf("unattendedCandidateQuery: %v", err)
	}
	defer rows.Close()

	found := false
	for rows.Next() {
		var c unattendedCandidate
		if err := rows.Scan(&c.IncidentID, &c.PlanID, &c.ClusterID, &c.ActionType, &c.GateReason, &c.FleetGroupID, &c.TargetNamespace); err != nil {
			t.Fatalf("scan candidate: %v", err)
		}
		if c.IncidentID == incidentID {
			found = true
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate: %v", err)
	}
	return found
}

// TestUnattendedCandidateQueryExemptsReleasedWave2FromAgeBound is BUGS.md
// 100's exact scenario: wave 2's plan was created more than
// maxUnattendedPlanAge (10 minutes) ago — deliberately backdated here rather
// than waiting 10 real minutes — and its batch has JUST been released
// (status='released', simulating wave 1 having validated moments ago). Before
// the fix, `r.created_at >= $2` alone excluded this row from the candidate
// query forever, regardless of the batch's status: wave 2 could never
// auto-execute. After the fix, the OR EXISTS clause recognizes the wave-2
// membership and the row is returned.
func TestUnattendedCandidateQueryExemptsReleasedWave2FromAgeBound(t *testing.T) {
	pool := authTestPool(t)
	backdated := time.Now().Add(-20 * time.Minute) // well past the 10-minute bound, well short of maxBatchHoldDuration's 2 hours
	tenantID, clusterID, incidentID, _ := unattendedBatchAgeFixture(t, pool, backdated)
	insertReleasedBatchMembership(t, pool, tenantID, clusterID, incidentID, "ScaleDeployment", 2)

	if !candidateQueryReturns(t, pool, tenantID, incidentID) {
		t.Fatal("a released wave-2 batch member with a 20-minute-old plan was not returned by unattendedCandidateQuery — " +
			"BUGS.md 100: this plan aged out of the 10-minute window before wave 1 (validationGracePeriod's 15-minute floor) ever released it, " +
			"so it could never auto-execute")
	}
}

// TestUnattendedCandidateQueryStillAgesOutNonBatchedCandidates is the control
// proving the fix is scoped to batch membership, not a general loosening of
// the staleness guard: an equally-old plan with NO batch membership at all
// must still be excluded, exactly as before.
func TestUnattendedCandidateQueryStillAgesOutNonBatchedCandidates(t *testing.T) {
	pool := authTestPool(t)
	backdated := time.Now().Add(-20 * time.Minute)
	tenantID, _, incidentID, _ := unattendedBatchAgeFixture(t, pool, backdated)
	// Deliberately no insertReleasedBatchMembership call.

	if candidateQueryReturns(t, pool, tenantID, incidentID) {
		t.Fatal("a 20-minute-old plan with no batch membership was returned by unattendedCandidateQuery — " +
			"the age bound must still apply to the ordinary, non-batched case")
	}
}

// TestUnattendedCandidateQueryStillAgesOutWave1Members: wave 1 is Eligible()
// immediately (orchestrator.BatchMembership.Eligible), so it never needs the
// exemption and must not get it by accident — a wave-1 candidate that ages
// out (e.g. because it kept losing to the blast-radius cap for many ticks)
// should still fall to the human queue exactly like today.
func TestUnattendedCandidateQueryStillAgesOutWave1Members(t *testing.T) {
	pool := authTestPool(t)
	backdated := time.Now().Add(-20 * time.Minute)
	tenantID, clusterID, incidentID, _ := unattendedBatchAgeFixture(t, pool, backdated)
	insertReleasedBatchMembership(t, pool, tenantID, clusterID, incidentID, "ScaleDeployment", 1)

	if candidateQueryReturns(t, pool, tenantID, incidentID) {
		t.Fatal("a 20-minute-old WAVE-1 plan was returned by unattendedCandidateQuery — " +
			"the age exemption is meant only for wave_number > 1; wave 1 is eligible immediately and still needs the ordinary staleness guard")
	}
}

// TestUnattendedCandidateQueryHonoursActionTypeWhenExemptingBatchMembers
// mirrors orchestrator.existingMembership's own action_type match: a batch
// membership row recorded under a DIFFERENT action_type than the
// recommendation currently proposes must not exempt it — a re-analysis that
// changed the proposed fix is a different coordination scope, per
// batch.go's header.
func TestUnattendedCandidateQueryHonoursActionTypeWhenExemptingBatchMembers(t *testing.T) {
	pool := authTestPool(t)
	backdated := time.Now().Add(-20 * time.Minute)
	tenantID, clusterID, incidentID, _ := unattendedBatchAgeFixture(t, pool, backdated) // recommendation's action_type is ScaleDeployment
	insertReleasedBatchMembership(t, pool, tenantID, clusterID, incidentID, "RestartPod", 2)

	if candidateQueryReturns(t, pool, tenantID, incidentID) {
		t.Fatal("a wave-2 membership recorded under a different action_type (RestartPod) exempted a ScaleDeployment recommendation from the age bound — " +
			"this must be scoped to the SAME action_type, exactly like orchestrator.existingMembership")
	}
}
