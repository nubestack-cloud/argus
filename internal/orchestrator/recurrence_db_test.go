package orchestrator

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"argus/internal/data"
	"argus/internal/dbtest"
	"argus/internal/domain"
	"argus/internal/remediation"
)

// PROJECT.md T7: "a rejection reason reaches something that acts on it."
// These exercise demoteIfPreviouslyRejected (recurrence.go) directly against
// a real Postgres — the behaviour under test IS a database read
// (remediation_approval_decisions joined through remediation_recommendations
// to a DIFFERENT incident sharing this one's object_key), which a unit test
// with no database cannot exercise honestly.

// recurrenceFixture inserts a throwaway cluster, a CLOSED "prior" incident
// naming objectKey with a rejected recommendation for actionType (unless
// skipRejection), and a second, OPEN "current" incident on the SAME object —
// the exact shape a real recurrence produces once T7's own link mechanism
// (internal/api/incidents.go's priorIncidentLinksFor) would show one linked
// to the other.
func recurrenceFixture(t *testing.T, pool *pgxpool.Pool, objectKey string, actionType remediation.ActionType, skipRejection bool) (fixture *dbtest.Fixture, tenantID, clusterID, priorIncidentID, currentIncidentID string) {
	t.Helper()
	ctx := context.Background()

	clusterID = domain.NewID(domain.PrefixCluster)
	priorIncidentID = domain.NewID(domain.PrefixIncident)
	currentIncidentID = domain.NewID(domain.PrefixIncident)

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
		clusterID, tenantID, "t7-test-"+clusterID, "fp-"+clusterID); err != nil {
		t.Fatalf("insert cluster: %v", err)
	}
	fixture.Created("clusters", 1)

	now := time.Now()
	if _, err := tx.Exec(ctx,
		`INSERT INTO incidents (id, tenant_id, cluster_id, fingerprint, severity, state, first_seen, last_seen, occurrence_count, object_key, resolved_at)
		 VALUES ($1, $2, $3, $4, 'high', 'Dismissed', $5, $5, 1, $6, $5)`,
		priorIncidentID, tenantID, clusterID, "test-t7-prior-"+priorIncidentID, now.Add(-24*time.Hour), objectKey); err != nil {
		t.Fatalf("insert prior incident: %v", err)
	}
	fixture.Created("incidents", 1)

	if _, err := tx.Exec(ctx,
		`INSERT INTO incidents (id, tenant_id, cluster_id, fingerprint, severity, state, first_seen, last_seen, occurrence_count, object_key)
		 VALUES ($1, $2, $3, $4, 'high', 'Investigating', $5, $5, 1, $6)`,
		currentIncidentID, tenantID, clusterID, "test-t7-current-"+currentIncidentID, now, objectKey); err != nil {
		t.Fatalf("insert current incident: %v", err)
	}
	fixture.Created("incidents", 1)

	if !skipRejection {
		analysisID := domain.NewID(domain.PrefixAnalysis)
		if _, err := tx.Exec(ctx,
			`INSERT INTO analyses (id, tenant_id, incident_id, cluster_id, prompt_version, model,
			    causal_chain, iterations, duration_ms, tokens_billed_in, tokens_cache_read, tokens_out, cost_usd)
			 VALUES ($1,$2,$3,$4,'test','test-model','[]'::jsonb,1,1,0,0,0,0)`,
			analysisID, tenantID, priorIncidentID, clusterID); err != nil {
			t.Fatalf("insert prior analysis: %v", err)
		}
		fixture.Created("analyses", 1)

		recID := domain.NewID(domain.PrefixPlan)
		if _, err := tx.Exec(ctx,
			`INSERT INTO remediation_recommendations
			   (id, incident_id, tenant_id, cluster_id, analysis_id, action_type, target_gvk,
			    target_namespace, target_name, params, reversible, risk_level, gate_outcome, gate_reason)
			 VALUES ($1, $2, $3, $4, $5, $6, 'apps/v1/Deployment', 'default', 'payments-api',
			         '{}'::jsonb, true, 'low', 'AutoApprove', 'test')`,
			recID, priorIncidentID, tenantID, clusterID, analysisID, string(actionType)); err != nil {
			t.Fatalf("insert prior recommendation: %v", err)
		}
		fixture.Created("remediation_recommendations", 1)

		approvalID := domain.NewID(domain.PrefixApproval)
		userID := domain.NewID(domain.PrefixUser)
		if _, err := tx.Exec(ctx,
			`INSERT INTO remediation_approval_decisions
			   (id, recommendation_id, incident_id, tenant_id, cluster_id, actor_id, verdict, reason)
			 VALUES ($1, $2, $3, $4, $5, $6, 'rejected', $7)`,
			approvalID, recID, priorIncidentID, tenantID, clusterID, userID,
			"scaling replicas does not fix a per-pod OOM"); err != nil {
			t.Fatalf("insert rejection: %v", err)
		}
		fixture.Created("remediation_approval_decisions", 1)
	} else {
		fixture.Created("analyses", 0)
		fixture.Created("remediation_recommendations", 0)
		fixture.Created("remediation_approval_decisions", 0)
	}
	// Neither branch above ever inserts evidence/analysis_embeddings, but
	// cleanupRecurrenceFixture deletes from both (matching every other
	// fixture in this package, per BUGS.md 119's delete-order note) — every
	// table a cleanup touches needs a tracked count, zero included, or
	// dbtest.Fixture refuses to run it at all.
	fixture.Created("evidence", 0)
	fixture.Created("analysis_embeddings", 0)

	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit setup: %v", err)
	}
	return fixture, tenantID, clusterID, priorIncidentID, currentIncidentID
}

func cleanupRecurrenceFixture(fixture *dbtest.Fixture, pool *pgxpool.Pool, tenantID, clusterID string) {
	fixture.Cleanup(pool, func(ctx context.Context, tx pgx.Tx) error {
		return data.SetRequestScope(ctx, tx, tenantID, []string{clusterID})
	}, []dbtest.TableDelete{
		{Table: "remediation_approval_decisions", SQL: `DELETE FROM remediation_approval_decisions WHERE cluster_id = $1`, Args: []any{clusterID}},
		{Table: "remediation_recommendations", SQL: `DELETE FROM remediation_recommendations WHERE cluster_id = $1`, Args: []any{clusterID}},
		{Table: "evidence", SQL: `DELETE FROM evidence WHERE analysis_id IN (SELECT id FROM analyses WHERE cluster_id = $1)`, Args: []any{clusterID}},
		{Table: "analysis_embeddings", SQL: `DELETE FROM analysis_embeddings WHERE analysis_id IN (SELECT id FROM analyses WHERE cluster_id = $1)`, Args: []any{clusterID}},
		{Table: "analyses", SQL: `DELETE FROM analyses WHERE cluster_id = $1`, Args: []any{clusterID}},
		{Table: "incidents", SQL: `DELETE FROM incidents WHERE cluster_id = $1`, Args: []any{clusterID}},
		{Table: "clusters", SQL: `DELETE FROM clusters WHERE id = $1`, Args: []any{clusterID}},
	})
}

func TestDemoteIfPreviouslyRejected_DowngradesAnIdenticalActionTypeOnTheSameObject(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	objectKey := "apps/v1/Deployment|default|payments-api"

	fixture, tenantID, clusterID, priorIncidentID, currentIncidentID := recurrenceFixture(t, pool, objectKey, remediation.ActionScaleDeployment, false)
	defer cleanupRecurrenceFixture(fixture, pool, tenantID, clusterID)

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if err := data.SetRequestScope(ctx, tx, tenantID, []string{clusterID}); err != nil {
		t.Fatalf("scope: %v", err)
	}

	plan := &remediation.RemediationPlan{ActionType: remediation.ActionScaleDeployment}
	decision := &remediation.Decision{Outcome: remediation.AutoApprove, Reason: "low risk, reversible, high confidence"}

	demoted, note := demoteIfPreviouslyRejected(ctx, tx, currentIncidentID, plan, decision)

	if !demoted {
		t.Fatalf("demoted = false, want true — an identical action type was rejected on incident %s for this same object", priorIncidentID)
	}
	if decision.Outcome != remediation.NeedsApproval {
		t.Fatalf("decision.Outcome = %v, want NeedsApproval — an AutoApprove verdict must not survive a prior rejection on this object", decision.Outcome)
	}
	if !strings.Contains(note, priorIncidentID) {
		t.Fatalf("note = %q, want it to name the prior incident %s — inspectable, not an opaque score", note, priorIncidentID)
	}
	if !strings.Contains(note, "scaling replicas does not fix a per-pod OOM") {
		t.Fatalf("note = %q, want it to quote the stored rejection reason verbatim", note)
	}
	if note != decision.Reason {
		t.Fatalf("decision.Reason = %q, want it to equal the returned note", decision.Reason)
	}
}

func TestDemoteIfPreviouslyRejected_LeavesADifferentActionTypeAlone(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	objectKey := "apps/v1/Deployment|default|payments-api-2"

	// Rejected ScaleDeployment before, but the CURRENT candidate plan is a
	// different action type — a rejection of one fix must not silently
	// demote an unrelated one on the same object.
	fixture, tenantID, clusterID, _, currentIncidentID := recurrenceFixture(t, pool, objectKey, remediation.ActionScaleDeployment, false)
	defer cleanupRecurrenceFixture(fixture, pool, tenantID, clusterID)

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if err := data.SetRequestScope(ctx, tx, tenantID, []string{clusterID}); err != nil {
		t.Fatalf("scope: %v", err)
	}

	plan := &remediation.RemediationPlan{ActionType: remediation.ActionRestartPod}
	decision := &remediation.Decision{Outcome: remediation.AutoApprove, Reason: "low risk, reversible, high confidence"}

	demoted, _ := demoteIfPreviouslyRejected(ctx, tx, currentIncidentID, plan, decision)

	if demoted {
		t.Fatalf("demoted = true, want false — RestartPod was never rejected on this object, only ScaleDeployment was")
	}
	if decision.Outcome != remediation.AutoApprove {
		t.Fatalf("decision.Outcome = %v, want AutoApprove unchanged", decision.Outcome)
	}
}

func TestDemoteIfPreviouslyRejected_NoPriorRejectionAtAll(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	objectKey := "apps/v1/Deployment|default|payments-api-3"

	fixture, tenantID, clusterID, _, currentIncidentID := recurrenceFixture(t, pool, objectKey, remediation.ActionScaleDeployment, true /* skipRejection */)
	defer cleanupRecurrenceFixture(fixture, pool, tenantID, clusterID)

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if err := data.SetRequestScope(ctx, tx, tenantID, []string{clusterID}); err != nil {
		t.Fatalf("scope: %v", err)
	}

	plan := &remediation.RemediationPlan{ActionType: remediation.ActionScaleDeployment}
	decision := &remediation.Decision{Outcome: remediation.AutoApprove, Reason: "low risk, reversible, high confidence"}

	demoted, _ := demoteIfPreviouslyRejected(ctx, tx, currentIncidentID, plan, decision)

	if demoted {
		t.Fatalf("demoted = true, want false — nothing was ever rejected on this object")
	}
	if decision.Outcome != remediation.AutoApprove {
		t.Fatalf("decision.Outcome = %v, want AutoApprove unchanged", decision.Outcome)
	}
}

func TestDemoteIfPreviouslyRejected_ShortCircuitsWhenNotAutoApprove(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	objectKey := "apps/v1/Deployment|default|payments-api-4"

	fixture, tenantID, clusterID, _, currentIncidentID := recurrenceFixture(t, pool, objectKey, remediation.ActionScaleDeployment, false)
	defer cleanupRecurrenceFixture(fixture, pool, tenantID, clusterID)

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if err := data.SetRequestScope(ctx, tx, tenantID, []string{clusterID}); err != nil {
		t.Fatalf("scope: %v", err)
	}

	// Already NeedsApproval — this rule has nothing to add; a rejected
	// prior plan on the same action type exists, but demoteIfPreviouslyRejected
	// must never touch an outcome that already reaches a human.
	plan := &remediation.RemediationPlan{ActionType: remediation.ActionScaleDeployment}
	decision := &remediation.Decision{Outcome: remediation.NeedsApproval, Reason: "confidence below threshold"}

	demoted, note := demoteIfPreviouslyRejected(ctx, tx, currentIncidentID, plan, decision)

	if demoted {
		t.Fatalf("demoted = true, want false — only AutoApprove is ever downgraded")
	}
	if note != "" {
		t.Fatalf("note = %q, want empty", note)
	}
	if decision.Outcome != remediation.NeedsApproval || decision.Reason != "confidence below threshold" {
		t.Fatalf("decision = %+v, want it completely unchanged", decision)
	}
}

// A Deployment's pods are renamed by every rollout. A rejection recorded on one
// pod must still demote the same action proposed for its replacement, matched
// through the shared workload_key (found live on rke2, 2026-10-12).
func TestDemoteIfPreviouslyRejected_MatchesTheSameWorkloadAcrossPodNames(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()

	fixture, tenantID, clusterID, priorIncidentID, currentIncidentID := recurrenceFixture(t, pool, "v1/Pod|default|web-f6f45b5bc-ddshr", remediation.ActionScaleDeployment, false)
	defer cleanupRecurrenceFixture(fixture, pool, tenantID, clusterID)

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if err := data.SetRequestScope(ctx, tx, tenantID, []string{clusterID}); err != nil {
		t.Fatalf("scope: %v", err)
	}
	// The replacement pod: a different object, the same workload.
	const workloadKey = "apps/v1/Deployment|default|web"
	if _, err := tx.Exec(ctx, `UPDATE incidents SET workload_key = $1 WHERE id = ANY($2)`, workloadKey, []string{priorIncidentID, currentIncidentID}); err != nil {
		t.Fatalf("set workload keys: %v", err)
	}
	if _, err := tx.Exec(ctx, `UPDATE incidents SET object_key = 'v1/Pod|default|web-99d6c96bf-8lxxm' WHERE id = $1`, currentIncidentID); err != nil {
		t.Fatalf("rename current pod: %v", err)
	}

	plan := &remediation.RemediationPlan{ActionType: remediation.ActionScaleDeployment}
	decision := &remediation.Decision{Outcome: remediation.AutoApprove, Reason: "low risk, reversible, high confidence"}
	demoted, note := demoteIfPreviouslyRejected(ctx, tx, currentIncidentID, plan, decision)
	if !demoted || decision.Outcome != remediation.NeedsApproval {
		t.Fatalf("demoted = %v, outcome = %v; want a demotion to NeedsApproval from the rejection on a sibling pod of the same workload", demoted, decision.Outcome)
	}
	if !strings.Contains(note, priorIncidentID) {
		t.Fatalf("note = %q, want it to name the prior incident %s", note, priorIncidentID)
	}
}
