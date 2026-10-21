package api

// TestFlagMissingRunnableNextStep_* is BACKLOG.md F27's proof that the
// mechanical guard actually records the honest note it claims to, against a
// real Postgres — the same ARGUS_TEST_DATABASE_URL-gated harness
// analyze_detach_db_test.go's own tests use, reusing its
// analyzeDetachTestPool/analyzeDetachTestIncident fixtures rather than
// building a third copy of the same throwaway-cluster-and-incident setup.

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"argus/internal/data"
	"argus/internal/llm"
	"argus/internal/remediation"
	"argus/internal/timeline"
)

// countNoActionableNextStepEvents reads back, in its own freshly-scoped
// transaction (never the transaction under test — the same "observe what is
// durable" discipline analyzeDetachTestIncidentState already follows), how
// many timeline_events rows of BACKLOG.md F27's own event type exist for
// incidentID.
func countNoActionableNextStepEvents(t *testing.T, pool *pgxpool.Pool, tenantID, clusterID, incidentID string) int {
	t.Helper()
	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin read transaction: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if err := data.SetRequestScope(ctx, tx, tenantID, []string{clusterID}); err != nil {
		t.Fatalf("set request scope: %v", err)
	}
	var count int
	if err := tx.QueryRow(ctx,
		`SELECT count(*) FROM timeline_events WHERE incident_id = $1 AND event_type = $2`,
		incidentID, timeline.EventNoActionableNextStep,
	).Scan(&count); err != nil {
		t.Fatalf("count timeline_events: %v", err)
	}
	return count
}

// TestFlagMissingRunnableNextStep_NoPlanNoCommand_RecordsTheEvent is the
// FAILS-the-check case: a "complete" analysis with no proposedPlan and
// suggestedNextSteps containing only prose/field-path advice, nothing an
// operator could copy and run. The guard must not mutate result (there is
// nothing to refuse), but must record exactly one
// timeline.EventNoActionableNextStep row.
func TestFlagMissingRunnableNextStep_NoPlanNoCommand_RecordsTheEvent(t *testing.T) {
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

	confidence := 0.9
	result := llm.Investigation{
		Model:      "test-model",
		Status:     "complete",
		RootCause:  &llm.RootCause{Statement: "BACKLOG.md F27 regression test: no plan, no runnable command"},
		Confidence: &confidence,
		SuggestedNextSteps: []string{
			"Restart the pod once the underlying disk pressure clears.",
			"Set spec.template.spec.containers[0].resources.limits.memory to 512Mi on deployment/checkout-api in payments-prod (currently 256Mi).",
		},
	}

	FlagMissingRunnableNextStep(ctx, tx, tenantID, clusterID, incidentID, result)

	if result.ProposedPlan != nil || result.ProposedPairedPlan != nil {
		t.Fatalf("FlagMissingRunnableNextStep must never fabricate a plan — got ProposedPlan=%v ProposedPairedPlan=%v", result.ProposedPlan, result.ProposedPairedPlan)
	}

	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit: %v", err)
	}

	if got := countNoActionableNextStepEvents(t, pool, tenantID, clusterID, incidentID); got != 1 {
		t.Errorf("timeline_events rows of type %q for this incident = %d, want 1 — the guard should have recorded exactly one honest note", timeline.EventNoActionableNextStep, got)
	}
}

// TestFlagMissingRunnableNextStep_RealCommandPresent_NoEventRecorded is the
// PASSES-the-check case: the same shape of "complete, no plan" analysis, but
// one suggestedNextSteps entry is a real, fully-filled-in kubectl command.
// The guard must be a complete no-op — no event, no mutation.
func TestFlagMissingRunnableNextStep_RealCommandPresent_NoEventRecorded(t *testing.T) {
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

	confidence := 0.9
	result := llm.Investigation{
		Model:      "test-model",
		Status:     "complete",
		RootCause:  &llm.RootCause{Statement: "BACKLOG.md F27 regression test: no plan, but a real runnable command"},
		Confidence: &confidence,
		SuggestedNextSteps: []string{
			"kubectl -n payments-prod patch deployment/checkout-api --type=json -p '[{\"op\":\"replace\",\"path\":\"/spec/template/spec/containers/0/resources/limits/memory\",\"value\":\"512Mi\"}]'",
		},
	}

	FlagMissingRunnableNextStep(ctx, tx, tenantID, clusterID, incidentID, result)

	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit: %v", err)
	}

	if got := countNoActionableNextStepEvents(t, pool, tenantID, clusterID, incidentID); got != 0 {
		t.Errorf("timeline_events rows of type %q for this incident = %d, want 0 — a real runnable command was present, so nothing should have been flagged", timeline.EventNoActionableNextStep, got)
	}
}

// TestFlagMissingRunnableNextStep_PlanProposed_NoEventRecorded proves the
// guard stays scoped to F27's actual case: a proposed plan means some
// channel already exists, so a prose-only suggestedNextSteps alongside it
// (the F21 "manual equivalent, even when a plan exists" behaviour) must
// never be flagged.
func TestFlagMissingRunnableNextStep_PlanProposed_NoEventRecorded(t *testing.T) {
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

	confidence := 0.9
	result := llm.Investigation{
		Model:      "test-model",
		Status:     "complete",
		RootCause:  &llm.RootCause{Statement: "BACKLOG.md F27 regression test: a plan exists, so this must never be flagged"},
		Confidence: &confidence,
		SuggestedNextSteps: []string{
			"Restart the pod once the underlying disk pressure clears.",
		},
		// A minimal, non-nil plan is all FlagMissingRunnableNextStep looks
		// at — it never inspects Params.
		ProposedPlan: &remediation.RemediationPlan{
			ActionType:      remediation.ActionScaleDeployment,
			TargetGVK:       "apps/v1/Deployment",
			TargetNamespace: "payments-prod",
			TargetName:      "checkout-api",
			RiskLevel:       remediation.RiskLow,
			Reversible:      true,
		},
	}

	FlagMissingRunnableNextStep(ctx, tx, tenantID, clusterID, incidentID, result)

	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit: %v", err)
	}

	if got := countNoActionableNextStepEvents(t, pool, tenantID, clusterID, incidentID); got != 0 {
		t.Errorf("timeline_events rows of type %q for this incident = %d, want 0 — a proposed plan means a channel already exists, so this must never be flagged", timeline.EventNoActionableNextStep, got)
	}
}
