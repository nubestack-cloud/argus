package orchestrator

import (
	"context"
	"strings"
	"testing"
	"time"

	"argus/internal/data"
	"argus/internal/domain"
	"argus/internal/remediation"
)

// TestActionTypeCheckConstraintAcceptsEveryActionType is the guard that should
// have existed after migration 000040 and did not.
//
// `remediation_recommendations.action_type` carries a CHECK constraint mirroring
// the Go enum. Twice now, an action type has been built with complete Go-side
// support — the constant, params marshalling, an agent tool, an execution mapping,
// tests at every layer — and the constraint was not updated, so the very first
// attempt to persist one failed at runtime:
//
//	ERROR: new row for relation "remediation_recommendations" violates
//	check constraint "remediation_recommendations_action_type_check"
//
// Migration 000040 fixed the first instance (PatchResourceLimits,
// RevertContainerImage) and left nothing behind to catch a recurrence. 000056
// fixed the second (PatchField). This test is what makes a third impossible: it
// drives the REAL constraint from remediation.AllActionTypes(), so adding a type
// to the Go enum without a migration fails here rather than in production after a
// human has approved a plan.
//
// Deliberately a DB test rather than a comparison of two string lists in Go: a
// list-vs-list test would compare the enum against a hand-copied set and pass while
// the actual constraint said something else. This inserts a real row per action type
// and lets Postgres answer.
func TestActionTypeCheckConstraintAcceptsEveryActionType(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	fixture, tenantID, clusterID, incidentID, _ := breakerFixture(t, pool)
	// This test never calls addExecution/checkBreakerIn — every sub-test's
	// own transaction is rolled back, not committed — so no
	// remediation_executions/circuit_breaker_trips rows survive it.
	fixture.Created("remediation_executions", 0)
	fixture.Created("circuit_breaker_trips", 0)
	fixture.Created("evidence", 0)
	fixture.Created("analysis_embeddings", 0)
	cleanupBreakerFixture(fixture, pool, tenantID, clusterID)

	types := remediation.AllActionTypes()
	if len(types) == 0 {
		t.Fatal("remediation.AllActionTypes() is empty, so this test would pass vacuously")
	}

	for _, at := range types {
		t.Run(string(at), func(t *testing.T) {
			tx, err := pool.Begin(ctx)
			if err != nil {
				t.Fatalf("begin: %v", err)
			}
			defer tx.Rollback(ctx) //nolint:errcheck
			if err := data.SetRequestScope(ctx, tx, tenantID, []string{clusterID}); err != nil {
				t.Fatalf("scope: %v", err)
			}
			analysisID := domain.NewID(domain.PrefixAnalysis)
			if _, err := tx.Exec(ctx,
				`INSERT INTO analyses (id, tenant_id, incident_id, cluster_id, prompt_version, model,
				    causal_chain, iterations, duration_ms, tokens_billed_in, tokens_cache_read, tokens_out, cost_usd)
				 VALUES ($1,$2,$3,$4,'test','test-model','[]'::jsonb,1,1,0,0,0,0)`,
				analysisID, tenantID, incidentID, clusterID); err != nil {
				t.Fatalf("insert analysis: %v", err)
			}
			_, err = tx.Exec(ctx,
				`INSERT INTO remediation_recommendations
				   (id, incident_id, tenant_id, cluster_id, analysis_id, action_type, target_gvk,
				    target_namespace, target_name, params, reversible, risk_level, gate_outcome, gate_reason)
				 VALUES ($1,$2,$3,$4,$5,$6,'apps/v1/Deployment','argus-test','web','{}'::jsonb,true,'medium','NeedsApproval','constraint coverage test')`,
				domain.NewID(domain.PrefixPlan), incidentID, tenantID, clusterID, analysisID, string(at))
			if err != nil {
				if strings.Contains(err.Error(), "action_type_check") {
					t.Fatalf("action type %q is in remediation.AllActionTypes() but the database CHECK constraint refuses it. "+
						"A plan of this type can never be persisted, so it fails after analysis and, for an auto-approved one, "+
						"after a human has authorised it. Add a migration widening "+
						"remediation_recommendations_action_type_check — this has already happened twice (migrations 000040 and 000056)", at)
				}
				t.Fatalf("insert %q: %v", at, err)
			}
			// Rolled back: this test proves the constraint accepts the value and
			// must leave no rows behind for the fixture's cleanup to trip over.
			_ = time.Now
		})
	}
}
