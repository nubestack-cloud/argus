package orchestrator

import (
	"context"
	"strings"
	"testing"

	"argus/internal/data"
	"argus/internal/domain"
	"argus/internal/remediation"
)

// TestRiskLevelCheckConstraintAcceptsEveryRiskLevel is
// TestActionTypeCheckConstraintAcceptsEveryActionType's own doc comment,
// applied to a different column: `remediation_recommendations.risk_level`
// carries a CHECK constraint mirroring internal/remediation.RiskLevel's Go
// enum, and migrations 000040/000056 already show what happens once a Go
// enum gains a value the database was never told about — the first plan
// carrying it fails at INSERT time, inside a transaction a human may have
// just approved.
//
// BACKLOG.md R4 added RiskForbidden without migration 000063 ever having
// been proven against a real constraint, so this test closes the same gap
// for risk_level that 000056 closed for action_type, driving the REAL
// constraint from remediation.AllRiskLevels() rather than a hand-copied
// list that could quietly drift from it.
func TestRiskLevelCheckConstraintAcceptsEveryRiskLevel(t *testing.T) {
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

	levels := remediation.AllRiskLevels()
	if len(levels) == 0 {
		t.Fatal("remediation.AllRiskLevels() is empty, so this test would pass vacuously")
	}

	for _, rl := range levels {
		t.Run(string(rl), func(t *testing.T) {
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
				 VALUES ($1,$2,$3,$4,$5,'ScaleDeployment','apps/v1/Deployment','argus-test','web','{}'::jsonb,true,$6,'NeedsApproval','constraint coverage test')`,
				domain.NewID(domain.PrefixPlan), incidentID, tenantID, clusterID, analysisID, string(rl))
			if err != nil {
				if strings.Contains(err.Error(), "risk_level_check") {
					t.Fatalf("risk level %q is in remediation.AllRiskLevels() but the database CHECK constraint refuses it. "+
						"A plan declaring this risk level can never be persisted. Add a migration widening "+
						"remediation_recommendations_risk_level_check", rl)
				}
				t.Fatalf("insert %q: %v", rl, err)
			}
		})
	}
}
