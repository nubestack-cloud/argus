package api

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"argus/internal/data"
	"argus/internal/dbtest"
	"argus/internal/domain"
)

// approvalCausalChainFixture mirrors timelineExecFixture's shape (same
// cluster/incident/analysis/recommendation quadruple) but writes a REAL
// causal_chain/ruled_out payload rather than an empty one — specifically one
// step whose only ToolCall is "contradicted" (PROJECT.md B151's own most
// serious signal) and one ruled-out hypothesis, so this test can prove
// PROJECT.md D8's approval-queue join actually surfaces both rather than
// silently dropping them the way the query used to before this column was
// added to its SELECT list.
func approvalCausalChainFixture(t *testing.T, pool *pgxpool.Pool) (tenantID, clusterID, incidentID string) {
	t.Helper()
	ctx := context.Background()

	clusterID = domain.NewID(domain.PrefixCluster)
	incidentID = domain.NewID(domain.PrefixIncident)
	analysisID := domain.NewID(domain.PrefixAnalysis)
	planID := domain.NewID(domain.PrefixPlan)

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
		clusterID, tenantID, "approval-causal-chain-test-"+clusterID, "fp-"+clusterID); err != nil {
		t.Fatalf("insert cluster: %v", err)
	}
	now := time.Now()
	if _, err := tx.Exec(ctx,
		`INSERT INTO incidents (id, tenant_id, cluster_id, fingerprint, severity, state, first_seen, last_seen, occurrence_count)
		 VALUES ($1, $2, $3, $4, 'high', 'AwaitingApproval', $5, $5, 1)`,
		incidentID, tenantID, clusterID, "test-approval-causal-chain-"+incidentID, now); err != nil {
		t.Fatalf("insert incident: %v", err)
	}

	const causalChain = `[
		{"step": 1, "hypothesis": "the sidecar has the wrong LOG_LEVEL",
		 "toolCalls": [{"tool": "describe_resource", "args": {}, "result": {"LOG_LEVEL": "info"}, "error": null, "corroborated": "contradicted"}],
		 "finding": "the analysis cited LOG_LEVEL=debug, but the real tool result says LOG_LEVEL=info"}
	]`
	const ruledOut = `[{"hypothesis": "the ConfigMap itself is missing", "reason": "confirmed present via describe_resource"}]`
	const rootCause = `{"status": "complete", "statement": "wrong sidecar env value", "causalChainProvenance": "self-reported"}`

	if _, err := tx.Exec(ctx,
		`INSERT INTO analyses (id, tenant_id, incident_id, cluster_id, prompt_version, model,
		    causal_chain, ruled_out, root_cause, confidence, iterations, duration_ms, tokens_billed_in, tokens_cache_read, tokens_out, cost_usd)
		 VALUES ($1,$2,$3,$4,'test','test-model',$5::jsonb,$6::jsonb,$7::jsonb,0.9,1,1,0,0,0,0)`,
		analysisID, tenantID, incidentID, clusterID, causalChain, ruledOut, rootCause); err != nil {
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
			t.Logf("cleanup begin: %v", err)
			return
		}
		defer tx.Rollback(ctx) //nolint:errcheck
		if err := data.SetRequestScope(ctx, tx, tenantID, []string{clusterID}); err != nil {
			t.Logf("cleanup scope: %v", err)
			return
		}
		// PROJECT.md B175: the analysis and the recommendation this fixture
		// itself inserts were missing from this list, so every run orphaned
		// both onto an incident id that no longer existed. t.Logf rather
		// than t.Errorf on the statements is this file's own idiom and is
		// kept; the residue check below is what turns a silent miss into a
		// failure, because a delete that removes nothing is not an error.
		for _, stmt := range []string{
			`DELETE FROM timeline_events WHERE cluster_id = $1`,
			`DELETE FROM incident_notifications WHERE cluster_id = $1`,
			`DELETE FROM remediation_recommendations WHERE cluster_id = $1`,
			`DELETE FROM evidence WHERE analysis_id IN (SELECT id FROM analyses WHERE cluster_id = $1)`,
			`DELETE FROM analysis_embeddings WHERE analysis_id IN (SELECT id FROM analyses WHERE cluster_id = $1)`,
			`DELETE FROM analyses WHERE cluster_id = $1`,
			`DELETE FROM incidents WHERE cluster_id = $1`,
			`DELETE FROM clusters WHERE id = $1`,
		} {
			if _, err := tx.Exec(ctx, stmt, clusterID); err != nil {
				t.Logf("cleanup %q: %v", stmt, err)
			}
		}
		if err := tx.Commit(ctx); err != nil {
			t.Logf("cleanup commit: %v", err)
			return
		}
		dbtest.AssertNoClusterResidue(t, pool, tenantID, clusterID)
	})

	return tenantID, clusterID, incidentID
}

// TestApprovalQueueItem_CarriesCausalChainAndRuledOut is PROJECT.md D8's own
// regression test: before the approvalQueueQuery/scanApprovalQueueItem
// change, an approver had no way to see a "contradicted" causal-chain
// citation, or what ARGUS ruled out, without navigating away from the
// approval queue to the incident detail page. Proves both now come through
// the SAME row a worklist/inline approval card renders from.
func TestApprovalQueueItem_CarriesCausalChainAndRuledOut(t *testing.T) {
	connString := os.Getenv("ARGUS_TEST_DATABASE_URL")
	if connString == "" {
		t.Skip("ARGUS_TEST_DATABASE_URL not set; skipping PROJECT.md D8 approval-queue causal-chain regression test")
	}
	pool, err := pgxpool.New(context.Background(), connString)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	// Registered before the fixture's own t.Cleanup below, so LIFO teardown
	// order runs the fixture's row cleanup FIRST and closes the pool only
	// once that cleanup no longer needs it.
	t.Cleanup(pool.Close)

	tenantID, clusterID, incidentID := approvalCausalChainFixture(t, pool)

	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if err := data.SetRequestScope(ctx, tx, tenantID, []string{clusterID}); err != nil {
		t.Fatalf("scope: %v", err)
	}

	rows, err := tx.Query(ctx, approvalQueueQuery, []string{"AwaitingApproval", "AwaitingMerge"})
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	defer rows.Close()

	var found *approvalQueueItem
	for rows.Next() {
		item, err := scanApprovalQueueItem(rows)
		if err != nil {
			t.Fatalf("scan: %v", err)
		}
		if item.IncidentID == incidentID {
			it := item
			found = &it
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("rows: %v", err)
	}
	if found == nil {
		t.Fatalf("incident %s not found in approval queue", incidentID)
	}

	if len(found.CausalChain) != 1 {
		t.Fatalf("CausalChain = %+v, want exactly 1 step", found.CausalChain)
	}
	step := found.CausalChain[0]
	if len(step.ToolCalls) != 1 {
		t.Fatalf("step.ToolCalls = %+v, want exactly 1 call", step.ToolCalls)
	}
	if got := step.ToolCalls[0].Corroborated; got != "contradicted" {
		t.Errorf("ToolCalls[0].Corroborated = %q, want %q — this is the exact signal an approver must not be able to miss", got, "contradicted")
	}
	if found.CausalChainProvenance != "self-reported" {
		t.Errorf("CausalChainProvenance = %q, want %q", found.CausalChainProvenance, "self-reported")
	}
	if len(found.RuledOut) != 1 || found.RuledOut[0].Hypothesis != "the ConfigMap itself is missing" {
		t.Fatalf("RuledOut = %+v, want the one hypothesis this fixture recorded", found.RuledOut)
	}
}
