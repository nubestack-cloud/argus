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
	"argus/internal/llm"
	"argus/internal/remediation"
	"argus/internal/resolution"
)

// blockedInvalidPlanFixture inserts a throwaway cluster, an incident in
// Investigating (so NeedsHumanInvestigation is a legal transition — see
// state.go's allowedTransitions), and the analysis row ApplyAnalysisResult's
// FK requires, and returns a *dbtest.Fixture tracking the deterministic part
// of what it created (clusters/incidents/analyses) WITHOUT calling Cleanup
// itself.
//
// This fixture is shared far more widely than its own file suggests: besides
// this file's own single test, structuredpatch_db_test.go (3 tests, one with
// 3 sub-tests each calling this fixture again for a fresh cluster) and
// timeline_db_test.go (2 tests) all build on it too, and they drive
// ApplyAnalysisResult to wildly different outcomes — a clean Blocked/
// InvalidPlan result writes 0 remediation_recommendations and exactly 1
// timeline_events (AnalysisCompleted) row, but a persisted NeedsApproval plan
// writes 1 remediation_recommendations row AND 2 timeline_events rows
// (AnalysisCompleted + RecommendationReady) — so only each individual test
// knows its own counts, and only it may call fixture.Cleanup (via
// cleanupBlockedInvalidPlanFixture below).
func blockedInvalidPlanFixture(t *testing.T, pool *pgxpool.Pool) (fixture *dbtest.Fixture, tenantID, clusterID, incidentID, analysisID string) {
	t.Helper()
	ctx := context.Background()

	clusterID = domain.NewID(domain.PrefixCluster)
	incidentID = domain.NewID(domain.PrefixIncident)
	analysisID = domain.NewID(domain.PrefixAnalysis)

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

	if _, err := tx.Exec(ctx,
		`INSERT INTO clusters (id, tenant_id, display_name, state, shard_id, cluster_fingerprint)
		 VALUES ($1, $2, $3, 'Active', 'shard-test', $4)`,
		clusterID, tenantID, "blocked-invalid-plan-test-"+clusterID, "fp-"+clusterID); err != nil {
		t.Fatalf("insert cluster: %v", err)
	}
	fixture = dbtest.New(t)
	fixture.OwnsCluster(tenantID, clusterID)
	fixture.Created("clusters", 1)
	now := time.Now()
	if _, err := tx.Exec(ctx,
		`INSERT INTO incidents (id, tenant_id, cluster_id, fingerprint, severity, state, first_seen, last_seen, occurrence_count)
		 VALUES ($1, $2, $3, $4, 'high', 'Investigating', $5, $5, 1)`,
		incidentID, tenantID, clusterID, "test-blocked-invalid-plan-"+incidentID, now); err != nil {
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
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit setup: %v", err)
	}

	return fixture, tenantID, clusterID, incidentID, analysisID
}

// cleanupBlockedInvalidPlanFixture runs fixture.Cleanup with the full delete
// list every test built on blockedInvalidPlanFixture needs — the caller must
// have already tracked its own remediation_recommendations/timeline_events/
// incident_notifications counts (all a direct consequence of what its own
// ApplyAnalysisResult call decided, per this fixture's own doc comment) via
// fixture.Created before calling this.
func cleanupBlockedInvalidPlanFixture(fixture *dbtest.Fixture, pool *pgxpool.Pool, tenantID, clusterID string) {
	fixture.Cleanup(pool, func(ctx context.Context, tx pgx.Tx) error {
		return data.SetRequestScope(ctx, tx, tenantID, []string{clusterID})
	}, []dbtest.TableDelete{
		// timeline_events (BACKLOG.md B1): ApplyAnalysisResult now writes
		// it unconditionally, so any test built on this fixture leaves
		// rows here unless this cleanup deletes them too.
		{Table: "timeline_events", SQL: `DELETE FROM timeline_events WHERE cluster_id = $1`, Args: []any{clusterID}},
		// BACKLOG.md N1: SetState (called by ApplyAnalysisResult, which
		// this fixture exercises) now writes incident_notifications for
		// every AwaitingApproval/Failed/ExecutionUnknown/Reopened
		// transition — no foreign key ties this to clusters (see
		// migration 000083's own comment for why), but it's cleaned up
		// here anyway, matching every other table in this list.
		{Table: "incident_notifications", SQL: `DELETE FROM incident_notifications WHERE cluster_id = $1`, Args: []any{clusterID}},
		{Table: "remediation_recommendations", SQL: `DELETE FROM remediation_recommendations WHERE cluster_id = $1`, Args: []any{clusterID}},
		// BUGS.md 119: same delete-order footgun as clearDemoData — this
		// fixture doesn't insert evidence/analysis_embeddings today, but
		// clearing them before analyses matches every other fixture in
		// this package. Tracked at 0 by every caller (see each test's own
		// fixture.Created calls).
		{Table: "evidence", SQL: `DELETE FROM evidence WHERE analysis_id IN (SELECT id FROM analyses WHERE cluster_id = $1)`, Args: []any{clusterID}},
		{Table: "analysis_embeddings", SQL: `DELETE FROM analysis_embeddings WHERE analysis_id IN (SELECT id FROM analyses WHERE cluster_id = $1)`, Args: []any{clusterID}},
		{Table: "analyses", SQL: `DELETE FROM analyses WHERE cluster_id = $1`, Args: []any{clusterID}},
		{Table: "incidents", SQL: `DELETE FROM incidents WHERE cluster_id = $1`, Args: []any{clusterID}},
		{Table: "clusters", SQL: `DELETE FROM clusters WHERE id = $1`, Args: []any{clusterID}},
	})
}

// TestApplyAnalysisResult_BlockedInvalidPlan_NeverHitsTheConstraint is
// BUGS.md 86's end-to-end reproduction and proof of fix.
//
// remediation.Evaluate correctly classifies a plan with an unrecognized
// RiskLevel/ActionType string as Blocked (Validate()'s job) — but before
// this fix, advanceForPlan's Blocked case still set Advancement.Plan to that
// same structurally-garbage plan, and persistRecommendation
// (internal/orchestrator/db.go) then tried to INSERT plan.RiskLevel/
// plan.ActionType verbatim into columns with a CHECK constraint on the
// closed set — producing a raw Postgres constraint violation (which
// internal/api surfaces as a 500) instead of the clean "Blocked: unrecognized
// X" outcome the gate already computed correctly.
//
// This plan is shaped exactly like what internal/llm/toolloop.go's
// parseProposedPlan hands back for a model that writes `"riskLevel":
// "critical"` — parseProposedPlan deliberately does not validate
// ActionType/RiskLevel itself (see its doc comment), casting the raw string
// straight into the Go enum type, precisely so Evaluate is the single place
// that rejects it.
//
// Against pre-fix code this test fails with:
//
//	ApplyAnalysisResult returned an error instead of a clean Blocked outcome
//	(BUGS.md 86's constraint violation reproducing): orchestrator: persist
//	recommendation for incident inc_...: ERROR: new row for relation
//	"remediation_recommendations" violates check constraint
//	"remediation_recommendations_risk_level_check" (SQLSTATE 23514)
//
// Run against a real (non-superuser) connection per this repo's own
// discipline for this bug class (migrations 000040/000056/000063's
// constraint-widening tests): a mocked/in-memory test would never actually
// exercise the CHECK constraint this bug is about.
func TestApplyAnalysisResult_BlockedInvalidPlan_NeverHitsTheConstraint(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()

	fixture, tenantID, clusterID, incidentID, analysisID := blockedInvalidPlanFixture(t, pool)

	plan := remediation.RemediationPlan{
		ActionType:      remediation.ActionScaleDeployment,
		TargetGVK:       "apps/v1/Deployment",
		TargetNamespace: "argus-test",
		TargetName:      "web",
		Reversible:      true,
		// Not a real RiskLevel — remediation.RiskLevel.Valid() rejects it,
		// and (pre-fix) the CHECK constraint rejects it a second time, but
		// as a raw 500 instead of a clean Blocked decision.
		RiskLevel: remediation.RiskLevel("critical"),
		Params:    remediation.ScaleDeploymentParams{Replicas: 3},
	}
	confidence := 0.9
	result := llm.Investigation{
		Status:       "complete",
		RootCause:    &llm.RootCause{Statement: "test root cause for BUGS.md 86"},
		Confidence:   &confidence,
		ProposedPlan: &plan,
	}
	routeDecision := RouteDecision{Route: resolution.RouteInPlace, Apply: true}

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if err := data.SetRequestScope(ctx, tx, tenantID, []string{clusterID}); err != nil {
		t.Fatalf("scope: %v", err)
	}

	adv, err := ApplyAnalysisResult(ctx, tx, tenantID, clusterID, incidentID, analysisID, result, routeDecision)
	if err != nil {
		t.Fatalf("ApplyAnalysisResult returned an error instead of a clean Blocked outcome "+
			"(BUGS.md 86's constraint violation reproducing): %v", err)
	}

	if adv.NextState != StateNeedsHumanInvestigation {
		t.Fatalf("NextState = %v, want %v", adv.NextState, StateNeedsHumanInvestigation)
	}
	if adv.Decision == nil || adv.Decision.Outcome != remediation.Blocked {
		t.Fatalf("Decision = %+v, want Outcome Blocked", adv.Decision)
	}
	if !strings.Contains(adv.Reason, "unrecognized risk level") {
		t.Fatalf("Reason = %q, want it to name the unrecognized risk level plainly (the clean rejection BUGS.md 86 asked for)", adv.Reason)
	}
	if adv.Plan != nil {
		t.Fatalf("Plan = %+v, want nil — a structurally invalid plan's raw enum values must never be handed to persistRecommendation, "+
			"let alone actually written", adv.Plan)
	}

	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit: %v", err)
	}

	// A clean Blocked outcome: adv.Plan == nil, so persistRecommendation is
	// never reached (0 remediation_recommendations rows). ApplyAnalysisResult
	// still writes exactly 1 timeline_events row (AnalysisCompleted) per
	// BACKLOG.md B1's unconditional-write rule. The transition this test
	// drives (Investigating -> NeedsHumanInvestigation) is not one of
	// BACKLOG.md N1's notified transitions, so incident_notifications stays 0.
	fixture.Created("remediation_recommendations", 0)
	fixture.Created("timeline_events", 1)
	fixture.Created("incident_notifications", 0)
	fixture.Created("evidence", 0)
	fixture.Created("analysis_embeddings", 0)
	cleanupBlockedInvalidPlanFixture(fixture, pool, tenantID, clusterID)
}
