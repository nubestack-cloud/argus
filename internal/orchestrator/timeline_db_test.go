package orchestrator

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"argus/internal/data"
	"argus/internal/llm"
	"argus/internal/remediation"
	"argus/internal/resolution"
)

// timelineRow is one timeline_events row, read back for assertions.
type timelineRow struct {
	eventType  string
	payload    map[string]any
	occurredAt time.Time
}

// readTimelineEvents returns every timeline_events row for incidentID, oldest
// first — the same ordering the real GET /incidents/{id}/timeline endpoint
// uses (internal/api/timeline.go's listTimelineEvents).
func readTimelineEvents(t *testing.T, tx pgx.Tx, incidentID string) []timelineRow {
	t.Helper()
	ctx := context.Background()
	rows, err := tx.Query(ctx,
		`SELECT event_type, payload, occurred_at FROM timeline_events WHERE incident_id = $1 ORDER BY occurred_at ASC, id ASC`,
		incidentID)
	if err != nil {
		t.Fatalf("query timeline_events: %v", err)
	}
	defer rows.Close()

	var out []timelineRow
	for rows.Next() {
		var eventType string
		var payload []byte
		var occurredAt time.Time
		if err := rows.Scan(&eventType, &payload, &occurredAt); err != nil {
			t.Fatalf("scan timeline_events row: %v", err)
		}
		var decoded map[string]any
		if err := json.Unmarshal(payload, &decoded); err != nil {
			t.Fatalf("unmarshal timeline_events payload: %v", err)
		}
		out = append(out, timelineRow{eventType: eventType, payload: decoded, occurredAt: occurredAt})
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate timeline_events rows: %v", err)
	}
	return out
}

// TestMarkInvestigatingWritesInvestigationStartedEvent is BACKLOG.md B1's
// acceptance test for the detection->investigation transition: before this
// task, timeline_events was a dead table (BACKLOG.md V2) and MarkInvestigating
// wrote nothing to it at all.
func TestMarkInvestigatingWritesInvestigationStartedEvent(t *testing.T) {
	pool := testPool(t)
	tenantID, clusterID, incidentID, _ := testIncident(t, pool, StateDetected)
	ctx := context.Background()

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if err := data.SetRequestScope(ctx, tx, tenantID, []string{clusterID}); err != nil {
		t.Fatalf("scope: %v", err)
	}

	if err := MarkInvestigating(ctx, tx, tenantID, clusterID, incidentID); err != nil {
		t.Fatalf("MarkInvestigating: %v", err)
	}

	events := readTimelineEvents(t, tx, incidentID)
	if len(events) != 1 {
		t.Fatalf("timeline_events for incident %s = %d rows, want exactly 1: %+v", incidentID, len(events), events)
	}
	if events[0].eventType != "InvestigationStarted" {
		t.Errorf("event_type = %q, want %q", events[0].eventType, "InvestigationStarted")
	}
	if _, ok := events[0].payload["summary"]; !ok {
		t.Errorf("payload has no \"summary\" key: %+v", events[0].payload)
	}

	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit: %v", err)
	}
}

// TestMarkInvestigatingRefusalWritesNoTimelineEvent proves the write is
// genuinely transitional, not unconditional: a refused transition (this
// codebase's own ErrIllegalTransition path, e.g. re-analysing a Dismissed
// incident) must leave no InvestigationStarted row behind, matching
// SetState's own "a refused transition must not partially apply" guarantee.
func TestMarkInvestigatingRefusalWritesNoTimelineEvent(t *testing.T) {
	pool := testPool(t)
	tenantID, clusterID, incidentID, _ := testIncident(t, pool, StateDismissed)
	ctx := context.Background()

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if err := data.SetRequestScope(ctx, tx, tenantID, []string{clusterID}); err != nil {
		t.Fatalf("scope: %v", err)
	}

	if err := MarkInvestigating(ctx, tx, tenantID, clusterID, incidentID); err == nil {
		t.Fatal("MarkInvestigating on a Dismissed incident succeeded; want ErrIllegalTransition")
	}

	if events := readTimelineEvents(t, tx, incidentID); len(events) != 0 {
		t.Errorf("timeline_events for a refused transition = %+v, want none", events)
	}
}

// TestApplyAnalysisResultWritesAnalysisAndRecommendationEvents covers the
// investigation-finishing and recommendation-produced transitions together,
// since orchestrator.ApplyAnalysisResult is the one function that can write
// both in a single call.
func TestApplyAnalysisResultWritesAnalysisAndRecommendationEvents(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	fixture, tenantID, clusterID, incidentID, analysisID := blockedInvalidPlanFixture(t, pool)

	plan := remediation.RemediationPlan{
		ActionType:      remediation.ActionScaleDeployment,
		TargetGVK:       "apps/v1/Deployment",
		TargetNamespace: "argus-test",
		TargetName:      "web",
		Reversible:      true,
		RiskLevel:       remediation.RiskLow,
		Params:          remediation.ScaleDeploymentParams{Replicas: 3},
	}
	confidence := 0.87
	result := llm.Investigation{
		Status:       "complete",
		RootCause:    &llm.RootCause{Statement: "test root cause for BACKLOG B1"},
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
		t.Fatalf("ApplyAnalysisResult: %v", err)
	}
	if adv.Plan == nil {
		t.Fatalf("adv.Plan = nil, want a real plan (test setup produced an AutoApprove/NeedsApproval-eligible plan) — got Reason=%q", adv.Reason)
	}

	events := readTimelineEvents(t, tx, incidentID)
	var sawAnalysisCompleted, sawRecommendationReady bool
	for _, e := range events {
		switch e.eventType {
		case "AnalysisCompleted":
			sawAnalysisCompleted = true
			if got, _ := e.payload["rootCause"].(string); got != "test root cause for BACKLOG B1" {
				t.Errorf("AnalysisCompleted payload[\"rootCause\"] = %q, want the investigation's root cause statement", got)
			}
		case "RecommendationReady":
			sawRecommendationReady = true
			if got, _ := e.payload["actionType"].(string); got != string(remediation.ActionScaleDeployment) {
				t.Errorf("RecommendationReady payload[\"actionType\"] = %q, want %q", got, remediation.ActionScaleDeployment)
			}
			if _, ok := e.payload["planId"]; !ok {
				t.Errorf("RecommendationReady payload has no planId: %+v", e.payload)
			}
		}
	}
	if !sawAnalysisCompleted {
		t.Errorf("no AnalysisCompleted event among %+v", events)
	}
	if !sawRecommendationReady {
		t.Errorf("no RecommendationReady event among %+v", events)
	}
	// AnalysisCompleted must precede RecommendationReady — the investigation
	// finishing is the cause, the recommendation is its consequence, and a
	// client rendering "durations from adjacent timestamps"
	// (lld/11-ui-design.md §4) depends on this order being real, not
	// coincidental.
	if len(events) >= 2 && events[0].eventType != "AnalysisCompleted" {
		t.Errorf("events[0].eventType = %q, want AnalysisCompleted to be recorded before RecommendationReady: %+v", events[0].eventType, events)
	}

	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit: %v", err)
	}

	// A persisted plan (adv.Plan != nil, asserted above): 1
	// remediation_recommendations row and 2 timeline_events rows
	// (AnalysisCompleted + RecommendationReady, both confirmed present
	// above). orchestrator.Advance never returns Executing — a persisted
	// plan's NextState is AwaitingApproval whatever the gate decision, which
	// is one of BACKLOG.md N1's notified transitions, so 1
	// incident_notifications row too.
	fixture.Created("remediation_recommendations", 1)
	fixture.Created("timeline_events", 2)
	fixture.Created("incident_notifications", 1)
	fixture.Created("evidence", 0)
	fixture.Created("analysis_embeddings", 0)
	cleanupBlockedInvalidPlanFixture(fixture, pool, tenantID, clusterID)
}

// TestApplyAnalysisResultWithNoPlanWritesOnlyAnalysisCompleted covers the
// other half of "the recommendation being produced is a separate,
// CONDITIONAL event" — a partial investigation with no plan at all must
// write AnalysisCompleted and nothing claiming a recommendation exists.
func TestApplyAnalysisResultWithNoPlanWritesOnlyAnalysisCompleted(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	fixture, tenantID, clusterID, incidentID, analysisID := blockedInvalidPlanFixture(t, pool)

	result := llm.Investigation{
		Status:        "partial",
		PartialReason: "iteration_limit",
	}
	routeDecision := RouteDecision{Apply: false}

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
		t.Fatalf("ApplyAnalysisResult: %v", err)
	}
	if adv.Plan != nil {
		t.Fatalf("adv.Plan = %+v, want nil for a partial investigation", adv.Plan)
	}

	events := readTimelineEvents(t, tx, incidentID)
	if len(events) != 1 {
		t.Fatalf("timeline_events = %+v, want exactly one AnalysisCompleted row and no RecommendationReady", events)
	}
	if events[0].eventType != "AnalysisCompleted" {
		t.Errorf("event_type = %q, want %q", events[0].eventType, "AnalysisCompleted")
	}
	if got, _ := events[0].payload["partialReason"].(string); got != "iteration_limit" {
		t.Errorf("payload[\"partialReason\"] = %q, want %q", got, "iteration_limit")
	}

	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit: %v", err)
	}

	// adv.Plan == nil (asserted above): 0 remediation_recommendations. Exactly
	// 1 timeline_events row (AnalysisCompleted only, confirmed above).
	fixture.Created("remediation_recommendations", 0)
	fixture.Created("timeline_events", 1)
	fixture.Created("incident_notifications", 0)
	fixture.Created("evidence", 0)
	fixture.Created("analysis_embeddings", 0)
	cleanupBlockedInvalidPlanFixture(fixture, pool, tenantID, clusterID)
}
