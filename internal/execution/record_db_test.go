package execution

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"argus/internal/data"
	"argus/internal/orchestrator"
)

// TestRecordExecutingTransitionWritesApprovalAndExecutionStartedEvents is
// BACKLOG.md B1's acceptance test for the approval-decision and
// execution-start transitions on the in-place route.
func TestRecordExecutingTransitionWritesApprovalAndExecutionStartedEvents(t *testing.T) {
	pool := authTestPool(t)
	tenantID, clusterID, incidentID, planID, fixture := timelineExecTrackedFixture(t, pool)

	s := &Executor{db: &data.DB{Pool: pool}}
	rc := Scope{TenantID: tenantID}
	actor := Actor{UserID: "usr_test", AuthMethod: "jwt"}

	if err := s.recordExecutingTransition(context.Background(), rc, incidentID, planID, clusterID, actor,
		false, false, "", nil, dryRunAttestation{At: time.Now()}, nil, executionAttempt{}); err != nil {
		t.Fatalf("recordExecutingTransition: %v", err)
	}

	// PROJECT.md L8: the in-place route's approval pins the analysis it was a
	// judgement of, exactly as the human reject path does. Asserted here
	// specifically because this is the writer the UNATTENDED executor reaches:
	// an automatic approval's only rationale is the gate's own words, which are
	// a verdict on an analysis's confidence and proposed action, and are
	// unreadable later without knowing which prompt version and model produced
	// them. Compared against the recommendation's own analysis rather than a
	// literal id — that is the claim, not "some analysis was recorded".
	assertDecisionPinsThePlansAnalysis(t, pool, tenantID, clusterID, planID)

	// recordExecutingTransition(executionAttempt{}) writes 1
	// remediation_approval_decisions row (unconditional) and 2 timeline_events
	// rows (ApprovalGranted, ExecutionStarted) — no remediation_executions,
	// and no remediation_execution_attempts since attempt.ID == "" (see that
	// function's own doc comment).
	fixture.Created("remediation_approval_decisions", 1)
	fixture.Created("remediation_execution_attempts", 0)
	fixture.Created("remediation_executions", 0)
	fixture.Created("timeline_events", 2)
	fixture.Created("evidence", 0)
	fixture.Created("analysis_embeddings", 0)
	fixture.Created("incident_notifications", 0)
	fixture.Cleanup(pool, timelineExecSetScope(tenantID, clusterID), timelineExecDeletes(clusterID))

	got := timelineEventTypesFor(t, pool, tenantID, clusterID, incidentID)
	want := []string{"ApprovalGranted", "ExecutionStarted"}
	if len(got) != len(want) {
		t.Fatalf("timeline event types = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("event[%d] = %q, want %q (order matters: approval precedes execution starting)", i, got[i], want[i])
		}
	}
}

// TestRecordExecutionOutcomeWritesExecutionOutcomeEvent covers the execution
// resolving (succeeded or not) — the last of the pair
// recordExecutingTransition/recordExecutionOutcome together implement.
func TestRecordExecutionOutcomeWritesExecutionOutcomeEvent(t *testing.T) {
	pool := authTestPool(t)
	tenantID, clusterID, incidentID, planID, fixture := timelineExecTrackedFixture(t, pool)

	s := &Executor{db: &data.DB{Pool: pool}}
	rc := Scope{TenantID: tenantID}
	actor := Actor{UserID: "usr_test", AuthMethod: "jwt"}

	// recordExecutionOutcome assumes the incident is already Executing (the
	// state recordExecutingTransition leaves it in) — set that up directly
	// rather than depending on the other test's ordering.
	if err := s.recordExecutingTransition(context.Background(), rc, incidentID, planID, clusterID, actor,
		false, false, "", nil, dryRunAttestation{At: time.Now()}, nil, executionAttempt{}); err != nil {
		t.Fatalf("recordExecutingTransition (setup): %v", err)
	}

	finalState, err := s.recordExecutionOutcome(context.Background(), rc, incidentID, planID, clusterID, actor,
		"succeeded", "", "rv-123", nil, "", forwardOutcomeStates(), "", "ScaleDeployment", "forward")
	if err != nil {
		t.Fatalf("recordExecutionOutcome: %v", err)
	}
	if finalState != orchestrator.StateValidating {
		t.Fatalf("finalState = %q, want %q", finalState, orchestrator.StateValidating)
	}

	// recordExecutingTransition (1 remediation_approval_decisions, 2
	// timeline_events: ApprovalGranted/ExecutionStarted) followed by
	// recordExecutionOutcome (1 remediation_executions, 1 more timeline_events:
	// ExecutionOutcome) — no remediation_execution_attempts rows either call,
	// since attempt.ID == "" throughout.
	fixture.Created("remediation_approval_decisions", 1)
	fixture.Created("remediation_execution_attempts", 0)
	fixture.Created("remediation_executions", 1)
	fixture.Created("timeline_events", 3)
	fixture.Created("evidence", 0)
	fixture.Created("analysis_embeddings", 0)
	fixture.Created("incident_notifications", 0)
	fixture.Cleanup(pool, timelineExecSetScope(tenantID, clusterID), timelineExecDeletes(clusterID))

	got := timelineEventTypesFor(t, pool, tenantID, clusterID, incidentID)
	want := []string{"ApprovalGranted", "ExecutionStarted", "ExecutionOutcome"}
	if len(got) != len(want) {
		t.Fatalf("timeline event types = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("event[%d] = %q, want %q", i, got[i], want[i])
		}
	}

	// The outcome event's own payload carries the real outcome/nextState —
	// re-read it directly rather than trusting the type list alone.
	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if err := data.SetRequestScope(ctx, tx, tenantID, []string{clusterID}); err != nil {
		t.Fatalf("scope: %v", err)
	}
	var payload []byte
	if err := tx.QueryRow(ctx, `SELECT payload FROM timeline_events WHERE incident_id = $1 AND event_type = 'ExecutionOutcome'`, incidentID).Scan(&payload); err != nil {
		t.Fatalf("read ExecutionOutcome payload: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(payload, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got, _ := decoded["outcome"].(string); got != "succeeded" {
		t.Errorf("payload[\"outcome\"] = %q, want %q", got, "succeeded")
	}
	if got, _ := decoded["nextState"].(string); got != orchestrator.StateValidating {
		t.Errorf("payload[\"nextState\"] = %q, want %q", got, orchestrator.StateValidating)
	}
}

// TestRecordExecutionOutcomeUnknownLandsOnExecutionUnknown is BACKLOG.md C8's
// DB-level acceptance test (BUGS.md 104): recordExecutionOutcome must accept
// outcome = "unknown" (the widened CHECK constraint, migration 000081) and
// land the incident on orchestrator.StateExecutionUnknown — never
// StateFailed, which would repeat the exact false-negative this fix exists
// to stop recording.
func TestRecordExecutionOutcomeUnknownLandsOnExecutionUnknown(t *testing.T) {
	pool := authTestPool(t)
	tenantID, clusterID, incidentID, planID, fixture := timelineExecTrackedFixture(t, pool)

	s := &Executor{db: &data.DB{Pool: pool}}
	rc := Scope{TenantID: tenantID}
	actor := Actor{UserID: "usr_test", AuthMethod: "jwt"}

	if err := s.recordExecutingTransition(context.Background(), rc, incidentID, planID, clusterID, actor,
		false, false, "", nil, dryRunAttestation{At: time.Now()}, nil, executionAttempt{}); err != nil {
		t.Fatalf("recordExecutingTransition (setup): %v", err)
	}

	const indeterminateErr = "gateway: cluster cl_1 disconnected while awaiting a tool result: tool result indeterminate; a follow-up read could not confirm whether the change applied"
	finalState, err := s.recordExecutionOutcome(context.Background(), rc, incidentID, planID, clusterID, actor,
		"unknown", indeterminateErr, "rv-123", nil, "", forwardOutcomeStates(), "", "ScaleDeployment", "forward")
	if err != nil {
		t.Fatalf("recordExecutionOutcome: %v", err)
	}
	if finalState != orchestrator.StateExecutionUnknown {
		t.Fatalf("finalState = %q, want %q", finalState, orchestrator.StateExecutionUnknown)
	}

	// Same shape as TestRecordExecutionOutcomeWritesExecutionOutcomeEvent: one
	// recordExecutingTransition + one recordExecutionOutcome call, regardless
	// of the outcome value.
	fixture.Created("remediation_approval_decisions", 1)
	fixture.Created("remediation_execution_attempts", 0)
	fixture.Created("remediation_executions", 1)
	fixture.Created("timeline_events", 3)
	fixture.Created("evidence", 0)
	fixture.Created("analysis_embeddings", 0)
	// ExecutionUnknown is one of orchestrator's notifiableStates, so this
	// close queues exactly one notification — the only caller in this file
	// that does (PROJECT.md B175).
	fixture.Created("incident_notifications", 1)
	fixture.Cleanup(pool, timelineExecSetScope(tenantID, clusterID), timelineExecDeletes(clusterID))

	// Re-read the incident's own persisted state directly, not just the
	// returned value — proving the CHECK constraint (migration 000081)
	// actually accepted the write rather than the whole transaction having
	// silently rolled back on some other error path.
	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if err := data.SetRequestScope(ctx, tx, tenantID, []string{clusterID}); err != nil {
		t.Fatalf("scope: %v", err)
	}
	var persistedState, persistedOutcome string
	if err := tx.QueryRow(ctx, `SELECT state FROM incidents WHERE id = $1`, incidentID).Scan(&persistedState); err != nil {
		t.Fatalf("read incident state: %v", err)
	}
	if persistedState != orchestrator.StateExecutionUnknown {
		t.Errorf("persisted incidents.state = %q, want %q", persistedState, orchestrator.StateExecutionUnknown)
	}
	if err := tx.QueryRow(ctx, `SELECT outcome FROM remediation_executions WHERE incident_id = $1`, incidentID).Scan(&persistedOutcome); err != nil {
		t.Fatalf("read remediation_executions.outcome: %v", err)
	}
	if persistedOutcome != "unknown" {
		t.Errorf("persisted remediation_executions.outcome = %q, want %q", persistedOutcome, "unknown")
	}

	got := timelineEventTypesFor(t, pool, tenantID, clusterID, incidentID)
	want := []string{"ApprovalGranted", "ExecutionStarted", "ExecutionOutcome"}
	if len(got) != len(want) {
		t.Fatalf("timeline event types = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("event[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

// assertDecisionPinsThePlansAnalysis checks the one thing migration 000116
// exists for: the decision row records WHICH analysis the verdict was passed
// on, and it is the analysis the decided plan was derived from — not the
// incident's newest, which a re-analysis can change underneath a pending
// approval.
func assertDecisionPinsThePlansAnalysis(t *testing.T, pool *pgxpool.Pool, tenantID, clusterID, planID string) {
	t.Helper()
	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin read tx: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if err := data.SetRequestScope(ctx, tx, tenantID, []string{clusterID}); err != nil {
		t.Fatalf("scope: %v", err)
	}
	var pinned, fromRecommendation *string
	if err := tx.QueryRow(ctx,
		`SELECT d.analysis_id, r.analysis_id
		   FROM remediation_approval_decisions d
		   JOIN remediation_recommendations r ON r.id = d.recommendation_id
		  WHERE d.recommendation_id = $1`, planID).Scan(&pinned, &fromRecommendation); err != nil {
		t.Fatalf("read the decision's analysis pin: %v", err)
	}
	if pinned == nil {
		t.Fatal("remediation_approval_decisions.analysis_id is NULL — the approval records no analysis, which is the gap PROJECT.md L8 exists to close")
	}
	if fromRecommendation == nil || *pinned != *fromRecommendation {
		t.Errorf("decision pinned analysis %v; want the plan's own analysis %v", *pinned, fromRecommendation)
	}
}
