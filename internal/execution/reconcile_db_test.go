package execution

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"argus/internal/data"
	"argus/internal/domain"
	"argus/internal/events"
	"argus/internal/gateway"
	"argus/internal/orchestrator"
	"argus/internal/remediation"
)

// incidentStateNow reads one incident's persisted state, scoped like every
// other read in this package's DB tests.
func incidentStateNow(t *testing.T, pool *pgxpool.Pool, tenantID, clusterID, incidentID string) string {
	t.Helper()
	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if err := data.SetRequestScope(ctx, tx, tenantID, []string{clusterID}); err != nil {
		t.Fatalf("scope: %v", err)
	}
	var state string
	if err := tx.QueryRow(ctx, `SELECT state FROM incidents WHERE id = $1`, incidentID).Scan(&state); err != nil {
		t.Fatalf("read incident state: %v", err)
	}
	return state
}

// executionRowsFor returns (id, outcome) for every execution recorded against
// one incident, oldest first.
func executionRowsFor(t *testing.T, pool *pgxpool.Pool, tenantID, clusterID, incidentID string) [][2]string {
	t.Helper()
	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if err := data.SetRequestScope(ctx, tx, tenantID, []string{clusterID}); err != nil {
		t.Fatalf("scope: %v", err)
	}
	rows, err := tx.Query(ctx,
		`SELECT id, outcome FROM remediation_executions WHERE incident_id = $1 ORDER BY executed_at ASC`, incidentID)
	if err != nil {
		t.Fatalf("read executions: %v", err)
	}
	defer rows.Close()
	var out [][2]string
	for rows.Next() {
		var id, outcome string
		if err := rows.Scan(&id, &outcome); err != nil {
			t.Fatalf("scan execution: %v", err)
		}
		out = append(out, [2]string{id, outcome})
	}
	return out
}

// setIncidentState walks an incident to a state through the real state machine,
// so a fixture can never set up a transition the product itself forbids.
func setIncidentState(t *testing.T, pool *pgxpool.Pool, tenantID, clusterID, incidentID string, states ...string) {
	t.Helper()
	ctx := context.Background()
	for _, state := range states {
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatalf("begin: %v", err)
		}
		if err := data.SetRequestScope(ctx, tx, tenantID, []string{clusterID}); err != nil {
			tx.Rollback(ctx) //nolint:errcheck
			t.Fatalf("scope: %v", err)
		}
		if err := orchestrator.SetState(ctx, tx, incidentID, state); err != nil {
			tx.Rollback(ctx) //nolint:errcheck
			t.Fatalf("SetState(%s): %v", state, err)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatalf("commit SetState(%s): %v", state, err)
		}
	}
}

// REPRODUCTION, finding 1a. An undo applied to an incident that has already
// closed changes the cluster and then loses its own record: the compensating
// action lands, recordExecutionOutcome computes Reopened, SetState refuses it
// (Resolved is terminal), and the whole transaction — including the
// remediation_executions row that is the only durable evidence the cluster was
// touched — rolls back.
//
// The assertion is deliberately about the ROW, not about the state: what an
// incident is called afterwards is bookkeeping, and the fact that a production
// cluster was mutated is not.
func TestUndoRecordSurvivesATerminalIncident(t *testing.T) {
	pool := authTestPool(t)
	tenantID, clusterID, incidentID, planID := timelineExecFixture(t, pool)

	s := &Executor{db: &data.DB{Pool: pool}}
	rc := Scope{TenantID: tenantID}
	actor := Actor{UserID: "usr_test", AuthMethod: "jwt"}

	// A real closed incident, reached through the real edges: a fix executed,
	// validated, and resolved.
	setIncidentState(t, pool, tenantID, clusterID, incidentID, orchestrator.StateResolved)

	finalState, err := s.recordExecutionOutcome(context.Background(), rc, incidentID, planID, clusterID, actor,
		"succeeded", "", "rv-undo", nil, "", undoOutcomeStates(orchestrator.StateResolved), "", "ScaleDeployment", "undo")
	if err != nil {
		t.Fatalf("recordExecutionOutcome for an undo on a Resolved incident: %v\n"+
			"The cluster has already been changed at this point. Refusing to record that is the worst possible answer.", err)
	}

	rows := executionRowsFor(t, pool, tenantID, clusterID, incidentID)
	if len(rows) != 1 {
		t.Fatalf("remediation_executions rows = %d, want 1 — the undo mutated the cluster and left no record of it", len(rows))
	}
	if rows[0][1] != "succeeded" {
		t.Errorf("recorded outcome = %q, want %q", rows[0][1], "succeeded")
	}
	if got := incidentStateNow(t, pool, tenantID, clusterID, incidentID); got != orchestrator.StateResolved {
		t.Errorf("incident state = %q, want %q — a closed incident stays closed; the undo is a fact about the cluster, not a reopening", got, orchestrator.StateResolved)
	}
	if finalState != orchestrator.StateResolved {
		t.Errorf("returned state = %q, want %q (the state the incident is actually in)", finalState, orchestrator.StateResolved)
	}
}

// REPRODUCTION, finding 1b. An undo that FAILS from Validating needs
// Validating -> Failed, an edge that does not exist. Same outcome as 1a: the
// undo attempt is lost, this time including the error explaining what went
// wrong with it.
//
// The right destination here is no transition at all. A failed undo did not
// fail the remediation — the remediation is still applied and still being
// validated — so asserting Failed would be a second untruth on top of the
// lost record.
func TestFailedUndoRecordSurvivesAValidatingIncident(t *testing.T) {
	pool := authTestPool(t)
	tenantID, clusterID, incidentID, planID := timelineExecFixture(t, pool)

	s := &Executor{db: &data.DB{Pool: pool}}
	rc := Scope{TenantID: tenantID}
	actor := Actor{UserID: "usr_test", AuthMethod: "jwt"}

	// The state a successful forward execution actually leaves behind.
	if err := s.recordExecutingTransition(context.Background(), rc, incidentID, planID, clusterID, actor,
		false, false, "", nil, dryRunAttestation{At: time.Now()}, nil, executionAttempt{}); err != nil {
		t.Fatalf("recordExecutingTransition (setup): %v", err)
	}
	if _, err := s.recordExecutionOutcome(context.Background(), rc, incidentID, planID, clusterID, actor,
		"succeeded", "", "rv-forward", nil, "3", forwardOutcomeStates(), "", "ScaleDeployment", "forward"); err != nil {
		t.Fatalf("recordExecutionOutcome (setup): %v", err)
	}

	if _, err := s.recordExecutionOutcome(context.Background(), rc, incidentID, planID, clusterID, actor,
		"failed", "the agent rejected the undo", "rv-undo", nil, "", undoOutcomeStates(orchestrator.StateValidating), "", "ScaleDeployment", "undo"); err != nil {
		t.Fatalf("recordExecutionOutcome for a failed undo from Validating: %v\n"+
			"An undo that failed is exactly the thing an operator most needs written down.", err)
	}

	rows := executionRowsFor(t, pool, tenantID, clusterID, incidentID)
	if len(rows) != 2 {
		t.Fatalf("remediation_executions rows = %d, want 2 (the forward execution and the failed undo) — the failed undo left no record", len(rows))
	}
	if rows[1][1] != "failed" {
		t.Errorf("second recorded outcome = %q, want %q", rows[1][1], "failed")
	}
	if got := incidentStateNow(t, pool, tenantID, clusterID, incidentID); got != orchestrator.StateValidating {
		t.Errorf("incident state = %q, want %q — the forward fix is still applied and still being validated", got, orchestrator.StateValidating)
	}
}

// REPRODUCTION, finding 2. handleApproveIncident runs the tunnel call and the
// outcome write on r.Context(). net/http cancels that the instant the client's
// connection closes, and an already-cancelled context makes every pgx
// operation fail immediately — so nothing writes the outcome, and the incident
// is left in Executing, which nothing in the product reconciles.
//
// This test asserts the FAULT (it passes today), and is kept as the
// description of what the recovery path exists for. The recovery itself is
// asserted separately.
func TestCancelledRequestContextStrandsTheIncidentInExecuting(t *testing.T) {
	pool := authTestPool(t)
	tenantID, clusterID, incidentID, planID := timelineExecFixture(t, pool)

	s := &Executor{db: &data.DB{Pool: pool}}
	rc := Scope{TenantID: tenantID}
	actor := Actor{UserID: "usr_test", AuthMethod: "jwt"}

	if err := s.recordExecutingTransition(context.Background(), rc, incidentID, planID, clusterID, actor,
		false, false, "", nil, dryRunAttestation{At: time.Now()}, nil, executionAttempt{}); err != nil {
		t.Fatalf("recordExecutingTransition: %v", err)
	}

	cancelled, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := s.recordExecutionOutcome(cancelled, rc, incidentID, planID, clusterID, actor,
		"succeeded", "", "rv-1", nil, "", forwardOutcomeStates(), "", "ScaleDeployment", "forward"); err == nil {
		t.Fatal("recordExecutionOutcome succeeded on a cancelled context; this reproduction is no longer valid")
	}

	if rows := executionRowsFor(t, pool, tenantID, clusterID, incidentID); len(rows) != 0 {
		t.Fatalf("remediation_executions rows = %d, want 0 — the reproduction assumes nothing was written", len(rows))
	}
	if got := incidentStateNow(t, pool, tenantID, clusterID, incidentID); got != orchestrator.StateExecuting {
		t.Fatalf("incident state = %q, want %q — the reproduction assumes the incident is stranded", got, orchestrator.StateExecuting)
	}
}

// reconcileTestServer is a Server with just enough wired for the reconciler:
// a pool and a real (unconnected) Gateway, since resolveAbandonedOutcome asks
// whether the cluster is reachable before it tries to verify anything.
// Unconnected is the honest fixture for a hub that has just restarted.
func reconcileTestServer(t *testing.T, pool *pgxpool.Pool) *Executor {
	t.Helper()
	ca, err := gateway.NewEphemeralDevCA()
	if err != nil {
		t.Fatalf("new dev CA: %v", err)
	}
	return &Executor{db: &data.DB{Pool: pool}, gw: gateway.NewGateway(nil, ca, events.NewBus())}
}

// openAttempt is the attempt row a dispatching request commits before its
// tunnel call, with an expiry the caller chooses so a test can be explicit
// about whether the dispatcher could still be alive.
func openAttempt(tenantID, clusterID, incidentID, planID string, expiresAt time.Time) executionAttempt {
	return executionAttempt{
		ID: domain.NewID(domain.PrefixExecutionAttempt), TenantID: tenantID, ClusterID: clusterID,
		IncidentID: incidentID, PlanID: planID,
		Kind: executionAttemptForward, ActionType: string(remediation.ActionScaleDeployment),
		TargetGVK: "apps/v1/Deployment", TargetNamespace: "default", TargetName: "web",
		ForwardApplied: "3", ResourceVersion: "rv-1",
		Actor:        Actor{UserID: "usr_test", AuthMethod: "jwt"},
		SuccessState: orchestrator.StateValidating, ExpiresAt: expiresAt,
	}
}

func attemptSettlement(t *testing.T, pool *pgxpool.Pool, tenantID, attemptID string) (settled bool, executionID string) {
	t.Helper()
	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if err := data.SetRequestScope(ctx, tx, tenantID, nil); err != nil {
		t.Fatalf("scope: %v", err)
	}
	var settledAt *time.Time
	var execID *string
	if err := tx.QueryRow(ctx,
		`SELECT settled_at, execution_id FROM remediation_execution_attempts WHERE id = $1`, attemptID).
		Scan(&settledAt, &execID); err != nil {
		t.Fatalf("read attempt %s: %v", attemptID, err)
	}
	return settledAt != nil, deref(execID)
}

// reconcileUntilSettled runs sweeps until this incident has left Executing, or
// gives up. One sweep is bounded (maxReconcilePerSweep) and this is a shared
// development database that other work also writes to, so a single pass is not
// guaranteed to reach any particular incident — successive ticks are how the
// real reconciler works through a backlog, and this asserts the same thing
// without depending on the rest of the database being empty.
func reconcileUntilSettled(t *testing.T, s *Executor, pool *pgxpool.Pool, tenantID, clusterID, incidentID string) string {
	t.Helper()
	ctx := context.Background()
	var state string
	for i := 0; i < 5; i++ {
		if err := s.reconcileExecutions(ctx); err != nil {
			t.Fatalf("reconcileExecutions: %v", err)
		}
		if state = incidentStateNow(t, pool, tenantID, clusterID, incidentID); state != orchestrator.StateExecuting {
			return state
		}
	}
	return state
}

// THE FIX for finding 2. An execution whose dispatcher never came back is
// picked up and settled — as ExecutionUnknown, because a hub that died proves
// nothing about whether the patch reached the API server, and this cluster is
// not connected for a follow-up read either.
func TestExecutionReconcilerSettlesAnAbandonedAttempt(t *testing.T) {
	pool := authTestPool(t)
	tenantID, clusterID, incidentID, planID := timelineExecFixture(t, pool)

	s := reconcileTestServer(t, pool)
	rc := Scope{TenantID: tenantID}
	actor := Actor{UserID: "usr_test", AuthMethod: "jwt"}
	ctx := context.Background()

	// Everything the dispatching request commits before its tunnel call — and
	// then nothing, exactly as if the process had been killed there.
	attempt := openAttempt(tenantID, clusterID, incidentID, planID, time.Now().Add(-time.Minute))
	if err := s.recordExecutingTransition(ctx, rc, incidentID, planID, clusterID, actor,
		false, false, "", nil, dryRunAttestation{At: time.Now()}, nil, attempt); err != nil {
		t.Fatalf("recordExecutingTransition: %v", err)
	}
	if got := incidentStateNow(t, pool, tenantID, clusterID, incidentID); got != orchestrator.StateExecuting {
		t.Fatalf("setup: incident state = %q, want %q", got, orchestrator.StateExecuting)
	}

	if got := reconcileUntilSettled(t, s, pool, tenantID, clusterID, incidentID); got != orchestrator.StateExecutionUnknown {
		t.Errorf("incident state = %q, want %q — an abandoned execution must not be left in Executing, and must not be called Failed either", got, orchestrator.StateExecutionUnknown)
	}
	rows := executionRowsFor(t, pool, tenantID, clusterID, incidentID)
	if len(rows) != 1 {
		t.Fatalf("remediation_executions rows = %d, want 1", len(rows))
	}
	if rows[0][1] != "unknown" {
		t.Errorf("recorded outcome = %q, want %q — a hub that died proves nothing about whether the patch landed", rows[0][1], "unknown")
	}
	settled, execID := attemptSettlement(t, pool, tenantID, attempt.ID)
	if !settled {
		t.Error("the attempt is still open after being reconciled; it would be settled again on every tick")
	}
	if execID != rows[0][0] {
		t.Errorf("attempt.execution_id = %q, want the execution it settled to (%q)", execID, rows[0][0])
	}
}

// The reconciler must never conclude anything about an execution that could
// still be in flight. This is the property the whole expires_at design exists
// to provide, so it gets its own test.
func TestExecutionReconcilerLeavesALiveAttemptAlone(t *testing.T) {
	pool := authTestPool(t)
	tenantID, clusterID, incidentID, planID := timelineExecFixture(t, pool)

	s := reconcileTestServer(t, pool)
	rc := Scope{TenantID: tenantID}
	actor := Actor{UserID: "usr_test", AuthMethod: "jwt"}
	ctx := context.Background()

	attempt := openAttempt(tenantID, clusterID, incidentID, planID, time.Now().Add(time.Hour))
	if err := s.recordExecutingTransition(ctx, rc, incidentID, planID, clusterID, actor,
		false, false, "", nil, dryRunAttestation{At: time.Now()}, nil, attempt); err != nil {
		t.Fatalf("recordExecutingTransition: %v", err)
	}

	if err := s.reconcileExecutions(ctx); err != nil {
		t.Fatalf("reconcileExecutions: %v", err)
	}

	if got := incidentStateNow(t, pool, tenantID, clusterID, incidentID); got != orchestrator.StateExecuting {
		t.Errorf("incident state = %q, want %q — the dispatching request's deadline has not passed, so it may still be mid-call", got, orchestrator.StateExecuting)
	}
	if rows := executionRowsFor(t, pool, tenantID, clusterID, incidentID); len(rows) != 0 {
		t.Errorf("remediation_executions rows = %d, want 0 — the reconciler recorded an outcome for a live execution", len(rows))
	}
	if settled, _ := attemptSettlement(t, pool, tenantID, attempt.ID); settled {
		t.Error("the reconciler settled an attempt whose owner is still within its deadline")
	}
}

// The orphan pass: incidents that entered Executing before attempts were
// recorded at all. Without this they stay stuck forever, which is the fault
// as it exists in the database right now, not just in future code paths.
func TestExecutionReconcilerRecoversAnOrphanedExecutingIncident(t *testing.T) {
	pool := authTestPool(t)
	tenantID, clusterID, incidentID, planID := timelineExecFixture(t, pool)

	s := reconcileTestServer(t, pool)
	rc := Scope{TenantID: tenantID}
	actor := Actor{UserID: "usr_test", AuthMethod: "jwt"}
	ctx := context.Background()

	// No attempt row at all — the shape every execution had before this change.
	if err := s.recordExecutingTransition(ctx, rc, incidentID, planID, clusterID, actor,
		false, false, "", nil, dryRunAttestation{At: time.Now()}, nil, executionAttempt{}); err != nil {
		t.Fatalf("recordExecutingTransition: %v", err)
	}
	backdateApproval(t, pool, tenantID, clusterID, incidentID, 30*time.Minute)

	if got := reconcileUntilSettled(t, s, pool, tenantID, clusterID, incidentID); got != orchestrator.StateExecutionUnknown {
		t.Errorf("incident state = %q, want %q", got, orchestrator.StateExecutionUnknown)
	}
	rows := executionRowsFor(t, pool, tenantID, clusterID, incidentID)
	if len(rows) != 1 || rows[0][1] != "unknown" {
		t.Fatalf("executions = %v, want exactly one 'unknown' row", rows)
	}
}

// backdateApproval ages an incident's approval decision, which is the clock
// the orphan pass reads (incidents has no state-change timestamp, and the
// approved decision row is written in the same transaction as the
// AwaitingApproval -> Executing transition).
func backdateApproval(t *testing.T, pool *pgxpool.Pool, tenantID, clusterID, incidentID string, age time.Duration) {
	t.Helper()
	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if err := data.SetRequestScope(ctx, tx, tenantID, []string{clusterID}); err != nil {
		t.Fatalf("scope: %v", err)
	}
	if _, err := tx.Exec(ctx,
		`UPDATE remediation_approval_decisions SET created_at = now() - ($2 * interval '1 second') WHERE incident_id = $1`,
		incidentID, age.Seconds()); err != nil {
		t.Fatalf("backdate approval: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit: %v", err)
	}
}

// Settlement is exactly-once: a request that comes back to life after a
// reconciler concluded must not write a second execution row for one mutation.
func TestAttemptSettlesExactlyOnce(t *testing.T) {
	pool := authTestPool(t)
	tenantID, clusterID, incidentID, planID := timelineExecFixture(t, pool)

	s := reconcileTestServer(t, pool)
	rc := Scope{TenantID: tenantID}
	actor := Actor{UserID: "usr_test", AuthMethod: "jwt"}
	ctx := context.Background()

	attempt := openAttempt(tenantID, clusterID, incidentID, planID, time.Now().Add(-time.Minute))
	if err := s.recordExecutingTransition(ctx, rc, incidentID, planID, clusterID, actor,
		false, false, "", nil, dryRunAttestation{At: time.Now()}, nil, attempt); err != nil {
		t.Fatalf("recordExecutingTransition: %v", err)
	}
	if _, err := s.recordExecutionOutcome(ctx, rc, incidentID, planID, clusterID, actor,
		"succeeded", "", "rv-1", nil, "3", forwardOutcomeStates(), attempt.ID, "ScaleDeployment", "forward"); err != nil {
		t.Fatalf("first settlement: %v", err)
	}

	_, err := s.recordExecutionOutcome(ctx, rc, incidentID, planID, clusterID, actor,
		"unknown", "a reconciler concluded second", "rv-1", nil, "3", forwardOutcomeStates(), attempt.ID, "ScaleDeployment", "forward")
	if !errors.Is(err, errAttemptAlreadySettled) {
		t.Fatalf("second settlement error = %v, want errAttemptAlreadySettled", err)
	}
	if rows := executionRowsFor(t, pool, tenantID, clusterID, incidentID); len(rows) != 1 {
		t.Errorf("remediation_executions rows = %d, want 1 — one mutation produced two records", len(rows))
	}
	if got := incidentStateNow(t, pool, tenantID, clusterID, incidentID); got != orchestrator.StateValidating {
		t.Errorf("incident state = %q, want %q — the losing writer overwrote the winner's conclusion", got, orchestrator.StateValidating)
	}
}

// THE FIX for finding 2's first half, at the exact call the fault was in.
// Same sequence as TestCancelledRequestContextStrandsTheIncidentInExecuting,
// with the one difference handleApproveIncident now makes: the work runs on a
// context detached from the request's. The outcome is recorded and the
// incident leaves Executing, with the client long gone.
func TestDetachedContextStillRecordsTheOutcomeAfterAClientDisconnect(t *testing.T) {
	pool := authTestPool(t)
	tenantID, clusterID, incidentID, planID := timelineExecFixture(t, pool)

	s := &Executor{db: &data.DB{Pool: pool}}
	rc := Scope{TenantID: tenantID}
	actor := Actor{UserID: "usr_test", AuthMethod: "jwt"}

	requestCtx, disconnect := context.WithCancel(context.Background())
	// Exactly what handleApproveIncident now does before executing.
	workCtx, cancelWork := context.WithTimeout(context.WithoutCancel(requestCtx), WorkLimit)
	defer cancelWork()

	attempt := openAttempt(tenantID, clusterID, incidentID, planID, time.Now().Add(time.Hour))
	if err := s.recordExecutingTransition(workCtx, rc, incidentID, planID, clusterID, actor,
		false, false, "", nil, dryRunAttestation{At: time.Now()}, nil, attempt); err != nil {
		t.Fatalf("recordExecutingTransition: %v", err)
	}

	// The operator closes the tab, mid-execution.
	disconnect()

	finalState, err := s.recordExecutionOutcome(workCtx, rc, incidentID, planID, clusterID, actor,
		"succeeded", "", "rv-1", nil, "3", forwardOutcomeStates(), attempt.ID, "ScaleDeployment", "forward")
	if err != nil {
		t.Fatalf("recordExecutionOutcome after the client disconnected: %v", err)
	}
	if finalState != orchestrator.StateValidating {
		t.Errorf("finalState = %q, want %q", finalState, orchestrator.StateValidating)
	}
	if got := incidentStateNow(t, pool, tenantID, clusterID, incidentID); got != orchestrator.StateValidating {
		t.Errorf("incident state = %q, want %q — a disconnect must not decide whether an execution is recorded", got, orchestrator.StateValidating)
	}
	rows := executionRowsFor(t, pool, tenantID, clusterID, incidentID)
	if len(rows) != 1 || rows[0][1] != "succeeded" {
		t.Fatalf("executions = %v, want exactly one 'succeeded' row", rows)
	}
	if settled, _ := attemptSettlement(t, pool, tenantID, attempt.ID); !settled {
		t.Error("the attempt was left open even though its outcome was recorded")
	}
}
