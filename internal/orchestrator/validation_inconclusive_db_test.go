package orchestrator

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"argus/internal/data"
	"argus/internal/domain"
)

// The end-to-end version of validation_inconclusive_test.go: a real Validating
// incident, a real succeeded execution older than the grace period, a verifier
// that cannot answer, and ValidationSweeper.sweep driven for real against
// Postgres.
//
// This is the test that actually fails against the pre-fix sweeper. The pure
// tests assert the rule; this one asserts that the rule is what the sweeper
// applies, through the same candidate query, the same RLS scope and the same
// SetState the hub uses. Before the fix it ends with the incident Resolved.
//
// Uses db_test.go's testPool harness (argus_app, so this runs under the same
// FORCE ROW LEVEL SECURITY the hub does).

// unansweredVerifier is a verifier that can never make an assertion — the
// unreachable-cluster case, which is the one this whole fix is about.
//
// It reports evaluated=true for RuleStillFires with an error, so BOTH
// assertions are attempted and BOTH fail: the strictest possible "we could not
// tell", and the exact shape a disconnected agent produces.
type unansweredVerifier struct{ ruleEvaluated bool }

func (u unansweredVerifier) VerifyAppliedValue(context.Context, string) (bool, string, error) {
	return false, "", errors.New("cluster is not connected")
}

func (u unansweredVerifier) VerifyMergedPullRequest(context.Context, string) (bool, string, error) {
	return false, "", errors.New("cluster is not connected")
}

func (u unansweredVerifier) RuleStillFires(context.Context, string) (bool, bool, string, error) {
	if !u.ruleEvaluated {
		return false, false, "", nil // scope boundary: nothing to re-run
	}
	return true, false, "", errors.New("cluster is not connected")
}

// validatingIncidentWithExecution builds the fixture the sweeper's in-place
// candidate query needs: a Validating incident whose newest succeeded
// execution landed fixLandedAgo ago, with last_seen at or before it (so no
// recurrence has been recorded since).
func validatingIncidentWithExecution(t *testing.T, pool *pgxpool.Pool, fixLandedAgo time.Duration) (tenantID, clusterID, incidentID string) {
	t.Helper()
	ctx := context.Background()

	tenantID, clusterID, incidentID, _ = testIncident(t, pool, StateValidating)

	landed := time.Now().Add(-fixLandedAgo)
	analysisID := domain.NewID(domain.PrefixAnalysis)
	recID := domain.NewID(domain.PrefixPlan)
	execID := domain.NewID(domain.PrefixExecution)

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin fixture: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if err := data.SetRequestScope(ctx, tx, tenantID, []string{clusterID}); err != nil {
		t.Fatalf("set request scope: %v", err)
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO analyses (id, incident_id, tenant_id, cluster_id, model, prompt_version, causal_chain,
		                       iterations, duration_ms, tokens_billed_in, tokens_cache_read, tokens_out, cost_usd,
		                       root_cause, confidence, created_at)
		 VALUES ($1, $2, $3, $4, 'test-model', 'v1', '[]', 1, 1, 0, 0, 0, 0, '{"summary":"fixture"}', 0.9, $5)`,
		analysisID, incidentID, tenantID, clusterID, landed); err != nil {
		t.Fatalf("insert analysis: %v", err)
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO remediation_recommendations
		   (id, incident_id, tenant_id, cluster_id, analysis_id, action_type, target_gvk, target_namespace, target_name,
		    params, reversible, risk_level, gate_outcome, gate_reason, created_at)
		 VALUES ($1, $2, $3, $4, $5, 'ScaleDeployment', 'apps/v1/Deployment', 'default', 'fixture-app',
		         '{"replicas":3}', true, 'low', 'NeedsApproval', 'fixture', $6)`,
		recID, incidentID, tenantID, clusterID, analysisID, landed); err != nil {
		t.Fatalf("insert recommendation: %v", err)
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO remediation_executions
		   (id, incident_id, recommendation_id, tenant_id, cluster_id, outcome, executed_at)
		 VALUES ($1, $2, $3, $4, $5, 'succeeded', $6)`,
		execID, incidentID, recID, tenantID, clusterID, landed); err != nil {
		t.Fatalf("insert execution: %v", err)
	}
	// last_seen must not be AFTER the fix landed, or the candidate query
	// (correctly) treats it as a recurrence and never selects the row.
	if _, err := tx.Exec(ctx,
		`UPDATE incidents SET last_seen = $2, first_seen = $2 WHERE id = $1`, incidentID, landed.Add(-time.Minute)); err != nil {
		t.Fatalf("backdate incident: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit fixture: %v", err)
	}

	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Errorf("cleanup: begin: %v", err)
			return
		}
		defer tx.Rollback(ctx) //nolint:errcheck
		if err := data.SetRequestScope(ctx, tx, tenantID, []string{clusterID}); err != nil {
			t.Errorf("cleanup: set request scope: %v", err)
			return
		}
		for _, stmt := range []string{
			`DELETE FROM remediation_executions WHERE incident_id = $1`,
			`DELETE FROM remediation_recommendations WHERE incident_id = $1`,
			`DELETE FROM analyses WHERE incident_id = $1`,
		} {
			if _, err := tx.Exec(ctx, stmt, incidentID); err != nil {
				t.Errorf("cleanup %q: %v", stmt, err)
				return
			}
		}
		if err := tx.Commit(ctx); err != nil {
			t.Errorf("cleanup: commit: %v", err)
		}
	})
	return tenantID, clusterID, incidentID
}

func incidentState(t *testing.T, pool *pgxpool.Pool, tenantID, clusterID, incidentID string) string {
	t.Helper()
	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin read: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if err := data.SetRequestScope(ctx, tx, tenantID, []string{clusterID}); err != nil {
		t.Fatalf("set request scope: %v", err)
	}
	var state string
	if err := tx.QueryRow(ctx, `SELECT state FROM incidents WHERE id = $1`, incidentID).Scan(&state); err != nil {
		t.Fatalf("read incident state: %v", err)
	}
	return state
}

// TestSweepDoesNotResolveWhenNothingCouldBeAsserted is the regression test for
// the bug itself, end to end.
//
// Before the fix, this sweep committed Resolved: targetState started at
// Resolved, the verifier's error only rewrote `evidence`, and SetState ran
// anyway. That row is then permanently indistinguishable from a fix ARGUS
// actually verified.
func TestSweepDoesNotResolveWhenNothingCouldBeAsserted(t *testing.T) {
	pool := testPool(t)
	tenantID, clusterID, incidentID := validatingIncidentWithExecution(t, pool, validationGracePeriod+2*time.Minute)

	v := NewValidationSweeper(&data.DB{Pool: pool}, nil, unansweredVerifier{})
	if err := v.sweep(context.Background()); err != nil {
		t.Fatalf("sweep: %v", err)
	}

	got := incidentState(t, pool, tenantID, clusterID, incidentID)
	if got == StateResolved {
		t.Fatal("the sweeper resolved an incident whose fix it could not re-check at all — 'we could not tell' was reported as 'we verified it worked', which is the exact defect this fix exists to close")
	}
	if got != StateValidating {
		t.Fatalf("incident state = %q, want %q — inside the retry window it must stay put and be asked again", got, StateValidating)
	}
}

// TestSweepReachesValidationUnknownPastTheDeadline is the other half: keeping
// it in Validating forever would be a different kind of silence, so the wait
// is bounded and lands somewhere explicit.
func TestSweepReachesValidationUnknownPastTheDeadline(t *testing.T) {
	pool := testPool(t)
	tenantID, clusterID, incidentID := validatingIncidentWithExecution(t, pool,
		validationGracePeriod+validationAssertionDeadline+2*time.Minute)

	v := NewValidationSweeper(&data.DB{Pool: pool}, nil, unansweredVerifier{ruleEvaluated: true})
	if err := v.sweep(context.Background()); err != nil {
		t.Fatalf("sweep: %v", err)
	}

	if got := incidentState(t, pool, tenantID, clusterID, incidentID); got != StateValidationUnknown {
		t.Fatalf("incident state = %q, want %q", got, StateValidationUnknown)
	}

	// The reason has to survive on the incident's own history, not only in a
	// hub log line, and it has to be worded so the two outcomes cannot be
	// confused.
	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin read: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if err := data.SetRequestScope(ctx, tx, tenantID, []string{clusterID}); err != nil {
		t.Fatalf("set request scope: %v", err)
	}
	var summary, outcome string
	if err := tx.QueryRow(ctx,
		`SELECT payload->>'summary', payload->>'outcome' FROM timeline_events
		  WHERE incident_id = $1 AND event_type = 'ValidationOutcome'
		  ORDER BY occurred_at DESC LIMIT 1`, incidentID).Scan(&summary, &outcome); err != nil {
		t.Fatalf("read ValidationOutcome timeline event: %v", err)
	}
	if outcome != StateValidationUnknown {
		t.Errorf("timeline outcome = %q, want %q", outcome, StateValidationUnknown)
	}
	if summary == "" {
		t.Error("the ValidationOutcome event recorded no explanation at all")
	}
	t.Logf("recorded: %s", summary)

	// And an operator is actually told (db.go's notifiableStates).
	var notifications int
	if err := tx.QueryRow(ctx,
		`SELECT count(*) FROM incident_notifications WHERE incident_id = $1`, incidentID).Scan(&notifications); err != nil {
		t.Fatalf("count notifications: %v", err)
	}
	if notifications == 0 {
		t.Error("reaching ValidationUnknown queued no notification — an incident that quietly stopped being validated is exactly what nobody goes looking for")
	}
}

// TestSweepStillResolvesOnARealAssertion is the guard against overcorrection:
// the fix must not turn every validation into "we could not tell".
func TestSweepStillResolvesOnARealAssertion(t *testing.T) {
	pool := testPool(t)
	tenantID, clusterID, incidentID := validatingIncidentWithExecution(t, pool, validationGracePeriod+2*time.Minute)

	v := NewValidationSweeper(&data.DB{Pool: pool}, nil,
		fakeVerifier{held: true, detail: fmt.Sprintf("replicas is still %q", "3")})
	if err := v.sweep(context.Background()); err != nil {
		t.Fatalf("sweep: %v", err)
	}

	if got := incidentState(t, pool, tenantID, clusterID, incidentID); got != StateResolved {
		t.Fatalf("incident state = %q, want %q — a verified fix must still close", got, StateResolved)
	}
}
