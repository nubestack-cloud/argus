package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"argus/internal/data"
)

// TestHandleRejectIncident_ConcurrentRejectsExactlyOneWins fires two real
// goroutines at the actual HTTP handler, both racing to reject the SAME
// incident/plan, released from a shared barrier so neither goroutine can
// start before the other. Postgres's row lock (via execution.LockIncidentForDecision)
// is what makes the outcome deterministic regardless of how the scheduler
// interleaves the two goroutines: exactly one of the two transactions can
// ever be the one that finds the incident still AwaitingApproval, so this
// assertion cannot flake into "usually" — it is the one outcome the schema
// and execution.LockIncidentForDecision's own lock allow.
func TestHandleRejectIncident_ConcurrentRejectsExactlyOneWins(t *testing.T) {
	pool := authTestPool(t)
	tenantID, clusterID, incidentID, _ := timelineExecFixture(t, pool)
	ctx := context.Background()

	run := func(barrier <-chan struct{}) (status int, body string) {
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Errorf("begin: %v", err)
			return 0, ""
		}
		defer tx.Rollback(ctx) //nolint:errcheck
		if err := data.SetRequestScope(ctx, tx, tenantID, []string{clusterID}); err != nil {
			t.Errorf("scope: %v", err)
			return 0, ""
		}
		rc := &requestContext{Tx: tx, TenantID: tenantID, UserID: "usr_test"}
		req := httptest.NewRequest(http.MethodPost, "/api/v1/incidents/"+incidentID+"/reject", strings.NewReader(`{"reason":"racing reject"}`))
		req.SetPathValue("id", incidentID)
		rec := httptest.NewRecorder()

		<-barrier // both goroutines are already past setup; released together
		s := &Server{}
		s.handleRejectIncident(rec, req, rc)
		if rec.Code < 400 {
			if err := tx.Commit(ctx); err != nil {
				t.Errorf("commit: %v", err)
			}
		}
		// A >=400 response leaves tx to be rolled back by the deferred call
		// above — matching internal/api/middleware.go's completeRequest
		// convention this test stands in for.
		return rec.Code, rec.Body.String()
	}

	barrier := make(chan struct{})
	var wg sync.WaitGroup
	codes := make([]int, 2)
	bodies := make([]string, 2)
	for i := range codes {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			codes[i], bodies[i] = run(barrier)
		}(i)
	}
	close(barrier)
	wg.Wait()

	var ok, conflict int
	for i, code := range codes {
		switch code {
		case http.StatusOK:
			ok++
		case http.StatusConflict:
			conflict++
			// Whichever of the two conflict checks the loser trips —
			// handleRejectIncident's own pre-existing "not AwaitingApproval"
			// check (if it re-reads state after the winner has already
			// committed) or execution.LockIncidentForDecision's new one (if it gets
			// there first and finds the row already decided under the lock)
			// — both are legitimate, clearly-worded 409s naming what
			// happened; which one fires is a timing detail, not a
			// correctness one.
			if !strings.Contains(bodies[i], "plan-already-decided") &&
				!strings.Contains(bodies[i], "already been") &&
				!strings.Contains(bodies[i], "not awaiting approval") {
				t.Errorf("goroutine %d: 409 body does not name what already happened: %s", i, bodies[i])
			}
		default:
			t.Errorf("goroutine %d: unexpected status %d, body=%s", i, code, bodies[i])
		}
	}
	if ok != 1 || conflict != 1 {
		t.Fatalf("codes = %v — want exactly one 200 and one 409, got %d OK and %d Conflict", codes, ok, conflict)
	}

	// The incident itself must show exactly ONE rejection decision, never
	// two — the duplicate-audit-row failure mode this task exists to close.
	verifyTx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("verify begin: %v", err)
	}
	defer verifyTx.Rollback(ctx) //nolint:errcheck
	if err := data.SetRequestScope(ctx, verifyTx, tenantID, []string{clusterID}); err != nil {
		t.Fatalf("verify scope: %v", err)
	}
	var decisionCount int
	if err := verifyTx.QueryRow(ctx, `SELECT count(*) FROM remediation_approval_decisions WHERE incident_id = $1`, incidentID).Scan(&decisionCount); err != nil {
		t.Fatalf("count decisions: %v", err)
	}
	if decisionCount != 1 {
		t.Fatalf("remediation_approval_decisions has %d rows for incident %s, want exactly 1", decisionCount, incidentID)
	}
}
