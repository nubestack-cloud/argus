package api

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"argus/internal/data"
)

// TestRecordFailedOpenPRApproval_WritesTimelineEventInItsOwnTransaction is
// BUGS.md 110's fix for the "zero recorded trace" half of that bug: before
// this existed, an OpenPR approval that failed to open a pull request left
// literally zero rows anywhere, because requireAuth rolls back the request's
// whole transaction (rc.Tx) on the resulting 422 — see
// recordFailedOpenPRApproval's own doc comment for why that forces a
// separately-committed transaction rather than a write to rc.Tx.
//
// This test drives that separately-committed transaction directly: it never
// commits (or even opens) an outer request transaction at all, matching how
// approveByOpeningPullRequest actually calls this — the fact that a
// timeline_events row is visible afterwards, over a fresh connection, proves
// the write survived independently of any caller-side rollback.
func TestRecordFailedOpenPRApproval_WritesTimelineEventInItsOwnTransaction(t *testing.T) {
	pool := authTestPool(t)
	tenantID, clusterID, incidentID, planID := timelineExecFixture(t, pool)

	s := &Server{db: &data.DB{Pool: pool}}
	cause := errors.New("gitops: that field cannot be changed by a minimal textual edit: the new value spans more than one line")

	s.recordFailedOpenPRApproval(context.Background(), tenantID, clusterID, incidentID, planID, cause, nil)

	got := timelineEventTypesFor(t, pool, tenantID, clusterID, incidentID)
	if len(got) != 1 || got[0] != "PullRequestProposalFailed" {
		t.Fatalf("timeline event types = %v, want exactly [\"PullRequestProposalFailed\"]", got)
	}

	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin verify tx: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if err := data.SetRequestScope(ctx, tx, tenantID, []string{clusterID}); err != nil {
		t.Fatalf("scope: %v", err)
	}
	var payload []byte
	if err := tx.QueryRow(ctx, `SELECT payload FROM timeline_events WHERE incident_id = $1 AND event_type = 'PullRequestProposalFailed'`, incidentID).Scan(&payload); err != nil {
		t.Fatalf("read PullRequestProposalFailed payload: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(payload, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got, _ := decoded["planId"].(string); got != planID {
		t.Errorf("payload[\"planId\"] = %q, want %q", got, planID)
	}
	if got, _ := decoded["reason"].(string); got != cause.Error() {
		t.Errorf("payload[\"reason\"] = %q, want %q", got, cause.Error())
	}

	// The incident's own state must be untouched — this event is a trace of
	// the attempt, not a new state-machine transition (BACKLOG.md AL1 leaves
	// that harder question open).
	var state string
	if err := tx.QueryRow(ctx, `SELECT state FROM incidents WHERE id = $1`, incidentID).Scan(&state); err != nil {
		t.Fatalf("read incident state: %v", err)
	}
	if state != "AwaitingApproval" {
		t.Errorf("incident state = %q, want unchanged %q", state, "AwaitingApproval")
	}
}
