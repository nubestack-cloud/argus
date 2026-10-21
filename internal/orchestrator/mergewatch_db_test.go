package orchestrator

import (
	"context"
	"fmt"
	"testing"
	"time"

	"argus/internal/data"
	"argus/internal/events"
	"argus/internal/timeline"
)

// scopedMergeChecker answers only for one incident id and refuses (as an
// error — "could not check", the safe direction) any other. sweep's
// candidate query is deliberately fleet-wide (`WHERE state = $1`, no cluster
// filter — matching ValidationSweeper's own tenant-wide sweep shape), and
// this codebase is single-tenant (DESIGN.md §5.1): every AwaitingMerge
// incident already sitting in whatever database ARGUS_TEST_DATABASE_URL
// points at is a REAL candidate sweep will pick up alongside this test's own
// throwaway one. A checker that answers the same outcome for every
// incidentID it's asked about — the shape fakeMergeChecker uses for the
// no-database logic tests — would act on those real rows too.
type scopedMergeChecker struct {
	incidentID string
	outcome    PullRequestOutcome
}

func (s scopedMergeChecker) CheckPullRequestMerged(_ context.Context, incidentID string) (PullRequestOutcome, error) {
	if incidentID != s.incidentID {
		return PullRequestOutcome{}, fmt.Errorf("scopedMergeChecker: not scoped to incident %s", incidentID)
	}
	return s.outcome, nil
}

// TestMergeSweeperMovesClosedUnmergedIncidentToAwaitingApproval is BUGS.md
// 82's end-to-end regression test, run against a real Postgres for the same
// reason validation_sibling_db_test.go's own doc comment gives: the write
// this exercises runs under FORCE ROW LEVEL SECURITY, so its real behaviour
// is a property of live Postgres, not of Go — a fake pool could not tell "the
// UPDATE ran" from "RLS silently hid the row".
//
// Before the fix, this incident would stay in AwaitingMerge forever: Merged
// was false for both "still open" and "closed without merging", and sweep's
// only branch on !Merged was `continue`.
func TestMergeSweeperMovesClosedUnmergedIncidentToAwaitingApproval(t *testing.T) {
	pool := testPool(t)
	tenantID, clusterID, incidentID, _ := testIncident(t, pool, StateAwaitingMerge)
	ctx := context.Background()

	sweeper := NewMergeSweeper(&data.DB{Pool: pool}, events.NewBus(), scopedMergeChecker{
		incidentID: incidentID,
		outcome:    PullRequestOutcome{Closed: true},
	})
	if err := sweeper.sweep(ctx); err != nil {
		t.Fatalf("sweep: %v", err)
	}

	if got := currentState(t, pool, tenantID, clusterID, incidentID); got != StateAwaitingApproval {
		t.Fatalf("incident state = %q, want %q — a closed-unmerged pull request must return its incident to the approval queue (DESIGN.md §12.3)", got, StateAwaitingApproval)
	}

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin read: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if err := data.SetRequestScope(ctx, tx, tenantID, []string{clusterID}); err != nil {
		t.Fatalf("set request scope: %v", err)
	}
	var closedAt *time.Time
	var reason *string
	if err := tx.QueryRow(ctx,
		`SELECT pr_closed_unmerged_at, pr_rejection_reason FROM incidents WHERE id = $1`, incidentID,
	).Scan(&closedAt, &reason); err != nil {
		t.Fatalf("read incident: %v", err)
	}
	if closedAt == nil || closedAt.IsZero() {
		t.Error("pr_closed_unmerged_at was not recorded")
	}
	if reason == nil || *reason == "" {
		t.Error("pr_rejection_reason was not recorded — DESIGN.md §12.3 asks for the rejection reason to be captured, not just the state change")
	}

	// BACKLOG.md D9 B7: this sweeper called timeline.Record nowhere at all
	// until now — a pull request closing unmerged left no trace on the
	// incident's own "what happened" history, even though the state change
	// and the two columns above were both recorded correctly.
	var eventType string
	if err := tx.QueryRow(ctx,
		`SELECT event_type FROM timeline_events WHERE incident_id = $1 AND event_type = $2`,
		incidentID, timeline.EventPullRequestClosed,
	).Scan(&eventType); err != nil {
		t.Errorf("no %s timeline event was recorded for incident %s: %v", timeline.EventPullRequestClosed, incidentID, err)
	}
}

// TestMergeSweeperLeavesAStillOpenPullRequestInAwaitingMerge is the negative
// case for the same branch: Merged=false and Closed=false (nobody has acted
// on the pull request at all) must change nothing, same as before this fix.
func TestMergeSweeperLeavesAStillOpenPullRequestInAwaitingMerge(t *testing.T) {
	pool := testPool(t)
	tenantID, clusterID, incidentID, _ := testIncident(t, pool, StateAwaitingMerge)
	ctx := context.Background()

	sweeper := NewMergeSweeper(&data.DB{Pool: pool}, events.NewBus(), scopedMergeChecker{
		incidentID: incidentID,
		outcome:    PullRequestOutcome{Merged: false, Closed: false, CreatedAt: time.Now()},
	})
	if err := sweeper.sweep(ctx); err != nil {
		t.Fatalf("sweep: %v", err)
	}

	if got := currentState(t, pool, tenantID, clusterID, incidentID); got != StateAwaitingMerge {
		t.Fatalf("incident state = %q, want %q — a pull request nobody has acted on yet must not move", got, StateAwaitingMerge)
	}
}

// TestMergeSweeperRecordsTimelineEventOnMerge is BACKLOG.md D9 B7's other
// half of the same gap: a MERGED-and-synced pull request also left no
// timeline trace at all before this fix, even though it correctly promoted
// the incident to Validating (pr_merged_at + StateValidating, both unchanged
// by this task).
func TestMergeSweeperRecordsTimelineEventOnMerge(t *testing.T) {
	pool := testPool(t)
	tenantID, clusterID, incidentID, _ := testIncident(t, pool, StateAwaitingMerge)
	ctx := context.Background()

	sweeper := NewMergeSweeper(&data.DB{Pool: pool}, events.NewBus(), scopedMergeChecker{
		incidentID: incidentID,
		outcome:    PullRequestOutcome{Merged: true, MergedAt: time.Now(), Synced: true},
	})
	if err := sweeper.sweep(ctx); err != nil {
		t.Fatalf("sweep: %v", err)
	}

	if got := currentState(t, pool, tenantID, clusterID, incidentID); got != StateValidating {
		t.Fatalf("incident state = %q, want %q", got, StateValidating)
	}

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin read: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if err := data.SetRequestScope(ctx, tx, tenantID, []string{clusterID}); err != nil {
		t.Fatalf("set request scope: %v", err)
	}
	var eventType string
	if err := tx.QueryRow(ctx,
		`SELECT event_type FROM timeline_events WHERE incident_id = $1 AND event_type = $2`,
		incidentID, timeline.EventPullRequestMerged,
	).Scan(&eventType); err != nil {
		t.Errorf("no %s timeline event was recorded for incident %s: %v", timeline.EventPullRequestMerged, incidentID, err)
	}
}
