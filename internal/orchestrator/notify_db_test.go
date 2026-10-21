package orchestrator

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"argus/internal/data"
	"argus/internal/events"
)

// readNotification reads back one incident's incident_notifications row (if
// any) in its own scoped transaction — the DB-level ground truth for what
// notify.NotifyTransition (called from SetState/mergewatch.go) actually
// wrote, without needing internal/notify's own sweep machinery.
func readNotification(t *testing.T, pool *pgxpool.Pool, tenantID, clusterID, incidentID string) (notifyKey string, pending bool, found bool) {
	t.Helper()
	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin read transaction: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if err := data.SetRequestScope(ctx, tx, tenantID, []string{clusterID}); err != nil {
		t.Fatalf("set request scope: %v", err)
	}
	err = tx.QueryRow(ctx, `SELECT notify_key, pending FROM incident_notifications WHERE incident_id = $1`, incidentID).
		Scan(&notifyKey, &pending)
	if err != nil {
		if err == pgx.ErrNoRows {
			return "", false, false
		}
		t.Fatalf("read incident_notifications: %v", err)
	}
	return notifyKey, pending, true
}

// setNotificationPending directly flips one incident's incident_notifications
// row to simulate "internal/notify's own sweep already sent this" without
// pulling in that package's HTTP machinery — this test only needs the DB
// state a real send would have left behind (pending=false, notified_at set).
func setNotificationPending(t *testing.T, pool *pgxpool.Pool, tenantID, clusterID, incidentID string, pending bool) {
	t.Helper()
	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if err := data.SetRequestScope(ctx, tx, tenantID, []string{clusterID}); err != nil {
		t.Fatalf("set request scope: %v", err)
	}
	if _, err := tx.Exec(ctx,
		`UPDATE incident_notifications SET pending = $2, notified_at = now() WHERE incident_id = $1`,
		incidentID, pending); err != nil {
		t.Fatalf("update incident_notifications: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit: %v", err)
	}
}

// TestSetStateQueuesNotificationForEachTrigger is BACKLOG.md N1's "a test
// proving each of the five trigger conditions above actually fires" for the
// four that go through SetState (the fifth, mergewatch.go's stale pull
// request, is covered in mergewatch_db_test.go since it isn't a state
// transition at all). Walks one incident through a realistic sequence of
// LEGAL transitions and checks incident_notifications after each one: a
// notifiable state queues a fresh, differently-keyed notification every
// time — including the SECOND entry into AwaitingApproval after a Failed
// cycle, which is the specific case notifiableStates' own comment in db.go
// explains a bare state-name key would have wrongly swallowed — and an
// ordinary transition (Executing, AwaitingMerge, Validating, Investigating)
// leaves the row exactly as it was.
func TestSetStateQueuesNotificationForEachTrigger(t *testing.T) {
	pool := testPool(t)
	tenantID, clusterID, incidentID, _ := testIncident(t, pool, StateInvestigating)
	ctx := context.Background()

	setState := func(to string) {
		t.Helper()
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatalf("begin: %v", err)
		}
		defer tx.Rollback(ctx) //nolint:errcheck
		if err := data.SetRequestScope(ctx, tx, tenantID, []string{clusterID}); err != nil {
			t.Fatalf("set request scope: %v", err)
		}
		if err := SetState(ctx, tx, incidentID, to); err != nil {
			t.Fatalf("SetState(%s): %v", to, err)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatalf("commit: %v", err)
		}
	}

	// No row at all before the first notifiable transition.
	if _, _, found := readNotification(t, pool, tenantID, clusterID, incidentID); found {
		t.Fatal("incident_notifications row exists before any notifiable transition")
	}

	// 1. Investigating -> AwaitingApproval: a plan needs a human decision.
	setState(StateAwaitingApproval)
	key1, pending, found := readNotification(t, pool, tenantID, clusterID, incidentID)
	if !found || !pending || !strings.HasPrefix(key1, StateAwaitingApproval+"@") {
		t.Fatalf("after -> AwaitingApproval: key=%q pending=%v found=%v, want a pending row keyed %q@...", key1, pending, found, StateAwaitingApproval)
	}

	// An ordinary, non-notifiable transition must not touch the row.
	setState(StateExecuting)
	if key, pend, found := readNotification(t, pool, tenantID, clusterID, incidentID); key != key1 || !pend || !found {
		t.Fatalf("after -> Executing (not notifiable): key=%q pending=%v found=%v, want unchanged (%q, true, true)", key, pend, found, key1)
	}

	// 2. Executing -> Failed: an execution attempt did not cleanly resolve.
	setState(StateFailed)
	key2, pending, found := readNotification(t, pool, tenantID, clusterID, incidentID)
	if !found || !pending || !strings.HasPrefix(key2, StateFailed+"@") {
		t.Fatalf("after -> Failed: key=%q pending=%v found=%v, want a pending row keyed %q@...", key2, pending, found, StateFailed)
	}
	if key2 == key1 {
		t.Fatal("Failed notification key collided with the earlier AwaitingApproval key")
	}

	// Route to AwaitingMerge, then Validating — neither notifiable.
	setState(StateAwaitingMerge)
	setState(StateValidating)
	if key, _, _ := readNotification(t, pool, tenantID, clusterID, incidentID); key != key2 {
		t.Fatalf("after two ordinary transitions: key=%q, want unchanged (%q)", key, key2)
	}

	// 3. Validating -> Reopened: the symptom came back.
	setState(StateReopened)
	key3, pending, found := readNotification(t, pool, tenantID, clusterID, incidentID)
	if !found || !pending || !strings.HasPrefix(key3, StateReopened+"@") {
		t.Fatalf("after -> Reopened: key=%q pending=%v found=%v, want a pending row keyed %q@...", key3, pending, found, StateReopened)
	}

	// Simulate a real send having gone out, then re-enter AwaitingApproval a
	// SECOND time — this must notify again, with a DIFFERENT key than key1,
	// even though the state name is identical to the first time. This is
	// the exact property db.go's notifiableStates comment calls out: a bare
	// state-name key would have been silently swallowed here.
	setState(StateInvestigating)
	setNotificationPending(t, pool, tenantID, clusterID, incidentID, false)
	setState(StateAwaitingApproval)
	key4, pending, found := readNotification(t, pool, tenantID, clusterID, incidentID)
	if !found || !pending || !strings.HasPrefix(key4, StateAwaitingApproval+"@") {
		t.Fatalf("after re-entering AwaitingApproval: key=%q pending=%v found=%v, want a pending row keyed %q@...", key4, pending, found, StateAwaitingApproval)
	}
	if key4 == key1 {
		t.Fatal("re-entering AwaitingApproval produced the SAME key as the first time — a second, later occurrence must still notify (see notifiableStates' own comment)")
	}

	// 4. AwaitingApproval -> Executing -> ExecutionUnknown: a mutating call's
	// own error was the disconnect/timeout shape and a follow-up read could
	// not confirm the change applied either.
	setState(StateExecuting)
	setState(StateExecutionUnknown)
	key5, pending, found := readNotification(t, pool, tenantID, clusterID, incidentID)
	if !found || !pending || !strings.HasPrefix(key5, StateExecutionUnknown+"@") {
		t.Fatalf("after -> ExecutionUnknown: key=%q pending=%v found=%v, want a pending row keyed %q@...", key5, pending, found, StateExecutionUnknown)
	}
}

// TestMergeSweeperEscalatesStalePRWithoutRefiringOnRepeatedTicks is BACKLOG.md
// N1's other required property test: mergewatch.go's stale-pull-request
// escalation (DESIGN.md §12.3) must queue exactly one notification the first
// time a pull request is found stale, and must NOT queue another one on a
// later tick that finds the SAME pull request STILL stale (i.e. still in the
// SAME escalation.go tier) — the literal "sweep runs again... must NOT
// re-notify every sweep" case BACKLOG.md N1 itself describes, exercised here
// against the real production call site rather than internal/notify's own
// generic mechanism test. BACKLOG.md T3 widened the key with a tier suffix
// (escalation.go) — this age (2x the first tier) lands in the FIRST tier
// still (mergeStalenessThreshold itself), so the expected key gains a "48h"
// suffix but the "same tier twice is a no-op" property this test exists for
// is otherwise unchanged; TestApprovalAndMergeEscalationCrossTierBoundary
// covers the new "a LATER tick that crossed into the NEXT tier must
// escalate again" behavior this test does not.
func TestMergeSweeperEscalatesStalePRWithoutRefiringOnRepeatedTicks(t *testing.T) {
	pool := testPool(t)
	tenantID, clusterID, incidentID, _ := testIncident(t, pool, StateAwaitingMerge)
	ctx := context.Background()

	staleOutcome := PullRequestOutcome{
		Merged:    false,
		Closed:    false,
		CreatedAt: time.Now().Add(-2 * mergeStalenessThreshold),
	}
	sweeper := NewMergeSweeper(&data.DB{Pool: pool}, events.NewBus(), scopedMergeChecker{
		incidentID: incidentID,
		outcome:    staleOutcome,
	})

	wantKey := "AwaitingMerge:StalePR:" + escalationTierLabel(mergeStalenessThreshold)
	if err := sweeper.sweep(ctx); err != nil {
		t.Fatalf("first sweep: %v", err)
	}
	key1, pending, found := readNotification(t, pool, tenantID, clusterID, incidentID)
	if !found || !pending || key1 != wantKey {
		t.Fatalf("after first stale-PR sweep: key=%q pending=%v found=%v, want a pending row keyed %q", key1, pending, found, wantKey)
	}

	// Simulate internal/notify's own sweep having actually sent it.
	setNotificationPending(t, pool, tenantID, clusterID, incidentID, false)

	// A second, later tick observes the EXACT SAME still-stale pull request
	// (mergeStalenessThreshold's own check re-runs from scratch every tick,
	// exactly like the real 60s-interval poller) — must be a no-op.
	if err := sweeper.sweep(ctx); err != nil {
		t.Fatalf("second sweep: %v", err)
	}
	key2, pending, found := readNotification(t, pool, tenantID, clusterID, incidentID)
	if !found || pending || key2 != key1 {
		t.Fatalf("after a second sweep of the SAME still-stale pull request: key=%q pending=%v found=%v, want (%q, false, true) — repeated observation of an unchanged condition must not re-arm the notification", key2, pending, found, key1)
	}

	// The incident itself must not have moved — this branch never
	// transitions the incident, only escalates.
	if got := currentState(t, pool, tenantID, clusterID, incidentID); got != StateAwaitingMerge {
		t.Fatalf("incident state = %q after a stale-but-still-open pull request, want %q — escalation must not change the incident's state", got, StateAwaitingMerge)
	}
}
