package notify

// PROJECT.md B175's acceptance criterion: "the notify sweeper stops retrying
// dead incidents." These are that demonstration.
//
// The measurement that opened the board item, taken read-only against this
// repository's development database as role `postgres`: 1,223 of 1,233
// incident_notifications rows named an incident that no longer existed, 39 of
// them still pending = true, and all 39 carried a notify_attempt_at — the
// sweeper had claimed them for delivery. Nothing about that state is exotic;
// internal/partition's retention job destroys incidents by DROP TABLE on a
// whole dated partition, so a production hub manufactures orphans on a
// schedule. The queue has to survive that, which is why the fix is here and
// not in a foreign key (see reapOrphanedTransitions' doc comment for the two
// measurements that rule one out).
//
// Two properties, tested separately because they fail separately:
//
//  1. A notification whose incident is gone is never CLAIMED, so it is never
//     POSTed. This is the one that stops the retry.
//  2. It is eventually DELETED, so the queue does not grow a permanent tail
//     of rows property 1 has to skip past on every 30-second tick forever.
//
// Same convention as this package's other DB-backed tests: skip cleanly when
// ARGUS_TEST_DATABASE_URL isn't set, run under argus_app with FORCE ROW LEVEL
// SECURITY otherwise.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"argus/internal/data"
	"argus/internal/dbtest"
	"argus/internal/domain"
)

// orphanFixture seeds one throwaway cluster carrying:
//
//   - one live incident with a pending notification, stamped updated_at = T;
//   - orphanCount pending notifications naming incidents that do not exist,
//     each stamped strictly EARLIER than T.
//
// The ordering is the point, and it is what makes these tests discriminating
// rather than decorative. claimTransitions claims fleet-wide, oldest
// updated_at first, capped at notifyBatchSize — so a test that merely
// observed "no POST mentioned the orphan" could be passing because the orphan
// sat behind a batch boundary and was never reached at all. Putting the
// orphans strictly in FRONT of the live row means a delivered live row proves
// the claim went past every orphan's position and declined to take it. The
// old code would have claimed and POSTed the orphans and left the live row
// for the next tick.
//
// orphanAge is how far back from NOW the orphan rows' updated_at is stamped,
// which is how a caller chooses whether reapOrphanedTransitions considers them
// eligible. The live row is stamped one minute AFTER the newest orphan, so the
// ordering property above holds whatever age is chosen.
func orphanFixture(t *testing.T, pool *pgxpool.Pool, orphanCount int, orphanAge time.Duration) (tenantID, clusterID, liveIncidentID string, orphanIDs []string) {
	t.Helper()
	ctx := context.Background()
	clusterID = domain.NewID(domain.PrefixCluster)
	liveIncidentID = domain.NewID(domain.PrefixIncident)

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin setup transaction: %v", err)
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
		clusterID, tenantID, "b175-test-"+clusterID, "fp-"+clusterID); err != nil {
		t.Fatalf("insert throwaway cluster: %v", err)
	}

	// Both the orphans and the live row are positioned relative to one
	// instant, so the caller's orphanAge cannot accidentally reorder them.
	// A caller that wants the whole set at the front of a fleet-wide,
	// oldest-first claim on a shared development database passes a large
	// orphanAge, exactly as this package's other fixtures backdate.
	oldestOrphanAt := time.Now().Add(-orphanAge)
	liveAt := oldestOrphanAt.Add(time.Minute)
	// liveAt positions the NOTIFICATION in the queue; the incident itself is
	// stamped now() and terminal regardless — see insertInertIncident for why
	// a fixture must never leave a realistic-looking incident where another
	// package's fleet-wide sweeper can find it.
	insertInertIncident(t, ctx, tx, tenantID, clusterID, liveIncidentID)
	if _, err := tx.Exec(ctx,
		`INSERT INTO incident_notifications (incident_id, tenant_id, cluster_id, notify_key, summary, pending, updated_at)
		 VALUES ($1, $2, $3, 'AwaitingApproval@b175-live', $4, true, $5)`,
		liveIncidentID, tenantID, clusterID,
		"Incident "+liveIncidentID+" is now AwaitingApproval.", liveAt); err != nil {
		t.Fatalf("insert live incident notification: %v", err)
	}

	// No incidents rows for these, deliberately — that IS the fixture.
	for i := 0; i < orphanCount; i++ {
		orphanID := domain.NewID(domain.PrefixIncident)
		if _, err := tx.Exec(ctx,
			`INSERT INTO incident_notifications (incident_id, tenant_id, cluster_id, notify_key, summary, pending, updated_at)
			 VALUES ($1, $2, $3, 'AwaitingApproval@b175-orphan', $4, true, $5)`,
			orphanID, tenantID, clusterID,
			"Incident "+orphanID+" is now AwaitingApproval.",
			// Strictly earlier than liveAt, so every orphan sits in front of
			// the live row in the claim's ORDER BY.
			oldestOrphanAt.Add(-time.Duration(i)*time.Minute)); err != nil {
			t.Fatalf("insert orphaned incident notification: %v", err)
		}
		orphanIDs = append(orphanIDs, orphanID)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit setup transaction: %v", err)
	}

	fixture := dbtest.New(t)
	fixture.Created("clusters", 1)
	fixture.Created("incidents", 1)
	// Only the LIVE notification is tracked here. The orphan rows are removed
	// by the t.Cleanup registered below instead, because whether they still
	// exist is the very thing TestOrphanedNotificationsAreReaped is asserting
	// — a fixed expected count for them would be an assertion about the
	// product's behaviour smuggled into the cleanup, and would fail the
	// cleanup rather than the test when it was wrong. Their removal is by
	// primary-key equality on ids this test itself minted, which is the one
	// predicate shape that cannot be mis-scoped, and OwnsCluster's residue
	// check below still refuses to let anything at all survive.
	fixture.Created("incident_notifications", 1)
	fixture.OwnsCluster(tenantID, clusterID)
	fixture.Cleanup(pool, func(ctx context.Context, tx pgx.Tx) error {
		return data.SetRequestScope(ctx, tx, tenantID, []string{clusterID})
	}, []dbtest.TableDelete{
		{Table: "incident_notifications", SQL: `DELETE FROM incident_notifications WHERE cluster_id = $1 AND incident_id = $2`, Args: []any{clusterID, liveIncidentID}},
		{Table: "incidents", SQL: `DELETE FROM incidents WHERE cluster_id = $1`, Args: []any{clusterID}},
		{Table: "clusters", SQL: `DELETE FROM clusters WHERE id = $1`, Args: []any{clusterID}},
	})

	// Registered AFTER fixture.Cleanup on purpose: t.Cleanup runs LIFO, so
	// this runs FIRST, and the fixture's own count-checked deletes (and the
	// residue check that follows them) then see exactly the state they expect.
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		_ = data.InScope(ctx, pool, tenantID, []string{clusterID}, func(ctx context.Context, tx pgx.Tx) error {
			_, err := tx.Exec(ctx, `DELETE FROM incident_notifications WHERE incident_id = ANY($1)`, orphanIDs)
			return err
		})
	})

	return tenantID, clusterID, liveIncidentID, orphanIDs
}

// readOrphanClaim reports whether a notification row still exists and, if so,
// whether a delivery was ever claimed against it. Read from its own
// transaction, like this package's other cross-connection readers.
func readOrphanClaim(t *testing.T, pool *pgxpool.Pool, tenantID, clusterID, incidentID string) (exists, claimed bool) {
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
	if err := tx.QueryRow(ctx,
		`SELECT count(*) > 0, coalesce(bool_or(notify_attempt_at IS NOT NULL), false)
		   FROM incident_notifications WHERE incident_id = $1`,
		incidentID).Scan(&exists, &claimed); err != nil {
		t.Fatalf("read notification %s: %v", incidentID, err)
	}
	return exists, claimed
}

// TestOrphanedNotificationIsNeverClaimedOrDelivered is B175's central
// property: a queued notification whose incident no longer exists is not
// attempted.
//
// Three readings, because "no POST arrived" alone is too weak — it is equally
// consistent with the sweep never having got that far:
//
//   - the LIVE notification behind the orphans in the queue IS delivered, so
//     the claim demonstrably reached past them;
//   - no POST mentioned any orphan;
//   - no orphan carries a notify_attempt_at afterwards, i.e. it was not
//     claimed-then-failed, it was never claimed. That is the difference
//     between "the webhook rejected it" and "the sweeper declined to try",
//     and only the second one stops a retry on the next tick.
//
// This drives sweepTransitions, which never reaps — so the orphan rows are
// still present afterwards to be inspected, and the claim guard is what is
// under test here rather than reapOrphanedTransitions.
func TestOrphanedNotificationIsNeverClaimedOrDelivered(t *testing.T) {
	pool := testPool(t)
	tenantID, clusterID, liveIncidentID, orphanIDs := orphanFixture(t, pool, 3, 100*24*time.Hour)
	ctx := context.Background()

	var liveDelivered atomic.Bool
	var orphanPosts atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var decoded map[string]string
		_ = json.NewDecoder(r.Body).Decode(&decoded)
		text := decoded["text"]
		if strings.Contains(text, liveIncidentID) {
			liveDelivered.Store(true)
		}
		for _, id := range orphanIDs {
			if strings.Contains(text, id) {
				orphanPosts.Add(1)
			}
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	n := NewWebhookNotifier(&data.DB{Pool: pool})
	// sweepTransitions directly rather than sweep(), for the reason
	// TestNotifyTransitionDedupAcrossSweeps gives: a shared development
	// database has real un-notified incidents in the OTHER queue, and this
	// test is about this one. Looped for the batch-cap reason the other
	// delivery tests loop.
	for i := 0; i < maxDeliverySweepTicks && !liveDelivered.Load(); i++ {
		if err := n.sweepTransitions(ctx, tenantID, defaultRouting(srv.URL)); err != nil {
			t.Fatalf("sweepTransitions: %v", err)
		}
	}

	if !liveDelivered.Load() {
		t.Fatalf("the live incident's notification was never delivered, so this test proves nothing about the orphans in front of it in the queue")
	}
	if got := orphanPosts.Load(); got != 0 {
		t.Errorf("the sweeper POSTed %d notification(s) for incidents that do not exist; want 0 — a reader following that message finds nothing", got)
	}
	for _, id := range orphanIDs {
		exists, claimed := readOrphanClaim(t, pool, tenantID, clusterID, id)
		if !exists {
			t.Errorf("orphaned notification %s was deleted during this test; sweepTransitions must deliver, not reap", id)
			continue
		}
		if claimed {
			t.Errorf("orphaned notification %s carries notify_attempt_at — it was claimed for delivery and merely failed, so it is eligible again once the lease expires. It must never be claimed at all", id)
		}
	}
}

// TestOrphanedNotificationsAreReaped is the other half: the queue does not
// keep them forever.
//
// Without this, claimTransitions' EXISTS guard would turn every orphan into a
// row the claim's ORDER BY has to sort and skip on every 30-second tick for
// the life of the deployment — 1,223 of them on this repository's own
// development database, growing by however many incidents retention drops
// each month.
func TestOrphanedNotificationsAreReaped(t *testing.T) {
	pool := testPool(t)
	// Stamped well past notifyOrphanGrace, which is what makes them eligible.
	tenantID, clusterID, liveIncidentID, orphanIDs := orphanFixture(t, pool, 3, 100*24*time.Hour)
	ctx := context.Background()

	n := NewWebhookNotifier(&data.DB{Pool: pool})
	reaped, err := n.reapOrphanedTransitions(ctx, tenantID)
	if err != nil {
		t.Fatalf("reapOrphanedTransitions: %v", err)
	}
	// Fleet-wide, like every other query in this package, so a shared
	// development database may hand back other people's orphans too. This
	// test's own three are what it can assert on.
	if reaped < int64(len(orphanIDs)) {
		t.Errorf("reapOrphanedTransitions deleted %d row(s), want at least %d", reaped, len(orphanIDs))
	}
	for _, id := range orphanIDs {
		if exists, _ := readOrphanClaim(t, pool, tenantID, clusterID, id); exists {
			t.Errorf("orphaned notification %s survived the reap", id)
		}
	}

	// The live one is the control: a reaper that deleted everything would
	// pass every assertion above and silently destroy the queue.
	if exists, _ := readOrphanClaim(t, pool, tenantID, clusterID, liveIncidentID); !exists {
		t.Fatalf("the reap deleted the notification for incident %s, which still exists — this predicate is matching live rows", liveIncidentID)
	}
}

// TestReapLeavesRecentOrphansAlone pins notifyOrphanGrace down as real
// behaviour rather than an unused constant. A notification queued moments ago
// for an incident the reader cannot see is the shape a future caller would
// produce if it ever queued a notification outside its incident's own
// transaction, and deleting it immediately would silently lose a real
// notification rather than send it late.
func TestReapLeavesRecentOrphansAlone(t *testing.T) {
	pool := testPool(t)
	tenantID, clusterID, _, orphanIDs := orphanFixture(t, pool, 1, notifyOrphanGrace/2)
	ctx := context.Background()

	n := NewWebhookNotifier(&data.DB{Pool: pool})
	if _, err := n.reapOrphanedTransitions(ctx, tenantID); err != nil {
		t.Fatalf("reapOrphanedTransitions: %v", err)
	}
	if exists, _ := readOrphanClaim(t, pool, tenantID, clusterID, orphanIDs[0]); !exists {
		t.Errorf("an orphan stamped inside notifyOrphanGrace (%s) was reaped; the grace window is not being applied", notifyOrphanGrace)
	}
}
