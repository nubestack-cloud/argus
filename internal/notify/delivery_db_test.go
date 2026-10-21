package notify

// PROJECT.md B166's acceptance criterion: "a hanging webhook receiver cannot
// hold a database transaction, demonstrated against a deliberately
// unresponsive endpoint." These are that demonstration, plus the two
// properties the restructure had to preserve while getting there — a
// notification is never lost, and never re-sent for free.
//
// Same convention as the DB-backed tests in transitions_test.go (whose
// testPool helper these reuse): skip cleanly when ARGUS_TEST_DATABASE_URL
// isn't set, run under argus_app with FORCE ROW LEVEL SECURITY otherwise.
//
// # What makes these tests discriminating rather than decorative
//
// Every assertion below is one the PREVIOUS implementation would have
// failed, and each is read from a DIFFERENT database connection than the
// sweep's own, while a delivery is still hanging. That is the only way to
// ask the question honestly: "is a transaction open right now?" cannot be
// answered from inside the transaction. Three independent readings:
//
//  1. The claim is visible. Another connection can see notify_attempt_at set
//     on the row being delivered. Under the old shape nothing the sweep
//     touched was committed until every POST in the batch had returned, so
//     this could not be observed at all.
//  2. The previous row's OUTCOME is visible. The row delivered just before
//     the hanging one already reads as sent. Under the old shape that mark
//     sat in the same uncommitted transaction as the hanging POST.
//  3. No row lock is held. Another connection can UPDATE that previous row
//     under a 2s statement_timeout. Under the old shape the sweep's own
//     un-committed UPDATE of it held the row lock for as long as the
//     receiver felt like blocking, so this would have timed out.

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

// maxDeliverySweepTicks bounds the sweep loop these tests run, for the same
// reason TestNotifyTransitionDedupAcrossSweeps loops: both queues are
// fleet-wide and capped at notifyBatchSize per tick, so on a shared,
// concurrently-used development database this test's own rows can be pushed
// out of a single batch by whatever else is genuinely queued. The seeded rows
// are stamped far enough in the past to sort to the front of an oldest-first
// claim, so one tick is the normal case; the loop is insurance, not an
// expectation.
const maxDeliverySweepTicks = 10

// blockedPostTimeout is how long a test waits for the deliberately
// unresponsive receiver to be reached. Generous: it covers the whole
// claim-plus-deliver path, and being slow here is not the failure under test.
const blockedPostTimeout = 20 * time.Second

// seedUnnotifiedIncidents inserts one throwaway cluster and count incidents
// with notified_at NULL — the "a new incident happened" queue (migration
// 000017) as sweepIncidents finds it.
//
// first_seen is stamped well in the past on purpose. The claim query is
// fleet-wide and oldest-first, so old rows sort to the front of the batch,
// which is what lets these tests reason about delivery ORDER (assertion 2
// above needs one specific row to have been delivered before another) on a
// database that may hold other people's un-notified incidents.
func seedUnnotifiedIncidents(t *testing.T, pool *pgxpool.Pool, count int) (tenantID, clusterID string, incidentIDs []string) {
	t.Helper()
	ctx := context.Background()
	clusterID = domain.NewID(domain.PrefixCluster)

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
		clusterID, tenantID, "b166-test-"+clusterID, "fp-"+clusterID); err != nil {
		t.Fatalf("insert throwaway cluster: %v", err)
	}

	base := time.Now().Add(-100 * 24 * time.Hour)
	for i := 0; i < count; i++ {
		incidentID := domain.NewID(domain.PrefixIncident)
		if _, err := tx.Exec(ctx,
			`INSERT INTO incidents (id, tenant_id, cluster_id, fingerprint, severity, state, first_seen, last_seen, occurrence_count)
			 VALUES ($1, $2, $3, $4, 'high', 'Detected', $5, $5, 1)`,
			incidentID, tenantID, clusterID, "fp-"+incidentID, base.Add(time.Duration(i)*time.Minute)); err != nil {
			t.Fatalf("insert throwaway incident: %v", err)
		}
		incidentIDs = append(incidentIDs, incidentID)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit setup transaction: %v", err)
	}

	fixture := dbtest.New(t)
	fixture.Created("clusters", 1)
	fixture.Created("incidents", count)
	fixture.Cleanup(pool, func(ctx context.Context, tx pgx.Tx) error {
		return data.SetRequestScope(ctx, tx, tenantID, []string{clusterID})
	}, []dbtest.TableDelete{
		{Table: "incidents", SQL: `DELETE FROM incidents WHERE cluster_id = $1`, Args: []any{clusterID}},
		{Table: "clusters", SQL: `DELETE FROM clusters WHERE id = $1`, Args: []any{clusterID}},
	})
	return tenantID, clusterID, incidentIDs
}

// seedPendingTransitions inserts one throwaway cluster and count pending
// incident_notifications rows — the widened trigger set's queue (migration
// 000083) as sweepTransitions finds it.
//
// Inserted directly rather than through NotifyTransition so updated_at (this
// queue's ORDER BY key) is controlled explicitly, for the same
// delivery-ordering reason seedUnnotifiedIncidents backdates first_seen.
//
// A matching incidents row IS seeded for each notification, and that changed
// under PROJECT.md B175. This fixture used to insert notifications alone —
// "no incidents rows are needed: incident_notifications.incident_id carries
// no foreign key" — which is still true of the schema and is no longer true
// of the queue: claimTransitions now refuses to claim a notification whose
// incident does not exist, and reapOrphanedTransitions deletes it. Seeding
// notifications alone therefore seeded exactly the debris B175 is about, and
// these tests would have been asserting delivery of rows the product is
// supposed to drop.
func seedPendingTransitions(t *testing.T, pool *pgxpool.Pool, count int) (tenantID, clusterID string, incidentIDs []string) {
	t.Helper()
	ctx := context.Background()
	clusterID = domain.NewID(domain.PrefixCluster)

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
		clusterID, tenantID, "b166-test-"+clusterID, "fp-"+clusterID); err != nil {
		t.Fatalf("insert throwaway cluster: %v", err)
	}

	base := time.Now().Add(-100 * 24 * time.Hour)
	for i := 0; i < count; i++ {
		incidentID := domain.NewID(domain.PrefixIncident)
		// Stamped now() and terminal, NOT backdated to match the notification
		// below — see insertInertIncident for why a fixture incident that
		// looks realistic is what made this suite intermittently red. Only
		// the notification's own updated_at governs queue order.
		insertInertIncident(t, ctx, tx, tenantID, clusterID, incidentID)
		if _, err := tx.Exec(ctx,
			`INSERT INTO incident_notifications (incident_id, tenant_id, cluster_id, notify_key, summary, pending, updated_at)
			 VALUES ($1, $2, $3, $4, $5, true, $6)`,
			incidentID, tenantID, clusterID, "AwaitingApproval@b166",
			"Incident "+incidentID+" is now AwaitingApproval.",
			base.Add(time.Duration(i)*time.Minute)); err != nil {
			t.Fatalf("insert throwaway incident notification: %v", err)
		}
		incidentIDs = append(incidentIDs, incidentID)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit setup transaction: %v", err)
	}

	fixture := dbtest.New(t)
	fixture.Created("clusters", 1)
	fixture.Created("incidents", count)
	fixture.Created("incident_notifications", count)
	// Deleting incidents before clusters keeps the ordering the cluster_id
	// foreign key needs.
	fixture.OwnsCluster(tenantID, clusterID)
	fixture.Cleanup(pool, func(ctx context.Context, tx pgx.Tx) error {
		return data.SetRequestScope(ctx, tx, tenantID, []string{clusterID})
	}, []dbtest.TableDelete{
		{Table: "incident_notifications", SQL: `DELETE FROM incident_notifications WHERE cluster_id = $1`, Args: []any{clusterID}},
		{Table: "incidents", SQL: `DELETE FROM incidents WHERE cluster_id = $1`, Args: []any{clusterID}},
		{Table: "clusters", SQL: `DELETE FROM clusters WHERE id = $1`, Args: []any{clusterID}},
	})
	return tenantID, clusterID, incidentIDs
}

// readIncidentDelivery reports one incident's delivery state as a DIFFERENT
// connection sees it: whether a claim is recorded, and whether the row is
// marked notified. Read in its own transaction, which is the point — an
// uncommitted claim or mark is invisible from here.
func readIncidentDelivery(t *testing.T, pool *pgxpool.Pool, tenantID, clusterID, incidentID string) (claimed, notified bool) {
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
		`SELECT notify_attempt_at IS NOT NULL, notified_at IS NOT NULL FROM incidents WHERE id = $1`,
		incidentID).Scan(&claimed, &notified); err != nil {
		t.Fatalf("read incident %s delivery state: %v", incidentID, err)
	}
	return claimed, notified
}

// readTransitionDelivery is readIncidentDelivery's counterpart for the
// transition queue, and also reports `pending`, which is that queue's
// "still needs sending" flag.
func readTransitionDelivery(t *testing.T, pool *pgxpool.Pool, tenantID, clusterID, incidentID string) (pending, claimed, notified bool) {
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
		`SELECT pending, notify_attempt_at IS NOT NULL, notified_at IS NOT NULL
		   FROM incident_notifications WHERE incident_id = $1`,
		incidentID).Scan(&pending, &claimed, &notified); err != nil {
		t.Fatalf("read notification %s delivery state: %v", incidentID, err)
	}
	return pending, claimed, notified
}

// requireNoRowLock is assertion 3: take a row lock on a row the sweep has
// already delivered, from another connection, under a short
// statement_timeout, and require it to succeed immediately.
//
// `SET x = x` still writes a new row version and therefore still takes the
// same lock a real UPDATE would, which is what makes this a lock test that
// changes no data the caller has to account for.
func requireNoRowLock(t *testing.T, pool *pgxpool.Pool, tenantID, clusterID, table, keyColumn, key string) {
	t.Helper()
	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin lock-probe transaction: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if err := data.SetRequestScope(ctx, tx, tenantID, []string{clusterID}); err != nil {
		t.Fatalf("set request scope: %v", err)
	}
	if _, err := tx.Exec(ctx, `SET LOCAL statement_timeout = '2s'`); err != nil {
		t.Fatalf("set statement timeout: %v", err)
	}
	if _, err := tx.Exec(ctx,
		`UPDATE `+table+` SET tenant_id = tenant_id WHERE `+keyColumn+` = $1`, key); err != nil {
		t.Fatalf("another connection could not take the row lock on %s %s within 2s — the sweep is still holding a transaction across the webhook POST: %v", table, key, err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit lock probe: %v", err)
	}
}

// blockingWebhook is a receiver that answers one nominated incident's POST by
// never answering at all until the test lets it, and answers everything else
// immediately.
//
// "Everything else" matters on a shared database: both queues are fleet-wide,
// so a sweep may legitimately deliver other people's rows in the same batch,
// and they must not block or be counted.
type blockingWebhook struct {
	srv      *httptest.Server
	arrived  chan string
	release  chan struct{}
	released bool
	posts    atomic.Int64
}

func newBlockingWebhook(t *testing.T, blockOn string, count ...string) *blockingWebhook {
	t.Helper()
	w := &blockingWebhook{arrived: make(chan string, 16), release: make(chan struct{})}
	counted := append([]string{blockOn}, count...)
	w.srv = httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		var decoded map[string]string
		_ = json.NewDecoder(r.Body).Decode(&decoded)
		text := decoded["text"]
		for _, id := range counted {
			if strings.Contains(text, id) {
				w.posts.Add(1)
				w.arrived <- id
				break
			}
		}
		if strings.Contains(text, blockOn) {
			// The deliberately unresponsive endpoint the board row asks for.
			<-w.release
		}
		rw.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(func() {
		w.Release()
		w.srv.Close()
	})
	return w
}

// Release unblocks the receiver. Idempotent, and registered as cleanup too,
// so a failed assertion can never leave the sweep goroutine parked forever.
func (w *blockingWebhook) Release() {
	if !w.released {
		w.released = true
		close(w.release)
	}
}

// waitForPost blocks until the receiver reports a POST mentioning id.
func (w *blockingWebhook) waitForPost(t *testing.T, id string) {
	t.Helper()
	deadline := time.After(blockedPostTimeout)
	for {
		select {
		case got := <-w.arrived:
			if got == id {
				return
			}
		case <-deadline:
			t.Fatalf("no webhook POST mentioning %s arrived within %s", id, blockedPostTimeout)
		}
	}
}

func TestIncidentQueueHoldsNoTransactionAcrossAnUnresponsiveReceiver(t *testing.T) {
	pool := testPool(t)
	tenantID, clusterID, ids := seedUnnotifiedIncidents(t, pool, 2)
	first, second := ids[0], ids[1]
	ctx := context.Background()

	hook := newBlockingWebhook(t, second, first)
	n := NewWebhookNotifier(&data.DB{Pool: pool})

	swept := make(chan error, 1)
	go func() {
		for i := 0; i < maxDeliverySweepTicks; i++ {
			if err := n.sweepIncidents(ctx, tenantID, defaultRouting(hook.srv.URL)); err != nil {
				swept <- err
				return
			}
			if hook.posts.Load() >= 2 {
				break
			}
		}
		swept <- nil
	}()

	// Delivery of `second` is now in flight and will not return until this
	// test says so. Everything below is read while it hangs.
	hook.waitForPost(t, second)

	// 1. The intent is committed: the claim for the in-flight row is visible
	//    from another connection, and it is NOT recorded as delivered.
	claimed, notified := readIncidentDelivery(t, pool, tenantID, clusterID, second)
	if !claimed {
		t.Errorf("incident %s: notify_attempt_at is NULL while its POST is in flight — the intent was not committed before delivery, so a hub crash here would lose the notification", second)
	}
	if notified {
		t.Errorf("incident %s: notified_at is set while its POST has not returned — a claim must never be recorded as a delivery", second)
	}

	// 2. The row delivered just before it is already recorded as sent, seen
	//    from another connection. This is the assertion the old
	//    one-transaction-per-sweep shape could not pass.
	if _, notifiedFirst := readIncidentDelivery(t, pool, tenantID, clusterID, first); !notifiedFirst {
		t.Errorf("incident %s was POSTed successfully but is not yet marked notified from another connection — its outcome is sitting in a transaction that is still open across %s's webhook POST", first, second)
	}

	// 3. And no row lock is held across the POST either.
	requireNoRowLock(t, pool, tenantID, clusterID, "incidents", "id", first)

	hook.Release()
	if err := <-swept; err != nil {
		t.Fatalf("sweepIncidents: %v", err)
	}

	// Both rows end delivered, recorded, and unclaimed — exactly once each.
	for _, id := range ids {
		claimed, notified := readIncidentDelivery(t, pool, tenantID, clusterID, id)
		if !notified {
			t.Errorf("incident %s was never marked notified", id)
		}
		if claimed {
			t.Errorf("incident %s still carries a delivery claim after its outcome was recorded", id)
		}
	}
	if got := hook.posts.Load(); got != 2 {
		t.Errorf("webhook received %d POSTs for this test's two incidents, want exactly 2", got)
	}
}

func TestTransitionQueueHoldsNoTransactionAcrossAnUnresponsiveReceiver(t *testing.T) {
	pool := testPool(t)
	tenantID, clusterID, ids := seedPendingTransitions(t, pool, 2)
	first, second := ids[0], ids[1]
	ctx := context.Background()

	hook := newBlockingWebhook(t, second, first)
	n := NewWebhookNotifier(&data.DB{Pool: pool})

	swept := make(chan error, 1)
	go func() {
		for i := 0; i < maxDeliverySweepTicks; i++ {
			if err := n.sweepTransitions(ctx, tenantID, defaultRouting(hook.srv.URL)); err != nil {
				swept <- err
				return
			}
			if hook.posts.Load() >= 2 {
				break
			}
		}
		swept <- nil
	}()

	hook.waitForPost(t, second)

	// The same three readings as the incident-queue test above, against the
	// other queue's own table and SQL — see that test for what each one rules
	// out.
	pending, claimed, notified := readTransitionDelivery(t, pool, tenantID, clusterID, second)
	if !claimed {
		t.Errorf("notification %s: notify_attempt_at is NULL while its POST is in flight — the intent was not committed before delivery", second)
	}
	if !pending {
		t.Errorf("notification %s: pending was cleared before its POST returned", second)
	}
	if notified {
		t.Errorf("notification %s: notified_at is set while its POST has not returned", second)
	}

	if pendingFirst, _, _ := readTransitionDelivery(t, pool, tenantID, clusterID, first); pendingFirst {
		t.Errorf("notification %s was POSTed successfully but still reads pending from another connection — its outcome is sitting in a transaction still open across %s's webhook POST", first, second)
	}

	requireNoRowLock(t, pool, tenantID, clusterID, "incident_notifications", "incident_id", first)

	hook.Release()
	if err := <-swept; err != nil {
		t.Fatalf("sweepTransitions: %v", err)
	}

	for _, id := range ids {
		pending, claimed, notified := readTransitionDelivery(t, pool, tenantID, clusterID, id)
		if pending || !notified {
			t.Errorf("notification %s ended pending=%v notified=%v, want pending=false notified=true", id, pending, notified)
		}
		if claimed {
			t.Errorf("notification %s still carries a delivery claim after its outcome was recorded", id)
		}
	}
	if got := hook.posts.Load(); got != 2 {
		t.Errorf("webhook received %d POSTs for this test's two notifications, want exactly 2", got)
	}
}

// TestClaimedDeliveryThatNeverReportsBackIsRetriedNotLostAndNotResentEarly is
// the other half of B166: moving the POST outside the transaction is only
// correct if a hub that dies in the new gap — after the claim commits,
// before the outcome is recorded — neither loses the notification nor
// re-sends it for free.
//
// The crash is simulated exactly, by doing what a dead process does: claim
// the work, then nothing. Both queues share one lease mechanism
// (notifyAttemptLease, and the identical predicate in claimIncidents and
// claimTransitions), so this exercises it through the transition queue only.
func TestClaimedDeliveryThatNeverReportsBackIsRetriedNotLostAndNotResentEarly(t *testing.T) {
	pool := testPool(t)
	tenantID, clusterID, ids := seedPendingTransitions(t, pool, 1)
	incidentID := ids[0]
	ctx := context.Background()

	n := NewWebhookNotifier(&data.DB{Pool: pool})

	claimed, err := n.claimTransitions(ctx, tenantID)
	if err != nil {
		t.Fatalf("claimTransitions: %v", err)
	}
	if !containsIncident(claimed, incidentID) {
		t.Fatalf("claimTransitions did not return the seeded pending notification %s", incidentID)
	}
	// ... and here the hub dies. No POST, no outcome write.

	// Not lost: the row still says it needs sending, and now carries an
	// intent record rather than a delivered one.
	pending, hasClaim, notified := readTransitionDelivery(t, pool, tenantID, clusterID, incidentID)
	if !pending || notified {
		t.Fatalf("notification %s reads pending=%v notified=%v after a claim with no delivery, want pending=true notified=false — a claim must never be recorded as a delivery", incidentID, pending, notified)
	}
	if !hasClaim {
		t.Fatalf("notification %s carries no notify_attempt_at after being claimed — the intent was not committed, so nothing distinguishes a crashed delivery from an untried one", incidentID)
	}

	// Not re-sent early: the very next tick must not hand the same row to a
	// second sender while the claim is still young. This is what bounds the
	// duplicate window to one resend per crash instead of one per tick.
	again, err := n.claimTransitions(ctx, tenantID)
	if err != nil {
		t.Fatalf("second claimTransitions: %v", err)
	}
	if containsIncident(again, incidentID) {
		t.Fatalf("notification %s was re-claimed on the next tick despite a live %s claim — a slow-but-successful delivery would be duplicated", incidentID, notifyAttemptLease)
	}

	// Once the claim ages past the lease, it comes back — and is delivered
	// exactly once, not once per tick.
	ageTransitionClaim(t, pool, tenantID, clusterID, incidentID, notifyAttemptLease+time.Minute)

	var posts atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var decoded map[string]string
		_ = json.NewDecoder(r.Body).Decode(&decoded)
		if strings.Contains(decoded["text"], incidentID) {
			posts.Add(1)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	for i := 0; i < maxDeliverySweepTicks; i++ {
		if err := n.sweepTransitions(ctx, tenantID, defaultRouting(srv.URL)); err != nil {
			t.Fatalf("sweepTransitions: %v", err)
		}
		if posts.Load() >= 1 {
			break
		}
	}
	if got := posts.Load(); got != 1 {
		t.Fatalf("after the claim expired the notification was POSTed %d times, want exactly 1", got)
	}
	// One more tick: the recovered delivery is terminal, not a row that now
	// re-sends every lease window.
	if err := n.sweepTransitions(ctx, tenantID, defaultRouting(srv.URL)); err != nil {
		t.Fatalf("sweepTransitions: %v", err)
	}
	if got := posts.Load(); got != 1 {
		t.Fatalf("notification %s was re-sent after being recorded as delivered: %d POSTs, want 1", incidentID, got)
	}
	pending, hasClaim, notified = readTransitionDelivery(t, pool, tenantID, clusterID, incidentID)
	if pending || hasClaim || !notified {
		t.Errorf("notification %s ended pending=%v claimed=%v notified=%v, want false/false/true", incidentID, pending, hasClaim, notified)
	}
}

func containsIncident(rows []transitionRow, incidentID string) bool {
	for _, row := range rows {
		if row.IncidentID == incidentID {
			return true
		}
	}
	return false
}

// ageTransitionClaim backdates one row's claim, standing in for the wall-clock
// passage of notifyAttemptLease. Backdating the row rather than sleeping for
// fifteen minutes is the only practical option, and it exercises the real
// predicate: claimTransitions compares notify_attempt_at against
// now() - notifyAttemptLease in SQL, so a backdated stamp is
// indistinguishable from an old one.
func ageTransitionClaim(t *testing.T, pool *pgxpool.Pool, tenantID, clusterID, incidentID string, by time.Duration) {
	t.Helper()
	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin claim-ageing transaction: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if err := data.SetRequestScope(ctx, tx, tenantID, []string{clusterID}); err != nil {
		t.Fatalf("set request scope: %v", err)
	}
	if _, err := tx.Exec(ctx,
		`UPDATE incident_notifications
		    SET notify_attempt_at = now() - make_interval(secs => $2)
		  WHERE incident_id = $1`,
		incidentID, by.Seconds()); err != nil {
		t.Fatalf("age claim on %s: %v", incidentID, err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit claim ageing: %v", err)
	}
}
