package notify

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"argus/internal/data"
	"argus/internal/dbtest"
	"argus/internal/domain"
)

// TestTransitionPayload is the DB-free pin on transitionRow.payload's shape
// and content, matching TestPayloadIncludesEveryField's own role for
// incidentRow in notifier_test.go.
func TestTransitionPayload(t *testing.T) {
	row := transitionRow{
		IncidentID: "inc_01example",
		NotifyKey:  "AwaitingApproval@2026-08-31T12:00:00Z",
		Summary:    "Incident inc_01example (cluster cl_x, fingerprint fp_x) is now AwaitingApproval.",
	}
	body, err := row.payload()
	if err != nil {
		t.Fatalf("payload: %v", err)
	}
	var decoded map[string]string
	if err := json.Unmarshal(body, &decoded); err != nil {
		t.Fatalf("payload did not produce valid JSON: %v", err)
	}
	text, ok := decoded["text"]
	if !ok {
		t.Fatalf("payload JSON has no \"text\" key (Slack incoming-webhook shape) — got %v", decoded)
	}
	for _, want := range []string{row.IncidentID, row.Summary} {
		if !strings.Contains(text, want) {
			t.Errorf("payload text %q does not contain %q", text, want)
		}
	}
}

// --- DB-backed tests: real Postgres, real webhook receiver -----------------
//
// Same convention as internal/orchestrator/db_test.go: skip cleanly when
// ARGUS_TEST_DATABASE_URL isn't set, run under argus_app (FORCE ROW LEVEL
// SECURITY) otherwise.

func testPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	connString := os.Getenv("ARGUS_TEST_DATABASE_URL")
	if connString == "" {
		t.Skip("ARGUS_TEST_DATABASE_URL not set; skipping DB-backed notify tests")
	}
	pool, err := pgxpool.New(context.Background(), connString)
	if err != nil {
		t.Fatalf("connect to test database: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

// insertInertIncident inserts the incidents row a queued notification needs in
// order to be deliverable at all, in a shape no OTHER package's sweeper will
// act on. Every fixture in this package that seeds an incident_notifications
// row goes through it.
//
// # Why this exists, and why "inert" is the whole requirement
//
// PROJECT.md B175 gave claimTransitions an `EXISTS (SELECT 1 FROM incidents
// ...)` guard, so these fixtures had to start seeding a real incident instead
// of a notification with nothing behind it. The first version of that seeded
// what looked like the most realistic incident available — state
// 'AwaitingApproval', first_seen backdated 100 days so the row would sort to
// the front of a fleet-wide, oldest-first queue — and that made the notify
// suite intermittently red under `go test ./...`, though never when the
// package was run alone.
//
// The cause, confirmed by reading the leftover rows out of the test database:
// orchestrator.ApprovalSweeper (internal/orchestrator/approvalwatch.go) polls
// `WHERE i.state = 'AwaitingApproval'` FLEET-WIDE, measures the stint from
// i.first_seen when an incident has no timeline events or recommendations —
// exactly a fixture's case — and calls notify.NotifyTransition on anything
// past an escalation tier. A 100-day-old AwaitingApproval incident is four
// tiers past, so it got a fresh notification keyed
// 'AwaitingApproval:Stale:96d'. Its tests run in a different package, which
// `go test ./...` runs CONCURRENTLY against the same database and the same
// single organisation every test in this repo shares.
//
// Two distinct failures came out of that, and both are the sweeper doing its
// job correctly to a row that happened to belong to a test:
//
//   - NotifyTransition with a DIFFERENT key sets pending back to true and
//     clears notify_attempt_at (transitions.go's ON CONFLICT guard), which
//     breaks every assertion here about claims and re-delivery — and the
//     escalation's own summary names the incident id, so a content-filtered
//     counter counts it as a duplicate of this test's own message.
//   - The escalation re-INSERTS a row for an incident a fixture has just
//     deleted (incident_notifications carries no foreign key, by design —
//     migration 000083), so the row reappears after cleanup committed and
//     AssertNoClusterResidue reports a leak that no delete list could have
//     prevented.
//
// This is a pre-existing fragility — one organisation, several fleet-wide
// sweepers, packages running in parallel — that a realistic fixture merely
// made reachable. The fix belongs here rather than in the sweeper: an
// incident that has genuinely sat unapproved for 100 days SHOULD escalate,
// and nothing about that is a defect.
//
// So the incident these fixtures need is one that exists and nothing else
// wants:
//
//   - state 'Dismissed' — terminal. ApprovalSweeper keys on
//     'AwaitingApproval', MergeSweeper on 'AwaitingMerge', ValidationSweeper
//     on 'Validating', and internal/autoanalyze's candidate query names
//     'Dismissed' in its own NOT IN exclusion list. It is also the one thing
//     claimTransitions does NOT care about: the guard asks whether the
//     incident exists, never what state it is in.
//   - first_seen/last_seen = now() — no age-based escalation can fire even if
//     some future sweeper does look at a closed incident, and the row lands
//     in the current month's partition the way a real one does. Queue
//     ORDERING is unaffected: that is incident_notifications.updated_at,
//     which each fixture still sets for itself.
//   - notified_at = now() — keeps it out of the OTHER fleet-wide queue as
//     well. Left NULL it would join sweepIncidents' backlog, where this
//     package's own metrics test POSTs every un-notified incident in the
//     tenant to a deliberately-500 receiver.
func insertInertIncident(t *testing.T, ctx context.Context, tx pgx.Tx, tenantID, clusterID, incidentID string) {
	t.Helper()
	if _, err := tx.Exec(ctx,
		`INSERT INTO incidents (id, tenant_id, cluster_id, fingerprint, severity, state, first_seen, last_seen, occurrence_count, notified_at)
		 VALUES ($1, $2, $3, $4, 'high', 'Dismissed', now(), now(), 1, now())`,
		incidentID, tenantID, clusterID, "fp-"+incidentID); err != nil {
		t.Fatalf("insert throwaway incident: %v", err)
	}
}

// testCluster inserts a throwaway cluster and one throwaway incident on it,
// and registers cleanup. It returns the incident id because the caller needs
// to queue notifications against a REAL incident: under PROJECT.md B175
// claimTransitions refuses to claim a notification whose incident does not
// exist, so the old shape here — a cluster and nothing else, on the grounds
// that "incident_notifications.incident_id carries no foreign key" (still
// true of the schema, see migration 000083) — now seeds a row the sweep is
// supposed to drop rather than deliver.
//
// incident_notifications is tracked as exactly 1 row: NotifyTransition
// (transitions.go) UPSERTs on incident_id (that column's own PRIMARY KEY —
// confirmed against migration 000083), so no matter how many times
// TestNotifyTransitionDedupAcrossSweeps below calls notify()/sweeps for this
// test's one incidentID, at most one row for it can ever exist — never more,
// from the very first call onward.
func testCluster(t *testing.T, pool *pgxpool.Pool) (tenantID, clusterID, incidentID string) {
	t.Helper()
	ctx := context.Background()
	clusterID = domain.NewID(domain.PrefixCluster)
	incidentID = domain.NewID(domain.PrefixIncident)

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
		clusterID, tenantID, "notify-test-"+clusterID, "fp-"+clusterID); err != nil {
		t.Fatalf("insert throwaway cluster: %v", err)
	}
	insertInertIncident(t, ctx, tx, tenantID, clusterID, incidentID)
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit setup transaction: %v", err)
	}

	fixture := dbtest.New(t)
	fixture.Created("clusters", 1)
	fixture.Created("incidents", 1)
	fixture.Created("incident_notifications", 1)
	fixture.OwnsCluster(tenantID, clusterID)
	fixture.Cleanup(pool, func(ctx context.Context, tx pgx.Tx) error {
		return data.SetRequestScope(ctx, tx, tenantID, []string{clusterID})
	}, []dbtest.TableDelete{
		{Table: "incident_notifications", SQL: `DELETE FROM incident_notifications WHERE cluster_id = $1`, Args: []any{clusterID}},
		{Table: "incidents", SQL: `DELETE FROM incidents WHERE cluster_id = $1`, Args: []any{clusterID}},
		{Table: "clusters", SQL: `DELETE FROM clusters WHERE id = $1`, Args: []any{clusterID}},
	})
	return tenantID, clusterID, incidentID
}

// TestNotifyTransitionDedupAcrossSweeps is the task's own required property
// test: construct a sequence of transitions and assert the notify CALL COUNT
// and CONTENT match DESIGN.md §13.3's "one notification per incident,
// updated in place, not one per event" rule — not just that some
// notification eventually fired.
//
// Runs the real WebhookNotifier.sweep against a real httptest.Server, so
// this is also this task's "verify live" leg for the delivery path itself
// (a real HTTP POST arriving at a real listener), standing in for a live
// Slack/webhook target the way internal/api/settings_test.go's
// "https://example.invalid/hook" fixtures stand in elsewhere in this
// codebase, except this one actually receives the request rather than just
// asserting a URL string round-trips.
func TestNotifyTransitionDedupAcrossSweeps(t *testing.T) {
	pool := testPool(t)
	tenantID, clusterID, incidentID := testCluster(t, pool)
	ctx := context.Background()

	// postCount/lastBody track only POSTs that mention THIS TEST's own
	// incidentID. sweepTransitions is, correctly, fleet-wide with no
	// incident/cluster filter (that's the whole point of a poller that has
	// to notice every incident's open question) — this is a shared,
	// concurrently-used dev database (RUNBOOK.md, and the "concurrent work"
	// notes throughout BACKLOG.md), so a bare global request counter would
	// be flaky against whatever ELSE is genuinely pending on the table at
	// the moment this test's sweep runs. Filtering by content is what makes
	// the assertion about THIS test's sequence of transitions, not about
	// how quiet the rest of the table happens to be right now.
	var postCount atomic.Int64
	var lastBody atomic.Value
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var decoded map[string]string
		_ = json.NewDecoder(r.Body).Decode(&decoded)
		if strings.Contains(decoded["text"], incidentID) {
			postCount.Add(1)
			lastBody.Store(decoded["text"])
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	n := NewWebhookNotifier(&data.DB{Pool: pool})

	notify := func(key, summary string) {
		t.Helper()
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatalf("begin: %v", err)
		}
		defer tx.Rollback(ctx) //nolint:errcheck
		if err := data.SetRequestScope(ctx, tx, tenantID, []string{clusterID}); err != nil {
			t.Fatalf("set request scope: %v", err)
		}
		if err := NotifyTransition(ctx, tx, tenantID, clusterID, incidentID, key, summary); err != nil {
			t.Fatalf("NotifyTransition: %v", err)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatalf("commit: %v", err)
		}
	}
	// Deliberately calls sweepTransitions directly, in its own scoped
	// transaction, rather than the full sweep() — this dev database has
	// real un-notified incidents sitting in the pre-existing "new incident"
	// queue (incidents.notified_at IS NULL), and sweep() would send those
	// too, since both queues share the resolved webhook URL by design (see
	// this package's own doc comment). This test is about the WIDENED
	// mechanism specifically, so it isolates that queue rather than racing
	// against however many real incidents happen to be sitting un-notified
	// right now.
	//
	// Loops up to maxSweepTicksForTest times rather than sweeping once:
	// sweepTransitions caps ONE pass at notifyBatchSize, oldest-pending-first
	// (notifier.go) — a real, un-contrived property of a shared,
	// concurrently-used dev database (this package's own doc comment, and
	// BACKLOG.md's repeated "concurrent activity is expected" note) is that
	// the fleet-wide pending queue can genuinely hold more than
	// notifyBatchSize rows at once (BACKLOG.md T3, 2026-09-04: a widening
	// escalation tier queues a fresh pending row for every incident whose
	// age just crossed a boundary — 22 real ones, on this dev DB, the day
	// this loop was added), which can push this test's own freshly-inserted
	// row (always the newest by definition) out of a single batch entirely.
	// Real internal/notify's poller never gets stuck on this — it ticks
	// forever, so a batch-sized backlog just drains over the next few
	// ticks — so looping a bounded number of real ticks here is the faithful
	// analogue of that, not a widened cap or a weakened assertion: every
	// individual sweepTransitions call still enforces the exact same
	// per-tick dedup contract, and the loop stops the moment this test's own
	// content-filtered postCount reaches the target, so the "must NOT
	// re-notify" cases (steps 2) still runs only as many ticks as it takes
	// to confirm that, same as before whenever the queue is otherwise quiet.
	//
	// sweepTransitions owns its own transactions now (PROJECT.md B166: a
	// claim transaction, then delivery with nothing open, then one outcome
	// transaction per row), so these helpers hand it a tenant id and a URL
	// rather than a transaction they opened themselves. That is also why they
	// no longer assert on a commit: whether each phase committed is
	// sweepTransitions' own business, and the properties this test is about —
	// how many POSTs arrive, carrying what — are unchanged by the split.
	const maxSweepTicksForTest = 10
	sweepUntil := func(wantAtLeast int64) {
		t.Helper()
		for i := 0; i < maxSweepTicksForTest; i++ {
			if err := n.sweepTransitions(ctx, tenantID, defaultRouting(srv.URL)); err != nil {
				t.Fatalf("sweepTransitions: %v", err)
			}
			if postCount.Load() >= wantAtLeast {
				return
			}
		}
	}
	// The negative case (step 2 below) has no "target" to reach — it wants
	// to confirm a fixed count stays fixed across repeated ticks, so it
	// calls this directly rather than through sweepUntil.
	sweep := func() {
		t.Helper()
		if err := n.sweepTransitions(ctx, tenantID, defaultRouting(srv.URL)); err != nil {
			t.Fatalf("sweepTransitions: %v", err)
		}
	}

	// 1. A genuinely new condition (AwaitingApproval) — must send once.
	notify("AwaitingApproval@t1", "Incident "+incidentID+" is now AwaitingApproval.")
	sweepUntil(1)
	if got := postCount.Load(); got != 1 {
		t.Fatalf("after first notify+sweep: postCount = %d, want 1", got)
	}
	if body, _ := lastBody.Load().(string); !strings.Contains(body, "AwaitingApproval") {
		t.Errorf("first POST body %q does not mention AwaitingApproval", body)
	}

	// 2. The SAME open question observed again (e.g. a second sweep tick
	// that re-runs the same detection with nothing new to say) — mirrors
	// mergewatch.go's repeated-tick call: same literal key, must NOT
	// re-send. Multiple sweeps in a row must not change the count either.
	notify("AwaitingApproval@t1", "Incident "+incidentID+" is now AwaitingApproval.")
	sweep()
	sweep()
	if got := postCount.Load(); got != 1 {
		t.Fatalf("after re-observing the SAME key and sweeping again: postCount = %d, want still 1 (must not re-notify on an unchanged condition)", got)
	}

	// 3. A genuinely NEW transition (AwaitingApproval -> Failed) — must send
	// again, with the NEW content, not a duplicate of message 1.
	notify("Failed@t2", "Incident "+incidentID+" is now Failed.")
	sweepUntil(2)
	if got := postCount.Load(); got != 2 {
		t.Fatalf("after a genuinely new transition: postCount = %d, want 2", got)
	}
	if body, _ := lastBody.Load().(string); !strings.Contains(body, "Failed") {
		t.Errorf("second POST body %q does not mention the new state (Failed)", body)
	}

	// 4. A second, later entry into a state this incident has already been
	// in (AwaitingApproval again, after Failed) is ALSO a genuinely new
	// event by this package's own contract (a different key, e.g. a fresh
	// timestamp suffix) — must send a third time, proving the mechanism
	// dedupes on the CONDITION, not merely on "have we ever sent this state
	// name before".
	notify("AwaitingApproval@t3", "Incident "+incidentID+" is AwaitingApproval again after a re-analysis.")
	sweepUntil(3)
	if got := postCount.Load(); got != 3 {
		t.Fatalf("after a fresh AwaitingApproval following a Failed cycle: postCount = %d, want 3 — re-entering a state must still notify", got)
	}
}
