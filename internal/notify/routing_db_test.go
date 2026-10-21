package notify

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"argus/internal/data"
	"argus/internal/dbtest"
	"argus/internal/domain"
)

// routingFixture seeds a throwaway cluster in a throwaway cluster group, plus
// the inert incident a queued notification needs, and registers cleanup for all
// of it INCLUDING the routing tables.
//
// The routing tables are cleaned up explicitly rather than left to
// dbtest.AssertNoClusterResidue, because neither carries a cluster_id — a
// notification rule is org-wide configuration that names a cluster GROUP — so
// the residue check cannot see them. Leaving a rule behind would change what
// every later test in this package (and every fleet-wide sweep running
// concurrently in another one) routes, which is the same class of cross-test
// contamination insertInertIncident exists to prevent.
func routingFixture(t *testing.T, pool *pgxpool.Pool) (fixture *dbtest.Fixture, tenantID, clusterID, groupID, incidentID string) {
	t.Helper()
	ctx := context.Background()
	clusterID = domain.NewID(domain.PrefixCluster)
	groupID = domain.NewID(domain.PrefixClusterGroup)
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
		clusterID, tenantID, "routing-test-"+clusterID, "fp-"+clusterID); err != nil {
		t.Fatalf("insert throwaway cluster: %v", err)
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO cluster_groups (id, tenant_id, name, label_selector) VALUES ($1, $2, $3, '{}'::jsonb)`,
		groupID, tenantID, "routing-test-"+groupID); err != nil {
		t.Fatalf("insert throwaway cluster group: %v", err)
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO cluster_group_members (id, tenant_id, cluster_group_id, cluster_id, added_by)
		 VALUES ($1, $2, $3, $4, 'usr_routing_test')`,
		domain.NewID(domain.PrefixClusterGroup)+"m", tenantID, groupID, clusterID); err != nil {
		t.Fatalf("insert cluster group membership: %v", err)
	}
	insertInertIncident(t, ctx, tx, tenantID, clusterID, incidentID)
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit setup transaction: %v", err)
	}

	// The caller adds its own Created counts for notification_routes and
	// integrations, because how many of each a test leaves behind is the
	// test's business — ReplaceRouting replaces the whole set, so there is no
	// count this helper could state that would be right for every caller.
	// dbtest requires the pairing to be exact in both directions, which is the
	// property worth keeping: an unpaired delete is how a fixture drifts out
	// of sync with itself.
	fixture = dbtest.New(t)
	fixture.Created("clusters", 1)
	fixture.Created("incidents", 1)
	// Zero, not omitted: the delete list below names this table, and dbtest
	// requires the pairing in both directions, so the entry has to exist even
	// for a test that queues no notification. The two tests that do queue one
	// add their own 1.
	fixture.Created("incident_notifications", 0)
	fixture.Created("cluster_groups", 1)
	fixture.Created("cluster_group_members", 1)
	fixture.OwnsCluster(tenantID, clusterID)
	fixture.Cleanup(pool, func(ctx context.Context, tx pgx.Tx) error {
		return data.SetRequestScope(ctx, tx, tenantID, []string{clusterID})
	}, []dbtest.TableDelete{
		// Rules before destinations: destination_id is ON DELETE RESTRICT, so
		// the other order fails — the same ordering the migration's own down
		// file states, for the same reason.
		{Table: "notification_routes", SQL: `DELETE FROM notification_routes`},
		{Table: "integrations", SQL: `DELETE FROM integrations`},
		{Table: "cluster_group_members", SQL: `DELETE FROM cluster_group_members WHERE cluster_id = $1`, Args: []any{clusterID}},
		{Table: "cluster_groups", SQL: `DELETE FROM cluster_groups WHERE id = $1`, Args: []any{groupID}},
		{Table: "incident_notifications", SQL: `DELETE FROM incident_notifications WHERE cluster_id = $1`, Args: []any{clusterID}},
		{Table: "incidents", SQL: `DELETE FROM incidents WHERE cluster_id = $1`, Args: []any{clusterID}},
		{Table: "clusters", SQL: `DELETE FROM clusters WHERE id = $1`, Args: []any{clusterID}},
	})
	return fixture, tenantID, clusterID, groupID, incidentID
}

// inScope runs f in a committed, tenant-scoped transaction — the shape every
// caller of ReplaceRouting/LoadRouting has to use, since all three tables carry
// tenant_id-keyed RLS.
func inScope(t *testing.T, pool *pgxpool.Pool, tenantID, clusterID string, f func(ctx context.Context, tx pgx.Tx)) {
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
	f(ctx, tx)
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit: %v", err)
	}
}

// inScopeExpectingError is inScope for a call that is meant to fail. It never
// commits: a ReplaceRouting that returns an error has already aborted the
// transaction, so committing would report "commit unexpectedly resulted in
// rollback" and hide what the test is actually asserting.
func inScopeExpectingError(t *testing.T, pool *pgxpool.Pool, tenantID, clusterID string, f func(ctx context.Context, tx pgx.Tx)) {
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
	f(ctx, tx)
}

func TestReplaceAndLoadRouting(t *testing.T) {
	pool := testPool(t)
	fixture, tenantID, clusterID, groupID, _ := routingFixture(t, pool)
	// The configuration this test ends on: one rule, one destination. The
	// third block below is rejected and rolled back, so it leaves nothing.
	fixture.Created("notification_routes", 1)
	fixture.Created("integrations", 1)

	url := func(s string) *string { return &s }

	// 1. Write a configuration and read it back through the same path the
	//    sweep uses.
	inScope(t, pool, tenantID, clusterID, func(ctx context.Context, tx pgx.Tx) {
		if err := ReplaceRouting(ctx, tx, tenantID, RoutingUpdate{
			Destinations: []DestinationInput{
				{Name: "platform", URL: url("https://hooks.example/platform")},
				{Name: "pager", URL: url("https://hooks.example/pager")},
			},
			Rules: []RuleInput{
				{Name: "platform group", Priority: 10, ClusterGroupID: groupID, Destination: "platform", Enabled: true},
				{Name: "critical pages", Priority: 5, MinSeverity: "critical", Transition: "Reopened", Destination: "pager", Enabled: true},
			},
		}); err != nil {
			t.Fatalf("ReplaceRouting: %v", err)
		}
	})

	inScope(t, pool, tenantID, clusterID, func(ctx context.Context, tx pgx.Tx) {
		table, err := LoadRouting(ctx, tx, "https://hooks.example/global")
		if err != nil {
			t.Fatalf("LoadRouting: %v", err)
		}
		rules := table.Rules()
		if len(rules) != 2 {
			t.Fatalf("loaded %d rules, want 2", len(rules))
		}
		// Ordered by priority, so the pager rule (5) comes before the group
		// rule (10) — the order first-match-wins actually evaluates in.
		if rules[0].Name != "critical pages" || rules[1].Name != "platform group" {
			t.Fatalf("rules loaded in order %q, %q; want the lower priority number first", rules[0].Name, rules[1].Name)
		}
		if rules[1].ClusterGroupName == "" {
			t.Error("the cluster group name was not joined in, so the admin API would render a bare id")
		}
		if len(table.Destinations()) != 2 {
			t.Errorf("loaded %d destinations, want 2", len(table.Destinations()))
		}

		// Matching, against real membership read from cluster_group_members.
		if got, _ := table.Match(Notification{ClusterID: clusterID, Severity: "critical", Transition: "Reopened"}); got.Name != "critical pages" {
			t.Errorf("a critical Reopened matched %q, want the pager rule", got.Name)
		}
		if got, _ := table.Match(Notification{ClusterID: clusterID, Severity: "low", Transition: "Failed"}); got.Name != "platform group" {
			t.Errorf("a low Failed on a group member matched %q, want the group rule", got.Name)
		}
		if got, _ := table.Match(Notification{ClusterID: "cl_not_a_member", Severity: "low", Transition: "Failed"}); !got.IsDefault() {
			t.Errorf("a cluster in no group matched %q, want the default rule", got.Name)
		}
		if got, _ := table.Match(Notification{ClusterID: "cl_not_a_member", Severity: "low", Transition: "Failed"}); got.Destination.URL != "https://hooks.example/global" {
			t.Errorf("the default rule routed to %q, want the settings-resolved webhook", got.Destination.URL)
		}
	})

	// 2. A second write with a nil URL keeps the stored one, and dropping a
	//    destination from the payload removes it.
	inScope(t, pool, tenantID, clusterID, func(ctx context.Context, tx pgx.Tx) {
		if err := ReplaceRouting(ctx, tx, tenantID, RoutingUpdate{
			Destinations: []DestinationInput{{Name: "platform"}},
			Rules: []RuleInput{
				{Name: "platform group", Priority: 10, ClusterGroupID: groupID, Destination: "platform", Enabled: true},
			},
		}); err != nil {
			t.Fatalf("second ReplaceRouting: %v", err)
		}
	})
	inScope(t, pool, tenantID, clusterID, func(ctx context.Context, tx pgx.Tx) {
		table, err := LoadRouting(ctx, tx, "")
		if err != nil {
			t.Fatalf("LoadRouting: %v", err)
		}
		if len(table.Destinations()) != 1 {
			t.Fatalf("after dropping one destination, %d remain; want 1", len(table.Destinations()))
		}
		if got := table.Destinations()[0].URL; got != "https://hooks.example/platform" {
			t.Errorf("a nil url did not keep the stored one: got %q", got)
		}
		if len(table.Rules()) != 1 {
			t.Errorf("after replacing the rule set, %d rules remain; want 1", len(table.Rules()))
		}
	})

	// 3. A rule naming a cluster group that does not exist is a caller error,
	//    not a 500 — and nothing is left half-written, because the whole
	//    update is one transaction.
	inScopeExpectingError(t, pool, tenantID, clusterID, func(ctx context.Context, tx pgx.Tx) {
		err := ReplaceRouting(ctx, tx, tenantID, RoutingUpdate{
			Destinations: []DestinationInput{{Name: "platform"}},
			Rules:        []RuleInput{{Name: "ghost", ClusterGroupID: "clg_does_not_exist", Destination: "platform", Enabled: true}},
		})
		var invalid *InvalidRoutingError
		if !errors.As(err, &invalid) {
			t.Fatalf("ReplaceRouting with an unknown cluster group returned %v (%T), want *InvalidRoutingError", err, err)
		}
		if !strings.Contains(err.Error(), "does not exist") {
			t.Errorf("message %q does not say the group is unknown", err.Error())
		}
	})
}

// TestReopenedRoutesToItsGroupDestination is PROJECT.md F32's acceptance
// exercised end to end through the real sweep: a Reopened transition on a
// cluster in a group reaches THAT group's destination, and does not reach the
// fleet-wide default — which is the whole point, since the default channel
// receiving everything is what F32 exists to stop.
//
// Reopened specifically, because it is the transition F32 names.
// internal/orchestrator's notifiableStates already queues it (its key is
// "Reopened@<instant>"), so what this asserts is that the queued notification
// is now ROUTED rather than unconditionally sent to the one global URL.
func TestReopenedRoutesToItsGroupDestination(t *testing.T) {
	pool := testPool(t)
	fixture, tenantID, clusterID, groupID, incidentID := routingFixture(t, pool)
	fixture.Created("notification_routes", 1)
	fixture.Created("integrations", 1)
	fixture.Created("incident_notifications", 1)
	ctx := context.Background()

	// Two receivers, both counting only POSTs that name THIS test's incident —
	// the sweep is fleet-wide by design, so a bare counter would be flaky
	// against whatever else is genuinely pending (the same reasoning
	// TestNotifyTransitionDedupAcrossSweeps records).
	count := func(hits *atomic.Int64) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var decoded map[string]string
			_ = json.NewDecoder(r.Body).Decode(&decoded)
			if strings.Contains(decoded["text"], incidentID) {
				hits.Add(1)
			}
			w.WriteHeader(http.StatusOK)
		}))
	}
	var teamHits, defaultHits atomic.Int64
	team := count(&teamHits)
	defer team.Close()
	fleet := count(&defaultHits)
	defer fleet.Close()

	inScope(t, pool, tenantID, clusterID, func(ctx context.Context, tx pgx.Tx) {
		if err := ReplaceRouting(ctx, tx, tenantID, RoutingUpdate{
			Destinations: []DestinationInput{{Name: "team", URL: &team.URL}},
			Rules: []RuleInput{{Name: "team reopened", Priority: 1, ClusterGroupID: groupID,
				Transition: "Reopened", Destination: "team", Enabled: true}},
		}); err != nil {
			t.Fatalf("ReplaceRouting: %v", err)
		}
		if err := NotifyTransition(ctx, tx, tenantID, clusterID, incidentID,
			"Reopened@2026-09-25T12:00:00.000000001Z",
			"Incident "+incidentID+" is now Reopened."); err != nil {
			t.Fatalf("NotifyTransition: %v", err)
		}
	})

	var table RoutingTable
	inScope(t, pool, tenantID, clusterID, func(ctx context.Context, tx pgx.Tx) {
		var err error
		table, err = LoadRouting(ctx, tx, fleet.URL)
		if err != nil {
			t.Fatalf("LoadRouting: %v", err)
		}
	})

	n := NewWebhookNotifier(&data.DB{Pool: pool})
	// sweepTransitions directly rather than sweep(), for the reason
	// TestNotifyTransitionDedupAcrossSweeps gives: the shared development
	// database has real un-notified incidents in the OTHER queue, and this
	// test is about where a routed transition lands.
	if err := n.sweepTransitions(ctx, tenantID, table); err != nil {
		t.Fatalf("sweepTransitions: %v", err)
	}

	if teamHits.Load() != 1 {
		t.Errorf("the group's destination received %d notifications for this incident, want 1", teamHits.Load())
	}
	if defaultHits.Load() != 0 {
		t.Errorf("the fleet-wide default received %d notifications a rule had already claimed, want 0", defaultHits.Load())
	}
}

// TestUnmatchedTransitionFallsBackToTheDefault is the other half of the same
// property, and the one that matters more: a rule that does NOT match must
// leave the notification with the default rule, never with nowhere.
func TestUnmatchedTransitionFallsBackToTheDefault(t *testing.T) {
	pool := testPool(t)
	fixture, tenantID, clusterID, groupID, incidentID := routingFixture(t, pool)
	fixture.Created("notification_routes", 1)
	fixture.Created("integrations", 1)
	fixture.Created("incident_notifications", 1)
	ctx := context.Background()

	var teamHits, defaultHits atomic.Int64
	count := func(hits *atomic.Int64) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var decoded map[string]string
			_ = json.NewDecoder(r.Body).Decode(&decoded)
			if strings.Contains(decoded["text"], incidentID) {
				hits.Add(1)
			}
			w.WriteHeader(http.StatusOK)
		}))
	}
	team := count(&teamHits)
	defer team.Close()
	fleet := count(&defaultHits)
	defer fleet.Close()

	inScope(t, pool, tenantID, clusterID, func(ctx context.Context, tx pgx.Tx) {
		if err := ReplaceRouting(ctx, tx, tenantID, RoutingUpdate{
			Destinations: []DestinationInput{{Name: "team", URL: &team.URL}},
			// Only matches Reopened; the notification below is a Failed.
			Rules: []RuleInput{{Name: "team reopened", Priority: 1, ClusterGroupID: groupID,
				Transition: "Reopened", Destination: "team", Enabled: true}},
		}); err != nil {
			t.Fatalf("ReplaceRouting: %v", err)
		}
		if err := NotifyTransition(ctx, tx, tenantID, clusterID, incidentID,
			"Failed@2026-09-25T12:00:00.000000002Z",
			"Incident "+incidentID+" is now Failed."); err != nil {
			t.Fatalf("NotifyTransition: %v", err)
		}
	})

	var table RoutingTable
	inScope(t, pool, tenantID, clusterID, func(ctx context.Context, tx pgx.Tx) {
		var err error
		table, err = LoadRouting(ctx, tx, fleet.URL)
		if err != nil {
			t.Fatalf("LoadRouting: %v", err)
		}
	})

	n := NewWebhookNotifier(&data.DB{Pool: pool})
	if err := n.sweepTransitions(ctx, tenantID, table); err != nil {
		t.Fatalf("sweepTransitions: %v", err)
	}

	if defaultHits.Load() != 1 {
		t.Errorf("the default rule received %d notifications for an unmatched transition, want 1", defaultHits.Load())
	}
	if teamHits.Load() != 0 {
		t.Errorf("a rule that should not have matched received %d notifications, want 0", teamHits.Load())
	}
}
