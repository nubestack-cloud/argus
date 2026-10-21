package api

import (
	"context"
	"encoding/json"
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"argus/internal/data"
	"argus/internal/dbtest"
	"argus/internal/domain"
	"argus/internal/orchestrator"
)

// The decommission-closure regression, against a real Postgres.
//
// # What was wrong
//
// handleDecommissionCluster closed an archived cluster's incidents with one
// raw statement:
//
//	UPDATE incidents SET state = 'Dismissed'
//	 WHERE cluster_id = $1 AND state NOT IN ('Resolved', 'Dismissed', 'Investigating')
//
// which sidestepped every invariant orchestrator.SetState holds. Each
// assertion below fails against that statement, and names which part of it it
// is pinning:
//
//   - resolved_at is NULL for every incident it closed (SetState stamps it).
//   - no timeline_events row is written at all, so the incident's own history
//     ends mid-story with no line saying the cluster went away.
//   - the fleet/replica/object correlation groups are never recomputed, so an
//     incident that has left the open set is still counted in its group.
//   - Executing -> Dismissed is not an edge orchestrator.allowedTransitions
//     permits, and the raw UPDATE took it anyway — closing incidents with a
//     signed plan in flight over the tunnel as though nothing were happening.
//   - Investigating was excluded to dodge that problem, which created the
//     opposite one: the incident stays open, its analysis lands afterwards and
//     moves it to AwaitingApproval, and an actionable plan awaits a human on a
//     cluster that can never reconnect. TestDecommissionLeavesNoIncidentOpen
//     is the assertion for this, and it is the reason the finding exists.
//
// Gated on ARGUS_TEST_DATABASE_URL exactly like this package's other
// *_db_test.go files; a machine without one gets a clean skip.

func decommissionTestPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	connString := os.Getenv("ARGUS_TEST_DATABASE_URL")
	if connString == "" {
		t.Skip("ARGUS_TEST_DATABASE_URL not set; skipping the decommission incident-closure regression test")
	}
	pool, err := pgxpool.New(context.Background(), connString)
	if err != nil {
		t.Fatalf("connect to test database: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

// decommissionFixture inserts a throwaway cluster carrying one incident in
// every state the CHECK constraint allows, and registers cleanup. The point of
// covering every state rather than a representative few is that the states
// that broke were the unusual ones — nobody writes a decommission test with an
// Executing incident in it unless the fixture makes them.
//
// Every incident shares a workload_key and carries an object_key, so
// SetState's replicagroup/objectgroup recomputation actually has something to
// recompute rather than short-circuiting on NULLs.
//
// Returns a *dbtest.Fixture tracking the deterministic clusters (1) and
// incidents (len(incidentStatesFromCheckConstraint)) rows this setup itself
// inserts. It does NOT call Cleanup: the three tests that use this fixture
// each call closeIncidentsForDecommission, which writes exactly 1
// timeline_events row per incident it actually closes and — only for the
// Executing-origin incident, whose closure path passes through the
// notifiable ExecutionUnknown state — an incident_notifications row; each
// caller must finish tracking those with fixture.Created(...) and then call
// fixture.Cleanup(decommissionDeletes(clusterID), ...) itself.
func decommissionFixture(t *testing.T, pool *pgxpool.Pool) (tenantID, clusterID string, byState map[string]string, fixture *dbtest.Fixture) {
	t.Helper()
	ctx := context.Background()

	clusterID = domain.NewID(domain.PrefixCluster)
	byState = make(map[string]string)

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
		clusterID, tenantID, "decommission-test-"+clusterID, "fp-"+clusterID); err != nil {
		t.Fatalf("insert throwaway cluster: %v", err)
	}
	fixture = dbtest.New(t)
	fixture.Created("clusters", 1)
	// Everything this fixture and closeIncidentsForDecommission produce
	// hangs off this one throwaway cluster, so the catalogue-driven residue
	// check applies: it is what caught the auto-suppression toleration that
	// no caller's delete list mentioned (PROJECT.md B175).
	fixture.OwnsCluster(tenantID, clusterID)

	now := time.Now()
	workloadKey := clusterID + "/apps/Deployment/default/checkout"
	for _, state := range incidentStatesFromCheckConstraint {
		incidentID := domain.NewID(domain.PrefixIncident)
		byState[state] = incidentID
		if _, err := tx.Exec(ctx,
			`INSERT INTO incidents (id, tenant_id, cluster_id, fingerprint, severity, state, first_seen, last_seen,
			   occurrence_count, workload_key, opening_reason, object_key)
			 VALUES ($1, $2, $3, $4, 'high', $5, $6, $6, 1, $7, 'CrashLoopBackOff', $8)`,
			incidentID, tenantID, clusterID, "fp-decom-"+incidentID, state, now,
			workloadKey, clusterID+"/v1/Pod/default/checkout-"+state); err != nil {
			t.Fatalf("insert %s incident: %v", state, err)
		}
		fixture.Created("incidents", 1)
	}
	// The already-closed pair need the closing stamps a real close would have
	// left, so the test can prove the decommission did not disturb them.
	if _, err := tx.Exec(ctx,
		`UPDATE incidents SET resolved_at = $2, resolution_kind = 'self_healed' WHERE id = $1`,
		byState[orchestrator.StateResolved], now.Add(-time.Hour)); err != nil {
		t.Fatalf("stamp the pre-existing Resolved incident: %v", err)
	}
	if _, err := tx.Exec(ctx,
		`UPDATE incidents SET resolved_at = $2 WHERE id = $1`,
		byState[orchestrator.StateDismissed], now.Add(-time.Hour)); err != nil {
		t.Fatalf("stamp the pre-existing Dismissed incident: %v", err)
	}

	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit setup transaction: %v", err)
	}

	return tenantID, clusterID, byState, fixture
}

// decommissionDeletes is the cleanup statement list every decommissionFixture
// caller uses — every table the fixture setup OR closeIncidentsForDecommission
// could touch, so callers only need to get the Created(...) counts right, not
// the delete list itself.
func decommissionDeletes(clusterID string) []dbtest.TableDelete {
	return []dbtest.TableDelete{
		{Table: "timeline_events", SQL: `DELETE FROM timeline_events WHERE cluster_id = $1`, Args: []any{clusterID}},
		{Table: "incident_notifications", SQL: `DELETE FROM incident_notifications WHERE cluster_id = $1`, Args: []any{clusterID}},
		// incident_tolerations is here because closing an incident can write
		// one WITHOUT this fixture ever naming the table: orchestrator's
		// recurrence.go auto-suppresses an object when a Dismissed close
		// carries a reason it can read off the incident's own findings. Only
		// TestDecommissionRecomputesFleetGroups seeds findings, so only that
		// test's Created count is non-zero — but the delete belongs in the
		// shared list for every caller, because a table that no caller
		// mentions is one dbtest cannot check in either direction, and that
		// is precisely how this row leaked once per full-suite run
		// (PROJECT.md B175).
		{Table: "incident_tolerations", SQL: `DELETE FROM incident_tolerations WHERE cluster_id = $1`, Args: []any{clusterID}},
		{Table: "incidents", SQL: `DELETE FROM incidents WHERE cluster_id = $1`, Args: []any{clusterID}},
		{Table: "clusters", SQL: `DELETE FROM clusters WHERE id = $1`, Args: []any{clusterID}},
	}
}

// decommissionSetScope is the setScope callback every decommissionFixture
// caller's Cleanup uses — tenant-wide (nil cluster list), matching
// decommissionScopedTx's own scope.
func decommissionSetScope(tenantID string) func(ctx context.Context, tx pgx.Tx) error {
	return func(ctx context.Context, tx pgx.Tx) error {
		return data.SetRequestScope(ctx, tx, tenantID, nil)
	}
}

// decommissionScopedTx opens a transaction with the same tenant-wide request
// scope a real request carries (data.SetRequestScope with a nil cluster list),
// which is what handleDecommissionCluster's rc.Tx actually runs with.
func decommissionScopedTx(t *testing.T, pool *pgxpool.Pool, tenantID string) pgx.Tx {
	t.Helper()
	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin transaction: %v", err)
	}
	t.Cleanup(func() { tx.Rollback(context.Background()) }) //nolint:errcheck
	if err := data.SetRequestScope(ctx, tx, tenantID, nil); err != nil {
		t.Fatalf("set request scope: %v", err)
	}
	return tx
}

// TestDecommissionLeavesNoIncidentOpen is the finding itself: after a
// decommission, nothing belonging to that cluster may still be open — most
// pointedly not the Investigating incident the old statement deliberately
// skipped, and not the Executing one it closed illegally.
func TestDecommissionLeavesNoIncidentOpen(t *testing.T) {
	pool := decommissionTestPool(t)
	tenantID, clusterID, _, fixture := decommissionFixture(t, pool)

	// closeIncidentsForDecommission writes exactly 1 timeline_events row per
	// incident it actually closes (never one per SetState hop in a multi-step
	// path — see decommissionFixture's own doc comment) — that's
	// len(incidentStatesFromCheckConstraint)-2 here, the same count this
	// test's own closure.Closed assertion below expects. Exactly 1
	// incident_notifications row is written fleet-wide: only the
	// Executing-origin incident's path passes through the notifiable
	// ExecutionUnknown state, and incident_notifications is keyed
	// PRIMARY KEY(incident_id), so it can never be more than 1 regardless of
	// how many SetState hops that one incident takes.
	fixture.Created("timeline_events", len(incidentStatesFromCheckConstraint)-2)
	fixture.Created("incident_notifications", 1)
	// No auto-suppression toleration: recurrence.go only writes one when the
	// dismissed incident has a finding to read a reason off, and this test
	// seeds none. Declared explicitly rather than omitted — a table dbtest is
	// never told about is a table it cannot check.
	fixture.Created("incident_tolerations", 0)
	fixture.Cleanup(pool, decommissionSetScope(tenantID), decommissionDeletes(clusterID))

	ctx := context.Background()
	tx := decommissionScopedTx(t, pool, tenantID)

	closure, err := closeIncidentsForDecommission(ctx, tx, tenantID, clusterID, "decommission-test")
	if err != nil {
		t.Fatalf("closeIncidentsForDecommission: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit: %v", err)
	}

	// 15 states in the fixture, 2 of them already closed.
	wantClosed := len(incidentStatesFromCheckConstraint) - 2
	if closure.Closed != wantClosed {
		t.Errorf("closed %d incident(s), want %d", closure.Closed, wantClosed)
	}
	if closure.LeftOpen != 0 {
		t.Errorf("left %d incident(s) open — an archived cluster must not keep un-actionable incidents", closure.LeftOpen)
	}
	if closure.InvestigationsCancelled != 1 {
		t.Errorf("cancelled %d investigation(s), want 1", closure.InvestigationsCancelled)
	}
	if closure.ExecutionsUnconfirmed != 1 {
		t.Errorf("recorded %d unconfirmed execution(s), want 1", closure.ExecutionsUnconfirmed)
	}

	verifyTx := decommissionScopedTx(t, pool, tenantID)
	var stillOpen []string
	rows, err := verifyTx.Query(ctx,
		`SELECT id, state FROM incidents WHERE cluster_id = $1 AND state NOT IN ('Resolved', 'Dismissed')`, clusterID)
	if err != nil {
		t.Fatalf("query still-open incidents: %v", err)
	}
	for rows.Next() {
		var id, state string
		if err := rows.Scan(&id, &state); err != nil {
			t.Fatalf("scan: %v", err)
		}
		stillOpen = append(stillOpen, id+"="+state)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		t.Fatalf("read still-open incidents: %v", err)
	}
	if len(stillOpen) > 0 {
		sort.Strings(stillOpen)
		t.Errorf("incidents left open on an archived cluster: %s", strings.Join(stillOpen, ", "))
	}
}

// TestDecommissionClosureRecordsClosureConsistently pins the invariants the
// raw UPDATE skipped: the close timestamp, the honest (absent) resolution
// kind, and the incident's own history line.
func TestDecommissionClosureRecordsClosureConsistently(t *testing.T) {
	pool := decommissionTestPool(t)
	tenantID, clusterID, byState, fixture := decommissionFixture(t, pool)

	// Same shape as TestDecommissionLeavesNoIncidentOpen: exactly 1
	// timeline_events row per closed incident, exactly 1 incident_notifications
	// row fleet-wide (the Executing-origin incident's ExecutionUnknown hop).
	fixture.Created("timeline_events", len(incidentStatesFromCheckConstraint)-2)
	fixture.Created("incident_notifications", 1)
	// No auto-suppression toleration: recurrence.go only writes one when the
	// dismissed incident has a finding to read a reason off, and this test
	// seeds none. Declared explicitly rather than omitted — a table dbtest is
	// never told about is a table it cannot check.
	fixture.Created("incident_tolerations", 0)
	fixture.Cleanup(pool, decommissionSetScope(tenantID), decommissionDeletes(clusterID))

	ctx := context.Background()
	tx := decommissionScopedTx(t, pool, tenantID)

	if _, err := closeIncidentsForDecommission(ctx, tx, tenantID, clusterID, "decommission-test"); err != nil {
		t.Fatalf("closeIncidentsForDecommission: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit: %v", err)
	}

	verifyTx := decommissionScopedTx(t, pool, tenantID)
	for _, state := range incidentStatesFromCheckConstraint {
		if orchestrator.IsTerminalState(state) {
			continue
		}
		incidentID := byState[state]

		var newState string
		var resolvedAt *time.Time
		var resolutionKind *string
		if err := verifyTx.QueryRow(ctx,
			`SELECT state, resolved_at, resolution_kind FROM incidents WHERE id = $1`, incidentID,
		).Scan(&newState, &resolvedAt, &resolutionKind); err != nil {
			t.Fatalf("read incident closed from %s: %v", state, err)
		}
		if newState != orchestrator.StateDismissed {
			t.Errorf("incident closed from %s is %q, want %q", state, newState, orchestrator.StateDismissed)
		}
		// The raw UPDATE never set this. resolved_at is how every other
		// closing path in this codebase records when an incident closed.
		if resolvedAt == nil {
			t.Errorf("incident closed from %s has a NULL resolved_at — its close time was not recorded", state)
		}
		// Decision 2: these closures are not Resolved, so resolution_kind stays
		// honestly inapplicable. Closing them as Resolved would stamp
		// 'self_healed' on incidents whose cluster was switched off, which is
		// precisely the distinction migration 000091 added the column to make.
		if resolutionKind != nil {
			t.Errorf("incident closed from %s carries resolution_kind %q — a decommission closure is neither remediated nor self-healed", state, *resolutionKind)
		}

		var eventType string
		var payload []byte
		if err := verifyTx.QueryRow(ctx,
			`SELECT event_type, payload FROM timeline_events
			  WHERE incident_id = $1 ORDER BY occurred_at DESC LIMIT 1`, incidentID,
		).Scan(&eventType, &payload); err != nil {
			t.Fatalf("read the closing timeline event for the incident closed from %s: %v", state, err)
		}
		if eventType != "IncidentDismissed" {
			t.Errorf("incident closed from %s: last timeline event is %q, want IncidentDismissed", state, eventType)
		}
		var decoded map[string]any
		if err := json.Unmarshal(payload, &decoded); err != nil {
			t.Fatalf("decode timeline payload for the incident closed from %s: %v", state, err)
		}
		if decoded["reason"] != "cluster_decommissioned" {
			t.Errorf("incident closed from %s: timeline reason = %v, want cluster_decommissioned", state, decoded["reason"])
		}
		if decoded["fromState"] != state {
			t.Errorf("incident closed from %s: timeline fromState = %v", state, decoded["fromState"])
		}
		summary, _ := decoded["summary"].(string)
		if !strings.Contains(summary, "decommissioned") {
			t.Errorf("incident closed from %s: timeline summary does not say why it closed: %q", state, summary)
		}
	}

	// The two already-closed incidents must be untouched — no second close
	// stamp, no new history, and in particular the pre-existing Resolved one
	// keeps the resolution_kind it earned.
	for _, closedState := range []string{orchestrator.StateResolved, orchestrator.StateDismissed} {
		incidentID := byState[closedState]
		var state string
		var resolvedAt time.Time
		if err := verifyTx.QueryRow(ctx,
			`SELECT state, resolved_at FROM incidents WHERE id = $1`, incidentID).Scan(&state, &resolvedAt); err != nil {
			t.Fatalf("read the pre-existing %s incident: %v", closedState, err)
		}
		if state != closedState {
			t.Errorf("pre-existing %s incident became %q", closedState, state)
		}
		if time.Since(resolvedAt) < 30*time.Minute {
			t.Errorf("pre-existing %s incident's resolved_at was overwritten by the decommission", closedState)
		}
		var events int
		if err := verifyTx.QueryRow(ctx,
			`SELECT count(*) FROM timeline_events WHERE incident_id = $1`, incidentID).Scan(&events); err != nil {
			t.Fatalf("count timeline events for the pre-existing %s incident: %v", closedState, err)
		}
		if events != 0 {
			t.Errorf("pre-existing %s incident gained %d timeline event(s) from a decommission that should not have touched it", closedState, events)
		}
	}

	var resolvedKind *string
	if err := verifyTx.QueryRow(ctx,
		`SELECT resolution_kind FROM incidents WHERE id = $1`, byState[orchestrator.StateResolved]).Scan(&resolvedKind); err != nil {
		t.Fatalf("read the pre-existing Resolved incident's resolution_kind: %v", err)
	}
	if resolvedKind == nil || *resolvedKind != "self_healed" {
		t.Errorf("pre-existing Resolved incident's resolution_kind = %v, want self_healed", resolvedKind)
	}
}

// TestDecommissionCancelsInFlightWorkAudibly covers the two decisions in
// closeIncidentsForDecommission's doc comment where they are observable:
// the in-flight cases say what was abandoned, and the abandoned execution
// notifies a human, because a mutation may have landed on a cluster ARGUS can
// no longer see.
func TestDecommissionCancelsInFlightWorkAudibly(t *testing.T) {
	pool := decommissionTestPool(t)
	tenantID, clusterID, byState, fixture := decommissionFixture(t, pool)

	// Same shape as TestDecommissionLeavesNoIncidentOpen: exactly 1
	// timeline_events row per closed incident, exactly 1 incident_notifications
	// row fleet-wide — which is exactly what this test's own "notifications
	// != 1" assertion below checks.
	fixture.Created("timeline_events", len(incidentStatesFromCheckConstraint)-2)
	fixture.Created("incident_notifications", 1)
	// No auto-suppression toleration: recurrence.go only writes one when the
	// dismissed incident has a finding to read a reason off, and this test
	// seeds none. Declared explicitly rather than omitted — a table dbtest is
	// never told about is a table it cannot check.
	fixture.Created("incident_tolerations", 0)
	fixture.Cleanup(pool, decommissionSetScope(tenantID), decommissionDeletes(clusterID))

	ctx := context.Background()
	tx := decommissionScopedTx(t, pool, tenantID)

	if _, err := closeIncidentsForDecommission(ctx, tx, tenantID, clusterID, "decommission-test"); err != nil {
		t.Fatalf("closeIncidentsForDecommission: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit: %v", err)
	}

	verifyTx := decommissionScopedTx(t, pool, tenantID)
	for state, wantWork := range map[string]string{
		orchestrator.StateInvestigating: "investigation",
		orchestrator.StateExecuting:     "execution",
	} {
		var payload []byte
		if err := verifyTx.QueryRow(ctx,
			`SELECT payload FROM timeline_events WHERE incident_id = $1 ORDER BY occurred_at DESC LIMIT 1`,
			byState[state]).Scan(&payload); err != nil {
			t.Fatalf("read timeline event for the %s incident: %v", state, err)
		}
		var decoded map[string]any
		if err := json.Unmarshal(payload, &decoded); err != nil {
			t.Fatalf("decode timeline payload for the %s incident: %v", state, err)
		}
		if decoded["inFlightWork"] != wantWork {
			t.Errorf("%s incident: timeline inFlightWork = %v, want %q — the cancelled work must be stated, not inferred",
				state, decoded["inFlightWork"], wantWork)
		}
	}

	// The Executing incident is walked through ExecutionUnknown, which is one
	// of orchestrator's notifiableStates: a plan was in flight when the tunnel
	// was severed, so a human is told even though the incident then closes.
	var pending bool
	var summary string
	if err := verifyTx.QueryRow(ctx,
		`SELECT pending, summary FROM incident_notifications WHERE incident_id = $1`,
		byState[orchestrator.StateExecuting]).Scan(&pending, &summary); err != nil {
		t.Fatalf("read the notification queued for the abandoned execution: %v", err)
	}
	if !pending {
		t.Error("the abandoned execution's notification is not pending")
	}
	if !strings.Contains(summary, orchestrator.StateExecutionUnknown) {
		t.Errorf("the abandoned execution's notification summary does not name %s: %q", orchestrator.StateExecutionUnknown, summary)
	}

	// Nothing else notifies. An operator who just decommissioned a cluster does
	// not need one message per incident telling them what they did.
	var notifications int
	if err := verifyTx.QueryRow(ctx,
		`SELECT count(*) FROM incident_notifications WHERE cluster_id = $1`, clusterID).Scan(&notifications); err != nil {
		t.Fatalf("count notifications: %v", err)
	}
	if notifications != 1 {
		t.Errorf("decommission queued %d notification(s), want exactly 1 (the abandoned execution)", notifications)
	}
}

// TestDecommissionRecomputesFleetGroups covers the invariant that is invisible
// on the archived cluster itself: an incident leaving the open set can shrink
// or disband a FLEET-WIDE group, which lives on OTHER clusters' incidents.
//
// The raw UPDATE never called fleetgroup.Recompute, so the surviving cluster's
// incident kept a fleet_group_id asserting "this fault is happening on two
// clusters at once" when one of the two had just been switched off. The
// grouping is what the fleet overview leads with, so this is a wrong number on
// the first screen an operator looks at.
//
// The assertion is on the SURVIVING cluster deliberately. Recompute only ever
// rewrites still-open incidents (a closed incident keeps its historical group
// id, which is correct — it records what was true while it was open), so the
// archived cluster's own rows are not where the effect shows up.
func TestDecommissionRecomputesFleetGroups(t *testing.T) {
	pool := decommissionTestPool(t)
	tenantID, clusterID, byState, fixture := decommissionFixture(t, pool)

	// Same shape as TestDecommissionLeavesNoIncidentOpen: exactly 1
	// timeline_events row per closed incident, exactly 1 incident_notifications
	// row fleet-wide. fleetgroup.Recompute (triggered on the archived
	// incident's own close, further down) only ever UPDATEs the survivor
	// incident's fleet_group_id column directly — it does not go through
	// orchestrator.SetState for the survivor, so it adds no timeline_events or
	// incident_notifications row of its own.
	fixture.Created("timeline_events", len(incidentStatesFromCheckConstraint)-2)
	fixture.Created("incident_notifications", 1)
	// One auto-suppression toleration, and only here: this is the only
	// decommission test that seeds findings, and recurrence.go writes a
	// toleration for the archived cluster's Detected incident when its
	// Dismissed close can read CrashLoopBackOff off one of them.
	fixture.Created("incident_tolerations", 1)
	fixture.Cleanup(pool, decommissionSetScope(tenantID), decommissionDeletes(clusterID))

	ctx := context.Background()

	// A second cluster with an open incident on the same fingerprint, grouped
	// with the first — a fleet-wide issue affecting exactly two clusters, which
	// is the smallest configuration where the group is meant to exist at all.
	survivorClusterID := domain.NewID(domain.PrefixCluster)
	survivorIncidentID := domain.NewID(domain.PrefixIncident)
	sharedFingerprint := "fp-decom-shared-" + survivorIncidentID
	groupID := "fg_decom_" + survivorIncidentID

	seedTx := decommissionScopedTx(t, pool, tenantID)
	if _, err := seedTx.Exec(ctx,
		`INSERT INTO clusters (id, tenant_id, display_name, state, shard_id, cluster_fingerprint)
		 VALUES ($1, $2, $3, 'Active', 'shard-test', $4)`,
		survivorClusterID, tenantID, "decommission-survivor-"+survivorClusterID, "fp-"+survivorClusterID); err != nil {
		t.Fatalf("insert survivor cluster: %v", err)
	}
	survivorFixture := dbtest.New(t)
	survivorFixture.Created("clusters", 1)
	// This block inserts exactly ONE new incident (survivorIncidentID) below —
	// the archived cluster's own Detected incident (archivedIncidentID) is
	// only ever UPDATEd here (its fingerprint/fleet_group_id), never inserted;
	// it already belongs to, and is deleted by, decommissionFixture's own
	// cleanup above. The ORIGINAL version of this cleanup deleted
	// `incidents WHERE fingerprint = $1`, which — since that UPDATE gives the
	// archived incident the SAME fingerprint — matched BOTH incidents despite
	// this fixture only having created one, silently deleting the archived
	// incident a run early (harmless under the old plain-DELETE
	// cleanup, since nothing asserted the count, but exactly the kind of
	// over-broad predicate dbtest.Fixture exists to catch). Scoped to
	// `id = $1` (survivorIncidentID only) instead, so this fixture's cleanup
	// touches only what it created.
	survivorFixture.Created("incidents", 1)
	// Both findings below ARE inserted by this block regardless of which
	// cluster_id they carry, and sharedFingerprint is freshly generated per
	// run (derived from survivorIncidentID), so scoping this one delete by
	// fingerprint is safe — unlike the incidents case above, there is no
	// other fixture's row this could reach.
	survivorFixture.Created("findings", 2)
	survivorFixture.Cleanup(pool, func(ctx context.Context, tx pgx.Tx) error {
		return data.SetRequestScope(ctx, tx, tenantID, nil)
	}, []dbtest.TableDelete{
		{Table: "findings", SQL: `DELETE FROM findings WHERE fingerprint = $1`, Args: []any{sharedFingerprint}},
		{Table: "incidents", SQL: `DELETE FROM incidents WHERE id = $1`, Args: []any{survivorIncidentID}},
		{Table: "clusters", SQL: `DELETE FROM clusters WHERE id = $1`, Args: []any{survivorClusterID}},
	})

	now := time.Now()
	if _, err := seedTx.Exec(ctx,
		`INSERT INTO incidents (id, tenant_id, cluster_id, fingerprint, severity, state, first_seen, last_seen,
		   occurrence_count, fleet_group_id)
		 VALUES ($1, $2, $3, $4, 'high', 'Detected', $5, $5, 1, $6)`,
		survivorIncidentID, tenantID, survivorClusterID, sharedFingerprint, now, groupID); err != nil {
		t.Fatalf("insert survivor incident: %v", err)
	}
	// The archived cluster's Detected incident joins the same group. Recompute
	// discovers membership through findings.fingerprint (migration 000036 —
	// incidents.fingerprint records only the symptom that OPENED an incident),
	// so both incidents need a finding carrying the shared fingerprint or the
	// group has no members to count.
	archivedIncidentID := byState[orchestrator.StateDetected]
	if _, err := seedTx.Exec(ctx,
		`UPDATE incidents SET fingerprint = $2, fleet_group_id = $3 WHERE id = $1`,
		archivedIncidentID, sharedFingerprint, groupID); err != nil {
		t.Fatalf("join the archived cluster's incident to the fleet group: %v", err)
	}
	for _, f := range []struct{ incidentID, clusterID string }{
		{survivorIncidentID, survivorClusterID},
		{archivedIncidentID, clusterID},
	} {
		if _, err := seedTx.Exec(ctx,
			`INSERT INTO findings (id, tenant_id, cluster_id, detector_id, detector_version, fingerprint,
			   gvk, namespace, object_name, reason, severity, occurred_at, incident_id)
			 VALUES ($1, $2, $3, 'test', '1', $4, 'v1/Pod', 'default', 'checkout', 'CrashLoopBackOff', 'high', $5, $6)`,
			domain.NewID(domain.PrefixFinding), tenantID, f.clusterID, sharedFingerprint, now, f.incidentID); err != nil {
			t.Fatalf("insert finding for incident %s: %v", f.incidentID, err)
		}
	}
	if err := seedTx.Commit(ctx); err != nil {
		t.Fatalf("commit fleet-group seed: %v", err)
	}

	tx := decommissionScopedTx(t, pool, tenantID)
	if _, err := closeIncidentsForDecommission(ctx, tx, tenantID, clusterID, "decommission-test"); err != nil {
		t.Fatalf("closeIncidentsForDecommission: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit: %v", err)
	}

	verifyTx := decommissionScopedTx(t, pool, tenantID)
	var survivorGroup *string
	if err := verifyTx.QueryRow(ctx,
		`SELECT fleet_group_id FROM incidents WHERE id = $1`, survivorIncidentID).Scan(&survivorGroup); err != nil {
		t.Fatalf("read the survivor incident's fleet group: %v", err)
	}
	if survivorGroup != nil {
		t.Errorf("the surviving cluster's incident is still in fleet group %q after the other cluster was decommissioned — "+
			"the fleet overview would still call this a two-cluster issue", *survivorGroup)
	}
}

// TestDecommissionClosurePathCoversEveryLiveState reads incidents_state_check
// out of the database and fails if a migration has added a state that
// incidentStatesFromCheckConstraint (and therefore decommissionClosurePath's
// coverage test) does not know about. Without this, adding a sixteenth state
// would silently give decommission a state it leaves open forever, and every
// test in this package would still pass.
func TestDecommissionClosurePathCoversEveryLiveState(t *testing.T) {
	pool := decommissionTestPool(t)
	ctx := context.Background()

	var def string
	if err := pool.QueryRow(ctx,
		`SELECT pg_get_constraintdef(oid) FROM pg_constraint WHERE conname = 'incidents_state_check'`).Scan(&def); err != nil {
		t.Fatalf("read incidents_state_check: %v", err)
	}
	live := regexp.MustCompile(`'([A-Za-z]+)'`).FindAllStringSubmatch(def, -1)
	if len(live) == 0 {
		t.Fatalf("could not parse any state out of incidents_state_check: %q", def)
	}

	known := make(map[string]bool, len(incidentStatesFromCheckConstraint))
	for _, s := range incidentStatesFromCheckConstraint {
		known[s] = true
	}
	for _, match := range live {
		state := match[1]
		if !known[state] {
			t.Errorf("incidents.state may be %q, which incidentStatesFromCheckConstraint does not list — decommission has never been considered for it", state)
			continue
		}
		if orchestrator.IsTerminalState(state) {
			continue
		}
		if decommissionClosurePath(state) == nil {
			t.Errorf("state %q has no decommission closure path", state)
		}
	}
}
