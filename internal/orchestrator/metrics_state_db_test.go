package orchestrator

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"argus/internal/data"
	"argus/internal/dbtest"
	"argus/internal/domain"
	"argus/internal/metrics"
)

// exposedGaugeValue scrapes DefaultRegistry and returns the numeric value of
// one `name{labels}` series, or ok=false if that exact series is absent —
// the same distinction metrics.Gauge's own doc comment makes between
// "never collected" and "collected, and it's zero" (PROJECT.md T11's "never
// fabricate a zero" rule): this helper must be able to tell the two apart,
// or these tests couldn't actually prove the rule holds.
func exposedGaugeValue(t *testing.T, name string, labels map[string]string) (float64, bool) {
	t.Helper()
	var buf strings.Builder
	metrics.DefaultRegistry.WriteExposition(&buf)

	prefix := name
	if len(labels) > 0 {
		parts := make([]string, 0, len(labels))
		for k, v := range labels {
			parts = append(parts, fmt.Sprintf(`%s="%s"`, k, v))
		}
		// Only one label is ever used by this test file's callers
		// (state="X"), so exact ordering doesn't need reconciling here.
		prefix = fmt.Sprintf("%s{%s}", name, strings.Join(parts, ","))
	}
	for _, line := range strings.Split(buf.String(), "\n") {
		if strings.HasPrefix(line, "#") {
			continue
		}
		if !strings.HasPrefix(line, prefix+" ") {
			continue
		}
		var value float64
		if _, err := fmt.Sscanf(strings.TrimPrefix(line, prefix+" "), "%g", &value); err != nil {
			t.Fatalf("parse exposition line %q: %v", line, err)
		}
		return value, true
	}
	return 0, false
}

// TestRefreshIncidentStateMetrics_MatchesIndependentCount proves
// metrics.IncidentsByState actually moves with the real table, not merely
// that the collector runs without error: it inserts one more Detected
// incident, independently counts Detected incidents itself with the exact
// same bounded predicate refreshIncidentStateMetricsOnce uses, refreshes,
// and asserts the gauge equals that independent count exactly — including
// whatever pre-existing rows a shared dev database already has, so this
// does not assume an empty table.
func TestRefreshIncidentStateMetrics_MatchesIndependentCount(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()

	clusterID := domain.NewID(domain.PrefixCluster)
	incidentID := domain.NewID(domain.PrefixIncident)

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin setup: %v", err)
	}
	tenantID, err := data.SingleOrganisationID(ctx, tx)
	if err != nil {
		t.Fatalf("resolve organisation: %v", err)
	}
	if err := data.SetRequestScope(ctx, tx, tenantID, []string{clusterID}); err != nil {
		t.Fatalf("set request scope: %v", err)
	}
	fixture := dbtest.New(t)
	fixture.OwnsCluster(tenantID, clusterID)
	if _, err := tx.Exec(ctx,
		`INSERT INTO clusters (id, tenant_id, display_name, state, shard_id, cluster_fingerprint)
		 VALUES ($1, $2, $3, 'Active', 'shard-test', $4)`,
		clusterID, tenantID, "metrics-state-test-"+clusterID, "fp-"+clusterID); err != nil {
		t.Fatalf("insert cluster: %v", err)
	}
	fixture.Created("clusters", 1)
	now := time.Now()
	if _, err := tx.Exec(ctx,
		`INSERT INTO incidents (id, tenant_id, cluster_id, fingerprint, severity, state, first_seen, last_seen, occurrence_count)
		 VALUES ($1, $2, $3, $4, 'high', $5, $6, $6, 1)`,
		incidentID, tenantID, clusterID, "test-metrics-state-"+incidentID, StateDetected, now); err != nil {
		t.Fatalf("insert incident: %v", err)
	}
	fixture.Created("incidents", 1)
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit setup: %v", err)
	}
	fixture.Cleanup(pool, func(ctx context.Context, tx pgx.Tx) error {
		return data.SetRequestScope(ctx, tx, tenantID, []string{clusterID})
	}, []dbtest.TableDelete{
		{Table: "incidents", SQL: `DELETE FROM incidents WHERE cluster_id = $1`, Args: []any{clusterID}},
		{Table: "clusters", SQL: `DELETE FROM clusters WHERE id = $1`, Args: []any{clusterID}},
	})

	// Independently count Detected incidents with the identical bounded
	// predicate the collector itself uses — a fleet-wide count (request
	// scope widened to nil), matching refreshIncidentStateMetricsOnce's own
	// "this is a scrape target, not a per-caller-visible-cluster read"
	// scope choice.
	countDetected := func() int64 {
		t.Helper()
		countTx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatalf("begin count: %v", err)
		}
		defer countTx.Rollback(ctx) //nolint:errcheck
		if err := data.SetRequestScope(ctx, countTx, tenantID, nil); err != nil {
			t.Fatalf("set request scope for count: %v", err)
		}
		var n int64
		if err := countTx.QueryRow(ctx,
			`SELECT count(*) FROM incidents WHERE state = $1 AND first_seen >= $2`,
			StateDetected, time.Now().Add(-incidentStateMetricsLookback)).Scan(&n); err != nil {
			t.Fatalf("independent count: %v", err)
		}
		return n
	}

	// Both the count and the gauge are deliberately FLEET-WIDE, so any test
	// in another package that commits a Detected incident between the two
	// reads makes them disagree about a table that was simply moving
	// underneath them. That is not hypothetical: this test passes alone and
	// failed once inside a full `go test ./...` the first time the whole
	// suite shared one Postgres (PROJECT.md P26's CI job).
	//
	// Re-counting AFTER the refresh is what separates the two explanations.
	// If the table did not move, the gauge must equal the count and a
	// mismatch is a real defect, failed on immediately. Only a table that
	// actually changed across the refresh is retried — so this buys
	// determinism without buying the collector any slack.
	var want int64
	var got float64
	for attempt := 1; ; attempt++ {
		want = countDetected()
		if want < 1 {
			t.Fatalf("independent count did not see the fixture's own inserted incident — test setup is broken, not the collector")
		}

		if err := refreshIncidentStateMetricsOnce(ctx, pool); err != nil {
			t.Fatalf("refreshIncidentStateMetricsOnce: %v", err)
		}

		var ok bool
		got, ok = exposedGaugeValue(t, "argus_incidents_by_state", map[string]string{"state": StateDetected})
		if !ok {
			t.Fatalf("argus_incidents_by_state{state=%q} is absent after a successful refresh", StateDetected)
		}

		if after := countDetected(); after == want {
			break // the table held still; the gauge has no excuse
		} else if attempt == 5 {
			t.Fatalf("incidents kept changing under the refresh across %d attempts (%d then %d Detected) — cannot attribute a gauge mismatch to the collector", attempt, want, after)
		}
	}
	if got != float64(want) {
		t.Fatalf("argus_incidents_by_state{state=%q} = %v, want %v (independently counted) — the gauge does not reflect the real table", StateDetected, got, want)
	}

	// Every other known state must also have been Set (a real, possibly
	// zero, query-confirmed value) by this same successful refresh — never
	// left absent just because it happened to have no rows.
	for _, state := range incidentMetricsKnownStates {
		if _, ok := exposedGaugeValue(t, "argus_incidents_by_state", map[string]string{"state": state}); !ok {
			t.Errorf("argus_incidents_by_state{state=%q} is absent after a successful refresh — every known state must be set, including a real zero", state)
		}
	}
}

// TestRefreshIncidentStateMetrics_FailureDoesNotFabricateZero pins PROJECT.md
// T11's explicit requirement: a collection failure must leave the gauge
// exactly where it was, never reset it to 0.
func TestRefreshIncidentStateMetrics_FailureDoesNotFabricateZero(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()

	if err := refreshIncidentStateMetricsOnce(ctx, pool); err != nil {
		t.Fatalf("initial refresh: %v", err)
	}
	before, ok := exposedGaugeValue(t, "argus_incidents_by_state", map[string]string{"state": StateDetected})
	if !ok {
		t.Fatalf("argus_incidents_by_state{state=%q} absent after a successful refresh", StateDetected)
	}

	// Force a failure with an already-cancelled context — Begin/Query must
	// fail immediately rather than actually reaching Postgres.
	cancelledCtx, cancel := context.WithCancel(ctx)
	cancel()
	if err := refreshIncidentStateMetricsOnce(cancelledCtx, pool); err == nil {
		t.Fatalf("expected refreshIncidentStateMetricsOnce to fail against an already-cancelled context")
	}

	after, ok := exposedGaugeValue(t, "argus_incidents_by_state", map[string]string{"state": StateDetected})
	if !ok {
		t.Fatalf("argus_incidents_by_state{state=%q} became absent after a failed refresh — it must keep its last successful value", StateDetected)
	}
	if after != before {
		t.Fatalf("argus_incidents_by_state{state=%q} changed from %v to %v after a FAILED refresh — a collection failure must never move this gauge, let alone fabricate a zero", StateDetected, before, after)
	}
}
