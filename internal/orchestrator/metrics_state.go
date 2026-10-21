package orchestrator

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"argus/internal/data"
	"argus/internal/metrics"
)

// incidentMetricsKnownStates is every incidents.state value this package's
// own three disposition slices (requiresActionStates/inProgressStates/
// closedStates, state.go) partition — the closed enum
// metrics.IncidentsByState zero-fills on every successful refresh below,
// exactly like internal/gateway.clusterLifecycleStates does for cluster
// state. Named distinctly from state_test.go's own hand-written
// allKnownStates (a test-only, independently-listed exhaustiveness check) —
// the two deliberately do NOT share a variable, so a state constant this
// package adds without giving it disposition edges still shows up as a test
// failure there, rather than this metric silently omitting it.
var incidentMetricsKnownStates = func() []string {
	out := make([]string, 0, len(requiresActionStates)+len(inProgressStates)+len(closedStates))
	out = append(out, requiresActionStates...)
	out = append(out, inProgressStates...)
	out = append(out, closedStates...)
	return out
}()

// incidentStateMetricsRefreshInterval bounds how often
// RefreshIncidentStateMetrics is willing to actually query Postgres,
// independent of how often it is CALLED — see that function's own doc
// comment for why this exists and what it protects against.
const incidentStateMetricsRefreshInterval = 30 * time.Second

// incidentStateMetricsLookback bounds the query itself to recent partitions
// of the range-partitioned incidents table (PARTITION BY RANGE (first_seen),
// migration 000005) via partition pruning on first_seen — see
// RefreshIncidentStateMetrics' own doc comment for the full argument. 35
// days is comfortably wider than every grace/expiry window this codebase
// currently defines (orchestrator's validation grace floor is minutes,
// StateExpired's own aging window is measured in hours-to-days) — an
// incident legitimately open longer than that is rare enough that being
// excluded from this fleet-wide GAUGE (never from the incident itself, or
// from any query that actually serves the product) is an acceptable,
// explicitly stated gap, not a silent one.
const incidentStateMetricsLookback = 35 * 24 * time.Hour

var (
	incidentStateMetricsMu   sync.Mutex
	incidentStateMetricsNext time.Time
)

// RefreshIncidentStateMetrics sets metrics.IncidentsByState from a bounded
// `GROUP BY state` query, at most once every
// incidentStateMetricsRefreshInterval regardless of how often this function
// is called — internal/api's GET /metrics handler calls it on every scrape,
// and this is what stops that from becoming "a full query every time
// Prometheus scrapes," per PROJECT.md T11's own explicit warning ("counts by
// state must not be computed per scrape with a heavy query").
//
// # Why this is safe to call from an HTTP handler at all
//
// Two independent bounds, not one:
//
//  1. The TTL above decouples query frequency from scrape frequency — a
//     15s Prometheus scrape interval still only reaches Postgres once every
//     30s, and a slow/failing DB cannot be hammered by a tight scrape loop.
//  2. The query itself is bounded to recent partitions via
//     incidentStateMetricsLookback's first_seen predicate, so its cost
//     tracks recent incident volume, never the fleet's entire history —
//     the actual "heavy query" shape T11 warns against (an unbounded
//     GROUP BY over a table that only grows) is what this predicate rules
//     out.
//
// On success, every state in incidentMetricsKnownStates is Set — including a real,
// query-confirmed 0 for a state with no matching incidents right now. On any
// error, metrics.IncidentsByState is left completely untouched (see
// metrics.Gauge's own doc comment) and metrics.RecordCollectionFailure
// records the failure so it is itself visible to an alert rule, rather than
// a gauge that silently stops moving.
func RefreshIncidentStateMetrics(ctx context.Context, pool *pgxpool.Pool) {
	incidentStateMetricsMu.Lock()
	if time.Now().Before(incidentStateMetricsNext) {
		incidentStateMetricsMu.Unlock()
		return
	}
	incidentStateMetricsNext = time.Now().Add(incidentStateMetricsRefreshInterval)
	incidentStateMetricsMu.Unlock()

	if err := refreshIncidentStateMetricsOnce(ctx, pool); err != nil {
		metrics.RecordCollectionFailure("incident_state", err)
		return
	}
	metrics.RecordCollectionSuccess("incident_state")
}

func refreshIncidentStateMetricsOnce(ctx context.Context, pool *pgxpool.Pool) error {
	counts := make(map[string]float64, len(incidentMetricsKnownStates))

	// Fleet-wide, deliberately: this is a scrape target answering "can ARGUS
	// be alerted on," not a request scoped to one caller's visible clusters —
	// the same widen-to-nil convention internal/gateway/finding.go's
	// fleetgroup.Recompute call site and internal/notify's own sweep already
	// use for an identical "this background job legitimately needs every
	// cluster this tenant owns" reason. InFleetScope is the tenant resolve and
	// the widen-to-nil in one step (PROJECT.md G11).
	if err := data.InFleetScope(ctx, pool, func(ctx context.Context, tx pgx.Tx, tenantID string) error {
		rows, err := tx.Query(ctx,
			`SELECT state, count(*) FROM incidents WHERE first_seen >= $1 GROUP BY state`,
			time.Now().Add(-incidentStateMetricsLookback))
		if err != nil {
			return fmt.Errorf("count incidents by state: %w", err)
		}
		for rows.Next() {
			var state string
			var count int64
			if err := rows.Scan(&state, &count); err != nil {
				rows.Close()
				return fmt.Errorf("scan incident state count: %w", err)
			}
			counts[state] = float64(count)
		}
		if err := rows.Err(); err != nil {
			return fmt.Errorf("iterate incident state counts: %w", err)
		}
		return nil
	}); err != nil {
		return err
	}

	for _, state := range incidentMetricsKnownStates {
		metrics.IncidentsByState.Set(counts[state], state)
	}
	return nil
}
