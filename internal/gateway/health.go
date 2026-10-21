package gateway

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"

	"argus/internal/data"
	"argus/internal/events"
	"argus/internal/logging"
	"argus/internal/metrics"
)

// clusterLifecycleStates is every value migration 000002_clusters.up.sql's
// CHECK constraint allows for clusters.state — the closed enum
// metrics.ClustersByState zero-fills on every successful refresh, so a state
// with genuinely no clusters in it reports a real 0 rather than being
// silently absent (see Gauge's own doc comment on the difference between
// "never collected" and "collected, and it's zero").
var clusterLifecycleStates = []string{
	"PendingApproval", "Provisioning", "Active", "Degraded", "Disconnected",
	"IncompatibleVersion", "Rejected", "Archived",
}

// Cluster health thresholds, translating lld/03-agent-protocol.md §4/§7's
// "consecutive missed heartbeats" state machine into wall-clock terms against
// clusters.last_heartbeat_at (the column handleHeartbeat, in server.go,
// updates on every heartbeat). §7 fixes the heartbeat interval at 30s:
//
//   - Active -> Degraded: 2 consecutive missed heartbeats, i.e. 60-90s of
//     silence depending on jitter. degradedThreshold uses the midpoint of
//     that range.
//   - Degraded -> Disconnected: 5 consecutive missed heartbeats, CUMULATIVE
//     from the original Active state, not reset by a brief Degraded->Active
//     blip — i.e. 5 x 30s = 150s. Measuring this as "how long since
//     last_heartbeat_at" rather than "how many Degraded ticks in a row" gets
//     that cumulative behaviour for free: last_heartbeat_at only ever
//     advances on a real heartbeat (handleHeartbeat), never on a state
//     transition by itself, so a Degraded->Active->Degraded flap doesn't
//     reset any separate counter the way tracking "consecutive Degraded
//     sweeps" would.
const (
	degradedThreshold     = 75 * time.Second
	disconnectedThreshold = 150 * time.Second
)

// degradeStaleActiveSQL and disconnectStaleSQL are sweep's two demotion
// statements. Both take their threshold as a BIND PARAMETER fed from the two
// constants above ($1, in seconds) rather than a hardcoded SQL interval
// literal. They used to read `interval '75 seconds'` / `interval '150
// seconds'`, which left degradedThreshold/disconnectedThreshold declared and
// never read by anything but health_test.go — so the test whose whole job is
// guarding these thresholds against drift from lld/03-agent-protocol.md §7
// was asserting on two numbers the actual sweep never consulted, and would
// have gone on passing while the real behaviour diverged from them. The
// `$n * interval '1 second'` form is the same one
// internal/orchestrator/validation.go already uses to feed
// validationGracePeriod into SQL. Named constants rather than inline
// literals so health_test.go can assert the parameterization itself is still
// there (TestDemotionSQLUsesThresholdParameters) — re-hardcoding a literal
// would otherwise silently re-open exactly the gap this closes.
//
// COALESCE(last_heartbeat_at, created_at): a cluster that reached Active via
// InventoryDelta (handleInventoryDelta) without ever having a real Heartbeat
// recorded — normally only possible for a test harness that sends
// InventoryDelta directly, since a real agent's tunnel loop sends both —
// would otherwise have last_heartbeat_at IS NULL forever, and "NULL < now()
// - interval" is never true in SQL, so such a cluster was silently exempt
// from ever demoting, no matter how long it went silent. Falling back to
// created_at closes that gap: it's a reasonable proxy for "since when have
// we heard nothing" when there's truly no heartbeat on record at all.
const (
	degradeStaleActiveSQL = `
		UPDATE clusters SET state = 'Degraded'
		 WHERE state = 'Active' AND COALESCE(last_heartbeat_at, created_at) < now() - ($1 * interval '1 second')
		 RETURNING id, display_name, COALESCE(last_heartbeat_at, created_at) AS last_heartbeat_at`

	disconnectStaleSQL = `
		UPDATE clusters SET state = 'Disconnected'
		 WHERE state IN ('Active', 'Degraded') AND COALESCE(last_heartbeat_at, created_at) < now() - ($1 * interval '1 second')
		 RETURNING id, display_name, COALESCE(last_heartbeat_at, created_at) AS last_heartbeat_at`
)

// DefaultHealthCheckInterval is how often HealthMonitor.Run sweeps for missed
// heartbeats. 15-30s was the suggested range; 20s is picked as a round middle
// value — well under degradedThreshold, so the thresholds above are enforced
// within one tick's margin rather than up to a whole extra heartbeat interval
// late, but not so frequent that it's polling pointlessly often relative to
// the 30s heartbeat cadence it's monitoring. Like lld/03-agent-protocol.md
// §8's 6-hour inventory-resync interval, this is a chosen default, not
// derived from any measured requirement — revisit if real operation shows a
// need for tighter or looser bounds.
const DefaultHealthCheckInterval = 20 * time.Second

// HealthMonitor implements the demotion half of
// lld/03-agent-protocol.md §4/§7's cluster health state machine:
// Active -> Degraded -> Disconnected on missed heartbeats. The recovery half
// (Degraded/Disconnected -> Active) lives in handleHeartbeat (server.go) —
// receiving any heartbeat is itself the recovery signal, so recovery doesn't
// need a poll loop, only demotion does.
//
// Not in scope here: whether the gateway should still be accepting a tunnel
// connection at all from a cluster in a terminal state (Archived, Rejected).
// As of this writing it does — nothing in Gateway.handleConn checks state
// before dispatching Heartbeat/InventoryDelta — which is a related gap worth
// flagging, but fixing cross-cluster-lifecycle interactions beyond heartbeat
// recovery/demotion is a separate concern from this monitor.
type HealthMonitor struct {
	db     *data.DB
	events *events.Bus // shared with internal/api.Server and internal/gateway.Gateway — see cmd/hub/main.go's construction order. May be nil in tests that don't care about live-update publishing (e.g. health_test.go's ctx.Done()-only case).
}

// NewHealthMonitor constructs a HealthMonitor. Doesn't start sweeping — call
// Run for that.
func NewHealthMonitor(db *data.DB, bus *events.Bus) *HealthMonitor {
	return &HealthMonitor{db: db, events: bus}
}

// Run ticks every interval, running one sweep per tick, until ctx is
// cancelled. Blocks — callers run it in its own goroutine, the same pattern
// cmd/hub/main.go's runAPI already uses for Gateway.ListenAndServeTLS.
func (h *HealthMonitor) Run(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			// One tick is one unit of work (PROJECT.md T23): every log
			// line this sweep produces — including the per-cluster
			// demotion lines, several packages' worth of query failures,
			// and the metrics refresh — carries the same request_id, so
			// "what did the sweep that demoted this cluster see?" is one
			// query rather than a timestamp-window guess.
			sweepCtx, _ := logging.NewUnitOfWork(ctx)
			start := time.Now()
			err := h.sweep(sweepCtx)
			metrics.ObserveSweeperRun("cluster_health", time.Since(start), err)
			if err != nil {
				logger.ErrorContext(sweepCtx, "cluster health sweep failed", logging.Err(err))
			}
		}
	}
}

// sweep runs one pass of both demotion transitions inside a single
// RLS-scoped transaction — data.SingleOrganisationID + data.SetRequestScope,
// the same pattern every other DB-touching gateway code uses (see
// lookupClusterBySerial in server.go).
//
// The Disconnected update runs SECOND, after the Degraded update, in the same
// transaction — deliberately, not incidentally. Both statements see the same
// now() (stable for the duration of a transaction in Postgres) and each
// statement sees the previous statement's already-applied changes, so a
// cluster that's been silent long enough to qualify for Disconnected also
// necessarily qualified for Degraded a moment earlier in the same sweep
// (150s of silence implies 75s of silence): the first statement flips it
// Active->Degraded, and the second statement then immediately catches that
// same row via its "state IN ('Active','Degraded')" predicate and flips it
// straight on to Disconnected — all within this one tick, rather than
// leaving it stuck at Degraded until the next tick.
func (h *HealthMonitor) sweep(ctx context.Context) error {
	var degradedIDs, disconnectedIDs []string
	if err := data.InFleetScope(ctx, h.db.Pool, func(ctx context.Context, tx pgx.Tx, tenantID string) error {
		var err error
		degradedIDs, err = logDemotions(ctx, tx, degradeStaleActiveSQL, "Active -> Degraded", degradedThreshold.Seconds())
		if err != nil {
			return fmt.Errorf("degrade stale-active clusters: %w", err)
		}
		disconnectedIDs, err = logDemotions(ctx, tx, disconnectStaleSQL, "Active/Degraded -> Disconnected", disconnectedThreshold.Seconds())
		if err != nil {
			return fmt.Errorf("disconnect stale clusters: %w", err)
		}
		return nil
	}); err != nil {
		return err
	}
	// Published only after a successful commit — never for a demotion that
	// might still roll back. A cluster demoted twice in one sweep (Active ->
	// Degraded -> Disconnected, per this function's own doc comment above)
	// appears in both slices; publishing twice for it is harmless (the
	// frontend's refetch is idempotent) so no dedup is needed here.
	if h.events != nil {
		for _, id := range degradedIDs {
			h.events.Publish(events.ClusterUpdated(id))
		}
		for _, id := range disconnectedIDs {
			h.events.Publish(events.ClusterUpdated(id))
		}
	}

	// PROJECT.md T11: piggybacked onto this sweep's own tick rather than a
	// new ticker — this is the tunnel/connected-cluster-state metric, and it
	// is deliberately its OWN transaction, run only after the demotion
	// transaction above has already committed, so a failure here (or a
	// query left in an aborted-transaction state) can never roll back a real
	// demotion. See refreshClusterStateMetrics' own doc comment for the
	// query itself.
	h.refreshClusterStateMetrics(ctx)
	return nil
}

// refreshClusterStateMetrics sets metrics.ClustersByState from a single
// cheap `GROUP BY state` over the clusters table — bounded by construction,
// not merely by convention: clusters is sized to the fleet (hundreds, not
// incidents' scale), has no partitioning, and this query has run on the same
// health-sweep tick as the demotion UPDATEs above since T11 landed, so it
// adds no new polling cadence.
//
// Every call either sets EVERY known state (clusterLifecycleStates) to its
// real count, including a true zero for a state that currently has no
// clusters in it, or leaves metrics.ClustersByState entirely untouched on
// any error — never a partial update, and never a fabricated zero from a
// failed query (see metrics.Gauge's own doc comment).
func (h *HealthMonitor) refreshClusterStateMetrics(ctx context.Context) {
	counts := make(map[string]float64, len(clusterLifecycleStates))
	// PROJECT.md T24's per-cluster gauges, built from the same pass. The
	// aggregate GROUP BY became a per-row scan rather than gaining a second
	// query: the fleet is hundreds of rows, both metrics want the same
	// snapshot, and two queries could disagree with each other about a
	// cluster demoted between them.
	var stateSeries, heartbeatSeries []metrics.Series
	if err := data.InFleetScope(ctx, h.db.Pool, func(ctx context.Context, tx pgx.Tx, tenantID string) error {
		rows, err := tx.Query(ctx, `
			SELECT id, state, COALESCE(last_heartbeat_at, created_at)
			  FROM clusters`)
		if err != nil {
			return fmt.Errorf("read cluster states: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var id, state string
			var lastSeen time.Time
			if err := rows.Scan(&id, &state, &lastSeen); err != nil {
				return fmt.Errorf("scan cluster state: %w", err)
			}
			counts[state]++
			code, known := metrics.ClusterStateCode(state)
			if !known {
				// A lifecycle state this build does not know about (a
				// migration ahead of this binary). Omitted from the
				// per-cluster gauge rather than given a default code —
				// see metrics.ClusterStateCode's own doc comment. It
				// still counts toward the aggregate above only if
				// clusterLifecycleStates knows it, which is the existing,
				// deliberate behaviour.
				continue
			}
			stateSeries = append(stateSeries, metrics.Series{Labels: []string{id}, Value: code})
			heartbeatSeries = append(heartbeatSeries, metrics.Series{Labels: []string{id}, Value: float64(lastSeen.Unix())})
		}
		return rows.Err()
	}); err != nil {
		// Never a partial update and never a fabricated zero: the gauge is
		// left entirely untouched, exactly as the doc comment above promises.
		metrics.RecordCollectionFailure("cluster_state", err)
		return
	}

	// Every known state gets set — including a real, query-confirmed zero
	// for a state with no clusters right now — only because the query above
	// actually succeeded. An unrecognized state (a future migration adding
	// one this slice hasn't been updated for yet) is intentionally dropped
	// rather than guessed at.
	for _, state := range clusterLifecycleStates {
		metrics.ClustersByState.Set(counts[state], state)
	}
	// ReplaceSeries, not Set: a decommissioned or deleted cluster has to
	// LOSE its series, or an alert on "cluster X is Disconnected" keeps
	// firing about a cluster that no longer exists. Only reached on the
	// success path, so the same "never a fabricated zero, never a partial
	// update" rule as the aggregate above holds.
	metrics.ClusterState.ReplaceSeries(stateSeries)
	metrics.ClusterLastHeartbeatTimestampSeconds.ReplaceSeries(heartbeatSeries)
	metrics.RecordCollectionSuccess("cluster_state")
}

// logDemotions runs one demotion UPDATE, logs a line per row it actually
// changed — never just "ran a sweep" — and returns the affected clusters'
// IDs so the caller can publish a live-update event for each after its
// transaction commits. sql must RETURNING (id, display_name,
// last_heartbeat_at) with that third column as (or coalesced to) a non-NULL
// value — every caller now does this via COALESCE(last_heartbeat_at,
// created_at), so scanning it as a plain time.Time rather than *time.Time
// is safe here. args carries sql's bind parameters (today: the one threshold
// each caller parameterizes rather than hardcodes — see sweep).
func logDemotions(ctx context.Context, tx pgx.Tx, sql, transition string, args ...any) ([]string, error) {
	rows, err := tx.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var ids []string
	for rows.Next() {
		var id, displayName string
		var lastHeartbeatAt time.Time
		if err := rows.Scan(&id, &displayName, &lastHeartbeatAt); err != nil {
			return nil, fmt.Errorf("scan demoted cluster: %w", err)
		}
		logger.WarnContext(ctx, "demoting cluster: no recent heartbeat",
			logging.ClusterID(id),
			slog.String("display_name", displayName),
			slog.String("transition", transition),
			slog.Time("last_heartbeat_at", lastHeartbeatAt))
		ids = append(ids, id)
	}
	return ids, rows.Err()
}
