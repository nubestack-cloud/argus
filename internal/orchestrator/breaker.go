package orchestrator

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"argus/internal/domain"
)

// Circuit breakers for unattended execution — REMEDIATION_ROADMAP.md D-R7's last
// unbuilt safety component, and the one docs/USER_GUIDE.md §6 listed as missing.
//
// # Why neither existing limit covers this
//
// Three mechanisms now bound unattended execution, and they are not
// substitutable:
//
//	blastradius.go  bounds VOLUME    "no more than N executions per hour"
//	windows.go      bounds TIME      "not during the change freeze"
//	this file       bounds OUTCOME   "stop, because it is not working"
//
// A cap and a window are both declared in advance, so neither can notice that the
// changes being made are failing. An unattended loop that keeps acting while every
// action fails has, until now, had no brake at all — it would simply spend its
// hourly budget on failures, every hour.
//
// # What counts as a bad outcome, and why it is these two
//
//   - A **failed execution**. Unambiguous: ARGUS tried to change something and the
//     cluster refused.
//   - An incident that is **Reopened despite a successful execution**. This is the
//     one that matters, and it only became observable when V1 started asserting
//     that a change still holds. It means the API call succeeded and the fix did
//     not work — Argo reverted it, or the symptom came straight back. A breaker
//     watching only for errors would sit closed through exactly that failure, and
//     it is the failure mode most likely to repeat across a fleet.
//
// Both are counted from what is already recorded, and the two are counted by
// different units — per execution for failures, per incident for reverted fixes.
// countBadOutcomes explains why, including what an earlier version of it got wrong.
//
// # Two decisions worth disagreeing with explicitly
//
// **Reset is manual.** A breaker that re-closes on a timer is a rate limiter, and
// blastradius.go is already the rate limiter. The value of this one is that
// somebody looks at why the changes were failing before the loop resumes. The cost
// is real and is not hidden: a breaker that trips on Friday night leaves unattended
// execution off until a human resets it.
//
// **A trip stops unattended execution only. It never blocks a human.** A person
// approving a change is the recovery path, and a breaker that also blocked them
// would turn a bad afternoon into an outage nobody could act on.

// BreakerLimits is the resolved breaker policy.
type BreakerLimits struct {
	Enabled bool
	// MaxPerCluster and MaxFleetWide are bad outcomes TOLERATED within Window.
	// Exceeding either trips the corresponding breaker.
	MaxPerCluster int
	MaxFleetWide  int
	Window        time.Duration
}

// DefaultBreakerLimits applies when the operator has left the fields blank.
//
// Deliberately below DefaultUnattendedLimits (3 per cluster, 10 fleet-wide per
// hour): a breaker whose threshold sits above the volume cap can never trip,
// because the cap stops the loop before enough bad outcomes can accumulate. Sizing
// it relative to the cap rather than picking a round number is the whole reason
// these numbers are what they are.
var DefaultBreakerLimits = BreakerLimits{
	MaxPerCluster: 2,
	MaxFleetWide:  4,
	Window:        time.Hour,
}

// BreakerDecision is the answer to "may unattended execution proceed?".
type BreakerDecision struct {
	Allowed bool
	// Reason is operator-facing and states which breaker and why. Empty when
	// Allowed.
	Reason string
	// TrippedNow is true when THIS evaluation is what tripped the breaker, as
	// opposed to finding one already open. Callers use it to avoid re-announcing a
	// standing trip on every sweep.
	TrippedNow bool
}

// ResolveBreakerLimits applies the stored policy over the defaults.
//
// A NULL column falls back rather than meaning "unlimited" — the same convention
// as ResolveUnattendedLimits, and for the same reason: on a safety setting, the
// worst possible reading of a blank field is "no limit".
func ResolveBreakerLimits(enabled bool, perCluster, fleetWide, windowSeconds *int) BreakerLimits {
	out := DefaultBreakerLimits
	out.Enabled = enabled
	if perCluster != nil && *perCluster > 0 {
		out.MaxPerCluster = *perCluster
	}
	if fleetWide != nil && *fleetWide > 0 {
		out.MaxFleetWide = *fleetWide
	}
	if windowSeconds != nil && *windowSeconds > 0 {
		out.Window = time.Duration(*windowSeconds) * time.Second
	}
	return out
}

// CheckBreaker decides whether unattended execution may proceed for one cluster,
// tripping either breaker if this evaluation is what crosses its threshold.
//
// Order matters and is not arbitrary: an OPEN trip is checked first, so a standing
// trip is honoured without counting anything. Only then are outcomes counted, and
// the fleet-wide count is checked before the per-cluster one — a fleet-wide problem
// is the more serious statement, and it should be the one an operator is told
// about when both are true at once.
//
// Runs inside the caller's transaction so the count and any resulting trip commit
// together. Two sweeps racing cannot both trip: the partial unique index on open
// trips makes the second INSERT conflict, which is handled as "already tripped"
// rather than as an error.
func CheckBreaker(ctx context.Context, tx pgx.Tx, tenantID, clusterID string, limits BreakerLimits) (BreakerDecision, error) {
	if !limits.Enabled {
		return BreakerDecision{Allowed: true}, nil
	}

	open, reason, err := openTrip(ctx, tx, tenantID, clusterID)
	if err != nil {
		return BreakerDecision{}, err
	}
	if open {
		return BreakerDecision{Allowed: false, Reason: reason}, nil
	}

	since := time.Now().Add(-limits.Window)

	fleetBad, err := countBadOutcomes(ctx, tx, tenantID, "", since)
	if err != nil {
		return BreakerDecision{}, fmt.Errorf("count fleet-wide bad outcomes: %w", err)
	}
	if fleetBad >= limits.MaxFleetWide {
		reason := fmt.Sprintf("the fleet-wide circuit breaker tripped: %d remediation(s) across the fleet failed or were reverted in the last %s, at or above the limit of %d. Unattended execution is stopped until an operator resets it; approving changes by hand still works.",
			fleetBad, limits.Window, limits.MaxFleetWide)
		if err := trip(ctx, tx, tenantID, "", reason, fleetBad, limits.MaxFleetWide); err != nil {
			return BreakerDecision{}, err
		}
		return BreakerDecision{Allowed: false, Reason: reason, TrippedNow: true}, nil
	}

	clusterBad, err := countBadOutcomes(ctx, tx, tenantID, clusterID, since)
	if err != nil {
		return BreakerDecision{}, fmt.Errorf("count bad outcomes for cluster %s: %w", clusterID, err)
	}
	if clusterBad >= limits.MaxPerCluster {
		reason := fmt.Sprintf("the circuit breaker for this cluster tripped: %d remediation(s) on it failed or were reverted in the last %s, at or above the limit of %d. Unattended execution is stopped for this cluster until an operator resets it; approving changes by hand still works.",
			clusterBad, limits.Window, limits.MaxPerCluster)
		if err := trip(ctx, tx, tenantID, clusterID, reason, clusterBad, limits.MaxPerCluster); err != nil {
			return BreakerDecision{}, err
		}
		return BreakerDecision{Allowed: false, Reason: reason, TrippedNow: true}, nil
	}

	return BreakerDecision{Allowed: true}, nil
}

// openTrip reports whether an unreset trip covers this cluster. A fleet-wide trip
// covers every cluster, so both scopes are checked in one query — and the
// fleet-wide row is ordered first so its (more serious) reason is the one returned.
func openTrip(ctx context.Context, tx pgx.Tx, tenantID, clusterID string) (bool, string, error) {
	var reason string
	err := tx.QueryRow(ctx,
		`SELECT reason FROM circuit_breaker_trips
		  WHERE tenant_id = $1
		    AND reset_at IS NULL
		    AND (cluster_id IS NULL OR cluster_id = $2)
		  ORDER BY cluster_id NULLS FIRST
		  LIMIT 1`, tenantID, clusterID).Scan(&reason)
	if err == pgx.ErrNoRows {
		return false, "", nil
	}
	if err != nil {
		return false, "", fmt.Errorf("look up open circuit breaker trip: %w", err)
	}
	return true, reason, nil
}

// countBadOutcomes counts bad outcomes since `since`, fleet-wide when clusterID is
// empty and for one cluster otherwise.
//
// The two halves count DIFFERENTLY, and the asymmetry is the point rather than an
// oversight — an earlier version deduplicated both by incident and a test caught
// it failing to trip on two failures of the same incident:
//
//   - **Failed executions are counted per execution.** Each one is a discrete
//     event: ARGUS tried, and the cluster refused. One incident failing five times
//     is five bad outcomes, and deduplicating it to one would hide a stuck retry
//     loop — which is the most likely real failure and the one least likely to
//     resolve itself. The blast-radius cap bounds how fast such a loop spins; only
//     a breaker stops it.
//
//   - **Reverted fixes are counted per incident.** timeline_events now records
//     state-transition history (BACKLOG.md B1), but this function predates that
//     and was not rewritten to use it — "the fix did not hold" is still not
//     something this query counts as a discrete event — it is read as
//     "this incident is Reopened NOW and was successfully executed on inside the
//     window". An incident with three successful executions produces three JOIN
//     rows for ONE such state, so counting rows there would be counting a join
//     artifact rather than bad outcomes.
//
// Summed rather than UNIONed for the same reason: UNION would silently collapse a
// failed execution and a reverted fix on the same incident into one, and those are
// two genuinely different things having gone wrong.
func countBadOutcomes(ctx context.Context, tx pgx.Tx, tenantID, clusterID string, since time.Time) (int, error) {
	// $3 = "" means fleet-wide; the predicate is written so one query serves both
	// scopes and the two counts cannot drift apart.
	var n int
	err := tx.QueryRow(ctx,
		`SELECT
		   (SELECT count(*)
		      FROM remediation_executions e
		     WHERE e.tenant_id = $1
		       AND e.executed_at >= $2
		       AND ($3 = '' OR e.cluster_id = $3)
		       AND e.outcome = 'failed')
		 + (SELECT count(DISTINCT i.id)
		      FROM incidents i
		      JOIN remediation_executions e
		        ON e.incident_id = i.id
		       AND e.outcome = 'succeeded'
		       AND e.executed_at >= $2
		     WHERE i.tenant_id = $1
		       AND ($3 = '' OR i.cluster_id = $3)
		       AND i.state = 'Reopened')`, tenantID, since, clusterID).Scan(&n)
	if err != nil {
		return 0, err
	}
	return n, nil
}

// trip records an open trip. A conflict on the partial unique index means a
// concurrent sweep got there first, which is the intended outcome and not an
// error — the breaker is open either way.
func trip(ctx context.Context, tx pgx.Tx, tenantID, clusterID, reason string, bad, threshold int) error {
	var cluster *string
	if clusterID != "" {
		cluster = &clusterID
	}
	_, err := tx.Exec(ctx,
		`INSERT INTO circuit_breaker_trips (id, tenant_id, cluster_id, reason, bad_outcomes, threshold)
		 VALUES ($1, $2, $3, $4, $5, $6)
		 ON CONFLICT DO NOTHING`,
		domain.NewID(domain.PrefixCircuitBreakerTrip), tenantID, cluster, reason, bad, threshold)
	if err != nil {
		return fmt.Errorf("record circuit breaker trip: %w", err)
	}
	return nil
}
