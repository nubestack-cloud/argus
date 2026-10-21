package orchestrator

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// Blast-radius limits for unattended execution.
//
// # Why this exists at all
//
// DESIGN.md §10.5 requires blast-radius batching to ship in the same release as
// unattended mode, and REMEDIATION_ROADMAP.md D-R7 sequences the whole safety
// net (rollback, freeze windows, blast-radius limits) *before* auto-remediation.
// The owner chose on 2026-08-22 to enable unattended execution with the smallest
// honest piece of that net rather than all of it — so this is the piece, and it
// is not optional.
//
// # The failure it exists to prevent, which per-incident risk cannot see
//
// Fleet correlation works. One bad image tag rolled to thirty clusters produces
// **thirty separate incidents**, each individually low-risk, each individually
// auto-approvable. Without a cap they all execute at once, and one wrong
// diagnosis becomes thirty wrong mutations. No per-incident risk assessment can
// catch that, because every one of those incidents genuinely *is* low-risk on its
// own — the danger is only visible in the aggregate, which is why the limit has
// to live here rather than in the gate.
//
// Two counters, because one cannot substitute for the other: thirty clusters
// each executing once is one per cluster (which no per-cluster limit would ever
// trip) and thirty in total.

// UnattendedLimits is the resolved budget for unattended execution.
type UnattendedLimits struct {
	Enabled bool
	// MaxPerCluster and MaxFleetWide are executions permitted within Window.
	MaxPerCluster int
	MaxFleetWide  int
	Window        time.Duration
}

// DefaultUnattendedLimits is what applies when the operator has enabled
// unattended execution but left the caps blank.
//
// Deliberately small. A blank field must not mean "unlimited" — that is the
// worst possible reading of an empty input on this screen, and it is why the
// columns are nullable-means-fall-back rather than nullable-means-off (the
// analysis.maxIterations convention, not detection's). These numbers are meant to
// be *noticed*: an operator who wants more raises them deliberately, having
// thought about the fleet-wide case.
var DefaultUnattendedLimits = UnattendedLimits{
	MaxPerCluster: 3,
	MaxFleetWide:  10,
	Window:        time.Hour,
}

// ResolveUnattendedLimits applies the DB-backed policy over the defaults, the
// same shape as ResolveAutonomyPolicy so both read the same way.
func ResolveUnattendedLimits(enabled bool, maxPerCluster, maxFleetWide, windowSeconds *int) UnattendedLimits {
	out := DefaultUnattendedLimits
	out.Enabled = enabled
	if maxPerCluster != nil && *maxPerCluster > 0 {
		out.MaxPerCluster = *maxPerCluster
	}
	if maxFleetWide != nil && *maxFleetWide > 0 {
		out.MaxFleetWide = *maxFleetWide
	}
	if windowSeconds != nil && *windowSeconds > 0 {
		out.Window = time.Duration(*windowSeconds) * time.Second
	}
	return out
}

// BlastRadiusDecision is why unattended execution may or may not proceed.
type BlastRadiusDecision struct {
	Allowed bool
	// Reason is written for a human and is recorded on the incident when a
	// refusal happens, because "nothing executed and nobody said why" is the
	// failure mode that makes an operator distrust the whole feature.
	Reason string
	// The counts behind the decision, so the reason can be checked rather than
	// believed — and so the same numbers can be shown in the UI.
	ClusterCount, FleetCount int
	Limits                   UnattendedLimits
}

// CheckBlastRadius decides whether one more unattended execution is within
// budget.
//
// Counts from remediation_executions, which is the only durable record of what
// actually ran — not from incident state, which can be rewritten, and not from an
// in-memory counter, which a hub restart would reset to zero and hand the fleet a
// fresh budget at the worst possible moment.
//
// Counts **succeeded and failed alike**. A failed unattended execution still
// mutated (or attempted to mutate) a live cluster and still consumed the
// operator's trust; excluding failures would mean a storm of failing executions
// never exhausted the budget, which is precisely backwards.
func CheckBlastRadius(ctx context.Context, tx pgx.Tx, clusterID string, limits UnattendedLimits, now time.Time) (BlastRadiusDecision, error) {
	d := BlastRadiusDecision{Limits: limits}
	if !limits.Enabled {
		d.Reason = "unattended execution is not enabled for this installation"
		return d, nil
	}

	since := now.Add(-limits.Window)
	if err := tx.QueryRow(ctx,
		`SELECT
		   count(*) FILTER (WHERE cluster_id = $1),
		   count(*)
		 FROM remediation_executions
		 WHERE unattended AND executed_at >= $2`,
		clusterID, since).Scan(&d.ClusterCount, &d.FleetCount); err != nil {
		// A counting failure must never read as "budget available". If the
		// budget cannot be established, unattended execution does not happen —
		// the incident still reaches a human, which is the pre-existing
		// behaviour and therefore a safe fallback rather than an outage.
		return BlastRadiusDecision{Limits: limits}, fmt.Errorf("orchestrator: count recent unattended executions: %w", err)
	}

	return decide(d.ClusterCount, d.FleetCount, limits), nil
}

// decide is the whole judgement, split out from the counting so it can be tested
// exhaustively without a database. The counting is one query; the reasoning is
// the part with cases worth being sure about.
func decide(clusterCount, fleetCount int, limits UnattendedLimits) BlastRadiusDecision {
	d := BlastRadiusDecision{ClusterCount: clusterCount, FleetCount: fleetCount, Limits: limits}
	if !limits.Enabled {
		d.Reason = "unattended execution is not enabled for this installation"
		return d
	}
	window := humanWindow(limits.Window)
	switch {
	case clusterCount >= limits.MaxPerCluster:
		d.Reason = fmt.Sprintf("this cluster has already run %s in the last %s (limit %d), so this one needs a human",
			plural(clusterCount, "unattended remediation"), window, limits.MaxPerCluster)
	case fleetCount >= limits.MaxFleetWide:
		d.Reason = fmt.Sprintf("the fleet has run %s in the last %s (limit %d), so this one needs a human. A burst across many clusters usually means one shared cause, which is exactly when a person should look before more changes land",
			plural(fleetCount, "unattended remediation"), window, limits.MaxFleetWide)
	default:
		d.Allowed = true
		d.Reason = fmt.Sprintf("within budget: %d/%d for this cluster and %d/%d fleet-wide in the last %s",
			clusterCount, limits.MaxPerCluster, fleetCount, limits.MaxFleetWide, window)
	}
	return d
}

// plural exists because a cap of 1 is not an unusual setting — it is the most
// conservative one an operator can express, and therefore likely the first one
// they try — so "1 unattended remediations" is a sentence this code would
// otherwise produce on its most cautious configuration.
func plural(n int, noun string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, noun)
	}
	return fmt.Sprintf("%d %ss", n, noun)
}

// humanWindow renders a duration the way the reason text needs to read, since
// "1h0m0s" in an operator-facing sentence is worse than no unit at all.
func humanWindow(d time.Duration) string {
	switch {
	case d >= time.Hour && d%time.Hour == 0:
		h := int(d.Hours())
		if h == 1 {
			return "hour"
		}
		return fmt.Sprintf("%d hours", h)
	case d >= time.Minute && d%time.Minute == 0:
		return fmt.Sprintf("%d minutes", int(d.Minutes()))
	default:
		return d.String()
	}
}
