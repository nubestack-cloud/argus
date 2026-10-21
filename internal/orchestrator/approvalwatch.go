package orchestrator

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"

	"argus/internal/data"
	"argus/internal/logging"
	"argus/internal/metrics"
	"argus/internal/notify"
)

// This file is BACKLOG.md T3's other half. mergewatch.go escalates a
// stale, unmerged pull request; ApprovalSweeper here escalates a stale,
// un-decided AwaitingApproval plan — DESIGN.md §13.3's "escalation on
// unattended incidents" applied to the second of the two "stuck behind a
// human" states T3 measured (10 AwaitingMerge, 1 AwaitingApproval, at the
// time T3 was filed; re-measure before citing either number). Before this,
// AwaitingApproval got exactly one notification ever — db.go's
// notifiableStates' one-shot "you just transitioned here" send — and
// nothing if the plan then just sat there for days with nobody deciding.
//
// Needs no external checker, unlike MergeSweeper: everything this sweep
// reads (the incident's state, its own timeline/recommendation history) is
// already in this database, so there is no "provider unreachable, retry
// next tick" case to model.

// DefaultApprovalSweepInterval mirrors DefaultMergeSweepInterval's cadence
// and reasoning exactly: one query per tick over however many
// AwaitingApproval incidents exist right now (normally very few), so
// ticking any slower would just leave a newly-crossed tier undetected
// longer for no real cost saved.
const DefaultApprovalSweepInterval = 60 * time.Second

// ApprovalSweeper polls every AwaitingApproval incident and escalates the
// ones whose current stint in that state has aged past the next
// escalation.go tier — see escalationTier's own doc comment for the
// widening schedule. Never changes an incident's state; escalation here is
// strictly a louder ask, the same non-negotiable mergewatch.go's own stale-
// PR branch already committed to (ARGUS must never act unilaterally on
// behalf of the missing human).
type ApprovalSweeper struct {
	db *data.DB
}

// NewApprovalSweeper constructs an ApprovalSweeper. Doesn't start sweeping
// — call Run for that.
func NewApprovalSweeper(db *data.DB) *ApprovalSweeper {
	return &ApprovalSweeper{db: db}
}

// Run ticks every interval, running one sweep per tick, until ctx is
// cancelled. Blocks — callers run it in its own goroutine, same pattern as
// MergeSweeper.Run/ValidationSweeper.Run.
func (a *ApprovalSweeper) Run(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			// One tick, one correlation id (PROJECT.md T23) — see
			// ValidationSweeper.Run for the argument.
			sweepCtx, _ := logging.NewUnitOfWork(ctx)
			start := time.Now()
			err := a.sweep(sweepCtx)
			metrics.ObserveSweeperRun("approval", time.Since(start), err)
			if err != nil {
				logger.ErrorContext(sweepCtx, "approval sweep failed", logging.Err(err))
			}
		}
	}
}

// approvalStintStartQuery answers "when did THIS incident's current,
// still-open AwaitingApproval stint begin", in COALESCE preference order:
//
//  1. The most recent RecommendationReady or PullRequestClosed timeline
//     event for the incident — both are real entry points into
//     AwaitingApproval today (orchestrator/db.go's ApplyAnalysisResult
//     writes RecommendationReady the moment a fresh plan is produced, in
//     the same transaction that calls SetState(..., StateAwaitingApproval);
//     mergewatch.go writes PullRequestClosed the moment a rejected pull
//     request bounces an incident back here) — so whichever is more recent
//     marks when the human's CURRENT decision actually became due, not
//     when some earlier, possibly-superseded plan first appeared.
//  2. Failing that — an incident from before timeline_events existed
//     (2026-08-26; see migration 000067's own comment), or one whose write
//     for some other reason never landed — the newest
//     remediation_recommendations row for the incident. Not as precise
//     (re-entering AwaitingApproval via the pull-request-closed path writes
//     no new recommendation row, only the timeline event above), but a plan
//     being produced and the incident entering AwaitingApproval happen in
//     the SAME transaction, so for the common "fresh plan" case this is
//     nearly as good.
//  3. Failing THAT too (should not happen — AwaitingApproval implies a
//     plan exists — but this sweep must never divide by a NULL), the
//     incident's own first_seen. Deliberately conservative: this OVER-
//     counts age for a row with no better signal, biasing toward
//     escalating too early rather than the opposite. A sweep that stays
//     silent on missing data is the exact failure T3 exists to close;
//     over-notifying a handful of edge-case rows is the safer direction to
//     err in.
const approvalStintStartQuery = `
	SELECT i.id, i.cluster_id,
	       COALESCE(
	         (SELECT MAX(occurred_at) FROM timeline_events
	            WHERE incident_id = i.id AND event_type IN ('RecommendationReady', 'PullRequestClosed')),
	         (SELECT MAX(created_at) FROM remediation_recommendations WHERE incident_id = i.id),
	         i.first_seen
	       ) AS stint_started_at
	  FROM incidents i
	 WHERE i.state = $1`

// sweep runs one pass inside a single RLS-scoped transaction — the same
// data.InFleetScope call MergeSweeper.sweep and ValidationSweeper.sweep use
// for this same kind of fleet-wide job. (PROJECT.md G11: this was the
// hand-rolled SingleOrganisationID + SetRequestScope(..., nil) pair until
// the helper existed; the transaction is now scoped before this function
// can see it — internal/data's own scope_structural_test.go is what keeps
// every background sweep on that helper.)
func (a *ApprovalSweeper) sweep(ctx context.Context) error {
	return data.InFleetScope(ctx, a.db.Pool, func(ctx context.Context, tx pgx.Tx, tenantID string) error {
		rows, err := tx.Query(ctx, approvalStintStartQuery, StateAwaitingApproval)
		if err != nil {
			return err
		}
		type candidate struct {
			incidentID, clusterID string
			stintStartedAt        time.Time
		}
		var candidates []candidate
		for rows.Next() {
			var c candidate
			if err := rows.Scan(&c.incidentID, &c.clusterID, &c.stintStartedAt); err != nil {
				rows.Close()
				return err
			}
			candidates = append(candidates, c)
		}
		if err := rows.Err(); err != nil {
			return err
		}

		for _, c := range candidates {
			age := time.Since(c.stintStartedAt)
			key, tierIndex, ok := escalationNotifyKey("AwaitingApproval:Stale", age)
			if !ok {
				continue
			}
			roundedAge := age.Round(time.Hour)
			logger.WarnContext(ctx, "escalating: a plan has been awaiting approval too long",
				logging.IncidentID(c.incidentID), logging.ClusterID(c.clusterID),
				slog.Duration("waiting_for", roundedAge), slog.Time("since", c.stintStartedAt),
				slog.String("tier_key", key))
			summary := fmt.Sprintf("%sIncident %s (cluster %s): a remediation plan has been awaiting approval for %s.",
				escalationUrgencyPrefix(tierIndex), c.incidentID, c.clusterID, roundedAge)
			if err := notify.NotifyTransition(ctx, tx, tenantID, c.clusterID, c.incidentID, key, summary); err != nil {
				return err
			}
		}

		return nil
	})
}
