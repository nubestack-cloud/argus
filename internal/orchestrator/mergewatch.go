package orchestrator

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"

	"argus/internal/data"
	"argus/internal/events"
	"argus/internal/logging"
	"argus/internal/metrics"
	"argus/internal/notify"
	"argus/internal/timeline"
)

// DefaultMergeSweepInterval is how often MergeSweeper polls. Same cadence as
// DefaultValidationSweepInterval and for the same reason — each tick is one
// provider call per AwaitingMerge incident (there are normally very few of
// these open at once), so ticking any slower would just leave a merged PR
// undetected longer for no real cost saved.
const DefaultMergeSweepInterval = 60 * time.Second

// mergeStalenessThreshold is how long a pull request may sit open, unmerged,
// before MergeSweeper flags it — DESIGN.md §12.3: "if a PR sits unmerged past
// a threshold, escalate." §12.3 itself sets the expectation that this is
// normal for "possibly days", so the threshold has to sit comfortably above
// an ordinary review cycle; nothing in DESIGN.md or lld/08 pins a number, so
// this is a starting default in the same spirit as validationGracePeriod's
// floor — a documented, revisable choice, not a measured one (see D15/D16 in
// DESIGN.md §23 for this codebase's other admittedly-provisional constants).
const mergeStalenessThreshold = 48 * time.Hour

// PullRequestOutcome is what MergeSweeper needs to know about one incident's
// pull request, each tick.
type PullRequestOutcome struct {
	Merged   bool
	MergedAt time.Time
	// Synced is meaningless when Merged is false. When Merged is true, Synced
	// distinguishes "merged and the GitOps controller has reconciled to it"
	// from "merged, but the workload has not picked it up yet" — the second
	// is not a state this incident should enter Validating on, because
	// nothing has actually changed in the cluster yet to watch for
	// recurrence of.
	Synced bool
	// Closed is meaningless when Merged is true. When Merged is false, Closed
	// distinguishes "closed without merging" from "still open" — BUGS.md 82:
	// PullRequestOutcome used to have no way to tell these apart at all, so a
	// rejected pull request left its incident in AwaitingMerge forever,
	// identically to one still under review.
	Closed bool
	// CreatedAt is when the provider recorded the pull request as opened.
	// Meaningless once Merged or Closed is true — both already have their own
	// resolution and sweep acts on them immediately, before staleness would
	// ever matter. Used only while the pull request is genuinely still open,
	// to flag one that has sat past mergeStalenessThreshold (DESIGN.md
	// §12.3's "escalate", BUGS.md 82's second half).
	CreatedAt time.Time
}

// PullRequestMergeChecker answers "what is true right now about the pull
// request behind this AwaitingMerge incident". Declared here and implemented
// by internal/api.Server (mergecheck.go) for the same reason
// AppliedValueVerifier is: the answer needs the scm provider and, to confirm
// Synced, a live tunnel call to the cluster, and internal/gateway already
// imports this package — so this package cannot import back to either.
type PullRequestMergeChecker interface {
	// CheckPullRequestMerged looks up the incident's recorded pull request
	// (incidents.pr_number, migration 000058) and asks the provider, then —
	// only if merged — asks the cluster whether it has synced past the merge
	// commit.
	//
	// An error means the check itself could not be made (unreachable
	// provider or cluster, no recorded PR) — not "not merged". Distinguishing
	// them matters exactly like it does in AppliedValueVerifier: an
	// unreachable provider must leave the incident in AwaitingMerge to be
	// retried next tick, not be read as "still open".
	CheckPullRequestMerged(ctx context.Context, incidentID string) (PullRequestOutcome, error)
}

// MergeSweeper polls every AwaitingMerge incident's pull request and, once
// merged AND converged, moves it to Validating — see this package's own doc
// comment and StateAwaitingMerge's for what this closes. From Validating
// onward it is one and the same mechanism as an in-place fix: ValidationSweeper
// promotes it to Resolved after a quiet grace period, or
// internal/gateway/finding.go's handleFinding reopens it the moment the
// symptom recurs. This sweeper's only job is supplying that mechanism's
// missing clock-start for the GitOps channel.
type MergeSweeper struct {
	db      *data.DB
	events  *events.Bus // may be nil in tests that don't care about live-update publishing, matching ValidationSweeper's own convention.
	checker PullRequestMergeChecker
}

// NewMergeSweeper constructs a MergeSweeper. Doesn't start sweeping — call
// Run for that.
func NewMergeSweeper(db *data.DB, bus *events.Bus, checker PullRequestMergeChecker) *MergeSweeper {
	return &MergeSweeper{db: db, events: bus, checker: checker}
}

// Run ticks every interval, running one sweep per tick, until ctx is
// cancelled. Blocks — callers run it in its own goroutine, same pattern as
// ValidationSweeper.Run.
func (m *MergeSweeper) Run(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			sweepCtx, _ := logging.NewUnitOfWork(ctx)
			start := time.Now()
			err := m.sweep(sweepCtx)
			metrics.ObserveSweeperRun("merge", time.Since(start), err)
			if err != nil {
				logger.ErrorContext(sweepCtx, "merge sweep failed", logging.Err(err))
			}
		}
	}
}

// sweep runs one pass inside a single RLS-scoped transaction — the same
// data.InFleetScope call ValidationSweeper.sweep uses for this same kind of
// fleet-wide job. (PROJECT.md G11: this was the hand-rolled
// SingleOrganisationID + SetRequestScope(..., nil) pair until the helper
// existed; the transaction is now scoped before this function can see it.)
func (m *MergeSweeper) sweep(ctx context.Context) error {
	type candidate struct{ incidentID, clusterID string }
	var updated []candidate

	if err := data.InFleetScope(ctx, m.db.Pool, func(ctx context.Context, tx pgx.Tx, tenantID string) error {
		rows, err := tx.Query(ctx, `SELECT id, cluster_id FROM incidents WHERE state = $1`, StateAwaitingMerge)
		if err != nil {
			return err
		}
		var candidates []candidate
		for rows.Next() {
			var c candidate
			if err := rows.Scan(&c.incidentID, &c.clusterID); err != nil {
				rows.Close()
				return err
			}
			candidates = append(candidates, c)
		}
		if err := rows.Err(); err != nil {
			return err
		}

		for _, c := range candidates {
			// Inline within the sweep's own transaction, same shape as
			// ValidationSweeper calling v.verifier — the checker opens and
			// commits its own separate transaction/tunnel call internally rather
			// than sharing this one.
			outcome, err := m.checker.CheckPullRequestMerged(ctx, c.incidentID)
			if err != nil {
				logger.WarnContext(ctx, "pull-request check failed; leaving the incident in AwaitingMerge to retry next sweep",
					logging.IncidentID(c.incidentID), logging.ClusterID(c.clusterID), logging.Err(err))
				continue
			}
			if !outcome.Merged {
				// BUGS.md 82: Closed and "still open" used to be the same branch
				// (this `if !outcome.Merged` covered both, and both simply
				// `continue`d) — a rejected pull request waited here forever,
				// identically to one still under review.
				if outcome.Closed {
					reason := "the pull request was closed without being merged"
					if _, err := tx.Exec(ctx,
						`UPDATE incidents SET pr_closed_unmerged_at = now(), pr_rejection_reason = $2 WHERE id = $1`,
						c.incidentID, reason); err != nil {
						return err
					}
					// DESIGN.md §12.3: "the incident returns to awaitingAction
					// [AwaitingApproval] with the rejection reason captured as
					// negative feedback" — the edge state.go's own doc comment
					// already draws and calls "legal and untravelled", because
					// until now nothing observed a close to travel it. The
					// in-place channel becomes available again the moment this
					// lands: AwaitingApproval is where a fresh plan (in-place or
					// another pull request) is approved from.
					//
					// Not recorded as §8.5's "negative-example store" — that
					// knowledge base does not exist yet (BACKLOG.md L2, "NOT
					// DONE — priority disputed"). pr_rejection_reason above is
					// the honest amount of persistence available today: durable
					// and queryable on the incident, but not yet feeding any
					// calibration or retrieval this codebase hasn't built.
					if err := SetState(ctx, tx, c.incidentID, StateAwaitingApproval); err != nil {
						if errors.Is(err, ErrIllegalTransition) {
							// Same race window as the merged/synced branch below:
							// a human already acted on this incident (or a
							// concurrent re-analysis moved it) between the
							// candidate query and now.
							logger.InfoContext(ctx, "incident left AwaitingMerge while this sweep was running; leaving it alone",
								logging.IncidentID(c.incidentID), logging.ClusterID(c.clusterID), logging.Err(err))
							continue
						}
						return err
					}
					// BACKLOG.md D9 B7: recorded on the incident's own timeline,
					// not just in the log line below — see
					// timeline.EventPullRequestClosed's own doc comment. Written
					// only after SetState actually succeeded, matching
					// ValidationSweeper's own ordering (timeline.go's own header
					// comment): a race that lost SetState above already
					// `continue`d before reaching here, so this can never record
					// a transition that did not really happen.
					if err := timeline.Record(ctx, tx, timeline.Event{
						TenantID: tenantID, ClusterID: c.clusterID, IncidentID: c.incidentID,
						Type:    timeline.EventPullRequestClosed,
						Summary: "Pull request closed without merging — returning to the approval queue",
						Detail:  map[string]any{"reason": reason},
					}); err != nil {
						return fmt.Errorf("record PullRequestClosed timeline event for incident %s: %w", c.incidentID, err)
					}
					updated = append(updated, c)
					logger.InfoContext(ctx, "incident returned to AwaitingApproval: its pull request was closed without merging",
						logging.IncidentID(c.incidentID), logging.ClusterID(c.clusterID))
					continue
				}
				// Genuinely still open. DESIGN.md §12.3: "if a PR sits unmerged
				// past a threshold, escalate" — mergeStalenessThreshold's doc
				// comment has the reasoning for the first number.
				// BACKLOG.md T3 (2026-09-04): the ORIGINAL version of this branch
				// notified exactly once, at 48h, forever after — a pull request
				// sitting unmerged for 7 days or 30 days got the identical single
				// nudge a 49-hour-old one did. escalation.go's escalationTiers
				// now widens the key with age (48h, then 5d, then 12d, then
				// weekly — see its own doc comment), so notify.NotifyTransition's
				// ON CONFLICT ... WHERE dedup guard still swallows a sweep that
				// observes the SAME still-current tier on its next 60s tick
				// (the key is unchanged), but a pull request that ages into the
				// NEXT tier gets a genuinely new key, and therefore a genuinely
				// new, more urgent send.
				if !outcome.CreatedAt.IsZero() {
					age := time.Since(outcome.CreatedAt)
					if key, tierIndex, ok := escalationNotifyKey("AwaitingMerge:StalePR", age); ok {
						roundedAge := age.Round(time.Hour)
						logger.WarnContext(ctx, "escalating: pull request has sat open and unmerged",
							logging.IncidentID(c.incidentID), logging.ClusterID(c.clusterID),
							slog.Duration("open_for", roundedAge), slog.Time("since", outcome.CreatedAt),
							slog.String("tier_key", key))
						summary := fmt.Sprintf("%sIncident %s (cluster %s): pull request has sat unmerged for %s.",
							escalationUrgencyPrefix(tierIndex), c.incidentID, c.clusterID, roundedAge)
						if err := notify.NotifyTransition(ctx, tx, tenantID, c.clusterID, c.incidentID, key, summary); err != nil {
							return err
						}
					}
				}
				continue
			}
			if !outcome.Synced {
				logger.InfoContext(ctx, "pull request merged but the GitOps controller has not synced past it yet; leaving the incident in AwaitingMerge",
					logging.IncidentID(c.incidentID), logging.ClusterID(c.clusterID))
				continue
			}

			if _, err := tx.Exec(ctx,
				`UPDATE incidents SET pr_merged_at = $2 WHERE id = $1`,
				c.incidentID, outcome.MergedAt); err != nil {
				return err
			}
			if err := SetState(ctx, tx, c.incidentID, StateValidating); err != nil {
				if errors.Is(err, ErrIllegalTransition) {
					// The candidate query above doesn't lock the rows it
					// returns, so this incident can have left AwaitingMerge
					// (closed by a human, or re-analysed back to
					// AwaitingApproval) between being selected and being
					// promoted. Skipped and logged, matching
					// ValidationSweeper's own race handling — one lost race
					// must not abort the whole sweep.
					logger.InfoContext(ctx, "incident left AwaitingMerge while this sweep was running; leaving it alone",
						logging.IncidentID(c.incidentID), logging.ClusterID(c.clusterID), logging.Err(err))
					continue
				}
				return err
			}
			// BACKLOG.md D9 B7: recorded on the incident's own timeline — see
			// timeline.EventPullRequestMerged's own doc comment for why this was
			// missing (mergewatch.go called timeline.Record nowhere at all).
			// Written only after SetState actually succeeded, for the same
			// race-safety reason the PullRequestClosed branch above is.
			if err := timeline.Record(ctx, tx, timeline.Event{
				TenantID: tenantID, ClusterID: c.clusterID, IncidentID: c.incidentID,
				Type:    timeline.EventPullRequestMerged,
				Summary: "Pull request merged, and the GitOps controller has synced past the merge commit",
				Detail:  map[string]any{"mergedAt": outcome.MergedAt.UTC().Format(time.RFC3339)},
			}); err != nil {
				return fmt.Errorf("record PullRequestMerged timeline event for incident %s: %w", c.incidentID, err)
			}
			updated = append(updated, c)
			logger.InfoContext(ctx, "incident moved to Validating: its pull request is merged and synced",
				logging.IncidentID(c.incidentID), logging.ClusterID(c.clusterID))
		}

		return nil
	}); err != nil {
		return err
	}
	// Published only after a successful commit, matching ValidationSweeper's
	// own reasoning: never announce a transition that might still roll back.
	if m.events != nil {
		for _, c := range updated {
			m.events.Publish(events.IncidentUpdated(c.incidentID, c.clusterID))
		}
	}
	return nil
}
