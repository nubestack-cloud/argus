// Package timeline implements BACKLOG.md B1: writing and reading
// timeline_events, the incident state-transition history lld/11-ui-design.md
// §4 specifies as GET /incidents/{id}/timeline and which — per BACKLOG.md V2
// — had a real migration (000005) and zero Go code writing it, "the worst of
// both" between wiring the table properly and deleting it. This package is
// the "wire it properly" half.
//
// Record is this package's one write entry point, deliberately shaped like
// internal/audit.RecordEvent: it takes the caller's own already-open,
// already-scoped pgx.Tx and never opens a transaction or calls
// data.SetRequestScope itself. Every one of this task's call sites
// (orchestrator.MarkInvestigating/ApplyAnalysisResult,
// internal/api/approvals.go's approve/reject handlers,
// internal/execution's recordExecutingTransition/
// recordExecutionOutcome, internal/orchestrator/validation.go's sweep) is
// already inside a transaction that resolved and set RLS scope for the
// state-changing write it commits alongside — writing here too, in the SAME
// transaction, means a timeline row can never survive a rolled-back
// transition, and a transition can never commit silently missing its own
// history line, matching this codebase's "one function, two callers can't
// silently diverge" / "no bare write outside an already-scoped transaction"
// conventions (see internal/data.SetRequestScope's own doc comment).
//
// migration 000067 is the reason this works at all under the ambient scope
// every one of those call sites actually runs with (almost always the
// tenant-wide "" app.accessible_cluster_ids, not narrowed to one cluster):
// timeline_events carried only migration 000009's original single
// PERMISSIVE cluster-keyed policy until then, with no "empty list means no
// narrowing" branch and no tenant fallback — so an INSERT run under the
// ordinary ambient scope would have been rejected outright as an RLS policy
// violation, and a read would have silently returned zero rows. See that
// migration's own header for the full reasoning; it mirrors the exact
// two-policy shape migration 000035 already proved correct for
// incidents/findings/analyses/clusters.
package timeline

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/jackc/pgx/v5"

	"argus/internal/domain"
)

// Event types. Named to mirror DESIGN.md §20.2's domain-event naming
// convention (lld/05-data-model.md §3.5's own comment on
// timeline_events.event_type: "mirrors HLD §20.1's domain-event names" — the
// live section is actually §20.2, see lld/10-api-spec.md §5's StreamEvent
// contract, which already uses this exact vocabulary for IncidentOpened/
// RecommendationReady). Kept as a closed Go const set, not a free-form string
// at each call site, so a typo can't silently create a new, unrecognized
// event type nothing renders.
const (
	// EventIncidentOpened is written once, when a Finding creates a brand
	// new incident (internal/gateway/finding.go's handleFinding) — the
	// "detection" transition, question 1 of the four the incident screen
	// answers.
	EventIncidentOpened = "IncidentOpened"

	// EventInvestigationStarted is written when an incident moves into
	// Investigating (orchestrator.MarkInvestigating) — an investigation
	// step starting, whether human-triggered re-analysis or the automatic
	// analyzer.
	EventInvestigationStarted = "InvestigationStarted"

	// EventAnalysisCompleted is written once an investigation finishes
	// (orchestrator.ApplyAnalysisResult), whatever it concluded — a root
	// cause found, "could not determine", or a bound hit. This is the
	// investigation-step-finishing half; EventRecommendationReady below is
	// the separate, conditional half for when that analysis also produced
	// a plan.
	EventAnalysisCompleted = "AnalysisCompleted"

	// EventRecommendationReady is written alongside EventAnalysisCompleted,
	// only when the analysis actually produced a remediation plan.
	EventRecommendationReady = "RecommendationReady"

	// EventApprovalGranted/EventApprovalRejected are written on a human (or
	// unattended-executor) approval decision — internal/api/approvals.go's
	// handleApproveIncident/handleRejectIncident and
	// internal/execution's recordExecutingTransition (the
	// in-place path's own approval bookkeeping).
	EventApprovalGranted  = "ApprovalGranted"
	EventApprovalRejected = "ApprovalRejected"

	// EventPullRequestOpened is written when an approved OpenPR plan
	// actually opens a pull request (internal/api/approvals.go's
	// approveByOpeningPullRequest) — the PR route's stand-in for
	// "execution starting", since nothing in-cluster changes until a human
	// merges it.
	EventPullRequestOpened = "PullRequestOpened"

	// EventExecutionStarted is written when an approved in-place plan
	// actually begins executing against the cluster
	// (internal/execution's recordExecutingTransition,
	// AwaitingApproval -> Executing).
	EventExecutionStarted = "ExecutionStarted"

	// EventExecutionOutcome is written once that execution resolves
	// (internal/execution's recordExecutionOutcome,
	// Executing -> Validating/Reopened or Failed) — succeeded or not, with
	// the real error on a failure.
	EventExecutionOutcome = "ExecutionOutcome"

	// EventParamsCorrectionAttempted is written whenever a proposed plan's
	// params got exactly one bounded internal/llm.CorrectPlanParams
	// correction attempt — win or lose — at any of the (now three) points in
	// a plan's lifecycle that mechanism is wired into. Detail always carries
	// "reason" (the rejection/Validate() failure the correction was given),
	// "outcome" (a short account of what the attempt itself produced), and
	// "succeeded" (bool); an analyze-time attempt additionally carries
	// "actionType". The three callers:
	//
	//   - internal/api/analyze.go (BUGS.md 109 / BACKLOG.md AG1), immediately
	//     before the AnalysisCompleted/RecommendationReady pair
	//     ApplyAnalysisResult writes for the same analysis, whenever a
	//     proposed plan's Params were nil/invalid (analyzeTimeCorrectionAttempt).
	//   - internal/execution/correction.go's retryDryRunWithCorrection (F12b),
	//     via recordExecutingTransition, on a post-approval dry-run rejection
	//     of an in-place plan (dryRunCorrectionAttempt).
	//   - internal/api/openpr_correction.go's retryOpenPRProposalWithCorrection
	//     (BACKLOG.md AL1 decision 4), on an approval-time
	//     gitops.ProposeChanges refusal of an OpenPR plan that is plausibly
	//     about its proposed Content being wrong (openPRApprovalCorrectionAttempt) —
	//     recorded in rc.Tx on success (internal/api/approvals.go's
	//     approveByOpeningPullRequest) or in recordFailedOpenPRApproval's own
	//     separately-committed transaction on failure, for the identical
	//     reason EventPullRequestProposalFailed below needs one.
	//
	// One event type for all three rather than a per-caller sibling: the
	// Detail shape and the fact it records ("a proposed plan's params were
	// corrected, win or lose") are identical across all three — only WHICH
	// rejection triggered it and WHEN in the lifecycle differ, and those are
	// already distinguishable from "reason" and from which other events
	// surround this one on the same incident's timeline. Exists so a plan
	// that reached AwaitingApproval, or an opened pull request, only after a
	// correction reads, in the incident's own history, as "corrected", never
	// as if the model got it right on the first try — and so a plan that
	// still landed on NeedsHumanInvestigation, or a still-refused repository
	// change, shows a human that a correction was already attempted and did
	// not help, rather than looking identical to no attempt at all.
	EventParamsCorrectionAttempted = "ParamsCorrectionAttempted"

	// EventPullRequestProposalFailed is BUGS.md 110's fix for the "zero
	// recorded trace" half of that bug: written by
	// internal/api/approvals.go's approveByOpeningPullRequest whenever an
	// approved OpenPR plan fails to actually open a pull request (a live-repo
	// refusal internal/gitops.ProposeChanges returns — a forbidden path, a
	// file outside the synced directory, content that does not parse, a blob
	// that moved since the synced commit, and so on). Before
	// this existed, that failure left literally zero rows anywhere:
	// requireAuth's own transaction handling rolls back the request's whole
	// transaction on any >=400 response, so even the
	// remediation_approval_decisions row this same function writes earlier
	// never survives. This event is therefore written in its OWN,
	// separately-committed transaction — the same reasoning
	// recordCapabilityDenial (internal/api/middleware.go) already
	// established for the identical problem. Detail carries "planId" and
	// "reason" (the verbatim refusal text, the same string returned in the
	// 422 response — nothing more sensitive than what the caller already
	// saw). The incident's state is deliberately left untouched
	// (AwaitingApproval) — this event is a trace of the attempt, not a new
	// state-machine transition; see BACKLOG.md AL1 for why that larger
	// question is left open.
	EventPullRequestProposalFailed = "PullRequestProposalFailed"

	// EventValidationOutcome is written once a Validating incident is
	// promoted to Resolved or Reopened, by either of the two independent
	// paths that make that transition: the automated post-fix re-check
	// (internal/orchestrator/validation.go's ValidationSweeper, the delayed
	// "no news is good news" half — Detail["route"] is the recorded
	// remediation route, "pullRequest" or in-place), or a live Finding
	// recurring on the object while still Validating
	// (internal/gateway/finding.go's reopenAfterRecurrence — the immediate,
	// event-driven half; Detail["route"] is "eventDriven" there). Both are the
	// same domain fact — a fix that did not hold — so they share one event
	// type rather than each minting its own.
	EventValidationOutcome = "ValidationOutcome"

	// EventNoActionableNextStep is BACKLOG.md F27's mechanical guard
	// (internal/api.FlagMissingRunnableNextStep, called from both
	// analyze.go and autoanalyze.go immediately after
	// orchestrator.EnforceRoute): written once, on a "complete" analysis
	// that proposed no plan at all (neither ProposedPlan nor
	// ProposedPairedPlan) AND whose suggestedNextSteps contains no entry
	// that looks like a real, directly runnable command. This is not a
	// refusal — the null plan is already the honest, correct outcome for
	// this incident — it is a recorded fact that the operator was left with
	// prose or field-path guidance only, so a human reading the incident's
	// timeline sees that gap rather than a silent one. Detail carries
	// "suggestedNextSteps" (the model's own list, verbatim, for context).
	EventNoActionableNextStep = "NoActionableNextStep"

	// EventPullRequestMerged/EventPullRequestClosed are BACKLOG.md D9 B7's
	// fix for a real hole in "what happened": internal/orchestrator/
	// mergewatch.go's MergeSweeper is the only place either outcome of a
	// pull request opened for an incident is ever detected, and until now it
	// called timeline.Record nowhere at all — an incident that sat in
	// AwaitingMerge, then merged (or was closed unmerged and bounced back to
	// AwaitingApproval), left no trace of either on this incident's own
	// timeline, even though EventPullRequestOpened above already records the
	// pull request being OPENED. Split into two event types, not folded into
	// one "PullRequestResolved" with an outcome field, because every other
	// pair of opposite outcomes in this const block (ApprovalGranted/
	// ApprovalRejected) already gets one type each — a reader scanning
	// event_type values for "was this incident's PR ever closed without
	// merging" should not have to open Detail to find out.
	//
	// EventPullRequestMerged is written once the sweeper observes BOTH the
	// provider reporting the PR merged AND the GitOps controller having
	// synced past the merge commit (PullRequestOutcome.Synced) — the same
	// gate mergewatch.go's own StateValidating promotion waits for, so this
	// event and that transition are always written together, in the same
	// transaction.
	EventPullRequestMerged = "PullRequestMerged"
	// EventPullRequestClosed is written when the provider reports the pull
	// request closed WITHOUT merging — BUGS.md 82's own outcome, which
	// returns the incident to AwaitingApproval rather than leaving it stuck.
	EventPullRequestClosed = "PullRequestClosed"

	// EventIncidentResolved/EventIncidentDismissed are BACKLOG.md D9 B7's
	// other fix: internal/api/incident_triage.go's triageIncident is the
	// shared body of POST .../resolve and POST .../dismiss, and until now it
	// wrote an audit.RecordEvent (the compliance trail) but no
	// timeline.Record at all — so a human closing an incident by hand, which
	// this codebase's own doc comments call one of the two most ordinary
	// things an operator does, left the incident's own "what happened"
	// history silent about the close itself. audit_events answers "is this
	// auditable"; timeline_events answers "what happened to THIS incident",
	// and the two must not be treated as substitutes for each other.
	//
	// Two types rather than one "IncidentClosed" with a verdict field, for
	// the identical reason EventPullRequestMerged/EventPullRequestClosed
	// above are split: ApprovalGranted/ApprovalRejected already set the
	// precedent that this package tells opposite verdicts apart by type, not
	// by a field a renderer has to branch on.
	EventIncidentResolved  = "IncidentResolved"
	EventIncidentDismissed = "IncidentDismissed"

	// EventIncidentRecurredAfterExpiry is PROJECT.md T2's own recurrence
	// event: a Finding re-attached to an incident that had aged out
	// (StateExpired), moving it back to StateDetected — "a recurrence can
	// reopen an expired incident," recorded as its own fact rather than
	// folded into ValidationOutcome (that event's own name and shape are
	// specific to the Validating -> Resolved/Reopened re-check; nothing was
	// ever fixed here, so nothing was validated).
	EventIncidentRecurredAfterExpiry = "IncidentRecurredAfterExpiry"

	// EventIncidentExpired is PROJECT.md T2's own third close-out type,
	// added for the identical reason Resolved/Dismissed are split rather
	// than sharing one type with a verdict field: a bulk/automatic closure
	// (nobody ever actioned this incident; it aged out) is a different
	// FACT from a human's deliberate Dismissed, and a renderer should never
	// have to inspect a detail field to tell them apart.
	EventIncidentExpired = "IncidentExpired"

	// EventIncidentSelfHealed also records the stale sweep's cleared-incident
	// closure (internal/autoanalyze/cleared.go): a Detected incident nobody
	// investigated, quiet for the same grace period, whose object reads
	// healthy when re-read live. Detail.fromState is "Detected" there.
	//
	// EventIncidentSelfHealed is PROJECT.md T4's own closure event: an
	// incident sitting in Diagnosed or NeedsHumanInvestigation — ARGUS
	// finished investigating and found no in-cluster action to propose (not
	// "hit a bound and gave up", see internal/orchestrator's own
	// disposition/isFault handling for that distinction) — whose object then
	// went quiet for the SAME grace period ValidationSweeper's own
	// Validating -> Resolved re-check uses (validationGracePeriod /
	// effectiveGracePeriod, internal/orchestrator/validation.go), with no
	// recurring Finding, no execution and no merged pull request anywhere in
	// the picture.
	//
	// Deliberately NOT EventValidationOutcome: that type's own doc comment
	// already draws the line this event is on the other side of — "nothing
	// was ever fixed here, so nothing was validated" is EXACTLY this event's
	// situation too (nothing was ever proposed here either, which is a
	// stronger version of the same fact), so reusing a type whose name and
	// shape are pinned to "a fix's outcome, positive or negative" would tell
	// the same kind of lie EventIncidentRecurredAfterExpiry was minted to
	// avoid. Deliberately NOT EventIncidentResolved either: that type is a
	// human's OWN triage decision (internal/api/incident_triage.go), and this
	// is the opposite fact — nobody decided anything, the fault simply
	// stopped recurring on its own. Detail carries "fromState" (Diagnosed or
	// NeedsHumanInvestigation) so a reader can tell which of PROJECT.md T4's
	// two live cases produced this closure without re-deriving it from the
	// rest of the incident's history.
	EventIncidentSelfHealed = "IncidentSelfHealed"

	// EventAutoAnalysisFailed is written by internal/autoanalyze whenever an
	// AUTOMATIC investigation it started did not complete — the provider
	// errored, the tool loop failed, no AI provider was usable at all.
	//
	// It exists because that outcome used to leave no trace anywhere. The
	// poller logged a line to stdout, left the incident in Investigating (a
	// state the candidate query excludes, so nothing ever retried it) and
	// stamped auto_analysis_attempted_at as if the attempt had concluded. The
	// incident then read as "an investigation is running now" forever, and the
	// reason it was not was recoverable only from hub logs nobody was reading.
	// An EventInvestigationStarted with no matching AnalysisCompleted after it
	// is exactly the shape a reader cannot interpret; this is the event that
	// closes that pair honestly.
	//
	// Detail carries "error" (the failure text, truncated at the write site),
	// "attempts" (how many automatic attempts this incident has now had),
	// "willRetry" (bool), and "classification" ("configuration" or
	// "transient") — so a reader can tell "we will try again shortly" from
	// "the automatic path has given up on this one, analyze it by hand"
	// without reading the prose.
	EventAutoAnalysisFailed = "AutoAnalysisFailed"

	// EventAnalysisFailed is AutoAnalysisFailed's counterpart for an
	// investigation a PERSON started (POST /incidents/{id}/analyze). That
	// request now answers 202 before the investigation runs (PROJECT.md M1),
	// so a failure can no longer be reported in the response — this event,
	// with incidents.analysis_error, is where it lands instead, closing the
	// InvestigationStarted it follows. Detail carries "error" (the reason, as
	// shown to the operator) and "restoredState" (where the incident was put
	// back to).
	EventAnalysisFailed = "AnalysisFailed"
)

// Event is one row to write. Mirrors internal/audit.Event's shape (a struct
// passed to a single Record function) for the same reason: adding a field
// later touches one signature, not every call site's positional argument
// list.
type Event struct {
	TenantID   string
	ClusterID  string
	IncidentID string
	Type       string
	// Summary is the short, human-readable line this task's brief asks
	// for — the one thing every event type carries regardless of what else
	// is known. Stored as payload["summary"] rather than a separate column:
	// the schema (migration 000005/lld/05-data-model.md §3.5) defines only
	// id/incident_id/tenant_id/cluster_id/event_type/payload/occurred_at,
	// and adding a column here would diverge from the LLD's own DDL for no
	// benefit — a jsonb key is exactly as queryable for the one thing this
	// table is read for (rendering a chronological list), and keeps every
	// event-type-specific detail in the same payload object instead of a
	// second place to look.
	Summary string
	// Detail is whatever event-type-specific, already-known structured
	// information is cheap to attach (a root-cause statement, an action
	// type, an outcome, an error string) — never a new evidence-capture
	// path (BACKLOG.md B2 is the sibling task for evidence drill-down; this
	// package only records that a transition happened and the facts already
	// in hand when it did). May be nil.
	Detail map[string]any
}

// Record inserts one timeline_events row inside tx, which must already be an
// open transaction with RLS scope resolved for tenantID (see this package's
// own doc comment on why Record never calls data.SetRequestScope itself).
func Record(ctx context.Context, tx pgx.Tx, ev Event) error {
	if ev.IncidentID == "" {
		return fmt.Errorf("timeline: refusing to record a %q event with no incident id", ev.Type)
	}
	if ev.Type == "" {
		return fmt.Errorf("timeline: refusing to record an event with no event type (incident %s)", ev.IncidentID)
	}

	detail := ev.Detail
	if detail == nil {
		detail = map[string]any{}
	}
	// summary is folded into the same payload object rather than sent as a
	// sibling column — see Event.Summary's doc comment.
	detail["summary"] = ev.Summary

	payload, err := json.Marshal(detail)
	if err != nil {
		return fmt.Errorf("timeline: marshal payload for %q event on incident %s: %w", ev.Type, ev.IncidentID, err)
	}

	// clock_timestamp(), NOT now()/transaction_timestamp(): now() is fixed at
	// the enclosing transaction's START and never advances within it, so two
	// Record calls in the same transaction (ApplyAnalysisResult's
	// AnalysisCompleted followed by RecommendationReady, or
	// recordExecutingTransition's ApprovalGranted followed by
	// ExecutionStarted) would otherwise get the IDENTICAL occurred_at value.
	// listTimelineEvents' ORDER BY occurred_at ASC, id ASC then falls back to
	// comparing ULIDs, which are NOT insertion-ordered among IDs minted in the
	// same millisecond (their tail is random, not a counter) — so two same-
	// transaction events could render in the wrong order despite one being a
	// documented consequence of the other. Caught by
	// TestApplyAnalysisResultWritesAnalysisAndRecommendationEvents and
	// TestRecordExecutionOutcomeWritesExecutionOutcomeEvent failing
	// intermittently before this fix. clock_timestamp() returns the actual
	// current instant, advancing on every call even mid-transaction, so
	// sequential writes get genuinely increasing timestamps.
	if _, err := tx.Exec(ctx,
		`INSERT INTO timeline_events (id, incident_id, tenant_id, cluster_id, event_type, payload, occurred_at)
		 VALUES ($1, $2, $3, $4, $5, $6, clock_timestamp())`,
		domain.NewID(domain.PrefixTimelineEvent), ev.IncidentID, ev.TenantID, ev.ClusterID, ev.Type, payload,
	); err != nil {
		return fmt.Errorf("timeline: record %q event for incident %s: %w", ev.Type, ev.IncidentID, err)
	}
	return nil
}
