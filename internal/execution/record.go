package execution

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"argus/internal/audit"
	"argus/internal/authz"
	"argus/internal/data"
	"argus/internal/domain"
	"argus/internal/logging"
	"argus/internal/metrics"
	"argus/internal/orchestrator"
	"argus/internal/remediation"
	"argus/internal/timeline"
)

// Actor is who authorized one execution, and it exists because
// "unattended" is not expressible as a user id.
//
// Before unattended execution shipped, both recording functions below read
// scope.UserID and hardcoded ActorAuthMethod "jwt", which was true of every caller
// there was. It is not true of the sweeper, and the tempting shortcuts — a
// sentinel user id, or an empty string that every reader has to know means
// something — both push a machine decision into a column readers treat as a
// person. Passing the actor explicitly means each call site states which it is,
// and neither can drift onto the other's attribution by accident.
type Actor struct {
	// UserID is the approving human, or empty for an unattended execution. It
	// becomes a genuine SQL NULL in that case, never a sentinel.
	UserID string
	// AuthMethod is audit.Event.ActorAuthMethod: how this actor was
	// authenticated, or how the decision was reached when there was no actor.
	AuthMethod string
	// SourceIP is the approver's address. Empty for the sweeper, which has no
	// remote peer — no request reached the hub, so there is no address to
	// record and recording the hub's own would be a fiction.
	SourceIP string
	// Unattended is the durable flag on both the approval decision and the
	// execution row. Kept as its own field rather than derived from
	// UserID == "" for the reason migrations 000046/000047 both give: "nobody
	// approved this" and "no human approved this" must stay distinguishable.
	Unattended bool
	// Reason is why this actor was entitled to act, and it is only ever set for
	// the unattended case — a human approval's rationale is the approval itself.
	// It carries the gate's verdict and the blast-radius numbers that were true
	// at the moment of the decision, which is the only explanation of this
	// change anyone will ever find.
	Reason string
}

// PolicyActor is the autonomy policy acting on its own. "policy" rather than
// "system": the hub did not decide this, the operator's own configured autonomy
// policy did, and an auditor tracing an unexplained change needs to be sent to
// the settings page rather than to a vague background process.
var PolicyActor = Actor{AuthMethod: "policy", Unattended: true}

// ActorIDOrNil returns what goes into a nullable actor column — a real SQL
// NULL for an unattended decision, never a sentinel. Exported because
// migration 000047's (actor_id IS NULL) = unattended invariant is asserted
// against it from internal/api's own actor test, which is where humanActor
// lives.
func (a Actor) ActorIDOrNil() *string { return nullIfEmpty(a.UserID) }

// recordExecutingTransition is the row-locked, separately-committed
// transaction that makes approving this plan irreversible: it re-checks
// (under a row lock on the incident, closing the double-approve race the
// approved plan calls out explicitly) that the incident is still
// AwaitingApproval and this plan hasn't already been approved, then
// records the approval decision and the AwaitingApproval -> Executing
// transition together, as one atomic fact — committed here, before the
// caller ever calls the agent, so a hub crash immediately after this
// returns still leaves a durable, honest "we committed to this" record.
//
// confirmScaleFromZero is recorded in the audit event's Details — see below
// for why it's recorded unconditionally, including when false.
//
// rollback is the pre-computed compensating action (nil for action types that
// have none) and is recorded in the same Details map, in the same transaction,
// for the reason DESIGN.md §10.3 asks for it at all: an undo
// must not require re-analysis. Once this commits, the values needed to put
// the workload back are durable and attributable even if the hub dies before
// the Patch is issued, or the cluster's own state has moved on by the time
// anyone looks. Recorded here rather than in recordExecutionOutcome
// deliberately — that transaction runs AFTER the mutation, which is exactly
// when a captured-before-execution record would no longer be one.
// corrections is BACKLOG.md F12b's retry history — empty for the ordinary
// case (the dry-run rehearsal was accepted on the first attempt), non-empty
// only when one or more automatic corrections were needed to reach an
// attestation that succeeded. Recorded into this same audit event, in this
// same transaction, so a plan that needed correcting is provably
// distinguishable from a first-try success rather than looking identical to
// one — see this file's own doc comment on why the exhausted-retry case
// (nothing committed) has no equivalent row to attach it to.
//
// attempt is the durable "a cluster is about to be changed" row (migration
// 000093, internal/execution/attempt.go). It rides in THIS transaction,
// for the same reason the compensating action does and one more: the
// incidents.state = 'Executing' marker this transaction commits is not on its
// own enough to recover from, because nothing can tell from it what was in
// flight, and — as the review that produced this found — nothing reconciles it
// at all. A zero-value attempt (ID == "") writes no row, which is what the
// DB-backed tests that drive this function directly pass.
func (s *Executor) recordExecutingTransition(ctx context.Context, scope Scope, incidentID, planID, clusterID string, actor Actor, confirmedScaleFromZero, confirmedGitOpsManaged bool, digestWarning string, rollback *remediation.CompensatingAction, attestation dryRunAttestation, corrections []dryRunCorrectionAttempt, attempt executionAttempt) error {
	tx, err := s.db.Pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	if err := data.SetRequestScope(ctx, tx, scope.TenantID, nil); err != nil {
		return fmt.Errorf("set request scope: %w", err)
	}

	// BACKLOG.md G6: the planId replay dedup chokepoint every one of the
	// three ways a plan gets decided (this one, approveByOpeningPullRequest,
	// and handleRejectIncident) now shares — see
	// concurrency.go's LockIncidentForDecision for why this is
	// the same lock orchestrator.SetState itself takes, rather than a
	// second, independently-fallible check.
	if err := LockIncidentForDecision(ctx, tx, incidentID, planID); err != nil {
		return err
	}

	// Written after the lock, so a request that loses the double-approve race
	// leaves no attempt behind — the whole transaction rolls back either way,
	// but "check whether this may still be decided, then write" is the order
	// this commit point reads in everywhere else.
	if attempt.ID != "" {
		if err := insertExecutionAttempt(ctx, tx, attempt); err != nil {
			return err
		}
	}

	decisionID := domain.NewID(domain.PrefixApproval)
	// A row is written for an unattended execution too, with a NULL actor and
	// the unattended flag set (migration 000047's XOR invariant). Skipping it
	// would leave executions nobody watched as the only ones with no decision
	// behind them, which is precisely backwards for an audit trail. `reason`
	// carries the gate's own words in that case — an unattended decision has no
	// human rationale, but it does have a machine one, and it is the only
	// explanation that will ever exist for this change.
	//
	// analysis_id (migration 000116, PROJECT.md L8) pins what this approval is
	// a judgement OF — see DecisionAnalysisSubquery below. It matters
	// at least as much on this path as on the human one: an unattended approval's
	// only rationale is the gate's own words, and those are a verdict on the
	// analysis's confidence and proposed action, which are meaningless later
	// without knowing which prompt version and model produced them.
	if _, err := tx.Exec(ctx,
		`INSERT INTO remediation_approval_decisions (id, recommendation_id, incident_id, tenant_id, cluster_id, actor_id, verdict, reason, unattended, analysis_id)
		 VALUES ($1, $2, $3, $4, $5, $6, 'approved', $7, $8, `+DecisionAnalysisSubquery("$2")+`)`,
		decisionID, planID, incidentID, scope.TenantID, clusterID, actor.ActorIDOrNil(),
		nullIfEmpty(actor.Reason), actor.Unattended); err != nil {
		return fmt.Errorf("record approval: %w", err)
	}

	if err := orchestrator.SetState(ctx, tx, incidentID, orchestrator.StateExecuting); err != nil {
		return err
	}

	// BACKLOG.md B1: the approval decision (question 3/4) and execution
	// starting (question 4/5) — two separate timeline events for two
	// separate facts, even though this in-place route reaches both in the
	// same transaction. approvalSummary is deliberately honest about an
	// unattended approval rather than implying a human clicked something.
	approvalSummary := "Approved"
	if actor.Unattended {
		approvalSummary = "Automatically approved by policy"
	}
	if err := timeline.Record(ctx, tx, timeline.Event{
		TenantID: scope.TenantID, ClusterID: clusterID, IncidentID: incidentID,
		Type: timeline.EventApprovalGranted, Summary: approvalSummary,
		Detail: map[string]any{
			"planId":     planID,
			"unattended": actor.Unattended,
			"reason":     actor.Reason,
		},
	}); err != nil {
		return fmt.Errorf("record ApprovalGranted timeline event: %w", err)
	}
	if err := timeline.Record(ctx, tx, timeline.Event{
		TenantID: scope.TenantID, ClusterID: clusterID, IncidentID: incidentID,
		Type: timeline.EventExecutionStarted, Summary: "Execution started",
		Detail: map[string]any{"planId": planID},
	}); err != nil {
		return fmt.Errorf("record ExecutionStarted timeline event: %w", err)
	}

	capability := authz.CapRemediationApprove
	// confirmScaleFromZero is recorded ALWAYS, including the ordinary false
	// case, and for every action type rather than only ScaleDeployment. It
	// is a fact about the request the approver made, which is what this log
	// is for, and recording it unconditionally means "this approver did not
	// claim that intent" is a provable statement rather than something
	// inferred from a missing key — a distinction that matters precisely
	// when someone is auditing whether a workload somebody switched off
	// got turned back on, and by whom.
	// confirmScaleFromZero/confirmGitOpsManaged record the REDEEMED value, not
	// the raw request boolean (WORKLOG §97 G5's whole point): after the token
	// requirement, "this approver's request had the flag set" and "this
	// approver actually proved the refusal was shown to them" can differ — a
	// stale, wrong, or absent token now makes the boolean false regardless of
	// what the client sent. Recording the raw boolean here would silently
	// undo the fix by making the audit trail believe the unverified claim
	// again. Always recorded, including the ordinary false case, and for
	// every action type: "this approver did not (successfully) claim that
	// intent" must be a provable fact, not an inference from a missing key.
	details := map[string]any{
		"action": "approve_remediation", "incidentId": incidentID, "planId": planID,
		"confirmScaleFromZero": confirmedScaleFromZero,
		"confirmGitOpsManaged": confirmedGitOpsManaged,
	}
	// Recorded only when non-empty (unlike the two confirm booleans above,
	// which are recorded unconditionally): this is informational context about
	// a RevertContainerImage plan specifically, not a fact "every approver
	// either did or did not claim" the way the two overrides are. WORKLOG §97
	// G4.
	if digestWarning != "" {
		details["imageMutableTagWarning"] = digestWarning
	}
	if rollback != nil {
		// Both the human-readable statement and the machine-applicable params:
		// the first is what an operator reads at 3am, the second is what a
		// future undo path re-signs and executes without re-deriving anything.
		// Recorded as decoded JSON rather than a string blob so the audit
		// record stays queryable.
		details["rollback"] = map[string]any{
			"actionType":  string(rollback.ActionType),
			"description": rollback.Description,
			"params":      json.RawMessage(rollback.Params),
		}
	}
	// Recorded unconditionally, like the two confirm booleans and for the same
	// reason: "the cluster was asked to rehearse this change, and accepted it,
	// at this instant" is the single fact that separates an execution ARGUS
	// verified from one it merely attempted. It has to be provable after the
	// fact, not inferable from the absence of a failure. The dry-run result
	// object is deliberately NOT stored here — it is a whole Kubernetes object
	// per approval, it is only needed while the approver is looking at it
	// (BACKLOG.md F13), and audit_events is the wrong place to accumulate
	// payloads that large.
	details["dryRunAttestedAt"] = attestation.At.Format(time.RFC3339)
	// BACKLOG.md F12b: recorded ONLY when non-empty, unlike the always-on
	// fields above — "corrected zero times" and "this plan had no need to be
	// corrected at all" are the same fact, so there is nothing false about
	// omitting the key, unlike confirmScaleFromZero/confirmGitOpsManaged
	// where a missing key would be ambiguous with "never asked". When
	// present, dryRunCorrectionCount is the plain number an approver reads
	// at a glance, and dryRunCorrections is the full per-attempt detail
	// (the rejection text, the corrected params, and the outcome) for
	// whoever needs to check exactly what changed and why.
	if len(corrections) > 0 {
		details["dryRunCorrectionCount"] = len(corrections)
		details["dryRunCorrections"] = corrections
	}
	// Recorded on every approval, not only unattended ones: "a person approved
	// this" has to be a positive, provable statement, not the absence of a flag.
	details["unattended"] = actor.Unattended
	if actor.Reason != "" {
		details["unattendedReason"] = actor.Reason
	}
	if err := audit.RecordEvent(ctx, tx, audit.Event{
		TenantID: scope.TenantID, ActorID: actor.ActorIDOrNil(), ActorAuthMethod: actor.AuthMethod, SourceIP: actor.SourceIP,
		Capability: &capability, ClusterID: &clusterID, Outcome: audit.OutcomeSuccess,
		Details: details,
	}); err != nil {
		return fmt.Errorf("record audit event: %w", err)
	}

	return tx.Commit(ctx)
}

// recordExecutionOutcome writes the second, separate transaction: the
// remediation_executions row, the settlement of the attempt that preceded the
// mutation, and whatever incident state transition the outcome calls for —
// always with the real reason on a failure. Returns the incident state the
// transaction leaves behind. Attributed to whoever authorised the change: the
// approving user, the autonomy policy, or (when a reconciler settles an
// abandoned attempt) the actor recorded on the attempt row, never a vague
// system actor invented at settlement time.
//
// states says where the incident goes for each outcome — see
// incidentOutcomeStates. An empty destination means "leave the state alone",
// which is a real answer for a rollback and not a missing one.
//
// # This function must never lose the execution row
//
// It used to compute one destination and let orchestrator.SetState's refusal
// abort the whole transaction. That inverted the priorities: by the time this
// runs, a production cluster has already been changed (or has already refused
// the change), and the remediation_executions row is the only durable record
// of it. An incident whose state is a little behind is a bookkeeping problem;
// a mutation with no record is an operator being lied to.
//
// So the transition is validated against the incident's ACTUAL current state,
// read here under the same row lock SetState itself takes, and a destination
// that is not reachable is REPORTED — logged, and carried on the timeline
// event and the audit record as stateNote — rather than allowed to discard the
// fact. Two live faults sat behind that inversion: an undo on a Resolved
// incident (terminal, so Reopened is refused) and a failed undo from
// Validating (no Validating -> Failed edge). Both changed the cluster and then
// rolled back their own record.
// actionType/kind are PROJECT.md T11's execution-outcomes metric labels —
// see this function's own doc comment for why this single chokepoint is
// where that metric is recorded: every remediation_executions row, forward
// or undo, is written here and nowhere else, so a metric recorded at any
// other call site could not be trusted to be exhaustive. actionType is a
// remediation.ActionType (11 fixed values) or "unknown" for the rare
// orphaned-Executing recovery path that genuinely has no attempt record to
// read one from (settleOrphanExecuting); kind is "forward" or "undo".
func (s *Executor) recordExecutionOutcome(ctx context.Context, scope Scope, incidentID, planID, clusterID string, actor Actor, outcome, execError, resourceVersionPrecondition string, rollback *remediation.CompensatingAction, forwardApplied string, states incidentOutcomeStates, attemptID, actionType, kind string) (string, error) {
	tx, err := s.db.Pool.Begin(ctx)
	if err != nil {
		return "", fmt.Errorf("begin transaction: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	if err := data.SetRequestScope(ctx, tx, scope.TenantID, nil); err != nil {
		return "", fmt.Errorf("set request scope: %w", err)
	}

	// The incident's real current state, under the same FOR UPDATE lock
	// orchestrator.SetState takes — so the legality check below and the write
	// that follows it cannot be separated by a concurrent transition, and so a
	// reconciler settling an abandoned attempt serialises against a request
	// that came back to life.
	var currentState string
	if err := tx.QueryRow(ctx, `SELECT state FROM incidents WHERE id = $1 FOR UPDATE`, incidentID).Scan(&currentState); err != nil {
		return "", fmt.Errorf("lock incident %s to record an execution outcome: %w", incidentID, err)
	}

	var errPtr *string
	if execError != "" {
		errPtr = &execError
	}
	// All three NULL together for an action type with no representable undo —
	// migration 000050's CHECK enforces that pairing, so it cannot drift.
	var rollbackActionType, rollbackDescription *string
	var rollbackParams []byte
	if rollback != nil {
		at := string(rollback.ActionType)
		rollbackActionType = &at
		rollbackParams = rollback.Params
		rollbackDescription = nullIfEmpty(rollback.Description)
	}
	executionID := domain.NewID(domain.PrefixExecution)
	if _, err := tx.Exec(ctx,
		`INSERT INTO remediation_executions (id, recommendation_id, incident_id, tenant_id, cluster_id, outcome, error, resource_version_precondition, unattended,
		   rollback_action_type, rollback_params, rollback_description, forward_applied_value)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)`,
		executionID, planID, incidentID, scope.TenantID, clusterID, outcome, errPtr, resourceVersionPrecondition,
		// This is the column the blast-radius cap counts. It is written here,
		// in the same transaction as the outcome, so a failed unattended
		// execution still consumes budget — a storm of failures that never
		// exhausted the limit would be exactly backwards.
		actor.Unattended,
		// The undo, on the row it undoes. Written for a FAILED execution too, and
		// deliberately: a failure that got as far as patching may have applied
		// part of the change, and the undo is the only record of what the values
		// were beforehand. The rollback endpoint refuses a failed execution
		// anyway; that is a policy decision made there, where it can be explained,
		// rather than by silently not storing the data.
		rollbackActionType, rollbackParams, rollbackDescription, nullIfEmpty(forwardApplied)); err != nil {
		return "", fmt.Errorf("record execution: %w", err)
	}

	// Close the attempt this outcome explains, in the same transaction as the
	// row that explains it, exactly once. A losing writer — a request that
	// came back after a reconciler had already concluded — is refused here
	// rather than allowed to record a second execution for one mutation.
	if attemptID != "" {
		if err := settleExecutionAttempt(ctx, tx, attemptID, executionID, outcome); err != nil {
			return "", err
		}
	}

	// The destination for this outcome, checked against the state the incident
	// is REALLY in. An unreachable destination is reported, never allowed to
	// discard the execution row — see this function's own doc comment.
	newState, stateNote := currentState, ""
	if want := states.forOutcome(outcome); want != "" && want != currentState {
		switch {
		case orchestrator.CanTransition(currentState, want):
			if err := orchestrator.SetState(ctx, tx, incidentID, want); err != nil {
				return "", err
			}
			newState = want
		default:
			stateNote = fmt.Sprintf("recorded a %s outcome but left this incident in %s: %s -> %s is not a legal transition",
				outcome, currentState, currentState, want)
			logger.WarnContext(ctx, "the execution is recorded but the incident state was not advanced",
				logging.IncidentID(incidentID), slog.String("note", stateNote))
		}
	}

	// BACKLOG.md B1: the execution outcome (question 4/5) — succeeded or
	// not, with the real error on a failure, same discipline as the audit
	// event a few lines below.
	outcomeSummary := fmt.Sprintf("Execution %s", outcome)
	outcomeDetail := map[string]any{"planId": planID, "outcome": outcome, "nextState": newState}
	if execError != "" {
		outcomeDetail["error"] = execError
	}
	// Recorded only when there IS one, unlike outcome/nextState: "the state
	// advanced normally" and "there was nothing to say about the state" are
	// the same fact, so an absent key means exactly one thing. When present it
	// is the operator's explanation for why an incident's state does not look
	// like what just happened to it.
	if stateNote != "" {
		outcomeDetail["stateNote"] = stateNote
	}
	if err := timeline.Record(ctx, tx, timeline.Event{
		TenantID: scope.TenantID, ClusterID: clusterID, IncidentID: incidentID,
		Type: timeline.EventExecutionOutcome, Summary: outcomeSummary, Detail: outcomeDetail,
	}); err != nil {
		return "", fmt.Errorf("record ExecutionOutcome timeline event: %w", err)
	}

	capability := authz.CapRemediationApprove
	auditOutcome := audit.OutcomeSuccess
	if outcome != "succeeded" {
		auditOutcome = audit.OutcomeError
	}
	if err := audit.RecordEvent(ctx, tx, audit.Event{
		TenantID: scope.TenantID, ActorID: actor.ActorIDOrNil(), ActorAuthMethod: actor.AuthMethod, SourceIP: actor.SourceIP,
		Capability: &capability, ClusterID: &clusterID, Outcome: auditOutcome,
		Details: map[string]any{"action": "execute_remediation", "incidentId": incidentID, "planId": planID,
			"outcome": outcome, "error": execError, "unattended": actor.Unattended,
			// The same explanation the timeline carries, in the record an
			// auditor reads: an execution whose incident did not move needs to
			// say so here too, or the audit trail and the incident disagree
			// with no way to tell which is right.
			"stateNote": stateNote, "incidentState": newState},
	}); err != nil {
		return "", fmt.Errorf("record audit event: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return "", fmt.Errorf("commit: %w", err)
	}
	// PROJECT.md T11 — recorded only after the commit above actually
	// succeeds, matching this function's own "the execution row is the one
	// thing that must never be lost" discipline: a metric for a row that
	// didn't durably land would misrepresent what actually happened.
	metrics.RemediationExecutionTotal.Inc(actionType, kind, outcome)
	return newState, nil
}

// DecisionAnalysisSubquery returns the scalar subquery every writer of a
// remediation_approval_decisions row uses to fill analysis_id (migration
// 000116): "the analysis the plan being decided was derived from". The
// argument is the placeholder that already carries the recommendation id in
// that INSERT — `$2` in all three of today's writers.
//
// PROJECT.md L8: a verdict is a judgement OF something, and until 000116 the
// row said only what the verdict WAS. Pinning the analysis makes the prompt
// version, the model, the root cause and the evidence the operator was
// reacting to reachable from the decision, at a point in time when all four
// still mean what they meant.
//
// WHY THE RECOMMENDATION'S ANALYSIS AND NOT THE INCIDENT'S NEWEST. The two can
// differ: a re-analysis can land between a plan reaching AwaitingApproval and a
// human deciding it, and getLatestAnalysis (analyze.go) orders by created_at
// DESC, so "newest at write time" is not necessarily what was on screen.
// approvalQueueQuery and approvalDetailQuery above both join the analysis
// through `analyses.id = rr.analysis_id` — the root cause, confidence, causal
// chain and ruled-out list rendered beside the Approve and Reject buttons are
// that recommendation's analysis. Keying off the recommendation is therefore
// the only derivation that matches what the operator was actually shown.
//
// WHY A SUBQUERY RATHER THAN A PRECEDING SELECT. The pin is then taken in the
// same statement as the decision itself: it cannot fail on its own, it cannot
// be skipped by a later early return added above it, and it cannot read a
// different row than the one recommendation_id names.
// remediation_recommendations.analysis_id is NOT NULL, nothing in the tree ever
// updates it, and recommendation_id is a NOT NULL foreign key into that table —
// so this always resolves to exactly one non-NULL id. A NULL in the column
// therefore means "written before migration 000116", never "the lookup missed".
func DecisionAnalysisSubquery(recommendationIDParam string) string {
	return "(SELECT analysis_id FROM remediation_recommendations WHERE id = " + recommendationIDParam + ")"
}
