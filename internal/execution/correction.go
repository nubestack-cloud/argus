package execution

// This file is BACKLOG.md F12b: the dry-run retry loop. F12 (this package)
// already rehearses every approved plan against the cluster immediately before
// the irreversible commit and refuses outright on rejection — before this file
// existed, that refusal was simply returned to the human approver, who had to
// re-diagnose by hand and re-submit a corrected plan (there was no plan to
// correct FROM; a human just approved a different one, or none). This closes
// that loop: on a dry-run rejection, the cluster's own refusal text is fed back
// to the model, which proposes a corrected Params value for the SAME action
// type and target, and the correction is run back through PreparePlan's full
// pipeline — never a shortened one — before ever being dry-run-attempted again.
//
// Deliberately scoped to the approval path (ExecuteApprovedPlan) only. The
// preflight/preview path (internal/api/preflight.go, BACKLOG.md F13) calls s.PreparePlan
// directly and NOT through preparePlanWithCorrection below: a preview's whole
// purpose is showing a human what the cluster would actually do, and silently
// substituting a model-corrected plan there would defeat that. The rollback/
// undo path (undo.go) is likewise left calling s.PreparePlan directly —
// undoing an already-executed change is a narrower, time-pressured operation
// this backlog item does not name, and extending retry to it is future work,
// not a silent scope creep here.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"

	"argus/internal/llm"
	"argus/internal/remediation"
	"argus/internal/resolution"
)

// maxDryRunCorrectionAttempts bounds how many times the retry loop will ask
// the model to correct a plan the cluster's dry-run rehearsal just refused,
// before giving up and surfacing the rejection exactly as it would have
// surfaced before this feature existed.
//
// dot-ai's own analogous loop (BACKLOG.md F12's original entry) bounds itself
// at 10 attempts, but that bounds GENERATION against no live system — a wrong
// guess there costs one more model turn and nothing else. Every attempt here
// costs a real signed dry-run round trip through the full authorisation chain
// of a customer's live cluster (attestByDryRun's own doc comment on what a
// dry run actually does), so copying that number uncritically would multiply
// real cluster load and model spend by a factor with no evidence behind it.
// Bounded at 3 instead: one attempt to get the schema/bounds right, one to
// actually use the specific rejection text rather than guess again, and a
// third for the case where the first correction reveals a SECOND constraint
// that only becomes visible once the first is satisfied (e.g. a quota
// rejection whose message changes once memory is lowered enough to reveal a
// separate CPU ceiling). A rejection that survives three genuine corrections
// is overwhelmingly more likely to need a human than a fourth guess, and
// leaving the incident AwaitingApproval with a clear "still refused" message
// is a better outcome for the operator than a longer wait for the same
// result.
const maxDryRunCorrectionAttempts = 3

// dryRunRejectedError marks a PreparePlan failure as the CLUSTER's (or its
// ARGUS agent's) own refusal of this specific plan's PARAMS — as opposed to
// every other way PreparePlan can fail: an unresolvable pod-template target,
// a stale/raised risk floor, a scale-from-zero or GitOps-precedence
// guardrail refusal, a protected namespace, or interpretDryRunResult's own
// version-skew integrity check (an agent that never confirmed it ran a dry
// run at all). None of those is something a corrected params value could
// plausibly fix — they are refusals of the PLAN'S SHAPE, its target, or
// ARGUS's own policy, not of the specific numbers inside it — so only THIS
// failure is what retryDryRunWithCorrection below acts on.
//
// Identified by type (errors.As), never by matching the message text: the
// human-facing sentence wrapping it (attestByDryRun) is explicit that it may
// be reworded, and a retry loop keyed to prose would silently stop firing
// the day someone improved that sentence.
type dryRunRejectedError struct {
	// Rejection is the cluster/agent's own words, unwrapped — exactly what
	// is fed back to the model, and what dryRunCorrectionAttempt.Rejection
	// records for the audit trail and the exhausted-retry error message.
	Rejection string
	cause     error
}

func (e *dryRunRejectedError) Error() string { return e.cause.Error() }
func (e *dryRunRejectedError) Unwrap() error { return e.cause }

// dryRunCorrectionAttempt is one round of the retry loop below — the
// rejection it responded to, the corrected params it produced (if any), and
// what happened next. Kept in order for two reasons: the operator-facing
// message on exhaustion (so "still refused after 3 attempts" is provably
// true rather than asserted), and BACKLOG.md F12b's explicit audit-visibility
// ask — recordExecutingTransition attaches this slice to the SAME approval
// audit event every other approval detail lands in, so an approver can tell
// "this plan was corrected N times before committing" instead of a
// successful commit looking identical to a first-try one.
type dryRunCorrectionAttempt struct {
	Rejection       string          `json:"rejection"`
	CorrectedParams json.RawMessage `json:"correctedParams,omitempty"`
	Outcome         string          `json:"outcome"`
}

// PlanCorrectionModel is implemented by *llm.Router's CorrectPlanParams —
// narrowed to just this one method (mirroring cliBackendReporter's own
// rationale in internal/api/server.go) so a test can supply a scripted stand-in without
// implementing llm.Investigator's whole tool-calling surface. s.llmProvider
// is ALSO the same *llm.Router in production (see cmd/hub/main.go), just
// held under the llm.Investigator interface there instead — the two Server
// fields exist because Investigate and CorrectPlanParams are two different
// narrow interfaces, not because they need to be two different instances.
// Before BACKLOG.md P13, CorrectPlanParams lived on *llm.Provider instead,
// which is why it used to need to be threaded through separately from the
// Router.
type PlanCorrectionModel interface {
	CorrectPlanParams(ctx context.Context, plan remediation.RemediationPlan, rejection string) (remediation.ActionParams, llm.Result, error)
}

// preparePlanWithCorrection is ExecuteApprovedPlan's entry point into the
// retry loop: it resolves this incident's stored resolution.Route (needed for
// the route-permitted-action-types safety check below) and closes over
// s.PreparePlan/s.planCorrector as the two seams retryDryRunWithCorrection
// needs, so that function itself stays a plain, DB-free, cluster-free
// function of its arguments and is unit-testable without either.
func (s *Executor) preparePlanWithCorrection(
	ctx context.Context, scope Scope,
	incidentID, planID, clusterID string,
	plan remediation.RemediationPlan,
	overrides Overrides,
) (PlanPrep, []dryRunCorrectionAttempt, error) {
	var routeCol *string
	if err := scope.Tx.QueryRow(ctx, `SELECT route FROM incidents WHERE id = $1`, incidentID).Scan(&routeCol); err != nil {
		return PlanPrep{}, nil, fmt.Errorf("look up this incident's resolution route: %w", err)
	}
	route := resolution.Route(deref(routeCol))

	attempt := func(ctx context.Context, p remediation.RemediationPlan) (PlanPrep, error) {
		return s.PreparePlan(ctx, scope, incidentID, planID, clusterID, p, overrides, PrepForExecution)
	}
	correct := func(ctx context.Context, p remediation.RemediationPlan, rejection string) (remediation.ActionParams, error) {
		if s.planCorrector == nil {
			// No AI provider configured (or the test/dev build wired none) —
			// behave exactly as if this feature did not exist: the ORIGINAL
			// dry-run rejection is what retryDryRunWithCorrection surfaces
			// when correct() returns an error, not this one.
			return nil, errors.New("no AI provider is configured to propose a correction")
		}
		params, _, err := s.planCorrector.CorrectPlanParams(ctx, p, rejection)
		return params, err
	}

	return retryDryRunWithCorrection(ctx, plan, route, attempt, correct)
}

// retryDryRunWithCorrection is BACKLOG.md F12b's loop itself, factored out as
// a function of two closures (attempt, correct) — matching this file's
// existing precedent for pulling a safety-critical check out into a pure,
// directly testable function (interpretDryRunResult's own doc comment gives
// the identical reasoning for the same move).
//
// attempt runs PreparePlan for one candidate plan end to end: target
// resolution, the risk-floor recheck against the resolved target, every
// per-action guardrail (scale-from-zero, resource-limit bounds, PatchField's
// live-value/allowlist checks, ...), GitOps precedence, signing, and the
// dry-run rehearsal itself. A corrected proposal gets the exact same
// preparation a first-try plan gets — never a shortened version — which is
// what makes "the retried proposal goes through the same validation the
// original plan did" true by construction rather than by a second,
// hand-maintained checklist.
//
// correct asks the model for a replacement Params value given one
// rejection's own text, and its return is treated as a bare, unvalidated
// suggestion: this function runs it through RemediationPlan.Validate() (the
// closed-enum check, the Params/ActionType match, risk-level validity, and —
// for a PatchField-shaped plan — the ValidatingAdmissionPolicy field
// allowlist via PatchFieldPermitted) and the incident's route-permitted
// action-types check BEFORE ever handing it to attempt for another dry run.
// A correction that fails either is refused outright, exactly like a
// freshly-proposed plan would be, and is never retried again with the same
// rejected shape — only a fresh model call, spending one of the bounded
// attempts, gets another try.
func retryDryRunWithCorrection(
	ctx context.Context,
	plan remediation.RemediationPlan,
	route resolution.Route,
	attempt func(ctx context.Context, plan remediation.RemediationPlan) (PlanPrep, error),
	correct func(ctx context.Context, plan remediation.RemediationPlan, rejection string) (remediation.ActionParams, error),
) (PlanPrep, []dryRunCorrectionAttempt, error) {
	current := plan
	var history []dryRunCorrectionAttempt

	for i := 0; ; i++ {
		prep, err := attempt(ctx, current)
		if err == nil {
			return prep, history, nil
		}

		var rejected *dryRunRejectedError
		if !errors.As(err, &rejected) {
			// Not the cluster's own content refusal — a guardrail, a
			// resolution failure, a stale risk floor, a version-skew
			// integrity check, or any other PreparePlan failure a corrected
			// params value could not plausibly address. Surfaced exactly as
			// it would have been before this feature existed.
			return PlanPrep{}, history, err
		}
		if i >= maxDryRunCorrectionAttempts {
			logger.WarnContext(ctx, "plan exhausted every automatic dry-run correction attempt and is still refused",
				slog.Int("attempts", maxDryRunCorrectionAttempts), slog.String("rejection", rejected.Rejection))
			history = append(history, dryRunCorrectionAttempt{Rejection: rejected.Rejection, Outcome: "exhausted"})
			return PlanPrep{}, history, fmt.Errorf(
				"the cluster still refuses this plan after %d automatic correction attempt(s): %w", maxDryRunCorrectionAttempts, err)
		}

		correctedParams, correctErr := correct(ctx, current, rejected.Rejection)
		if correctErr != nil {
			history = append(history, dryRunCorrectionAttempt{Rejection: rejected.Rejection, Outcome: "correction unavailable: " + correctErr.Error()})
			// The ORIGINAL dry-run rejection, not correctErr — a caller with
			// no AI provider configured, or a model that failed to answer,
			// sees the same error this dry-run failure would have produced
			// with no retry loop at all.
			return PlanPrep{}, history, err
		}

		candidate := current
		candidate.Params = correctedParams
		if valErr := candidate.Validate(); valErr != nil {
			history = append(history, dryRunCorrectionAttempt{Rejection: rejected.Rejection, Outcome: "corrected proposal refused as structurally invalid: " + valErr.Error()})
			return PlanPrep{}, history, fmt.Errorf(
				"a corrected proposal was generated but refused as structurally invalid (%v); the cluster's original refusal was: %w", valErr, err)
		}
		if !actionTypePermittedByRoute(route, candidate.ActionType) {
			history = append(history, dryRunCorrectionAttempt{Rejection: rejected.Rejection, Outcome: fmt.Sprintf("corrected proposal refused: action type %q is not permitted on this incident's %q route", candidate.ActionType, route)})
			return PlanPrep{}, history, fmt.Errorf(
				"a corrected proposal was generated but its action type %q is not permitted on this incident's %q route; the cluster's original refusal was: %w", candidate.ActionType, route, err)
		}

		correctedJSON, marshalErr := json.Marshal(correctedParams)
		if marshalErr != nil {
			// Can only mean correctedParams holds something json.Marshal
			// itself refuses (a channel, a func — not a real params struct)
			// which candidate.Validate() above would already have to have
			// let through; kept as a hard stop rather than silently logging
			// no params at all, since this is exactly the shape of bug this
			// whole file exists to make loud rather than quiet.
			return PlanPrep{}, history, fmt.Errorf("marshal corrected params for the audit trail: %w", marshalErr)
		}
		history = append(history, dryRunCorrectionAttempt{Rejection: rejected.Rejection, CorrectedParams: correctedJSON, Outcome: "retrying with corrected params"})
		current = candidate
	}
}

// actionTypePermittedByRoute is orchestrator.EnforceRoute's own
// refuseIfNotPermitted check, restated here as a plain boolean predicate:
// this package already depends on internal/resolution (routing.go), and a
// second dependency on internal/orchestrator just to reuse a five-line loop
// would be the wrong direction for a one-function need. Deliberately no
// carve-out for an empty/unknown route (a legacy, pre-F17 incident with no
// stored route, or a route that failed to resolve) — resolution.
// PermittedActionTypes(Route("")) already returns nil for any unrecognized
// value, so an unknown route fails closed the same way a genuinely
// disallowed one does, rather than a special case silently trusting an
// action type this function could not actually verify.
func actionTypePermittedByRoute(route resolution.Route, actionType remediation.ActionType) bool {
	for _, permitted := range resolution.PermittedActionTypes(route) {
		if permitted == string(actionType) {
			return true
		}
	}
	return false
}
