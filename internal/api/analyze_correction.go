// This file is BUGS.md 109 / BACKLOG.md AG1's fix: analyze-time (as opposed
// to internal/execution/correction.go's post-approval-dry-run-rejection-time) correction
// of a proposed plan whose Params the model left nil or invalid.
//
// Root cause, restated briefly (BUGS.md 109 has the full live reproduction):
// internal/llm/toolloop.go's parseProposedPlan deliberately leaves Params nil
// when the model's own wire.Params for an action is empty or fails to
// unmarshal, rather than fabricate a params struct. internal/remediation
// .RemediationPlan.Validate() then correctly Blocks that plan outright — a
// plan with no params cannot execute, and that refusal is exactly right.
// What was missing is the retry mechanism internal/execution/correction.go's F12b
// correction loop already built for the identical shape of problem
// (internal/llm.CorrectPlanParams: feed the rejection text back to the
// model, ask for a corrected Params value ALONE, re-validate before ever
// trusting it) — wired, until now, only into the post-approval dry-run-
// rejection path, which requires a plan to already exist and be approved. A
// plan Blocked at /analyze time, before an operator ever sees anything, had
// no equivalent: the only recourse was a brand-new, full-cost,
// non-deterministic re-investigation, which BUGS.md 109's own four-attempt
// live reproduction shows does not reliably converge even against completely
// unchanged evidence.
//
// This file closes that gap with exactly one bounded attempt, reusing
// CorrectPlanParams point-for-point rather than building a second mechanism:
// correctBlockedPlanParams is deliberately shaped like
// internal/execution/correction.go's retryDryRunWithCorrection (a plain function of its
// arguments plus one closure, no DB/HTTP/gateway dependency of its own) so it
// is unit-testable the same way, and deliberately NOT a loop — one attempt,
// win or lose, then fall through to today's unchanged behaviour. It must
// live here, in internal/api (analyze.go's own package), rather than inside
// internal/orchestrator: internal/orchestrator.Advance is a pure function by
// explicit design ("no I/O, no mutation" — its own doc comment) and
// internal/orchestrator.ApplyAnalysisResult runs inside an open pgx.Tx, so
// neither may hold a transaction open across a slow external LLM round trip
// or make one at all. The one available seam is analyze.go itself, between
// the investigation call finishing and ApplyAnalysisResult ever being
// invoked — before either of those two respects the plan as final.
package api

import (
	"context"
	"encoding/json"
	"errors"

	"argus/internal/remediation"
)

// analyzeTimeCorrectionAttempt records what happened when
// correctBlockedPlanParams attempted a correction — attached to the
// incident's timeline (timeline.EventParamsCorrectionAttempted) by
// handleAnalyzeIncident so the audit trail says plainly that a plan reaching
// AwaitingApproval went through a correction step, and a plan that still
// landed on NeedsHumanInvestigation shows a human that a correction was
// already tried and did not help — never silently indistinguishable from
// "the model got it right the first time" or "nothing was ever attempted".
type analyzeTimeCorrectionAttempt struct {
	// Reason is the exact RemediationPlan.Validate() failure the original
	// plan produced — what CorrectPlanParams was given as the rejection
	// text to correct against.
	Reason string
	// CorrectedParams is the model's proposed replacement, present only when
	// a correction call actually returned one (never set on a "correction
	// unavailable" outcome — no AI provider, or the call itself failed).
	CorrectedParams json.RawMessage
	// Outcome is a short, human-readable account of what happened to this
	// one attempt: "corrected params passed validation" (Succeeded), or one
	// of the two ways it did not — "correction unavailable: <err>" (the
	// model/provider call itself failed) or "corrected proposal still
	// failed validation: <err>" (the model tried, but its replacement was
	// itself invalid).
	Outcome string
	// Succeeded is true only when the corrected plan now passes
	// RemediationPlan.Validate() and was substituted in. False means the
	// ORIGINAL, still-Blocked plan proceeds exactly as it would have with
	// no correction attempted at all — today's unchanged Blocked ->
	// NeedsHumanInvestigation behaviour.
	Succeeded bool
}

// correctBlockedPlanParams is BUGS.md 109 / BACKLOG.md AG1's one-bounded-
// attempt correction. plan is result.ProposedPlan exactly as it came back
// from the investigation (after orchestrator.EnforceRoute has already run —
// see this file's package comment on why ActionType is therefore already
// known to be permitted on this incident's route, and does not need
// re-checking here). correct is the single seam this function needs — closed
// over s.planCorrector.CorrectPlanParams by this file's caller — so this
// function itself stays DB-free, network-free, and directly unit-testable
// with a scripted stand-in, matching retryDryRunWithCorrection's own
// precedent.
//
// Returns plan UNCHANGED, with a nil *analyzeTimeCorrectionAttempt, in every
// case where no correction was even attempted: plan is nil (nothing was
// proposed at all — the overwhelming majority of calls), or plan already
// passes Validate() (nothing Blocked to correct), or plan is Blocked for any
// reason OTHER than nil/invalid Params (remediation
// .RemediationPlan.ParamsOnlyValidationFailure's own distinction) — an
// unrecognized ActionType, an invalid RiskLevel, a missing TargetName, or a
// PatchField/StructuredPatch path the allowlist itself refuses need a
// different fix than different Params values, and must fall straight
// through to today's unchanged NeedsHumanInvestigation, never spend a
// correction attempt guessing.
//
// When a correction IS attempted (plan Blocked purely on Params), the
// returned *analyzeTimeCorrectionAttempt is always non-nil, whether the
// attempt succeeded or not, so the caller can always record that one was
// made. On success, the returned plan is the CORRECTED one, already
// re-validated; on failure (the model/provider call errored, or the
// correction it proposed still fails Validate()), the returned plan is the
// ORIGINAL, unchanged plan — proceeding exactly as it would have with no
// correction mechanism at all.
func correctBlockedPlanParams(
	ctx context.Context,
	plan *remediation.RemediationPlan,
	correct func(ctx context.Context, plan remediation.RemediationPlan, rejection string) (remediation.ActionParams, error),
) (*remediation.RemediationPlan, *analyzeTimeCorrectionAttempt) {
	if plan == nil {
		return nil, nil
	}
	reason, correctable := plan.ParamsOnlyValidationFailure()
	if !correctable {
		return plan, nil
	}

	correctedParams, err := correct(ctx, *plan, reason)
	if err != nil {
		return plan, &analyzeTimeCorrectionAttempt{
			Reason:  reason,
			Outcome: "correction unavailable: " + err.Error(),
		}
	}

	candidate := *plan
	candidate.Params = correctedParams
	if valErr := candidate.Validate(); valErr != nil {
		return plan, &analyzeTimeCorrectionAttempt{
			Reason:  reason,
			Outcome: "corrected proposal still failed validation: " + valErr.Error(),
		}
	}

	// Best-effort only: a failure to marshal for the audit record must not
	// throw away a plan that already validated — the correction still
	// happened and still succeeds; it is only the AUDIT TRAIL'S copy of the
	// corrected params that would be missing, not the plan itself. Mirrors
	// retryDryRunWithCorrection's own harder stance (it treats this as fatal)
	// only where that stance is actually reachable: there, correctedParams
	// has already passed a live dry run by the time marshaling is attempted,
	// so a marshal failure is a genuine "something is very wrong" signal.
	// Here, marshaling is purely for display, so degrading gracefully is the
	// more honest choice than discarding a valid, already-corrected plan over
	// a cosmetic failure.
	correctedJSON, marshalErr := json.Marshal(correctedParams)
	if marshalErr != nil {
		correctedJSON = nil
	}
	return &candidate, &analyzeTimeCorrectionAttempt{
		Reason:          reason,
		CorrectedParams: correctedJSON,
		Outcome:         "corrected params passed validation",
		Succeeded:       true,
	}
}

// planCorrectorFunc adapts s.planCorrector (planCorrectionModel,
// internal/execution/correction.go) into correctBlockedPlanParams's plain closure shape
// — the same one-line adaptation preparePlanWithCorrection's own "correct"
// closure already does for the post-approval path, restated here rather than
// shared, since the two closures wrap slightly different fallback behaviour
// (this one has no dry-run rejection to fall back to; a nil planCorrector
// here just means "no correction available", exactly like there).
func (s *Server) planCorrectorFunc() func(ctx context.Context, plan remediation.RemediationPlan, rejection string) (remediation.ActionParams, error) {
	return func(ctx context.Context, plan remediation.RemediationPlan, rejection string) (remediation.ActionParams, error) {
		if s.planCorrector == nil {
			return nil, errNoPlanCorrectorConfigured
		}
		params, _, err := s.planCorrector.CorrectPlanParams(ctx, plan, rejection)
		return params, err
	}
}

// errNoPlanCorrectorConfigured is a plain sentinel (not llm.ErrNotConfigured
// itself, which propagates from Provider.Complete and would be misleading
// here — s.planCorrector being nil can also mean a build wired no provider
// at all, a distinct condition from a configured provider being reachable
// but unusable) — its text is what an operator sees in the
// ParamsCorrectionAttempted timeline entry when no correction could even be
// attempted. Matches preparePlanWithCorrection's own identical fallback
// message for the post-approval path (internal/execution/correction.go), so the two
// "no AI provider configured" surfaces read identically.
var errNoPlanCorrectorConfigured = errors.New("no AI provider is configured to propose a correction")
