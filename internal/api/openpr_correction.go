// This file is BACKLOG.md item #5's second half ("decision 4" against AL1,
// its own #5 sub-item (b)): approveByOpeningPullRequest's call into
// gitops.ProposeChanges was, until now, the ONE approval-time repository-
// change refusal that could never reach the F12b/BUGS.md 109 correction
// primitive at all. internal/execution/correction.go's retryDryRunWithCorrection is wired
// only into execution.ExecuteApprovedPlan (the in-place path) — OpenPR never touches a
// cluster, so approveByOpeningPullRequest deliberately bypasses
// execution.ExecuteApprovedPlan entirely (see approvals.go's own "OpenPR (GitOps)
// execution is explicitly out of scope" comment). The consequence: a plan
// that passed RemediationPlan.Validate() and the confidence/risk gate at
// analyze time, reached AutoApprove, and was only THEN rejected by the real
// GitHub/GitLab call — a file that changed underneath it since analysis, a
// provider-specific rejection, content that turns out not to parse once
// actually diffed against the live file — got nothing but a 422, identical to
// a plan that was never any good, with no automatic retry attempted at all.
//
// This closes that gap with the same non-loop, one-bounded-attempt shape
// correctBlockedPlanParams (analyze_correction.go) and
// retryDryRunWithCorrection (internal/execution/correction.go) both already established:
// reuse internal/llm.CorrectPlanParams via s.planCorrectorFunc() (the exact
// adapter correctBlockedPlanParams already uses — ActionOpenPR's params
// schema hint was added to CorrectPlanParams for BUGS.md 109/AG1's
// analyze-time caller, and is reused here unchanged), feed it the
// repository's own rejection text, re-validate the result before ever
// trusting it, retry gitops.ProposeChanges exactly once, and on a second
// failure surface an error to the human exactly as if this file did not
// exist.
//
// # What counts as "content-fixable" here, and what does not
//
// gitops.ProposeChanges/prepareChanges can fail for reasons that are NOT
// about the proposed Content being wrong at all:
//
//   - A git-level conflict (scm.ErrConflict) — a blob moved between the
//     synced read and the commit, or a branch moved before an atomic commit
//     landed. Retrying with different bytes at the same path does not
//     un-conflict a moved blob SHA; the fix is re-reading the file, which is
//     a fresh proposal (a re-analysis), not a correction of this one.
//   - A forbidden or out-of-source-directory path, or the same path named
//     twice. These are policy/structural refusals — WHERE the change may
//     land — not a statement that the CONTENT proposed for that path is
//     wrong.
//   - No synced revision recorded, too many/zero files, a branch that
//     already exists, a provider failure resolving/creating a branch or
//     opening the pull request itself. All provider/preparation failures a
//     corrected Content value could not plausibly address.
//
// Attempting a correction for any of those would spend a real model call
// solely to reproduce the identical refusal — the same reasoning
// retryDryRunWithCorrection already applies to a guardrail refusal, a stale
// risk floor, or a version-skew integrity check: only a refusal of the
// PARAMS' own content is what this mechanism acts on.
//
// The one class this DOES treat as content-fixable is
// gitops.ErrVerificationFailed — internal/gitops/files.go's ApplyFileEdit
// refusing content that cannot be reviewed at all: empty content, content
// over the byte bound, or content that is plain YAML and does not parse.
// That last case is the approval-time analogue of BUGS.md 109/110's
// malformed-content correction: the model produced something structurally
// broken, and the repository's own words about why are exactly the kind of
// rejection CorrectPlanParams's prompt is built to react to.
//
// Two classes are deliberately excluded even though they are refusals of
// content rather than of git state or policy:
//
//   - gitops.ErrRedactedValueEchoed — matching BUGS.md 112's already-made
//     decision for the identical shape of problem
//     (remediation.ErrNewValueEchoesRedactionMarker, excluded by
//     RemediationPlan.ParamsOnlyValidationFailure). The model is
//     structurally never shown the real value internal/redact withheld
//     before the object crossed the tunnel, so a second guess has no more
//     information than the first and would only reproduce the same
//     refusal.
//   - gitops.ErrNothingToChange — unlike malformed YAML, there is no
//     objectively correct replacement to ask for here: the proposed files
//     are not WRONG, they are simply identical to what the synced commit
//     already holds. Asking the model to try again supplies it no new
//     information about what SHOULD differ, only a request to guess again
//     with the same evidence it already had — the same reasoning BUGS.md
//     109/112 already used to exclude a refusal from correction eligibility
//     when a second attempt is not expected to converge.
package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"argus/internal/gitops"
	"argus/internal/remediation"
)

// openPRRefusalCorrectionEligible reports whether err is the kind of
// gitops.ProposeChanges failure a corrected Content value could plausibly
// fix. See this file's own package comment for the full reasoning behind
// drawing the line at exactly gitops.ErrVerificationFailed.
//
// Checked with errors.Is, never by matching the message text, for the same
// reason dryRunRejectedError's own doc comment gives: the human-facing
// sentence wrapping a refusal may be reworded, and a correction gate keyed to
// prose would silently stop firing the day someone improved it.
func openPRRefusalCorrectionEligible(err error) bool {
	return errors.Is(err, gitops.ErrVerificationFailed)
}

// openPRApprovalCorrectionAttempt records what happened when
// retryOpenPRProposalWithCorrection attempted a correction — the same
// win-or-lose shape as analyzeTimeCorrectionAttempt (analyze_correction.go)
// and dryRunCorrectionAttempt (internal/execution/correction.go), restated here for a
// THIRD point in a plan's lifecycle those two do not cover. Recorded onto
// timeline.EventParamsCorrectionAttempted exactly like the analyze-time one
// — the same domain fact ("a proposed plan's params were corrected, win or
// lose"), just triggered by a different caller and a different kind of
// refusal. A narrowly-scoped sibling event was considered and rejected: the
// Detail shape (reason/outcome/succeeded/correctedParams) and the meaning an
// operator reads off it are identical either way, and a second event name
// for the same fact would only cost a reader having to know both.
type openPRApprovalCorrectionAttempt struct {
	// Reason is the repository's own rejection text — what correct() was
	// given to correct against.
	Reason string
	// CorrectedParams is the model's proposed replacement, present only when
	// a correction call actually returned one that passed validation (never
	// set on a "correction unavailable" or "still structurally invalid"
	// outcome).
	CorrectedParams json.RawMessage
	// Outcome is a short, human-readable account of what happened to this
	// one attempt.
	Outcome string
	// Succeeded is true only when the corrected params were used to open the
	// pull request. False means the ORIGINAL error is what the caller
	// surfaces — proceeding exactly as if this mechanism did not exist.
	Succeeded bool
}

// retryOpenPRProposalWithCorrection is approveByOpeningPullRequest's entry
// point into the correction. propose runs one real attempt at turning params
// into an opened pull request (closed over s.proposeFromApprovedPlan by the
// caller, mirroring preparePlanWithCorrection's own closure-seam pattern —
// internal/execution/correction.go — so this function itself stays free of the
// DB/HTTP/SCM-provider dependencies its caller has, and is directly
// unit-testable with a scripted stand-in). correct is s.planCorrectorFunc(),
// the identical adapter correctBlockedPlanParams already uses.
//
// Never a loop: at most one gitops.ProposeChanges call beyond the first. The
// returned *openPRApprovalCorrectionAttempt is non-nil exactly when a
// correction was attempted at all — nil when the first attempt already
// succeeded, or when it failed for a reason openPRRefusalCorrectionEligible
// says a corrected Content value could not plausibly fix.
//
// On a correction that fails outright (correct() itself errors, e.g. no AI
// provider configured) or whose result fails RemediationPlan/OpenPRParams
// validation, the ORIGINAL refusal is what gets surfaced — the human sees
// exactly the error they would have seen with no correction mechanism at
// all, plus (via the returned attempt) a record that one was tried. On a
// correction that passes validation but is retried against the real
// repository and refused there too, the SECOND (final) refusal is surfaced
// instead, since by that point it is the more informative, more current
// answer — the repository's live response to the actual bytes it was just
// asked to accept, not a rejection of the version that has already been
// superseded by the corrected one.
func retryOpenPRProposalWithCorrection(
	ctx context.Context,
	plan remediation.RemediationPlan,
	params remediation.OpenPRParams,
	propose func(ctx context.Context, params remediation.OpenPRParams) (gitopsProposalResult, error),
	correct func(ctx context.Context, plan remediation.RemediationPlan, rejection string) (remediation.ActionParams, error),
) (gitopsProposalResult, *openPRApprovalCorrectionAttempt, error) {
	result, err := propose(ctx, params)
	if err == nil {
		return result, nil, nil
	}
	if !openPRRefusalCorrectionEligible(err) {
		// Not a content refusal — a git-level conflict, a forbidden/
		// out-of-directory path, a missing synced revision, or any other
		// preparation/provider failure a corrected Content value could not
		// plausibly address. Surfaced exactly as it would have been before
		// this feature existed.
		return gitopsProposalResult{}, nil, err
	}

	rejection := err.Error()
	correctedParams, correctErr := correct(ctx, plan, rejection)
	if correctErr != nil {
		// The ORIGINAL refusal, not correctErr — a caller with no AI
		// provider configured, or a model that failed to answer, sees the
		// same error this refusal would have produced with no retry
		// mechanism at all. Matches retryDryRunWithCorrection's identical
		// choice for the identical situation.
		return gitopsProposalResult{}, &openPRApprovalCorrectionAttempt{
			Reason:  rejection,
			Outcome: "correction unavailable: " + correctErr.Error(),
		}, err
	}

	corrected, ok := correctedParams.(remediation.OpenPRParams)
	if !ok {
		// Not reachable given internal/llm's parseCorrectedParams already
		// returns remediation.OpenPRParams for ActionOpenPR — kept as an
		// explicit, named outcome rather than a panic, matching this
		// codebase's posture toward "should not happen" states elsewhere in
		// this same family.
		return gitopsProposalResult{}, &openPRApprovalCorrectionAttempt{
			Reason:  rejection,
			Outcome: fmt.Sprintf("correction returned %T, not an OpenPR params value", correctedParams),
		}, err
	}
	if valErr := corrected.Validate(); valErr != nil {
		return gitopsProposalResult{}, &openPRApprovalCorrectionAttempt{
			Reason:  rejection,
			Outcome: "corrected proposal refused as structurally invalid: " + valErr.Error(),
		}, fmt.Errorf("a corrected proposal was generated but refused as structurally invalid (%v); the original refusal was: %w", valErr, err)
	}

	// correctedJSON is about to be USED (retried for real against a live
	// repository), not merely displayed — a value that cannot even be
	// marshalled is treated as the same hard stop retryDryRunWithCorrection
	// uses for the identical situation, rather than correctBlockedPlanParams's
	// softer "degrade the audit trail, keep the plan" stance, which only
	// applies when marshaling is purely for display.
	correctedJSON, marshalErr := json.Marshal(corrected)
	if marshalErr != nil {
		return gitopsProposalResult{}, nil, fmt.Errorf("marshal corrected params for the audit trail: %w", marshalErr)
	}

	retryResult, retryErr := propose(ctx, corrected)
	if retryErr != nil {
		return gitopsProposalResult{}, &openPRApprovalCorrectionAttempt{
			Reason:          rejection,
			CorrectedParams: correctedJSON,
			Outcome:         "retried with corrected params, still refused: " + retryErr.Error(),
		}, fmt.Errorf("the repository still refused this plan after one automatic correction attempt: %w", retryErr)
	}

	return retryResult, &openPRApprovalCorrectionAttempt{
		Reason:          rejection,
		CorrectedParams: correctedJSON,
		Outcome:         "corrected params opened the pull request",
		Succeeded:       true,
	}, nil
}

// gitopsProposalResult bundles proposeFromApprovedPlan's two return values
// (the proposal and the repository's display name) into one value, so
// retryOpenPRProposalWithCorrection's propose closure has a single result to
// pass around rather than a second positional value that would have to be
// threaded through every branch above.
type gitopsProposalResult struct {
	Proposal gitops.Proposal
	RepoName string
}
