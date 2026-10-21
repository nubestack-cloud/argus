package api

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"argus/internal/gitops"
	"argus/internal/remediation"
	"argus/internal/scm"
)

// openPRBasePlan is a minimal, already-Validate()-passing OpenPR plan — the
// starting point for every test below, mirroring remediation_retry_test.go's
// basePlan() for the identical reason: retryOpenPRProposalWithCorrection's
// own validation step only means something starting from a plan that itself
// would pass it.
func openPRBasePlan() remediation.RemediationPlan {
	return remediation.RemediationPlan{
		ActionType:      remediation.ActionOpenPR,
		TargetGVK:       "apps/v1/Deployment",
		TargetNamespace: "prod",
		TargetName:      "checkout",
		RiskLevel:       remediation.RiskLow,
		Params: remediation.OpenPRParams{
			Files: []remediation.ProposedFile{{Path: "envs/prod/deployment.yaml", Content: "not: [valid"}},
		},
	}
}

// verificationFailedErr builds the exact shape gitops.ApplyFileEdit returns
// for unparseable plain YAML — the one class this file's own package comment
// names as correction-eligible.
func verificationFailedErr(msg string) error {
	return fmt.Errorf("%w: %s", gitops.ErrVerificationFailed, msg)
}

// TestRetryOpenPRProposalWithCorrection_SucceedsAfterOneCorrection is
// BACKLOG.md AL1 decision 4's headline case: a content-fixable refusal
// (unparseable YAML) triggers exactly one correction, which opens the pull
// request on the very next attempt.
func TestRetryOpenPRProposalWithCorrection_SucceedsAfterOneCorrection(t *testing.T) {
	const wantRejection = "gitops: refusing this edit: the proposed content for envs/prod/deployment.yaml is plain YAML and does not parse, so it could not be applied: yaml: line 1: did not find expected node content"
	var proposeCalls []remediation.OpenPRParams
	propose := func(_ context.Context, p remediation.OpenPRParams) (gitopsProposalResult, error) {
		proposeCalls = append(proposeCalls, p)
		if len(proposeCalls) == 1 {
			return gitopsProposalResult{}, verificationFailedErr("the proposed content for envs/prod/deployment.yaml is plain YAML and does not parse, so it could not be applied: yaml: line 1: did not find expected node content")
		}
		return gitopsProposalResult{Proposal: gitops.Proposal{PullRequest: scm.PullRequest{URL: "https://example.test/pr/1"}}, RepoName: "org/repo"}, nil
	}
	var correctCalls int
	correct := func(_ context.Context, _ remediation.RemediationPlan, rejection string) (remediation.ActionParams, error) {
		correctCalls++
		if rejection != wantRejection {
			t.Errorf("correct() received rejection %q, want %q", rejection, wantRejection)
		}
		return remediation.OpenPRParams{
			Files: []remediation.ProposedFile{{Path: "envs/prod/deployment.yaml", Content: "replicas: 3\n"}},
		}, nil
	}

	result, attempt, err := retryOpenPRProposalWithCorrection(context.Background(), openPRBasePlan(), openPRBasePlan().Params.(remediation.OpenPRParams), propose, correct)
	if err != nil {
		t.Fatalf("retryOpenPRProposalWithCorrection: unexpected error: %v", err)
	}
	if result.Proposal.PullRequest.URL != "https://example.test/pr/1" {
		t.Errorf("result = %#v, want the second attempt's successful proposal", result)
	}
	if len(proposeCalls) != 2 {
		t.Fatalf("propose() called %d times, want exactly 2 (original + one retry)", len(proposeCalls))
	}
	if correctCalls != 1 {
		t.Fatalf("correct() called %d times, want exactly 1", correctCalls)
	}
	// The SECOND attempt must have been proposed with the corrected content,
	// not the original one — otherwise "retrying" would just resend the same
	// rejected proposal.
	if got := proposeCalls[1].Files[0].Content; got != "replicas: 3\n" {
		t.Errorf("second attempt's content = %q, want the corrected value", got)
	}
	if attempt == nil {
		t.Fatal("attempt = nil, want a non-nil record of the correction that was tried")
	}
	if !attempt.Succeeded {
		t.Errorf("attempt.Succeeded = false, want true")
	}
	if attempt.Reason != wantRejection {
		t.Errorf("attempt.Reason = %q, want %q", attempt.Reason, wantRejection)
	}
	if len(attempt.CorrectedParams) == 0 {
		t.Error("attempt.CorrectedParams is empty, want the corrected params marshalled for the audit trail")
	}
}

// TestRetryOpenPRProposalWithCorrection_CorrectionFailsSurfacesOriginalError
// is BACKLOG.md AL1 decision 4's second case: a content-fixable refusal,
// where the correction call itself fails (e.g. no AI provider configured) —
// the ORIGINAL refusal is what the human sees, never the correction
// machinery's own error, and propose() is never called a second time.
func TestRetryOpenPRProposalWithCorrection_CorrectionFailsSurfacesOriginalError(t *testing.T) {
	const wantRejection = "gitops: refusing this edit: envs/prod/deployment.yaml has no content"
	var proposeCalls int
	propose := func(_ context.Context, _ remediation.OpenPRParams) (gitopsProposalResult, error) {
		proposeCalls++
		return gitopsProposalResult{}, verificationFailedErr("envs/prod/deployment.yaml has no content")
	}
	correct := func(_ context.Context, _ remediation.RemediationPlan, _ string) (remediation.ActionParams, error) {
		return nil, errors.New("no AI provider is configured to propose a correction")
	}

	plan := openPRBasePlan()
	_, attempt, err := retryOpenPRProposalWithCorrection(context.Background(), plan, plan.Params.(remediation.OpenPRParams), propose, correct)
	if err == nil {
		t.Fatal("retryOpenPRProposalWithCorrection: expected an error, got nil")
	}
	if err.Error() != wantRejection {
		t.Errorf("err = %q, want the ORIGINAL refusal %q, not a correction-machinery error", err.Error(), wantRejection)
	}
	if proposeCalls != 1 {
		t.Errorf("propose() called %d times, want exactly 1 (no retry attempted)", proposeCalls)
	}
	if attempt == nil || attempt.Succeeded {
		t.Fatalf("attempt = %#v, want a non-nil, non-succeeded record of the attempt that was tried", attempt)
	}

	// Second flavour of the same case: the correction call succeeds, but the
	// value it returns is itself invalid (fails OpenPRParams.Validate()) — the
	// ORIGINAL refusal is still what gets surfaced, and propose() is still
	// never called a second time.
	proposeCalls = 0
	correctInvalid := func(_ context.Context, _ remediation.RemediationPlan, _ string) (remediation.ActionParams, error) {
		return remediation.OpenPRParams{Files: nil}, nil // fails Validate(): no files
	}
	_, attempt2, err2 := retryOpenPRProposalWithCorrection(context.Background(), plan, plan.Params.(remediation.OpenPRParams), propose, correctInvalid)
	if err2 == nil {
		t.Fatal("retryOpenPRProposalWithCorrection: expected an error for an invalid correction, got nil")
	}
	if !strings.Contains(err2.Error(), wantRejection) {
		t.Errorf("err2 = %q, want it to still name the ORIGINAL refusal %q", err2.Error(), wantRejection)
	}
	if proposeCalls != 1 {
		t.Errorf("propose() called %d times, want exactly 1 (no retry attempted for an invalid correction)", proposeCalls)
	}
	if attempt2 == nil || attempt2.Succeeded {
		t.Fatalf("attempt2 = %#v, want a non-nil, non-succeeded record", attempt2)
	}
}

// TestRetryOpenPRProposalWithCorrection_NotContentFixableNeverAttemptsCorrection
// is BACKLOG.md AL1 decision 4's third case: a refusal that is NOT plausibly
// fixable by different content — a genuine git-level conflict, chosen here as
// the sharpest example the task names explicitly — must fail immediately,
// with correct() never called at all and propose() never retried.
func TestRetryOpenPRProposalWithCorrection_NotContentFixableNeverAttemptsCorrection(t *testing.T) {
	conflictErr := fmt.Errorf("gitops: envs/prod/deployment.yaml changed between the synced commit and main, so the edit computed for it no longer applies: %w", scm.ErrConflict)

	var proposeCalls int
	propose := func(_ context.Context, _ remediation.OpenPRParams) (gitopsProposalResult, error) {
		proposeCalls++
		return gitopsProposalResult{}, conflictErr
	}
	var correctCalls int
	correct := func(_ context.Context, _ remediation.RemediationPlan, _ string) (remediation.ActionParams, error) {
		correctCalls++
		return remediation.OpenPRParams{Files: []remediation.ProposedFile{{Path: "x", Content: "y"}}}, nil
	}

	plan := openPRBasePlan()
	_, attempt, err := retryOpenPRProposalWithCorrection(context.Background(), plan, plan.Params.(remediation.OpenPRParams), propose, correct)
	if !errors.Is(err, scm.ErrConflict) {
		t.Fatalf("err = %v, want it to still be (wrap) the original git-conflict error", err)
	}
	if proposeCalls != 1 {
		t.Errorf("propose() called %d times, want exactly 1 (no retry for a non-content refusal)", proposeCalls)
	}
	if correctCalls != 0 {
		t.Errorf("correct() called %d times, want exactly 0 — a git-level conflict is not something a corrected Content value can fix", correctCalls)
	}
	if attempt != nil {
		t.Errorf("attempt = %#v, want nil — no correction was even attempted", attempt)
	}

	// The other two non-content refusals this package calls out explicitly:
	// a forbidden/out-of-directory path, and the "nothing actually changed"
	// case. Neither carries gitops.ErrVerificationFailed, so neither should
	// attempt a correction either.
	for _, tc := range []struct {
		name string
		err  error
	}{
		{"forbidden path", errors.New(`gitops: refusing to write .github/workflows/ci.yaml — it matches the forbidden path ".github/**"`)},
		{"nothing to change", gitops.ErrNothingToChange},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls int
			propose := func(_ context.Context, _ remediation.OpenPRParams) (gitopsProposalResult, error) {
				calls++
				return gitopsProposalResult{}, tc.err
			}
			var correctCalls int
			correct := func(_ context.Context, _ remediation.RemediationPlan, _ string) (remediation.ActionParams, error) {
				correctCalls++
				return nil, nil
			}
			_, attempt, err := retryOpenPRProposalWithCorrection(context.Background(), plan, plan.Params.(remediation.OpenPRParams), propose, correct)
			if !errors.Is(err, tc.err) {
				t.Errorf("err = %v, want it to still be the original refusal", err)
			}
			if calls != 1 {
				t.Errorf("propose() called %d times, want exactly 1", calls)
			}
			if correctCalls != 0 {
				t.Errorf("correct() called %d times, want exactly 0", correctCalls)
			}
			if attempt != nil {
				t.Errorf("attempt = %#v, want nil", attempt)
			}
		})
	}
}

// TestRetryOpenPRProposalWithCorrection_FirstAttemptSucceedsIsUnaffected is
// the regression guard: an OpenPR approval that succeeds on the very first
// attempt must never call correct() at all, and must return the first
// attempt's own result untouched — no extra latency, no extra calls, whether
// or not a plan corrector is even configured.
func TestRetryOpenPRProposalWithCorrection_FirstAttemptSucceedsIsUnaffected(t *testing.T) {
	var proposeCalls int
	propose := func(_ context.Context, _ remediation.OpenPRParams) (gitopsProposalResult, error) {
		proposeCalls++
		return gitopsProposalResult{Proposal: gitops.Proposal{PullRequest: scm.PullRequest{URL: "https://example.test/pr/2"}}, RepoName: "org/repo"}, nil
	}
	correctCalled := false
	correct := func(_ context.Context, _ remediation.RemediationPlan, _ string) (remediation.ActionParams, error) {
		correctCalled = true
		return nil, errors.New("must never be called")
	}

	plan := openPRBasePlan()
	result, attempt, err := retryOpenPRProposalWithCorrection(context.Background(), plan, plan.Params.(remediation.OpenPRParams), propose, correct)
	if err != nil {
		t.Fatalf("retryOpenPRProposalWithCorrection: unexpected error: %v", err)
	}
	if result.Proposal.PullRequest.URL != "https://example.test/pr/2" {
		t.Errorf("result = %#v, want the first attempt's own proposal, untouched", result)
	}
	if proposeCalls != 1 {
		t.Errorf("propose() called %d times, want exactly 1", proposeCalls)
	}
	if correctCalled {
		t.Error("correct() was called, want it never invoked when the first attempt already succeeds")
	}
	if attempt != nil {
		t.Errorf("attempt = %#v, want nil — no correction was attempted", attempt)
	}
}

// TestOpenPRRefusalCorrectionEligible pins the exact classification decision
// this file's own package comment argues for, as a fast, direct check
// independent of the fuller scenarios above.
func TestOpenPRRefusalCorrectionEligible(t *testing.T) {
	cases := []struct {
		name     string
		err      error
		eligible bool
	}{
		{"unparseable plain YAML (ErrVerificationFailed)", verificationFailedErr("does not parse"), true},
		{"empty content (ErrVerificationFailed)", verificationFailedErr("has no content"), true},
		{"redacted value echoed", fmt.Errorf("%w: x", gitops.ErrRedactedValueEchoed), false},
		{"nothing to change", gitops.ErrNothingToChange, false},
		{"git-level conflict", fmt.Errorf("gitops: moved: %w", scm.ErrConflict), false},
		{"forbidden path", errors.New(`gitops: refusing to write x — it matches the forbidden path "y"`), false},
		{"plain unrelated error", errors.New("gitops: could not determine the base branch"), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := openPRRefusalCorrectionEligible(tc.err); got != tc.eligible {
				t.Errorf("openPRRefusalCorrectionEligible(%v) = %v, want %v", tc.err, got, tc.eligible)
			}
		})
	}
}
