package execution

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"argus/internal/remediation"
	"argus/internal/resolution"
)

// fakeRejection builds a dryRunRejectedError the way attestByDryRun's own
// CallTool-failure branch does, without needing a live gateway/cluster.
func fakeRejection(msg string) *dryRunRejectedError {
	return &dryRunRejectedError{Rejection: msg, cause: errors.New(msg)}
}

// basePlan is a minimal, already-Validate()-passing PatchResourceLimits plan
// — used as the starting point for every test below, since
// retryDryRunWithCorrection's safety checks (RemediationPlan.Validate(),
// the route-permitted check) only mean something starting from a plan that
// itself would pass them.
func basePlan() remediation.RemediationPlan {
	return remediation.RemediationPlan{
		ActionType:      remediation.ActionPatchResourceLimits,
		TargetGVK:       "apps/v1/Deployment",
		TargetNamespace: "prod",
		TargetName:      "checkout",
		RiskLevel:       remediation.RiskMedium,
		Params:          remediation.PatchResourceLimitsParams{Container: "app", MemoryLimit: "256Mi"},
	}
}

// TestRetryDryRunWithCorrection_SucceedsAfterOneCorrection is the headline
// case BACKLOG.md F12b asks for: a dry-run rejection triggers exactly one
// correction, which is then accepted on the very next attempt.
func TestRetryDryRunWithCorrection_SucceedsAfterOneCorrection(t *testing.T) {
	const wantRejection = `exceeds quota "compute-quota": requested 256Mi, quota allows 128Mi`
	var attemptCalls []remediation.RemediationPlan
	attempt := func(_ context.Context, p remediation.RemediationPlan) (PlanPrep, error) {
		attemptCalls = append(attemptCalls, p)
		if len(attemptCalls) == 1 {
			return PlanPrep{}, fmt.Errorf("rehearsal refused: %w", fakeRejection(wantRejection))
		}
		return PlanPrep{TargetName: "checkout"}, nil
	}
	var correctCalls int
	correct := func(_ context.Context, p remediation.RemediationPlan, rejection string) (remediation.ActionParams, error) {
		correctCalls++
		if rejection != wantRejection {
			t.Errorf("correct() received rejection %q, want %q", rejection, wantRejection)
		}
		return remediation.PatchResourceLimitsParams{Container: "app", MemoryLimit: "128Mi"}, nil
	}

	prep, history, err := retryDryRunWithCorrection(context.Background(), basePlan(), resolution.RouteInPlace, attempt, correct)
	if err != nil {
		t.Fatalf("retryDryRunWithCorrection: unexpected error: %v", err)
	}
	if prep.TargetName != "checkout" {
		t.Errorf("prep = %#v, want the second attempt's successful result", prep)
	}
	if len(attemptCalls) != 2 {
		t.Fatalf("attempt() called %d times, want exactly 2 (original + one retry)", len(attemptCalls))
	}
	if correctCalls != 1 {
		t.Fatalf("correct() called %d times, want exactly 1", correctCalls)
	}
	// The SECOND attempt must have been prepared with the corrected params,
	// not the original ones — otherwise "retrying" would just resend the
	// same rejected plan.
	got, ok := attemptCalls[1].Params.(remediation.PatchResourceLimitsParams)
	if !ok || got.MemoryLimit != "128Mi" {
		t.Errorf("second attempt's plan params = %#v, want the corrected 128Mi value", attemptCalls[1].Params)
	}
	if len(history) != 1 || history[0].Outcome != "retrying with corrected params" {
		t.Errorf("history = %#v, want exactly one 'retrying with corrected params' entry", history)
	}
}

// TestRetryDryRunWithCorrection_ExhaustsTheBoundCleanly is the second case
// BACKLOG.md F12b's brief explicitly asks for: a rejection that never goes
// away must stop after maxDryRunCorrectionAttempts corrections (not loop
// forever, not panic) and surface a clean error an HTTP handler can turn
// into an ordinary problem response — not a 500, not a silent failure.
func TestRetryDryRunWithCorrection_ExhaustsTheBoundCleanly(t *testing.T) {
	var attemptCount int
	attempt := func(_ context.Context, _ remediation.RemediationPlan) (PlanPrep, error) {
		attemptCount++
		return PlanPrep{}, fmt.Errorf("rehearsal refused: %w", fakeRejection("policy X always refuses this"))
	}
	var correctCount int
	correct := func(_ context.Context, p remediation.RemediationPlan, _ string) (remediation.ActionParams, error) {
		correctCount++
		// Always returns a validly-shaped, but equally-doomed, correction —
		// the loop must still stop at the bound rather than accepting a
		// correction forever.
		return remediation.PatchResourceLimitsParams{Container: "app", MemoryLimit: fmt.Sprintf("%dMi", 256+correctCount)}, nil
	}

	_, history, err := retryDryRunWithCorrection(context.Background(), basePlan(), resolution.RouteInPlace, attempt, correct)
	if err == nil {
		t.Fatal("retryDryRunWithCorrection: expected an error once the bound is exhausted, got nil")
	}
	if attemptCount != maxDryRunCorrectionAttempts+1 {
		t.Errorf("attempt() called %d times, want exactly %d (the original try plus %d corrections)", attemptCount, maxDryRunCorrectionAttempts+1, maxDryRunCorrectionAttempts)
	}
	if correctCount != maxDryRunCorrectionAttempts {
		t.Errorf("correct() called %d times, want exactly %d", correctCount, maxDryRunCorrectionAttempts)
	}
	// One "retrying with corrected params" entry per correction, plus a
	// final "exhausted" entry for the attempt that used up the bound.
	if len(history) != maxDryRunCorrectionAttempts+1 {
		t.Errorf("history has %d entries, want exactly %d", len(history), maxDryRunCorrectionAttempts+1)
	}
	if history[len(history)-1].Outcome != "exhausted" {
		t.Errorf("last history entry outcome = %q, want %q", history[len(history)-1].Outcome, "exhausted")
	}
	// The final error must still be a plain, well-formed Go error (an HTTP
	// handler's ordinary error path handles this exactly like any other
	// PreparePlan failure — see ExecuteApprovedPlan/handleApproveIncident,
	// which turn any non-nil error here into a normal problem response, not
	// a 500 or a crash).
	if err.Error() == "" {
		t.Error("exhausted-retry error has no message")
	}
}

// TestRetryDryRunWithCorrection_RefusesAnOutOfBoundsCorrection is the third
// case BACKLOG.md F12b's brief asks for: a corrected proposal that would
// itself violate a safety check — here, PatchResourceLimitsParams.Validate's
// absolute memory ceiling — must be refused outright rather than ever being
// handed to attempt() (i.e. dry-run-attempted) a second time.
func TestRetryDryRunWithCorrection_RefusesAnOutOfBoundsCorrection(t *testing.T) {
	var attemptCount int
	attempt := func(_ context.Context, _ remediation.RemediationPlan) (PlanPrep, error) {
		attemptCount++
		return PlanPrep{}, fmt.Errorf("rehearsal refused: %w", fakeRejection("memory limit too low for this workload"))
	}
	correct := func(_ context.Context, _ remediation.RemediationPlan, _ string) (remediation.ActionParams, error) {
		// A "correction" that massively overshoots — PatchResourceLimitsParams'
		// own maxMemoryQuantity absolute ceiling is 64Gi; this proposes 999Ti,
		// which Validate() must refuse.
		return remediation.PatchResourceLimitsParams{Container: "app", MemoryLimit: "999Ti"}, nil
	}

	_, history, err := retryDryRunWithCorrection(context.Background(), basePlan(), resolution.RouteInPlace, attempt, correct)
	if err == nil {
		t.Fatal("retryDryRunWithCorrection: expected an error for an out-of-bounds correction, got nil")
	}
	if attemptCount != 1 {
		t.Errorf("attempt() called %d times, want exactly 1 — an invalid correction must never be dry-run-attempted", attemptCount)
	}
	if len(history) != 1 || history[0].Outcome == "" {
		t.Fatalf("history = %#v, want exactly one recorded refusal", history)
	}
	if !strings.Contains(history[0].Outcome, "refused as structurally invalid") {
		t.Errorf("history[0].Outcome = %q, want it to say the correction was refused as structurally invalid", history[0].Outcome)
	}
}

// TestRetryDryRunWithCorrection_RefusesAnActionTypeTheRouteDoesNotPermit
// exercises the route-permitted-action-types safety check directly. In
// production the action type never actually changes between the original
// plan and a correction (only Params does), so this check is normally
// unreachable as a REFUSAL — this test proves the wiring is real and would
// catch a violation, by constructing a plan/route combination that the
// check must reject, rather than only trusting that "ActionType never
// changes" holds forever.
func TestRetryDryRunWithCorrection_RefusesAnActionTypeTheRouteDoesNotPermit(t *testing.T) {
	plan := basePlan() // ActionPatchResourceLimits
	attempt := func(_ context.Context, _ remediation.RemediationPlan) (PlanPrep, error) {
		return PlanPrep{}, fmt.Errorf("rehearsal refused: %w", fakeRejection("refused"))
	}
	correct := func(_ context.Context, _ remediation.RemediationPlan, _ string) (remediation.ActionParams, error) {
		return remediation.PatchResourceLimitsParams{Container: "app", MemoryLimit: "512Mi"}, nil
	}

	// RoutePullRequest permits only OpenPR (resolution.PermittedActionTypes) —
	// PatchResourceLimits is never in that set, so any correction (which
	// keeps the same action type) must be refused before a second dry run.
	_, history, err := retryDryRunWithCorrection(context.Background(), plan, resolution.RoutePullRequest, attempt, correct)
	if err == nil {
		t.Fatal("retryDryRunWithCorrection: expected an error, got nil")
	}
	if len(history) != 1 || !strings.Contains(history[0].Outcome, "not permitted") {
		t.Fatalf("history = %#v, want a single 'not permitted' refusal", history)
	}
}

// TestRetryDryRunWithCorrection_NonRejectionErrorsAreNotRetried checks that
// only a dryRunRejectedError triggers a correction attempt — every other
// PreparePlan failure (a guardrail refusal, an unresolvable target, a stale
// risk floor) must pass straight through with NO call to correct() at all,
// exactly as it would have before this feature existed.
func TestRetryDryRunWithCorrection_NonRejectionErrorsAreNotRetried(t *testing.T) {
	sentinel := errors.New("no owning Deployment/StatefulSet/DaemonSet found")
	attempt := func(_ context.Context, _ remediation.RemediationPlan) (PlanPrep, error) {
		return PlanPrep{}, sentinel
	}
	correctCalled := false
	correct := func(_ context.Context, _ remediation.RemediationPlan, _ string) (remediation.ActionParams, error) {
		correctCalled = true
		return nil, nil
	}

	_, history, err := retryDryRunWithCorrection(context.Background(), basePlan(), resolution.RouteInPlace, attempt, correct)
	if !errors.Is(err, sentinel) {
		t.Errorf("retryDryRunWithCorrection error = %v, want the original sentinel unwrapped via errors.Is", err)
	}
	if correctCalled {
		t.Error("correct() must not be called for a non-dry-run-rejection failure")
	}
	if len(history) != 0 {
		t.Errorf("history = %#v, want empty — nothing was corrected", history)
	}
}

// TestRetryDryRunWithCorrection_CorrectionUnavailableSurfacesOriginalError
// checks the "no AI provider configured" degrade path
// (preparePlanWithCorrection's own correct() closure returns this when
// s.planCorrector is nil): the loop must surface the ORIGINAL dry-run
// rejection, not the correction-unavailable error, so a deployment with no
// AI provider configured behaves exactly as if this feature did not exist.
func TestRetryDryRunWithCorrection_CorrectionUnavailableSurfacesOriginalError(t *testing.T) {
	original := fmt.Errorf("rehearsal refused: %w", fakeRejection("some cluster refusal"))
	attempt := func(_ context.Context, _ remediation.RemediationPlan) (PlanPrep, error) {
		return PlanPrep{}, original
	}
	correct := func(_ context.Context, _ remediation.RemediationPlan, _ string) (remediation.ActionParams, error) {
		return nil, errors.New("no AI provider is configured to propose a correction")
	}

	_, history, err := retryDryRunWithCorrection(context.Background(), basePlan(), resolution.RouteInPlace, attempt, correct)
	if !errors.Is(err, original) {
		t.Errorf("error = %v, want the original dry-run rejection (via errors.Is), not the correction-unavailable error", err)
	}
	if len(history) != 1 || !strings.Contains(history[0].Outcome, "correction unavailable") {
		t.Errorf("history = %#v, want one 'correction unavailable' entry", history)
	}
}

// TestActionTypePermittedByRoute pins the membership check itself against
// resolution.PermittedActionTypes' documented table, including the fail-
// closed behaviour for an empty/unrecognized route.
func TestActionTypePermittedByRoute(t *testing.T) {
	cases := []struct {
		route      resolution.Route
		actionType remediation.ActionType
		want       bool
	}{
		{resolution.RouteInPlace, remediation.ActionPatchResourceLimits, true},
		{resolution.RoutePullRequest, remediation.ActionPatchResourceLimits, false},
		{resolution.RoutePullRequest, remediation.ActionOpenPR, true},
		{resolution.RoutePaired, remediation.ActionScaleDeployment, true},
		{resolution.RoutePaired, remediation.ActionOpenPR, true},
		{resolution.RouteGuidance, remediation.ActionScaleDeployment, false},
		{resolution.Route(""), remediation.ActionScaleDeployment, false},
	}
	for _, c := range cases {
		got := actionTypePermittedByRoute(c.route, c.actionType)
		if got != c.want {
			t.Errorf("actionTypePermittedByRoute(%q, %s) = %v, want %v", c.route, c.actionType, got, c.want)
		}
	}
}

// A preview's refusal must not describe an execution nobody asked for; an
// approval's must still say the incident was not moved to Executing.
func TestDryRunRefusalLeadIsWordedPerMode(t *testing.T) {
	preview := dryRunRefusalLead(PrepForPreflight)
	if strings.Contains(preview, "executed") || strings.Contains(preview, "Executing") {
		t.Errorf("preview wording mentions execution: %q", preview)
	}
	if !strings.Contains(dryRunRefusalLead(PrepForExecution), "not moved to Executing") {
		t.Errorf("execution wording lost its state statement: %q", dryRunRefusalLead(PrepForExecution))
	}
}
