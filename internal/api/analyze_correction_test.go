package api

import (
	"context"
	"errors"
	"strings"
	"testing"

	"argus/internal/redact"
	"argus/internal/remediation"
)

// openPRPlanWithNilParams is BUGS.md 109's exact live shape: an OpenPR plan
// whose Params the model left nil (internal/llm/toolloop.go's
// parseProposedPlan deliberately does this rather than fabricate a params
// struct when the model's own wire.Params was empty or failed to unmarshal).
func openPRPlanWithNilParams() *remediation.RemediationPlan {
	return &remediation.RemediationPlan{
		ActionType:      remediation.ActionOpenPR,
		TargetGVK:       "apps/v1/Deployment",
		TargetNamespace: "argus-r41-argo003",
		TargetName:      "argo003-selfheal",
		Reversible:      true,
		RiskLevel:       remediation.RiskLow,
		Params:          nil,
	}
}

// TestCorrectBlockedPlanParams_SucceedsOnce is the headline case BUGS.md 109
// / BACKLOG.md AG1 asks for: a plan Blocked purely because Params was nil
// gets exactly one correction attempt, and a validly-parameterized
// correction is substituted in.
func TestCorrectBlockedPlanParams_SucceedsOnce(t *testing.T) {
	var correctCalls int
	var gotRejection string
	correct := func(_ context.Context, p remediation.RemediationPlan, rejection string) (remediation.ActionParams, error) {
		correctCalls++
		gotRejection = rejection
		if p.ActionType != remediation.ActionOpenPR {
			t.Errorf("correct() called with ActionType %q, want OpenPR", p.ActionType)
		}
		return remediation.OpenPRParams{
			Files: []remediation.ProposedFile{{
				Path:    "envs/prod/checkout.yaml",
				Content: "spec:\n  template:\n    spec:\n      containers:\n        - livenessProbe:\n            httpGet:\n              port: 80\n",
			}},
		}, nil
	}

	plan, attempt := correctBlockedPlanParams(context.Background(), openPRPlanWithNilParams(), correct)

	if correctCalls != 1 {
		t.Fatalf("correct() called %d times, want exactly 1", correctCalls)
	}
	if gotRejection == "" || !strings.Contains(gotRejection, "params is required") {
		t.Errorf("correct() was given rejection %q, want it to name the params-required failure", gotRejection)
	}
	if attempt == nil {
		t.Fatal("attempt = nil, want a non-nil record — a correction WAS attempted")
	}
	if !attempt.Succeeded {
		t.Errorf("attempt.Succeeded = false, want true")
	}
	if attempt.CorrectedParams == nil {
		t.Error("attempt.CorrectedParams is nil, want the corrected params recorded for the audit trail")
	}
	if plan == nil {
		t.Fatal("plan = nil, want the corrected plan")
	}
	got, ok := plan.Params.(remediation.OpenPRParams)
	if !ok {
		t.Fatalf("plan.Params = %#v (%T), want remediation.OpenPRParams", plan.Params, plan.Params)
	}
	if len(got.Files) != 1 || got.Files[0].Path != "envs/prod/checkout.yaml" {
		t.Errorf("plan.Params.Files = %+v, want the one corrected file", got.Files)
	}
	if err := plan.Validate(); err != nil {
		t.Errorf("corrected plan.Validate() = %v, want nil — the substituted plan must actually validate", err)
	}
}

// TestCorrectBlockedPlanParams_CorrectionCallFails covers the "no AI
// provider configured, or the call itself errors" fallback: the ORIGINAL
// plan proceeds unchanged, exactly as if this feature did not exist, and the
// attempt is still recorded so the audit trail says a correction was tried.
func TestCorrectBlockedPlanParams_CorrectionCallFails(t *testing.T) {
	original := openPRPlanWithNilParams()
	wantErr := errors.New("no AI provider is configured to propose a correction")
	correct := func(_ context.Context, _ remediation.RemediationPlan, _ string) (remediation.ActionParams, error) {
		return nil, wantErr
	}

	plan, attempt := correctBlockedPlanParams(context.Background(), original, correct)

	if plan != original {
		t.Errorf("plan = %#v, want the SAME original plan pointer returned unchanged", plan)
	}
	if attempt == nil {
		t.Fatal("attempt = nil, want a non-nil record even though the correction failed")
	}
	if attempt.Succeeded {
		t.Error("attempt.Succeeded = true, want false")
	}
	if attempt.CorrectedParams != nil {
		t.Errorf("attempt.CorrectedParams = %v, want nil — no correction was ever produced", attempt.CorrectedParams)
	}
	if !strings.Contains(attempt.Outcome, wantErr.Error()) {
		t.Errorf("attempt.Outcome = %q, want it to include the correction error %q", attempt.Outcome, wantErr.Error())
	}
}

// TestCorrectBlockedPlanParams_CorrectedProposalStillInvalid covers the
// second fallback shape: the model DID respond, but its replacement params
// still fail RemediationPlan.Validate() — the original plan proceeds
// unchanged, and the attempt is recorded as a failure, not silently retried
// a second time.
func TestCorrectBlockedPlanParams_CorrectedProposalStillInvalid(t *testing.T) {
	original := openPRPlanWithNilParams()
	var correctCalls int
	correct := func(_ context.Context, _ remediation.RemediationPlan, _ string) (remediation.ActionParams, error) {
		correctCalls++
		// Still invalid: fieldPath/newValue both empty, same shape as the
		// rejection this correction was supposed to fix.
		return remediation.OpenPRParams{}, nil
	}

	plan, attempt := correctBlockedPlanParams(context.Background(), original, correct)

	if correctCalls != 1 {
		t.Fatalf("correct() called %d times, want exactly 1 — never retried a second time", correctCalls)
	}
	if plan != original {
		t.Errorf("plan = %#v, want the SAME original plan pointer returned unchanged", plan)
	}
	if attempt == nil || attempt.Succeeded {
		t.Fatalf("attempt = %#v, want a non-nil, unsuccessful record", attempt)
	}
	if !strings.Contains(attempt.Outcome, "still failed validation") {
		t.Errorf("attempt.Outcome = %q, want it to say the corrected proposal still failed validation", attempt.Outcome)
	}
}

// TestCorrectBlockedPlanParams_NoPlanNoAttempt is the "nothing to correct"
// case: no plan was proposed at all (the ordinary, expected outcome for most
// investigations) — correct() must never be called, and no attempt is
// recorded.
func TestCorrectBlockedPlanParams_NoPlanNoAttempt(t *testing.T) {
	var correctCalls int
	correct := func(_ context.Context, _ remediation.RemediationPlan, _ string) (remediation.ActionParams, error) {
		correctCalls++
		return nil, nil
	}

	plan, attempt := correctBlockedPlanParams(context.Background(), nil, correct)

	if plan != nil {
		t.Errorf("plan = %#v, want nil", plan)
	}
	if attempt != nil {
		t.Errorf("attempt = %#v, want nil — nothing was proposed, so nothing should be attempted", attempt)
	}
	if correctCalls != 0 {
		t.Errorf("correct() called %d times, want 0", correctCalls)
	}
}

// TestCorrectBlockedPlanParams_AlreadyValidPlanNoAttempt is requirement 3 of
// BUGS.md 109's fix, exercised directly at this function's own boundary: a
// plan that already passes Validate() must never trigger a correction
// attempt — there is nothing to correct.
func TestCorrectBlockedPlanParams_AlreadyValidPlanNoAttempt(t *testing.T) {
	var correctCalls int
	correct := func(_ context.Context, _ remediation.RemediationPlan, _ string) (remediation.ActionParams, error) {
		correctCalls++
		return nil, nil
	}
	valid := &remediation.RemediationPlan{
		ActionType:      remediation.ActionScaleDeployment,
		TargetGVK:       "apps/v1/Deployment",
		TargetNamespace: "payments",
		TargetName:      "checkout",
		Params:          remediation.ScaleDeploymentParams{Replicas: 3},
		Reversible:      true,
		RiskLevel:       remediation.RiskLow,
	}

	plan, attempt := correctBlockedPlanParams(context.Background(), valid, correct)

	if plan != valid {
		t.Errorf("plan = %#v, want the same valid plan pointer, unchanged", plan)
	}
	if attempt != nil {
		t.Errorf("attempt = %#v, want nil — an already-valid plan must never trigger a correction attempt", attempt)
	}
	if correctCalls != 0 {
		t.Errorf("correct() called %d times, want 0", correctCalls)
	}
}

// TestCorrectBlockedPlanParams_DifferentBlockedReasonNoAttempt is requirement
// 3's other half: a plan Blocked for a reason OTHER than nil/invalid Params
// (here, an unrecognized ActionType) must NOT trigger a correction attempt —
// a different value for the SAME Params could never fix an unrecognized
// action type, a missing target, or an invalid risk level.
func TestCorrectBlockedPlanParams_DifferentBlockedReasonNoAttempt(t *testing.T) {
	var correctCalls int
	correct := func(_ context.Context, _ remediation.RemediationPlan, _ string) (remediation.ActionParams, error) {
		correctCalls++
		return nil, nil
	}
	badActionType := &remediation.RemediationPlan{
		ActionType:      remediation.ActionType("DeleteNamespace"),
		TargetGVK:       "apps/v1/Deployment",
		TargetNamespace: "payments",
		TargetName:      "checkout",
		Params:          remediation.ScaleDeploymentParams{Replicas: 3},
		Reversible:      true,
		RiskLevel:       remediation.RiskLow,
	}

	plan, attempt := correctBlockedPlanParams(context.Background(), badActionType, correct)

	if plan != badActionType {
		t.Errorf("plan = %#v, want the same original plan pointer, unchanged", plan)
	}
	if attempt != nil {
		t.Errorf("attempt = %#v, want nil — this Blocked reason is not a Params problem", attempt)
	}
	if correctCalls != 0 {
		t.Errorf("correct() called %d times, want 0 — must never spend a correction attempt on an unrelated Blocked reason", correctCalls)
	}
}

// openPRPlanWithEmptyFile is the whole-file successor to BUGS.md 110's
// fixture. That one was RUN-018: a one-word fix inside a YAML block-scalar
// shell script, which the single-field grammar could only express as a
// multi-line NewValue and therefore refused. Whole-file content spans as many
// lines as the file does, so that plan is now simply valid — RUN-018 is a fix
// ARGUS can propose rather than a rejection to correct.
//
// What can still make an OpenPR plan structurally unusable is a file set that
// is not a file set, and that is what this fixture carries: the model named a
// file and left it empty.
func openPRPlanWithEmptyFile() *remediation.RemediationPlan {
	return &remediation.RemediationPlan{
		ActionType:      remediation.ActionOpenPR,
		TargetGVK:       "apps/v1/Deployment",
		TargetNamespace: "argus-r47-run018",
		TargetName:      "run018-victim",
		Reversible:      true,
		RiskLevel:       remediation.RiskLow,
		Params: remediation.OpenPRParams{
			Files: []remediation.ProposedFile{{Path: "envs/prod/run018-victim.yaml", Content: ""}},
		},
	}
}

// TestCorrectBlockedPlanParams_UnusableFileSet_CorrectionEligible is BUGS.md
// 110 / BACKLOG.md AL1's decision carried into the whole-file grammar,
// exercised through the same caller path a real /analyze request uses: a plan
// Blocked because its OpenPR file set is unusable DOES get exactly one
// correction attempt — it is a problem with what the model PRODUCED
// (RemediationPlan.ParamsOnlyValidationFailure's own distinction), not a
// structural/allowlist problem no corrected proposal could ever satisfy, so a
// model might legitimately produce a usable one on the second try. This covers
// both directions of that one bounded attempt: a corrected proposal that now
// validates, and one that still fails — either way, called exactly once, never
// retried.
func TestCorrectBlockedPlanParams_UnusableFileSet_CorrectionEligible(t *testing.T) {
	t.Run("corrected file set now validates", func(t *testing.T) {
		var correctCalls int
		correct := func(_ context.Context, p remediation.RemediationPlan, rejection string) (remediation.ActionParams, error) {
			correctCalls++
			if !strings.Contains(rejection, "no content") {
				t.Errorf("correct() was given rejection %q, want it to name the empty-content failure", rejection)
			}
			// The fix RUN-018 actually needed, and could not be expressed at
			// all under the single-field grammar: one word inside a YAML
			// block-scalar shell script.
			return remediation.OpenPRParams{
				Files: []remediation.ProposedFile{{
					Path:    "envs/prod/run018-victim.yaml",
					Content: "spec:\n  initContainers:\n    - command:\n        - sh\n        - -c\n        - |\n          until nc -z run018-db 5432; do\n            sleep 1\n          done\n",
				}},
			}, nil
		}

		plan, attempt := correctBlockedPlanParams(context.Background(), openPRPlanWithEmptyFile(), correct)

		if correctCalls != 1 {
			t.Fatalf("correct() called %d times, want exactly 1 — an unusable file set must be treated as correction-eligible", correctCalls)
		}
		if attempt == nil || !attempt.Succeeded {
			t.Fatalf("attempt = %#v, want a non-nil, successful record", attempt)
		}
		if err := plan.Validate(); err != nil {
			t.Errorf("corrected plan.Validate() = %v, want nil", err)
		}
	})

	t.Run("model proposes another unusable file set, still blocked, not retried", func(t *testing.T) {
		var correctCalls int
		correct := func(_ context.Context, _ remediation.RemediationPlan, _ string) (remediation.ActionParams, error) {
			correctCalls++
			// The model tries again and still returns nothing usable.
			return remediation.OpenPRParams{
				Files: []remediation.ProposedFile{{Path: "envs/prod/run018-victim.yaml", Content: "   "}},
			}, nil
		}
		original := openPRPlanWithEmptyFile()

		plan, attempt := correctBlockedPlanParams(context.Background(), original, correct)

		if correctCalls != 1 {
			t.Fatalf("correct() called %d times, want exactly 1 — never a second attempt", correctCalls)
		}
		if plan != original {
			t.Errorf("plan = %#v, want the SAME original plan pointer returned unchanged", plan)
		}
		if attempt == nil || attempt.Succeeded {
			t.Fatalf("attempt = %#v, want a non-nil, unsuccessful record", attempt)
		}
		if !strings.Contains(attempt.Outcome, "still failed validation") {
			t.Errorf("attempt.Outcome = %q, want it to say the corrected proposal still failed validation", attempt.Outcome)
		}
	})
}

// openPRPlanWithRedactedContent is BUGS.md 112's exact live shape
// (CFG-004, incident inc_01m14p3awe53gd6ha49a02dvcf): a correct root-cause
// diagnosis ("rename this ConfigMap key, keep its value") whose only way to
// carry the value forward required echoing redact.Marker, because the model
// was never shown the real value in the first place.
func openPRPlanWithRedactedContent() *remediation.RemediationPlan {
	return &remediation.RemediationPlan{
		ActionType:      remediation.ActionOpenPR,
		TargetGVK:       "v1/ConfigMap",
		TargetNamespace: "argus-r58-cfg4",
		TargetName:      "cfg4-config",
		Reversible:      true,
		RiskLevel:       remediation.RiskLow,
		Params: remediation.OpenPRParams{
			Files: []remediation.ProposedFile{{
				Path:    "envs/prod/cfg4-config.yaml",
				Content: "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: cfg4-config\ndata:\n  RETRY_LIMIT: \"" + redact.Marker + "\"\n",
			}},
		},
	}
}

// TestCorrectBlockedPlanParams_RedactionMarker_CorrectionIneligible is
// BUGS.md 112's explicit decision, exercised through the same
// correctBlockedPlanParams caller path a real /analyze request uses, in
// deliberate contrast to
// TestCorrectBlockedPlanParams_UnusableFileSet_CorrectionEligible just
// above: correct() must NEVER be called for this Blocked reason, because a
// second attempt would ask the exact same model, with the exact same
// redacted evidence, to guess a value it was structurally never shown —
// unlike the unusable-file-set case, there is no version of "try again" that could
// possibly help. The plan must fall straight through, unchanged, exactly as
// if no correction mechanism existed at all.
func TestCorrectBlockedPlanParams_RedactionMarker_CorrectionIneligible(t *testing.T) {
	var correctCalls int
	correct := func(_ context.Context, _ remediation.RemediationPlan, _ string) (remediation.ActionParams, error) {
		correctCalls++
		return nil, nil
	}
	original := openPRPlanWithRedactedContent()

	plan, attempt := correctBlockedPlanParams(context.Background(), original, correct)

	if correctCalls != 0 {
		t.Fatalf("correct() called %d times, want 0 — a redaction-marker echo cannot be fixed by asking the same model again", correctCalls)
	}
	if plan != original {
		t.Errorf("plan = %#v, want the SAME original plan pointer returned unchanged", plan)
	}
	if attempt != nil {
		t.Errorf("attempt = %#v, want nil — no correction attempt should ever be recorded for this Blocked reason", attempt)
	}
}
