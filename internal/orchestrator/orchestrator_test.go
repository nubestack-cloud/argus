package orchestrator

import (
	"strings"
	"testing"

	"argus/internal/llm"
	"argus/internal/remediation"
	"argus/internal/resolution"
	"argus/internal/settings"
)

func floatPtr(f float64) *float64 { return &f }

// scaleUpPlan is a well-formed, low-risk, reversible plan — deliberately
// shaped so DefaultAutonomyPolicy's ceiling (low risk, reversible required,
// 0.90 confidence threshold) can go either way depending on the confidence
// passed alongside it in each test case below.
func scaleUpPlan() *remediation.RemediationPlan {
	return &remediation.RemediationPlan{
		ActionType:      remediation.ActionScaleDeployment,
		TargetGVK:       "apps/v1/Deployment",
		TargetNamespace: "payments",
		TargetName:      "checkout-worker",
		Params:          remediation.ScaleDeploymentParams{Replicas: 4},
		Reversible:      true,
		RiskLevel:       remediation.RiskLow,
	}
}

// mediumRiskPlan is well-formed but above DefaultAutonomyPolicy's
// AutoApproveMaxRisk ceiling regardless of confidence — used to exercise
// NeedsApproval independent of the confidence threshold.
func mediumRiskPlan() *remediation.RemediationPlan {
	return &remediation.RemediationPlan{
		ActionType:      remediation.ActionRestartPod,
		TargetGVK:       "v1/Pod",
		TargetNamespace: "payments",
		TargetName:      "checkout-worker-7f8d9c-abcde",
		Params:          remediation.RestartPodParams{},
		Reversible:      true,
		RiskLevel:       remediation.RiskMedium,
	}
}

// invalidPlan has an unrecognized ActionType — internal/remediation.Evaluate
// always Blocks this, regardless of confidence/policy.
func invalidPlan() *remediation.RemediationPlan {
	return &remediation.RemediationPlan{
		ActionType: remediation.ActionType("DeleteNamespace"),
		TargetName: "payments",
		RiskLevel:  remediation.RiskLow,
	}
}

func TestAdvance_Partial(t *testing.T) {
	for _, reason := range []string{"iteration_limit", "time_limit"} {
		result := llm.Investigation{
			Status:        "partial",
			PartialReason: reason,
			// A partial investigation could in principle still carry a
			// ProposedPlan field if some future prompt change allowed it —
			// but Advance must ignore it entirely for a partial result,
			// per its own doc comment, so this is deliberately non-nil
			// here to prove that.
			ProposedPlan: scaleUpPlan(),
			Confidence:   floatPtr(0.5),
		}
		adv := Advance(result, DefaultAutonomyPolicy, resolution.RouteInPlace)
		if adv.NextState != StateNeedsHumanInvestigation {
			t.Errorf("partial (%s): NextState = %q, want %q", reason, adv.NextState, StateNeedsHumanInvestigation)
		}
		if adv.Plan != nil {
			t.Errorf("partial (%s): Plan should be nil, got %+v", reason, adv.Plan)
		}
		if adv.Decision != nil {
			t.Errorf("partial (%s): Decision should be nil, got %+v", reason, adv.Decision)
		}
		if !strings.Contains(adv.Reason, reason) {
			t.Errorf("partial (%s): Reason %q does not mention the bound that was hit", reason, adv.Reason)
		}
	}
}

func TestAdvance_CompleteNoPlan(t *testing.T) {
	result := llm.Investigation{
		Status:       "complete",
		Confidence:   floatPtr(0.95),
		ProposedPlan: nil,
	}
	adv := Advance(result, DefaultAutonomyPolicy, resolution.RouteInPlace)
	if adv.NextState != StateNeedsHumanInvestigation {
		t.Errorf("NextState = %q, want %q", adv.NextState, StateNeedsHumanInvestigation)
	}
	if adv.Plan != nil || adv.Decision != nil {
		t.Errorf("expected no Plan/Decision, got Plan=%+v Decision=%+v", adv.Plan, adv.Decision)
	}
	if adv.Reason == "" {
		t.Error("expected a non-empty Reason")
	}
}

// TestAdvance_CompleteNoPlanGuidanceRoute is lld/08 §12.7's own regression
// test: guidance is a destination, not a fallthrough — the same "no plan"
// input TestAdvance_CompleteNoPlan covers must land somewhere DIFFERENT when
// the route is guidance, because the reason for having no plan is opposite
// (nothing to propose at all, vs. a route that permits nothing).
func TestAdvance_CompleteNoPlanGuidanceRoute(t *testing.T) {
	result := llm.Investigation{
		Status:             "complete",
		Confidence:         floatPtr(0.7),
		ProposedPlan:       nil,
		SuggestedNextSteps: []string{"check the referenced ConfigMap exists"},
	}
	adv := Advance(result, DefaultAutonomyPolicy, resolution.RouteGuidance)
	if adv.NextState != StateDiagnosed {
		t.Errorf("NextState = %q, want %q for a guidance route with no plan", adv.NextState, StateDiagnosed)
	}
	if adv.Plan != nil || adv.Decision != nil {
		t.Errorf("expected no Plan/Decision, got Plan=%+v Decision=%+v", adv.Plan, adv.Decision)
	}
}

// TestAdvance_NotAFault_DropsPlanRegardlessOfRoute pins BUGS.md 136: an
// investigation whose own rootCause.isFault is explicitly false must land on
// StateDiagnosed and carry NO plan/decision, even though a proposedPlan
// (a DeleteResource cleanup, the observed real case) was present and even on
// a route that would otherwise send it straight to AutoApprove — this check
// must run before route or plan-gating even gets a look at it.
func TestAdvance_NotAFault_DropsPlanRegardlessOfRoute(t *testing.T) {
	cleanupPlan := &remediation.RemediationPlan{
		ActionType:      remediation.ActionDeleteResource,
		TargetGVK:       "v1/Pod",
		TargetNamespace: "kube-system",
		TargetName:      "bootstrap-job-abc123",
		Reversible:      false,
		RiskLevel:       remediation.RiskLow,
	}
	result := llm.Investigation{
		Status:       "complete",
		Confidence:   floatPtr(0.98),
		RootCause:    &llm.RootCause{Statement: "completed Job pod, working as intended", IsFault: boolPtrForConfig(false)},
		ProposedPlan: cleanupPlan,
	}
	adv := Advance(result, DefaultAutonomyPolicy, resolution.RouteInPlace)
	if adv.NextState != StateDiagnosed {
		t.Errorf("NextState = %q, want %q for an explicit not-a-fault conclusion", adv.NextState, StateDiagnosed)
	}
	if adv.Plan != nil {
		t.Errorf("expected no Plan attached, got %+v — cleanup must never reach the approval queue", adv.Plan)
	}
	if adv.Decision != nil {
		t.Errorf("expected no Decision attached, got %+v", adv.Decision)
	}
	if adv.Reason == "" {
		t.Error("expected a non-empty Reason")
	}
}

// TestAdvance_IsFaultNilOrTrue_BehavesExactlyAsBefore is the regression half
// of the above: a nil IsFault (the model was never asked — every existing
// caller until this fix) or an explicit true must be completely unaffected,
// still reaching AutoApprove for a plan that otherwise qualifies.
func TestAdvance_IsFaultNilOrTrue_BehavesExactlyAsBefore(t *testing.T) {
	for name, rc := range map[string]*llm.RootCause{
		"nil IsFault":      {Statement: "OOMKilled"},
		"explicit IsFault": {Statement: "OOMKilled", IsFault: boolPtrForConfig(true)},
	} {
		t.Run(name, func(t *testing.T) {
			result := llm.Investigation{
				Status:       "complete",
				Confidence:   floatPtr(0.95),
				RootCause:    rc,
				ProposedPlan: scaleUpPlan(),
			}
			adv := Advance(result, DefaultAutonomyPolicy, resolution.RouteInPlace)
			if adv.NextState != StateAwaitingApproval {
				t.Errorf("NextState = %q, want %q", adv.NextState, StateAwaitingApproval)
			}
			if adv.Plan == nil {
				t.Error("expected a Plan attached")
			}
		})
	}
}

// TestAdvance_PairedRoute covers §12.6's second recommendation: both halves
// of a pullRequest+inPlace proposal are evaluated, and NextState follows the
// PRIMARY (in-place) plan's gate outcome regardless of how the paired
// OpenPR plan gates.
func TestAdvance_PairedRoute(t *testing.T) {
	result := llm.Investigation{
		Status:       "complete",
		Confidence:   floatPtr(0.95),
		ProposedPlan: scaleUpPlan(), // low risk, reversible, high confidence -> AutoApprove
		ProposedPairedPlan: &remediation.RemediationPlan{
			ActionType:      remediation.ActionOpenPR,
			TargetGVK:       "apps/v1/Deployment",
			TargetNamespace: "payments",
			TargetName:      "checkout-worker",
			Params:          remediation.OpenPRParams{Repository: "org/repo", Files: []remediation.ProposedFile{{Path: "envs/prod/checkout.yaml", Content: "spec:\n  replicas: 4\n"}}},
			Reversible:      true,
			RiskLevel:       remediation.RiskLow,
		},
	}
	adv := Advance(result, DefaultAutonomyPolicy, resolution.RoutePaired)
	if adv.NextState != StateAwaitingApproval {
		t.Errorf("NextState = %q, want %q", adv.NextState, StateAwaitingApproval)
	}
	if adv.Plan == nil || adv.Plan.ActionType != remediation.ActionScaleDeployment {
		t.Errorf("Plan = %+v, want the in-place plan as the primary", adv.Plan)
	}
	if adv.PairedPlan == nil || adv.PairedPlan.ActionType != remediation.ActionOpenPR {
		t.Errorf("PairedPlan = %+v, want the OpenPR plan", adv.PairedPlan)
	}
	if adv.PairedDecision == nil {
		t.Error("PairedDecision should be set alongside PairedPlan")
	}
}

func TestAdvance_CompleteWithPlan_AutoApprove(t *testing.T) {
	result := llm.Investigation{
		Status:       "complete",
		Confidence:   floatPtr(0.95), // above DefaultAutonomyPolicy's 0.90 threshold
		ProposedPlan: scaleUpPlan(),  // low risk, reversible — within DefaultAutonomyPolicy's ceiling
	}
	adv := Advance(result, DefaultAutonomyPolicy, resolution.RouteInPlace)

	// The hard boundary remains: AutoApprove must NEVER advance straight to
	// execution — unattended mutation stays gated on blast-radius batching,
	// rollback and freeze windows (STATUS.md §3 Tier 3).
	//
	// But it must land somewhere a human can ACT on, which is the part this
	// test originally got wrong by pinning RecommendationReady. That state's
	// only outgoing transition is back to Investigating, and /approve accepts
	// only AwaitingApproval — so the gate's safest verdict (low risk,
	// reversible, high confidence) was the one verdict nobody could approve.
	// A live scenario hit exactly that dead end. AwaitingApproval keeps the
	// human in the loop while making the recommendation actionable.
	if adv.NextState != StateAwaitingApproval {
		t.Errorf("NextState = %q, want %q (AutoApprove still requires a human, but must be approvable)", adv.NextState, StateAwaitingApproval)
	}
	if adv.NextState == StateExecuting {
		t.Fatal("AutoApprove must never advance directly to Executing")
	}
	if adv.Plan == nil {
		t.Fatal("expected a non-nil Plan")
	}
	if adv.Decision == nil || adv.Decision.Outcome != remediation.AutoApprove {
		t.Fatalf("expected a recorded AutoApprove Decision, got %+v", adv.Decision)
	}
	if !strings.Contains(adv.Reason, "auto-approve") {
		t.Errorf("Reason should record that the gate would have auto-approved, got %q", adv.Reason)
	}
}

func TestAdvance_CompleteWithPlan_NeedsApproval(t *testing.T) {
	cases := []struct {
		name string
		plan *remediation.RemediationPlan
		conf float64
	}{
		{"risk above ceiling", mediumRiskPlan(), 0.99},
		{"confidence below threshold", scaleUpPlan(), 0.10},
	}
	for _, c := range cases {
		result := llm.Investigation{Status: "complete", Confidence: floatPtr(c.conf), ProposedPlan: c.plan}
		adv := Advance(result, DefaultAutonomyPolicy, resolution.RouteInPlace)
		if adv.NextState != StateAwaitingApproval {
			t.Errorf("%s: NextState = %q, want %q", c.name, adv.NextState, StateAwaitingApproval)
		}
		if adv.Decision == nil || adv.Decision.Outcome != remediation.NeedsApproval {
			t.Errorf("%s: expected NeedsApproval decision, got %+v", c.name, adv.Decision)
		}
		if adv.Plan == nil {
			t.Errorf("%s: expected a non-nil Plan", c.name)
		}
	}
}

func TestAdvance_CompleteWithPlan_Blocked(t *testing.T) {
	result := llm.Investigation{
		Status:       "complete",
		Confidence:   floatPtr(0.95),
		ProposedPlan: invalidPlan(),
	}
	adv := Advance(result, DefaultAutonomyPolicy, resolution.RouteInPlace)
	if adv.NextState != StateNeedsHumanInvestigation {
		t.Errorf("NextState = %q, want %q", adv.NextState, StateNeedsHumanInvestigation)
	}
	if adv.Decision == nil || adv.Decision.Outcome != remediation.Blocked {
		t.Fatalf("expected Blocked decision, got %+v", adv.Decision)
	}
	if !strings.Contains(adv.Reason, "invalid") {
		t.Errorf("Reason should mention the plan was invalid, got %q", adv.Reason)
	}
}

// TestAdvance_CompleteWithPlan_NilConfidence covers a structurally odd but
// possible case: Investigation.Status == "complete" (so ProposedPlan is
// meaningful) yet Confidence is nil — internal/remediation.Evaluate's own
// documented behavior for a nil confidence is NeedsApproval, never
// AutoApprove, and Advance must not special-case around that.
func TestAdvance_CompleteWithPlan_NilConfidence(t *testing.T) {
	result := llm.Investigation{Status: "complete", Confidence: nil, ProposedPlan: scaleUpPlan()}
	adv := Advance(result, DefaultAutonomyPolicy, resolution.RouteInPlace)
	if adv.NextState != StateAwaitingApproval {
		t.Errorf("NextState = %q, want %q", adv.NextState, StateAwaitingApproval)
	}
	if adv.Decision == nil || adv.Decision.Outcome != remediation.NeedsApproval {
		t.Fatalf("expected NeedsApproval decision, got %+v", adv.Decision)
	}
}

// TestAdvance_NeverReturnsExecuting is a structural guard: whatever this
// function can return, it must be one of exactly the five states this
// package's doc comment says it wires — this is what would fail loudly if
// a future edit ever taught Advance to return StateExecuting (which
// doesn't even exist as a constant in this package today, by design).
func TestAdvance_NeverReturnsExecuting(t *testing.T) {
	allowed := map[string]bool{
		StateDetected:                true,
		StateInvestigating:           true,
		StateRecommendationReady:     true,
		StateNeedsHumanInvestigation: true,
		StateAwaitingApproval:        true,
	}
	scenarios := []llm.Investigation{
		{Status: "partial", PartialReason: "iteration_limit"},
		{Status: "complete", Confidence: floatPtr(0.99), ProposedPlan: nil},
		{Status: "complete", Confidence: floatPtr(0.99), ProposedPlan: scaleUpPlan()},
		{Status: "complete", Confidence: floatPtr(0.10), ProposedPlan: mediumRiskPlan()},
		{Status: "complete", Confidence: floatPtr(0.99), ProposedPlan: invalidPlan()},
		{Status: "complete", Confidence: nil, ProposedPlan: scaleUpPlan()},
	}
	for _, s := range scenarios {
		if got := Advance(s, DefaultAutonomyPolicy, resolution.RouteInPlace).NextState; !allowed[got] {
			t.Errorf("Advance returned an unrecognized/forbidden state %q for %+v", got, s)
		}
	}
}

func floatPtrForConfig(f float64) *float64 { return &f }
func strPtrForConfig(s string) *string     { return &s }
func boolPtrForConfig(b bool) *bool        { return &b }

// TestResolveAutonomyPolicy_Precedence pins ResolveAutonomyPolicy's
// documented DB-row-else-hardcoded-default rule: a non-nil
// settings.Config field always wins; a nil one falls back to
// DefaultAutonomyPolicy's own value — never to remediation's own
// zero-value "auto-approve nothing" default, which would be a silent
// behavior change for every installation that has never touched this
// setting.
func TestResolveAutonomyPolicy_Precedence(t *testing.T) {
	t.Run("unconfigured Config resolves to exactly DefaultAutonomyPolicy", func(t *testing.T) {
		// A bare settings.Config{} now genuinely represents "nothing
		// configured" for all three fields, AutonomyRequireReversibleFor
		// AutoApprove included: migration 000085 (BUGS.md 97) made that
		// field a *bool, matching its two siblings, so its zero value (nil)
		// means "not configured in the DB" rather than an arbitrary,
		// permissive false — no workaround value needs to be set here
		// anymore.
		got := ResolveAutonomyPolicy(settings.Config{})
		if got != DefaultAutonomyPolicy {
			t.Errorf("ResolveAutonomyPolicy(unconfigured) = %+v, want DefaultAutonomyPolicy %+v", got, DefaultAutonomyPolicy)
		}
	})

	t.Run("a configured max risk overrides the default", func(t *testing.T) {
		got := ResolveAutonomyPolicy(settings.Config{AutonomyAutoApproveMaxRisk: strPtrForConfig("high")})
		if got.AutoApproveMaxRisk != remediation.RiskHigh {
			t.Errorf("AutoApproveMaxRisk = %q, want high (DB override)", got.AutoApproveMaxRisk)
		}
		// The other two fields still fall back to DefaultAutonomyPolicy —
		// setting one field doesn't clear the others.
		if got.MinConfidenceForAutoApprove != DefaultAutonomyPolicy.MinConfidenceForAutoApprove {
			t.Errorf("MinConfidenceForAutoApprove = %v, want the untouched default %v",
				got.MinConfidenceForAutoApprove, DefaultAutonomyPolicy.MinConfidenceForAutoApprove)
		}
	})

	t.Run("a configured min confidence overrides the default", func(t *testing.T) {
		got := ResolveAutonomyPolicy(settings.Config{AutonomyMinConfidenceForAutoApprove: floatPtrForConfig(0.5)})
		if got.MinConfidenceForAutoApprove != 0.5 {
			t.Errorf("MinConfidenceForAutoApprove = %v, want 0.5 (DB override)", got.MinConfidenceForAutoApprove)
		}
	})

	// BUGS.md 97's regression test: before migration 000085, this field was
	// a plain bool with no nil case in ResolveAutonomyPolicy at all — any
	// Config not explicitly carrying true (including the zero-value
	// Config{} a PUT that omitted the field, decoded through
	// settings.AutonomyUpdate, used to produce) silently resolved to false,
	// the permissive direction. Proves the fix: nil now falls back to
	// DefaultAutonomyPolicy's true, and only an explicit false actually
	// turns the guardrail off.
	t.Run("nil falls back to DefaultAutonomyPolicy's true, not to false", func(t *testing.T) {
		got := ResolveAutonomyPolicy(settings.Config{AutonomyRequireReversibleForAutoApprove: nil})
		if !got.RequireReversibleForAutoApprove {
			t.Errorf("RequireReversibleForAutoApprove = false, want true (DefaultAutonomyPolicy's fallback value) when Config leaves this field unconfigured — this is exactly the BUGS.md 97 regression")
		}
	})

	t.Run("an explicit false override is honored", func(t *testing.T) {
		f := false
		got := ResolveAutonomyPolicy(settings.Config{AutonomyRequireReversibleForAutoApprove: &f})
		if got.RequireReversibleForAutoApprove {
			t.Errorf("RequireReversibleForAutoApprove = true, want false (explicit DB override)")
		}
	})

	t.Run("an explicit true override is honored", func(t *testing.T) {
		tr := true
		got := ResolveAutonomyPolicy(settings.Config{AutonomyRequireReversibleForAutoApprove: &tr})
		if !got.RequireReversibleForAutoApprove {
			t.Errorf("RequireReversibleForAutoApprove = false, want true (explicit DB override)")
		}
	})

	t.Run("an unrecognized risk string resolves to a RiskLevel that never matches any real level", func(t *testing.T) {
		// Defensive: this should never happen past migration 000028's CHECK
		// constraint and internal/api/settings.go's own validation, but
		// ResolveAutonomyPolicy must fail safe (never auto-approve) rather
		// than panic or silently treat it as some real level.
		got := ResolveAutonomyPolicy(settings.Config{AutonomyAutoApproveMaxRisk: strPtrForConfig("not-a-real-level")})
		if got.AutoApproveMaxRisk.Valid() {
			t.Errorf("AutoApproveMaxRisk = %q unexpectedly Valid(); want an unrecognized RiskLevel", got.AutoApproveMaxRisk)
		}
	})
}

// TestResolveAutonomyPolicyCannotWeakenSafetyFloor is the test this whole
// task's brief specifically asked for: configure the MOST PERMISSIVE
// possible autonomy policy through the exact same path a real admin would
// (a settings.Config as if freshly resolved from org_settings, translated
// by ResolveAutonomyPolicy, then run through the real, unmodified
// internal/remediation.Evaluate via Advance) and confirm a high-risk,
// irreversible plan still comes back NeedsApproval — never AutoApprove,
// regardless of confidence. This proves the hard safety floor
// (WORKLOG.md §31: "high risk + irreversible always needs a human") is
// genuinely unreachable through this task's new configuration surface, not
// merely untested by it.
func TestResolveAutonomyPolicyCannotWeakenSafetyFloor(t *testing.T) {
	mostPermissive := settings.Config{
		AutonomyAutoApproveMaxRisk:              strPtrForConfig("high"),
		AutonomyMinConfidenceForAutoApprove:     floatPtrForConfig(0.0),
		AutonomyRequireReversibleForAutoApprove: boolPtrForConfig(false),
	}
	policy := ResolveAutonomyPolicy(mostPermissive)

	plan := scaleUpPlan()
	plan.RiskLevel = remediation.RiskHigh
	plan.Reversible = false

	result := llm.Investigation{
		Status:       "complete",
		Confidence:   floatPtr(1.0), // maximum possible confidence
		ProposedPlan: plan,
	}

	adv := Advance(result, policy, resolution.RouteInPlace)
	if adv.NextState != StateAwaitingApproval {
		t.Fatalf("NextState = %q, want %q — the most permissive configurable policy must not move a high-risk, "+
			"irreversible plan past a human approver", adv.NextState, StateAwaitingApproval)
	}
	if adv.Decision == nil || adv.Decision.Outcome != remediation.NeedsApproval {
		t.Fatalf("Decision = %+v, want NeedsApproval regardless of policy/confidence", adv.Decision)
	}
	if !strings.Contains(adv.Decision.Reason, "safety floor") {
		t.Errorf("Decision.Reason = %q, want it to name the hard safety floor explicitly", adv.Decision.Reason)
	}
}

// TestPlanParamsRoundTrip_PatchResourceLimits guards the one params type whose
// wire shape is defined by its own struct tags rather than by a hand-built map
// in marshalPlanParams: the same JSON has to be readable both by
// UnmarshalPlanParams here and by internal/agent/tools.go, which decodes it
// into the identical Go type to re-run the shared bounds check before issuing
// a Patch. A field name that survives marshal but not unmarshal would show up
// as an agent that silently declines every plan of this type — or, worse, one
// that reads a zero value past a bounds check written to ignore unset fields.
func TestPlanParamsRoundTrip_PatchResourceLimits(t *testing.T) {
	original := remediation.PatchResourceLimitsParams{
		Container:     "api",
		MemoryLimit:   "256Mi",
		MemoryRequest: "64Mi",
		CPULimit:      "1500m",
		CPURequest:    "250m",
	}
	plan := remediation.RemediationPlan{
		IncidentID:      "inc_01",
		ActionType:      remediation.ActionPatchResourceLimits,
		TargetGVK:       "apps/v1/Deployment",
		TargetNamespace: "payments",
		TargetName:      "checkout-api",
		Params:          original,
		Reversible:      true,
		RiskLevel:       remediation.RiskMedium,
	}

	paramsJSON, err := MarshalPlanParams(plan)
	if err != nil {
		t.Fatalf("MarshalPlanParams: %v", err)
	}

	reconstructed, err := ReconstructPlan(plan.IncidentID, "an_01", string(plan.ActionType),
		plan.TargetGVK, plan.TargetNamespace, plan.TargetName, paramsJSON, plan.Reversible, string(plan.RiskLevel))
	if err != nil {
		t.Fatalf("ReconstructPlan: %v", err)
	}
	got, ok := reconstructed.Params.(remediation.PatchResourceLimitsParams)
	if !ok {
		t.Fatalf("reconstructed params are %T, want remediation.PatchResourceLimitsParams", reconstructed.Params)
	}
	if got != original {
		t.Errorf("round-tripped params = %+v, want %+v", got, original)
	}
	// And the reconstructed plan must still be a valid plan, since the approve
	// path signs and executes exactly this value.
	if err := reconstructed.Validate(); err != nil {
		t.Errorf("reconstructed plan does not validate: %v", err)
	}
}
