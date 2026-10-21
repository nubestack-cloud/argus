package remediation

import "fmt"

// Outcome is the closed set of results Evaluate can produce.
type Outcome string

const (
	// AutoApprove means the plan may execute without a human clicking
	// approve — every one of AutonomyPolicy's conditions was satisfied.
	AutoApprove Outcome = "AutoApprove"

	// NeedsApproval means the plan is well-formed and could, in
	// principle, be executed, but at least one autonomy condition wasn't
	// met (confidence too low or unknown, effective risk above this
	// policy's ceiling, not reversible when policy requires it, the hard
	// high-risk/irreversible safety floor, or an action type that is
	// approval-only by construction — see risk.go). This is
	// DESIGN.md §9.2's "any failure -> awaitingApproval"
	// outcome — a gate failure routes to a human, it never silently
	// drops the plan.
	NeedsApproval Outcome = "NeedsApproval"

	// Blocked means the plan itself is not something this gate will
	// route anywhere at all — an unrecognized action type, a
	// params/action-type mismatch, an invalid risk level, missing target
	// identification, an out-of-range confidence value, or an effective
	// risk of RiskForbidden (§9.3's "never, at any confidence" tier). A
	// Blocked plan is never a risk judgment call a human approver should
	// be asked to make — usually because it's a data problem upstream (a
	// bug in whatever authored the plan), and for RiskForbidden
	// specifically because presenting it for approval is the exact outcome
	// the tier exists to rule out.
	Blocked Outcome = "Blocked"
)

// Decision is Evaluate's result: one of the three Outcome values, always
// paired with a human-readable Reason. Per
// DESIGN.md §9.2: "'Why wasn't this auto-fixed?' must
// always have a precise answer — an opaque gate is one operators disable."
// Reason is written to be exactly that answer, suitable for display next
// to a gated plan in a future approval-queue UI (out of scope to build
// here — see this package's doc comment).
type Decision struct {
	Outcome Outcome
	Reason  string

	// InvalidPlan is true only for the Blocked decision produced by
	// plan.Validate() failing outright (an unrecognized ActionType/
	// RiskLevel string, a Params/ActionType mismatch, nil Params, missing
	// target identification, or an invalid embedded Params value) — the
	// first check below, before confidence or policy are even consulted.
	// It is false for every other Blocked reason (confidence out of range,
	// or RiskForbidden), and always false for AutoApprove/NeedsApproval,
	// because every one of those is only reached once Validate() has
	// already succeeded.
	//
	// The distinction matters because plan.ActionType/plan.RiskLevel are
	// guaranteed to be members of the closed enum (and therefore safe to
	// persist into remediation_recommendations' CHECK-constrained columns)
	// exactly when Validate() passed — never otherwise. BUGS.md 86: a
	// caller that persists plan.ActionType/plan.RiskLevel verbatim without
	// checking InvalidPlan first will hit a raw constraint violation for a
	// plan whose declared strings were never in the closed set to begin
	// with, rather than the clean "Blocked: unrecognized X" outcome this
	// gate already computed. Widening the constraint is not the fix here —
	// unlike the adjacent bug migrations 000040/000056/000063 fixed (a
	// valid NEW enum value the constraint hadn't been told about yet), an
	// InvalidPlan-true plan's RiskLevel/ActionType is not a value that was
	// ever meant to be persisted at all.
	InvalidPlan bool
}

// AutonomyPolicy expresses "auto-approve only low-risk (or below) +
// reversible (if required) + confidence above a threshold" —
// DESIGN.md §9.4's graduated-autonomy ladder made
// concrete as a small, configurable struct, not a hardcoded single rule
// and not a rules engine. A zero-value AutonomyPolicy (empty
// AutoApproveMaxRisk, MinConfidenceForAutoApprove 0, RequireReversible...
// false) auto-approves nothing, because "" is not a valid RiskLevel and
// therefore RiskLevel.atMost always fails against it — the safe default
// for "no policy has been configured yet" is never-auto-approve, not
// auto-approve-everything.
type AutonomyPolicy struct {
	// AutoApproveMaxRisk is the highest RiskLevel eligible for automatic
	// approval under this policy. A plan riskier than this ceiling always
	// falls through to NeedsApproval, regardless of confidence.
	AutoApproveMaxRisk RiskLevel

	// MinConfidenceForAutoApprove is the minimum confidence (expected in
	// [0,1]) required for automatic approval. A nil confidence (see
	// Evaluate) never meets any threshold, however low.
	MinConfidenceForAutoApprove float64

	// RequireReversibleForAutoApprove, when true, means an irreversible
	// plan never auto-approves under this policy regardless of risk or
	// confidence. Independent of, and layered on top of, the package's
	// own hard floor below (which applies unconditionally to
	// high-risk+irreversible plans even if a policy sets this to false).
	RequireReversibleForAutoApprove bool
}

// Evaluate is the risk/autonomy gate: it decides what should happen to one
// RemediationPlan, given the confidence of the analysis that produced it
// and the autonomy policy currently in force. It is a pure function — no
// I/O, no mutation, no connection to any cluster — matching this task's
// explicit scope (DESIGN.md §9's "confidence x risk
// gating," "never trust a bare confidence number alone").
//
// confidence is *float64, not float64, specifically so "unknown" has a
// real representation (nil) distinct from every valid number, including
// zero — DESIGN.md §8.4/§26's PartialAnalysis already
// models an incomplete investigation's confidence as JSON null for exactly
// this reason, and this gate must not coerce that into 0.0 (which would
// read as "very low confidence," a claim the model never made) or, worse,
// into some accidentally-passing sentinel. A nil confidence can never
// satisfy MinConfidenceForAutoApprove, however low that threshold is set.
func Evaluate(plan RemediationPlan, confidence *float64, policy AutonomyPolicy) Decision {
	// A structurally invalid plan is blocked outright, before confidence
	// or policy ever enter the picture — an unrecognized ActionType (or
	// any other Validate failure) is never silently treated as
	// "acceptable, just needs a human" or, worse, auto-approved.
	if err := plan.Validate(); err != nil {
		return Decision{Outcome: Blocked, Reason: fmt.Sprintf("plan rejected: %v", err), InvalidPlan: true}
	}

	if confidence != nil && (*confidence < 0 || *confidence > 1) {
		return Decision{Outcome: Blocked, Reason: fmt.Sprintf(
			"confidence %v is outside the valid [0,1] range", *confidence)}
	}

	// Every risk comparison from here on is made against the EFFECTIVE risk
	// level (risk.go): the plan's declared level raised to the deterministic
	// floor for its action type and target. DESIGN.md §9.3's
	// "the model may raise risk; it may never lower it below the rule-derived
	// floor" is not expressible if the gate reads plan.RiskLevel directly —
	// that field is whatever the model wrote.
	//
	// The declared value is deliberately NOT overwritten on the plan: the
	// record of what the model claimed is evidence about the model (§9.5's
	// calibration data is exactly this), and silently rewriting it would
	// destroy the signal that a class of plans is being under-classified.
	// Instead the divergence is reported in the Reason below, so "why wasn't
	// this auto-fixed?" answers with the rule, not with a mystery.
	effectiveRisk := EffectiveRiskLevel(plan)
	floorNote := ""
	if effectiveRisk != plan.RiskLevel {
		floorNote = fmt.Sprintf(" (the plan declared %q; the deterministic floor for a %s targeting %s in namespace %q is %q, and a declared level is never allowed to sit below it)",
			plan.RiskLevel, plan.ActionType, plan.TargetGVK, plan.TargetNamespace, effectiveRisk)
	}

	// Absolute, non-configurable refusal: RiskForbidden means "never, at any
	// confidence" (§9.3) — stronger than NeedsApproval, because presenting
	// this to a human for approval is exactly what §9.3 rules out. No
	// ActionType declares this as its own base floor (see RiskForbidden's
	// doc comment), so the only way to reach it today is a model-declared
	// riskLevel of "forbidden" — never prompted for, but Valid() accepts it,
	// and a deterministic gate must not trust a self-report to stay below
	// the one tier it must never claim. Checked first, before the
	// high-risk+irreversible floor and NeverAutoApprove below, so a caller
	// asking "why wasn't this auto-fixed" never gets a weaker true-but-not-
	// the-real-reason answer.
	if effectiveRisk == RiskForbidden {
		return Decision{Outcome: Blocked, Reason: fmt.Sprintf(
			"risk level is forbidden — this action is never permitted, under any policy or confidence, and is not routed to a human approver%s", floorNote)}
	}

	// Hard, non-configurable safety floor: a high-risk action with no
	// known compensating/undo path never auto-approves, no matter how
	// confident the analysis or how permissive the policy. Modeled after
	// lld/08-remediation-contracts.md §9's "halt-on-failure is a hard
	// invariant of the controller's own state machine, not a
	// configurable field a policy can disable" — this is that same
	// pattern applied to the gate: AutonomyPolicy has no field that can
	// switch this off.
	if effectiveRisk == RiskHigh && !plan.Reversible {
		return Decision{Outcome: NeedsApproval, Reason: fmt.Sprintf(
			"blocked from auto-approval by a hard safety floor: risk=%s and reversible=false — "+
				"high-risk, irreversible actions are never auto-approved regardless of confidence or policy%s",
			effectiveRisk, floorNote)}
	}

	// Second hard, non-configurable floor: some action types are
	// approval-only by construction, independent of risk level, confidence
	// or policy — see risk.go's neverAutoApprove for the per-action-type
	// reasoning. Checked before confidence so that the answer to "why wasn't
	// this auto-fixed?" is the real reason (this action never is) rather than
	// an incidental one (confidence was 0.02 below the threshold this time),
	// which would imply that a more confident analysis would have executed
	// it unattended.
	if NeverAutoApprove(plan.ActionType) {
		return Decision{Outcome: NeedsApproval, Reason: fmt.Sprintf(
			"%s is approval-only by construction: it is never auto-approved at any confidence, "+
				"under any policy — a human authorizes every execution%s", plan.ActionType, floorNote)}
	}

	if confidence == nil {
		return Decision{Outcome: NeedsApproval, Reason: "confidence is null (partial or incomplete analysis) — " +
			"a plan can never auto-approve without a known confidence value"}
	}

	if !effectiveRisk.atMost(policy.AutoApproveMaxRisk) {
		return Decision{Outcome: NeedsApproval, Reason: fmt.Sprintf(
			"risk level %q exceeds this policy's auto-approve ceiling %q%s", effectiveRisk, policy.AutoApproveMaxRisk, floorNote)}
	}

	if policy.RequireReversibleForAutoApprove && !plan.Reversible {
		return Decision{Outcome: NeedsApproval, Reason: "plan is not reversible, and this policy requires " +
			"reversibility for auto-approval"}
	}

	if *confidence < policy.MinConfidenceForAutoApprove {
		return Decision{Outcome: NeedsApproval, Reason: fmt.Sprintf(
			"confidence %.2f is below this policy's auto-approve threshold %.2f",
			*confidence, policy.MinConfidenceForAutoApprove)}
	}

	return Decision{Outcome: AutoApprove, Reason: fmt.Sprintf(
		"risk %q is within this policy's ceiling %q, reversible=%v, and confidence %.2f meets the %.2f threshold%s",
		effectiveRisk, policy.AutoApproveMaxRisk, plan.Reversible, *confidence, policy.MinConfidenceForAutoApprove, floorNote)}
}
