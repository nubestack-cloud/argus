package orchestrator

import (
	"argus/internal/llm"
	"argus/internal/remediation"
	"argus/internal/resolution"
	"argus/internal/settings"
)

// DefaultAutonomyPolicy is the hardcoded, conservative internal/remediation
// .AutonomyPolicy this package evaluates every proposed plan against
// whenever the organisation hasn't overridden a given field through
// PUT /api/v1/admin/settings (see ResolveAutonomyPolicy below) — the
// further, hardcoded-default fallback tier, not a bypass of that
// resolution path.
//
// FORMERLY an OPEN QUESTION, now closed: this constant used to be consulted
// directly, with no DB-backed override anywhere (WORKLOG.md §50 flagged this
// explicitly as "the clear next step"). internal/settings.Config now carries
// AutonomyAutoApproveMaxRisk/AutonomyMinConfidenceForAutoApprove/
// AutonomyRequireReversibleForAutoApprove (migration 000028_autonomy_policy),
// resolved fresh per call by ResolveAutonomyPolicy and consumed by
// ApplyAnalysisResult (db.go) — the same live-editable, no-restart-required
// discipline every other setting in this codebase already follows. This
// constant remains genuinely conservative (matches internal/remediation's
// own "a zero-value policy auto-approves nothing" safe-default philosophy,
// just relaxed enough to demonstrate the AutoApprove path is reachable at
// all — a policy so strict it can NEVER auto-approve anything would make
// this package's own AutoApprove handling untestable end to end), so an
// installation that never touches the new setting behaves exactly as it did
// before this setting existed:
//
//   - AutoApproveMaxRisk: low — never medium/high, regardless of confidence.
//   - MinConfidenceForAutoApprove: 0.90 — a high bar; most real
//     investigations (see the honest ~0.15 confidence scores this
//     project's own live verification runs have produced against an
//     unreachable cluster) will land well below this and route to
//     NeedsApproval instead, which is the safe failure mode.
//   - RequireReversibleForAutoApprove: true — belt and suspenders on top of
//     the risk ceiling.
var DefaultAutonomyPolicy = remediation.AutonomyPolicy{
	AutoApproveMaxRisk:              remediation.RiskLow,
	MinConfidenceForAutoApprove:     0.90,
	RequireReversibleForAutoApprove: true,
}

// ResolveAutonomyPolicy is the OPEN QUESTION above, now closed: it turns a
// freshly-Resolve()d internal/settings.Config into the real
// remediation.AutonomyPolicy that governs THIS call, applying
// DefaultAutonomyPolicy as the further, hardcoded-default fallback tier for
// whichever of the three nullable settings.Config fields the organisation
// hasn't configured yet — exactly the same DB-row-else-hardcoded-default
// precedence internal/llm/toolloop.go's resolveBounds already applies to
// AnalysisMaxIterations/AnalysisTimeLimitSeconds, extended here to a struct
// instead of two bare ints. AutonomyRequireReversibleForAutoApprove joined
// the other two as a *bool in migration 000085 (BUGS.md 97) — it used to be
// taken as-is with no nil case at all, which is exactly what let a PUT that
// omitted the field silently overwrite it with false, the permissive
// direction, instead of falling back to DefaultAutonomyPolicy's safe true.
//
// AutonomyAutoApproveMaxRisk is a plain *string on settings.Config (that
// package is imported BY internal/llm/internal/notify and deliberately
// carries no dependency on internal/remediation's types — see Config's own
// doc comment), so the cast to remediation.RiskLevel happens here, in the
// one package that already imports both settings and remediation. An
// unrecognized string (which should never happen past migration 000028's
// CHECK constraint and internal/api/settings.go's own validation, but this
// function doesn't trust either of those blindly) becomes a RiskLevel that
// fails remediation.RiskLevel.Valid()/atMost() against every real risk
// level, which is remediation.AutonomyPolicy's own documented safe failure
// mode — never auto-approve — not a panic or a silent "treat as low."
//
// Called fresh on every ApplyAnalysisResult, never cached, so a policy
// change made through PUT /api/v1/admin/settings governs the very next
// investigation with no hub restart — matching every other setting in this
// codebase's "live-editable" discipline (see internal/settings' own package
// doc comment).
//
// This function cannot weaken internal/remediation.Evaluate's hard,
// non-configurable high-risk+irreversible safety floor: that check runs
// unconditionally inside Evaluate, before the AutonomyPolicy this function
// builds is ever consulted, and has no field this function's output could
// use to disable it (see gate.go's own doc comment). What this function
// configures is the graduated-autonomy CEILING
// DESIGN.md §9.4 describes, not the floor beneath it.
func ResolveAutonomyPolicy(cfg settings.Config) remediation.AutonomyPolicy {
	policy := DefaultAutonomyPolicy
	if cfg.AutonomyAutoApproveMaxRisk != nil {
		policy.AutoApproveMaxRisk = remediation.RiskLevel(*cfg.AutonomyAutoApproveMaxRisk)
	}
	if cfg.AutonomyMinConfidenceForAutoApprove != nil {
		policy.MinConfidenceForAutoApprove = *cfg.AutonomyMinConfidenceForAutoApprove
	}
	if cfg.AutonomyRequireReversibleForAutoApprove != nil {
		policy.RequireReversibleForAutoApprove = *cfg.AutonomyRequireReversibleForAutoApprove
	}
	return policy
}

// Advancement is Advance's result: the incident's next state, the plan (if
// any) that was proposed and evaluated, and the gate's own Decision (if a
// plan was evaluated at all) — everything the DB-touching half of this
// package (db.go) and its callers (internal/api/analyze.go,
// internal/autoanalyze) need to persist and report, with no DB/I/O
// dependency of its own, so Advance itself is trivially unit-testable
// against a hand-built llm.Investigation (see orchestrator_test.go) with no
// LLM call, no tunnel, and no database involved.
type Advancement struct {
	NextState string
	Plan      *remediation.RemediationPlan
	Decision  *remediation.Decision
	// Reason is a human-readable explanation of why NextState was chosen —
	// distinct from Decision.Reason (which explains the GATE's verdict
	// specifically): Reason also covers the two cases where there's no gate
	// decision to explain at all (a partial investigation, or a complete one
	// with no proposed plan).
	Reason string
	// PlanID is set only by db.go's ApplyAnalysisResult, AFTER it persists
	// Plan into remediation_recommendations — always empty on Advance's own,
	// pure return value, since a plan has no identity until something
	// actually writes it to a table. Kept on this same struct rather than a
	// second wrapper type so callers (internal/api/analyze.go,
	// internal/autoanalyze) have exactly one result value to hold onto.
	PlanID string
	// PairedPlan/PairedDecision/PairedPlanID mirror Plan/Decision/PlanID for
	// route == resolution.RoutePaired's second recommendation (lld/08
	// §12.6: "two live recommendations may coexist for one incident... a
	// pull-request AND an in-place action"). Nil/empty for every other
	// route. PairedPlanID is set by ApplyAnalysisResult the same way PlanID
	// is.
	PairedPlan     *remediation.RemediationPlan
	PairedDecision *remediation.Decision
	PairedPlanID   string
}

// Advance is the pure decision function this package's whole design centers
// on: given one investigation result and the autonomy policy in force, it
// decides which of the five states an incident should move to next, per
// lld/08-remediation-contracts.md §2's diagram as far as this task's scope
// goes. No I/O, no mutation, no connection to any database — ApplyResult
// (db.go) is the thin, separately-testable layer that actually persists
// what this function decides.
//
//   - A "partial" investigation (a bound was hit, no conclusion reached)
//     always routes to NeedsHumanInvestigation — a bound-hit investigation
//     needs a human to pick up where the bounded loop left off, not more
//     automation piled on top of an already-inconclusive result. This is
//     the one case in this function with no plan and no gate decision at
//     all: there was nothing to propose a fix for.
//
//   - A "complete" investigation with NO proposed plan (result.ProposedPlan
//     == nil — the model concluded a root cause but didn't think any of
//     the three typed actions applied, or thought a human should decide
//     without any). This is a genuinely different kind of "needs human"
//     than the partial case (investigation succeeded; there's just no
//     candidate automation to gate), but this task's own five-state slice
//     has no better-fitting state for it than NeedsHumanInvestigation — see
//     this function's own reasoning restated in STATUS.md.
//
//   - A "complete" investigation WITH a proposed plan is run through
//     internal/remediation.Evaluate (the existing, already-tested gate),
//     and the resulting Outcome decides the next state:
//     Blocked (the plan itself doesn't hold up structurally) ->
//     NeedsHumanInvestigation, with Decision.Reason folded into Advancement
//     .Reason so the precise "why" survives to whatever displays it.
//     NeedsApproval -> AwaitingApproval — the plan is well-formed and could,
//     in principle, run, but at least one autonomy condition wasn't met, so
//     a human approver is next.
//     AutoApprove -> AwaitingApproval, DELIBERATELY NOT Executing. This
//     function never returns Executing, and that is still true now that
//     unattended execution exists — the reason has just moved.
//
//     It used to be the guarantee itself: no executor existed, then one
//     existed but nothing could reach it without a human. Since migration
//     000046 an operator CAN enable unattended execution, so the guarantee
//     is no longer "this never happens" but "this never happens HERE".
//     Executing is reached only through internal/api's execution path, which
//     re-checks the incident's state under a row lock, rehearses the change
//     against the live cluster, signs the plan and records an execution row.
//     Returning Executing from a pure function that has done none of those
//     things would mean an incident claiming to be executing while nothing
//     was ever sent — so the boundary is kept, on its own merits, and the
//     decision about whether to act without a human belongs to the sweeper
//     (internal/api/unattended.go) which is where the blast-radius cap can
//     actually be enforced sequentially.
func Advance(result llm.Investigation, policy remediation.AutonomyPolicy, route resolution.Route) Advancement {
	if result.Status != "complete" {
		reason := "the investigation hit a bound"
		if result.PartialReason != "" {
			reason = "the investigation hit its " + result.PartialReason + " bound"
		}
		return Advancement{
			NextState: StateNeedsHumanInvestigation,
			Reason:    reason + " without reaching a conclusion — needs a human to continue where the bounded loop left off",
		}
	}

	// BUGS.md 136: an investigation that itself concluded there is no fault
	// here — root_cause.isFault explicitly false, not merely absent — never
	// reaches AwaitingApproval, regardless of route and regardless of
	// whether the model filled in a proposedPlan anyway (a plausible-looking
	// DeleteResource cleanup was the observed case). Checked before the
	// ProposedPlan-nil branch below so it takes priority over route, and
	// the plan is dropped here rather than merely left unevaluated — an
	// operator reading this Advancement must never see a decision or a
	// plan attached to a "there is nothing to fix" outcome. A nil IsFault
	// (the model was never asked — any backend/prompt that doesn't set this
	// field) falls through unchanged: this only ever suppresses, never
	// invents, a plan.
	if result.RootCause != nil && result.RootCause.IsFault != nil && !*result.RootCause.IsFault {
		return Advancement{
			NextState: StateDiagnosed,
			Reason:    "the investigation concluded this is not a fault — nothing here needs remediation (see rootCause); any cleanup action is a routine housekeeping decision for a human, not an approval",
		}
	}

	if result.ProposedPlan == nil {
		if route == resolution.RouteGuidance {
			// lld/08 §12.7: guidance is a destination, not a fallthrough.
			// EnforceRoute has already dropped any plan the model proposed
			// anyway (guidance permits none), so this branch is where a
			// genuinely successful, action-free investigation lands —
			// Diagnosed, not NeedsHumanInvestigation, because nothing about
			// the analysis itself failed.
			return Advancement{
				NextState: StateDiagnosed,
				Reason:    "the investigation reached a root cause, but no in-cluster action is available for this incident (route: guidance) — see suggestedNextSteps",
			}
		}
		return Advancement{
			NextState: StateNeedsHumanInvestigation,
			Reason:    "the investigation reached a root cause, but proposed no actionable remediation plan — needs a human to decide next steps",
		}
	}

	plan := *result.ProposedPlan
	decision := remediation.Evaluate(plan, result.Confidence, policy)
	adv := advanceForPlan(plan, decision)

	// The paired route's second recommendation (§12.6) is evaluated
	// independently and carried alongside — NextState still follows the
	// PRIMARY (in-place) plan above: it is the more urgent action ("in-place
	// stops the outage now", §12.4's row 4), and the pull request is always
	// available in the approval queue regardless of how the in-place half
	// gates. A structural problem with ONLY the paired half (Blocked) does
	// not need to demote the whole incident to NeedsHumanInvestigation when
	// the in-place half is fine on its own.
	if result.ProposedPairedPlan != nil {
		pairedPlan := *result.ProposedPairedPlan
		pairedDecision := remediation.Evaluate(pairedPlan, result.Confidence, policy)
		adv.PairedDecision = &pairedDecision
		// BUGS.md 86 applies here identically to the primary plan above
		// (advanceForPlan's Blocked case): a paired plan that failed
		// plan.Validate() itself may carry an ActionType/RiskLevel string
		// outside the closed enum, and ApplyAnalysisResult persists
		// PairedPlan verbatim the same way it persists Plan. Only attach it
		// when Validate() already passed.
		if !pairedDecision.InvalidPlan {
			adv.PairedPlan = &pairedPlan
		}
	}
	return adv
}

// advanceForPlan is Advance's single-plan decision, pulled out so the paired
// route's second recommendation can reuse the exact same gate-outcome ->
// NextState mapping without duplicating it.
func advanceForPlan(plan remediation.RemediationPlan, decision remediation.Decision) Advancement {
	switch decision.Outcome {
	case remediation.Blocked:
		adv := Advancement{
			NextState: StateNeedsHumanInvestigation,
			Decision:  &decision,
			Reason:    "the proposed plan was rejected by the autonomy gate as structurally invalid: " + decision.Reason,
		}
		// BUGS.md 86: only attach the plan (and, downstream in
		// ApplyAnalysisResult, persist it) when it passed plan.Validate() —
		// i.e. decision.InvalidPlan is false, meaning this Blocked came from
		// confidence-out-of-range or RiskForbidden, not from Validate()
		// itself. Those two are the ONLY Blocked sub-reasons where
		// plan.ActionType/plan.RiskLevel are guaranteed to already be
		// members of the closed enum (Decision.InvalidPlan's doc comment).
		// A Validate()-shaped Blocked plan's declared strings can be
		// anything a model wrote — persisting them verbatim is exactly the
		// raw constraint violation BUGS.md 86 describes, so this plan is
		// deliberately left unpersisted: the precise reason still reaches
		// the incident via Reason/Decision above, it just never becomes a
		// remediation_recommendations row.
		if !decision.InvalidPlan {
			adv.Plan = &plan
		}
		return adv
	case remediation.AutoApprove:
		// Deliberately the SAME next state as NeedsApproval, for a reason that
		// took a live end-to-end run to see. Still the same state now that
		// unattended execution exists: the sweeper's candidate query keys off
		// AwaitingApproval precisely so that an auto-approved plan is in the
		// human queue for as long as it has not been executed, whichever way it
		// eventually leaves.
		//
		// This used to route to StateRecommendationReady, on the reasoning that
		// the gate would auto-approve but no executor existed, so the decision
		// was recorded "for visibility only". Both halves of that have since
		// stopped being true: ScaleDeployment/RestartPod execute end to end
		// (WORKLOG §69), and RecommendationReady's only outgoing transition is
		// back to Investigating — so it was a terminal state in practice.
		//
		// The effect was an inverted incentive that a real scenario walked
		// straight into: a plan the gate judged low-risk, reversible and
		// high-confidence — the safest class of plan there is — became the ONE
		// class a human could not approve, because /approve only accepts
		// AwaitingApproval. A riskier plan was actionable; the safest was a
		// dead end reading "no remediation to approve yet".
		//
		// What the original routing was actually protecting is unattended
		// mutation, and that protection now lives in one place, off this path
		// entirely: org_settings.autonomy_unattended_execution_enabled (default
		// false) plus the blast-radius cap DESIGN.md §10.5 requires alongside it.
		// Decision is still recorded, so the UI can distinguish "the gate would
		// have auto-approved this" from "the gate required a human", which is
		// the visibility the old routing was reaching for — and which is now
		// also what the sweeper selects on.
		return Advancement{
			NextState: StateAwaitingApproval,
			Plan:      &plan,
			Decision:  &decision,
			// Says what is true regardless of the setting, because this function
			// cannot see it and must not guess: the plan is queued and the gate
			// approved it. Whether a person or the policy acts on it is decided
			// later, by whoever gets there first.
			Reason: decision.Reason + " — the gate auto-approved this plan, so it is queued ready to run: " +
				"a person can approve it now, and it also executes on its own if unattended execution is enabled",
		}
	case remediation.NeedsApproval:
		return Advancement{
			NextState: StateAwaitingApproval,
			Plan:      &plan,
			Decision:  &decision,
			Reason:    decision.Reason,
		}
	default:
		// remediation.Evaluate's Outcome is a closed set of exactly these
		// three values — this branch exists only so an unrecognized value
		// (a future outcome this package hasn't been updated for) fails
		// safe to the human-in-the-loop state rather than falling through
		// to a zero-value NextState, matching this codebase's "unknown
		// routes to a human, never auto-approved" default posture.
		return Advancement{
			NextState: StateNeedsHumanInvestigation,
			Plan:      &plan,
			Decision:  &decision,
			Reason:    "the autonomy gate returned an unrecognized outcome " + string(decision.Outcome),
		}
	}
}
