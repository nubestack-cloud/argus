package execution

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"argus/internal/llm"
	"argus/internal/logging"
	"argus/internal/orchestrator"
	"argus/internal/remediation"
)

// PrepMode says whether a preparation will go on to mutate the cluster.
//
// It exists for exactly one reason, and it is a sharp one:
// authz.GuardrailConfirmationIssuer.Redeem is SINGLE-USE and burns its token
// before it checks anything, so a read-only preflight that redeemed the
// operator's confirmation would leave their subsequent real approval refused by
// the very guardrail they had just confirmed — an invisible failure with a
// confusing message. Making the mode explicit means that cannot happen by
// forgetting to zero a struct field at one call site.
type PrepMode int

const (
	// PrepForExecution is the real thing: guardrail confirmations are redeemed
	// and the caller goes on to commit and mutate.
	PrepForExecution PrepMode = iota
	// PrepForPreflight prepares and rehearses only. Nothing is redeemed,
	// nothing is committed, and the caller must not proceed to execution.
	PrepForPreflight
)

func (m PrepMode) redeemsGuardrails() bool { return m == PrepForExecution }

// PlanPrep is everything resolved, checked, captured and signed for one plan —
// the whole of approval up to but NOT including the irreversible commit.
type PlanPrep struct {
	Tool            string
	TargetGVK       string
	TargetNamespace string
	TargetName      string
	ResourceVersion string
	// LiveObject is the complete pre-change object, kept for BACKLOG.md F13's
	// diff. Free: FetchPreconditionWithObject already read it.
	LiveObject json.RawMessage
	Content    remediation.PlanContent
	Signed     remediation.SignedPlan
	Rollback   *remediation.CompensatingAction
	// ForwardApplied is the scalar value this change SETS, empty for action types
	// where that is not a single value. Recorded so a later undo can refuse when
	// the field has moved since — the analogue of the pull-request path's
	// expectedCurrentValue, and the difference between an undo that restores what
	// we changed and one that discards somebody else's change.
	ForwardApplied string
	// Attestation is the dry-run gate's result (F12). Always populated — a
	// preparation that could not be rehearsed returns an error instead, so no
	// caller can proceed on an unattested plan by forgetting to check.
	Attestation            dryRunAttestation
	ConfirmedScaleFromZero bool
	ConfirmedGitOpsManaged bool
	DigestWarning          string
	// BlockedBy is the guardrail refusals a real approval would hit, collected
	// only in PrepForPreflight. Always empty for PrepForExecution, where such a
	// refusal is returned as an error instead.
	BlockedBy []string
}

// ErrRiskFloorRecheckRefused is the sentinel behind PreparePlan's live
// tier=data / PersistentVolumeClaim risk-floor recheck below — BUGS.md 101,
// the same class BUGS.md 95 already fixed for four sibling PreparePlan
// refusals: this is a pre-flight rejection, before anything is signed, sent
// to the agent, or changed on the cluster, so it gets its own problem type
// mapped to 409 rather than falling into the generic "could not execute this
// remediation" 502 that a disconnected cluster or a signing failure produce.
// One sentinel for both the tier=data and the PersistentVolumeClaim case —
// unlike ErrScaleBoundRefused/ErrResourceLimitsBoundRefused, which stay
// distinct because they come from different functions, these two share the
// exact same return statement (only liveFloorReason differs), so a second
// sentinel here would distinguish nothing a caller could act on differently.
// No confirm-and-retry override, same reasoning as BUGS.md 95's four: the
// gate's decision no longer reflects reality, and only re-analysis — not
// confirming past a stale evaluation — produces an honest one.
var ErrRiskFloorRecheckRefused = errors.New("refusing a plan whose real target carries a higher live-state risk floor than it was evaluated against")

// ErrNamespaceProtectedRefused is the sentinel behind PreparePlan's
// argus.io/protected namespace guardrail below — BUGS.md 101. Same
// pre-flight-rejection reasoning as ErrRiskFloorRecheckRefused right above:
// nothing has been signed, sent, or changed yet, so 409 is the honest
// status, not the generic 502. This is DESIGN.md §9.3's `forbidden` risk
// tier, framed there as applying "even to a super-admin" — there is no
// confirmation that ever waives it, unlike ErrScaleFromZeroRefused/
// ErrGitOpsManagedRefused, so it is dispatched with a plain writeProblem,
// never writeGuardrailRefusal's confirmation-token mechanism.
var ErrNamespaceProtectedRefused = errors.New("refusing an action against a namespace marked argus.io/protected")

// checkLiveRiskFloorBound re-derives §9.3's tier=data / PersistentVolumeClaim
// risk-floor modifiers against the REAL live target (labels and pod-template
// volumes an authored RemediationPlan never carries) and refuses if either
// modifier now floors the risk above what the plan was originally evaluated
// against. Split out to a pure function, taking already-decoded live values
// rather than reading them itself, so a unit test can assert the sentinel
// directly without PreparePlan's DB/cluster/gateway context — see
// TestCheckLiveRiskFloorBoundWrapsItsSentinel.
func checkLiveRiskFloorBound(labels map[string]string, volumes []map[string]any, targetGVK, targetNamespace, targetName string, originalFloor remediation.RiskLevel) error {
	var liveFloorReason string
	switch {
	case remediation.DataTierRaisesFloor(labels):
		liveFloorReason = "is labelled tier=data"
	case remediation.VolumeMountedRaisesFloor(volumes):
		liveFloorReason = "mounts a PersistentVolumeClaim"
	}
	if liveFloorReason == "" || !remediation.HigherRisk(remediation.RiskHigh, originalFloor) {
		return nil
	}
	return fmt.Errorf("%w: the real target %s %s/%s %s, which carries a minimum risk floor of %q — higher than what this plan was evaluated against (%s). Re-analyze this incident so the gate can decide against the real target",
		ErrRiskFloorRecheckRefused, targetGVK, targetNamespace, targetName, liveFloorReason, remediation.RiskHigh, originalFloor)
}

// checkNamespaceNotProtected refuses when the target namespace carries
// DESIGN.md §9.3's argus.io/protected annotation. Same testability split as
// checkLiveRiskFloorBound just above — see
// TestCheckNamespaceNotProtectedWrapsItsSentinel.
func checkNamespaceNotProtected(annotations map[string]string, targetNamespace string) error {
	if !remediation.NamespaceIsProtected(annotations) {
		return nil
	}
	return fmt.Errorf("%w: namespace %q is marked argus.io/protected — this action is never permitted against it, regardless of approval or policy",
		ErrNamespaceProtectedRefused, targetNamespace)
}

// PreparePlan resolves the real target, re-checks the risk floor against it,
// reads a fresh precondition, applies every per-action guardrail, captures the
// rollback from live state, signs the plan, and rehearses it against the
// cluster.
//
// Extracted from ExecuteApprovedPlan so the read-only preflight (F13) and the
// real execution share one implementation rather than two that drift. That
// sharing is the point: a diff shown to an approver has to be a diff of the
// change that will actually be sent, and a preflight built from a parallel copy
// of this logic would be a diff of something adjacent to it.
//
// Everything here is non-committing. The single destructive step is guardrail
// token redemption, which PrepMode gates.
func (s *Executor) PreparePlan(
	ctx context.Context, scope Scope,
	incidentID, planID, clusterID string,
	plan remediation.RemediationPlan,
	overrides Overrides,
	mode PrepMode,
) (PlanPrep, error) {
	tool, ok := ToolForAction(plan.ActionType)
	if !ok {
		// Should not be reachable — handleApproveIncident only calls this
		// for ScaleDeployment/RestartPod/PatchResourceLimits/
		// RevertContainerImage (see its own dispatch).
		return PlanPrep{}, fmt.Errorf("action type %q has no execution path", plan.ActionType)
	}

	targetGVK, targetNamespace, targetName := plan.TargetGVK, plan.TargetNamespace, plan.TargetName
	if plan.ActionType == remediation.ActionRestartPod ||
		plan.ActionType == remediation.ActionPatchResourceLimits ||
		plan.ActionType == remediation.ActionRevertContainerImage {
		// All three act on a pod template, so all three must be applied to the
		// workload
		// that owns the template rather than to whatever object the finding
		// happened to name — for an OOMKilled or CrashLooping container that is
		// the Pod, and
		// patching a Pod's resources or image in place would be reverted by its
		// controller on the next reconcile even where the API server allowed
		// it at all.
		var err error
		targetGVK, targetNamespace, targetName, err = s.resolvePodTemplateTarget(ctx, clusterID, plan.TargetGVK, plan.TargetNamespace, plan.TargetName)
		if err != nil {
			return PlanPrep{}, fmt.Errorf("resolve pod template target: %w", err)
		}
	}

	// Re-derive the risk floor against the RESOLVED target, and refuse if it
	// rose — WORKLOG §97's finding G3.
	//
	// remediation.RiskFloorFor is keyed on Kind and namespace, both of which
	// this function may just have changed: a RestartPod/PatchResourceLimits/
	// RevertContainerImage plan is authored against the finding's object (often
	// a Pod) but resolved above to the workload that owns its template. The
	// gate that approved this plan evaluated the floor for the PRE-resolution
	// target — a Pod is never in statefulTargetKinds, so a plan against a Pod
	// owned by a StatefulSet was gated at whatever floor a bare "RestartPod"
	// implies, not DESIGN.md §9.3's higher StatefulSet floor. Purely cosmetic
	// while every execution needs a human anyway; it stops being cosmetic the
	// day AutoApprove may reach Executing unattended, which is exactly why this
	// is fixed now rather than deferred alongside that work.
	//
	// Refused outright, with no override, because this is not a decision an
	// operator can meaningfully confirm in the moment: the recorded Decision
	// was made against a floor that turned out to be wrong, so re-approving
	// after a fresh, correct evaluation — not confirming past a stale one — is
	// the only honest path forward.
	resolvedFloor := remediation.RiskFloorFor(remediation.RemediationPlan{
		ActionType: plan.ActionType, TargetGVK: targetGVK, TargetNamespace: targetNamespace,
	})
	originalFloor := remediation.RiskFloorFor(plan)
	if remediation.HigherRisk(resolvedFloor, originalFloor) {
		return PlanPrep{}, fmt.Errorf(
			"the real target %s %s/%s carries a higher risk floor (%s) than this plan was evaluated against (%s) — its actual owner was not known until now. Re-analyze this incident so the gate can decide against the real target",
			targetGVK, targetNamespace, targetName, resolvedFloor, originalFloor)
	}

	// CreateResource's target does not exist yet — there is no live object
	// to fetch a resourceVersion precondition from, and confirming ABSENCE
	// (rather than reading a live value) IS this action type's precondition.
	// See confirmTargetAbsentForCreate's own doc comment for exactly what
	// that confirms and what it structurally cannot. Every check below that
	// depends on a live object existing (the tier=data/PVC risk-floor
	// recheck) is therefore skipped for this action type rather than run
	// against data that does not exist — there is nothing yet for either
	// modifier to be true OF.
	var resourceVersion string
	var spec map[string]any
	var liveObject json.RawMessage
	var err error
	if plan.ActionType == remediation.ActionCreateResource {
		if err := s.confirmTargetAbsentForCreate(ctx, clusterID, targetGVK, targetNamespace, targetName); err != nil {
			return PlanPrep{}, err
		}
	} else {
		resourceVersion, spec, liveObject, err = s.FetchPreconditionWithObject(ctx, clusterID, targetGVK, targetNamespace, targetName)
		if err != nil {
			return PlanPrep{}, fmt.Errorf("fetch precondition: %w", err)
		}

		// §9.3's three remaining risk modifiers (BACKLOG.md R4): a
		// RemediationPlan carries a GVK/namespace/name only, never a target's
		// own labels, its pod template's volumes, or its namespace's own
		// annotations, so RiskFloorFor (evaluated at analysis time, before any
		// live object existed to read) cannot see any of them. This is the one
		// place that just fetched the live object and can — same reasoning as
		// the resolvedFloor/originalFloor recheck just above, and placed
		// immediately after it for the same reason: before anything is signed
		// or mutated.
		var liveMeta struct {
			Metadata struct {
				Labels map[string]string `json:"labels"`
			} `json:"metadata"`
			Spec struct {
				Template struct {
					Spec struct {
						Volumes []map[string]any `json:"volumes"`
					} `json:"spec"`
				} `json:"template"`
			} `json:"spec"`
		}
		if err := json.Unmarshal(liveObject, &liveMeta); err != nil {
			return PlanPrep{}, fmt.Errorf("decode live target metadata: %w", err)
		}
		// tier=data, and a pod template mounting a PersistentVolumeClaim (DESIGN.md
		// §9.3; the PVC case is PVC-014's own concrete finding — see
		// VolumeMountedRaisesFloor's doc comment) both floor at a minimum of
		// RiskHigh. Unconditional, like the resolvedFloor/originalFloor check
		// above and unlike the GitOps-precedence check below: this is the same
		// "the gate's decision no longer reflects reality" situation, not a
		// preview-vs-real distinction, so there is nothing for PrepForPreflight
		// to usefully downgrade to advice — a stale gate decision isn't something
		// a reviewer can confirm past, only re-analysis produces an honest one.
		//
		// checkLiveRiskFloorBound (below) is a pure function purely so
		// TestCheckLiveRiskFloorBoundWrapsItsSentinel can assert the sentinel
		// directly, the same testability reason checkResourceLimitsBound is
		// split from checkResourceLimitsBoundRules.
		if err := checkLiveRiskFloorBound(liveMeta.Metadata.Labels, liveMeta.Spec.Template.Spec.Volumes, targetGVK, targetNamespace, targetName, originalFloor); err != nil {
			return PlanPrep{}, err
		}
	}

	// argus.io/protected on the target's NAMESPACE -> forbidden (DESIGN.md
	// §9.3), an absolute guardrail that "applies even to a super-admin"
	// (DESIGN.md's own framing of this class of check) — so unlike GitOps
	// precedence below, it is never downgraded to advice even in
	// PrepForPreflight: a preview must refuse too, not merely warn, or the
	// preview screen would be the one place this guardrail doesn't apply.
	_, _, nsLive, err := s.FetchPreconditionWithObject(ctx, clusterID, "v1/Namespace", "", targetNamespace)
	if err != nil {
		return PlanPrep{}, fmt.Errorf("fetch target namespace %q to check the argus.io/protected guardrail: %w", targetNamespace, err)
	}
	var nsMeta struct {
		Metadata struct {
			Annotations map[string]string `json:"annotations"`
		} `json:"metadata"`
	}
	if err := json.Unmarshal(nsLive, &nsMeta); err != nil {
		return PlanPrep{}, fmt.Errorf("decode target namespace metadata: %w", err)
	}
	// checkNamespaceNotProtected (below) is a pure function for the same
	// testability reason as checkLiveRiskFloorBound just above.
	if err := checkNamespaceNotProtected(nsMeta.Metadata.Annotations, targetNamespace); err != nil {
		return PlanPrep{}, err
	}

	// The undo, and what the forward change applied. Declared here because the
	// per-action blocks below fill them in and every one of them needs the live
	// object read just above: a compensating action is only knowable before the
	// mutation, which is what makes its capture point non-negotiable.
	var rollback *remediation.CompensatingAction
	var forwardApplied string

	// blockedBy collects guardrail refusals that a real approval would fail on.
	// In PrepForExecution it stays empty — those refusals return immediately, as
	// they always have. In PrepForPreflight they are downgraded to advice, so a
	// reviewer can SEE the change and be told what confirming it will also
	// require. Without that downgrade the preflight would refuse for every
	// GitOps-managed object, which is the population whose diff matters most.
	var blockedBy []string

	// Hoisted to function scope (rather than declared inside the
	// ScaleDeployment-only block below) because recordExecutingTransition
	// needs the REDEEMED value, not the raw request boolean, for the audit
	// trail — see that function's own comment on why the distinction matters.
	// false unless the ScaleDeployment branch below actually redeems a token.
	var confirmedScaleFromZero bool
	// digestWarning is set only by the RevertContainerImage branch below
	// (WORKLOG §97 G4) — non-empty when the resolved image is a mutable tag
	// rather than a content digest, surfaced in both the audit trail and the
	// success response so the approver sees it even though it never blocks
	// execution.
	var digestWarning string

	if plan.ActionType == remediation.ActionScaleDeployment {
		// A CHECKED assertion, where this used to be `params, _ :=`. The
		// requested count is now load-bearing for a safety refusal, and the
		// zero value a failed assertion yields would read as "scale to 0" —
		// which both checks below wave through as harmless, silently disabling
		// the guardrail. orchestrator.UnmarshalPlanParams guarantees this type
		// for a ScaleDeployment row, so this branch is unreachable today; it
		// exists because "unreachable" combined with "turns off a guardrail if
		// ever reached" is the wrong pair of properties to leave lying around.
		params, ok := plan.Params.(remediation.ScaleDeploymentParams)
		if !ok {
			return PlanPrep{}, fmt.Errorf("plan %s is a ScaleDeployment but its params are %T, not ScaleDeploymentParams — refusing to execute a scale whose requested replica count cannot be read", planID, plan.Params)
		}
		if err := checkScaleBound(spec, params.Replicas); err != nil {
			return PlanPrep{}, err
		}
		// Ordered after the sanity bound deliberately: an absurd count is a
		// plan-authoring bug and should be reported as one even on a workload
		// that happens to sit at zero, and — more importantly — this ordering
		// is what makes confirmScaleFromZero an override of ONE specific
		// guardrail rather than a blanket "execute it anyway" flag. A confirmed
		// 0->500 is still refused by the line above.
		// The boolean alone no longer proves intent (WORKLOG §97 G5) — it must be
		// paired with a token this same refusal minted for this same plan. A
		// true with no matching token is treated exactly like false: the
		// guardrail's own default, refuse.
		confirmedScaleFromZero = mode.redeemsGuardrails() && overrides.ScaleFromZero &&
			s.guardrailTokens.Redeem(overrides.Token, planID, GuardrailScaleFromZero)
		if err := checkScaleFromZero(spec, params.Replicas, confirmedScaleFromZero); err != nil {
			if mode == PrepForExecution {
				return PlanPrep{}, err
			}
			blockedBy = append(blockedBy, err.Error())
		}

		// The undo, captured here for the same reason the other two action types
		// capture theirs: the pre-change replica count is only knowable before the
		// change. ScaleDeployment has been "reversible in principle" since the
		// beginning and nothing ever wrote down what to reverse it to, which made
		// the most common and most obviously undoable action the one with no undo.
		//
		// forwardApplied is what the change SETS, and it is what makes replaying
		// this safe later: an undo derived from before the forward change must not
		// be applied once someone else has moved the same field. See
		// remediation_executions.forward_applied_value (migration 000050).
		if live, ok := liveReplicaCount(spec); ok {
			rollback, err = captureRollback(rollbackForScale(live))
			if err != nil {
				return PlanPrep{}, err
			}
			forwardApplied = strconv.Itoa(params.Replicas)
		}
	}

	// CordonNode (PROJECT.md PG15) is its own undo: the node's schedulability
	// as it is now, read before the change. A DrainNode has none — evicted
	// pods are recreated elsewhere, not put back — and Validate already
	// refuses one that claims otherwise.
	if plan.ActionType == remediation.ActionCordonNode {
		params, ok := plan.Params.(remediation.CordonNodeParams)
		if !ok {
			return PlanPrep{}, fmt.Errorf("plan %s is a CordonNode but its params are %T, not CordonNodeParams", planID, plan.Params)
		}
		live, _ := spec["unschedulable"].(bool)
		if live == params.Unschedulable {
			return PlanPrep{}, fmt.Errorf("node %s is already %s; there is nothing to change", targetName, map[bool]string{true: "cordoned", false: "schedulable"}[live])
		}
		rollback, err = captureRollback(rollbackForCordon(live))
		if err != nil {
			return PlanPrep{}, err
		}
		forwardApplied = strconv.FormatBool(params.Unschedulable)
	}
	if plan.ActionType == remediation.ActionDrainNode {
		if _, ok := plan.Params.(remediation.DrainNodeParams); !ok {
			return PlanPrep{}, fmt.Errorf("plan %s is a DrainNode but its params are %T, not DrainNodeParams", planID, plan.Params)
		}
	}

	// GitOps precedence (§10.1), applied to EVERY action type rather than one.
	//
	// Placed after the per-action guardrails and before anything is signed, so a
	// refusal costs nothing and mutates nothing.
	confirmedGitOpsManaged := mode.redeemsGuardrails() && overrides.GitOpsManaged &&
		s.guardrailTokens.Redeem(overrides.Token, planID, GuardrailGitOpsManaged)
	// BACKLOG F11: the allowlist now comes from the declared table in
	// internal/remediation, and an undeclared action type is an ERROR rather than an
	// empty list. That distinction is the whole point — an empty list made
	// fieldContentionDetail return "", so a new action type silently got no warning
	// that a controller owned the field it was about to write.
	//
	// Logged and passed on as empty rather than failing the request: the contention
	// detail is advisory (every other gate still applies), so refusing an otherwise
	// valid remediation over a missing table entry would be a worse outcome than
	// proceeding with a loud log line. The test in internal/remediation is what
	// stops this branch being reachable in the first place.
	plannedPaths, pathsErr := remediation.PlannedFieldPaths(plan)
	if pathsErr != nil {
		logger.ErrorContext(ctx, "cannot determine the field paths for this plan, so the field-contention check is skipped: a missing entry in internal/remediation/fieldpaths.go, not a cluster problem",
			slog.String("action_type", string(plan.ActionType)), logging.Err(pathsErr))
	}
	// CreateResource is skipped here entirely, rather than let it reach
	// checkGitOpsPrecedence and be refused for a reason that would read as
	// nonsensical to an approver: this target does not exist yet, so
	// resolveOwnership's own tool call (get_gitops_ownership, which itself
	// needs to Get the object first) can only ever answer "could not
	// determine" for it — every CreateResource plan would then require
	// confirmGitOpsManaged:true unconditionally, for a guardrail whose
	// entire premise ("this object is owned by a controller that will
	// revert your patch on the next reconcile") presupposes an object that
	// already exists to be reconciled. A future sync that ALSO wants to
	// create this same object is a distinct, real conflict this action does
	// not check for today — a known, stated gap, not one silently assumed
	// away: the closest defence against it is confirmTargetAbsentForCreate's
	// own existence check immediately before this plan is signed, and the
	// agent's own Get-before-Create immediately before it executes.
	if plan.ActionType != remediation.ActionCreateResource {
		if err := s.checkGitOpsPrecedence(ctx, scope, incidentID, clusterID, targetGVK, targetNamespace, targetName, confirmedGitOpsManaged,
			liveObject, plannedPaths); err != nil {
			if mode == PrepForExecution {
				return PlanPrep{}, err
			}
			blockedBy = append(blockedBy, err.Error())
		}
	}

	// DeleteResource's own, stricter, non-overridable ownership re-check for
	// a PersistentVolumeClaim target — see ErrDeleteResourcePVCManagedRefused's
	// doc comment for why this cannot just be checkGitOpsPrecedence's
	// ordinary confirmGitOpsManaged path. Every other DeleteResource target
	// (Pod, Job) relies on checkGitOpsPrecedence alone, exactly like every
	// other action type — this extra call fires only for the one kind whose
	// allowlist entry depends on ownership genuinely being "none".
	if plan.ActionType == remediation.ActionDeleteResource && gvkKind(targetGVK) == "PersistentVolumeClaim" {
		if err := s.checkDeleteResourcePVCOwnership(ctx, clusterID, targetGVK, targetNamespace, targetName); err != nil {
			if mode == PrepForExecution {
				return PlanPrep{}, err
			}
			blockedBy = append(blockedBy, err.Error())
		}
	}

	// rollback is the compensating action captured from live state before
	// anything is mutated (§10.3). Nil for the two action types that have no
	// representable inverse today, and that is now a statement about RestartPod
	// alone: a rollout restart cannot be un-restarted, because the pods it
	// replaced are already gone. ScaleDeployment's inverse used to be listed here
	// as "computable but not captured", deferred on the grounds that capturing it
	// would change the signed content of a shipped action. It is captured now
	// (rollbackForScale, above) — that deferral had left the most obviously
	// undoable action as the one with no undo.

	// execParams, when non-nil, REPLACES the plan's own marshaled params in the
	// signed envelope. Exactly one action type sets it — RevertContainerImage,
	// whose executable params carry a field its proposable params deliberately
	// cannot (the image; see remediation.RevertContainerImageParams). Modeled
	// as an override rather than by giving every action type a resolve step,
	// because for every other action type "what was proposed" and "what gets
	// executed" must remain the same bytes, and a general hook would make that
	// a convention instead of a property.
	var execParams json.RawMessage

	if plan.ActionType == remediation.ActionPatchResourceLimits {
		// Same CHECKED assertion as the ScaleDeployment branch above, for the
		// same reason: every bound below is computed from these params, and a
		// zero-value PatchResourceLimitsParams would name no container and set
		// no field, which would sail through a check written to ignore unset
		// fields.
		params, ok := plan.Params.(remediation.PatchResourceLimitsParams)
		if !ok {
			return PlanPrep{}, fmt.Errorf("plan %s is a PatchResourceLimits but its params are %T, not PatchResourceLimitsParams — refusing to execute a resource change whose requested values cannot be read", planID, plan.Params)
		}
		// Kind check before anything else: on a Kind this pack cannot patch,
		// nothing that follows is worth computing.
		if !patchResourceLimitsKinds[gvkKind(targetGVK)] {
			return PlanPrep{}, fmt.Errorf("resource limits can only be patched on a Deployment or StatefulSet; the resolved target is %s %s/%s", targetGVK, targetNamespace, targetName)
		}
		// FAIL CLOSED on an unreadable live container. Every bound below and
		// the rollback itself are derived from these values, so "we could not
		// read them" can only mean "we do not execute" — there is no
		// conservative default for "what is this container's memory limit".
		live, err := liveContainerResources(spec, params.Container)
		if err != nil {
			return PlanPrep{}, err
		}
		if err := checkResourceLimitsBound(live, params, plan.RestoreVerified()); err != nil {
			return PlanPrep{}, err
		}
		// The forward value for a limits change is whichever single field it sets;
		// with more than one it is left empty rather than guessed, and the undo
		// then relies on the resourceVersion precondition alone. Honest about what
		// it can and cannot assert.
		forwardApplied = singleAppliedValue(params)
		if rollback, err = captureRollback(rollbackForResourceLimits(params.Container, live, params)); err != nil {
			return PlanPrep{}, err
		}
	}

	if plan.ActionType == remediation.ActionRevertContainerImage {
		// Same CHECKED assertion as the two branches above, and for a sharper
		// reason here: a zero-value RevertContainerImageParams names no
		// container, and the container name is what every lookup below keys on —
		// the live image, the historical images, the rollback. A silent zero
		// value would turn all of them into "container \"\"", which
		// findPodTemplateContainer refuses, but it would refuse with a message
		// blaming the workload for a bug in this file.
		params, ok := plan.Params.(remediation.RevertContainerImageParams)
		if !ok {
			return PlanPrep{}, fmt.Errorf("plan %s is a RevertContainerImage but its params are %T, not RevertContainerImageParams — refusing to execute a revert whose target container cannot be read", planID, plan.Params)
		}
		if execParams, rollback, digestWarning, err = s.resolveRevertContainerImage(ctx, clusterID, targetGVK, targetNamespace, targetName, spec, params); err != nil {
			return PlanPrep{}, err
		}
		// The image this revert will set, read back out of the params the resolver
		// produced rather than from the plan — a RevertContainerImage plan does
		// not name an image (the hub resolves it from rollout history and never
		// accepts one from a model), so the resolver's output is the only place
		// the forward value exists.
		var applied struct {
			Image string `json:"image"`
		}
		if err := json.Unmarshal(execParams, &applied); err == nil {
			forwardApplied = applied.Image
		}
	}

	if plan.ActionType == remediation.ActionPatchField {
		// Same CHECKED assertion as the three branches above: a zero-value
		// PatchFieldParams names no field, and this is the one action type
		// whose entire reach is defined by that field name (see
		// patchfield.go's own doc comment), so a silent zero value here would
		// not fail loudly — it would fail against "" and blame the object.
		params, ok := plan.Params.(remediation.PatchFieldParams)
		if !ok {
			return PlanPrep{}, fmt.Errorf("plan %s is a PatchField but its params are %T, not PatchFieldParams — refusing to execute a field patch whose target field cannot be read", planID, plan.Params)
		}

		// The independent, execution-time re-check of the (kind, path)
		// allowlist (BUGS.md 78, point 4). RemediationPlan.Validate already
		// ran this at proposal time, but approval and execution are not the
		// same moment: the entry's NeedsGrant may have been true then and
		// still be true now — every row has NeedsGrant == "" as of BACKLOG.md
		// "still open" #9 (2026-08-29), but the next row added to the
		// allowlist can reintroduce one before the chart catches up — and
		// that has to surface as this same clean, actionable refusal —
		// naming the missing RBAC grant — rather than as a cluster-side 403
		// discovered only after the approval was spent and the incident
		// moved to Executing.
		if _, err := remediation.PatchFieldPermitted(targetGVK, params.FieldPath); err != nil {
			return PlanPrep{}, err
		}

		current, found, err := readLiveFieldValue(liveObject, params.FieldPath)
		if err != nil {
			return PlanPrep{}, fmt.Errorf("read the live value of %s on %s %s/%s before patching: %w", params.FieldPath, targetGVK, targetNamespace, targetName, err)
		}
		if !found {
			// FAIL CLOSED, on purpose, mirroring PatchResourceLimits' "will
			// not introduce a field" rule (checkResourceLimitsBound) rather
			// than exploiting the agent's own ability to `add` a field whose
			// parent exists. The reason is the rollback, not the write: this
			// action's compensating action is itself a PatchField plan, and
			// PatchFieldParams.Validate refuses an empty NewValue because the
			// schema cannot express "delete this field" — so a field this
			// plan would ADD has no representable undo. Until this codebase
			// has a way to express that inverse, a plan against an unset
			// field is refused here rather than executed with no way back.
			return PlanPrep{}, fmt.Errorf("%s is not currently set on %s %s/%s, and PatchField cannot capture a rollback for introducing a new field (there is no way to express \"remove this field\" as a PatchField plan) — this needs a plan against a field that already has a value", params.FieldPath, targetGVK, targetNamespace, targetName)
		}
		// %v-rendered, matching internal/agent/patchfield.go's own
		// ExpectCurrent/no-op comparisons exactly, so a refusal made here
		// and the same comparison the agent independently repeats moments
		// later describe the same value the same way.
		currentValue := fmt.Sprintf("%v", current)
		if params.ExpectCurrent != "" && params.ExpectCurrent != currentValue {
			return PlanPrep{}, fmt.Errorf("this plan expected %s to be %q; the live value is %q — it was built against a different version of this object", params.FieldPath, params.ExpectCurrent, currentValue)
		}
		if currentValue == params.NewValue {
			return PlanPrep{}, fmt.Errorf("%s is already %q — refusing to execute a change with nothing in it", params.FieldPath, params.NewValue)
		}

		forwardApplied = params.NewValue
		if rollback, err = captureRollback(rollbackForPatchField(params.FieldPath, currentValue)); err != nil {
			return PlanPrep{}, err
		}
	}

	if plan.ActionType == remediation.ActionStructuredPatch {
		// Same CHECKED assertion as every branch above, for the same reason:
		// a zero-value StructuredPatchParams names no operations, and this
		// action type's entire reach is its Ops list.
		params, ok := plan.Params.(remediation.StructuredPatchParams)
		if !ok {
			return PlanPrep{}, fmt.Errorf("plan %s is a StructuredPatch but its params are %T, not StructuredPatchParams — refusing to execute a multi-field patch whose operations cannot be read", planID, plan.Params)
		}

		// The independent, execution-time re-check of the (kind, path)
		// allowlist, once per operation — PatchField's own re-check above,
		// extended across the list per this task's requirement 2: EVERY path
		// goes through the SAME PatchFieldPermitted check, and the first
		// operation this cluster cannot patch refuses the WHOLE plan, before
		// any live value is read and before anything is signed. There is no
		// partial acceptance: an approver never sees "5 of 6 fields will
		// change."
		for i, op := range params.Ops {
			if _, err := remediation.PatchFieldPermitted(targetGVK, op.FieldPath); err != nil {
				return PlanPrep{}, fmt.Errorf("operation %d of %d: %w", i+1, len(params.Ops), err)
			}
		}

		// Read every operation's live value out of the ONE live object this
		// function already fetched above (FetchPreconditionWithObject) —
		// this task's requirement 3's "batched read": readLiveFieldValue
		// walks the same in-memory liveObject bytes per operation, so N
		// operations cost zero additional cluster round trips, not N of
		// them. (This codebase's live-cluster reads for a single object are
		// already "fetch once, read many fields from the JSON" — there is no
		// separate multi-get primitive to call instead of this, because none
		// is needed: one GET already returned the whole object.)
		currentValues := make(map[string]string, len(params.Ops))
		for _, op := range params.Ops {
			current, found, err := readLiveFieldValue(liveObject, op.FieldPath)
			if err != nil {
				return PlanPrep{}, fmt.Errorf("read the live value of %s on %s %s/%s before patching: %w", op.FieldPath, targetGVK, targetNamespace, targetName, err)
			}
			if !found {
				// Same fail-closed reasoning as PatchField's own check above,
				// applied per operation: this plan's rollback is itself a
				// StructuredPatch plan, which cannot express "remove this
				// field" any more than PatchField can, so a plan that would
				// ADD a field has no representable undo.
				return PlanPrep{}, fmt.Errorf("%s is not currently set on %s %s/%s, and StructuredPatch cannot capture a rollback for introducing a new field (there is no way to express \"remove this field\" as a StructuredPatch operation) — this needs a plan against fields that already have a value", op.FieldPath, targetGVK, targetNamespace, targetName)
			}
			// %v-rendered, matching PatchField's own comparison exactly (and
			// internal/agent/patchfield.go's), so a refusal made here and the
			// agent's own re-read moments later describe the same value the
			// same way.
			currentValue := fmt.Sprintf("%v", current)
			if op.ExpectCurrent != "" && op.ExpectCurrent != currentValue {
				return PlanPrep{}, fmt.Errorf("this plan expected %s to be %q; the live value is %q — it was built against a different version of this object", op.FieldPath, op.ExpectCurrent, currentValue)
			}
			currentValues[remediation.NormaliseFieldPath(op.FieldPath)] = currentValue
		}

		// No-op refusal, per operation rather than only "if every operation is
		// a no-op": a plan mixing one stale (already-applied) field with real
		// changes is exactly as likely to be a stale plan as PatchField's own
		// single-field case, and this action type has no way to apply some of
		// an atomic patch while skipping the rest. Refusing on the FIRST no-op
		// operation is the same "reject in full, not partially" discipline
		// this task applies to the allowlist check above, extended to
		// staleness.
		for _, op := range params.Ops {
			if currentValues[remediation.NormaliseFieldPath(op.FieldPath)] == op.NewValue {
				return PlanPrep{}, fmt.Errorf("%s is already %q — refusing to execute a change with nothing in it", op.FieldPath, op.NewValue)
			}
		}

		// forwardApplied is left empty, the same honest choice
		// PatchResourceLimits' multi-field case makes (singleAppliedValue):
		// there is no single scalar this plan "sets", so an undo relies on the
		// resourceVersion precondition alone rather than a forward-value
		// staleness check.
		if rollback, err = captureRollback(rollbackForStructuredPatch(params.Ops, currentValues)); err != nil {
			return PlanPrep{}, err
		}
	}

	if plan.ActionType == remediation.ActionAnnotateResource || plan.ActionType == remediation.ActionLabelResource {
		mapName := "annotations"
		if plan.ActionType == remediation.ActionLabelResource {
			mapName = "labels"
		}
		key, value, err := annotateOrLabelKeyValue(plan)
		if err != nil {
			return PlanPrep{}, err
		}

		// The independent, execution-time re-check of the (kind, key) ->
		// allowed-value allowlist — same reasoning as PatchField's own
		// re-check above: approval and execution are not the same moment.
		if plan.ActionType == remediation.ActionAnnotateResource {
			if _, err := remediation.AnnotationPermitted(targetGVK, key, value); err != nil {
				return PlanPrep{}, err
			}
		} else {
			if _, err := remediation.LabelPermitted(targetGVK, key, value); err != nil {
				return PlanPrep{}, err
			}
		}

		current, found, err := readLiveMetadataValue(liveObject, mapName, key)
		if err != nil {
			return PlanPrep{}, fmt.Errorf("read the live %s %q of %s %s/%s before patching: %w", mapName, key, targetGVK, targetNamespace, targetName, err)
		}
		if found && current == value {
			return PlanPrep{}, fmt.Errorf("%s %q is already %q — refusing to execute a change with nothing in it", mapName, key, value)
		}

		forwardApplied = value
		// Unlike PatchField, a key this action would ADD (found == false) is
		// NOT refused here — adding a brand-new annotation/label is this
		// action's most common and most expected use, unlike PatchField's
		// correction-of-an-existing-value shape. There is simply no
		// representable rollback for that case (this schema cannot express
		// "remove this key", the same limitation PatchField's own doc
		// comment carries), so rollback stays nil, matching RestartPod's own
		// "no representable inverse" precedent — an operator can always
		// remove a label/annotation by hand, and every one of these actions
		// requires human approval anyway.
		if found {
			restore, restoreErr := captureRollback(rollbackForAnnotateOrLabel(plan.ActionType, key, current))
			if restoreErr != nil {
				return PlanPrep{}, restoreErr
			}
			rollback = restore
		}
	}

	if plan.ActionType == remediation.ActionDeleteResource {
		if _, ok := plan.Params.(remediation.DeleteResourceParams); !ok {
			return PlanPrep{}, fmt.Errorf("plan %s is a DeleteResource but its params are %T, not DeleteResourceParams", planID, plan.Params)
		}
		// The independent, execution-time re-check of the kind allowlist —
		// same reasoning as every other action type's re-check above.
		if _, err := remediation.DeleteResourcePermitted(targetGVK); err != nil {
			return PlanPrep{}, err
		}
		// No forwardApplied (there is no scalar value this plan "sets") and
		// no rollback: DESIGN.md §10.5 — deletion has no representable
		// inverse through this mechanism, and RemediationPlan.Validate has
		// already refused a plan that claims otherwise (plan.Reversible ==
		// true), so reaching here means the plan itself already agrees.
	}

	if plan.ActionType == remediation.ActionCreateResource {
		createParams, ok := plan.Params.(remediation.CreateResourceParams)
		if !ok {
			return PlanPrep{}, fmt.Errorf("plan %s is a CreateResource but its params are %T, not CreateResourceParams", planID, plan.Params)
		}
		// The independent, execution-time re-check of the kind allowlist —
		// same reasoning as every other action type's re-check above.
		if _, err := remediation.CreateResourcePermitted(targetGVK); err != nil {
			return PlanPrep{}, err
		}

		// PROJECT.md B161 — the follow-on named by B151's own honest limit.
		// B151's live defect was a CreateResource that wrote factually wrong
		// values to a real cluster object; the model's own Finding text
		// never cited those wrong values (it named the keys, never the
		// values), so the existing Finding-vs-tool-result corroboration
		// (internal/llm/value_agreement.go's checkValueAgreement, driven off
		// the causal chain) could not have caught it by construction. This
		// compares the EXECUTED PLAN's own Data directly against the hub's
		// own recorded evidence for this incident's investigation instead —
		// never the Finding text, never anything the model said about
		// either side. See llm.CheckPlanValueAgreement's own doc comment
		// for exactly how "evidence never mentions this key" (a legitimate
		// new value — the ordinary case for a create) is told apart from
		// "evidence contradicts this key" (refused below), and for why this
		// is wired for CreateResource only today.
		//
		// Best-effort on the read itself: ListMCPToolCalls only has content
		// for the cli backend (see its own doc comment) — an api-backend
		// investigation, or any transient DB error, yields "no evidence" and
		// this proceeds unchecked exactly as llm.CheckPlanValueAgreement's
		// own empty-evidence case does, rather than refusing an execution
		// because the ledger read failed rather than because the plan is
		// unsafe.
		evidence, evErr := s.listEvidence(ctx, clusterID, incidentID)
		if evErr != nil {
			logger.WarnContext(ctx, "could not read MCP tool-call evidence to check a CreateResource plan's values against it; proceeding unchecked",
				logging.IncidentID(incidentID), logging.ClusterID(clusterID),
				slog.String("target_gvk", targetGVK), slog.String("target_namespace", targetNamespace),
				slog.String("target_name", targetName), logging.Err(evErr))
		} else if contradicted, mismatches := llm.CheckPlanValueAgreement(createParams.Data, evidence); contradicted {
			return PlanPrep{}, fmt.Errorf("%w: %s", ErrCreateResourceContradictsEvidence, strings.Join(mismatches, "; "))
		}

		// No forwardApplied (there is no single scalar value this plan
		// "sets" — Data is a map) and no rollback: see
		// internal/remediation/createresource.go's own header comment for
		// why there is no representable inverse through this codebase's
		// reviewed delete mechanism (deleteResource's own allowlist does
		// not include ConfigMap), and RemediationPlan.Validate has already
		// refused a plan that claims Reversible=true, so reaching here means
		// the plan itself already agrees.
	}

	paramsJSON := execParams
	if paramsJSON == nil {
		paramsJSON, err = orchestrator.MarshalPlanParams(plan)
		if err != nil {
			return PlanPrep{}, fmt.Errorf("marshal plan params: %w", err)
		}
	}

	perClusterKey, err := remediation.DeriveClusterSigningKey(s.planSigningRootKey, clusterID)
	if err != nil {
		return PlanPrep{}, fmt.Errorf("derive signing key: %w", err)
	}

	expiresAt := time.Now().Add(signedPlanTTL)
	content := remediation.PlanContent{
		RecommendationID: planID,
		ActionType:       plan.ActionType,
		TargetGVK:        targetGVK,
		TargetNamespace:  targetNamespace,
		TargetName:       targetName,
		Params:           paramsJSON,
		Rollback:         rollback,
		ResourceVersion:  resourceVersion,
	}
	signed, err := remediation.Sign(content, clusterID, expiresAt, perClusterKey)
	if err != nil {
		return PlanPrep{}, fmt.Errorf("sign plan: %w", err)
	}

	// BACKLOG.md F12 — the machine-attested dry-run gate. Deliberately the
	// LAST thing before the irreversible commit below, so it validates the
	// fully-resolved plan (real target, fresh precondition, computed rollback,
	// guardrails already satisfied) rather than an earlier approximation of
	// it, and so a rejection commits nothing and mutates nothing. ("Commits
	// nothing" rather than "costs nothing" — see attestByDryRun on the one
	// third-party side effect a dry run can still have.)
	//
	// What this buys, concretely. Until now an admission webhook that refuses
	// the change — a resource quota, an OPA/Kyverno policy, a mutating webhook
	// that rejects the shape, a validation error the schema catches — was
	// discovered at EXECUTION time, which is after the approval was recorded
	// and after the incident had been moved to Executing. The operator's
	// reward for approving correctly was a Failed incident. Now the cluster
	// itself is asked first, and its refusal is reported back in its own
	// words with nothing spent.
	//
	// The distinction that makes this worth building rather than describing:
	// the assurance shown to an operator is the API SERVER's, obtained by
	// ARGUS. dot-ai's equivalent field is emitted by the model and only
	// type-checked for existence (WORKLOG §116), which means the assurance
	// grades itself. This one cannot.
	attestation, err := s.attestByDryRun(ctx, clusterID, tool, content, expiresAt, perClusterKey, mode)
	if err != nil {
		return PlanPrep{}, err
	}

	return PlanPrep{
		Tool: tool, TargetGVK: targetGVK, TargetNamespace: targetNamespace, TargetName: targetName,
		ResourceVersion: resourceVersion, LiveObject: liveObject,
		Content: content, Signed: signed, Rollback: rollback, ForwardApplied: forwardApplied, Attestation: attestation,
		ConfirmedScaleFromZero: confirmedScaleFromZero, ConfirmedGitOpsManaged: confirmedGitOpsManaged,
		DigestWarning: digestWarning, BlockedBy: blockedBy,
	}, nil
}

// Overrides bundles the operator's explicit intents so the execution path takes
// one value rather than a growing list of booleans whose call-site order can be
// transposed silently — the failure mode a second bool parameter would have
// introduced (two adjacent untyped bools mean a swap compiles and waives the
// wrong guardrail).
//
// Moved here from internal/api with PROJECT.md P23: it is an input to the
// safety pipeline, not a wire format. internal/api's approveIncidentRequest /
// rollbackRequest still decode the JSON and build one of these.
type Overrides struct {
	ScaleFromZero bool
	GitOpsManaged bool
	// Token is the confirmation token from the request body
	// (approveIncidentRequest.ConfirmationToken). Redeemed inside PreparePlan
	// against the specific guardrail it is about to honour — not decoded by the
	// handler, because at that point neither the planID nor which guardrail (if
	// any) will actually fire is known yet.
	Token string
}

// listEvidence calls the injected EvidenceLister, tolerating a nil one.
//
// Nil is the ordinary case for a unit test built as a bare &Executor{}, and it
// must behave like the already-tolerated "this investigation recorded no tool
// call content" case rather than panicking — see EvidenceLister's own doc
// comment and preparePlan's call site for why an unavailable ledger never
// refuses an otherwise safe plan.
func (s *Executor) listEvidence(ctx context.Context, clusterID, incidentID string) ([]llm.RecordedToolCall, error) {
	if s.evidence == nil {
		return nil, nil
	}
	return s.evidence(ctx, clusterID, incidentID)
}
