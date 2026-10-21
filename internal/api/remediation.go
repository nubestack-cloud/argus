package api

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"argus/internal/logging"
	"argus/internal/orchestrator"
	"argus/internal/remediation"
)

// planView is the API representation of one proposed remediation plan —
// shared by handleAnalyzeIncident's response (a freshly authored plan, not
// yet persisted when this is built) and the approvals queue
// (handleListApprovals, a remediation_recommendations row read back from
// the DB) so the two never drift into two different shapes for what is
// conceptually the same object. Summary is plain language ("Scale
// payments/checkout-worker to 4 replicas"), not a raw params dump — per
// this task's brief, ApprovalsPage.tsx renders Summary directly rather than
// interpreting Params itself.
type planView struct {
	ID              string          `json:"id"`
	ActionType      string          `json:"actionType"`
	TargetGVK       string          `json:"targetGvk"`
	TargetNamespace string          `json:"targetNamespace"`
	TargetName      string          `json:"targetName"`
	Params          json.RawMessage `json:"params"`
	Reversible      bool            `json:"reversible"`
	RiskLevel       string          `json:"riskLevel"`
	// EffectiveRiskLevel is internal/remediation.EffectiveRiskLevel's result
	// for this exact plan — the deterministic-floor-adjusted risk the GATE
	// actually enforced, as opposed to RiskLevel above, which is whatever the
	// model self-declared and is never overwritten (risk.go's own comment:
	// silently rewriting it would destroy the calibration signal that a class
	// of plans is under-classified). BACKLOG.md D11 #1: the approval queue
	// used to badge the DECLARED level, so a plan whose declared "low" was
	// overridden by the hard high-risk/irreversible floor showed a "low risk"
	// badge directly above gate text reading "risk=high and reversible=false"
	// — the one element an approver glances at was flatly wrong. Computed
	// here, at read time, from fields the row already carries (never
	// persisted, never recomputed against a DIFFERENT policy the way
	// GateOutcome/GateReason explicitly must not be — this is a pure function
	// of the plan's own shape, not of AutonomyPolicy, so recomputing it here
	// answers the exact same question EffectiveRiskLevel answered at gate
	// time, not a different one).
	EffectiveRiskLevel string `json:"effectiveRiskLevel"`
	Summary            string `json:"summary"`
	// GateOutcome/GateReason are internal/remediation.Evaluate's decision
	// for this exact plan, recorded once at proposal time — see migration
	// 000025's own comment on remediation_recommendations.gate_outcome for
	// why this is never recomputed against whatever policy happens to be
	// configured when a caller reads it back.
	GateOutcome string `json:"gateOutcome"`
	GateReason  string `json:"gateReason"`
	CreatedAt   string `json:"createdAt"`

	// Approval/Execution are additive, both nil until they actually happen —
	// populated only on the incident-detail read path (latestPlanViewForAnalysis
	// in analyze.go), not on the approval-queue's own listing (which only ever
	// shows AwaitingApproval incidents; a ScaleDeployment/RestartPod plan that
	// successfully commits to executing leaves that queue before a decision
	// could ever appear on it there — see approvals.go's own doc comment).
	// IncidentDetailPage's resolution-path panel is what actually needs these:
	// without them it has no way to say who approved a plan or what executing
	// it actually did, and had to fall back to a permanently-"not implemented"
	// stage even after real execution existed.
	Approval  *planApprovalView  `json:"approval,omitempty"`
	Execution *planExecutionView `json:"execution,omitempty"`
}

// planApprovalView is the most recent human decision recorded against a
// plan — remediation_approval_decisions' own shape, with the actor resolved
// to an email for display rather than a bare user id.
type planApprovalView struct {
	Verdict    string `json:"verdict"` // "approved" | "rejected"
	ActorEmail string `json:"actorEmail,omitempty"`
	Reason     string `json:"reason,omitempty"`
	CreatedAt  string `json:"createdAt"`
}

// planExecutionView is the most recent real-execution outcome recorded
// against a plan (internal/execution's recordExecutionOutcome)
// — nil for a plan that was never approved, that's still AwaitingApproval,
// or whose action type (OpenPR) never executes at all.
type planExecutionView struct {
	Outcome    string `json:"outcome"` // "succeeded" | "failed" | "unknown" (BACKLOG.md C8)
	Error      string `json:"error,omitempty"`
	ExecutedAt string `json:"executedAt"`
	// ID is needed because the undo is addressed by execution, not by plan: one
	// recommendation can have two executions (the change and its reversal), and
	// only the row knows which is which.
	ID string `json:"id"`
	// Rollback is what undoing this would do, in the words captured before the
	// change was made. Empty when the action type has no representable undo — a
	// workload restart cannot be un-restarted — which is why the control is absent
	// rather than disabled in that case: there is nothing to offer.
	Rollback string `json:"rollback,omitempty"`
	// RolledBackAt is set once this execution has been undone. Present so the UI
	// shows the history rather than an Undo button that would 409.
	RolledBackAt string `json:"rolledBackAt,omitempty"`
}

// latestApprovalDecisionView returns the most recent approval/rejection
// decision recorded against planID, or nil if none exists yet.
func latestApprovalDecisionView(ctx context.Context, tx pgx.Tx, planID string) (*planApprovalView, error) {
	var verdict string
	var actorEmail, reason *string
	var createdAt time.Time
	err := tx.QueryRow(ctx,
		`SELECT d.verdict, u.email, d.reason, d.created_at
		   FROM remediation_approval_decisions d
		   LEFT JOIN users u ON u.id = d.actor_id
		  WHERE d.recommendation_id = $1
		  ORDER BY d.created_at DESC LIMIT 1`, planID,
	).Scan(&verdict, &actorEmail, &reason, &createdAt)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return &planApprovalView{
		Verdict:    verdict,
		ActorEmail: deref(actorEmail),
		Reason:     deref(reason),
		CreatedAt:  formatRFC3339(createdAt),
	}, nil
}

// latestExecutionView returns the most recent real-execution outcome
// recorded against planID, or nil if this plan was never executed.
func latestExecutionView(ctx context.Context, tx pgx.Tx, planID string) (*planExecutionView, error) {
	var id, outcome string
	var execErr, rollbackDescription *string
	var executedAt time.Time
	var rolledBackAt *time.Time
	err := tx.QueryRow(ctx,
		`SELECT x.id, x.outcome, x.error, x.executed_at, x.rollback_description,
		        (SELECT u.executed_at FROM remediation_executions u WHERE u.id = x.rolled_back_by_execution_id)
		   FROM remediation_executions x
		  WHERE x.recommendation_id = $1
		  ORDER BY x.executed_at DESC LIMIT 1`, planID,
	).Scan(&id, &outcome, &execErr, &executedAt, &rollbackDescription, &rolledBackAt)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	v := &planExecutionView{
		ID:         id,
		Outcome:    outcome,
		Error:      deref(execErr),
		ExecutedAt: formatRFC3339(executedAt),
		Rollback:   deref(rollbackDescription),
	}
	if rolledBackAt != nil {
		v.RolledBackAt = formatRFC3339(*rolledBackAt)
	}
	return v, nil
}

// buildPlanView assembles a planView from a plan's already-marshaled
// fields — the one function both handleAnalyzeIncident (from an in-memory
// remediation.RemediationPlan, via orchestrator.MarshalPlanParams) and
// handleListApprovals (from a remediation_recommendations row's own
// already-jsonb params column) funnel through, so planSummary's
// plain-language rendering is defined exactly once.
func buildPlanView(id, actionType, targetGVK, targetNamespace, targetName string, params json.RawMessage, reversible bool, riskLevel, gateOutcome, gateReason, createdAt string) planView {
	return planView{
		ID:                 id,
		ActionType:         actionType,
		TargetGVK:          targetGVK,
		TargetNamespace:    targetNamespace,
		TargetName:         targetName,
		Params:             params,
		Reversible:         reversible,
		RiskLevel:          riskLevel,
		EffectiveRiskLevel: effectiveRiskLevelFor(actionType, targetGVK, targetNamespace, targetName, params, reversible, riskLevel),
		Summary:            planSummary(actionType, targetNamespace, targetName, params),
		GateOutcome:        gateOutcome,
		GateReason:         gateReason,
		CreatedAt:          createdAt,
	}
}

// effectiveRiskLevelFor recomputes internal/remediation.EffectiveRiskLevel —
// the SAME deterministic-floor function internal/remediation.Evaluate calls
// at gate time (gate.go) — from a plan's own already-persisted fields, purely
// so a caller can DISPLAY it (BACKLOG.md D11 #1). It deliberately does not
// consult AutonomyPolicy or confidence, because EffectiveRiskLevel doesn't
// either: it is a pure function of action type, target and the model's own
// declared level, so recomputing it here answers exactly the question the
// gate answered, never a policy-dependent one gate_outcome/gate_reason
// (pinned at proposal time, see planView's own doc comment) would be wrong to
// recompute.
//
// orchestrator.ReconstructPlan needs an incident/analysis id only to fill in
// fields EffectiveRiskLevel never reads — empty strings are fine here.
func effectiveRiskLevelFor(actionType, targetGVK, targetNamespace, targetName string, params json.RawMessage, reversible bool, riskLevel string) string {
	plan, err := orchestrator.ReconstructPlan("", "", actionType, targetGVK, targetNamespace, targetName, params, reversible, riskLevel)
	if err != nil {
		// A row whose own params don't unmarshal is a bug this queue must not
		// crash on. Falling back to the declared level is the honest response
		// to "we can't compute this" — it's no worse than what every caller
		// rendered before this field existed, never worse than the truth.
		logger.Warn("reconstructing the plan to compute its effective risk failed", logging.Err(err))
		return riskLevel
	}
	return string(remediation.EffectiveRiskLevel(plan))
}

// planSummary renders a plan in plain language for a human approver —
// lld/11-ui-design.md §6's "disabled-not-hidden... discoverability" spirit
// applied to plan display too: an approver should never have to read raw
// JSON params to understand what they're being asked to approve.
func planSummary(actionType, targetNamespace, targetName string, paramsJSON json.RawMessage) string {
	target := targetName
	if targetNamespace != "" {
		target = targetNamespace + "/" + targetName
	}

	var params map[string]any
	_ = json.Unmarshal(paramsJSON, &params) // best-effort; a params-less/malformed row still gets a reasonable fallback summary below

	switch remediation.ActionType(actionType) {
	case remediation.ActionScaleDeployment:
		if replicas, ok := params["replicas"]; ok {
			return fmt.Sprintf("Scale %s to %v replicas", target, replicas)
		}
		return fmt.Sprintf("Scale %s", target)
	case remediation.ActionRestartPod:
		return fmt.Sprintf("Restart %s", target)
	case remediation.ActionCordonNode:
		if v, ok := params["unschedulable"].(bool); ok && !v {
			return fmt.Sprintf("Uncordon %s", target)
		}
		return fmt.Sprintf("Cordon %s", target)
	case remediation.ActionDrainNode:
		return fmt.Sprintf("Drain %s", target)
	case remediation.ActionDeleteResource:
		// DeleteResourceParams is empty (deleteresource.go) — there is no
		// field to name, only the target. Before this case existed, a
		// DeleteResource plan fell all the way through to the generic
		// `default` branch below and rendered the raw action-type identifier
		// verbatim ("DeleteResource payments/orphaned-pod") as its own
		// plain-language summary — exactly the raw-enum-as-user-text bug
		// components.md's "never render a raw API identifier" rule bans,
		// and BACKLOG.md D11 #5's own example of this screen's boilerplate
		// problem. This says the same thing a human would.
		return fmt.Sprintf("Delete %s", target)
	case remediation.ActionPatchResourceLimits:
		// Every value the plan sets, named and spelled out, plus the
		// consequence the action's name hides (this rolls the workload's
		// pods). An approver deciding on a resource change needs to see the
		// numbers — "adjust resources" is not something anyone can
		// responsibly approve — and lld/11-ui-design.md's rule is that they
		// must not have to read raw params JSON to get them.
		container, _ := params["container"].(string)
		var changes []string
		for _, f := range []struct{ key, label string }{
			{"memoryLimit", "memory limit"},
			{"memoryRequest", "memory request"},
			{"cpuLimit", "CPU limit"},
			{"cpuRequest", "CPU request"},
		} {
			if v, ok := params[f.key].(string); ok && v != "" {
				changes = append(changes, fmt.Sprintf("%s to %s", f.label, v))
			}
		}
		if container == "" || len(changes) == 0 {
			// A malformed or empty params row: say what is known and nothing
			// more, rather than implying a change nobody can name.
			return fmt.Sprintf("Change container resource limits on %s", target)
		}
		return fmt.Sprintf("Set container %q on %s: %s (rolls the workload's pods)", container, target, strings.Join(changes, ", "))
	case remediation.ActionRevertContainerImage:
		// This summary cannot name the image, and saying so is the point rather
		// than a shortfall. The params a proposed plan carries are a container
		// name and nothing else (remediation.RevertContainerImageParams): the
		// image is resolved from the workload's own rollout history at the
		// moment of approval, because a value resolved at proposal time would be
		// stale by however long the plan sat in this queue — and because an
		// image ARGUS could have named earlier is an image something other than
		// the cluster chose. So the summary states the RULE that will be applied
		// ("the image from the previous revision") plus both consequences an
		// approver needs, and the concrete image appears in the audit record and
		// the signed plan once it exists.
		container, _ := params["container"].(string)
		if container == "" {
			return fmt.Sprintf("Revert a container on %s to the image from the workload's previous revision", target)
		}
		return fmt.Sprintf("Revert container %q on %s to the image from the workload's previous revision (resolved from the cluster's own rollout history when you approve; rolls the workload's pods and undoes whatever the newer image contained)", container, target)
	case remediation.ActionOpenPR:
		// A repository change is one or more whole files, so the summary names
		// the files rather than a field and a value. It deliberately does NOT
		// try to characterise WHAT changed inside them — that is the diff's
		// job, the approver is shown the diff before they approve, and a
		// one-line paraphrase of a multi-file patch is exactly the kind of
		// confident summary that would let someone approve without reading it.
		//
		// A legacy row (the retired filePath/fieldPath/newValue shape) is
		// summarised as such rather than rendered as an empty change: it is
		// still displayed, and approving it fails loudly in
		// orchestrator.UnmarshalPlanParams.
		files, _ := params["files"].([]any)
		var paths []string
		for _, f := range files {
			if m, ok := f.(map[string]any); ok {
				if p, ok := m["path"].(string); ok && p != "" {
					paths = append(paths, p)
				}
			}
		}
		switch {
		case len(paths) == 1:
			return fmt.Sprintf("Open a pull request changing %s (fixes %s)", paths[0], target)
		case len(paths) > 1:
			return fmt.Sprintf("Open a pull request changing %d files — %s (fixes %s)", len(paths), strings.Join(paths, ", "), target)
		case params["fieldPath"] != nil || params["filePath"] != nil:
			return fmt.Sprintf("Open a pull request against %s — proposed in a retired single-field form this build can no longer act on; re-analyse the incident", target)
		default:
			return fmt.Sprintf("Open a pull request against %s", target)
		}
	default:
		return fmt.Sprintf("%s %s", actionType, target)
	}
}
