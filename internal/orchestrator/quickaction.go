package orchestrator

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"argus/internal/domain"
	"argus/internal/remediation"
	"argus/internal/settings"
)

// ErrNoAnalysis is returned when an incident has no analysis to attach a
// quick action's recommendation to.
var ErrNoAnalysis = errors.New("the incident has no analysis yet; analyse it first")

// RecordQuickAction records a human-initiated, single-action remediation
// plan (docs/CLUSTER_INSIGHT_SPECS.md CI-S15 — a GitOps refresh/reconcile)
// as an ordinary recommendation on the incident's latest analysis, gated by
// the live autonomy policy exactly like a model-proposed plan, and moves
// the incident to AwaitingApproval so the normal approval card, signing and
// execution path take it from there. It never executes anything itself, and
// a nil confidence can never satisfy an auto-approve threshold, so the
// outcome is at best NeedsApproval.
func RecordQuickAction(ctx context.Context, tx pgx.Tx, tenantID, clusterID, incidentID string, plan remediation.RemediationPlan) (string, remediation.Decision, error) {
	var analysisID string
	err := tx.QueryRow(ctx, `SELECT id FROM analyses WHERE incident_id = $1 ORDER BY created_at DESC LIMIT 1`, incidentID).Scan(&analysisID)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", remediation.Decision{}, ErrNoAnalysis
	}
	if err != nil {
		return "", remediation.Decision{}, fmt.Errorf("orchestrator: latest analysis for incident %s: %w", incidentID, err)
	}
	cfg, err := settings.Resolve(ctx, tx)
	if err != nil {
		return "", remediation.Decision{}, fmt.Errorf("orchestrator: resolve autonomy policy: %w", err)
	}
	plan.IncidentID, plan.AnalysisID = incidentID, analysisID
	decision := remediation.Evaluate(plan, nil, ResolveAutonomyPolicy(cfg))
	if decision.Outcome == remediation.AutoApprove {
		decision.Outcome = remediation.NeedsApproval
		decision.Reason = "a person requested this action; it still needs an approval"
	}
	planID := domain.NewID(domain.PrefixPlan)
	if err := persistRecommendation(ctx, tx, planID, incidentID, tenantID, clusterID, analysisID, plan, decision, ""); err != nil {
		return "", decision, fmt.Errorf("orchestrator: persist quick-action recommendation: %w", err)
	}
	if decision.Outcome == remediation.Blocked {
		return planID, decision, nil
	}
	var state string
	if err := tx.QueryRow(ctx, `SELECT state FROM incidents WHERE id = $1`, incidentID).Scan(&state); err != nil {
		return "", decision, err
	}
	if state != StateAwaitingApproval {
		if !CanTransition(state, StateAwaitingApproval) {
			if err := SetState(ctx, tx, incidentID, StateInvestigating); err != nil {
				return "", decision, err
			}
		}
		if err := SetState(ctx, tx, incidentID, StateAwaitingApproval); err != nil {
			return "", decision, err
		}
	}
	return planID, decision, nil
}
