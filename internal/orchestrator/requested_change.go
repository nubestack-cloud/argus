package orchestrator

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"argus/internal/domain"
	"argus/internal/remediation"
	"argus/internal/timeline"
)

// RequestedChange is a change a person asks for from a measurement rather
// than from a fault (PROJECT.md PG8): today, a rightsizing recommendation.
// Plans are bound to an incident and an analysis, so it opens a low-severity
// incident of its own whose "analysis" is the measurement — confidence 1,
// no model involved — and attaches the plan through RecordQuickAction, which
// never lets it auto-approve. From there it is an ordinary plan: preflight,
// approval, execution, validation and undo.
type RequestedChange struct {
	Reason    string // opening reason, e.g. "RightsizingRequested"
	Statement string // what was measured and what the change does
	Plan      remediation.RemediationPlan
}

// OpenRequestedChange writes the incident, its measurement analysis and the
// plan in tx, and returns the incident and plan ids.
func OpenRequestedChange(ctx context.Context, tx pgx.Tx, tenantID, clusterID string, rc RequestedChange) (string, string, remediation.Decision, error) {
	now := time.Now().UTC()
	incidentID := domain.NewID(domain.PrefixIncident)
	objectKey := rc.Plan.TargetGVK + "|" + rc.Plan.TargetNamespace + "|" + rc.Plan.TargetName
	if _, err := tx.Exec(ctx,
		`INSERT INTO incidents (id, tenant_id, cluster_id, fingerprint, object_key, opening_reason, severity, state, first_seen, last_seen, occurrence_count)
		 VALUES ($1, $2, $3, $4, $5, $6, 'low', 'Detected', $7, $7, 1)`,
		incidentID, tenantID, clusterID, "requested:"+incidentID, objectKey, rc.Reason, now); err != nil {
		return "", "", remediation.Decision{}, fmt.Errorf("orchestrator: insert requested-change incident: %w", err)
	}
	if err := timeline.Record(ctx, tx, timeline.Event{
		TenantID: tenantID, ClusterID: clusterID, IncidentID: incidentID,
		Type:    timeline.EventIncidentOpened,
		Summary: rc.Reason + ": " + rc.Statement,
		Detail:  map[string]any{"gvk": rc.Plan.TargetGVK, "namespace": rc.Plan.TargetNamespace, "objectName": rc.Plan.TargetName, "reason": rc.Reason, "requested": true},
	}); err != nil {
		return "", "", remediation.Decision{}, fmt.Errorf("orchestrator: record requested-change opening: %w", err)
	}
	rootCause, _ := json.Marshal(map[string]any{"status": "complete", "statement": rc.Statement, "isFault": false})
	if _, err := tx.Exec(ctx,
		`INSERT INTO analyses (id, incident_id, tenant_id, cluster_id, prompt_version, model, causal_chain, ruled_out,
		   root_cause, confidence, iterations, duration_ms, tokens_billed_in, tokens_cache_read, tokens_out, cost_usd, created_at, triggered_by)
		 VALUES ($1, $2, $3, $4, 'measurement-v1', 'measured', '[]', '[]', $5, 1, 0, 0, 0, 0, 0, 0, $6, 'manual')`,
		domain.NewID(domain.PrefixAnalysis), incidentID, tenantID, clusterID, rootCause, now); err != nil {
		return "", "", remediation.Decision{}, fmt.Errorf("orchestrator: insert measurement analysis: %w", err)
	}
	planID, decision, err := RecordQuickAction(ctx, tx, tenantID, clusterID, incidentID, rc.Plan)
	if err != nil {
		return "", "", decision, err
	}
	return incidentID, planID, decision, nil
}
