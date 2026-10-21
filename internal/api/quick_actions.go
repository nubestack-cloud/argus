package api

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"argus/internal/authz"
	"argus/internal/logging"
	"argus/internal/orchestrator"
	"argus/internal/remediation"
)

// POST /api/v1/incidents/{id}/quick-actions (docs/CLUSTER_INSIGHT_SPECS.md
// CI-S15): a person asks for one of a closed set of GitOps "act now"
// requests — Argo CD refresh or Flux reconcile — on an object in the
// incident's own cluster. It becomes an ordinary AnnotateResource
// recommendation awaiting approval; nothing executes here. The model cannot
// reach this route.

var quickActionKinds = map[string]struct {
	gvk   string
	key   string
	value func() string
}{
	"argoRefresh":       {"argoproj.io/v1alpha1/Application", "argocd.argoproj.io/refresh", func() string { return "normal" }},
	"argoHardRefresh":   {"argoproj.io/v1alpha1/Application", "argocd.argoproj.io/refresh", func() string { return "hard" }},
	"fluxReconcileKs":   {"kustomize.toolkit.fluxcd.io/v1/Kustomization", "reconcile.fluxcd.io/requestedAt", quickActionTimestamp},
	"fluxReconcileHr":   {"helm.toolkit.fluxcd.io/v2/HelmRelease", "reconcile.fluxcd.io/requestedAt", quickActionTimestamp},
	"fluxReconcileGit":  {"source.toolkit.fluxcd.io/v1/GitRepository", "reconcile.fluxcd.io/requestedAt", quickActionTimestamp},
	"fluxReconcileHelm": {"source.toolkit.fluxcd.io/v1/HelmRepository", "reconcile.fluxcd.io/requestedAt", quickActionTimestamp},
	"fluxReconcileOci":  {"source.toolkit.fluxcd.io/v1beta2/OCIRepository", "reconcile.fluxcd.io/requestedAt", quickActionTimestamp},
}

func quickActionTimestamp() string { return time.Now().UTC().Format(time.RFC3339) }

func (s *Server) handleIncidentQuickAction(w http.ResponseWriter, r *http.Request, rc *requestContext) {
	ctx := r.Context()
	incidentID := r.PathValue("id")
	var body struct {
		Action    string `json:"action"`
		Namespace string `json:"namespace"`
		Name      string `json:"name"`
	}
	raw, _ := io.ReadAll(io.LimitReader(r.Body, 4096))
	if err := json.Unmarshal(raw, &body); err != nil || body.Name == "" || body.Namespace == "" {
		writeProblem(w, http.StatusBadRequest, "https://argus.io/errors/validation", "Invalid quick action", "action, namespace and name are required")
		return
	}
	qa, ok := quickActionKinds[body.Action]
	if !ok {
		writeProblem(w, http.StatusBadRequest, "https://argus.io/errors/validation", "Unknown quick action", "action must be one of the offered GitOps quick actions")
		return
	}
	var clusterID, tenantID string
	if err := rc.Tx.QueryRow(ctx, `SELECT cluster_id, tenant_id FROM incidents WHERE id = $1`, incidentID).Scan(&clusterID, &tenantID); err != nil {
		writeProblem(w, http.StatusNotFound, "https://argus.io/errors/not-found", "Incident not found", "")
		return
	}
	// The plan will be approved and executed through the in-place channel,
	// so requesting one needs that capability on this incident's cluster.
	if !s.authorizeClusterScoped(w, r, rc, authz.CapRemediationExecInplace, clusterID) {
		return
	}
	plan := remediation.RemediationPlan{
		ActionType: remediation.ActionAnnotateResource, TargetGVK: qa.gvk, TargetNamespace: body.Namespace, TargetName: body.Name,
		Params: remediation.AnnotateResourceParams{Key: qa.key, Value: qa.value()}, Reversible: true, RiskLevel: remediation.RiskLow,
	}
	if err := plan.Validate(); err != nil {
		writeProblem(w, http.StatusUnprocessableEntity, "https://argus.io/errors/plan-invalid", "Quick action refused", err.Error())
		return
	}
	planID, decision, err := orchestrator.RecordQuickAction(ctx, rc.Tx, tenantID, clusterID, incidentID, plan)
	if errors.Is(err, orchestrator.ErrNoAnalysis) {
		writeProblem(w, http.StatusConflict, "https://argus.io/errors/invalid-state", "Analyse first", err.Error())
		return
	}
	if err != nil {
		logger.ErrorContext(ctx, "recording a quick action failed", logging.IncidentID(incidentID), logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not record the quick action", "")
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"recommendationId": planID, "gateOutcome": decision.Outcome, "gateReason": decision.Reason})
}
