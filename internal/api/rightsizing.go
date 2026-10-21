package api

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"argus/internal/agent/rightsizing"
	"argus/internal/authz"
	"argus/internal/logging"
	"argus/internal/orchestrator"
	"argus/internal/remediation"
	"k8s.io/apimachinery/pkg/api/resource"
)

// POST /api/v1/clusters/{id}/rightsizing/proposals (PROJECT.md PG8): turn one
// rightsizing row into a PatchResourceLimits plan awaiting approval. The
// browser names only the row (namespace, workload, container); the values
// come from the agent's own measurement, re-read here, so nothing a client
// sends sets a request. Only requests the container already has are changed —
// PatchResourceLimits never introduces one — and a memory request that would
// exceed the container's limit is left out rather than proposed.

type rightsizingProposalRequest struct {
	Namespace string `json:"namespace"`
	Kind      string `json:"kind"`
	Workload  string `json:"workload"`
	Container string `json:"container"`
}

type rightsizingProposalResponse struct {
	IncidentID string `json:"incidentId"`
	PlanID     string `json:"planId"`
	Outcome    string `json:"outcome"`
	Reason     string `json:"reason"`
}

var rightsizingTargetGVK = map[string]string{"Deployment": "apps/v1/Deployment", "StatefulSet": "apps/v1/StatefulSet"}

func (s *Server) handleRightsizingProposal(w http.ResponseWriter, r *http.Request, rc *requestContext) {
	ctx := r.Context()
	clusterID := r.PathValue("id")
	if !s.authorizeClusterScoped(w, r, rc, authz.CapRemediationExecInplace, clusterID) {
		return
	}
	var body rightsizingProposalRequest
	raw, _ := io.ReadAll(io.LimitReader(r.Body, 4096))
	if err := json.Unmarshal(raw, &body); err != nil || body.Namespace == "" || body.Workload == "" || body.Container == "" {
		writeProblem(w, http.StatusBadRequest, "https://argus.io/errors/validation", "Invalid proposal", "namespace, kind, workload and container are required")
		return
	}
	gvk, ok := rightsizingTargetGVK[body.Kind]
	if !ok {
		writeProblem(w, http.StatusUnprocessableEntity, "https://argus.io/errors/plan-invalid", "Not proposable",
			"a resource change can be proposed for a Deployment or StatefulSet; this row belongs to a "+body.Kind)
		return
	}
	if s.gw == nil || !s.gw.IsConnected(clusterID) {
		writeProblem(w, http.StatusServiceUnavailable, "https://argus.io/errors/cluster-disconnected", "Cluster not connected", "this cluster's agent is not connected")
		return
	}
	row, err := s.rightsizingRow(ctx, clusterID, body)
	if err != nil {
		writeProblem(w, http.StatusConflict, "https://argus.io/errors/invalid-state", "No recommendation", err.Error())
		return
	}
	params, statement, err := rightsizingParams(row)
	if err != nil {
		writeProblem(w, http.StatusConflict, "https://argus.io/errors/invalid-state", "Nothing to change", err.Error())
		return
	}
	plan := remediation.RemediationPlan{
		ActionType: remediation.ActionPatchResourceLimits, TargetGVK: gvk, TargetNamespace: body.Namespace, TargetName: body.Workload,
		Params: params, Reversible: true, RiskLevel: remediation.RiskMedium,
	}
	if err := plan.Validate(); err != nil {
		writeProblem(w, http.StatusUnprocessableEntity, "https://argus.io/errors/plan-invalid", "Proposal refused", err.Error())
		return
	}
	var tenantID string
	if err := rc.Tx.QueryRow(ctx, `SELECT tenant_id FROM clusters WHERE id = $1`, clusterID).Scan(&tenantID); err != nil {
		writeProblem(w, http.StatusNotFound, "https://argus.io/errors/not-found", "Cluster not found", "")
		return
	}
	incidentID, planID, decision, err := orchestrator.OpenRequestedChange(ctx, rc.Tx, tenantID, clusterID, orchestrator.RequestedChange{
		Reason: "RightsizingRequested", Statement: statement, Plan: plan,
	})
	if err != nil {
		logger.ErrorContext(ctx, "opening a rightsizing proposal failed", logging.ClusterID(clusterID), logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not record the proposal", "")
		return
	}
	writeJSON(w, http.StatusCreated, rightsizingProposalResponse{IncidentID: incidentID, PlanID: planID, Outcome: string(decision.Outcome), Reason: decision.Reason})
}

func (s *Server) rightsizingRow(ctx context.Context, clusterID string, body rightsizingProposalRequest) (rightsizing.Row, error) {
	callCtx, cancel := context.WithTimeout(ctx, inspectCallTimeout)
	defer cancel()
	args, _ := json.Marshal(map[string]string{"namespace": body.Namespace, "workload": body.Workload})
	raw, err := s.gw.CallTool(callCtx, clusterID, "get_rightsizing", args)
	if err != nil {
		return rightsizing.Row{}, fmt.Errorf("the agent could not measure this workload: %s", agentToolFailureDetail(err))
	}
	var res rightsizing.Result
	if err := json.Unmarshal(raw, &res); err != nil || !res.Available {
		return rightsizing.Row{}, fmt.Errorf("no measurement is available for %s/%s", body.Namespace, body.Workload)
	}
	for _, row := range res.Rows {
		if row.Kind == body.Kind && row.Workload == body.Workload && row.Container == body.Container {
			return row, nil
		}
	}
	return rightsizing.Row{}, fmt.Errorf("no measured container %q in %s %s/%s", body.Container, body.Kind, body.Namespace, body.Workload)
}

// rightsizingParams builds the change from a measured row: each request the
// container already has, set to the recommendation, when the two differ.
func rightsizingParams(row rightsizing.Row) (remediation.PatchResourceLimitsParams, string, error) {
	p := remediation.PatchResourceLimitsParams{Container: row.Container}
	if row.PodLevel {
		return p, "", fmt.Errorf("this pod is sized at pod level; a per-container change does not apply")
	}
	var parts []string
	if row.CPURequestMilli != nil && row.RecCPUMilli != nil && *row.RecCPUMilli != *row.CPURequestMilli {
		p.CPURequest = resource.NewMilliQuantity(*row.RecCPUMilli, resource.DecimalSI).String()
		parts = append(parts, fmt.Sprintf("CPU request %s → %s", resource.NewMilliQuantity(*row.CPURequestMilli, resource.DecimalSI), p.CPURequest))
	}
	if row.MemRequestBytes != nil && row.RecMemBytes != nil && *row.RecMemBytes != *row.MemRequestBytes &&
		(row.MemLimitBytes == nil || *row.RecMemBytes <= *row.MemLimitBytes) {
		p.MemoryRequest = resource.NewQuantity(*row.RecMemBytes, resource.BinarySI).String()
		parts = append(parts, fmt.Sprintf("memory request %s → %s", resource.NewQuantity(*row.MemRequestBytes, resource.BinarySI), p.MemoryRequest))
	}
	if len(parts) == 0 {
		return p, "", fmt.Errorf("the container's requests already match the recommendation, or it has none to change")
	}
	statement := fmt.Sprintf("Container %s in %s %s: measured over %s, p95 CPU %s and p95 memory %s (peak %s). Proposed: %s.",
		row.Container, row.Kind, row.Workload, "7 days", fmtMilli(row.CPUP95Milli), fmtBytes(row.MemP95Bytes), fmtBytes(row.MemPeakBytes), join(parts))
	return p, statement, nil
}

func fmtMilli(v *float64) string {
	if v == nil {
		return "unmeasured"
	}
	return fmt.Sprintf("%.0fm", *v)
}

func fmtBytes(v *float64) string {
	if v == nil {
		return "unmeasured"
	}
	return fmt.Sprintf("%.0fMi", *v/(1<<20))
}

func join(parts []string) string {
	out := ""
	for i, p := range parts {
		if i > 0 {
			out += "; "
		}
		out += p
	}
	return out
}
