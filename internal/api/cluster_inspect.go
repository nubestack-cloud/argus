package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"argus/internal/audit"
	"argus/internal/authz"
	"argus/internal/logging"
	"argus/internal/settings"
)

// inspectableTools is the closed set of agent tools a person may call
// directly through POST /api/v1/clusters/{id}/inspect/{tool}
// (docs/CLUSTER_INSIGHT_SPECS.md CI-S6 and the views built on it). Every
// entry is a read-only tool served by the investigation identity, whose
// output ToolExecutor.Execute has already redacted at capture. A tool not in
// this map is refused here, before the gateway is asked anything —
// non-advertisement in the UI is not the control (argus-context lesson 5).
//
// audited marks tools whose output is free text the pattern redaction layer
// can only partly clean (logs), so every read is recorded in the audit
// trail with who asked for what.
var inspectableTools = map[string]struct{ audited bool }{
	"describe_resource":       {},
	"get_events":              {},
	"get_logs":                {audited: true},
	"get_owner_chain":         {},
	"get_gitops_ownership":    {},
	"get_neighborhood":        {},
	"trace_service_path":      {},
	"evaluate_network_policy": {},
	"get_subject_permissions": {},
	"diagnose_autoscaler":     {},
	"diagnose_rollout":        {},
	"explain_scheduling":      {},
	"get_drain_impact":        {},
	"get_karpenter_capacity":  {},
	"get_rightsizing":         {},
	"get_policy_findings":     {},
	"get_gitops_insight":      {},
	"get_helm_release_status": {},
	"get_upgrade_readiness":   {},
	"get_traffic":             {},
	"get_cost_summary":        {},
	"search_objects":          {},
	"get_posture_findings":    {},
	"list_certificates":       {},
	// PROJECT.md AD5/AD6: the cluster page's Helm, GitOps and Map tabs.
	"list_helm_releases":     {},
	"list_gitops_apps":       {},
	"get_namespace_topology": {},
	// The cluster page's Network policy tab.
	"get_network_policy_map": {},
}

// inspectCallTimeout bounds one inspect call. A little above the gateway's
// own per-call timeout so the gateway's clearer error wins when both fire.
const inspectCallTimeout = 20 * time.Second

// maxInspectArgsBytes bounds the request body; tool arguments are a handful
// of identifiers.
const maxInspectArgsBytes = 16 << 10

type inspectResponse struct {
	Tool string `json:"tool"`
	// ReceivedAt is when the hub got the agent's answer — the freshness
	// stamp the UI shows (CI-U10). Tools reading the object cache also carry
	// their own observedAt.
	ReceivedAt time.Time       `json:"receivedAt"`
	Result     json.RawMessage `json:"result"`
}

// handleClusterInspect forwards one allowlisted read-only tool call to a
// cluster's agent on behalf of a person.
func (s *Server) handleClusterInspect(w http.ResponseWriter, r *http.Request, rc *requestContext) {
	ctx := r.Context()
	clusterID := r.PathValue("id")
	tool := r.PathValue("tool")

	spec, ok := inspectableTools[tool]
	if !ok {
		writeProblem(w, http.StatusNotFound, "https://argus.io/errors/not-found", "Unknown inspection",
			fmt.Sprintf("%q is not an inspection this hub offers", tool))
		return
	}

	// Route-level requireCapability checked the capability without a scope;
	// the cluster comes from the URL, so it must be authorised against that
	// cluster before anything is sent to it (same reasoning as
	// handleGetCluster's comment).
	allowed, err := authz.HasCapabilityForCluster(ctx, rc.Tx, rc.Grants, authz.CapClusterInspect, clusterID)
	if err != nil {
		logger.ErrorContext(ctx, "resolving cluster-scoped capability failed", logging.ClusterID(clusterID), logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not resolve the scope of your permissions", "")
		return
	}
	if !allowed {
		s.recordCapabilityDenial(ctx, rc, authz.CapClusterInspect, clientIP(r))
		writeProblem(w, http.StatusForbidden, "https://argus.io/errors/scope-denied", "Missing required capability",
			fmt.Sprintf("inspecting cluster %s requires capability %q on that cluster", clusterID, authz.CapClusterInspect))
		return
	}

	args, err := readInspectArgs(r.Body)
	if err != nil {
		writeProblem(w, http.StatusBadRequest, "https://argus.io/errors/validation", "Invalid arguments", err.Error())
		return
	}

	if !s.gw.IsConnected(clusterID) {
		writeProblem(w, http.StatusServiceUnavailable, "https://argus.io/errors/cluster-disconnected", "Cluster not connected",
			"this cluster's agent is not connected, so live detail cannot be read right now")
		return
	}

	if tool == "get_posture_findings" {
		if cfg, err := settings.Resolve(ctx, rc.Tx); err == nil {
			args = cfg.WithPostureArgs(args)
		}
	}

	callCtx, cancel := context.WithTimeout(ctx, inspectCallTimeout)
	defer cancel()
	raw, err := s.gw.CallTool(callCtx, clusterID, tool, args)
	if spec.audited {
		s.auditInspection(r, rc, clusterID, tool, args, err)
	}
	if err != nil {
		// The agent answered, and the answer is that the object is not
		// there: a 404 the UI can treat as an ordinary empty state, not a
		// 502 that reads as the agent failing.
		if isAgentNotFound(err) {
			writeProblem(w, http.StatusNotFound, "https://argus.io/errors/object-not-found", "Not found", agentToolFailureDetail(err))
			return
		}
		logger.WarnContext(ctx, "cluster inspection failed", logging.ClusterID(clusterID), slog.String("tool", tool), logging.Err(err))
		writeProblem(w, http.StatusBadGateway, "https://argus.io/errors/agent-tool", "The agent could not answer",
			agentToolFailureDetail(err))
		return
	}
	writeJSON(w, http.StatusOK, inspectResponse{Tool: tool, ReceivedAt: time.Now().UTC(), Result: raw})
}

func readInspectArgs(body io.Reader) (json.RawMessage, error) {
	b, err := io.ReadAll(io.LimitReader(body, maxInspectArgsBytes+1))
	if err != nil {
		return nil, errors.New("could not read the request body")
	}
	if len(b) > maxInspectArgsBytes {
		return nil, errors.New("arguments too large")
	}
	if len(b) == 0 {
		return json.RawMessage(`{}`), nil
	}
	var obj map[string]any
	if err := json.Unmarshal(b, &obj); err != nil {
		return nil, errors.New("arguments must be a JSON object")
	}
	return json.RawMessage(b), nil
}

// auditInspection records one audited inspection. A successful read is
// recorded in the request's own transaction, so it commits with the answer.
// A failed one is recorded in a transaction of its own: the request
// transaction is rolled back on every error response (completeRequest), and
// an attempt to read logs is exactly as much the trail's business when it
// failed as when it succeeded.
func (s *Server) auditInspection(r *http.Request, rc *requestContext, clusterID, tool string, args json.RawMessage, callErr error) {
	capability := authz.CapClusterInspect
	var argMap map[string]any
	_ = json.Unmarshal(args, &argMap)
	cid := clusterID
	ev := audit.Event{
		TenantID:        rc.TenantID,
		ActorID:         &rc.UserID,
		ActorAuthMethod: "jwt",
		SourceIP:        clientIP(r),
		Capability:      &capability,
		ClusterID:       &cid,
		Outcome:         audit.OutcomeSuccess,
		Details:         map[string]any{"action": "cluster:inspect", "tool": tool, "args": argMap},
	}
	if callErr != nil {
		ev.Outcome = audit.OutcomeError
		ev.Details["error"] = agentToolFailureDetail(callErr)
		s.writeAuditEvent(r.Context(), ev)
		return
	}
	if err := audit.RecordEvent(r.Context(), rc.Tx, ev); err != nil {
		logger.ErrorContext(r.Context(), "recording a cluster inspection in the audit log failed", logging.Err(err))
	}
}
