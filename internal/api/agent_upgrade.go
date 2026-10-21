package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"argus/internal/audit"
	"argus/internal/authz"
	"argus/internal/domain"
	"argus/internal/logging"
	"argus/internal/remediation"
	"argus/internal/tunnel"
)

// POST /api/v1/clusters/{id}/agent-upgrade (PROJECT.md AD10): a person moves
// a cluster's agent onto the image this hub was released with
// (ARGUS_AGENT_IMAGE, from the hub chart's agentImage). The hub signs the
// request with the cluster's plan key, pinned to the investigate Deployment's
// current resourceVersion, and sends it to the cluster's remediate connection;
// the agent re-checks the image against its own chart's repository. Nothing
// here is reachable from model output: UpgradeAgent is in no list the model
// is offered.

const (
	agentDeployment          = "argus-agent"
	agentRemediateDeployment = "argus-agent-remediate"
	agentUpgradeTTL          = 5 * time.Minute
)

type agentUpgradeResponse struct {
	Image string `json:"image"`
	From  string `json:"from,omitempty"`
}

func hubAgentImage() string { return strings.TrimSpace(os.Getenv("ARGUS_AGENT_IMAGE")) }

func (s *Server) handleAgentUpgrade(w http.ResponseWriter, r *http.Request, rc *requestContext) {
	ctx := r.Context()
	clusterID := r.PathValue("id")
	if !s.authorizeClusterScoped(w, r, rc, authz.CapAgentUpgrade, clusterID) {
		return
	}
	target := hubAgentImage()
	if target == "" {
		writeProblem(w, http.StatusConflict, "https://argus.io/errors/invalid-state", "No agent image configured",
			"this hub was not told which agent image it ships with (the hub chart's agentImage)")
		return
	}
	var raw json.RawMessage
	err := rc.Tx.QueryRow(ctx, `SELECT facts FROM cluster_facts WHERE cluster_id = $1`, clusterID).Scan(&raw)
	if errors.Is(err, pgx.ErrNoRows) {
		writeProblem(w, http.StatusConflict, "https://argus.io/errors/invalid-state", "Agent has not reported", "this cluster's agent has not reported its facts yet")
		return
	}
	if err != nil {
		logger.ErrorContext(ctx, "reading cluster facts for an agent upgrade failed", logging.ClusterID(clusterID), logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not read cluster facts", "")
		return
	}
	var facts tunnel.ClusterFacts
	_ = json.Unmarshal(raw, &facts)
	if facts.Agent == nil || !facts.Agent.SelfUpgrade {
		writeProblem(w, http.StatusConflict, "https://argus.io/errors/invalid-state", "Self-upgrade not enabled",
			"this cluster's agent chart does not allow upgrades from the hub (selfUpgrade.enabled with remediate.enabled); upgrade it with helm instead")
		return
	}
	if facts.Agent.Image == target {
		writeProblem(w, http.StatusConflict, "https://argus.io/errors/invalid-state", "Already current", "this agent already runs "+target)
		return
	}
	if s.gw == nil || !s.gw.IsConnected(clusterID) {
		writeProblem(w, http.StatusServiceUnavailable, "https://argus.io/errors/cluster-disconnected", "Cluster not connected", "this cluster's agent is not connected")
		return
	}
	ns, rv, err := s.agentDeploymentPrecondition(ctx, clusterID, facts.Agent.Namespace)
	if err != nil {
		logger.WarnContext(ctx, "reading the agent Deployment for an upgrade failed", logging.ClusterID(clusterID), logging.Err(err))
		writeProblem(w, http.StatusBadGateway, "https://argus.io/errors/agent", "Could not read the agent Deployment", "the agent did not return its own Deployment")
		return
	}
	key, err := remediation.DeriveClusterSigningKey(s.planSigningRootKey, clusterID)
	if err != nil {
		logger.ErrorContext(ctx, "deriving the plan signing key failed", logging.ClusterID(clusterID), logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not sign the upgrade", "")
		return
	}
	params, _ := json.Marshal(map[string]string{"image": target, "investigateDeployment": agentDeployment, "remediateDeployment": agentRemediateDeployment})
	signed, err := remediation.Sign(remediation.PlanContent{
		RecommendationID: domain.NewID("agu"),
		ActionType:       remediation.ActionUpgradeAgent,
		TargetGVK:        "apps/v1/Deployment",
		TargetNamespace:  ns,
		TargetName:       agentDeployment,
		Params:           params,
		ResourceVersion:  rv,
	}, clusterID, time.Now().Add(agentUpgradeTTL), key)
	if err != nil {
		logger.ErrorContext(ctx, "signing an agent upgrade failed", logging.ClusterID(clusterID), logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not sign the upgrade", "")
		return
	}
	args, _ := json.Marshal(map[string]any{"plan": signed})
	callCtx, cancel := context.WithTimeout(ctx, inspectCallTimeout)
	defer cancel()
	_, callErr := s.gw.CallTool(callCtx, clusterID, "upgrade_agent", args)

	capability := authz.CapAgentUpgrade
	outcome := audit.OutcomeSuccess
	if callErr != nil {
		outcome = audit.OutcomeError
	}
	if err := audit.RecordEvent(ctx, rc.Tx, audit.Event{
		TenantID: rc.TenantID, ActorID: &rc.UserID, ActorAuthMethod: "jwt", SourceIP: clientIP(r),
		Capability: &capability, ClusterID: &clusterID, Outcome: outcome,
		Details: map[string]any{"action": "agent:upgrade", "from": facts.Agent.Image, "to": target},
	}); err != nil {
		logger.ErrorContext(ctx, "recording an agent upgrade in the audit log failed", logging.ClusterID(clusterID), logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not record audit event", "")
		return
	}
	if callErr != nil {
		logger.WarnContext(ctx, "the agent refused or failed the upgrade", logging.ClusterID(clusterID), logging.Err(callErr))
		writeProblem(w, http.StatusBadGateway, "https://argus.io/errors/agent", "Upgrade refused", agentToolFailureDetail(callErr))
		return
	}
	writeJSON(w, http.StatusOK, agentUpgradeResponse{Image: target, From: facts.Agent.Image})
}

// agentDeploymentPrecondition reads the investigate agent's own Deployment
// through the read-only connection, for its resourceVersion.
func (s *Server) agentDeploymentPrecondition(ctx context.Context, clusterID, namespace string) (string, string, error) {
	if namespace == "" {
		return "", "", errors.New("the agent did not report its namespace")
	}
	callCtx, cancel := context.WithTimeout(ctx, inspectCallTimeout)
	defer cancel()
	args, _ := json.Marshal(map[string]string{"gvk": "apps/v1/Deployment", "namespace": namespace, "name": agentDeployment})
	raw, err := s.gw.CallTool(callCtx, clusterID, "describe_resource", args)
	if err != nil {
		return "", "", err
	}
	var out struct {
		Object struct {
			Metadata struct {
				ResourceVersion string `json:"resourceVersion"`
			} `json:"metadata"`
		} `json:"object"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return "", "", err
	}
	if out.Object.Metadata.ResourceVersion == "" {
		return "", "", errors.New("the agent Deployment came back without a resourceVersion")
	}
	return namespace, out.Object.Metadata.ResourceVersion, nil
}
