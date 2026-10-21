package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"argus/internal/agent/upgradeready"
	"argus/internal/audit"
	"argus/internal/authz"
	"argus/internal/logging"
	"argus/internal/upgradescans"
)

// Upgrade readiness (docs/CLUSTER_INSIGHT_SPECS.md CI-S5).

// GET /api/v1/clusters/{id}/upgrade-scans/latest
func (s *Server) handleLatestUpgradeScan(w http.ResponseWriter, r *http.Request, rc *requestContext) {
	clusterID := r.PathValue("id")
	if !s.authorizeClusterScoped(w, r, rc, authz.CapClusterRead, clusterID) {
		return
	}
	scan, err := upgradescans.Latest(r.Context(), rc.Tx, clusterID)
	if err != nil {
		logger.ErrorContext(r.Context(), "reading the latest upgrade scan failed", logging.ClusterID(clusterID), logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not read upgrade scan", "")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"scan": scan})
}

var targetVersionRE = regexp.MustCompile(`^v?1\.\d{1,3}$`)

// clusterMinorRE reads the major.minor out of the agent-reported server
// version ("v1.33.5+rke2r1" → 1, 33).
var clusterMinorRE = regexp.MustCompile(`^v?(\d+)\.(\d+)`)

// minorOf parses "1.34" / "v1.34.2" into major and minor.
func minorOf(v string) (major, minor int, ok bool) {
	m := clusterMinorRE.FindStringSubmatch(strings.TrimSpace(v))
	if m == nil {
		return 0, 0, false
	}
	major, err1 := strconv.Atoi(m[1])
	minor, err2 := strconv.Atoi(m[2])
	return major, minor, err1 == nil && err2 == nil
}

// validateScanTarget decides whether a requested target is one a scan can
// honestly answer, returning the problem detail when it is not. current is
// the cluster's reported server version ("" when unreported); reviewed is the
// release the check catalogue is reviewed through.
//
// The rules:
//   - the target must be newer than the cluster's current minor — an
//     upgrade "to" the version it runs, or an older one, is not an upgrade;
//   - it must be within the catalogue's reviewed range, because a scan for a
//     release nobody has reviewed checks nothing about what that release
//     changes and would still produce a verdict. The one exception is the
//     next minor itself, which the daily scheduled scan always asks about:
//     its answer for an unreviewed release is "incomplete", which is true.
//
// A jump of more than one minor is allowed on purpose: the catalogue's
// upgrade-path check reports every skipped minor as a blocker, so the scan
// answers "what would it take to get to 1.N" rather than refusing to.
func validateScanTarget(target, current, reviewed string) string {
	tMaj, tMin, ok := minorOf(target)
	if !ok {
		return `targetVersion must look like "1.37"`
	}
	rMaj, rMin, rOK := minorOf(reviewed)
	cMaj, cMin, cOK := minorOf(current)
	if cOK {
		if tMaj != cMaj || tMin <= cMin {
			return fmt.Sprintf("%d.%d is not newer than this cluster's Kubernetes %d.%d; choose a later minor version, starting at %d.%d.", tMaj, tMin, cMaj, cMin, cMaj, cMin+1)
		}
		if tMaj == cMaj && tMin == cMin+1 {
			return ""
		}
	}
	if rOK && (tMaj > rMaj || (tMaj == rMaj && tMin > rMin)) {
		rangeHint := fmt.Sprintf("up to %d.%d", rMaj, rMin)
		if cOK && cMaj == rMaj && cMin+1 < rMin {
			rangeHint = fmt.Sprintf("%d.%d to %d.%d", cMaj, cMin+1, rMaj, rMin)
		} else if cOK && cMaj == rMaj && cMin+1 >= rMin {
			rangeHint = fmt.Sprintf("only %d.%d, the next minor", cMaj, cMin+1)
		}
		return fmt.Sprintf("ARGUS's upgrade checks are reviewed through Kubernetes %d.%d, so a scan for %d.%d would have nothing reviewed to check; choose %s.", rMaj, rMin, tMaj, tMin, rangeHint)
	}
	return ""
}

// POST /api/v1/clusters/{id}/upgrade-scans {"targetVersion":"1.37"} — an
// on-demand scan. Read-only for the cluster (the agent reads its cache), so
// it is gated like a read; at most one per cluster per minute. Every request
// is audited with its outcome — refused, failed or completed — because a scan
// stores a verdict other people will read.
func (s *Server) handleRunUpgradeScan(w http.ResponseWriter, r *http.Request, rc *requestContext) {
	ctx := r.Context()
	clusterID := r.PathValue("id")
	if !s.authorizeClusterScoped(w, r, rc, authz.CapClusterRead, clusterID) {
		return
	}
	var body struct {
		TargetVersion string `json:"targetVersion"`
	}
	// Every request past authorisation leaves an audit row, refused ones
	// included: a burst of rejected or rate-limited scans is as much a part
	// of the trail as a completed one. (A capability denial is audited by
	// authorizeClusterScoped itself.)
	refuse := func(status int, problemType, title, detail string) {
		s.auditUpgradeScanRefused(r, rc, clusterID, body.TargetVersion, status, title, detail)
		writeProblem(w, status, problemType, title, detail)
	}
	raw, _ := io.ReadAll(io.LimitReader(r.Body, 4096))
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &body); err != nil {
			refuse(http.StatusBadRequest, "https://argus.io/errors/validation", "Invalid body", "body must be JSON")
			return
		}
	}
	body.TargetVersion = strings.TrimPrefix(strings.TrimSpace(body.TargetVersion), "v")
	if body.TargetVersion != "" && !targetVersionRE.MatchString(body.TargetVersion) {
		refuse(http.StatusBadRequest, "https://argus.io/errors/validation", "Invalid target version", `targetVersion must look like "1.37"`)
		return
	}
	if body.TargetVersion != "" {
		var current string
		if err := rc.Tx.QueryRow(ctx, `SELECT coalesce(facts->>'kubernetesVersion', '') FROM cluster_facts WHERE cluster_id = $1`, clusterID).Scan(&current); err != nil && !errors.Is(err, pgx.ErrNoRows) {
			logger.ErrorContext(ctx, "reading the cluster's version for an upgrade scan failed", logging.ClusterID(clusterID), logging.Err(err))
			refuse(http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not read the cluster's version", "")
			return
		}
		if detail := validateScanTarget(body.TargetVersion, current, upgradeready.ReviewedThrough); detail != "" {
			refuse(http.StatusBadRequest, "https://argus.io/errors/validation", "Target version out of range", detail)
			return
		}
	}
	if age, ok, _ := upgradescans.ScanAge(ctx, rc.Tx, clusterID); ok && age < time.Minute {
		refuse(http.StatusTooManyRequests, "https://argus.io/errors/rate-limited", "Scan just ran", "this cluster was scanned less than a minute ago")
		return
	}
	if s.gw == nil || !s.gw.IsConnected(clusterID) {
		refuse(http.StatusServiceUnavailable, "https://argus.io/errors/cluster-disconnected", "Cluster not connected", "the agent is not connected, so a scan cannot run now")
		return
	}
	scan, err := upgradescans.Run(ctx, s.db, s.gw, clusterID, body.TargetVersion, rc.UserID)
	s.auditUpgradeScan(r, rc, clusterID, body.TargetVersion, scan, err)
	if err != nil {
		logger.WarnContext(ctx, "on-demand upgrade scan failed", logging.ClusterID(clusterID), logging.Err(err))
		writeProblem(w, http.StatusBadGateway, "https://argus.io/errors/agent-tool", "Scan failed", agentToolFailureDetail(err))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"scan": scan})
}

// upgradeScanAuditEvent is the row every scan request writes; the caller
// fills in the outcome and what happened.
func upgradeScanAuditEvent(r *http.Request, rc *requestContext, clusterID, requested string) (audit.Event, map[string]any) {
	capability := authz.CapClusterRead
	cid := clusterID
	details := map[string]any{"action": "upgrade_scan:run", "requestedTarget": requested}
	if requested == "" {
		details["requestedTarget"] = "next minor"
	}
	return audit.Event{
		TenantID:        rc.TenantID,
		ActorID:         &rc.UserID,
		ActorAuthMethod: "jwt",
		SourceIP:        clientIP(r),
		Capability:      &capability,
		ClusterID:       &cid,
		Outcome:         audit.OutcomeSuccess,
		Details:         details,
	}, details
}

// auditUpgradeScanRefused records a scan request the hub turned away before
// asking the agent — invalid input, the per-cluster rate limit, a
// disconnected agent. Validation and the rate limit are "denied" (policy said
// no); anything else is "error". In its own committed transaction, because
// the error response rolls the request transaction back.
func (s *Server) auditUpgradeScanRefused(r *http.Request, rc *requestContext, clusterID, requested string, status int, title, detail string) {
	ev, details := upgradeScanAuditEvent(r, rc, clusterID, requested)
	ev.Outcome = audit.OutcomeError
	if status == http.StatusBadRequest || status == http.StatusTooManyRequests {
		ev.Outcome = audit.OutcomeDenied
	}
	details["status"] = status
	details["refused"] = title
	if detail != "" {
		details["reason"] = detail
	}
	s.writeAuditEvent(r.Context(), ev)
}

// auditUpgradeScan records an on-demand scan in its own committed
// transaction: a failed scan returns an error response, which rolls the
// request transaction back, and the attempt still belongs in the trail.
func (s *Server) auditUpgradeScan(r *http.Request, rc *requestContext, clusterID, requested string, scan upgradescans.Scan, callErr error) {
	ev, details := upgradeScanAuditEvent(r, rc, clusterID, requested)
	if callErr != nil {
		ev.Outcome = audit.OutcomeError
		details["error"] = agentToolFailureDetail(callErr)
	} else {
		details["scanId"] = scan.ID
		details["currentVersion"] = scan.CurrentVersion
		details["targetVersion"] = scan.TargetVersion
		details["verdict"] = scan.Verdict
	}
	s.writeAuditEvent(r.Context(), ev)
}

// GET /api/v1/upgrade-scans/latest — each visible cluster's newest verdict.
func (s *Server) handleFleetUpgradeScans(w http.ResponseWriter, r *http.Request, rc *requestContext) {
	scans, err := upgradescans.LatestPerCluster(r.Context(), rc.Tx)
	if err != nil {
		logger.ErrorContext(r.Context(), "listing upgrade scans failed", logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not list upgrade scans", "")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"scans": scans})
}
