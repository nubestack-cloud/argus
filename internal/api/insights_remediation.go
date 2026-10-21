package api

import (
	"context"
	"net/http"
	"strconv"
	"time"

	"argus/internal/logging"

	"github.com/jackc/pgx/v5"
)

// This file implements GET /api/v1/insights/remediation-quality — the two
// BACKLOG.md L4 analytics that read remediation_recommendations/
// remediation_approval_decisions: "recommendations frequently rejected" and
// "automation candidates." Deliberately a SEPARATE endpoint from GET
// /api/v1/insights (insights.go), not two more fields on that response —
// see that file's own header comment for the full reasoning, in one line:
// those two tables are already treated as gated behind remediation:approve
// specifically (GET /api/v1/approvals, server.go), a strictly narrower set
// of roles than incident:read + analysis:read (a "viewer" role holds the
// latter two but not the former — authz/permissions.go's
// builtinRoleCapabilities), so folding this into the main insights response
// would either have to weaken that response's own gate (leaking approval/
// rejection history to viewers) or silently omit fields in Go for a
// capability check the frontend has no honest way to react to mid-response.
// A route with its own capability check is the same shape GET
// /api/v1/spend/today already established for exactly this situation.
//
// Both queries below are plain GROUP BY/COUNT aggregation over
// remediation_recommendations joined to remediation_approval_decisions,
// scoped by the same clusterId/days query parameters GET /api/v1/insights
// accepts, inside the request's already-RLS-scoped transaction — no new
// query parameter shape, no full-table fetch into Go.

// rejectedRecommendationSummary is one element of "frequentlyRejected" —
// remediation_recommendations grouped by (action_type, target_gvk), kept
// only when at least one decision on a recommendation in that group was a
// rejection (the HAVING clause in queryFrequentlyRejectedRecommendations).
// That HAVING is what makes RejectionRate always computable: rejectedCount
// > 0 guarantees decidedCount > 0, so there is no divide-by-zero case to
// paper over with a fabricated 0 — every row here really was rejected at
// least once, and the rate is real.
type rejectedRecommendationSummary struct {
	ActionType            string  `json:"actionType"`
	TargetGVK             string  `json:"targetGvk"`
	RecommendedCount      int     `json:"recommendedCount"`
	DecidedCount          int     `json:"decidedCount"`
	RejectedCount         int     `json:"rejectedCount"`
	RejectionRate         float64 `json:"rejectionRate"`
	SampleRejectionReason *string `json:"sampleRejectionReason"`
	LastRejectedAt        string  `json:"lastRejectedAt"`
}

// automationCandidateSummary is one element of "automationCandidates" —
// remediation_recommendations that the autonomy gate marked NeedsApproval
// (internal/remediation.Evaluate's decision at proposal time, recorded on
// gate_outcome — never recomputed later, see that column's own migration
// comment), grouped by (action_type, target_gvk, risk_level), joined to
// every human decision made on one. This is deliberately the narrow,
// honest definition from this task's own scoping note: NOT "risk+
// confidence combos that keep needing a human" (recommendations carry no
// confidence column — that lives on `analyses`, one level up, and joining
// it in would mean picking a confidence bucketing scheme with no precedent
// anywhere in this codebase), but "this exact (action, target kind, risk)
// combination already requires a human today, and every time it has come
// up, the human agreed." ApprovedCount == DecidedCount (RejectedCount == 0)
// is the strongest form of that signal; the frontend surfaces it as a
// candidate for the operator to consider promoting to auto-approve, always
// alongside the real sample size, never as a bare percentage.
//
// The INNER JOIN in queryAutomationCandidates (not a LEFT JOIN) guarantees
// DecidedCount > 0 for every row returned — a recommendation with zero
// decisions yet is still awaiting a human, not evidence that a human
// agrees, so it is correctly absent rather than shown with an invented 0%
// or 100% rate.
type automationCandidateSummary struct {
	ActionType    string  `json:"actionType"`
	TargetGVK     string  `json:"targetGvk"`
	RiskLevel     string  `json:"riskLevel"`
	DecidedCount  int     `json:"decidedCount"`
	ApprovedCount int     `json:"approvedCount"`
	RejectedCount int     `json:"rejectedCount"`
	ApprovalRate  float64 `json:"approvalRate"`
	LastDecidedAt string  `json:"lastDecidedAt"`
}

// remediationQualityResponse is GET /api/v1/insights/remediation-quality's
// full response shape.
type remediationQualityResponse struct {
	GeneratedAt          string                          `json:"generatedAt"`
	FrequentlyRejected   []rejectedRecommendationSummary `json:"frequentlyRejected"`
	AutomationCandidates []automationCandidateSummary    `json:"automationCandidates"`
}

// handleGetInsightsRemediationQuality is GET
// /api/v1/insights/remediation-quality. Requires remediation:approve alone
// (server.go's route registration) — see this file's header comment for
// why that, and not incident:read/analysis:read, is the correct gate.
func (s *Server) handleGetInsightsRemediationQuality(w http.ResponseWriter, r *http.Request, rc *requestContext) {
	ctx := r.Context()
	// One parse of the query string for the whole handler: r.URL.Query()
	// re-parses RawQuery and allocates a fresh url.Values on every call.
	q := r.URL.Query()
	clusterID := q.Get("clusterId")
	// Same days=14|30|90 contract GET /api/v1/insights enforces
	// (insights.go's handleGetInsights) — duplicated inline rather than
	// factored out, matching that handler's own style.
	days := 0
	if raw := q.Get("days"); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || (parsed != 14 && parsed != 30 && parsed != 90) {
			writeProblem(w, http.StatusBadRequest, "https://argus.io/errors/malformed-request",
				"Invalid date range", "days must be 14, 30, or 90")
			return
		}
		days = parsed
	}

	frequentlyRejected, err := queryFrequentlyRejectedRecommendations(ctx, rc.Tx, clusterID, days)
	if err != nil {
		logger.ErrorContext(ctx, "querying the frequently rejected remediations failed", logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not compute remediation quality insights", "")
		return
	}

	automationCandidates, err := queryAutomationCandidates(ctx, rc.Tx, clusterID, days)
	if err != nil {
		logger.ErrorContext(ctx, "querying the remediation-quality automation candidates failed", logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not compute remediation quality insights", "")
		return
	}

	writeJSON(w, http.StatusOK, remediationQualityResponse{
		GeneratedAt:          nowRFC3339(),
		FrequentlyRejected:   frequentlyRejected,
		AutomationCandidates: automationCandidates,
	})
}

// queryFrequentlyRejectedRecommendations groups remediation_recommendations
// by (action_type, target_gvk) — action_type alone is too coarse for
// OpenPR, which can target any GVK a repository binding covers, and too
// fine-grained a group (e.g. per target_name) would fragment a real
// pattern across dozens of near-identical rows for different objects of
// the same kind. LEFT JOINed to remediation_approval_decisions because a
// recommendation can have zero decisions yet (still pending); the HAVING
// clause then keeps only groups with at least one real rejection, which is
// what "frequently rejected" means and what makes RejectionRate always
// well-defined (see rejectedRecommendationSummary's doc comment).
func queryFrequentlyRejectedRecommendations(ctx context.Context, tx pgx.Tx, clusterID string, days int) ([]rejectedRecommendationSummary, error) {
	rows, err := tx.Query(ctx, `
		SELECT r.action_type,
		       r.target_gvk,
		       COUNT(DISTINCT r.id) AS recommended_count,
		       COUNT(d.id) AS decided_count,
		       COUNT(d.id) FILTER (WHERE d.verdict = 'rejected') AS rejected_count,
		       (array_agg(d.reason ORDER BY d.created_at DESC) FILTER (WHERE d.verdict = 'rejected' AND d.reason IS NOT NULL))[1] AS sample_reason,
		       MAX(d.created_at) FILTER (WHERE d.verdict = 'rejected') AS last_rejected_at
		  FROM remediation_recommendations r
		  LEFT JOIN remediation_approval_decisions d ON d.recommendation_id = r.id
		 WHERE ($1 = '' OR r.cluster_id = $1)
		   AND ($2 = 0 OR r.created_at >= now() - ($2 * interval '1 day'))
		 GROUP BY r.action_type, r.target_gvk
		HAVING COUNT(d.id) FILTER (WHERE d.verdict = 'rejected') > 0
		 ORDER BY rejected_count DESC, decided_count DESC
		 LIMIT $3`, clusterID, days, insightsTopN)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []rejectedRecommendationSummary{}
	for rows.Next() {
		var s rejectedRecommendationSummary
		var lastRejectedAt time.Time
		if err := rows.Scan(&s.ActionType, &s.TargetGVK, &s.RecommendedCount, &s.DecidedCount, &s.RejectedCount,
			&s.SampleRejectionReason, &lastRejectedAt); err != nil {
			return nil, err
		}
		s.RejectionRate = float64(s.RejectedCount) / float64(s.DecidedCount)
		s.LastRejectedAt = formatRFC3339(lastRejectedAt)
		out = append(out, s)
	}
	return out, rows.Err()
}

// queryAutomationCandidates groups remediation_recommendations still
// gated NeedsApproval by (action_type, target_gvk, risk_level) — see
// automationCandidateSummary's doc comment for why this triple, not a
// confidence bucket. The INNER JOIN (not LEFT) is deliberate: it excludes
// any recommendation with zero decisions yet, so every row returned
// genuinely reflects "a human has ruled on this combination at least
// once," never a group that only LOOKS unanimous because nobody has
// decided yet.
func queryAutomationCandidates(ctx context.Context, tx pgx.Tx, clusterID string, days int) ([]automationCandidateSummary, error) {
	rows, err := tx.Query(ctx, `
		SELECT r.action_type,
		       r.target_gvk,
		       r.risk_level,
		       COUNT(d.id) AS decided_count,
		       COUNT(d.id) FILTER (WHERE d.verdict = 'approved') AS approved_count,
		       COUNT(d.id) FILTER (WHERE d.verdict = 'rejected') AS rejected_count,
		       MAX(d.created_at) AS last_decided_at
		  FROM remediation_recommendations r
		  JOIN remediation_approval_decisions d ON d.recommendation_id = r.id
		 WHERE r.gate_outcome = 'NeedsApproval'
		   AND ($1 = '' OR r.cluster_id = $1)
		   AND ($2 = 0 OR r.created_at >= now() - ($2 * interval '1 day'))
		 GROUP BY r.action_type, r.target_gvk, r.risk_level
		 ORDER BY decided_count DESC, approved_count DESC
		 LIMIT $3`, clusterID, days, insightsTopN)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []automationCandidateSummary{}
	for rows.Next() {
		var s automationCandidateSummary
		var lastDecidedAt time.Time
		if err := rows.Scan(&s.ActionType, &s.TargetGVK, &s.RiskLevel, &s.DecidedCount, &s.ApprovedCount,
			&s.RejectedCount, &lastDecidedAt); err != nil {
			return nil, err
		}
		s.ApprovalRate = float64(s.ApprovedCount) / float64(s.DecidedCount)
		s.LastDecidedAt = formatRFC3339(lastDecidedAt)
		out = append(out, s)
	}
	return out, rows.Err()
}
