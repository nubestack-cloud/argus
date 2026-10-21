package api

import (
	"context"
	"net/http"
	"strconv"
	"time"

	"argus/internal/logging"

	"github.com/jackc/pgx/v5"
)

// This file implements GET /api/v1/insights — lld/11-ui-design.md §15.1's
// "Insights" screen (`InsightsDashboard` in that doc's §3 component
// inventory), the last of the ten named screens in that section that had no
// backend or UI at all before this task. Read-only, aggregate, fleet-wide
// reporting only — no new write path, no new capability.
//
// Deliberately scoped down from §15.1's full description ("recurring issue
// classes, calibration curves, autonomy readiness per class, cost per
// incident, top noisy namespaces"): a real confidence calibration curve and
// a per-class autonomy-readiness rating both need either a real eval/
// golden-set harness (STATUS.md's D16/§28 notes: no such harness exists) or
// enough real human approve/reject history to be meaningful (the approval
// queue itself is only just being built by a parallel task, with zero
// historical decisions yet) — see notBuiltInsights below for the explicit,
// honest markers this endpoint returns instead of a fabricated chart.
// Everything else here is real SQL aggregation (GROUP BY/COUNT/SUM/AVG,
// computed by Postgres, never by fetching whole tables into Go) over
// `incidents`/`findings`/`analyses` — tables WORKLOG.md §25/§28 confirm are
// genuinely populated by the real investigation loop today, not synthetic
// fixtures assembled just to make a chart look interesting.
//
// Capability: gated on BOTH incident:read AND analysis:read (nested
// requireCapability, server.go) rather than either alone, because the
// response genuinely reads both incidents/findings (incident:read's table)
// and analyses (analysis:read's table) — narrower than "pick one capability
// as a stand-in" and not so broad as to invent a third insights:read
// capability with no lld/02-authz-spec.md §4 precedent. Every builtin role
// that holds one of these two capabilities already holds the other
// (authz/permissions.go's builtinRoleCapabilities), so in practice this
// changes nothing about who can see the page — it just documents the real
// dependency rather than picking one capability arbitrarily.
//
// Scope: this is intentionally fleet-wide, not narrowed to any one
// cluster's accessible-cluster-ID set — there is no per-request query
// parameter that could narrow it even if scope resolution existed. That
// said, per-cluster-scoped grants and their app.accessible_cluster_ids
// resolution are STILL not implemented anywhere in this codebase
// (internal/api/middleware.go's requireAuth always passes a nil cluster
// scope — see that file's own comment, unchanged by this task), so in
// practice every route today, including this one, is already only scoped
// down to app.tenant_id, not to any narrower per-cluster grant. This
// endpoint's rows come from `incidents`/`findings`/`analyses`, all of which
// carry the additive tenant_id-keyed RLS policy migrations 000013/000015
// already added (see those migrations' own comments for why the
// cluster_id-only policy from 000009 would otherwise return zero rows for
// every caller) — so rc.Tx queries below see every one of this tenant's
// rows, exactly like handleListIncidents already does, and nothing less
// scoped than any other route in this codebase today.
//
// BACKLOG.md L4 ("evolve Insights from counts toward operational
// decisions") added queryUnstableClusters below — the one L4 analytic that
// fits this endpoint's existing capability gate unchanged, since it reads
// only `incidents` (already covered by incident:read) joined to
// `clusters.display_name` for a readable label (already covered by
// cluster:read's own table, but display_name carries no more sensitivity
// than the cluster names already shown elsewhere on incident:read-gated
// screens). "Recurring root causes" and "noisiest workloads" are already
// served by issueClasses/noisyNamespaces above — see BACKLOG.md's
// "Delivered work" entry for why L4 didn't duplicate them. "Recommendations
// frequently rejected" and "automation candidates" read
// remediation_recommendations/remediation_approval_decisions, which this
// codebase already treats as gated behind remediation:approve specifically
// (GET /api/v1/approvals, server.go) — a viewer role holds incident:read +
// analysis:read but NOT remediation:approve (authz/permissions.go's
// builtinRoleCapabilities), so folding those two analytics into THIS
// response would leak approval/rejection history to a capability that was
// never meant to see it. See insights_remediation.go for that pair, as a
// separate endpoint with its own capability, matching GET
// /api/v1/spend/today's already-established precedent for "a genuinely
// different capability requirement earns its own route, not a field
// silently gated in Go on this same response." "Estimated toil saved" and
// "spend vs value" are not built at all — see notBuiltInsights below.

// insightsTrendDays is the daily cost/token trend's window — matches
// OverviewPage.tsx's ActivitySparkline's SPARKLINE_DAYS (14) so the two
// "how has this looked over the last little while" panels in this app read
// on the same timescale, even though one is computed client-side from an
// already-fetched list and this one is a real GROUP BY over `analyses`.
const insightsTrendDays = 14

// costTrackingNote is surfaced verbatim in the API response so the frontend
// never has to independently know (or invent its own copy of) *why*
// totalCostUsd may still read 0 — see internal/api.PersistAnalysis's doc
// comment (analyze.go) and internal/settings.Config.ComputeCostUSD for the
// full explanation this note summarizes: cost_usd is computed from a real,
// operator-configured per-token pricing table (Settings > Cost, or
// PUT /api/v1/admin/settings' "cost" section) the moment one is set for
// whichever model is configured in AI Connector settings — this endpoint's
// own SUM(cost_usd) query (queryCostAndTokens below) was never the gap;
// it was always correct and simply summing whatever cost_usd already held.
// Two things worth saying plainly rather than leaving implicit: (1) an
// analysis persisted BEFORE pricing was configured keeps its honest,
// historical 0 permanently — this endpoint does not retroactively recompute
// past rows, since that would mean pricing a token at a rate that wasn't
// actually in effect when it was billed; (2) token counts above are real
// regardless of whether pricing is configured at all.
const costTrackingNote = "This total covers only analyses whose cost was actually measured. It is 0 for any analysis run before an operator configured per-token pricing (Settings > Cost) — that historical 0 is never retroactively recomputed. Analyses run through a subscription-billed agent-CLI provider have no per-investigation cost at all and are excluded from the total rather than counted as free; unmeasuredCostCount says how many. Once pricing is configured, every new analysis on a metered provider gets a real, nonzero cost_usd computed from real token counts."

// issueClassSummary is one element of insightsResponse's "issueClasses" —
// incidents grouped by their exact fingerprint (internal/agent/detector.go's
// computeFingerprint: sha256(namespace, kind, name, reason)) across the
// WHOLE visible incident history, not just currently-open ones. Fingerprint
// is deliberately used as-is, not narrowed to (gvk, reason): an exact
// fingerprint match already guarantees the same namespace/gvk/object
// name/reason (all four are inputs to the hash), so grouping by fingerprint
// is strictly more precise, not a different grouping, AND lets this row
// show all four sample fields below with zero ambiguity — every row sharing
// one fingerprint agrees on all of them by construction. Unlike a
// fingerprint, none of the four include cluster_id, so a fingerprint
// recurring across ClusterCount>1 rows below is genuinely "the same
// problem, the same namespace/kind/object name/reason, recurring on more
// than one cluster," exactly the ops signal DESIGN.md
// §15.1 asks this screen to surface.
type issueClassSummary struct {
	Fingerprint      string  `json:"fingerprint"`
	SampleGVK        string  `json:"sampleGvk"`
	SampleNamespace  *string `json:"sampleNamespace"`
	SampleObjectName *string `json:"sampleObjectName"`
	SampleReason     *string `json:"sampleReason"`
	IncidentCount    int     `json:"incidentCount"`
	ClusterCount     int     `json:"clusterCount"`
	TotalOccurrences int     `json:"totalOccurrences"`
	FirstSeen        string  `json:"firstSeen"`
	LastSeen         string  `json:"lastSeen"`
}

// noisyNamespaceSummary is one element of insightsResponse's
// "noisyNamespaces" — findings grouped by namespace (findings.namespace,
// the same column handleGetIncident's findingSummary already exposes per
// incident), ranked by raw finding volume.
type noisyNamespaceSummary struct {
	Namespace     string `json:"namespace"`
	FindingCount  int    `json:"findingCount"`
	IncidentCount int    `json:"incidentCount"`
	ClusterCount  int    `json:"clusterCount"`
}

// newNoisyNamespaceSummary is one element of insightsResponse's
// "newNoisyNamespaces" — see queryNewNoisyNamespaces' doc comment for what
// "new" means. Adds FirstSeen over noisyNamespaceSummary above: "since when"
// is exactly the fact that answers "how new is this," which the existing
// all-time top-N namespace list has no reason to carry.
type newNoisyNamespaceSummary struct {
	Namespace     string `json:"namespace"`
	FindingCount  int    `json:"findingCount"`
	IncidentCount int    `json:"incidentCount"`
	ClusterCount  int    `json:"clusterCount"`
	FirstSeen     string `json:"firstSeen"`
}

// investigationOutcomes summarizes every row in `analyses` ever written —
// "complete" (root_cause->>'status') means the investigation loop concluded
// with a real root cause and confidence; "partial" means a bound (max
// iterations / time limit) was hit first (lld/07-analysis-contracts.md §4,
// analyze.go's own doc comments). This is a genuinely new signal: no
// existing screen shows "is our investigation loop actually reaching a
// conclusion, and how many tool-calling round-trips does that typically
// take."
type investigationOutcomes struct {
	TotalAnalyses int `json:"totalAnalyses"`
	CompleteCount int `json:"completeCount"`
	PartialCount  int `json:"partialCount"`
	// CompleteRate/AvgIterations are both nil, never a fabricated 0, when
	// TotalAnalyses is 0 — there is a real difference between "0 of 0
	// investigations reached a conclusion" (undefined) and "0 of 40 did"
	// (a genuinely bad rate), and collapsing them into the same number
	// would lose that distinction, matching lld/11-ui-design.md §7's
	// "distinguish no-data-at-all from a genuine zero" rule.
	CompleteRate  *float64 `json:"completeRate"`
	AvgIterations *float64 `json:"avgIterations"`
}

// dailyTrendPoint is one day of costAndTokensSummary's "dailyTrend" —
// zero-filled for a day with no analyses (see fillDailyTrend below),
// matching OverviewPage.tsx's ActivitySparkline day-bucket-fill convention.
type dailyTrendPoint struct {
	Day            string `json:"day"`
	Investigations int    `json:"investigations"`
	TotalTokens    int64  `json:"totalTokens"`
}

// costAndTokensSummary is insightsResponse's "cost per incident/analysis"
// section — real averages over analyses.tokens_billed_in/tokens_cache_read/
// tokens_out (all real, populated columns per WORKLOG.md §28), plus the
// honestly-always-zero cost_usd sum and costTrackingNote explaining why.
type costAndTokensSummary struct {
	TotalInvestigations int     `json:"totalInvestigations"`
	AvgTokensBilledIn   float64 `json:"avgTokensBilledIn"`
	AvgTokensCacheRead  float64 `json:"avgTokensCacheRead"`
	AvgTokensOut        float64 `json:"avgTokensOut"`
	// TotalCostUSD covers only analyses whose cost was actually measured.
	// UnmeasuredCostCount is how many are excluded because their provider
	// cannot report a per-investigation cost (a subscription-billed CLI run) —
	// reported rather than silently folded in as zero, so the UI can say
	// "plus N with no cost data" instead of implying the total is complete.
	TotalCostUSD        float64           `json:"totalCostUsd"`
	UnmeasuredCostCount int               `json:"unmeasuredCostCount"`
	CostTrackingNote    string            `json:"costTrackingNote"`
	DailyTrend          []dailyTrendPoint `json:"dailyTrend"`
}

// notBuiltSection is one explicit "not built yet" entry in insightsResponse
// — rendered by InsightsPage.tsx as an honest empty/unbuilt state, per this
// task's own explicit instruction not to fake a calibration curve or an
// autonomy-readiness rating with synthetic data just to fill the panel.
type notBuiltSection struct {
	ID     string `json:"id"`
	Label  string `json:"label"`
	Reason string `json:"reason"`
}

// notBuiltInsights is returned verbatim as insightsResponse.NotBuilt — a
// fixed, static list (not derived from any query) because both gaps are
// structural, not data-dependent: no query against today's schema could
// ever populate either section honestly yet.
var notBuiltInsights = []notBuiltSection{
	{
		ID:    "calibrationCurve",
		Label: "Confidence calibration curve",
		Reason: "Needs shadow-mode history (D10/§9.4: \"is confidence 0.9 actually right 90% of the time in this " +
			"environment\") — shadow mode itself isn't built yet (only the decision logic exists so far; " +
			"nothing is recorded). Building a curve from today's analyses.confidence values " +
			"alone would plot self-reported model confidence as if it were a verified probability, exactly what " +
			"D10 says never to ship.",
	},
	{
		ID:    "autonomyReadiness",
		Label: "Autonomy readiness per class",
		Reason: "Needs real approve/reject decision history per issue class (D15's 20-occurrence/30-day shadow-" +
			"soak minimum before a class can even be considered) — the approval queue this would read from is " +
			"only just being built by a parallel task, with zero historical decisions to compute readiness from " +
			"yet.",
	},
	{
		ID:    "estimatedToilSaved",
		Label: "Estimated toil saved",
		Reason: "Would need a baseline for how long a human takes to fix each issue class by hand — this " +
			"codebase records no such baseline anywhere, and no state-transition history exists yet — " +
			"timeline_events exists but nothing writes it — which rules out even deriving " +
			"one from how long an incident spent open. Any number here would be invented, not measured, exactly " +
			"what cost_usd's honest-zero precedent (below) exists to prevent.",
	},
	{
		ID:    "spendVsValue",
		Label: "Spend vs. value",
		Reason: "The spend half is real (costAndTokens.totalCostUsd below). The value half — cost or downtime " +
			"avoided by a remediation — has no methodology anywhere in this codebase: D16's own cost figures are " +
			"still \"pending a Phase 1 measurement harness,\" and value avoided is a harder number than cost " +
			"measured. Charting a real total against a fabricated one would misrepresent the real figure by " +
			"association, so this stays unbuilt until there is an honest way to compute the second half.",
	},
}

// unstableClusterSummary is one element of insightsResponse's
// "unstableClusters" — BACKLOG.md L4's "unstable clusters" analytic:
// incidents grouped by cluster_id, ranked by how many reopened or failed
// outright in the selected window, then by raw incident volume as the
// tiebreak. Deliberately two plain counts rather than one invented
// "instability score" — `reference/screens.md`'s "no state-transition
// history" gap (nothing writes timeline_events, so age-in-state/MTTR can't
// be computed) rules out anything fancier than "how many of this cluster's
// incidents are currently Reopened or Failed," which IS a real, current
// value of incidents.state, not a derived history. ReopenedOrFailedCount
// can legitimately be 0 for every cluster in the window (a fleet that has
// never had a remediation fail or an incident reopen) — the ranking still
// degrades gracefully to "busiest by incident volume" in that case, and the
// UI's section note says exactly what the ranking is so nobody reads it as
// a trained score.
type unstableClusterSummary struct {
	ClusterID             string `json:"clusterId"`
	ClusterDisplayName    string `json:"clusterDisplayName"`
	TotalIncidents        int    `json:"totalIncidents"`
	ReopenedOrFailedCount int    `json:"reopenedOrFailedCount"`
	OpenCount             int    `json:"openCount"`
}

// insightsResponse is GET /api/v1/insights' full response shape.
type insightsResponse struct {
	GeneratedAt     string                  `json:"generatedAt"`
	IssueClasses    []issueClassSummary     `json:"issueClasses"`
	NoisyNamespaces []noisyNamespaceSummary `json:"noisyNamespaces"`
	// NewIssueClasses/NewNoisyNamespaces are BUGS.md 121 part (b)'s "new in
	// this window" lists — genuinely new signals with no history before
	// NewSignalWindowDays, added alongside IssueClasses/NoisyNamespaces
	// above WITHOUT changing either's own count-based top-N ranking at all
	// (see queryNewIssueClasses/queryNewNoisyNamespaces' doc comments).
	// NewSignalWindowDays is carried on the payload rather than left for the
	// frontend to hardcode, matching costTrackingNote's precedent of the API
	// explaining its own number instead of the UI silently assuming one.
	NewIssueClasses       []issueClassSummary        `json:"newIssueClasses"`
	NewNoisyNamespaces    []newNoisyNamespaceSummary `json:"newNoisyNamespaces"`
	NewSignalWindowDays   int                        `json:"newSignalWindowDays"`
	UnstableClusters      []unstableClusterSummary   `json:"unstableClusters"`
	InvestigationOutcomes investigationOutcomes      `json:"investigationOutcomes"`
	CostAndTokens         costAndTokensSummary       `json:"costAndTokens"`
	NotBuilt              []notBuiltSection          `json:"notBuilt"`
}

// insightsTopN caps every ranked list this endpoint returns — a reporting
// screen's "top offenders" panel, not a paginated full listing (ClusterList/
// IncidentList's own virtualization discipline, lld/11-ui-design.md §3, is
// for exhaustive lists; this is deliberately a top-10 digest instead).
const insightsTopN = 10

// insightsNewSignalWindowDays is the fixed lookback queryNewIssueClasses/
// queryNewNoisyNamespaces use to decide "new in this window" — BUGS.md 121
// part (b). Deliberately NOT the request's own `days` parameter: `days` only
// narrows the EXISTING top-N lists' ranking window (and is left completely
// unchanged by this addition, per the owner's own decision on 121). "New"
// asks a different question — "does this fingerprint/namespace have ANY
// history before the last N days" — which has to be answered against the
// WHOLE visible history regardless of whatever window the caller asked the
// top-N lists to rank over, or narrowing `days` would silently narrow what
// "new" means too.
//
// 7 days, matching BACKLOG.md E12's condition-polarity model-verdict TTL
// (internal/conditionpolarity/polarity.go's modelVerdictTTL) — the closest
// existing "how long counts as 'recent' in this codebase" precedent, reused
// rather than inventing a second, unrelated notion of recency. Not
// insightsTrendDays (14): that constant was chosen to match a UI sparkline's
// display width, not a "how new is new" judgement, and reusing it here would
// borrow a number for a reason that has nothing to do with this decision.
const insightsNewSignalWindowDays = 7

// handleGetInsights is GET /api/v1/insights. Requires incident:read AND
// analysis:read (see server.go's route registration and this file's own
// header comment for why both). Runs six independent aggregate queries
// against the current request's already-scoped transaction — no N+1, and
// no full-table fetch into Go: every GROUP BY/COUNT/SUM/AVG happens in
// Postgres.
//
// The remediation-recommendation-derived analytics (BACKLOG.md L4's
// "recommendations frequently rejected" and "automation candidates") are
// deliberately NOT here — see insights_remediation.go's header comment for
// why that is a genuinely separate endpoint rather than two more fields on
// this response.
func (s *Server) handleGetInsights(w http.ResponseWriter, r *http.Request, rc *requestContext) {
	ctx := r.Context()
	// One parse of the query string for the whole handler: r.URL.Query()
	// re-parses RawQuery and allocates a fresh url.Values on every call.
	q := r.URL.Query()
	clusterID := q.Get("clusterId")
	// No `days` preserves the endpoint's original all-history aggregates;
	// the UI always sends an explicit supported window.
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

	issueClasses, err := queryIssueClasses(ctx, rc.Tx, clusterID, days)
	if err != nil {
		logger.ErrorContext(ctx, "querying insights: issue classes failed", logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not compute insights", "")
		return
	}

	noisyNamespaces, err := queryNoisyNamespaces(ctx, rc.Tx, clusterID, days)
	if err != nil {
		logger.ErrorContext(ctx, "querying insights: noisy namespaces failed", logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not compute insights", "")
		return
	}

	// BUGS.md 121 part (b): a separate "new in this window" pass, alongside
	// (not replacing) the two count-ranked queries above — see
	// queryNewIssueClasses/queryNewNoisyNamespaces' own doc comments. Always
	// run, regardless of the caller's `days` query param — see
	// insightsNewSignalWindowDays' doc comment for why "new" uses its own
	// fixed window rather than the request's.
	newIssueClasses, err := queryNewIssueClasses(ctx, rc.Tx, clusterID)
	if err != nil {
		logger.ErrorContext(ctx, "querying insights: new issue classes failed", logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not compute insights", "")
		return
	}

	newNoisyNamespaces, err := queryNewNoisyNamespaces(ctx, rc.Tx, clusterID)
	if err != nil {
		logger.ErrorContext(ctx, "querying insights: new noisy namespaces failed", logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not compute insights", "")
		return
	}

	unstableClusters, err := queryUnstableClusters(ctx, rc.Tx, clusterID, days)
	if err != nil {
		logger.ErrorContext(ctx, "querying insights: unstable clusters failed", logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not compute insights", "")
		return
	}

	outcomes, err := queryInvestigationOutcomes(ctx, rc.Tx, clusterID, days)
	if err != nil {
		logger.ErrorContext(ctx, "querying insights: investigation outcomes failed", logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not compute insights", "")
		return
	}

	costAndTokens, err := queryCostAndTokens(ctx, rc.Tx, clusterID, days)
	if err != nil {
		logger.ErrorContext(ctx, "querying insights: cost and tokens failed", logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not compute insights", "")
		return
	}

	writeJSON(w, http.StatusOK, insightsResponse{
		GeneratedAt:           nowRFC3339(),
		IssueClasses:          issueClasses,
		NoisyNamespaces:       noisyNamespaces,
		NewIssueClasses:       newIssueClasses,
		NewNoisyNamespaces:    newNoisyNamespaces,
		NewSignalWindowDays:   insightsNewSignalWindowDays,
		UnstableClusters:      unstableClusters,
		InvestigationOutcomes: outcomes,
		CostAndTokens:         costAndTokens,
		NotBuilt:              notBuiltInsights,
	})
}

// queryIssueClasses groups `findings` by fingerprint — see issueClassSummary's
// doc comment for why fingerprint alone (not (gvk, reason)) is both the more
// precise and the least-invented grouping available. gvk/namespace/object
// name/reason are all pulled via MAX() rather than a second query per
// fingerprint (no N+1): since every row sharing one fingerprint is
// guaranteed to share all four (they're inputs to the hash), MAX() here is
// just "pick the one value every row in this group already agrees on," not
// a real aggregation choice.
func queryIssueClasses(ctx context.Context, tx pgx.Tx, clusterID string, days int) ([]issueClassSummary, error) {
	rows, err := tx.Query(ctx, `
		SELECT fingerprint,
		       MAX(gvk) AS gvk,
		       MAX(namespace) AS namespace,
		       MAX(object_name) AS object_name,
		       MAX(reason) AS reason,
		       COUNT(DISTINCT incident_id) AS incident_count,
		       COUNT(DISTINCT cluster_id) AS cluster_count,
		       COALESCE(SUM(occurrence_count), 0) AS total_occurrences,
		       MIN(occurred_at) AS first_seen,
		       MAX(occurred_at) AS last_seen
		  FROM findings
		 WHERE incident_id IS NOT NULL
		   AND ($1 = '' OR cluster_id = $1)
		   AND ($2 = 0 OR occurred_at >= now() - ($2 * interval '1 day'))
		 GROUP BY fingerprint
		 ORDER BY incident_count DESC, total_occurrences DESC, last_seen DESC
		 LIMIT $3`, clusterID, days, insightsTopN)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []issueClassSummary{}
	for rows.Next() {
		var s issueClassSummary
		var namespace, objectName, reason *string
		var firstSeen, lastSeen time.Time
		if err := rows.Scan(&s.Fingerprint, &s.SampleGVK, &namespace, &objectName, &reason, &s.IncidentCount,
			&s.ClusterCount, &s.TotalOccurrences, &firstSeen, &lastSeen); err != nil {
			return nil, err
		}
		s.SampleNamespace = namespace
		s.SampleObjectName = objectName
		s.SampleReason = reason
		s.FirstSeen = formatRFC3339(firstSeen)
		s.LastSeen = formatRFC3339(lastSeen)
		out = append(out, s)
	}
	return out, rows.Err()
}

// queryNoisyNamespaces groups `findings` by namespace, ranked by raw finding
// volume — cluster-namespace pairs aren't distinguished (a namespace name
// like "default" recurring across many clusters is deliberately folded into
// one row, matching issueClassSummary's fleet-wide-by-design framing above),
// but ClusterCount says how many distinct clusters contributed so that
// isn't hidden either.
func queryNoisyNamespaces(ctx context.Context, tx pgx.Tx, clusterID string, days int) ([]noisyNamespaceSummary, error) {
	rows, err := tx.Query(ctx, `
		SELECT namespace,
		       COUNT(*) AS finding_count,
		       COUNT(DISTINCT incident_id) AS incident_count,
		       COUNT(DISTINCT cluster_id) AS cluster_count
		  FROM findings
		 WHERE namespace IS NOT NULL
		   AND ($1 = '' OR cluster_id = $1)
		   AND ($2 = 0 OR occurred_at >= now() - ($2 * interval '1 day'))
		 GROUP BY namespace
		 ORDER BY finding_count DESC
		 LIMIT $3`, clusterID, days, insightsTopN)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []noisyNamespaceSummary{}
	for rows.Next() {
		var n noisyNamespaceSummary
		if err := rows.Scan(&n.Namespace, &n.FindingCount, &n.IncidentCount, &n.ClusterCount); err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

// queryNewIssueClasses is BUGS.md 121 part (b)'s "new in this window" list
// for issue classes — the same fingerprint grouping queryIssueClasses above
// uses (see issueClassSummary's doc comment), but instead of ranking by
// count over ALL history, this keeps only a fingerprint whose EARLIEST
// occurrence ever recorded falls inside insightsNewSignalWindowDays — i.e.
// it has NO history before the window at all, a genuinely brand-new signal.
//
// Deliberately scoped to that one shape only ("brand new: zero occurrences
// before the window"), not also "was quiet, then started spiking well above
// its own historical baseline rate": shape (a) is unambiguous and needs no
// baseline-rate math or judgement call about what counts as "much higher
// than normal," which has no precedent anywhere in this codebase to anchor
// on; that is real, additional scope, deferred rather than shipped as a rough
// guess (BUGS.md 121 itself flags (a) alone as "probably the right MVP
// scope").
//
// queryIssueClasses above is completely unchanged by this addition — same
// query text, same ORDER BY, same LIMIT, same insightsTopN — this is an
// entirely separate query building an entirely separate list, exactly the
// "add a list, don't touch the existing one" shape the owner decided on.
//
// HAVING MIN(occurred_at) >= window-start is shape (a)'s definition applied
// directly: if the group's OWN earliest row is inside the window, then by
// definition every row in the group is (MIN is the earliest one), so "no
// history before the window" holds with no second query needed to check it.
func queryNewIssueClasses(ctx context.Context, tx pgx.Tx, clusterID string) ([]issueClassSummary, error) {
	rows, err := tx.Query(ctx, `
		SELECT fingerprint,
		       MAX(gvk) AS gvk,
		       MAX(namespace) AS namespace,
		       MAX(object_name) AS object_name,
		       MAX(reason) AS reason,
		       COUNT(DISTINCT incident_id) AS incident_count,
		       COUNT(DISTINCT cluster_id) AS cluster_count,
		       COALESCE(SUM(occurrence_count), 0) AS total_occurrences,
		       MIN(occurred_at) AS first_seen,
		       MAX(occurred_at) AS last_seen
		  FROM findings
		 WHERE incident_id IS NOT NULL
		   AND ($1 = '' OR cluster_id = $1)
		 GROUP BY fingerprint
		HAVING MIN(occurred_at) >= now() - ($2 * interval '1 day')
		 ORDER BY total_occurrences DESC, last_seen DESC
		 LIMIT $3`, clusterID, insightsNewSignalWindowDays, insightsTopN)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []issueClassSummary{}
	for rows.Next() {
		var s issueClassSummary
		var namespace, objectName, reason *string
		var firstSeen, lastSeen time.Time
		if err := rows.Scan(&s.Fingerprint, &s.SampleGVK, &namespace, &objectName, &reason, &s.IncidentCount,
			&s.ClusterCount, &s.TotalOccurrences, &firstSeen, &lastSeen); err != nil {
			return nil, err
		}
		s.SampleNamespace = namespace
		s.SampleObjectName = objectName
		s.SampleReason = reason
		s.FirstSeen = formatRFC3339(firstSeen)
		s.LastSeen = formatRFC3339(lastSeen)
		out = append(out, s)
	}
	return out, rows.Err()
}

// queryNewNoisyNamespaces is queryNewIssueClasses' namespace-grouped
// counterpart — see that function's doc comment for what "new" means and
// why this is scoped to shape (a) only. queryNoisyNamespaces above is
// completely unchanged: same query, same ranking, same LIMIT.
func queryNewNoisyNamespaces(ctx context.Context, tx pgx.Tx, clusterID string) ([]newNoisyNamespaceSummary, error) {
	rows, err := tx.Query(ctx, `
		SELECT namespace,
		       COUNT(*) AS finding_count,
		       COUNT(DISTINCT incident_id) AS incident_count,
		       COUNT(DISTINCT cluster_id) AS cluster_count,
		       MIN(occurred_at) AS first_seen
		  FROM findings
		 WHERE namespace IS NOT NULL
		   AND ($1 = '' OR cluster_id = $1)
		 GROUP BY namespace
		HAVING MIN(occurred_at) >= now() - ($2 * interval '1 day')
		 ORDER BY finding_count DESC
		 LIMIT $3`, clusterID, insightsNewSignalWindowDays, insightsTopN)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []newNoisyNamespaceSummary{}
	for rows.Next() {
		var n newNoisyNamespaceSummary
		var firstSeen time.Time
		if err := rows.Scan(&n.Namespace, &n.FindingCount, &n.IncidentCount, &n.ClusterCount, &firstSeen); err != nil {
			return nil, err
		}
		n.FirstSeen = formatRFC3339(firstSeen)
		out = append(out, n)
	}
	return out, rows.Err()
}

// queryUnstableClusters groups `incidents` by cluster_id — see
// unstableClusterSummary's doc comment for why the ranking is two plain
// counts (reopened-or-failed, then total) rather than an invented
// composite score. incidents.state is read as of NOW, not as a
// state-transition history (none is recorded anywhere in this codebase —
// see queryInvestigationOutcomes' own precedent for reading a live column
// rather than fabricating a derived one), so this is exactly as honest as
// any other "current count of rows in state X" query already on this page.
func queryUnstableClusters(ctx context.Context, tx pgx.Tx, clusterID string, days int) ([]unstableClusterSummary, error) {
	rows, err := tx.Query(ctx, `
		SELECT i.cluster_id,
		       MAX(c.display_name) AS display_name,
		       COUNT(*) AS total_incidents,
		       COUNT(*) FILTER (WHERE i.state IN ('Reopened', 'Failed')) AS reopened_or_failed_count,
		       -- 'Expired' (PROJECT.md T2) is a CLOSED outcome — an incident
		       -- nobody actioned, aged out — so it must not count as open.
		       -- Measured on 2026-09-07 before this was added: this card
		       -- reported 56 open against an actual 14, because migration
		       -- 000101 reclassified 42 historical rows into Expired and this
		       -- predicate still had the pre-T2 two-state list.
		       COUNT(*) FILTER (WHERE i.state NOT IN ('Resolved', 'Dismissed', 'Expired')) AS open_count
		  FROM incidents i
		  JOIN clusters c ON c.id = i.cluster_id
		 WHERE ($1 = '' OR i.cluster_id = $1)
		   AND ($2 = 0 OR i.first_seen >= now() - ($2 * interval '1 day'))
		 GROUP BY i.cluster_id
		 ORDER BY reopened_or_failed_count DESC, total_incidents DESC
		 LIMIT $3`, clusterID, days, insightsTopN)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []unstableClusterSummary{}
	for rows.Next() {
		var u unstableClusterSummary
		if err := rows.Scan(&u.ClusterID, &u.ClusterDisplayName, &u.TotalIncidents, &u.ReopenedOrFailedCount, &u.OpenCount); err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// queryInvestigationOutcomes reads analyses.root_cause->>'status' the exact
// same way getLatestAnalysis (analyze.go) already decodes a single row's
// status, just aggregated: COALESCE(...,'complete') matches
// getLatestAnalysis's own fallback for a pre-v2 row with no status tag
// (treated as complete, per that function's doc comment) — this endpoint
// must never silently disagree with how the exact same column is
// interpreted on the incident detail screen.
//
// BUGS.md 102: this used to INNER JOIN incidents ON incidents.id =
// analyses.incident_id purely to reach incidents.cluster_id for the
// clusterID filter below — analyses.incident_id carries no foreign key (see
// analyses' own CREATE TABLE in migration 000005, and 000053/000044's
// comments on why one is impossible: incidents is PARTITION BY RANGE
// (first_seen) with PRIMARY KEY (id, first_seen), so there is no unique
// constraint on id alone for anything to reference — Postgres refuses the FK
// outright), so any analyses row whose incident/cluster was later deleted
// directly (a real, confirmed case: 7 rows from 2026-08-23) was silently
// dropped from every total this endpoint reports, with no error and no
// visible gap. Fixed by filtering on analyses.cluster_id directly instead of
// joining to reach it — analyses already carries its own NOT NULL cluster_id
// (set once, at PersistAnalysis time, from the same value as the owning
// incident's; incidents.cluster_id is never updated anywhere in this
// codebase), so the join added a dependency on a row that could vanish
// without adding any information the query didn't already have. This also
// matches how RLS already scopes `analyses` (migrations 000015/000035):
// tenant_id/cluster_id live on the row itself, never derived through
// incidents, so an orphaned analysis was always correctly readable — it was
// only ever this endpoint's own JOIN silently excluding it.
func queryInvestigationOutcomes(ctx context.Context, tx pgx.Tx, clusterID string, days int) (investigationOutcomes, error) {
	var out investigationOutcomes
	var avgIterations *float64
	err := tx.QueryRow(ctx, `
		SELECT COUNT(*),
		       COUNT(*) FILTER (WHERE COALESCE(root_cause->>'status', 'complete') = 'partial'),
		       AVG(iterations)::float8
		  FROM analyses a
		 WHERE ($1 = '' OR a.cluster_id = $1)
		   AND ($2 = 0 OR a.created_at >= now() - ($2 * interval '1 day'))`, clusterID, days,
	).Scan(&out.TotalAnalyses, &out.PartialCount, &avgIterations)
	if err != nil {
		return out, err
	}
	out.CompleteCount = out.TotalAnalyses - out.PartialCount
	out.AvgIterations = avgIterations
	if out.TotalAnalyses > 0 {
		rate := float64(out.CompleteCount) / float64(out.TotalAnalyses)
		out.CompleteRate = &rate
	}
	return out, nil
}

// queryCostAndTokens computes the real per-investigation token averages and
// the (honestly zero) total cost, then attaches the daily trend.
//
// BUGS.md 102: no JOIN to incidents here either — see
// queryInvestigationOutcomes' doc comment for why filtering on
// analyses.cluster_id directly is both correct (it is the same value
// incidents.cluster_id had at PersistAnalysis time, which never changes
// afterward) and necessary (the JOIN it replaces silently dropped any
// analyses row whose incident had since been deleted).
func queryCostAndTokens(ctx context.Context, tx pgx.Tx, clusterID string, days int) (costAndTokensSummary, error) {
	var out costAndTokensSummary
	err := tx.QueryRow(ctx, `
		SELECT COUNT(*),
		       COALESCE(AVG(tokens_billed_in), 0)::float8,
		       COALESCE(AVG(tokens_cache_read), 0)::float8,
		       COALESCE(AVG(tokens_out), 0)::float8,
		       -- FILTER on cost_basis, matching TodaySpend in spend.go. A
		       -- subscription-billed CLI analysis stores cost_usd = 0 meaning
		       -- *unavailable*, not free (lld/07-analysis-contracts.md §10.5),
		       -- so summing every row understated real usage while presenting
		       -- the total as complete. This query had no filter while spend.go
		       -- did — an inconsistency that made the same underlying data
		       -- report two different totals.
		       COALESCE(SUM(cost_usd) FILTER (WHERE cost_basis = 'metered'), 0)::float8,
		       COUNT(*) FILTER (WHERE cost_basis IS DISTINCT FROM 'metered')
		  FROM analyses a
		 WHERE ($1 = '' OR a.cluster_id = $1)
		   AND ($2 = 0 OR a.created_at >= now() - ($2 * interval '1 day'))`, clusterID, days,
	).Scan(&out.TotalInvestigations, &out.AvgTokensBilledIn, &out.AvgTokensCacheRead, &out.AvgTokensOut, &out.TotalCostUSD, &out.UnmeasuredCostCount)
	if err != nil {
		return out, err
	}
	out.CostTrackingNote = costTrackingNote

	trendDays := days
	if trendDays == 0 {
		trendDays = insightsTrendDays
	}
	trend, err := queryDailyTrend(ctx, tx, clusterID, trendDays)
	if err != nil {
		return out, err
	}
	out.DailyTrend = trend
	return out, nil
}

// queryDailyTrend aggregates `analyses` by calendar day (UTC) for the last
// `days` days, then zero-fills any day with no analyses so the frontend
// renders a fixed-width trend instead of a sparse, gap-shaped one — the same
// "an empty day is a real, meaningful zero, not a missing data point"
// convention OverviewPage.tsx's ActivitySparkline already established for
// incident-open counts, applied here to a server-aggregated query instead of
// a client-side reduce over an already-fetched list.
//
// Both the day bucket and the window start are pinned to UTC explicitly.
// This used to be `date_trunc('day', a.created_at)::date`, which buckets in
// the Postgres SESSION time zone — and nothing in this deployment sets one
// (the hub's DSN carries no TimeZone parameter; see startOfUTCDay in
// spend.go), so the bucket boundary was whatever the database server's
// timezone GUC happened to be, while the zero-fill keys below have always
// been generated from time.Now().UTC(). On a server east of UTC, an analysis
// created late in the UTC day bucketed as *tomorrow* — a key that is never
// in the generated set — so the newest analyses were dropped and today
// silently rendered as 0 investigations and 0 tokens. `created_at AT TIME
// ZONE 'UTC'` makes the bucket independent of session state, and passing the
// window start in as a Go-computed UTC instant (trendWindowStart, sharing
// the one `now` used for the zero-fill) makes SQL and Go agree by
// construction rather than by coincidence.
func queryDailyTrend(ctx context.Context, tx pgx.Tx, clusterID string, days int) ([]dailyTrendPoint, error) {
	now := time.Now().UTC()
	// BUGS.md 102: no JOIN to incidents — see queryInvestigationOutcomes'
	// doc comment. Filtering on analyses.cluster_id directly means a day's
	// bucket can no longer silently lose an analysis whose incident was
	// later deleted.
	rows, err := tx.Query(ctx, `
		SELECT (a.created_at AT TIME ZONE 'UTC')::date AS day,
		       COUNT(*) AS investigations,
		       COALESCE(SUM(tokens_billed_in + tokens_cache_read + tokens_out), 0) AS total_tokens
		  FROM analyses a
		 WHERE a.created_at >= $1
		   AND ($2 = '' OR a.cluster_id = $2)
		 GROUP BY day
		 ORDER BY day`, trendWindowStart(now, days), clusterID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	byDay := map[string]dailyTrendPoint{}
	for rows.Next() {
		var day time.Time
		var investigations int
		var totalTokens int64
		if err := rows.Scan(&day, &investigations, &totalTokens); err != nil {
			return nil, err
		}
		key := day.UTC().Format("2006-01-02")
		byDay[key] = dailyTrendPoint{Day: key, Investigations: investigations, TotalTokens: totalTokens}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	return fillDailyTrend(byDay, days, now), nil
}

// trendWindowStart is the earliest instant queryDailyTrend's window includes:
// midnight UTC on the oldest of the `days` calendar days fillDailyTrend will
// emit a key for. Pure and DB-free, like fillDailyTrend, specifically so the
// SQL window and the Go zero-fill keys can be unit-tested to agree
// (insights_test.go) instead of being two independent pieces of date
// arithmetic that happen to line up.
//
// This replaces `created_at >= now() - (days * interval '1 day')`: a rolling
// window starting mid-day, which returned a partial bucket for the day
// *before* the oldest zero-filled key — a real aggregated row that
// fillDailyTrend then silently discarded, since its key was outside the
// generated set.
func trendWindowStart(now time.Time, days int) time.Time {
	return startOfUTCDay(now).AddDate(0, 0, -(days - 1))
}

// fillDailyTrend is queryDailyTrend's pure, DB-free zero-fill step, pulled
// out on its own specifically so it has a real unit test (insights_test.go)
// — every other DB-touching query in this file needs a live Postgres to
// exercise meaningfully (this codebase's existing convention: see
// incidents_test.go's own doc comment, "needs a live Postgres connection
// and is covered by scripts/smoke-test.sh instead"), but this particular
// step is ordinary date arithmetic with no query in it, so it doesn't have
// to be one of those.
//
// The keys it generates are UTC calendar days, whatever location `now`
// carries — normalized through startOfUTCDay rather than trusting every
// caller to pass an already-UTC clock, since a key set generated in local
// time would disagree with the UTC buckets queryDailyTrend's SQL now
// produces, and that disagreement is exactly the silent "today reads 0" bug
// this pairing exists to prevent.
func fillDailyTrend(byDay map[string]dailyTrendPoint, days int, now time.Time) []dailyTrendPoint {
	today := startOfUTCDay(now)
	out := make([]dailyTrendPoint, 0, days)
	for i := days - 1; i >= 0; i-- {
		key := today.AddDate(0, 0, -i).Format("2006-01-02")
		if point, ok := byDay[key]; ok {
			out = append(out, point)
		} else {
			out = append(out, dailyTrendPoint{Day: key, Investigations: 0, TotalTokens: 0})
		}
	}
	return out
}
