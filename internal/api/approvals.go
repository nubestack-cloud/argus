// This file implements the approval queue: GET /api/v1/approvals (a
// worklist of every incident currently AwaitingApproval, per
// lld/11-ui-design.md §3's ApprovalQueue component — "sorted server-side by
// severity/age, not client-sorted after a full fetch") and
// POST /api/v1/incidents/{id}/approve|reject, the two write actions a
// human approver takes on one of those incidents.
//
// Capability gating, per this task's brief: GET requires the SAME
// CapRemediationApprove that gates the write action, rather than a separate
// read capability — matching org:settings:write's established precedent
// (internal/api/settings.go's own doc comment) for a view-and-act pair this
// tightly coupled. There's no scenario where someone can approve a
// remediation but shouldn't be able to see the queue of things awaiting
// approval, so a second capability here would be a distinction without a
// difference, not real defense in depth.
//
// POST .../approve additionally requires the EXECUTION capability for the
// channel the approved plan actually uses — remediation:execute:inplace for
// ScaleDeployment/RestartPod/PatchResourceLimits/RevertContainerImage,
// remediation:execute:pr for
// OpenPR — checked per-plan inside the handler rather than per-route in
// server.go, because one route approves every action type. See
// planApprovalGates below for the bug that motivated it.
//
// THE REAL BOUNDARY THIS FILE RESPECTS (rewritten 2026-08-21 — the previous
// version of this comment described a world that no longer exists, claiming
// "no executor exists anywhere in this codebase" and that approving "does NOT
// change incidents.state at all"; both became false when execution shipped,
// and a comment that confidently describes the opposite of the code is worse
// than no comment):
//
// Approving a ScaleDeployment, RestartPod, PatchResourceLimits or
// RevertContainerImage plan really
// does mutate the customer's cluster. The boundary is therefore not "nothing
// executes" but the four independent things that must all hold before
// anything does:
//  1. remediation:approve (route-level, server.go), AND the execution
//     capability for that plan's own action type (planApprovalGates below).
//  2. The agent must be running under the opt-in argus-remediate identity —
//     the default investigate-only ServiceAccount cannot write at all.
//  3. A ValidatingAdmissionPolicy the API server itself enforces, restricting
//     that identity's writes to the exact field paths the action needs.
//  4. The agent re-verifies the plan's signature against its own persisted
//     per-cluster key before issuing any Patch — it never trusts a bare
//     target+params argument from the hub.
//
// REJECTION REJECTS THE PLAN, NOT THE INCIDENT. handleRejectIncident applies
// AwaitingApproval -> PlanRejected. It used to apply AwaitingApproval ->
// Dismissed — lld/08-remediation-contracts.md §2 does name that edge — and
// that was wrong in a way §2 does not cover: Dismissed is terminal and means
// "this is real but needs no action from ARGUS", so "this proposed fix is
// unsafe" silently became "this fault no longer matters" and the incident left
// the queue with the fault still live in the cluster. A refusal is evidence the
// problem is still there, not evidence it is gone. See
// orchestrator.StatePlanRejected for the state's full argument, including why
// it is not a reuse of NeedsHumanInvestigation.
//
// What the refusal leaves behind, and where it is read: the
// remediation_approval_decisions row (verdict + reason + actor), which
// latestApprovalDecisionView puts on the plan the incident detail page renders,
// and an EventApprovalRejected timeline entry. No new column — this codebase
// has already written two rejection reasons nothing read back, and the fix for
// that is to read one, not to add a third.
package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"argus/internal/audit"
	"argus/internal/authz"
	"argus/internal/data"
	"argus/internal/domain"
	"argus/internal/events"
	"argus/internal/execution"
	"argus/internal/llm"
	"argus/internal/logging"
	"argus/internal/orchestrator"
	"argus/internal/remediation"
	"argus/internal/timeline"
)

// approvalQueueItem is one element of GET /api/v1/approvals' response —
// everything ApprovalsPage.tsx needs to render one worklist row without a
// second round trip: the incident's own identity/severity/age (mirrors
// incidentSummary), its currently-proposed plan (planView — plain-language
// Summary, not raw params), and the analysis' own confidence/root-cause
// statement that plan was proposed alongside.
type approvalQueueItem struct {
	IncidentID         string   `json:"incidentId"`
	ClusterID          string   `json:"clusterId"`
	ClusterDisplayName string   `json:"clusterDisplayName"`
	Fingerprint        string   `json:"fingerprint"`
	Severity           string   `json:"severity"`
	FirstSeen          string   `json:"firstSeen"`
	LastSeen           string   `json:"lastSeen"`
	OccurrenceCount    int      `json:"occurrenceCount"`
	Plan               planView `json:"plan"`
	Confidence         *float64 `json:"confidence"`
	RootCauseStatement string   `json:"rootCauseStatement"`
	// CausalChain/RuledOut/CausalChainProvenance are PROJECT.md D8's own
	// addition — the SAME per-analysis evidence the incident detail page's
	// "Why?" section already renders (analysisResponse's own fields,
	// analyze.go), joined onto the approval queue row directly rather than
	// making an approver navigate away to see it. The whole point: a
	// "contradicted" ToolCall.Corroborated citation (PROJECT.md B151) is real
	// signal about whether the evidence behind THIS plan can be trusted, and
	// it belongs in front of the person about to approve a live mutation, not
	// one click deeper. Empty/omitted for an investigation that made no tool
	// calls at all (a hub-observed chain with zero steps) or predates this
	// column being read here.
	CausalChain           []llm.CausalStep         `json:"causalChain"`
	RuledOut              []llm.RuledOutHypothesis `json:"ruledOut"`
	CausalChainProvenance string                   `json:"causalChainProvenance,omitempty"`
	// AlreadyApproved is true once someone has already approved this exact
	// plan — the incident still shows up here (approving never moves it out
	// of AwaitingApproval; see this file's own doc comment), so
	// ApprovalsPage needs this to render "already approved, awaiting an
	// execution capability that doesn't exist yet" instead of a live
	// Approve/Reject pair a second click would just 409 against.
	AlreadyApproved bool `json:"alreadyApproved"`
	// SupersededByURL is set when ARGUS has already proposed the durable fix for
	// this incident at its source (migration 000049). Non-empty means Approve is
	// refused with a 409, so the queue must not offer it — but the row STAYS in
	// the queue on purpose. "Should I merge this pull request?" is a real
	// decision, and hiding the row would silently drop work: the incident would
	// vanish from the only screen an operator watches while still being open.
	// What changes is the action offered, not whether the item is shown.
	SupersededByURL string `json:"supersededByUrl,omitempty"`
	// ExecutionBlockedReason is the "may this plan execute" gate's answer when
	// it is NO for a reason no policy gate covers: the cluster has no
	// remediation agent connected (remediationAgentBlockedReason). Non-empty
	// means Approve would only fail at the dry run, so the UI disables it and
	// renders this sentence beside it. Empty for OpenPR plans and whenever a
	// remediation connection is live.
	ExecutionBlockedReason string `json:"executionBlockedReason,omitempty"`
}

// approvalQueueQuery joins each AwaitingApproval incident to its own most
// recent remediation_recommendations row (the plan that put it there — see
// orchestrator.ApplyAnalysisResult, which persists a plan and sets this
// exact state in the same transaction) and that plan's own analysis, so one
// TWO states, not one: AwaitingApproval and AwaitingMerge. An incident whose fix
// ARGUS has proposed as a pull request has left the approval queue in the sense
// that nothing here can be approved — but it has NOT stopped needing a human, and
// "should I merge this pull request?" is a real decision. Dropping it from this
// list would make it vanish from the only screen an operator watches while still
// being open. So the row stays and the offered action changes; see
// approvalQueueItem.SupersededByURL.
//
// query builds one complete queue row. A LATERAL join, not a plain JOIN
// keyed on MAX(created_at): an incident could in principle carry more than
// one recommendation row (e.g. a rejected plan from an earlier analysis,
// followed by a re-analysis that produced a new one) and this must always
// show the CURRENT one, not an arbitrary/oldest match.
//
// The tiebreak on sibling_of_recommendation_id IS NULL matters only for a
// paired `pullRequest+inPlace` route's two rows (F17, BACKLOG D8): both are
// written in the SAME transaction against a created_at column whose default
// is `now()`, fixed at the transaction's start rather than advancing between
// statements — so they carry an IDENTICAL created_at, and `ORDER BY
// created_at DESC LIMIT 1` alone breaks that tie non-deterministically (the
// same class of bug D8's B1 found and fixed for timeline_events). This does
// NOT change which ANALYSIS wins — a genuinely newer re-analysis's plan still
// sorts first on created_at exactly as before, since only same-transaction
// rows can tie — it only makes today's existing "one decision per incident"
// behavior deterministic (always the pair's primary row, never a coin flip
// between the two), not a fix that lets both halves of a pair be decided
// independently — that gap is real and still open (BACKLOG D8's paired-panel
// entry).
const approvalQueueQuery = `
	SELECT incidents.id, incidents.cluster_id, clusters.display_name, incidents.fingerprint,
	       incidents.severity, incidents.first_seen, incidents.last_seen, incidents.occurrence_count,
	       rr.id, rr.action_type, rr.target_gvk, rr.target_namespace, rr.target_name, rr.params,
	       rr.reversible, rr.risk_level, rr.gate_outcome, rr.gate_reason, rr.created_at,
	       analyses.confidence, analyses.root_cause, analyses.causal_chain, analyses.ruled_out,
	       EXISTS (SELECT 1 FROM remediation_approval_decisions
	                WHERE recommendation_id = rr.id AND verdict = 'approved') AS already_approved,
	       rr.superseded_by_url
	  FROM incidents
	  JOIN clusters ON clusters.id = incidents.cluster_id
	  JOIN LATERAL (
	    SELECT * FROM remediation_recommendations
	     WHERE incident_id = incidents.id
	     ORDER BY created_at DESC, (sibling_of_recommendation_id IS NULL) DESC LIMIT 1
	  ) rr ON true
	  LEFT JOIN analyses ON analyses.id = rr.analysis_id
	 WHERE incidents.state = ANY($1) AND incidents.archived_at IS NULL
	 ORDER BY CASE incidents.severity
	            WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4
	          END,
	          incidents.first_seen ASC`

// --- PROJECT.md B167: server-side filter/sort/count/pagination ---
//
// GET /api/v1/approvals used to run approvalQueueQuery verbatim and return
// EVERY AwaitingApproval/AwaitingMerge row, unbounded, and ApprovalsPage
// filtered by cluster/action/risk, sorted, counted the risk breakdown and
// paginated all of it in the browser over that one full fetch. Correct at
// the handful of approvals this queue held early on; silently wrong past
// whatever one response could hold, for the identical reason
// incidents.go's own P9/P10 history already learned (see incidentScopeFilter
// and handleListIncidents' pagination doc comment): the bug is invisible
// until the queue is big enough to matter, and by then a client-side
// .filter()/.sort() over a truncated JSON body describes a PREFIX, not the
// answer.
//
// What follows mirrors incidents.go's own shapes deliberately (same
// ?sort=/?direction=/?cursor=/?limit= contract, same keyset-not-offset
// reasoning, same "counts query shares its scope with the row query"
// discipline) rather than inventing a second convention for one more list.

// approvalListColumns/approvalListFrom are the paginated/filtered
// counterpart of approvalQueueQuery's own column list and FROM/JOIN —
// character-identical to it, but kept as their own constants rather than
// factored out of approvalQueueQuery, so approvals_causal_chain_db_test.go's
// existing regression test keeps exercising that exact, untouched query and
// is not coupled to this endpoint's new filtering. approvalListFrom's WHERE
// fixes the two states this queue is defined over as a literal (which
// incidents belong on this list at all is a product decision, not a
// per-request ?state=) — approvalScopeFilter below only ever ANDs onto it.
const approvalListColumns = `incidents.id, incidents.cluster_id, clusters.display_name, incidents.fingerprint,
       incidents.severity, incidents.first_seen, incidents.last_seen, incidents.occurrence_count,
       rr.id, rr.action_type, rr.target_gvk, rr.target_namespace, rr.target_name, rr.params,
       rr.reversible, rr.risk_level, rr.gate_outcome, rr.gate_reason, rr.created_at,
       analyses.confidence, analyses.root_cause, analyses.causal_chain, analyses.ruled_out,
       EXISTS (SELECT 1 FROM remediation_approval_decisions
                WHERE recommendation_id = rr.id AND verdict = 'approved') AS already_approved,
       rr.superseded_by_url`

var approvalListFrom = `
  FROM incidents
  JOIN clusters ON clusters.id = incidents.cluster_id
  JOIN LATERAL (
    SELECT * FROM remediation_recommendations
     WHERE incident_id = incidents.id
     ORDER BY created_at DESC, (sibling_of_recommendation_id IS NULL) DESC LIMIT 1
  ) rr ON true
  LEFT JOIN analyses ON analyses.id = rr.analysis_id
 WHERE incidents.state IN (` + sqlQuoteLiteral(orchestrator.StateAwaitingApproval) + `, ` + sqlQuoteLiteral(orchestrator.StateAwaitingMerge) + `)
   AND incidents.archived_at IS NULL`

// approvalCountColumns is approvalListColumns' lighter counterpart for
// approvalCountsFor's two aggregate queries below — just the columns a
// COUNT needs to classify a row (which action type, target, declared risk,
// and whether it's already been decided), never the heavy JSON columns
// (params/causal_chain/ruled_out) a count has no use for.
const approvalCountColumns = `rr.action_type, rr.target_gvk, rr.target_namespace, rr.risk_level,
       EXISTS (SELECT 1 FROM remediation_approval_decisions
                WHERE recommendation_id = rr.id AND verdict = 'approved') AS already_approved`

// approvalRiskLevelRank gives the three levels a plan on this queue can ever
// carry (RiskForbidden is excluded — see validApprovalRiskLevels) the same
// low<medium<high order internal/remediation.riskRank keeps private, so
// ?riskLevel= and approvalRiskRankExpr agree on what an integer rank means.
var approvalRiskLevelRank = map[remediation.RiskLevel]int{
	remediation.RiskLow:    0,
	remediation.RiskMedium: 1,
	remediation.RiskHigh:   2,
}

// validApprovalRiskLevels is the closed set ?riskLevel= accepts.
// RiskForbidden is deliberately excluded: Evaluate blocks a forbidden plan
// before a remediation_recommendations row is ever written (gate.go), so no
// row on this queue can carry it — accepting it here would be a filter that
// always, silently matches nothing rather than an honest 400, the same
// reasoning incidents.go's own validIncidentSeverities gives for rejecting
// an unrecognized value outright.
var validApprovalRiskLevels = []string{"low", "medium", "high"}

// approvalRiskRankExpr is a SQL rendering of
// internal/remediation.EffectiveRiskLevel, so ?sort=risk and ?riskLevel= can
// be evaluated by Postgres against every row instead of requiring every one
// of them to be pulled into Go first — which is exactly the over-fetch this
// section exists to remove.
//
// It mirrors EffectiveRiskLevel = maxRisk(RiskFloorFor(plan), declared) and
// RiskFloorFor = maxRisk(baseFloor, modifierFloor) as GREATEST over three
// rank expressions — GREATEST is associative/commutative, so the nesting
// order Go's two maxRisk calls use doesn't matter: the base floor
// (internal/remediation.BaseRiskFloors(), rendered as a CASE so this can
// never independently drift from that table the way AllActionTypes/
// AllRiskLevels exist to prevent for this package's other closed sets), the
// two floor-raising-only modifiers (StatefulTargetKinds()/
// ProtectedNamespaces()), and the plan's own declared risk_level column.
//
// ONE DELIBERATE GAP, documented rather than silently wrong: StructuredPatch's
// real floor is per-OPERATION (RiskFloorFor iterates plan.Params.Ops and takes
// the highest matched patchableField.Risk) — logic this expression does not
// reproduce in SQL. It falls back to BaseRiskFloors()'s own entry for that
// action type (high) instead, which is exactly what Go itself falls back to
// whenever the per-op computation finds nothing to compute from. Safe rather
// than silently wrong because StructuredPatch is unreachable in production
// today (ActionStructuredPatch's own doc comment in plan.go: no system
// prompt, no wire-parser case, no agent-side tool) —
// TestApprovalRiskRankExprMatchesEffectiveRiskLevel asserts parity against
// every OTHER action type and explicitly documents this one exclusion rather
// than silently skipping it.
var approvalRiskRankExpr = buildApprovalRiskRankExpr()

func buildApprovalRiskRankExpr() string {
	highRank := approvalRiskLevelRank[remediation.RiskHigh]

	actionTypes := remediation.AllActionTypes()
	sort.Slice(actionTypes, func(i, j int) bool { return actionTypes[i] < actionTypes[j] })
	floors := remediation.BaseRiskFloors()
	var floorCase strings.Builder
	floorCase.WriteString("CASE rr.action_type")
	for _, actionType := range actionTypes {
		rank, ok := approvalRiskLevelRank[floors[actionType]]
		if !ok {
			rank = highRank
		}
		fmt.Fprintf(&floorCase, " WHEN %s THEN %d", sqlQuoteLiteral(string(actionType)), rank)
	}
	fmt.Fprintf(&floorCase, " ELSE %d END", highRank)

	kinds := make([]string, 0)
	for kind := range remediation.StatefulTargetKinds() {
		kinds = append(kinds, sqlQuoteLiteral(kind))
	}
	sort.Strings(kinds)
	namespaces := make([]string, 0)
	for ns := range remediation.ProtectedNamespaces() {
		namespaces = append(namespaces, sqlQuoteLiteral(ns))
	}
	sort.Strings(namespaces)
	// regexp_replace(..., '^.*/', '') mirrors internal/remediation.GVKKind
	// exactly: everything after the last "/", or the whole string when there
	// is none.
	modifierCase := fmt.Sprintf(
		"CASE WHEN regexp_replace(rr.target_gvk, '^.*/', '') IN (%s) OR rr.target_namespace IN (%s) THEN %d ELSE 0 END",
		strings.Join(kinds, ", "), strings.Join(namespaces, ", "), highRank,
	)

	declaredCase := fmt.Sprintf(
		"CASE rr.risk_level WHEN 'low' THEN %d WHEN 'medium' THEN %d WHEN 'high' THEN %d ELSE %d END",
		approvalRiskLevelRank[remediation.RiskLow], approvalRiskLevelRank[remediation.RiskMedium], highRank, highRank,
	)

	return fmt.Sprintf("GREATEST((%s), (%s), (%s))", floorCase.String(), modifierCase, declaredCase)
}

// approvalSortSpec is one sortable column for GET /api/v1/approvals — the
// SQL expression to ORDER BY and to keyset-compare a cursor against (the
// SAME expression in both places, mirroring incidentSortSpec's own reasoning
// in incidents.go: the page boundary and the ordering can never disagree).
type approvalSortSpec struct {
	Expr       string
	Kind       incidentSortKind
	DefaultDir string
}

// approvalSortSpecs' three keys are exactly ApprovalsPage's old client-side
// `sort` <select> (waiting/risk/severity) — moved here unchanged in meaning,
// each keeping its own default DIRECTION so "waiting" stays
// longest-waiting-first without a caller having to know that "asc" is what
// that means. risk/severity rank HIGH first by default because that is what
// "highest risk/severity first" always meant on this screen; waiting ranks
// OLDEST (smallest first_seen) first by default for the reason this file's
// own approveIncidentRequest doc comment gives elsewhere: the failure mode
// this queue actually has is an item sitting unnoticed.
var approvalSortSpecs = map[string]approvalSortSpec{
	"waiting":  {Expr: "incidents.first_seen", Kind: sortKindTime, DefaultDir: "asc"},
	"risk":     {Expr: approvalRiskRankExpr, Kind: sortKindInt, DefaultDir: "desc"},
	"severity": {Expr: rankCaseExpr("incidents.severity", severityOrder), Kind: sortKindInt, DefaultDir: "desc"},
}

// approvalSortKeysSorted is approvalSortSpecs' keys in a fixed order for the
// 400 body — map iteration order is random in Go.
var approvalSortKeysSorted = []string{"waiting", "risk", "severity"}

// approvalScopeFilter builds the ?clusterId=/?actionType=/?riskLevel= WHERE
// fragment shared by handleListApprovals' row query and approvalCountsFor's
// aggregates — mirrors incidentScopeFilter's own reasoning in incidents.go
// exactly: the row query and the count(s) query must always agree on which
// rows are "in scope", or the number in the header and the rows a page could
// show would silently describe two different sets. Each call starts its own
// args slice, so placeholder numbering is always correct for whatever else
// the query it's spliced into does.
//
// includeRiskLevel is false for approvalCountsFor's risk-BREAKDOWN query
// specifically: "how many pending approvals are high risk" is not a question
// ?riskLevel=high can narrow the input to and still answer — see that
// function's own doc comment. Every other caller (the row query itself, and
// the pending/approved totals) passes true, so ?riskLevel= narrows them
// exactly like ?clusterId=/?actionType= do.
func approvalScopeFilter(r *http.Request, includeRiskLevel bool) (clause string, args []any, invalid string) {
	q := r.URL.Query()
	if clusterID := q.Get("clusterId"); clusterID != "" {
		args = append(args, clusterID)
		clause += fmt.Sprintf(" AND incidents.cluster_id = $%d", len(args))
	}
	if actionType := q.Get("actionType"); actionType != "" {
		if !remediation.ActionType(actionType).Valid() {
			names := make([]string, 0, len(remediation.AllActionTypes()))
			for _, t := range remediation.AllActionTypes() {
				names = append(names, string(t))
			}
			sort.Strings(names)
			return "", nil, "actionType must be one of: " + strings.Join(names, ", ")
		}
		args = append(args, actionType)
		clause += fmt.Sprintf(" AND rr.action_type = $%d", len(args))
	}
	if includeRiskLevel {
		if riskLevel := q.Get("riskLevel"); riskLevel != "" {
			if !slices.Contains(validApprovalRiskLevels, riskLevel) {
				return "", nil, "riskLevel must be one of: " + strings.Join(validApprovalRiskLevels, ", ")
			}
			args = append(args, approvalRiskLevelRank[remediation.RiskLevel(riskLevel)])
			clause += fmt.Sprintf(" AND (%s) = $%d", approvalRiskRankExpr, len(args))
		}
	}
	return clause, args, ""
}

// approvalAlreadyApprovedClause is NOT part of approvalScopeFilter above —
// deliberately, because approvalCountsFor needs pending/approved as two
// numbers computed from the exact SAME clusterId/actionType/riskLevel scope
// (so whichever bucket a request is actually paging through, its count and
// its rows narrow together by construction), rather than one bucket
// filtered further by the other's own presence/absence.
func approvalAlreadyApprovedClause(alreadyApproved bool) string {
	if alreadyApproved {
		return " AND EXISTS (SELECT 1 FROM remediation_approval_decisions WHERE recommendation_id = rr.id AND verdict = 'approved')"
	}
	return " AND NOT EXISTS (SELECT 1 FROM remediation_approval_decisions WHERE recommendation_id = rr.id AND verdict = 'approved')"
}

// Page-size bounds for handleListApprovals — same shape as
// defaultIncidentPageLimit/maxIncidentPageLimit (incidents.go), smaller
// numbers because a tenant's approval queue is a fraction of its incident
// count by construction (only AwaitingApproval/AwaitingMerge, not every
// state).
const (
	defaultApprovalPageLimit = 200
	maxApprovalPageLimit     = 500
)

func approvalPageLimit(raw string) (int, error) {
	if raw == "" {
		return defaultApprovalPageLimit, nil
	}
	n, err := strconv.Atoi(raw)
	if err != nil {
		return 0, fmt.Errorf("limit must be a whole number")
	}
	if n < 1 {
		return 0, fmt.Errorf("limit must be at least 1")
	}
	if n > maxApprovalPageLimit {
		return 0, fmt.Errorf("limit must be at most %d; use the nextCursor from the previous response to read further", maxApprovalPageLimit)
	}
	return n, nil
}

// approvalCounts is GET /api/v1/approvals' own aggregate, computed over the
// FULL matching set — never limited by ?limit=/?cursor= — for the identical
// reason incidentCounts exists in incidents.go: the header's "N need a
// decision" and its risk breakdown must describe the whole queue, not
// whatever page happened to load.
type approvalCounts struct {
	// Pending/Approved are each scoped by ?clusterId=/?actionType=/
	// ?riskLevel= EXACTLY like the row query is (approvalScopeFilter,
	// includeRiskLevel=true) — whichever bucket a request's own
	// ?alreadyApproved= is actually paging through, the matching one of
	// these two numbers is the literal COUNT(*) of that same WHERE clause,
	// so a page can never show more matches than the header claims, or an
	// empty page while the header says there's something to see (the exact
	// bug incidentScopeFilter's own doc comment records).
	Pending  int `json:"pending"`
	Approved int `json:"approved"`
	// High/Medium/Low are the PENDING set's risk breakdown, scoped by
	// ?clusterId=/?actionType= but deliberately WITHOUT ?riskLevel=
	// (approvalScopeFilter, includeRiskLevel=false) — "how many pending
	// approvals are high risk" is not a question that still means anything
	// once the input has already been narrowed to one risk level, the same
	// reason incidentCountsQuery's own severity buckets are computed over
	// the state/cluster scope rather than pre-filtered to whichever severity
	// a caller happens to be looking at.
	High   int `json:"high"`
	Medium int `json:"medium"`
	Low    int `json:"low"`
}

// approvalCountsFor runs two aggregate queries scoped like the calling
// request's row query — fresh calls to approvalScopeFilter, not args the
// caller already built, for the identical reason incidentCountsFor takes
// fresh ones: each call starts its own placeholder numbering from $1.
func approvalCountsFor(ctx context.Context, rc *requestContext, r *http.Request) (approvalCounts, error) {
	var counts approvalCounts

	scopeClause, scopeArgs, invalid := approvalScopeFilter(r, true)
	if invalid != "" {
		return approvalCounts{}, fmt.Errorf("unexpected invalid scope filter: %s", invalid)
	}
	pendingQuery := `SELECT
	    count(*) FILTER (WHERE NOT already_approved) AS pending_count,
	    count(*) FILTER (WHERE already_approved) AS approved_count
	  FROM (SELECT ` + approvalCountColumns + approvalListFrom + scopeClause + `) scoped`
	if err := rc.Tx.QueryRow(ctx, pendingQuery, scopeArgs...).Scan(&counts.Pending, &counts.Approved); err != nil {
		return approvalCounts{}, err
	}

	breakdownClause, breakdownArgs, invalid := approvalScopeFilter(r, false)
	if invalid != "" {
		return approvalCounts{}, fmt.Errorf("unexpected invalid scope filter: %s", invalid)
	}
	breakdownQuery := `SELECT
	    count(*) FILTER (WHERE NOT already_approved AND (` + approvalRiskRankExpr + `) = 2) AS high_count,
	    count(*) FILTER (WHERE NOT already_approved AND (` + approvalRiskRankExpr + `) = 1) AS medium_count,
	    count(*) FILTER (WHERE NOT already_approved AND (` + approvalRiskRankExpr + `) = 0) AS low_count
	  FROM (SELECT ` + approvalCountColumns + approvalListFrom + breakdownClause + `) rr`
	if err := rc.Tx.QueryRow(ctx, breakdownQuery, breakdownArgs...).Scan(&counts.High, &counts.Medium, &counts.Low); err != nil {
		return approvalCounts{}, err
	}
	return counts, nil
}

// handleListApprovals is GET /api/v1/approvals. Requires
// remediation:approve — see this file's own doc comment for why read and
// write share one capability here.
//
// Accepts the same shape of parameters incidents.go's handleListIncidents
// does, scoped to this queue:
//
//   - ?clusterId= (exact match)
//   - ?actionType= (one of remediation.AllActionTypes(); unrecognized is a
//     400, not a filter that silently matches nothing)
//   - ?riskLevel= (one of validApprovalRiskLevels; matches
//     EffectiveRiskLevel — see approvalRiskRankExpr — never the model's bare
//     declared risk_level, D11's own rule)
//   - ?alreadyApproved=true|false — which of this queue's two buckets to
//     return rows FROM. Defaults to "false" (the pending queue: the primary,
//     day-to-day use of this endpoint) — a deliberate narrowing from this
//     endpoint's old behavior of always returning both buckets mixed in one
//     array, which is what forced ApprovalsPage to do the split client-side
//     in the first place. `counts` below (Pending/Approved) always reports
//     BOTH bucket totals regardless of this parameter, so a caller paging
//     one bucket can still show the other's count without a second request.
//   - ?sort=waiting|risk|severity, ?direction=asc|desc (default
//     waiting/asc — longest-waiting-first, unchanged from before this
//     endpoint took a sort parameter at all)
//   - ?cursor=/?limit= — keyset pagination, never OFFSET, for the identical
//     reason incidents.go's own pagination doc comment gives: severity/risk/
//     first_seen are all live-mutating columns.
//
// `counts` is always present and always computed over the FULL matching
// scope, never the bounded page — see approvalCounts' own doc comment.
func (s *Server) handleListApprovals(w http.ResponseWriter, r *http.Request, rc *requestContext) {
	q := r.URL.Query()

	scopeClause, scopeArgs, invalid := approvalScopeFilter(r, true)
	if invalid != "" {
		writeProblem(w, http.StatusBadRequest, "https://argus.io/errors/invalid-request", "Invalid filter", invalid)
		return
	}

	alreadyApproved := false
	if raw := q.Get("alreadyApproved"); raw != "" {
		switch raw {
		case "true":
			alreadyApproved = true
		case "false":
			alreadyApproved = false
		default:
			writeProblem(w, http.StatusBadRequest, "https://argus.io/errors/invalid-request",
				"Invalid alreadyApproved", "alreadyApproved must be true or false")
			return
		}
	}

	sortKey := q.Get("sort")
	if sortKey == "" {
		sortKey = "waiting"
	}
	spec, ok := approvalSortSpecs[sortKey]
	if !ok {
		writeProblem(w, http.StatusBadRequest, "https://argus.io/errors/invalid-request",
			"Invalid sort key", "sort must be one of: "+strings.Join(approvalSortKeysSorted, ", "))
		return
	}
	direction := q.Get("direction")
	if direction == "" {
		direction = spec.DefaultDir
	}
	if direction != "asc" && direction != "desc" {
		writeProblem(w, http.StatusBadRequest, "https://argus.io/errors/invalid-request",
			"Invalid direction", `direction must be "asc" or "desc"`)
		return
	}
	sqlDir, cmp := "DESC", "<"
	if direction == "asc" {
		sqlDir, cmp = "ASC", ">"
	}

	limit, err := approvalPageLimit(q.Get("limit"))
	if err != nil {
		writeProblem(w, http.StatusBadRequest, "https://argus.io/errors/malformed-request", "Invalid limit", err.Error())
		return
	}

	query := "SELECT " + approvalListColumns
	if sortKey != "waiting" {
		query += ", (" + spec.Expr + ") AS sort_value"
	}
	query += approvalListFrom + scopeClause + approvalAlreadyApprovedClause(alreadyApproved)
	args := append([]any{}, scopeArgs...)

	if cursor := q.Get("cursor"); cursor != "" {
		if sortKey == "waiting" {
			cursorFirstSeen, cursorID, err := decodeIncidentCursor(cursor)
			if err != nil {
				writeProblem(w, http.StatusBadRequest, "https://argus.io/errors/malformed-request",
					"Invalid cursor", "cursor is not a valid page-continuation token")
				return
			}
			args = append(args, cursorFirstSeen, cursorID)
			query += fmt.Sprintf(" AND (incidents.first_seen, incidents.id) %s ($%d, $%d)", cmp, len(args)-1, len(args))
		} else {
			cursorID, cursorSortKey, cursorValue, err := decodeIncidentSortCursor(cursor)
			if err != nil || cursorSortKey != sortKey {
				writeProblem(w, http.StatusBadRequest, "https://argus.io/errors/malformed-request",
					"Invalid cursor", "cursor is not a valid page-continuation token for this sort")
				return
			}
			if spec.Kind == sortKindInt {
				n, err := strconv.ParseInt(cursorValue, 10, 64)
				if err != nil {
					writeProblem(w, http.StatusBadRequest, "https://argus.io/errors/malformed-request",
						"Invalid cursor", "cursor is not a valid page-continuation token")
					return
				}
				args = append(args, n, cursorID)
			} else {
				args = append(args, cursorValue, cursorID)
			}
			query += fmt.Sprintf(" AND (%s, incidents.id) %s ($%d, $%d)", spec.Expr, cmp, len(args)-1, len(args))
		}
	}

	args = append(args, limit)
	// incidents.id tiebreak: none of waiting/risk/severity are unique columns
	// (a storm re-sees many incidents at once; several legitimately share a
	// risk or severity), and a keyset cursor over a non-unique sort key
	// silently drops or repeats tied rows without it — incidents.go's own
	// handleListIncidents carries the identical tiebreak for the identical
	// reason.
	query += fmt.Sprintf(" ORDER BY %s %s, incidents.id %s LIMIT $%d", spec.Expr, sqlDir, sqlDir, len(args))

	rows, err := rc.Tx.Query(r.Context(), query, args...)
	if err != nil {
		logger.ErrorContext(r.Context(), "querying approvals failed", logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not list approvals", "")
		return
	}
	defer rows.Close()

	items := []approvalQueueItem{}
	var lastFirstSeen time.Time
	var lastID string
	var lastSortInt int64
	var lastSortText string
	for rows.Next() {
		if sortKey == "waiting" {
			item, firstSeen, scanErr := scanApprovalQueueRow(rows)
			if scanErr != nil {
				err = scanErr
				break
			}
			items = append(items, item)
			lastFirstSeen, lastID = firstSeen, item.IncidentID
		} else {
			item, sortInt, sortText, scanErr := scanApprovalQueueItemWithSortValue(rows, spec.Kind)
			if scanErr != nil {
				err = scanErr
				break
			}
			items = append(items, item)
			lastID, lastSortInt, lastSortText = item.IncidentID, sortInt, sortText
		}
	}
	if err != nil {
		logger.ErrorContext(r.Context(), "scanning an approval row failed", logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not list approvals", "")
		return
	}
	if err := rows.Err(); err != nil {
		logger.ErrorContext(r.Context(), "iterating the approval rows failed", logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not list approvals", "")
		return
	}

	for i := range items {
		items[i].ExecutionBlockedReason = s.remediationAgentBlockedReason(
			remediation.ActionType(items[i].Plan.ActionType), items[i].ClusterID, items[i].ClusterDisplayName)
	}

	resp := map[string]any{"approvals": items}
	// A full page might not be the last page; handing back a cursor costs one
	// extra empty request in the exact-multiple case, cheaper than a
	// COUNT(*) or a limit+1 fetch — same trade handleListIncidents makes.
	if len(items) == limit {
		if sortKey == "waiting" {
			resp["nextCursor"] = encodeIncidentCursor(lastFirstSeen, lastID)
		} else if spec.Kind == sortKindInt {
			resp["nextCursor"] = encodeIncidentSortCursor(lastID, sortKey, strconv.FormatInt(lastSortInt, 10))
		} else {
			resp["nextCursor"] = encodeIncidentSortCursor(lastID, sortKey, lastSortText)
		}
	}

	counts, err := approvalCountsFor(r.Context(), rc, r)
	if err != nil {
		logger.ErrorContext(r.Context(), "reading the approval counts failed", logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not count approvals", "")
		return
	}
	resp["counts"] = counts

	writeJSON(w, http.StatusOK, resp)
}

func scanApprovalQueueItem(row pgx.Row) (approvalQueueItem, error) {
	item, _, err := scanApprovalQueueRow(row)
	return item, err
}

// scanApprovalQueueRow is scanApprovalQueueItem's core implementation, with
// one difference: it also returns the row's own first_seen, and takes
// optional extra destination pointers appended after the fixed column list —
// PROJECT.md B167's handleListApprovals needs both, for a keyset cursor and
// for the extra "sort_value" column its query appends whenever ?sort= isn't
// the default "waiting" (see scanApprovalQueueItemWithSortValue below; this
// mirrors incidents.go's scanIncidentSummaryWithLastSeen/
// scanIncidentSummaryWithSortValue split for the identical reason). Kept as
// ONE function with the original's exact column list rather than two
// separately-maintained copies of this Scan call, which is exactly the kind
// of hand-duplicated list this codebase has already been burned by.
func scanApprovalQueueRow(row pgx.Row, extra ...any) (approvalQueueItem, time.Time, error) {
	var item approvalQueueItem
	var firstSeen, lastSeen, planCreatedAt time.Time
	var planID, actionType, targetGVK, targetName, riskLevel, gateOutcome, gateReason string
	var targetNamespace *string
	var paramsJSON []byte
	var reversible bool
	var confidence *float64
	var rootCauseJSON, causalChainJSON, ruledOutJSON []byte
	var supersededByURL *string

	dest := []any{&item.IncidentID, &item.ClusterID, &item.ClusterDisplayName, &item.Fingerprint,
		&item.Severity, &firstSeen, &lastSeen, &item.OccurrenceCount,
		&planID, &actionType, &targetGVK, &targetNamespace, &targetName, &paramsJSON,
		&reversible, &riskLevel, &gateOutcome, &gateReason, &planCreatedAt,
		&confidence, &rootCauseJSON, &causalChainJSON, &ruledOutJSON, &item.AlreadyApproved, &supersededByURL}
	dest = append(dest, extra...)
	if err := row.Scan(dest...); err != nil {
		return approvalQueueItem{}, time.Time{}, err
	}
	if supersededByURL != nil {
		item.SupersededByURL = *supersededByURL
	}

	item.FirstSeen = formatRFC3339(firstSeen)
	item.LastSeen = formatRFC3339(lastSeen)
	item.Plan = buildPlanView(planID, actionType, targetGVK, deref(targetNamespace), targetName, paramsJSON,
		reversible, riskLevel, gateOutcome, gateReason, formatRFC3339(planCreatedAt))
	item.Confidence = confidence
	item.CausalChain = []llm.CausalStep{}
	item.RuledOut = []llm.RuledOutHypothesis{}

	if len(causalChainJSON) > 0 {
		var chain []llm.CausalStep
		if err := json.Unmarshal(causalChainJSON, &chain); err == nil && chain != nil {
			item.CausalChain = chain
		}
	}
	if len(ruledOutJSON) > 0 {
		var ruledOut []llm.RuledOutHypothesis
		if err := json.Unmarshal(ruledOutJSON, &ruledOut); err == nil && ruledOut != nil {
			item.RuledOut = ruledOut
		}
	}

	if len(rootCauseJSON) > 0 {
		var stored rootCauseStored
		if err := json.Unmarshal(rootCauseJSON, &stored); err == nil {
			item.RootCauseStatement = stored.Statement
			item.CausalChainProvenance = stored.CausalChainProvenance
		}
	}
	return item, firstSeen, nil
}

// scanApprovalQueueItemWithSortValue is scanApprovalQueueRow's counterpart
// for every ?sort= key OTHER than "waiting": the row carries one extra
// trailing column (handleListApprovals' "sort_value", the ORDER BY
// expression's own value for this row), scanned into whichever of
// sortInt/sortText matches kind so the next page's cursor can be built from
// the EXACT value the ORDER BY used — never a value independently
// recomputed in Go, which could drift from the SQL expression it's supposed
// to match.
func scanApprovalQueueItemWithSortValue(rows pgx.Rows, kind incidentSortKind) (item approvalQueueItem, sortInt int64, sortText string, err error) {
	if kind == sortKindInt {
		item, _, err = scanApprovalQueueRow(rows, &sortInt)
	} else {
		item, _, err = scanApprovalQueueRow(rows, &sortText)
	}
	return item, sortInt, sortText, err
}

// latestRecommendationForIncident looks up the most recent
// remediation_recommendations row for one incident — shared by
// handleApproveIncident/handleRejectIncident, both of which need the plan's
// id (to record which plan the decision is about) and cluster_id (to
// denormalize onto the remediation_approval_decisions row, per this
// codebase's RLS convention).
//
// The same sibling_of_recommendation_id tiebreak as approvalQueueQuery,
// and for the same reason: a paired route's two rows share an identical
// created_at, so without it this call — the ONE place that decides which
// plan an approve/reject actually acts on — could resolve to either half of
// a pair non-deterministically. This still does not let both halves be
// decided independently (neither this function nor its two callers take a
// planId), only makes the single decision reproducibly land on the pair's
// primary row.
func latestRecommendationForIncident(ctx context.Context, tx pgx.Tx, incidentID string) (planID, clusterID string, err error) {
	err = tx.QueryRow(ctx,
		`SELECT id, cluster_id FROM remediation_recommendations
		  WHERE incident_id = $1
		  ORDER BY created_at DESC, (sibling_of_recommendation_id IS NULL) DESC LIMIT 1`, incidentID,
	).Scan(&planID, &clusterID)
	return planID, clusterID, err
}

// incidentState looks up one incident's current state — used by both
// approve/reject to enforce "only an incident actually AwaitingApproval can
// be decided on" before doing anything else.
func incidentState(ctx context.Context, tx pgx.Tx, incidentID string) (string, error) {
	var state string
	err := tx.QueryRow(ctx, `SELECT state FROM incidents WHERE id = $1`, incidentID).Scan(&state)
	return state, err
}

// approveRejectResponse is the shared response shape for both
// POST .../approve and POST .../reject.
type approveRejectResponse struct {
	IncidentID    string `json:"incidentId"`
	PlanID        string `json:"planId"`
	Verdict       string `json:"verdict"`
	IncidentState string `json:"incidentState"`
	Message       string `json:"message"`
}

// planApprovalGate is the extra authorization one action type's approval
// requires, plus a plain-language description of what approving it actually
// does — used to build a 403 that names both the missing capability and the
// reason it applies, rather than a bare "forbidden".
//
// effect is a function of the plan, not a static string, because of
// PatchField (BUGS.md 78): every other action type's side effect is fully
// described by its NAME plus a fixed caveat, but PatchField's name says
// nothing about which field it touches — that varies per plan — so its entry
// needs the plan's own params to say anything honest. The other five entries
// below ignore the argument; only PatchField's reads it.
type planApprovalGate struct {
	capability string
	effect     func(plan remediation.RemediationPlan) string
}

// planApprovalGates maps each action type to the execution capability approving
// it requires IN ADDITION TO remediation:approve.
//
// BUG FIX (2026-08-21): POST /api/v1/incidents/{id}/approve is registered with
// requireCapability(CapRemediationApprove) alone (server.go), which was right
// while approving only ever recorded a decision — but since
// internal/execution landed, approving a ScaleDeployment/
// RestartPod plan issues a REAL mutating Patch against the customer's cluster.
// Meanwhile authz.CapRemediationExecInplace and CapRemediationExecPR existed in
// the catalogue (internal/authz/permissions.go) and were referenced by no route
// anywhere, so lld/02-authz-spec.md §6's headline custom-capability-set pattern
// — "this principal may approve PRs but never touch a cluster in place", the
// one §6 calls out as a genuine differentiator — could not be expressed: a
// grant of exactly {remediation:approve, remediation:execute:pr} still
// triggered a live scale/restart.
//
// The check has to key off the PLAN's action type, not the route: one route
// approves all three action types, and only the action type says which channel
// the approval authorizes. A closed table rather than an "everything else needs
// nothing extra" branch, on purpose — this bug happened precisely because an
// execution path was added under a gate that didn't know about it, so an action
// type with no entry here is refused outright instead of being silently
// ungated, mirroring remediation.validActionTypes' own closed-set discipline.
// staticEffect adapts a plain description to planApprovalGate.effect's
// func(plan) string shape for the five action types whose side effect does not
// depend on that plan's own params — everything except PatchField, whose
// entry below builds its own string instead of calling this.
func staticEffect(s string) func(remediation.RemediationPlan) string {
	return func(remediation.RemediationPlan) string { return s }
}

var planApprovalGates = map[remediation.ActionType]planApprovalGate{
	// All three of these end in a live Patch against the cluster
	// (internal/execution's ExecuteApprovedPlan), which is exactly what
	// remediation:execute:inplace names.
	remediation.ActionScaleDeployment: {
		capability: authz.CapRemediationExecInplace,
		effect:     staticEffect("scales the target workload in the cluster in place"),
	},
	remediation.ActionRestartPod: {
		capability: authz.CapRemediationExecInplace,
		effect:     staticEffect("restarts the target workload in the cluster in place"),
	},
	remediation.ActionPatchResourceLimits: {
		capability: authz.CapRemediationExecInplace,
		// Deliberately spells out the side effect the action's NAME does not:
		// changing a pod template rolls every pod of the workload. An approver
		// reading "patch resource limits" could reasonably expect an in-place
		// adjustment of a running container (which is what Kubernetes' own
		// in-place resize does, and is not what this is); a 403 or a
		// confirmation dialog quoting this string should not be the first place
		// they learn that approving it restarts the workload.
		effect: staticEffect("changes the named container's CPU/memory requests or limits in the cluster in place, which rolls every pod of the target workload"),
	},
	remediation.ActionRevertContainerImage: {
		capability: authz.CapRemediationExecInplace,
		// Says the two things the action's name does not, both of which an
		// approver needs BEFORE they click rather than after. It rolls every pod
		// (same as any pod-template change), and it undoes a release: whatever
		// the newer image contained — a security fix, a fix for a different
		// incident — goes with it. The image itself is deliberately absent from
		// this string: it is not known until approval time, when the hub reads
		// it out of the workload's own rollout history (see
		// internal/execution's resolvePreviousImage), and a capability-denial
		// message is not the place to promise a value that has not been
		// resolved yet.
		effect: staticEffect("reverts the named container to the image from the workload's previous revision in the cluster in place, which rolls every pod of the target workload and undoes whatever the newer image contained"),
	},
	// PatchField (BUGS.md 78) ends in the same kind of live Patch as the three
	// above — patch_field, dispatched through the same execution.ToolForAction
	// table (internal/execution) — so it is gated on the same
	// remediation:execute:inplace capability. What makes this entry different
	// is the effect string itself: PatchField's name says nothing about which
	// field it touches (that is the whole point of the action — see
	// patchfield.go's header comment), so unlike the four static entries above,
	// an approver reading a bare "patches a field in place" would learn nothing
	// a generic patch action couldn't have told them. Naming the actual field
	// path and value is the one piece of information that turns this refusal
	// into something they can act on, and it is only available per-plan.
	remediation.ActionPatchField: {
		capability: authz.CapRemediationExecInplace,
		effect: func(plan remediation.RemediationPlan) string {
			if params, ok := plan.Params.(remediation.PatchFieldParams); ok && params.FieldPath != "" {
				return fmt.Sprintf("sets %s to %q on the target object in the cluster in place — the specific field this plan changes, since PatchField's name alone does not say which one", params.FieldPath, params.NewValue)
			}
			// Params were not the expected type (a malformed or hand-edited row) —
			// fall back to a description that is still true, rather than
			// panicking or naming a field/value that isn't there.
			return "patches one field on the target object in the cluster in place, from the reviewed allowlist in internal/remediation/patchfield.go"
		},
	},
	// OpenPR never touches a cluster — approving it opens a pull request and
	// leaves the cluster untouched until somebody merges — so it is gated on the
	// PR channel's own capability and never on the in-place one.
	// This is what makes the "may approve PRs, never in place" grant real: a
	// principal holding approve + execute:pr satisfies this entry and fails
	// the two in-place entries above.
	remediation.ActionOpenPR: {
		capability: authz.CapRemediationExecPR,
		effect:     staticEffect("authorizes the pull-request remediation channel"),
	},
	// StructuredPatch (BACKLOG.md F11's offline-testable slice) would end in
	// the same kind of live Patch as PatchField above, gated on the same
	// capability — this entry exists so TestPlanApprovalGatesCoverEveryActionType
	// (BUGS.md 78's own regression guard) stays a real exhaustiveness check
	// covering every member of remediation.validActionTypes, not a hand-copied
	// list that would have missed this action type exactly the way it missed
	// PatchField before 78 was fixed.
	//
	// This entry does not make StructuredPatch reachable: nothing in this
	// codebase ever produces a StructuredPatch recommendation row (see
	// ActionStructuredPatch's own doc comment in internal/remediation/plan.go
	// for the three independent reasons — no system prompt, no wire-parser
	// case, no agent-side tool), so this gate and execution.ToolForAction's
	// matching entry below are dead code in production today, exercised only
	// by tests that construct a plan of this type directly. Present anyway,
	// because BUGS.md 78 is exactly the failure mode of an action type that
	// exists in the Go enum without one, and this codebase should not need to
	// relearn that lesson a second time for a second action type.
	remediation.ActionStructuredPatch: {
		capability: authz.CapRemediationExecInplace,
		effect: func(plan remediation.RemediationPlan) string {
			params, ok := plan.Params.(remediation.StructuredPatchParams)
			if !ok || len(params.Ops) == 0 {
				return "patches several fields on the target object in the cluster in place, in one atomic patch, from the reviewed allowlist in internal/remediation/patchfield.go"
			}
			parts := make([]string, 0, len(params.Ops))
			for _, op := range params.Ops {
				parts = append(parts, fmt.Sprintf("%s to %q", op.FieldPath, op.NewValue))
			}
			return fmt.Sprintf("sets %d field(s) on the target object in the cluster in place, in one atomic patch — the specific fields this plan changes: %s",
				len(parts), strings.Join(parts, "; "))
		},
	},
	// AnnotateResource/LabelResource end in the same kind of live Patch as
	// PatchField above (annotate_resource/label_resource, dispatched through
	// execution.ToolForAction), so they share the same
	// in-place capability. Same reasoning as PatchField's own entry for why
	// the effect string is dynamic rather than static: the action's name
	// says nothing about which key or value, and that is the one piece of
	// information an approver needs that a generic description could not
	// give.
	remediation.ActionAnnotateResource: {
		capability: authz.CapRemediationExecInplace,
		effect: func(plan remediation.RemediationPlan) string {
			if params, ok := plan.Params.(remediation.AnnotateResourceParams); ok && params.Key != "" {
				return fmt.Sprintf("sets the annotation %s to %q on the target object in the cluster in place", params.Key, params.Value)
			}
			return "sets one annotation on the target object in the cluster in place, from the reviewed allowlist in internal/remediation/annotatelabel.go"
		},
	},
	remediation.ActionLabelResource: {
		capability: authz.CapRemediationExecInplace,
		effect: func(plan remediation.RemediationPlan) string {
			if params, ok := plan.Params.(remediation.LabelResourceParams); ok && params.Key != "" {
				return fmt.Sprintf("sets the label %s to %q on the target object in the cluster in place", params.Key, params.Value)
			}
			return "sets one label on the target object in the cluster in place, from the reviewed allowlist in internal/remediation/annotatelabel.go"
		},
	},
	// DeleteResource is gated on the same in-place capability — there is no
	// separate "delete" capability, because RBAC (the ClusterRole's own
	// `delete` verb, opt-in with the rest of remediate.enabled) is what
	// actually bounds who this identity may delete, and DESIGN.md §10.5's
	// own approval-integrity requirement is "requireApprovers >= 1", not a
	// separate capability tier. The effect string states the
	// irreversibility explicitly and unconditionally, per that same
	// section: "the irreversibility stated in the approval UI".
	remediation.ActionCordonNode: {
		capability: authz.CapRemediationExecInplace,
		effect: func(plan remediation.RemediationPlan) string {
			if p, ok := plan.Params.(remediation.CordonNodeParams); ok && !p.Unschedulable {
				return "makes the node schedulable again; new pods may be placed on it"
			}
			return "stops new pods being scheduled on the node for the whole cluster; pods already on it keep running"
		},
	},
	remediation.ActionDrainNode: {
		capability: authz.CapRemediationExecInplace,
		effect: func(plan remediation.RemediationPlan) string {
			s := "cordons the node and evicts every pod on it except DaemonSet and static pods; disruption budgets are respected, and a workload with no ready replica elsewhere is unavailable until its replacements are ready. Not undoable: the pods are recreated elsewhere, not put back"
			if p, ok := plan.Params.(remediation.DrainNodeParams); ok && p.DeleteEmptyDirData {
				s += ". emptyDir data on the node is lost"
			}
			return s
		},
	},
	remediation.ActionDeleteResource: {
		capability: authz.CapRemediationExecInplace,
		effect:     staticEffect("permanently deletes the target object from the cluster — this cannot be undone by ARGUS: a pre-flight snapshot restores an object's spec, never its identity (uid) or any PersistentVolumeClaim data, so every ownerReference into the deleted object would dangle. Recovery, if any, depends entirely on whatever recreates the object afterwards (its controller, GitOps, or a human)"),
	},
	// CreateResource is gated on the same in-place capability as every other
	// live-cluster mutation this table lists — there is no separate "create"
	// capability, the same reasoning DeleteResource's own entry gives for why
	// there is no separate "delete" one: RBAC (the ClusterRole's own narrow
	// `create` verb on configmaps, opt-in with the rest of remediate.enabled)
	// is what actually bounds what this identity may create. The effect
	// string names the exact data keys being set, for the identical reason
	// AnnotateResource/LabelResource's entries name the exact key/value: the
	// action's name alone says nothing about what content a human is being
	// asked to approve.
	remediation.ActionCreateResource: {
		capability: authz.CapRemediationExecInplace,
		effect: func(plan remediation.RemediationPlan) string {
			if params, ok := plan.Params.(remediation.CreateResourceParams); ok && len(params.Data) > 0 {
				keys := make([]string, 0, len(params.Data))
				for k := range params.Data {
					keys = append(keys, k)
				}
				sort.Strings(keys)
				return fmt.Sprintf("creates a new %s in the cluster with data key(s): %s — this object does not exist today; ARGUS refuses to execute if one is found to exist by the time this is approved", plan.TargetGVK, strings.Join(keys, ", "))
			}
			return "creates a new object in the cluster, from the reviewed allowlist in internal/remediation/createresource.go"
		},
	},
}

// approveIncidentRequest is POST .../approve's request body. Unlike
// rejectIncidentRequest's mandatory Reason, every field here is optional AND
// the body as a whole may be absent entirely: approving with no body at all
// has always been this endpoint's calling convention (scripts/smoke-test.sh
// still calls it exactly that way), and a guardrail whose default is "refuse"
// needs no body to express that default.
//
// ConfirmScaleFromZero is the operator's explicit statement of intent for the
// one thing the execution layer refuses to decide alone: scaling a workload
// that is LIVE at 0 replicas back up (checkScaleFromZero in
// internal/execution carries the full reasoning). It is deliberately a
// per-request flag rather than a tenant setting, a role, or a policy knob —
// the point is that a human states the intent for THIS workload at THIS
// moment, so it cannot be switched on once and then quietly apply to every
// future plan, least of all an auto-approved one.
//
// ConfirmGitOpsManaged is the same idea for the second thing the execution
// layer refuses to decide alone: patching an object whose spec is owned by a
// Helm release or an Argo CD/Flux controller, where the fix is undone by the
// next reconcile or upgrade (checkGitOpsPrecedence). Same per-request
// reasoning — an operator states "yes, I know this is a stop-gap" for this
// object now, and cannot pre-arm it for everything.
//
// Both are separate flags rather than one generic "confirmAnything": an
// operator who intends to turn a switched-off workload back on has not thereby
// agreed to have their fix silently reverted, and vice versa. A single flag
// would let confirming one guardrail waive the other.
type approveIncidentRequest struct {
	ConfirmScaleFromZero bool `json:"confirmScaleFromZero"`
	ConfirmGitOpsManaged bool `json:"confirmGitOpsManaged"`

	// ConfirmationToken is the token a guardrail's own refusal minted
	// (internal/authz.GuardrailConfirmationIssuer, WORKLOG §97 G5). Set the
	// boolean above AND echo the matching token here — a boolean with no
	// token, or a token for the wrong guardrail or the wrong plan, is treated
	// as if the boolean were never set, because the whole point of the token
	// is that the boolean alone no longer proves anything. See
	// execution.ExecuteApprovedPlan's use of it for exactly what "matching" checks.
	ConfirmationToken string `json:"confirmationToken"`
}

// decodeApproveRequest reads that optional body. An empty body decodes to the
// zero value — every guardrail off, which is the safe direction — while
// malformed JSON is an error the caller turns into a 400 rather than quietly
// reading it as "nothing": a request that tried to say something and failed
// is not a request that said nothing, and silently treating the two the same
// is how an operator's intended confirmation could vanish into a default.
// (Here that would fail closed anyway; the discipline is what matters, since
// this struct will grow fields where the safe default is less obvious.)
//
// Split out of the handler so the empty-body-means-refuse contract is
// unit-testable without a live Postgres — everything past this point in
// handleApproveIncident needs one.
func decodeApproveRequest(body io.Reader) (approveIncidentRequest, error) {
	var req approveIncidentRequest
	if err := json.NewDecoder(body).Decode(&req); err != nil && !errors.Is(err, io.EOF) {
		return approveIncidentRequest{}, err
	}
	return req, nil
}

// handleApproveIncident is POST /api/v1/incidents/{id}/approve. Requires
// remediation:approve (the route's own gate) AND the approved plan's own
// execution capability — see planApprovalGates. What approving actually does
// depends on the plan: ScaleDeployment/RestartPod/PatchResourceLimits/
// RevertContainerImage are
// signed and executed
// against the cluster right here (internal/execution's ExecuteApprovedPlan,
// which moves the incident AwaitingApproval -> Executing -> Validating or
// Failed), while OpenPR keeps the original execution-free behavior of
// recording the decision and leaving the incident AwaitingApproval. See this
// file's own doc comment for the four independent controls that must all hold
// before anything is executed.
func (s *Server) handleApproveIncident(w http.ResponseWriter, r *http.Request, rc *requestContext) {
	incidentID := r.PathValue("id")
	ctx := r.Context()

	req, err := decodeApproveRequest(r.Body)
	if err != nil {
		writeProblem(w, http.StatusBadRequest, "https://argus.io/errors/malformed-request", "Malformed request body", err.Error())
		return
	}

	state, err := incidentState(ctx, rc.Tx, incidentID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			writeProblem(w, http.StatusNotFound, "https://argus.io/errors/not-found", "Incident not found", "")
			return
		}
		logger.ErrorContext(ctx, "looking up the incident to approve failed", logging.IncidentID(incidentID), logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not look up incident", "")
		return
	}
	if state != orchestrator.StateAwaitingApproval {
		writeProblem(w, http.StatusConflict, "https://argus.io/errors/invalid-state",
			"Incident is not awaiting approval", wrongStateForApprovalDetail(state, "approved"))
		return
	}

	planID, clusterID, err := latestRecommendationForIncident(ctx, rc.Tx, incidentID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			// Should not be reachable — orchestrator.ApplyAnalysisResult
			// only ever sets AwaitingApproval in the same transaction it
			// persists the plan that led to it. Logged loudly rather than
			// silently 404ing, since this would indicate a real bug
			// elsewhere (a plan was deleted, or AwaitingApproval was set
			// through some other path).
			logger.ErrorContext(ctx, "incident is AwaitingApproval but has no remediation_recommendations row", logging.IncidentID(incidentID))
			writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "No plan found for this incident", "")
			return
		}
		logger.ErrorContext(ctx, "looking up the plan to approve failed", logging.IncidentID(incidentID), logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not look up plan", "")
		return
	}

	var alreadyApproved bool
	if err := rc.Tx.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM remediation_approval_decisions WHERE recommendation_id = $1 AND verdict = 'approved')`,
		planID).Scan(&alreadyApproved); err != nil {
		logger.ErrorContext(ctx, "checking for a prior approval decision on this plan failed", slog.String("plan_id", planID), logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not check prior approval", "")
		return
	}
	if alreadyApproved {
		writeProblem(w, http.StatusConflict, "https://argus.io/errors/invalid-state", "This plan has already been approved", "")
		return
	}

	// Superseded by a pull request ARGUS itself opened (migration 000049).
	//
	// Refused rather than warned about, because the first live GitOps run showed
	// what approving one of these can do: the incident's in-place plan was
	// RevertContainerImage, the pull request fixing the tag at source had been
	// merged and synced, and a preflight showed that approving the plan would
	// now set the image BACK to the broken tag. RevertContainerImage resolves
	// "the previous revision" from live rollout history at approval time, so once
	// the fix landed the previous revision was the bad one and the plan meant the
	// opposite of what it had been written to mean.
	//
	// A 409 with the pull request's URL, because the operator's real question at
	// this moment is "then what should I look at instead", and the answer is a
	// link. Nothing here can be overridden: there is no confirmation that makes
	// re-applying a superseded change correct, and if the source fix was wrong
	// the honest path is a fresh analysis against the current state, not the
	// re-approval of a plan derived from a world that no longer exists.
	var supersededBy *string
	if err := rc.Tx.QueryRow(ctx,
		`SELECT superseded_by_url FROM remediation_recommendations WHERE id = $1`, planID).Scan(&supersededBy); err != nil {
		logger.ErrorContext(ctx, "reading whether the plan has been superseded failed", slog.String("plan_id", planID), logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not check whether this plan is still current", "")
		return
	}
	if supersededBy != nil && *supersededBy != "" {
		writeProblem(w, http.StatusConflict, "https://argus.io/errors/plan-superseded",
			"This plan has been superseded by a pull request",
			fmt.Sprintf("ARGUS has already proposed the durable fix for this incident at its source: %s. This in-place plan was derived from the cluster's state before that, so applying it now could undo the source fix rather than repeat it — a revert-to-previous-image plan, for instance, means the opposite once a newer image has been synced. Review the pull request instead. If it is wrong, re-analyse this incident so a new plan is derived from the current state.", *supersededBy))
		return
	}

	plan, err := execution.LoadRecommendationPlan(ctx, rc.Tx, planID)
	if err != nil {
		logger.ErrorContext(ctx, "loading the plan to approve failed", logging.IncidentID(incidentID), slog.String("plan_id", planID), logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not load the plan for this incident", "")
		return
	}

	// The route's remediation:approve gate is necessary but NOT sufficient:
	// approving this plan also authorizes a specific execution channel, and
	// which one depends on the plan itself. See planApprovalGates.
	gate, ok := planApprovalGates[plan.ActionType]
	if !ok {
		// Not reachable today: orchestrator.ReconstructPlan (via
		// execution.LoadRecommendationPlan above) already rejects an unrecognized action
		// type. Fail closed anyway rather than execute something no capability
		// covers — that combination is the bug this table exists to prevent.
		logger.ErrorContext(ctx, "plan has an action type with no approval gate defined; refusing to execute it",
			slog.String("plan_id", planID), slog.String("action_type", string(plan.ActionType)))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal",
			"Could not determine which capability approving this plan requires", "")
		return
	}
	// Scope-aware, not just capability-aware (BACKLOG S1). Holding
	// remediation:execute:inplace on one cluster is not holding it on another, and
	// until this check existed a grant the UI displayed as "Cluster: rke2"
	// authorised the whole fleet. The route-level requireCapability above cannot do
	// this — it does not know which cluster the request touches — so the per-plan
	// gate is where it belongs.
	allowed, err := authz.HasCapabilityForCluster(ctx, rc.Tx, rc.Grants, gate.capability, clusterID)
	if err != nil {
		logger.ErrorContext(ctx, "resolving cluster-scoped capability failed", logging.ClusterID(clusterID), logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not resolve the scope of your permissions", "")
		return
	}
	if !allowed {
		s.recordCapabilityDenial(ctx, rc, gate.capability, clientIP(r))
		writeProblem(w, http.StatusForbidden, "https://argus.io/errors/scope-denied",
			"Missing required capability",
			fmt.Sprintf("approving this %s plan %s, which requires capability %q in addition to %q — you hold %q but not %q",
				plan.ActionType, gate.effect(plan), gate.capability, authz.CapRemediationApprove,
				authz.CapRemediationApprove, gate.capability))
		return
	}

	// OpenPR (GitOps) execution is explicitly out of scope for this
	// increment (see internal/execution's header comment) —
	// this keeps the exact original, execution-free behavior: the decision
	// is recorded, the incident stays AwaitingApproval, and the response
	// says so plainly. Every other action type goes through the real
	// execution path below instead.
	if plan.ActionType == remediation.ActionOpenPR {
		// Approving an OpenPR plan now OPENS THE PULL REQUEST. It used to record
		// the decision and do nothing, returning a message that said the route
		// was "not implemented in this build" — which stopped being true once
		// pull requests were being opened, merged and synced, and left the model's
		// proposal as something a human had to relay by hand to another endpoint.
		//
		// Every security refusal is still made, and made in the same place the
		// human-driven endpoint makes them: inside gitops.ProposeFieldChange.
		// This path adds no exemption of its own.
		params, ok := plan.Params.(remediation.OpenPRParams)
		if !ok {
			writeProblem(w, http.StatusUnprocessableEntity, "https://argus.io/errors/invalid-state",
				"This plan is not a usable repository change",
				fmt.Sprintf("the stored plan's params are %T rather than an OpenPR params shape, so there is no field and value to propose", plan.Params))
			return
		}
		resp, err := s.approveByOpeningPullRequest(ctx, r, rc, incidentID, planID, clusterID, plan, params)
		if err != nil {
			// BACKLOG.md G6: a concurrent request already decided this exact
			// plan (approved or rejected) while this one was still checking —
			// a clean 409 naming what happened, not the generic
			// repository-change-refused 422 below, which would misdescribe a
			// concurrency conflict as a problem with the repository.
			var alreadyDecided *execution.ErrPlanAlreadyDecided
			if errors.As(err, &alreadyDecided) {
				writeProblem(w, http.StatusConflict, "https://argus.io/errors/plan-already-decided",
					"This plan has already been decided", alreadyDecided.Detail)
				return
			}
			// A refusal here is almost always about the repository — unpinned
			// revision, a file declared in several places, a forbidden path — and
			// each of those messages is written to be acted on, so it is passed
			// through rather than replaced with a generic failure. Nothing has
			// been changed in any repository when this fires: the first
			// irreversible call inside Propose is creating the branch, and every
			// refusal precedes it.
			writeProblem(w, http.StatusUnprocessableEntity, "https://argus.io/errors/repository-change-refused",
				"The pull request could not be opened", err.Error())
			return
		}
		writeJSON(w, http.StatusOK, resp)
		return
	}

	if !s.gw.IsConnected(clusterID) {
		writeProblem(w, http.StatusServiceUnavailable, "https://argus.io/errors/cluster-unreachable",
			"Cluster not connected",
			"This cluster has no live agent connection right now, so this plan cannot be executed. Nothing has been recorded or changed — try again once the cluster reconnects.")
		return
	}
	// The cluster is connected, but only the remediation agent can write.
	// Refused here, before anything is signed or recorded, rather than left to
	// fail at the dry run with the gateway's id-only wording — the same
	// sentence GET /approvals already showed beside the disabled button.
	if reason := s.remediationAgentBlockedReason(plan.ActionType, clusterID, clusterDisplayName(ctx, rc.Tx, clusterID)); reason != "" {
		writeProblem(w, http.StatusConflict, "https://argus.io/errors/no-remediation-agent",
			"This plan cannot execute", reason+" Nothing was executed and the incident is still awaiting approval.")
		return
	}

	// From here on the work must survive the client going away. net/http
	// cancels r.Context() the instant the connection closes — not when this
	// handler next looks — and an already-cancelled context makes every pgx
	// operation fail immediately (proved against a live Postgres for BUGS.md
	// 89, see analyze_detach_db_test.go). Undetached, a disconnect between the
	// AwaitingApproval -> Executing commit and the outcome write meant nothing
	// ever recorded what the cluster did, and the incident was left in
	// Executing, which nothing reconciled.
	//
	// Detached but bounded, the same shape handleAnalyzeIncident already uses:
	// execution.WorkLimit is a safety net over a sequence that already has its
	// own much shorter timeouts, so "detached from the request" can never mean
	// "unbounded". The work stays SYNCHRONOUS — this handler still returns the
	// real outcome — so rc.Tx, and with it the per-target lock
	// execution.ExecuteApprovedPlan takes on it, is held for exactly as long as it was
	// before.
	workCtx, cancelWork := context.WithTimeout(context.WithoutCancel(ctx), execution.WorkLimit)
	defer cancelWork()

	resp, err := s.exec().ExecuteApprovedPlan(workCtx, scopeOf(rc), incidentID, planID, clusterID, plan,
		execution.Overrides{ScaleFromZero: req.ConfirmScaleFromZero, GitOpsManaged: req.ConfirmGitOpsManaged, Token: req.ConfirmationToken},
		humanActor(rc, r))
	if err != nil {
		// workCtx here too: writePreparePlanExecutionError's own job is to
		// RECORD the refusal (recordPolicyRefusal, its own transaction), and a
		// policy refusal that goes unrecorded because the operator closed the
		// tab is the same class of silence this detachment exists to remove.
		s.writePreparePlanExecutionError(workCtx, rc, r, w, incidentID, planID, clusterID, plan.ActionType, err)
		return
	}
	// The same documented shape as the pull-request path and reject
	// (ApprovalDecisionResponse), not execution.Result as-is.
	writeJSON(w, http.StatusOK, approveRejectResponse{
		IncidentID:    incidentID,
		PlanID:        planID,
		Verdict:       "approved",
		IncidentState: resp.IncidentState,
		Message:       resp.Message,
	})
}

// writePreparePlanExecutionError classifies an execution.ExecuteApprovedPlan failure
// into its HTTP response — split out of handleApproveIncident so the
// classification itself (which sentinel maps to which status/problem type)
// is a plain function a unit test can drive directly with a synthetic
// error, rather than only being reachable through the full approve request
// (live DB, gateway, transaction) the way it was before. Behaviour is
// unchanged; this is the same dispatch, only callable on its own.
//
// BACKLOG.md L5: every one of the eight execution.PreparePlan pre-flight sentinels
// below is the hub actively refusing a remediation on policy grounds
// BEFORE a human's reject ever happens — and until this fix, none of them
// left any trace in audit_events, so the whole class of event was
// invisible to Insights, the audit trail, and any future autonomy-readiness
// query. Each sentinel branch now also calls recordPolicyRefusal — its own,
// separate, best-effort transaction (see that function's doc comment for
// why: writeProblem below always answers >= 400, and requireAuth's wrapper
// rolls rc.Tx back for any >= 400 response, so recording this on rc.Tx would
// be silently discarded exactly like a capability denial would be). rc may
// be nil here (TestWritePreparePlanExecutionError's synthetic-error cases
// construct this function's dependencies directly, without a live
// request/DB) — recordPolicyRefusal treats that as "nothing to record" and
// returns immediately, matching how a DB-free classification test expects
// the response to be unaffected either way.
func (s *Server) writePreparePlanExecutionError(ctx context.Context, rc *requestContext, r *http.Request, w http.ResponseWriter, incidentID, planID, clusterID string, actionType remediation.ActionType, err error) {
	// The scale-from-zero guardrail gets its own status and problem type
	// rather than the generic 502 below, for two reasons. It is not a
	// failed execution attempt — nothing was signed, recorded or sent, the
	// incident is untouched at AwaitingApproval, and this exact request
	// succeeds if repeated with the confirmation — so 409 (the same status
	// this handler already uses for "the current state conflicts with what
	// you asked for") is the honest answer, not 502 Bad Gateway, which
	// blames the cluster for a decision the hub made. And a distinct
	// `type` is what lets the UI offer the one extra deliberate click
	// (ApprovalsPage) structurally, instead of string-matching a detail
	// message that will be reworded.
	if errors.Is(err, execution.ErrScaleFromZeroRefused) {
		s.recordPolicyRefusal(ctx, rc, r, clusterID, incidentID, planID, actionType, "scale-from-zero-refused", err)
		s.writeGuardrailRefusal(ctx, w, planID, execution.GuardrailScaleFromZero,
			"https://argus.io/errors/scale-from-zero-refused", "Refusing to scale this workload up from zero", err.Error())
		return
	}
	// Same shape, different guardrail — a distinct type so the UI offers the
	// matching confirmation rather than the wrong one. Two guardrails with
	// one problem type would let a "yes, turn it back on" click silently
	// waive "yes, I accept this will be reverted".
	if errors.Is(err, execution.ErrGitOpsManagedRefused) {
		s.recordPolicyRefusal(ctx, rc, r, clusterID, incidentID, planID, actionType, "gitops-managed-refused", err)
		s.writeGuardrailRefusal(ctx, w, planID, execution.GuardrailGitOpsManaged,
			"https://argus.io/errors/gitops-managed-refused", "Refusing to patch an object whose source of truth is elsewhere", err.Error())
		return
	}
	// BUGS.md 95: these four are the same "we understood perfectly and are
	// declining, nothing was signed/sent/recorded" class as the two
	// guardrails above — an execution.PreparePlan pre-flight check refused the plan
	// before execution.ExecuteApprovedPlan ever touched the agent or cluster, so 409
	// is the honest status, not the 502 below that blames the cluster for
	// a decision the hub made. Unlike the two guardrails, none of these
	// four has a confirm-and-retry path: the plan is unsafe on its own
	// terms (an implausible replica jump, a resource change that fails a
	// live-state bound, a container that does not exist on the target, a
	// revert with no well-defined previous image), and resubmitting it
	// unchanged will fail identically every time — so plain writeProblem
	// at 409, no guardrailTokens confirmation token to mint.
	if errors.Is(err, execution.ErrScaleBoundRefused) {
		s.recordPolicyRefusal(ctx, rc, r, clusterID, incidentID, planID, actionType, "scale-bound-refused", err)
		writeProblem(w, http.StatusConflict, "https://argus.io/errors/scale-bound-refused",
			"Refusing an implausible scale target", err.Error())
		return
	}
	if errors.Is(err, execution.ErrResourceLimitsBoundRefused) {
		s.recordPolicyRefusal(ctx, rc, r, clusterID, incidentID, planID, actionType, "resource-limits-bound-refused", err)
		writeProblem(w, http.StatusConflict, "https://argus.io/errors/resource-limits-bound-refused",
			"Refusing this resource limits change", err.Error())
		return
	}
	// PROJECT.md B161: a CreateResource plan whose own Data contradicts the
	// hub's recorded investigation evidence. Same class as its siblings above
	// — understood perfectly, declined, nothing signed, sent or recorded — so
	// the same 409 and its own problem type rather than the generic 502,
	// which would read as the cluster having refused a change ARGUS
	// attempted. No confirmation token: a value that disagrees with what was
	// actually observed does not become correct by an operator confirming
	// intent (see execution.ErrCreateResourceContradictsEvidence's own doc comment).
	if errors.Is(err, execution.ErrCreateResourceContradictsEvidence) {
		s.recordPolicyRefusal(ctx, rc, r, clusterID, incidentID, planID, actionType, "create-resource-contradicts-evidence", err)
		writeProblem(w, http.StatusConflict, "https://argus.io/errors/create-resource-contradicts-evidence",
			"Refusing a change whose values contradict the evidence", err.Error())
		return
	}
	if errors.Is(err, execution.ErrContainerNotInPodTemplate) {
		s.recordPolicyRefusal(ctx, rc, r, clusterID, incidentID, planID, actionType, "container-not-found", err)
		writeProblem(w, http.StatusConflict, "https://argus.io/errors/container-not-found",
			"Target container not found", err.Error())
		return
	}
	if errors.Is(err, execution.ErrImageRevertRefused) {
		s.recordPolicyRefusal(ctx, rc, r, clusterID, incidentID, planID, actionType, "image-revert-refused", err)
		writeProblem(w, http.StatusConflict, "https://argus.io/errors/image-revert-refused",
			"No well-defined previous image to revert to", err.Error())
		return
	}
	// BUGS.md 101: the same "understood perfectly and are declining, nothing
	// signed/sent/recorded" class as the five above, for two execution.PreparePlan
	// refusals added on 2026-08-25 (two days before 95's fix pass) that
	// hadn't gotten the sentinel treatment yet. Both stay 409/writeProblem
	// with no confirmation token, for the same reason as the four above: a
	// stale risk floor or a protected namespace does not become safe by
	// resubmitting the identical plan.
	//
	// execution.ErrNamespaceProtectedRefused specifically was considered for 403
	// instead of 409 — DESIGN.md §9.3 frames the argus.io/protected
	// guardrail as an absolute, authorization-style denial ("applies even to
	// a super-admin"), which arguably fits 403's "forbidden regardless of
	// who's asking" better than 409's "conflicts with current state." But
	// every sibling refusal in this same dispatch (scale-bound,
	// resource-limits-bound, container-not-found, image-revert, and the risk
	// floor recheck right below) is equally "permanently unsafe, not a state
	// conflict in the literal sense" and all of them use 409 for
	// consistency — introducing a one-off 403 here would split an otherwise
	// uniform class on a distinction no caller (human or UI) currently acts
	// on differently. Kept at 409 to match the established pattern rather
	// than introduce a new status-code convention unilaterally; revisit if a
	// caller ever needs to tell "permanently forbidden" apart from
	// "permanently unsafe" programmatically.
	if errors.Is(err, execution.ErrRiskFloorRecheckRefused) {
		s.recordPolicyRefusal(ctx, rc, r, clusterID, incidentID, planID, actionType, "risk-floor-recheck-refused", err)
		writeProblem(w, http.StatusConflict, "https://argus.io/errors/risk-floor-recheck-refused",
			"Refusing a plan whose live risk floor rose", err.Error())
		return
	}
	if errors.Is(err, execution.ErrNamespaceProtectedRefused) {
		s.recordPolicyRefusal(ctx, rc, r, clusterID, incidentID, planID, actionType, "namespace-protected-refused", err)
		writeProblem(w, http.StatusConflict, "https://argus.io/errors/namespace-protected-refused",
			"Refusing an action against a protected namespace", err.Error())
		return
	}
	// BUGS.md 118 part (b): same "permanently unsafe on its own terms, not a
	// state conflict, no confirm-and-retry path" class as the block above —
	// see execution.ErrDeleteResourcePVCManagedRefused's own doc comment for why a
	// DeleteResource plan against a PersistentVolumeClaim gets no
	// confirmation override the way execution.ErrGitOpsManagedRefused offers every
	// other action type. 409/writeProblem, not writeGuardrailRefusal: there
	// is no guardrailTokens confirmation to mint here, deliberately.
	if errors.Is(err, execution.ErrDeleteResourcePVCManagedRefused) {
		s.recordPolicyRefusal(ctx, rc, r, clusterID, incidentID, planID, actionType, "delete-resource-pvc-managed-refused", err)
		writeProblem(w, http.StatusConflict, "https://argus.io/errors/delete-resource-pvc-managed-refused",
			"Refusing to delete a PersistentVolumeClaim that is not genuinely orphaned", err.Error())
		return
	}
	// Found live 2026-09-17 (T5): a rollback-capture refusal — ARGUS declining
	// to make a change because it could not write down how to undo it — came
	// back as the generic 502 below, "Could not execute this remediation",
	// which reads as the cluster having rejected something ARGUS attempted.
	// Nothing was attempted: this is the same understood-and-declining class
	// as every branch above, so it gets the same 409 and its own problem type.
	// Like them, no confirmation token is minted — an undo that could not be
	// captured is not captured any better on a second identical request.
	if errors.Is(err, execution.ErrRollbackCaptureRefused) {
		s.recordPolicyRefusal(ctx, rc, r, clusterID, incidentID, planID, actionType, "rollback-capture-refused", err)
		writeProblem(w, http.StatusConflict, "https://argus.io/errors/rollback-capture-refused",
			"Refusing a change whose undo could not be captured", err.Error())
		return
	}
	// BACKLOG.md G6: recordExecutingTransition lost the planId replay
	// race (a concurrent request already approved/rejected this exact
	// plan) — a clean 409 naming what happened, not the generic 502
	// below, which would misdescribe a concurrency conflict this hub
	// itself caught as a failed cluster execution.
	var alreadyDecided *execution.ErrPlanAlreadyDecided
	if errors.As(err, &alreadyDecided) {
		writeProblem(w, http.StatusConflict, "https://argus.io/errors/plan-already-decided",
			"This plan has already been decided", alreadyDecided.Detail)
		return
	}
	logger.ErrorContext(ctx, "preparing or executing an approved plan failed", logging.IncidentID(incidentID), logging.Err(err))
	writeProblem(w, http.StatusBadGateway, "https://argus.io/errors/remediation-execution-failed",
		"Could not execute this remediation", err.Error())
}

// recordPolicyRefusal writes the audit_events row for an execution.PreparePlan
// pre-flight refusal (BACKLOG.md L5) — the hub itself declining to execute a
// remediation on policy grounds, before a human ever reaches the approval
// decision and before anything is signed, sent to a cluster, or recorded in
// remediation_approval_decisions. Until this existed, that entire class of
// event was invisible everywhere: not in Insights' "frequently rejected
// recommendations" (which, correctly, only counts a human's `verdict =
// 'rejected'`), not in the audit trail, not queryable by anything.
//
// Details.action is deliberately "remediation_policy_refused" — distinct
// from handleRejectIncident's "reject_remediation" — so the two are
// machine-distinguishable: one is a human clicking reject on a plan the hub
// was willing to run, the other is the hub refusing to let ANY human
// approve it at all. Details.rule carries the specific sentinel/guardrail
// that fired (the same slug used in that branch's own problem `type`, e.g.
// "namespace-protected-refused"), so a future reader — human or an Insights
// query — can tell execution.ErrNamespaceProtectedRefused's absolute policy wall
// apart from execution.ErrScaleFromZeroRefused's confirm-and-retry guardrail without
// parsing prose.
//
// This opens and commits its OWN small transaction rather than reusing
// rc.Tx, for the exact reason recordCapabilityDenial (middleware.go) does:
// writePreparePlanExecutionError's caller always answers this request with
// a >= 400 status, and requireAuth's wrapper rolls rc.Tx back for any such
// response — a refusal recorded on rc.Tx would be silently discarded the
// instant it was written, which is exactly the bug this function exists to
// fix. Best-effort: a failed audit write is logged server-side and must
// never change the response the caller already received, and must never
// block on rc — a nil rc (as used by TestWritePreparePlanExecutionError's
// synthetic-error cases, which construct this function's dependencies
// directly with no live request/DB behind them) is "nothing to record", not
// an error.
func (s *Server) recordPolicyRefusal(ctx context.Context, rc *requestContext, r *http.Request, clusterID, incidentID, planID string, actionType remediation.ActionType, rule string, refusalErr error) {
	if rc == nil || s.db == nil {
		return
	}

	tx, err := s.db.Pool.Begin(ctx)
	if err != nil {
		logger.ErrorContext(ctx, "recording a policy refusal: begin transaction failed", logging.IncidentID(incidentID), logging.Err(err))
		return
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	if err := data.SetRequestScope(ctx, tx, rc.TenantID, nil); err != nil {
		logger.ErrorContext(ctx, "recording a policy refusal: set request scope failed", logging.IncidentID(incidentID), logging.Err(err))
		return
	}

	var clusterRef *string
	if clusterID != "" {
		clusterRef = &clusterID
	}
	var sourceIP string
	if r != nil {
		sourceIP = clientIP(r)
	}

	if err := audit.RecordEvent(ctx, tx, audit.Event{
		TenantID: rc.TenantID, ActorID: &rc.UserID, ActorAuthMethod: "jwt",
		SourceIP: sourceIP, ClusterID: clusterRef, Outcome: audit.OutcomeDenied,
		Details: map[string]any{
			"action":     "remediation_policy_refused",
			"rule":       rule,
			"incidentId": incidentID,
			"planId":     planID,
			"actionType": string(actionType),
			"reason":     refusalErr.Error(),
		},
	}); err != nil {
		logger.ErrorContext(ctx, "recording a policy refusal: audit write failed", logging.IncidentID(incidentID), logging.Err(err))
		return
	}

	if err := tx.Commit(ctx); err != nil {
		logger.ErrorContext(ctx, "recording a policy refusal: commit failed", logging.IncidentID(incidentID), logging.Err(err))
	}
}

// approveByOpeningPullRequest records the approval AND opens the pull request, in
// one transaction.
//
// Ordering is deliberate and matches the human-driven endpoint: the pull request
// is opened first, then everything that records it. A failure after the pull
// request exists is logged rather than returned for the bookkeeping writes, and
// returned for the audit write — the same trade handleOpenRepositoryChange makes,
// for the same reason: reporting failure over bookkeeping sends someone looking
// for a pull request that exists, while an unrecorded change to a customer's
// repository is not something to report as a success.
func (s *Server) approveByOpeningPullRequest(ctx context.Context, r *http.Request, rc *requestContext, incidentID, planID, clusterID string, plan remediation.RemediationPlan, params remediation.OpenPRParams) (approveRejectResponse, error) {
	// BACKLOG.md G6: the planId replay dedup chokepoint, taken BEFORE the one
	// irreversible step in this function (opening the pull request itself).
	// This was previously the one plan-decision path with no such check at
	// all — recordExecutingTransition already took the equivalent lock for
	// the four in-place action types, and handleRejectIncident's own INSERT
	// now waits behind the same lock too. See internal/execution/concurrency.go.
	if err := execution.LockIncidentForDecision(ctx, rc.Tx, incidentID, planID); err != nil {
		return approveRejectResponse{}, err
	}

	approver := s.approverIdentity(ctx, rc)
	// BACKLOG.md AL1 decision 4 (openpr_correction.go): a refusal here that is
	// plausibly about the proposed CONTENT being wrong gets exactly one
	// bounded correction attempt before this function gives up on it, the
	// same primitive BUGS.md 109/110 already built for the post-approval
	// dry-run-rejection path (internal/execution/correction.go) and the analyze-time
	// Blocked-plan path (analyze_correction.go) — reused here for the one
	// point in the OpenPR lifecycle neither of those two reaches.
	propose := func(ctx context.Context, p remediation.OpenPRParams) (gitopsProposalResult, error) {
		proposal, repoName, err := s.proposeFromApprovedPlan(ctx, rc, incidentID, clusterID, approver, p)
		if err != nil {
			return gitopsProposalResult{}, err
		}
		return gitopsProposalResult{Proposal: proposal, RepoName: repoName}, nil
	}
	result, correctionAttempt, err := retryOpenPRProposalWithCorrection(ctx, plan, params, propose, s.planCorrectorFunc())
	if err != nil {
		// BUGS.md 110: before recordFailedOpenPRApproval existed, a refusal
		// here left literally zero rows anywhere — requireAuth rolls back
		// rc.Tx entirely on the >=422 response this error becomes, taking the
		// lockIncidentForDecision read and anything else this function had
		// done in rc.Tx down with it. See that function's own doc comment for
		// why this needs its own, separately-committed transaction rather
		// than a write to rc.Tx — correctionAttempt (non-nil exactly when one
		// was tried, win or lose) is recorded in that SAME small transaction,
		// so a correction attempt that still ended in this failure is not
		// lost along with everything else rc.Tx would otherwise take with it.
		s.recordFailedOpenPRApproval(ctx, rc.TenantID, clusterID, incidentID, planID, err, correctionAttempt)
		return approveRejectResponse{}, err
	}
	proposal, repoName := result.Proposal, result.RepoName

	// The correction succeeded (or was never needed) and this transaction is
	// about to commit along with everything else below — recorded in rc.Tx,
	// not the separate failure transaction above, since this one lives or
	// dies with the rest of a successful approval. Written before any of the
	// bookkeeping below so an operator reading the incident's history sees
	// the correction precede the pull request it produced, not follow it.
	if correctionAttempt != nil {
		if err := timeline.Record(ctx, rc.Tx, timeline.Event{
			TenantID: rc.TenantID, ClusterID: clusterID, IncidentID: incidentID,
			Type:    timeline.EventParamsCorrectionAttempted,
			Summary: fmt.Sprintf("Attempted to correct %s's proposed params: %s", plan.ActionType, correctionAttempt.Outcome),
			Detail: map[string]any{
				"actionType":      string(plan.ActionType),
				"reason":          correctionAttempt.Reason,
				"outcome":         correctionAttempt.Outcome,
				"succeeded":       correctionAttempt.Succeeded,
				"correctedParams": correctionAttempt.CorrectedParams,
			},
		}); err != nil {
			logger.ErrorContext(ctx, "recording the ParamsCorrectionAttempted timeline event failed — the pull request IS open",
				logging.IncidentID(incidentID), slog.String("pull_request_url", proposal.PullRequest.URL), logging.Err(err))
		}
	}

	decisionID := domain.NewID(domain.PrefixApproval)
	if _, err := rc.Tx.Exec(ctx,
		`INSERT INTO remediation_approval_decisions (id, recommendation_id, incident_id, tenant_id, cluster_id, actor_id, verdict, reason, analysis_id)
		 VALUES ($1, $2, $3, $4, $5, $6, 'approved', NULL, `+execution.DecisionAnalysisSubquery("$2")+`)`,
		decisionID, planID, incidentID, rc.TenantID, clusterID, rc.UserID); err != nil {
		logger.ErrorContext(ctx, "recording the approval decision failed — the pull request IS open",
			logging.IncidentID(incidentID), slog.String("pull_request_url", proposal.PullRequest.URL), logging.Err(err))
	}

	// BACKLOG.md B1: the approval decision. Logged rather than returned on
	// failure, matching every other bookkeeping write in this function —
	// the pull request already exists by this point, and reporting failure
	// over a missing timeline row would send someone looking for a pull
	// request that exists.
	if err := timeline.Record(ctx, rc.Tx, timeline.Event{
		TenantID: rc.TenantID, ClusterID: clusterID, IncidentID: incidentID,
		Type: timeline.EventApprovalGranted, Summary: "Approved (pull request)",
		Detail: map[string]any{"planId": planID},
	}); err != nil {
		logger.ErrorContext(ctx, "recording the ApprovalGranted timeline event failed — the pull request IS open",
			logging.IncidentID(incidentID), slog.String("pull_request_url", proposal.PullRequest.URL), logging.Err(err))
	}

	// pr_number (migration 000058, on incidents — see that migration's comment
	// for why not on the recommendation) is what orchestrator.MergeSweeper polls
	// the provider with later. Recorded now because proposal.PullRequest.Number
	// is already in hand, rather than parsed back out of the URL below.
	//
	// pr_field_path/pr_expected_value (migration 000059) are explicitly NULLed.
	// A whole-file change has no single field to re-assert once the merge
	// syncs, so claiming one — or leaving a STALE one from an earlier
	// recommendation on this incident — would be worse than the honest
	// degradation those columns already support: VerifyMergedPullRequest treats
	// a NULL field path as "this pull request opened through a path that did
	// not record one" and falls back to the per-file check below (migration
	// 000075), or to ValidationSweeper's quiet-grace-period behaviour if that
	// has nothing recorded either.
	//
	// pr_proposed_files (migration 000075, BACKLOG.md F23) is the whole-file
	// successor: every changed file's whole proposed content, captured from
	// the SAME proposal.Verification the pull request body and audit record
	// already quote, so VerifyMergedPullRequest can re-read each file at the
	// revision the GitOps controller reports synced and confirm nothing
	// reverted or conflicted with it after this merged.
	// pr_url (migration 000089, BACKLOG.md D9 U6): the provider's own link to
	// this pull request, so the incident detail page can render a real
	// hyperlink instead of a bare "#63" the operator cannot click through.
	//
	// pr_merged_at/pr_closed_unmerged_at/pr_rejection_reason are explicitly
	// NULLed here too — a real bug found alongside BACKLOG.md D9 B3, not
	// merely a defensive precaution: an incident whose first pull request was
	// closed unmerged returns to AwaitingApproval (mergewatch.go) with those
	// three columns still set from THAT pull request, and until now nothing
	// cleared them when a second one opened. incidentPullRequestRecord
	// (incidents.go) reports one row keyed only by incident id, so the new
	// pr_number would otherwise carry the OLD pull request's
	// pr_closed_unmerged_at timestamp — PullRequestRecord (IncidentDetailPage)
	// would render a currently-open pull request as "Closed without merging".
	//
	// pr_opened_at (migration 000114) is set to now() in this SAME statement,
	// unconditionally, precisely so it obeys the rule the paragraph above
	// states: every column here describes the pull request pr_number names, and
	// a re-proposal replaces all of them together. Writing it only when it was
	// previously NULL would leave the FIRST pull request's open-time attached to
	// the second one's number — the same class of bug the three explicit NULLs
	// above exist to close, in the one column whose whole job is to say how long
	// the operator has been waiting on THIS merge.
	if _, err := rc.Tx.Exec(ctx,
		`UPDATE incidents SET pr_number = $2, pr_url = $3, pr_field_path = NULL, pr_expected_value = NULL, pr_proposed_files = $4,
		        pr_opened_at = now(),
		        pr_merged_at = NULL, pr_closed_unmerged_at = NULL, pr_rejection_reason = NULL
		  WHERE id = $1`,
		incidentID, proposal.PullRequest.Number, nullIfEmpty(proposal.PullRequest.URL), encodeProposedFiles(proposal.Verification.Changed())); err != nil {
		logger.ErrorContext(ctx, "recording the pull-request number on the incident failed — the pull request IS open",
			logging.IncidentID(incidentID), slog.String("pull_request_url", proposal.PullRequest.URL), logging.Err(err))
	}

	// The in-place recommendations on this incident are now superseded by a source
	// fix — the same guard migration 000049 exists for, and it matters most for
	// RevertContainerImage, whose meaning inverts once the source is corrected.
	//
	// EXCEPT planID's own paired sibling (lld/08 §12.6, migration 000062): under
	// route = pullRequest+inPlace this OpenPR recommendation has an in-place
	// COMPANION, not a predecessor it obsoletes — "in-place stops the outage
	// now, the PR stops the next deploy reintroducing it" is the whole point of
	// the pair, and marking the companion superseded the moment the PR opens
	// would undo that before the in-place half ever got a chance to run.
	if _, err := rc.Tx.Exec(ctx,
		`UPDATE remediation_recommendations
		    SET superseded_at = now(), superseded_by_url = $2
		  WHERE incident_id = $1 AND superseded_at IS NULL
		    AND id <> COALESCE((SELECT sibling_of_recommendation_id FROM remediation_recommendations WHERE id = $3), '')`,
		incidentID, proposal.PullRequest.URL, planID); err != nil {
		logger.ErrorContext(ctx, "marking the superseded recommendations failed — the pull request IS open",
			logging.IncidentID(incidentID), slog.String("pull_request_url", proposal.PullRequest.URL), logging.Err(err))
	}

	if err := orchestrator.SetState(ctx, rc.Tx, incidentID, orchestrator.StateAwaitingMerge); err != nil {
		logger.ErrorContext(ctx, "moving the incident to AwaitingMerge failed — the pull request IS open",
			logging.IncidentID(incidentID), slog.String("pull_request_url", proposal.PullRequest.URL), logging.Err(err))
	}

	// BACKLOG.md B1: the PR route's stand-in for "execution starting" —
	// nothing in-cluster changes until a human merges it, so this is the
	// event that marks the fix actually being proposed at its source.
	if err := timeline.Record(ctx, rc.Tx, timeline.Event{
		TenantID: rc.TenantID, ClusterID: clusterID, IncidentID: incidentID,
		Type: timeline.EventPullRequestOpened, Summary: fmt.Sprintf("Pull request opened: %s", proposal.PullRequest.URL),
		Detail: map[string]any{
			"planId":         planID,
			"pullRequestUrl": proposal.PullRequest.URL,
			"repository":     repoName,
			"filePaths":      proposal.Verification.Paths(),
			"filesChanged":   proposal.Verification.FilesChanged,
			"linesAdded":     proposal.Verification.LinesAdded,
			"linesRemoved":   proposal.Verification.LinesRemoved,
			// BACKLOG.md F26 — always present, including nil ("never
			// attempted"); see renderEvidenceAuditFields' own comment.
			"renderEvidence": renderEvidenceAuditFields(proposal.RenderEvidence),
		},
	}); err != nil {
		logger.ErrorContext(ctx, "recording the PullRequestOpened timeline event failed — the pull request IS open",
			logging.IncidentID(incidentID), slog.String("pull_request_url", proposal.PullRequest.URL), logging.Err(err))
	}

	capability := authz.CapRepoWrite
	var clusterRef *string
	if clusterID != "" {
		clusterRef = &clusterID
	}
	if auditErr := audit.RecordEvent(ctx, rc.Tx, audit.Event{
		TenantID: rc.TenantID, ActorID: &rc.UserID, ActorAuthMethod: "jwt",
		SourceIP: clientIP(r), Capability: &capability, ClusterID: clusterRef,
		Outcome: audit.OutcomeSuccess,
		Details: map[string]any{
			"action":     "open_repository_change",
			"trigger":    "plan_approval",
			"incidentId": incidentID,
			"planId":     planID,
			"repository": repoName,
			// Every changed path is named, and the advisory count is recorded
			// ALWAYS — including the ordinary zero — for the same reason
			// confirmScaleFromZero is: a key that only appears on the
			// interesting case cannot be searched for.
			"filePaths":      proposal.Verification.Paths(),
			"filesChanged":   proposal.Verification.FilesChanged,
			"linesAdded":     proposal.Verification.LinesAdded,
			"linesRemoved":   proposal.Verification.LinesRemoved,
			"advisories":     proposal.Verification.Advisories,
			"branch":         proposal.PullRequest.Head,
			"baseBranch":     proposal.PullRequest.Base,
			"commitSha":      proposal.CommitSHA,
			"commits":        proposal.Commits,
			"pullRequestUrl": proposal.PullRequest.URL,
			"filePathSource": "proposed_by_model",
			"approvedBy":     approver,
		},
	}); auditErr != nil {
		return approveRejectResponse{}, fmt.Errorf("the pull request %s IS OPEN but could not be recorded: %w", proposal.PullRequest.URL, auditErr)
	}

	if s.events != nil {
		s.events.Publish(events.IncidentUpdated(incidentID, clusterID))
	}
	return approveRejectResponse{
		IncidentID:    incidentID,
		PlanID:        planID,
		Verdict:       "approved",
		IncidentState: orchestrator.StateAwaitingMerge,
		Message: fmt.Sprintf("Approved, and pull request %s is open against %s: %d file(s) changed (%s), +%d/-%d lines. "+
			"Nothing in the cluster has changed — this incident is now AwaitingMerge, and the fix lands when your team reviews and merges it.",
			proposal.PullRequest.URL, repoName, proposal.Verification.FilesChanged,
			strings.Join(proposal.Verification.Paths(), ", "),
			proposal.Verification.LinesAdded, proposal.Verification.LinesRemoved),
	}, nil
}

// recordFailedOpenPRApproval is BUGS.md 110's fix for the "zero recorded
// trace" half of that bug: an OpenPR approval that fails to actually open a
// pull request — s.proposeFromApprovedPlan returning an error, for ANY
// reason internal/gitops refuses (a multi-line field this build's
// OpenPRParams.Validate() guard did not already catch, a moved/compare-and-
// swap value, an ambiguous or forbidden file path) — used to leave literally
// zero rows anywhere, confirmed live by direct psql inspection of
// remediation_approval_decisions. The incident stayed AwaitingApproval,
// indistinguishable from a plan nobody had ever tried to approve.
//
// This deliberately opens and commits its OWN small transaction rather than
// writing into rc.Tx, for exactly the reason
// recordCapabilityDenial (middleware.go) already documents for the identical
// shape of problem: requireAuth rolls back rc.Tx whenever the wrapped
// handler's response status is >= 400, which a repository-change-refused 422
// always is — by the time that rollback runs, anything this call recorded in
// rc.Tx would be gone along with it. A failed attempt being durably traceable
// must not depend on the outcome of the very transaction whose entire point
// was to record a failure.
//
// Best-effort and silent-on-its-own-failure, matching recordCapabilityDenial's
// posture: this must never turn an already-decided 422 into a 500, and must
// never delay or alter the real error returned to the caller. It does NOT
// touch remediation_approval_decisions or the incident's state — only a
// timeline event, which is the bounded, low-risk piece of BUGS.md 110's
// "should this leave some trace" question this task's brief asked to close if
// tractable. Whether a failed OpenPR approval attempt should also move the
// incident to a different state is a separate, harder question left open in
// BACKLOG.md AL1 — this function makes no claim about that.
//
// correctionAttempt (BACKLOG.md AL1 decision 4, openpr_correction.go) is
// non-nil exactly when retryOpenPRProposalWithCorrection tried a correction
// before ultimately still failing — win or lose, that attempt gets its own
// timeline.EventParamsCorrectionAttempted row in this SAME separately-
// committed transaction, for the identical reason the failure event itself
// needs one: rc.Tx is what rolls back on the >=422 response, and a correction
// attempt that still ended in failure must not vanish along with it. nil
// means no correction was attempted at all (the original refusal was not
// content-fixable), in which case only the failure event below is written,
// exactly as before this decision was closed.
func (s *Server) recordFailedOpenPRApproval(ctx context.Context, tenantID, clusterID, incidentID, planID string, cause error, correctionAttempt *openPRApprovalCorrectionAttempt) {
	tx, err := s.db.Pool.Begin(ctx)
	if err != nil {
		logger.ErrorContext(ctx, "recording a failed OpenPR approval: begin transaction failed", logging.IncidentID(incidentID), logging.Err(err))
		return
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	if err := data.SetRequestScope(ctx, tx, tenantID, nil); err != nil {
		logger.ErrorContext(ctx, "recording a failed OpenPR approval: set request scope failed", logging.IncidentID(incidentID), logging.Err(err))
		return
	}

	if correctionAttempt != nil {
		if err := timeline.Record(ctx, tx, timeline.Event{
			TenantID: tenantID, ClusterID: clusterID, IncidentID: incidentID,
			Type:    timeline.EventParamsCorrectionAttempted,
			Summary: fmt.Sprintf("Attempted to correct proposed params: %s", correctionAttempt.Outcome),
			Detail: map[string]any{
				"planId":          planID,
				"reason":          correctionAttempt.Reason,
				"outcome":         correctionAttempt.Outcome,
				"succeeded":       correctionAttempt.Succeeded,
				"correctedParams": correctionAttempt.CorrectedParams,
			},
		}); err != nil {
			// Best-effort within an already best-effort function: logged, not
			// returned — the failure event below is the more important of the
			// two and must still be attempted.
			logger.ErrorContext(ctx, "recording a failed OpenPR approval: ParamsCorrectionAttempted timeline write failed", logging.IncidentID(incidentID), logging.Err(err))
		}
	}

	if err := timeline.Record(ctx, tx, timeline.Event{
		TenantID: tenantID, ClusterID: clusterID, IncidentID: incidentID,
		Type:    timeline.EventPullRequestProposalFailed,
		Summary: "Approval attempted, but the pull request could not be opened",
		Detail: map[string]any{
			"planId": planID,
			"reason": cause.Error(),
		},
	}); err != nil {
		logger.ErrorContext(ctx, "recording a failed OpenPR approval: timeline write failed", logging.IncidentID(incidentID), logging.Err(err))
		return
	}

	if err := tx.Commit(ctx); err != nil {
		logger.ErrorContext(ctx, "recording a failed OpenPR approval: commit failed", logging.IncidentID(incidentID), logging.Err(err))
	}
}

// wrongStateForApprovalDetail explains a state mismatch on the approve, reject
// and preflight paths, which all require AwaitingApproval.
//
// It exists because "incident is currently X; only Y can be approved" is true and
// useless for the one state an operator will actually hit: AwaitingMerge. There,
// the honest answer is not "wrong state" but "the fix for this is a pull request
// ARGUS already opened, and applying the in-place plan now could undo it" — a
// different sentence that sends the operator somewhere useful instead of leaving
// them to work out why a queued incident refuses the action the queue offered.
func wrongStateForApprovalDetail(state, verb string) string {
	if state == orchestrator.StateAwaitingMerge {
		return fmt.Sprintf("ARGUS has already proposed the durable fix for this incident as a pull request, so it is %q rather than %q and the in-place plan cannot be %s. "+
			"That plan was derived from the cluster as it was before the fix — for a revert-to-previous-image plan it means the opposite once a newer image has synced. "+
			"Review the pull request; if it is wrong, re-analyse this incident so a new plan is derived from the current state.",
			orchestrator.StateAwaitingMerge, orchestrator.StateAwaitingApproval, verb)
	}
	// The second state an operator will actually hit, for the same reason:
	// two people looking at the same queue row, or one person with a stale
	// tab. "Wrong state" would leave them wondering whether the click
	// registered; naming the refusal says both what happened and what is left
	// to do. The reason itself is on the incident, not repeated here — this is
	// an error detail, and the plan card is where the decision is read.
	if state == orchestrator.StatePlanRejected {
		return fmt.Sprintf("someone has already rejected this plan, so the incident is %q rather than %q and it cannot be %s. "+
			"The fault is unchanged and the incident is still open. Open it to see who refused the plan and why; "+
			"a different fix has to come from a new analysis, which no longer has this plan in front of it.",
			orchestrator.StatePlanRejected, orchestrator.StateAwaitingApproval, verb)
	}
	return fmt.Sprintf("incident is currently %q; only an incident in %q can be %s", state, orchestrator.StateAwaitingApproval, verb)
}

// rejectIncidentRequest is POST .../reject's request body — Reason is
// required and non-empty (validated below), matching this task's brief:
// "a reason is reasonable to require" for a rejection.
type rejectIncidentRequest struct {
	Reason string `json:"reason"`
}

// handleRejectIncident is POST /api/v1/incidents/{id}/reject. Requires
// remediation:reject (a distinct capability from approve — a role could in
// principle hold one without the other, though today's five builtin roles
// always grant both together).
//
// Unlike approve, rejection transitions the incident's state, and the state it
// transitions to is AwaitingApproval -> PlanRejected: the plan is refused, the
// incident stays open and stays on a human's list. It is not Dismissed — see
// this file's doc comment and orchestrator.StatePlanRejected for why that was
// the finding, not the design.
//
// Everything else about this handler is unchanged, deliberately: the
// capability gate, the plan lock (lockIncidentForDecision — one decision per
// plan, enforced by a row lock, not by hope), the decision row, the timeline
// event and the audit record all still happen, in the same order, in the same
// transaction. The fix is in what the transition asserts, not in what the
// rejection costs.
func (s *Server) handleRejectIncident(w http.ResponseWriter, r *http.Request, rc *requestContext) {
	incidentID := r.PathValue("id")
	ctx := r.Context()

	var req rejectIncidentRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeProblem(w, http.StatusBadRequest, "https://argus.io/errors/malformed-request", "Malformed request body", err.Error())
		return
	}
	if strings.TrimSpace(req.Reason) == "" {
		writeProblem(w, http.StatusBadRequest, "https://argus.io/errors/invalid-request", "A reason is required to reject a remediation", "")
		return
	}

	state, err := incidentState(ctx, rc.Tx, incidentID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			writeProblem(w, http.StatusNotFound, "https://argus.io/errors/not-found", "Incident not found", "")
			return
		}
		logger.ErrorContext(ctx, "looking up the incident to reject failed", logging.IncidentID(incidentID), logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not look up incident", "")
		return
	}
	if state != orchestrator.StateAwaitingApproval {
		writeProblem(w, http.StatusConflict, "https://argus.io/errors/invalid-state",
			"Incident is not awaiting approval", wrongStateForApprovalDetail(state, "rejected"))
		return
	}

	planID, clusterID, err := latestRecommendationForIncident(ctx, rc.Tx, incidentID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			logger.WarnContext(ctx, "incident is AwaitingApproval but has no remediation_recommendations row", logging.IncidentID(incidentID))
			writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "No plan found for this incident", "")
			return
		}
		logger.ErrorContext(ctx, "looking up the plan to reject failed", logging.IncidentID(incidentID), logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not look up plan", "")
		return
	}

	// BACKLOG.md G6: the planId replay dedup chokepoint, taken BEFORE
	// inserting the rejection decision below — previously this insert ran
	// first and only orchestrator.SetState's own lock (reached afterward)
	// would have caught a concurrent approval/rejection, by which point a
	// duplicate decision row had already been written (it would have been
	// rolled back along with the rest of this request once SetState failed,
	// since a >=400 response rolls rc.Tx back — but the caller still saw a
	// generic 500 instead of a clean, correctly-worded 409). See
	// internal/execution's LockIncidentForDecision.
	if err := execution.LockIncidentForDecision(ctx, rc.Tx, incidentID, planID); err != nil {
		var alreadyDecided *execution.ErrPlanAlreadyDecided
		if errors.As(err, &alreadyDecided) {
			writeProblem(w, http.StatusConflict, "https://argus.io/errors/plan-already-decided",
				"This plan has already been decided", alreadyDecided.Detail)
			return
		}
		logger.ErrorContext(ctx, "locking the incident for a rejection decision failed", logging.IncidentID(incidentID), slog.String("plan_id", planID), logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not process rejection", "")
		return
	}

	decisionID := domain.NewID(domain.PrefixApproval)
	if _, err := rc.Tx.Exec(ctx,
		`INSERT INTO remediation_approval_decisions (id, recommendation_id, incident_id, tenant_id, cluster_id, actor_id, verdict, reason, analysis_id)
		 VALUES ($1, $2, $3, $4, $5, $6, 'rejected', $7, `+execution.DecisionAnalysisSubquery("$2")+`)`,
		decisionID, planID, incidentID, rc.TenantID, clusterID, rc.UserID, req.Reason); err != nil {
		logger.ErrorContext(ctx, "recording a rejection decision failed", logging.IncidentID(incidentID), slog.String("plan_id", planID), logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not record rejection", "")
		return
	}

	if err := orchestrator.SetState(ctx, rc.Tx, incidentID, orchestrator.StatePlanRejected); err != nil {
		logger.ErrorContext(ctx, "moving a rejected incident to PlanRejected failed", logging.IncidentID(incidentID), logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not update incident state", "")
		return
	}

	// BACKLOG.md B1: the approval decision — rejected. Nothing irreversible
	// has happened outside this transaction yet, so unlike
	// approveByOpeningPullRequest's bookkeeping writes, a failure here fails
	// the whole request rather than being logged and carried on past.
	if err := timeline.Record(ctx, rc.Tx, timeline.Event{
		TenantID: rc.TenantID, ClusterID: clusterID, IncidentID: incidentID,
		Type: timeline.EventApprovalRejected, Summary: fmt.Sprintf("Rejected: %s", req.Reason),
		Detail: map[string]any{"planId": planID, "reason": req.Reason},
	}); err != nil {
		logger.ErrorContext(ctx, "recording the ApprovalRejected timeline event failed", logging.IncidentID(incidentID), slog.String("plan_id", planID), logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not record timeline event", "")
		return
	}

	capability := authz.CapRemediationReject
	if err := audit.RecordEvent(ctx, rc.Tx, audit.Event{
		TenantID:        rc.TenantID,
		ActorID:         &rc.UserID,
		ActorAuthMethod: "jwt",
		SourceIP:        clientIP(r),
		Capability:      &capability,
		ClusterID:       &clusterID,
		Outcome:         audit.OutcomeSuccess,
		Details: map[string]any{
			"action":     "reject_remediation",
			"incidentId": incidentID,
			"planId":     planID,
			"reason":     req.Reason,
		},
	}); err != nil {
		logger.ErrorContext(ctx, "recording a plan rejection in the audit log failed", logging.IncidentID(incidentID), slog.String("plan_id", planID), logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not record audit event", "")
		return
	}

	if s.events != nil {
		s.events.Publish(events.IncidentUpdated(incidentID, clusterID))
	}
	writeJSON(w, http.StatusOK, approveRejectResponse{
		IncidentID:    incidentID,
		PlanID:        planID,
		Verdict:       "rejected",
		IncidentState: orchestrator.StatePlanRejected,
		// Says what did NOT happen, because that is the part a reader is most
		// likely to assume wrongly: refusing the fix did not close anything.
		Message: "Rejected — this plan will not be executed. The incident stays open with the fault unchanged; re-analyse it for a different fix, propose one at the source, or close it out.",
	})
}

// writeGuardrailRefusal is the shared tail of both guardrail refusal
// responses: mint a confirmation token bound to (planID, guardrail) and
// attach it as an RFC 9457 extension member, so the client's retry can echo
// it back and prove this exact refusal was actually shown (WORKLOG §97 G5) —
// see internal/authz.GuardrailConfirmationIssuer's own doc comment for the
// gap this closes.
//
// Token minting failure (entropy exhaustion, effectively never) degrades to
// the plain refusal rather than a 500: the operator still sees why the
// action was refused, they just cannot immediately confirm past it — a worse
// UX than a working token, not a security gap, so it is logged and the
// response proceeds without one rather than hiding the real refusal behind a
// different error.
func (s *Server) writeGuardrailRefusal(ctx context.Context, w http.ResponseWriter, planID, guardrail, problemType, title, detail string) {
	extras := map[string]any{}
	if token, err := s.guardrailTokens.Issue(planID, guardrail); err != nil {
		logger.WarnContext(ctx, "minting a guardrail confirmation token failed; returning the refusal without one",
			slog.String("plan_id", planID), slog.String("guardrail", guardrail), logging.Err(err))
	} else {
		extras["confirmationToken"] = token
	}
	writeProblemWithExtras(w, http.StatusConflict, problemType, title, detail, extras)
}
