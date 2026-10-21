package api

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"argus/internal/importance"
	"argus/internal/llm"
	"argus/internal/logging"
	"argus/internal/orchestrator"
	"argus/internal/timeline"
)

// validIncidentStates mirrors internal/migrations/000005_incidents_and_analysis
// .up.sql's incidents.state CHECK constraint exactly — the same enum
// lld/08-remediation-contracts.md §2's state machine defines. Kept here so
// handleListIncidents can validate ?state= without a round trip to Postgres
// just to discover it's invalid.
var validIncidentStates = []string{
	"Detected", "Investigating", "RecommendationReady", "NeedsHumanInvestigation",
	"AwaitingApproval", "Executing", "AwaitingMerge", "Validating",
	"Resolved", "Failed", "Reopened", "Dismissed", "Diagnosed", "ExecutionUnknown",
	"ValidationUnknown", "PlanRejected", "Expired",
}

// incidentSummary is the shape returned by both handleListIncidents (as an
// element of "incidents") and as the base fields of handleGetIncident's
// response — mirrors clusterSummary's role in clusters.go.
type incidentSummary struct {
	ID                 string  `json:"id"`
	ClusterID          string  `json:"clusterId"`
	ClusterDisplayName string  `json:"clusterDisplayName"`
	Fingerprint        string  `json:"fingerprint"`
	Severity           string  `json:"severity"`
	State              string  `json:"state"`
	FirstSeen          string  `json:"firstSeen"`
	LastSeen           string  `json:"lastSeen"`
	OccurrenceCount    int     `json:"occurrenceCount"`
	FleetGroupID       *string `json:"fleetGroupId,omitempty"` // set by internal/fleetgroup.Recompute whenever this fingerprint is currently open on 2+ distinct clusters at once; omitted (not just null) when this incident isn't part of a fleet-wide group.
	// WorkloadGroupID/WorkloadKey/OpeningReason are replica-level
	// correlation's counterpart (BACKLOG.md's A3, migration 000042,
	// internal/replicagroup) — set only when this incident's Finding named a
	// Pod whose owning workload the agent could resolve, and WorkloadGroupID
	// specifically only when 2+ currently-open incidents on this CLUSTER
	// share (WorkloadKey, OpeningReason) at once. All three omitted (not
	// just null) when not applicable, same convention as FleetGroupID.
	WorkloadGroupID *string `json:"workloadGroupId,omitempty"`
	WorkloadKey     *string `json:"workloadKey,omitempty"`
	OpeningReason   *string `json:"openingReason,omitempty"`
	// ObjectGroupID/RelatedWorkloadKey are cross-object correlation's own
	// pair (BACKLOG.md's A3b, migration 000070, internal/objectgroup) —
	// the harder remainder after A1 (object-level) and the above (replica-
	// level): a Service's selector matched against the Pods it targets, or
	// a PersistentVolumeClaim matched against the Pod(s) that mount it,
	// resolved to a WORKLOAD identity agent-side
	// (internal/agent/objectref.go) and joined hub-side exactly like
	// WorkloadKey above. ObjectGroupID is set only when 2+ currently-open
	// incidents on this CLUSTER share an anchor workload — either because
	// they ARE that workload's own incident (WorkloadKey) or because they
	// REFERENCE it (RelatedWorkloadKey) — at once. Same "omitted, not null,
	// when not applicable" convention as every group id above, and the same
	// read-only guarantee: this never merges incident state, findings, or
	// lifecycle (see internal/objectgroup's package doc).
	ObjectGroupID      *string `json:"objectGroupId,omitempty"`
	RelatedWorkloadKey *string `json:"relatedWorkloadKey,omitempty"`
	// ObjectGVK/ObjectNamespace/ObjectName are the object this incident is
	// about, split out of incidents.object_key (migration 000036's
	// `gvk|namespace|name`). Added for BUGS.md item 35: the list previously
	// carried no object identity at all, so a row could only be identified by
	// a 64-character fingerprint hash and a cluster name — nothing saying WHAT
	// failed. Paired with OpeningReason this gives the row a readable label
	// ("OOMKilled · payments-api"), which is the same shape OverviewPage
	// already renders from its own aggregate.
	//
	// Omitted when object_key is NULL, which happens exactly when the opening
	// finding named no object — the fingerprint-only correlation fallback (see
	// gateway.objectCorrelationKey).
	ObjectGVK       *string `json:"objectGvk,omitempty"`
	ObjectNamespace *string `json:"objectNamespace,omitempty"`
	ObjectName      *string `json:"objectName,omitempty"`
	// ResolvedAt is the moment this incident actually closed (BACKLOG.md H4,
	// migration 000065) — set by internal/orchestrator.SetState whenever the
	// incident transitions to Resolved or Dismissed, distinct from LastSeen
	// (the last FINDING recurrence, not the close). Omitted, not null, for
	// every incident that has never closed — including one that closed
	// before this migration existed, which has no honest value to report
	// and is deliberately left that way rather than backfilled from LastSeen.
	ResolvedAt *string `json:"resolvedAt,omitempty"`
	// ResolutionKind is BACKLOG.md T2 (migration 000091)'s answer to "did
	// ARGUS's own remediation have anything to do with this closing" —
	// "remediated" (a succeeded execution or a merged pull request is
	// linked) or "self_healed" (neither is — the symptom simply stopped, or
	// a human closed it with nothing executed). Set only on the transition
	// INTO Resolved (internal/orchestrator/db.go's SetState), so this is
	// omitted, not null, for every incident that isn't Resolved, and for a
	// Dismissed incident too — see that column's own migration comment for
	// why Dismissed deliberately gets no value here at all.
	ResolutionKind *string `json:"resolutionKind,omitempty"`
	// ImportanceExplanation is PROJECT.md T1's own "why did this rank here"
	// answer — set ONLY when ?sort=importance (the one sort mode that
	// computes it; every other sort leaves this omitted, not an empty
	// array, since the ranking that would explain isn't the one that ran).
	// See internal/importance.Explain — the exact reasons the SQL ORDER BY
	// expression's own score actually came from, ranked by real
	// contribution, never a guess reconstructed after the fact. Nil (fully
	// omitted) for an incident where nothing about it stood out on any
	// factor, which is itself a real, honest answer.
	ImportanceExplanation []string `json:"importanceExplanation,omitempty"`
	// Route is internal/resolution.RouteFor's decision for this incident —
	// pullRequest / inPlace / pullRequest+inPlace / guidance (ADR-18,
	// migration 000062). Computed from ownership facts by product code
	// BEFORE the model is asked anything and persisted on the incident, so it
	// is a property of the incident rather than of whichever plan was
	// eventually proposed.
	//
	// On the list because "how would this one actually get fixed" is a triage
	// question, and re-deriving it per row from plan.actionType is exactly the
	// mistake incidentRouteRecord was written to stop — that derivation shows
	// nothing at all for the `guidance` route, the one case with no plan.
	// The prose route_reason deliberately does NOT join it here; see
	// incidentRouteRecord's own doc comment.
	//
	// Omitted, not null, when the column is NULL — the ordinary state for an
	// incident that predates lld/08 §12's routing step or has simply never
	// been investigated (206 of 225 on the development database, 2026-09-19).
	// A client renders that as "not routed yet", never as a guessed route.
	Route *string `json:"route,omitempty"`
}

// incidentListColumns/incidentListFrom together are incidentListQuery, split
// apart so handleListIncidents can splice in one extra sort-key-dependent
// column (see incidentSortSpecs) between the fixed column list and the
// FROM/WHERE — handleGetIncident has no use for that extra column and keeps
// using incidentListQuery exactly as before.
const incidentListColumns = `incidents.id, incidents.cluster_id, clusters.display_name, incidents.fingerprint,
	       incidents.severity, incidents.state, incidents.first_seen, incidents.last_seen,
	       incidents.occurrence_count, incidents.fleet_group_id,
	       incidents.workload_group_id, incidents.workload_key, incidents.opening_reason,
	       incidents.object_key, incidents.resolved_at,
	       incidents.object_group_id, incidents.related_workload_key, incidents.resolution_kind,
	       incidents.route`

// incidentListFrom excludes archived_at IS NOT NULL rows defensively:
// nothing sets archived_at on an incident yet (lld/05-data-model.md §3.5 has
// the column, but no code path in this increment writes it), but
// handleListClusters already excludes archived clusters the same way, and
// matching that convention here means this query's behavior doesn't
// silently change later once something does start archiving incidents.
const incidentListFrom = `
	  FROM incidents
	  JOIN clusters ON clusters.id = incidents.cluster_id
	 WHERE incidents.archived_at IS NULL`

// incidentListQuery is shared by handleListIncidents and handleGetIncident —
// same join/column set, the latter just adds a WHERE incidents.id = $1.
const incidentListQuery = "SELECT " + incidentListColumns + incidentListFrom

// incidentScopeFilter builds the ?clusterId=/?state=/?fleetGroupId=/
// ?workloadGroupId=/?objectGroupId= WHERE fragment shared by
// handleListIncidents' row query and incidentCountsFor's aggregate — the two
// must always agree on which incidents are "in scope", or the number on a
// quick-view tab and the rows a click on that tab could show would silently
// describe two different sets. Called once per query rather than once per
// request: each call starts its own args slice, so the placeholder
// numbering ($1, $2, ...) is always correct for whichever query it's
// spliced into, independent of what else that query does (search, cursor,
// limit).
//
// invalid is non-empty (and clause/args unusable) only for an unrecognized
// ?state= — every other parameter here is a freely-generated id that simply
// matches nothing when unknown, the same tolerant treatment
// handleListIncidents' own doc comment already describes for ?fleetGroupId=/
// ?workloadGroupId=/?objectGroupId=.
// validIncidentSeverities is the closed set ?severity= accepts. Kept beside
// validIncidentStates deliberately: both are request-validation vocabularies,
// and an unknown value must be a 400 rather than a filter that silently
// matches nothing and reads to the operator as "there is none of that".
var validIncidentSeverities = []string{"low", "medium", "high", "critical"}

// requiresActionStateClause is the ONE definition of "on a human's plate" this
// file has. The counts query and ?requiresAction= both read it, so a tab's
// number and the rows beneath it can never disagree about what it counts.
//
// It replaced a `NOT IN ('Resolved', 'Dismissed')` clause named
// openStateClause, which asked the wrong question. "Not terminal" put
// Investigating and Executing — where ARGUS is mid-flight and a human can do
// nothing useful — in the same bucket as AwaitingApproval, and it left
// Diagnosed inexplicable: a finished investigation, legitimately still open
// because the fault is live, sitting in a queue with nothing saying why it
// never moved (six of them, on the development database). Queue membership is
// a product decision, and it now lives in one place as one —
// internal/orchestrator's disposition table, whose doc comment carries the
// per-state reasoning. This constant is only its SQL rendering.
var requiresActionStateClause = orchestrator.RequiresActionStateSQL()

// closedStateClause is the same arrangement for the CLOSED set, and exists for
// the same reason: the counts query's open_count is the complement of this, so
// "open" on the overview and "closed" in the state machine are one definition.
var closedStateClause = orchestrator.ClosedStateSQL()

// fixNotHeldStateClause is the same arrangement for "ARGUS acted and it did
// not demonstrably work" — see orchestrator.fixNotHeldStates for what is in it
// and why it is not derivable from a disposition.
var fixNotHeldStateClause = orchestrator.FixNotHeldStateSQL()

func incidentScopeFilter(r *http.Request) (clause string, args []any, invalid string) {
	q := r.URL.Query()
	if clusterID := q.Get("clusterId"); clusterID != "" {
		args = append(args, clusterID)
		clause += fmt.Sprintf(" AND incidents.cluster_id = $%d", len(args))
	}
	if state := q.Get("state"); state != "" {
		if !slices.Contains(validIncidentStates, state) {
			return "", nil, "state must be one of: " + strings.Join(validIncidentStates, ", ")
		}
		args = append(args, state)
		clause += fmt.Sprintf(" AND incidents.state = $%d", len(args))
	}
	// ?severity= and ?requiresAction= — added 2026-09-05 for the review's
	// finding 8 (the second landed as ?open= and was renamed the same day by
	// finding 9; see its own comment below). The UI held both of these
	// client-side, so they narrowed only the page that happened to load: a
	// "needs action" view could render empty while matching incidents sat past
	// the truncation cap, which showed an operator "nothing to do" when there
	// was something to do.
	//
	// Both live HERE rather than in handleListIncidents because this function is
	// shared by the row query and incidentCountsFor — so the tab counts and the
	// rows they label narrow together by construction, which is the bug the
	// count/row split would otherwise reintroduce one release later.
	if severity := q.Get("severity"); severity != "" {
		if !slices.Contains(validIncidentSeverities, severity) {
			return "", nil, "severity must be one of: " + strings.Join(validIncidentSeverities, ", ")
		}
		args = append(args, severity)
		clause += fmt.Sprintf(" AND incidents.severity = $%d", len(args))
	}
	// "Needs action" is not a state, it is a bucket of them — the same
	// definition incidentCountsQuery's own requires_action_count filter uses
	// (requiresActionStateClause: the counts query interpolates the same
	// string, so a tab's number and the rows beneath it cannot drift apart).
	//
	// This parameter was ?open= for one day, and the rename is the review's
	// finding 9 in one place. "Open" answered "is this row not terminal?",
	// which is a question about the state machine; the product question
	// underneath it is "does anybody still owe this incident work?".
	// ?requiresAction=false is therefore NOT "closed" — it is every incident
	// nobody has to act on, which includes Investigating, Executing,
	// AwaitingMerge and Validating alongside the two closed states. A caller
	// who wants only the closed ones asks for them by ?state=.
	if requiresAction := q.Get("requiresAction"); requiresAction != "" {
		switch requiresAction {
		case "true":
			clause += " AND incidents.state IN " + requiresActionStateClause
		case "false":
			clause += " AND incidents.state NOT IN " + requiresActionStateClause
		default:
			return "", nil, "requiresAction must be true or false"
		}
	}
	// ?status= is the incident list's primary axis: which part of the
	// lifecycle. The buckets are the three dispositions (requiresAction,
	// inProgress, closed — internal/orchestrator's table, mirrored by
	// STATE_DISPOSITION in web/src/utils/incidents.ts) plus "open", the first
	// two together. No value means every state.
	if status := q.Get("status"); status != "" {
		switch status {
		case "open":
			clause += " AND incidents.state NOT IN " + closedStateClause
		case "requiresAction":
			clause += " AND incidents.state IN " + requiresActionStateClause
		case "inProgress":
			clause += " AND incidents.state NOT IN " + requiresActionStateClause + " AND incidents.state NOT IN " + closedStateClause
		case "closed":
			clause += " AND incidents.state IN " + closedStateClause
		default:
			return "", nil, "status must be one of: open, requiresAction, inProgress, closed"
		}
	}
	if fleetGroupID := q.Get("fleetGroupId"); fleetGroupID != "" {
		args = append(args, fleetGroupID)
		clause += fmt.Sprintf(" AND incidents.fleet_group_id = $%d", len(args))
	}
	if workloadGroupID := q.Get("workloadGroupId"); workloadGroupID != "" {
		args = append(args, workloadGroupID)
		clause += fmt.Sprintf(" AND incidents.workload_group_id = $%d", len(args))
	}
	if objectGroupID := q.Get("objectGroupId"); objectGroupID != "" {
		args = append(args, objectGroupID)
		clause += fmt.Sprintf(" AND incidents.object_group_id = $%d", len(args))
	}
	return clause, args, ""
}

// --- BACKLOG P10: server-side sort ---
//
// IncidentsPage used to sort the array it held, in JS, over whatever page
// happened to load — silently a sort of the loaded PREFIX rather than of the
// matching set once the response was truncated (see handleListIncidents'
// pagination doc comment). Six columns, six SQL expressions to order and
// keyset-paginate by; two of them (severity, state) need a real rank rather
// than alphabetical order, the same problem internal/remediation.riskRank
// solves for RiskLevel with a Go map — this is that idea's SQL-side
// counterpart, since the ranking has to live in the ORDER BY itself for a
// keyset cursor over it to mean anything.

type incidentSortKind int

const (
	sortKindTime incidentSortKind = iota
	sortKindInt
	sortKindText
)

// incidentSortSpec is one sortable column: the SQL expression to ORDER BY
// and to keyset-compare a cursor against (the SAME expression in both
// places, so the page boundary and the ordering can never disagree), and
// which of the cursor's typed slots that expression's value belongs in.
type incidentSortSpec struct {
	Expr string
	Kind incidentSortKind
}

// severityOrder/stateOrder are the total orders rankCaseExpr turns into SQL.
// stateOrder is validIncidentStates itself — one source of truth, so a sort
// by state can never rank a value that column's own CHECK constraint
// doesn't, and can't drift from ?state='s own validation the way a second
// hand-written list could.
var severityOrder = []string{"low", "medium", "high", "critical"}
var stateOrder = validIncidentStates

// rankCaseExpr builds a SQL CASE expression giving column a total order
// matching order's sequence. order is always one of this file's own package
// vars above — never request input — so the literals below need no
// placeholder, only quoting (sqlQuoteLiteral) against the outside chance one
// of them ever contains a quote.
func rankCaseExpr(column string, order []string) string {
	var b strings.Builder
	b.WriteString("CASE " + column)
	for i, v := range order {
		fmt.Fprintf(&b, " WHEN %s THEN %d", sqlQuoteLiteral(v), i)
	}
	fmt.Fprintf(&b, " ELSE %d END", len(order))
	return b.String()
}

func sqlQuoteLiteral(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}

// incidentFailureLabelExpr mirrors web/src/utils/incidents.ts's
// incidentFailureLabel exactly (reason · object name, falling back to
// whichever of the two is present, falling back to the fingerprint prefix)
// so that sorting by the "Incident" column server-side orders rows the same
// way the label the operator actually reads would. split_part's field-3 is
// the object NAME half of incidents.object_key's `gvk|namespace|name`
// composite (splitObjectKey's own Go-side parsing) — split_part tolerates a
// malformed/short key by returning the empty string, which only matters for
// a hand-edited or pre-migration row, and degrades to the fingerprint fallback exactly
// like the Go function's own "unexpected shape" branch.
const incidentFailureLabelExpr = `COALESCE(
		NULLIF(
			CASE WHEN COALESCE(incidents.opening_reason, '') <> ''
			      AND COALESCE(split_part(COALESCE(incidents.object_key, ''), '|', 3), '') <> ''
			     THEN incidents.opening_reason || ' · ' || split_part(incidents.object_key, '|', 3)
			END,
			''
		),
		NULLIF(incidents.opening_reason, ''),
		NULLIF(split_part(COALESCE(incidents.object_key, ''), '|', 3), ''),
		'Incident ' || left(incidents.fingerprint, 8)
	)`

// PROJECT.md T1's four raw factor expressions — each read from data this hub
// already durably records, no new detection. Kept as their own named
// constants (rather than inlined once into importanceScoreExpr) because
// handleListIncidents' ?sort=importance path also selects each of these as
// its OWN column, to rebuild importance.Factors in Go for
// incidentSummary.ImportanceExplanation — the explanation must be built from
// the EXACT same values the SQL score used, not independently recomputed.
//
// importanceBlastRadiusExpr: the widest of this incident's three existing
// correlation groups (internal/fleetgroup, internal/replicagroup,
// internal/objectgroup) — GREATEST(...,1) so an incident in no group is its
// own group of one, never zero. Counts every incident sharing a group
// (open or closed): group membership is a historical fact about which
// incidents this fault-shape actually touched, not a live headcount, so a
// since-resolved sibling still legitimately counts toward "how wide was
// this."
const importanceBlastRadiusExpr = `GREATEST(
		COALESCE((SELECT count(*) FROM incidents fg WHERE fg.fleet_group_id = incidents.fleet_group_id AND fg.archived_at IS NULL), 0),
		COALESCE((SELECT count(*) FROM incidents wg WHERE wg.workload_group_id = incidents.workload_group_id AND wg.archived_at IS NULL), 0),
		COALESCE((SELECT count(*) FROM incidents og WHERE og.object_group_id = incidents.object_group_id AND og.archived_at IS NULL), 0),
		1
	)`

// importanceAgeHoursExpr: hours since first_seen.
const importanceAgeHoursExpr = `(EXTRACT(EPOCH FROM (now() - incidents.first_seen)) / 3600.0)`

// importanceOccurrenceRateExpr: how many times this incident has recurred
// BEYOND its first sighting, per hour open — occurrence_count - 1, not the
// raw count. A first-ever sighting (occurrence_count = 1) is not yet a
// trend and must score/read as zero recurrence, not "recurring": dividing
// the RAW count by an hours-open figure floored at 1 (needed so a
// few-minutes-old incident's rate isn't inflated by a near-zero
// denominator) would otherwise make every brand-new incident evaluate to
// exactly 1.0/hour regardless of whether anything ever actually recurred —
// caught by this file's own DB-backed test asserting a genuinely one-off,
// two-minutes-old incident produces NO recurrence explanation.
const importanceOccurrenceRateExpr = `(GREATEST(incidents.occurrence_count - 1, 0)::float8 / GREATEST(` + importanceAgeHoursExpr + `, 1))`

// importanceConfidenceExpr: the latest analysis's own stated confidence, or
// SQL NULL when none exists yet — deliberately NOT wrapped in COALESCE here
// (importance.SQLExpr's own combined expression does that once, for the
// score; the raw per-row column below stays nullable so Go can tell "no
// analysis yet" apart from "confidence 0").
const importanceConfidenceExpr = `(SELECT a.confidence FROM analyses a WHERE a.incident_id = incidents.id ORDER BY a.created_at DESC LIMIT 1)`

// importanceWorkloadCriticalityExpr: the resolved spec.priority of the Pod
// that OPENED this incident, stamped once at open (migration 000111). Left
// nullable on purpose and NOT wrapped in COALESCE here — the combined score
// expression clamps and log-scales it once, while the raw per-row column
// below stays nullable so Go can tell "no priority signal" (a non-Pod, an
// older agent, or a Pod the admission plugin never stamped) apart from a
// real, resolved priority of 0.
const importanceWorkloadCriticalityExpr = `incidents.pod_priority`

// importanceScoreExpr is the one ORDER BY/keyset-cursor expression for
// ?sort=importance — built from the five raw expressions above via
// internal/importance.SQLExprWithCriticality, so its weights can never
// independently drift from Explain's (see that package's own doc comment).
var importanceScoreExpr = importance.SQLExprWithCriticality(importanceBlastRadiusExpr, importanceAgeHoursExpr, importanceOccurrenceRateExpr, importanceConfidenceExpr, importanceWorkloadCriticalityExpr)

// incidentSortSpecs is deliberately not exported and has no default entry:
// handleListIncidents always resolves a ?sort= (defaulting to "lastSeen")
// against this map itself, so a typo in a sort key is a 400, not a silent
// fall-through to the default ordering.
var incidentSortSpecs = map[string]incidentSortSpec{
	"lastSeen":    {Expr: "incidents.last_seen", Kind: sortKindTime},
	"occurrences": {Expr: "incidents.occurrence_count", Kind: sortKindInt},
	"cluster":     {Expr: "clusters.display_name", Kind: sortKindText},
	"severity":    {Expr: rankCaseExpr("incidents.severity", severityOrder), Kind: sortKindInt},
	"state":       {Expr: rankCaseExpr("incidents.state", stateOrder), Kind: sortKindInt},
	"failure":     {Expr: incidentFailureLabelExpr, Kind: sortKindText},
	// PROJECT.md T1: blast radius + duration/trend + evidence learned during
	// analysis, combined into one explainable, kind-agnostic ranking — see
	// this file's importance* constants and internal/importance's own doc
	// comment for why workload criticality (T1's fourth named factor) is not
	// included yet.
	"importance": {Expr: importanceScoreExpr, Kind: sortKindInt},
}

// incidentSortKeysSorted is incidentSortSpecs' keys in a fixed order for the
// 400 body — map iteration order is random in Go, and that list must not
// vary request to request.
var incidentSortKeysSorted = []string{"failure", "cluster", "severity", "state", "occurrences", "lastSeen", "importance"}

// escapeLikePattern escapes the three characters ILIKE treats specially
// (the wildcards %/_ and the escape character itself) out of a caller's raw
// ?search= text before it is wrapped in %...% and sent as a pattern —
// without this, searching for a literal "%" or "_" (both appear in real
// k8s object names) would silently mean something else.
func escapeLikePattern(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, "%", `\%`)
	s = strings.ReplaceAll(s, "_", `\_`)
	return s
}

// encodeIncidentSortCursor/decodeIncidentSortCursor are the keyset token for
// every sort key OTHER than the default "lastSeen", which keeps its own
// pre-existing encodeIncidentCursor/decodeIncidentCursor pair below,
// completely unchanged — BACKLOG P10 flagged the cursor as the hard part
// ("sort by severity cannot reuse the (last_seen, id) token") precisely
// because the paginated value's TYPE changes with the sort key. One encoding
// covers the other five sort keys' two shapes (an integer rank for
// severity/state/occurrences, free text for cluster/failure) rather than
// four near-identical ones, because the thing that actually has to travel
// with the value is not its Go type but WHICH sort key produced it — a
// cursor minted under one sort must never be silently applied to another,
// and handleListIncidents checks that explicitly rather than assuming a
// caller's cursor and ?sort= always agree.
//
// Payload: id + "|" + sortKey + "|" + value. id and sortKey come first
// because both are guaranteed never to contain "|" (a ULID, and a fixed key
// out of incidentSortSpecs) — value comes last and is read as everything
// after the second "|", so a cluster display name or a failure label that
// happens to contain a literal "|" still round-trips exactly.
func encodeIncidentSortCursor(id, sortKey, value string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(id + "|" + sortKey + "|" + value))
}

func decodeIncidentSortCursor(cursor string) (id, sortKey, value string, err error) {
	raw, err := base64.RawURLEncoding.DecodeString(cursor)
	if err != nil {
		return "", "", "", fmt.Errorf("decode cursor: %w", err)
	}
	parts := strings.SplitN(string(raw), "|", 3)
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" {
		return "", "", "", fmt.Errorf("malformed cursor payload")
	}
	return parts[0], parts[1], parts[2], nil
}

// --- BACKLOG P10: server-side quick-view counts ---

// incidentCounts is IncidentsPage's five quick-view tab numbers
// (all/requiresAction/critical/high/medium), computed here rather than by counting
// the array the list query happened to return: that used to silently shrink
// once a fleet had enough open incidents to fill a page (see
// handleListIncidents' pagination doc comment). This is a second aggregate
// query in the SAME clusterId/state/fleetGroupId/workloadGroupId/objectGroupId scope as
// the list itself, but never limited by ?limit=/?cursor=, so these five
// numbers are always exact — the same "count the whole history, not the
// bounded slice sent alongside it" discipline findingReasonGroup already
// applies to a different list.
//
// Deliberately NOT scoped by ?search=: the quick-view tabs never reacted to
// the search box before this change either (the old client-side count ran
// over the fetched array before the text filter was applied), and keeping
// that means typing in the search box narrows the rows without also
// rewriting the tab counts out from under the operator mid-keystroke.
type incidentCounts struct {
	All int `json:"all"`
	// RequiresAction was `open` until the review's finding 9. Renamed rather
	// than redefined: this number now counts something different (see
	// requiresActionStateClause), and leaving it called "open" while it
	// excluded Investigating and Executing would have been the same
	// count-says-one-thing-rows-say-another bug in a new place. The UI tab it
	// feeds is labelled "Needs action" for the same reason.
	RequiresAction int `json:"requiresAction"`
	// Open is "the lifecycle is not over" — the complement of
	// orchestrator.ClosedStateSQL, which is the complement of
	// DispositionClosed. Deliberately NOT the same question as
	// RequiresAction: an incident ARGUS is mid-investigation on, or one
	// waiting for a reviewer to merge a pull request, is open and owes a
	// human nothing. Both numbers are on the overview and they are supposed
	// to differ; a single "open" figure covering both is what the review's
	// finding 9 removed.
	//
	// Whole-set, like every field here — the overview used to derive this by
	// filtering the fetched page, which silently understated it the moment
	// the list truncated.
	Open int `json:"open"`
	// ResolvedLast7Days counts transitions INTO a resolved state in the last
	// seven days, from incidents.resolved_at (stamped by
	// orchestrator.SetState via IsClosed, migration 000021).
	//
	// Two things it is careful about. It counts `resolved_at`, not the
	// current state, so an incident that resolved and later reopened is still
	// counted for the week it resolved in — the question is "did work land",
	// not "is it closed right now". And it is a rolling seven days from the
	// request's own `now()`, never a calendar week, because a Monday-morning
	// figure that resets to zero reads as a regression rather than as a new
	// window.
	ResolvedLast7Days int `json:"resolvedLast7Days"`
	// FixNotHeld is the quality signal the overview leads with: attempts that
	// failed, could not be established, or came back. Distinct from
	// RequiresAction (which includes everything nobody has tried yet) and from
	// Open (which includes everything healthy-but-unfinished).
	FixNotHeld int `json:"fixNotHeld"`
	Critical   int `json:"critical"`
	High       int `json:"high"`
	Medium     int `json:"medium"`
}

// incidentSearchClause is ?search= as SQL, appended after the scope clause
// with its one argument numbered after the ones already in args. Shared by
// the row query and the status × severity breakdown, so a search narrows the
// counts on the filter controls exactly as it narrows the rows.
func incidentSearchClause(search string, args []any) (string, []any) {
	args = append(args, "%"+escapeLikePattern(search)+"%")
	n := len(args)
	return fmt.Sprintf(` AND (
			incidents.fingerprint ILIKE $%d ESCAPE '\' OR
			incidents.id ILIKE $%d ESCAPE '\' OR
			clusters.display_name ILIKE $%d ESCAPE '\' OR
			incidents.cluster_id ILIKE $%d ESCAPE '\' OR
			incidents.opening_reason ILIKE $%d ESCAPE '\' OR
			incidents.object_key ILIKE $%d ESCAPE '\'
		)`, n, n, n, n, n, n), args
}

// incidentBreakdownCell is one (status, severity) cell of the list's filter
// counts. Status is the disposition: requiresAction, inProgress or closed.
type incidentBreakdownCell struct {
	Status   string `json:"status"`
	Severity string `json:"severity"`
	Count    int    `json:"count"`
}

// incidentBreakdownFor counts the request's matching incidents by status and
// severity, with every filter applied EXCEPT ?status=, ?severity= and
// ?requiresAction= (the two axes being counted). The incident list draws both
// controls from it: a status tab's number is its row of this matrix under
// the chosen severity, and a severity option's number is its column under the
// chosen status. Each control therefore counts what clicking it would show,
// given every other filter, search included.
func incidentBreakdownFor(ctx context.Context, rc *requestContext, r *http.Request) ([]incidentBreakdownCell, error) {
	stripped := r.Clone(ctx)
	q := stripped.URL.Query()
	q.Del("status")
	q.Del("severity")
	q.Del("requiresAction")
	stripped.URL.RawQuery = q.Encode()
	scopeClause, args, invalid := incidentScopeFilter(stripped)
	if invalid != "" {
		return nil, fmt.Errorf("unexpected invalid scope filter: %s", invalid)
	}
	query := `
	SELECT CASE
	         WHEN incidents.state IN ` + requiresActionStateClause + ` THEN 'requiresAction'
	         WHEN incidents.state IN ` + closedStateClause + ` THEN 'closed'
	         ELSE 'inProgress'
	       END AS status,
	       incidents.severity,
	       count(*)
	  FROM incidents
	  JOIN clusters ON clusters.id = incidents.cluster_id
	 WHERE incidents.archived_at IS NULL` + scopeClause
	if search := q.Get("search"); search != "" {
		var clause string
		clause, args = incidentSearchClause(search, args)
		query += clause
	}
	query += ` GROUP BY 1, 2`
	rows, err := rc.Tx.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []incidentBreakdownCell{}
	for rows.Next() {
		var c incidentBreakdownCell
		if err := rows.Scan(&c.Status, &c.Severity, &c.Count); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// incidentCountsQuery's FILTER clauses are the same bucket definitions
// quickView encodes in web/src/pages/IncidentsPage.tsx. The requires-action
// bucket is an enumerated IN-list rather than the complement of the terminal
// states, and that is deliberate: a new state must be classified in
// internal/orchestrator's disposition table before it can appear here at all
// (an unclassified one still surfaces — DispositionOf falls back to
// requires-action — but a Go test fails on it, which is the point).
var incidentCountsQuery = `
	SELECT
	    count(*) AS all_count,
	    count(*) FILTER (WHERE incidents.state IN ` + requiresActionStateClause + `) AS requires_action_count,
	    count(*) FILTER (WHERE incidents.state NOT IN ` + closedStateClause + `) AS open_count,
	    count(*) FILTER (WHERE incidents.resolved_at >= now() - interval '7 days') AS resolved_last_7_days_count,
	    count(*) FILTER (WHERE incidents.state IN ` + fixNotHeldStateClause + `) AS fix_not_held_count,
	    count(*) FILTER (WHERE incidents.severity = 'critical') AS critical_count,
	    count(*) FILTER (WHERE incidents.severity = 'high') AS high_count,
	    count(*) FILTER (WHERE incidents.severity = 'medium') AS medium_count
	  FROM incidents
	  JOIN clusters ON clusters.id = incidents.cluster_id
	 WHERE incidents.archived_at IS NULL`

// incidentCountsFor runs incidentCountsQuery scoped exactly like the calling
// request's list query. A fresh call to incidentScopeFilter, not the
// caller's already-built clause/args: each call starts its own placeholder
// numbering from $1, so this query can never collide with the differently
// shaped list query built alongside it in the same request. The scope
// filter was already validated once before this is reached (handleListIncidents
// checks it first), so an error here would mean the two calls disagreed
// about the same request, which should not happen.
func incidentCountsFor(ctx context.Context, rc *requestContext, r *http.Request) (incidentCounts, error) {
	scopeClause, scopeArgs, invalid := incidentScopeFilter(r)
	if invalid != "" {
		return incidentCounts{}, fmt.Errorf("unexpected invalid scope filter: %s", invalid)
	}
	var counts incidentCounts
	err := rc.Tx.QueryRow(ctx, incidentCountsQuery+scopeClause, scopeArgs...).
		Scan(&counts.All, &counts.RequiresAction, &counts.Open, &counts.ResolvedLast7Days,
			&counts.FixNotHeld, &counts.Critical, &counts.High, &counts.Medium)
	return counts, err
}

// handleListIncidents is GET /api/v1/incidents. Requires incident:read.
// Ordered by ?sort=/?direction= (default last_seen DESC — most recently
// active incident first). Accepts several optional, independently-ANDed
// query parameters:
//
//   - ?clusterId= (ClusterDetailPage's use of this same list endpoint to
//     show "this cluster's own incidents" — no separate endpoint)
//   - ?state= (one of validIncidentStates, the exact enum incidents.state's
//     CHECK constraint defines; an unrecognized value is a 400, not a query
//     that silently matches nothing)
//   - ?fleetGroupId= (surfaces one fleet-wide group's own member incidents —
//     internal/fleetgroup.Recompute is what actually assigns this value;
//     no validation against a known-values list the way ?state= gets, since
//     group ids are freely generated ULIDs, not a fixed enum — an unknown
//     id here is not an error, it's simply a filter that matches nothing,
//     the same as filtering ?clusterId= by a cluster id that doesn't exist)
//   - ?workloadGroupId= (the replica-level counterpart — internal/
//     replicagroup.Recompute assigns this; same "unknown id matches
//     nothing, not an error" treatment as ?fleetGroupId=)
//   - ?objectGroupId= (the cross-object counterpart, BACKLOG.md A3b —
//     internal/objectgroup.Recompute assigns this; same tolerant treatment
//     as the two group-id filters above)
//   - ?severity= (one of validIncidentSeverities; an unrecognized value is a
//     400, for ?state='s reason — a filter that silently matches nothing
//     reads to an operator as "there is none of that")
//   - ?requiresAction=true|false (the incident queue's own definition — see
//     requiresActionStateClause. "false" is not "closed": it is everything
//     nobody owes work on, in-flight states included)
//   - ?search= (BACKLOG P10 — free text, ILIKE'd across the same seven
//     fields IncidentsPage used to filter client-side: fingerprint, id,
//     cluster display name, cluster id, opening reason, and object
//     name/namespace via the object_key composite they're both substrings
//     of. See the search-clause comment below for the ILIKE-vs-index call.)
//   - ?sort=/?direction= (BACKLOG P10 — one of incidentSortSpecs' six keys
//     — failure, cluster, severity, state, occurrences, lastSeen — and
//     "asc"/"desc"; defaults to lastSeen/desc, the endpoint's original and
//     only ordering before this parameter existed)
//
// When any of these is absent, behavior for that dimension is unchanged
// from before the parameter existed.
//
// # Pagination (BACKLOG P9)
//
// This endpoint used to return EVERY matching row. That was invisible at 178
// incidents and is not a rounding error on a real fleet: at the time the
// incident list polled every five seconds, so a tenant with 10,000 open
// incidents re-serialised all of them twelve times a minute, per open tab.
// PROJECT.md P16 has since cut that rate (the live event stream refreshes the
// list, with a 60s fallback poll), which lowers the standing cost and does
// nothing about the burst one: an incident event still means a full page, and
// on a busy fleet the events come steadily.
//
//   - ?limit= caps the page. Defaults to defaultIncidentPageLimit and is clamped
//     to maxIncidentPageLimit — a caller cannot ask for everything by passing a
//     huge number, which is the loophole that would leave the old behaviour
//     reachable.
//   - ?cursor= continues from a previous response's nextCursor.
//
// Keyset, never OFFSET, and `lld/10-api-spec.md` rules out offset pagination
// explicitly. The reason bites harder here than in the audit log: this list is
// ordered by last_seen DESC over rows whose last_seen changes constantly, and an
// offset page would skip and repeat rows as incidents are re-seen underneath the
// reader. The same argument applies to every other sort key on a fleet where
// occurrence_count/state/severity are also live-mutating columns, which is why
// every one of them gets its own keyset cursor rather than a shared numbered page
// (see incidentSortSpecs, encodeIncidentSortCursor).
//
// **The honest limit of a keyset cursor over a MUTABLE sort key**, which the audit
// log does not have to worry about because occurred_at never changes: an incident
// whose last_seen jumps to now while a reader is on page 3 moves to page 1. It will
// not be returned twice — the (last_seen, id) comparison excludes it — but a reader
// who has already read page 1 will not see it at all until they start again. That
// is the correct trade against duplicates, and it is why the response is not
// presented to the operator as a stable numbered set.
//
// nextCursor is present only when a full page came back, so a client that ignores
// it entirely keeps working — the shape did not change, a field was added. The
// same is true of "counts" (BACKLOG P10's third piece): always present, and always
// an aggregate over the FULL clusterId/state/fleetGroupId/workloadGroupId/objectGroupId-scoped
// set, never affected by ?limit=/?cursor= — see incidentCountsFor.
func (s *Server) handleListIncidents(w http.ResponseWriter, r *http.Request, rc *requestContext) {
	scopeClause, scopeArgs, invalid := incidentScopeFilter(r)
	if invalid != "" {
		writeProblem(w, http.StatusBadRequest, "https://argus.io/errors/invalid-request",
			"Invalid state filter", invalid)
		return
	}
	// One parse of the query string for the whole handler: r.URL.Query()
	// re-parses RawQuery and allocates a fresh url.Values on every call.
	q := r.URL.Query()

	sortKey := q.Get("sort")
	if sortKey == "" {
		sortKey = "lastSeen"
	}
	spec, ok := incidentSortSpecs[sortKey]
	if !ok {
		writeProblem(w, http.StatusBadRequest, "https://argus.io/errors/invalid-request",
			"Invalid sort key", "sort must be one of: "+strings.Join(incidentSortKeysSorted, ", "))
		return
	}
	direction := q.Get("direction")
	if direction == "" {
		direction = "desc"
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

	// The extra column is only needed to recover the value the ORDER BY
	// actually used, for the next cursor — lastSeen's cursor is built from
	// incidents.last_seen, already in incidentListColumns, so it skips this
	// entirely rather than selecting a redundant second copy of the same
	// column.
	query := "SELECT " + incidentListColumns
	if sortKey != "lastSeen" {
		query += ", (" + spec.Expr + ") AS sort_value"
	}
	if sortKey == "importance" {
		// The five raw factors, as their OWN columns — so Go can rebuild the
		// exact importance.Factors the sort_value/ORDER BY expression scored,
		// for ImportanceExplanation, rather than recomputing anything.
		query += ", (" + importanceBlastRadiusExpr + "), (" + importanceAgeHoursExpr + "), (" +
			importanceOccurrenceRateExpr + "), (" + importanceConfidenceExpr + "), (" +
			importanceWorkloadCriticalityExpr + ")"
	}
	query += incidentListFrom + scopeClause
	args := append([]any{}, scopeArgs...)

	// ?search=: ILIKE across the six columns above (object name and object
	// namespace share one ILIKE against the object_key composite they are
	// both substrings of, which is why the doc comment above lists seven
	// searched fields against six conditions).
	//
	// Deliberately plain ILIKE, not a trigram/full-text index, and that is a
	// deliberate call rather than the default: ARGUS's target scale is 200+
	// clusters (argus-context skill / DESIGN.md §5.1), not millions of open
	// incidents, and this scan already runs under whatever clusterId/state
	// scope and archived_at IS NULL already bound it to. A sequential ILIKE
	// scan over a fleet's open incidents (thousands, not millions) is
	// millisecond-order; a pg_trgm GIN index is real, standing infrastructure
	// — an extension, a migration, an index-maintenance cost paid on every
	// write to this hot table — for a problem this fleet size does not have.
	// Revisit if CAPABILITIES.md ever records this endpoint slow against a
	// real fleet; that observed evidence is the trigger, not a guess made now.
	if search := q.Get("search"); search != "" {
		var clause string
		clause, args = incidentSearchClause(search, args)
		query += clause
	}

	if cursor := q.Get("cursor"); cursor != "" {
		if sortKey == "lastSeen" {
			cursorLastSeen, cursorID, err := decodeIncidentCursor(cursor)
			if err != nil {
				writeProblem(w, http.StatusBadRequest, "https://argus.io/errors/malformed-request",
					"Invalid cursor", "cursor is not a valid page-continuation token")
				return
			}
			args = append(args, cursorLastSeen, cursorID)
			query += fmt.Sprintf(" AND (incidents.last_seen, incidents.id) %s ($%d, $%d)", cmp, len(args)-1, len(args))
		} else {
			cursorID, cursorSortKey, cursorValue, err := decodeIncidentSortCursor(cursor)
			if err != nil || cursorSortKey != sortKey {
				// A cursor minted under a different ?sort= is exactly as
				// invalid as a garbled one — applying its value against
				// THIS sort's expression would compare unrelated things and
				// silently mis-paginate rather than error.
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

	limit, err := incidentPageLimit(q.Get("limit"))
	if err != nil {
		writeProblem(w, http.StatusBadRequest, "https://argus.io/errors/malformed-request",
			"Invalid limit", err.Error())
		return
	}
	args = append(args, limit)
	// id is the tiebreaker, not decoration: none of these sort columns are
	// unique (a storm re-sees many incidents in the same instant; several
	// incidents legitimately share a severity or a state), and a keyset
	// cursor over a non-unique sort key silently drops or repeats the tied
	// rows without it.
	query += fmt.Sprintf(" ORDER BY %s %s, incidents.id %s LIMIT $%d", spec.Expr, sqlDir, sqlDir, len(args))

	rows, err := rc.Tx.Query(r.Context(), query, args...)
	if err != nil {
		logger.ErrorContext(r.Context(), "querying incidents failed", logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not list incidents", "")
		return
	}
	defer rows.Close()

	incidents := []incidentSummary{}
	var lastSeen time.Time
	var lastID string
	var lastSortInt int64
	var lastSortText string
	for rows.Next() {
		if sortKey == "lastSeen" {
			inc, rawLastSeen, scanErr := scanIncidentSummaryWithLastSeen(rows)
			if scanErr != nil {
				err = scanErr
				break
			}
			incidents = append(incidents, inc)
			lastSeen, lastID = rawLastSeen, inc.ID
		} else {
			inc, sortInt, sortText, scanErr := scanIncidentSummaryWithSortValue(rows, spec.Kind, sortKey)
			if scanErr != nil {
				err = scanErr
				break
			}
			incidents = append(incidents, inc)
			lastID, lastSortInt, lastSortText = inc.ID, sortInt, sortText
		}
	}
	if err != nil {
		logger.ErrorContext(r.Context(), "scanning an incident row failed", logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not list incidents", "")
		return
	}
	if err := rows.Err(); err != nil {
		logger.ErrorContext(r.Context(), "iterating the incident rows failed", logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not list incidents", "")
		return
	}

	resp := map[string]any{"incidents": incidents}
	// A full page might not be the last page; handing back a cursor costs one
	// extra empty request in the exact-multiple case, which is cheaper than a
	// COUNT(*) or a limit+1 fetch. Same trade handleListAuditEvents makes.
	if len(incidents) == limit {
		if sortKey == "lastSeen" {
			resp["nextCursor"] = encodeIncidentCursor(lastSeen, lastID)
		} else if spec.Kind == sortKindInt {
			resp["nextCursor"] = encodeIncidentSortCursor(lastID, sortKey, strconv.FormatInt(lastSortInt, 10))
		} else {
			resp["nextCursor"] = encodeIncidentSortCursor(lastID, sortKey, lastSortText)
		}
	}

	counts, err := incidentCountsFor(r.Context(), rc, r)
	if err != nil {
		logger.ErrorContext(r.Context(), "reading the incident counts failed", logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not count incidents", "")
		return
	}
	resp["counts"] = counts

	breakdown, err := incidentBreakdownFor(r.Context(), rc, r)
	if err != nil {
		logger.ErrorContext(r.Context(), "reading the incident breakdown failed", logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not count incidents", "")
		return
	}
	resp["breakdown"] = breakdown

	if q.Get("groups") == "lookalike" {
		groups, err := incidentLookalikeGroupsFor(r.Context(), rc, r)
		if err != nil {
			logger.ErrorContext(r.Context(), "reading the look-alike groups failed", logging.Err(err))
			writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not count incidents", "")
			return
		}
		resp["lookalikeGroups"] = groups
	}

	writeJSON(w, http.StatusOK, resp)
}

// incidentLookalikeGroup counts the incidents that share a kind, namespace,
// opening reason, severity and state across everything the request matches,
// not just the page, so a cluster's grouped list states whole-set counts
// past the page cap (PROJECT.md UX13). Key matches the web client's
// groupKey: kind|namespace|reason|severity|state.
type incidentLookalikeGroup struct {
	Key   string `json:"key"`
	Count int    `json:"count"`
}

func incidentLookalikeGroupsFor(ctx context.Context, rc *requestContext, r *http.Request) ([]incidentLookalikeGroup, error) {
	scopeClause, args, invalid := incidentScopeFilter(r)
	if invalid != "" {
		return nil, fmt.Errorf("unexpected invalid scope filter: %s", invalid)
	}
	query := `
	SELECT concat_ws('|',
	         regexp_replace(split_part(COALESCE(incidents.object_key, ''), '|', 1), '^.*/', ''),
	         split_part(COALESCE(incidents.object_key, ''), '|', 2),
	         COALESCE(incidents.opening_reason, ''),
	         incidents.severity,
	         incidents.state) AS key,
	       count(*)
	  FROM incidents
	  JOIN clusters ON clusters.id = incidents.cluster_id
	 WHERE incidents.archived_at IS NULL` + scopeClause
	if search := r.URL.Query().Get("search"); search != "" {
		var clause string
		clause, args = incidentSearchClause(search, args)
		query += clause
	}
	query += ` GROUP BY 1 HAVING count(*) > 1 ORDER BY 2 DESC LIMIT 500`
	rows, err := rc.Tx.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []incidentLookalikeGroup{}
	for rows.Next() {
		var g incidentLookalikeGroup
		if err := rows.Scan(&g.Key, &g.Count); err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

// Page-size bounds for handleListIncidents.
//
// The default is large because the UI still filters, searches, sorts and counts
// over the array it receives (BACKLOG P9's second half is moving that work to the
// server). A small default would not "paginate" that UI — it would make its search
// return wrong answers with no indication, which is worse than a big response.
// This bounds the pathological case honestly and leaves the UI's behaviour intact
// on any fleet below the cap.
const (
	defaultIncidentPageLimit = 500
	maxIncidentPageLimit     = 1000
)

// incidentPageLimit parses ?limit=, rejecting nonsense rather than clamping it
// silently. Clamping a too-large value quietly would let a caller keep asking for
// everything and be told nothing about the cap.
func incidentPageLimit(raw string) (int, error) {
	if raw == "" {
		return defaultIncidentPageLimit, nil
	}
	n, err := strconv.Atoi(raw)
	if err != nil {
		return 0, fmt.Errorf("limit must be a whole number")
	}
	if n < 1 {
		return 0, fmt.Errorf("limit must be at least 1")
	}
	if n > maxIncidentPageLimit {
		return 0, fmt.Errorf("limit must be at most %d; use the nextCursor from the previous response to read further", maxIncidentPageLimit)
	}
	return n, nil
}

// encodeIncidentCursor/decodeIncidentCursor are handleListIncidents' keyset token:
// base64(last_seen in RFC3339Nano + "|" + id).
//
// Deliberately the same shape and the same NON-sealed choice as the audit log's
// cursor — there is nothing in a (last_seen, id) pair that the caller cannot
// already read in the same response, so signing it would protect nothing. Kept as
// its own pair of functions rather than shared with the audit one so that changing
// either list's sort key cannot silently invalidate the other's tokens.
func encodeIncidentCursor(lastSeen time.Time, id string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(lastSeen.UTC().Format(time.RFC3339Nano) + "|" + id))
}

func decodeIncidentCursor(cursor string) (time.Time, string, error) {
	raw, err := base64.RawURLEncoding.DecodeString(cursor)
	if err != nil {
		return time.Time{}, "", fmt.Errorf("decode cursor: %w", err)
	}
	lastSeenStr, id, ok := strings.Cut(string(raw), "|")
	if !ok || lastSeenStr == "" || id == "" {
		return time.Time{}, "", fmt.Errorf("malformed cursor payload")
	}
	lastSeen, err := time.Parse(time.RFC3339Nano, lastSeenStr)
	if err != nil {
		return time.Time{}, "", fmt.Errorf("parse cursor timestamp: %w", err)
	}
	return lastSeen, id, nil
}

// scanIncidentSummary scans one row shaped like incidentListQuery's SELECT
// into an incidentSummary. Three callers want only this; handleListIncidents
// needs the raw last_seen as well, for its keyset cursor.
func scanIncidentSummary(row pgx.Row) (incidentSummary, error) {
	inc, _, err := scanIncidentSummaryWithLastSeen(row)
	return inc, err
}

// scanIncidentSummaryWithLastSeen also returns last_seen as a time.Time.
//
// incidentSummary.LastSeen is a formatted string, and re-parsing it to build a
// cursor would round-trip through second-or-so precision — enough for two
// incidents re-seen in the same storm to compare equal and be skipped by the
// keyset comparison. Carrying the original value avoids inventing a bug in a
// format conversion.
func scanIncidentSummaryWithLastSeen(row pgx.Row) (incidentSummary, time.Time, error) {
	var inc incidentSummary
	var firstSeen, lastSeen time.Time
	var objectKey *string
	var resolvedAt *time.Time
	if err := row.Scan(&inc.ID, &inc.ClusterID, &inc.ClusterDisplayName, &inc.Fingerprint,
		&inc.Severity, &inc.State, &firstSeen, &lastSeen, &inc.OccurrenceCount, &inc.FleetGroupID,
		&inc.WorkloadGroupID, &inc.WorkloadKey, &inc.OpeningReason, &objectKey, &resolvedAt,
		&inc.ObjectGroupID, &inc.RelatedWorkloadKey, &inc.ResolutionKind, &inc.Route); err != nil {
		return incidentSummary{}, time.Time{}, err
	}
	finishIncidentSummaryScan(&inc, firstSeen, lastSeen, objectKey, resolvedAt)
	return inc, lastSeen, nil
}

// scanIncidentSummaryWithSortValue is scanIncidentSummaryWithLastSeen's
// counterpart for every sort key OTHER than "lastSeen": the row carries one
// extra trailing column (handleListIncidents' "sort_value", the ORDER BY
// expression's own value for this row), scanned into whichever of sortInt/
// sortText matches kind so the next page's cursor can be built from the
// EXACT value the ORDER BY used — never a value independently recomputed in
// Go, which could drift from the SQL expression it's supposed to match and
// silently corrupt the keyset boundary.
//
// sortKey == "importance" carries five MORE trailing columns (the raw
// factors handleListIncidents' query appends for exactly this sort key) —
// scanned and turned into inc.ImportanceExplanation via
// internal/importance.Explain, from the SAME values sort_value's own score
// was built from, never re-derived independently.
func scanIncidentSummaryWithSortValue(rows pgx.Rows, kind incidentSortKind, sortKey string) (inc incidentSummary, sortInt int64, sortText string, err error) {
	var firstSeen, lastSeen time.Time
	var objectKey *string
	var resolvedAt *time.Time
	dest := []any{&inc.ID, &inc.ClusterID, &inc.ClusterDisplayName, &inc.Fingerprint,
		&inc.Severity, &inc.State, &firstSeen, &lastSeen, &inc.OccurrenceCount, &inc.FleetGroupID,
		&inc.WorkloadGroupID, &inc.WorkloadKey, &inc.OpeningReason, &objectKey, &resolvedAt,
		&inc.ObjectGroupID, &inc.RelatedWorkloadKey, &inc.ResolutionKind, &inc.Route}
	if kind == sortKindInt {
		dest = append(dest, &sortInt)
	} else {
		dest = append(dest, &sortText)
	}
	var blastRadius int64
	var ageHours, occurrenceRate float64
	var confidence *float64
	var workloadCriticality *int32
	if sortKey == "importance" {
		dest = append(dest, &blastRadius, &ageHours, &occurrenceRate, &confidence, &workloadCriticality)
	}
	if err = rows.Scan(dest...); err != nil {
		return incidentSummary{}, 0, "", err
	}
	finishIncidentSummaryScan(&inc, firstSeen, lastSeen, objectKey, resolvedAt)
	if sortKey == "importance" {
		inc.ImportanceExplanation = importance.Explain(importance.Factors{
			BlastRadius:    int(blastRadius),
			AgeHours:       ageHours,
			OccurrenceRate: occurrenceRate,
			Confidence:     confidence,
			// nil stays nil: Explain omits the factor entirely rather than
			// reporting a fabricated zero-criticality reason.
			WorkloadCriticality: workloadCriticality,
		})
	}
	return inc, sortInt, sortText, nil
}

// finishIncidentSummaryScan is the formatting/derivation tail shared by both
// scan functions above, factored out so the object_key split and the
// resolved_at/last_seen/first_seen formatting can never drift between the
// "just the fixed columns" and "fixed columns plus one sort-value column"
// cases.
func finishIncidentSummaryScan(inc *incidentSummary, firstSeen, lastSeen time.Time, objectKey *string, resolvedAt *time.Time) {
	inc.FirstSeen = formatRFC3339(firstSeen)
	inc.LastSeen = formatRFC3339(lastSeen)
	if resolvedAt != nil {
		formatted := formatRFC3339(*resolvedAt)
		inc.ResolvedAt = &formatted
	}
	// Split rather than shipped raw, for the same reason the tolerations view
	// does it (splitObjectKey's own doc comment): the composite ends with the
	// object NAME, so any client that width-limits the string loses exactly the
	// part that identifies what failed. Left omitted entirely when object_key
	// is NULL — the fingerprint-only fallback — so a client can tell "no object"
	// from "an object with empty fields".
	if objectKey != nil && *objectKey != "" {
		gvk, ns, name := splitObjectKey(*objectKey)
		inc.ObjectGVK, inc.ObjectNamespace, inc.ObjectName = &gvk, &ns, &name
	}
}

// findingSummary is one element of handleGetIncident's "findings" array.
// Deliberately a narrower field set than the full findings table (or
// tunnel.Finding) — exactly the fields the API contract below specifies,
// e.g. detector_version/object_uid/resource_version are stored but not
// exposed here.
type findingSummary struct {
	ID              string `json:"id"`
	DetectorID      string `json:"detectorId"`
	GVK             string `json:"gvk"`
	Namespace       string `json:"namespace"`
	ObjectName      string `json:"objectName"`
	Reason          string `json:"reason"`
	Message         string `json:"message"`
	Severity        string `json:"severity"`
	OccurrenceCount int    `json:"occurrenceCount"`
	OccurredAt      string `json:"occurredAt"`
}

// maxFindingsPerReason bounds how many individual findings one reason
// contributes to a GET /incidents/{id} response.
//
// Findings accumulate without limit on a long-lived incident, for two
// compounding reasons: object-level correlation (migration 000036) deliberately
// attaches every distinct symptom of one broken object to a single incident, and
// each agent-side detector re-sends its own fingerprint once per resend cooldown
// for as long as the problem persists. One incident on the cluster this repo is
// tested against already holds 81 findings for a single broken pod — 34
// ImagePullBackOff, 34 ErrImagePull, 13 Failed — and that number tracks how long
// the pod has been broken, not how much there is to know about it.
//
// The 34th repeat of ImagePullBackOff is not evidence. That it happened 34
// times, first at 17:02 and last at 21:15, is — so the response carries every
// reason's totals in full (findingReasonGroup) and only the newest few
// individual events beneath each. Ten is enough to see whether the repeats are
// seconds or hours apart, which is the question the raw rows get asked.
//
// Bounded per reason rather than per incident on purpose: a flat "newest 30
// findings" cap would have dropped the Failed reason entirely behind the two
// noisier ones, hiding exactly the structure this history exists to show. The
// payload therefore scales with the number of distinct symptoms one object
// showed — a small number set by the detectors' reason vocabulary — instead of
// with the incident's age.
const maxFindingsPerReason = 10

// findingReasonGroup is one reason's whole-history totals for an incident: how
// often it has been reported, and the window it has been happening in.
//
// Computed over EVERY stored finding for that reason, never over the bounded
// subset sent alongside it (see incidentFindingsQuery). A count that quietly
// meant "of the ones we happened to send" would be worse than no count at all:
// it is the number an operator reads to judge whether a symptom is settling down
// or accelerating, and a silently-capped 10 says the opposite of a true 34.
type findingReasonGroup struct {
	Reason    string `json:"reason"`
	Count     int    `json:"count"`
	FirstSeen string `json:"firstSeen"`
	LastSeen  string `json:"lastSeen"`
}

// incidentFindingsQuery returns the newest maxFindingsPerReason findings for
// each distinct reason on one incident, every row also carrying its reason's
// totals over the incident's whole history.
//
// ONE query rather than two (a GROUP BY reason aggregate plus a separate
// bounded row fetch): findings carries no index on incident_id — only
// (cluster_id, fingerprint, occurred_at DESC) from migration 000004 — so every
// partition is scanned to answer this, and IncidentDetailPage refetches GET
// /incidents/{id} on every event touching that incident (PROJECT.md P16), which
// during an active investigation is more often than the 60s fallback poll
// suggests. A second statement would double that scan for numbers a window
// function produces in the same pass. Adding the index is
// the real fix and needs a migration, which is out of scope here.
//
// The totals repeat identically on every kept row of a reason, which is the
// price of riding along on the row set; groupFindingsByReason keeps the first of
// each and drops the duplicates before they reach the wire.
//
// reason is coalesced to the empty string in both the select list and the
// partitioning expressions. The column is nullable and
// internal/gateway/finding.go never writes NULL into it, but a legacy or
// hand-inserted NULL must land in the same group as the empty string rather than
// in a second, separately-counted partition that Go would then fold into the
// first — that fold would undercount, which is the one thing this aggregate is
// not allowed to do.
//
// occurred_at DESC with an id tiebreak, in both the ranking window and the outer
// ORDER BY: rows sharing a timestamp are normal here (migration 000036 records
// two different detectors reporting one failed Job in the same second), and
// without the tiebreak they could swap places between two polls of an otherwise
// unchanged incident.
const incidentFindingsQuery = `
	SELECT id, detector_id, gvk, namespace, object_name, reason, message, severity,
	       occurrence_count, occurred_at, reason_count, reason_first_seen, reason_last_seen
	  FROM (
	    SELECT id, detector_id, gvk, namespace, object_name, coalesce(reason, '') AS reason,
	           message, severity, occurrence_count, occurred_at,
	           count(*)         OVER per_reason AS reason_count,
	           min(occurred_at) OVER per_reason AS reason_first_seen,
	           max(occurred_at) OVER per_reason AS reason_last_seen,
	           row_number() OVER (PARTITION BY coalesce(reason, '')
	                                  ORDER BY occurred_at DESC, id DESC) AS recency_rank
	      FROM findings
	     WHERE incident_id = $1
	    WINDOW per_reason AS (PARTITION BY coalesce(reason, ''))
	  ) ranked
	 WHERE recency_rank <= $2
	 ORDER BY occurred_at DESC, id DESC`

// findingWithReasonTotals is one incidentFindingsQuery row: the finding itself,
// plus the totals for the reason it belongs to.
type findingWithReasonTotals struct {
	Finding findingSummary
	Totals  findingReasonGroup
}

// groupFindingsByReason splits incidentFindingsQuery's rows into the flat,
// newest-first findings list the response has always carried and one group per
// distinct reason.
//
// Group order is the order in which each reason first appears in the
// recency-ordered rows, which is "most recently seen reason first" — the current
// symptom at the top — without a second sort. More importantly it derives both
// orderings from the same single ordering, so the group list and the events
// inside it can never disagree about which symptom is the current one.
func groupFindingsByReason(rows []findingWithReasonTotals) ([]findingSummary, []findingReasonGroup) {
	findings := make([]findingSummary, 0, len(rows))
	groups := []findingReasonGroup{}
	seen := map[string]bool{}
	for _, row := range rows {
		findings = append(findings, row.Finding)
		if !seen[row.Totals.Reason] {
			seen[row.Totals.Reason] = true
			groups = append(groups, row.Totals)
		}
	}
	return findings, groups
}

// handleGetIncident is GET /api/v1/incidents/{id}. Requires incident:read.
// Same fields as handleListIncidents' elements, plus this incident's findings,
// ordered occurred_at DESC (most recent first) and bounded to the newest
// maxFindingsPerReason per reason, plus "findingGroups" — every reason's true
// count and time range over the whole history, which is what makes that bound
// safe to render.
func (s *Server) handleGetIncident(w http.ResponseWriter, r *http.Request, rc *requestContext) {
	incidentID := r.PathValue("id")
	ctx := r.Context()

	row := rc.Tx.QueryRow(ctx, incidentListQuery+" AND incidents.id = $1", incidentID)
	inc, err := scanIncidentSummary(row)
	if err != nil {
		if err == pgx.ErrNoRows {
			writeProblem(w, http.StatusNotFound, "https://argus.io/errors/not-found", "Incident not found", "")
			return
		}
		logger.ErrorContext(ctx, "looking up the incident failed", logging.IncidentID(incidentID), logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not look up incident", "")
		return
	}

	rows, err := rc.Tx.Query(ctx, incidentFindingsQuery, incidentID, maxFindingsPerReason)
	if err != nil {
		logger.ErrorContext(ctx, "querying the incident's findings failed", logging.IncidentID(incidentID), logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not look up incident findings", "")
		return
	}
	defer rows.Close()

	scanned := []findingWithReasonTotals{}
	for rows.Next() {
		f, err := scanFindingWithReasonTotals(rows)
		if err != nil {
			logger.ErrorContext(ctx, "scanning a finding row failed", logging.IncidentID(incidentID), logging.Err(err))
			writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not look up incident findings", "")
			return
		}
		scanned = append(scanned, f)
	}
	if err := rows.Err(); err != nil {
		logger.ErrorContext(ctx, "iterating the incident's finding rows failed", logging.IncidentID(incidentID), logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not look up incident findings", "")
		return
	}
	findings, findingGroups := groupFindingsByReason(scanned)

	// PROJECT.md IN5: how many distinct objects folded into this incident —
	// the pods that joined a producer's incident, the HPAs that joined an
	// APIService's — counted over every finding, not the slice above.
	var objectsFolded int
	if err := rc.Tx.QueryRow(ctx,
		`SELECT count(DISTINCT (gvk, COALESCE(namespace, ''), COALESCE(object_name, ''))) FROM findings WHERE incident_id = $1`,
		incidentID).Scan(&objectsFolded); err != nil {
		logger.WarnContext(ctx, "counting the incident's objects failed", logging.IncidentID(incidentID), logging.Err(err))
		objectsFolded = 0
	}

	analysis, err := getLatestAnalysis(ctx, rc, incidentID)
	if err != nil {
		logger.ErrorContext(ctx, "looking up the incident's analysis failed", logging.IncidentID(incidentID), logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not look up incident analysis", "")
		return
	}

	// What the investigation actually asked the cluster (evidence.go). A
	// TOP-LEVEL field rather than part of "analysis", which was the other
	// candidate and is the wrong home for it: mcp_tool_calls rows are keyed to
	// the incident, not to an analysis (migration 000037's header explains why
	// they cannot be keyed to one — the analyses row does not exist yet while
	// the calls are being made), so an incident analysed twice has both runs'
	// calls in this aggregate. Hanging that off `analysis`, which is
	// specifically the LATEST analysis, would attribute an earlier run's work
	// to a later verdict — a subtle lie in exactly the field an operator is
	// consulting to decide whether to trust that verdict.
	//
	// Also nil for every analysis that predates this feature, which is why the
	// field is null rather than a zero-valued object: see
	// buildEvidenceSummary's doc comment.
	evidence, err := getEvidenceSummary(ctx, rc.Tx, incidentID)
	if err != nil {
		logger.ErrorContext(ctx, "looking up the incident's recorded tool calls failed", logging.IncidentID(incidentID), logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not look up the incident's gathered evidence", "")
		return
	}

	// PROJECT.md T15: "what happened right before this" — a bounded,
	// source-labelled reading of evidence this incident's own investigation(s)
	// already gathered (see getRecentChanges' own doc comment for the two
	// tables it reads and the two-part honesty rule it enforces). Not fatal,
	// matching every other extra read on this page: a detail page that 500s
	// because a nicety could not be read would be a worse outcome than
	// rendering without it.
	firstSeen, parseErr := time.Parse(time.RFC3339, inc.FirstSeen)
	if parseErr != nil {
		logger.ErrorContext(ctx, "parsing the incident's first_seen timestamp failed",
			logging.IncidentID(incidentID), slog.String("first_seen", inc.FirstSeen), logging.Err(parseErr))
	}
	var recentChanges *recentChangesView
	if parseErr == nil {
		recentChanges, err = getRecentChanges(ctx, rc.Tx, incidentID, firstSeen, analysis, evidence)
		if err != nil {
			logger.ErrorContext(ctx, "looking up recent changes around the incident failed", logging.IncidentID(incidentID), logging.Err(err))
		}
	}

	// Whether a fix applied to this object would actually hold (see
	// deriveOwnership). Top-level, next to "evidence", rather than a field of
	// "analysis" — even though it is derived from that analysis's own recorded
	// tool calls — for two reasons. It is a fact about a live cluster object,
	// not about the verdict: two analyses of the same incident do not disagree
	// about who owns the Deployment. And "analysis" is a shape POST
	// /incidents/{id}/analyze returns too (analyze.go's analysisResponse), so
	// putting it there would extend a second endpoint's pinned contract to no
	// benefit — IncidentDetailPage renders exclusively from GET
	// /incidents/{id}, with its analyze mutation only invalidating that query.
	//
	// Two sources, stored first.
	//
	// incidents.ownership (migration 000038) is what the HUB determined by
	// asking the cluster directly at analysis time, and it is preferred because
	// it is authoritative in the two ways the derived answer is not: it exists
	// on the cli backend (which records no causal chain to scrape), and it does
	// not depend on the model having chosen to ask. Falling back to
	// deriveOwnership keeps every analysis recorded before 000038 working
	// rather than silently losing the caveat on historical incidents.
	//
	// Either way, null whenever nothing says — see deriveOwnership.
	// Queried on its own rather than added to incidentListQuery, because that
	// query and incidentSummary are shared with the list endpoint, which has no
	// use for it — a per-row jsonb on every incident in a fleet-wide listing is
	// bytes nobody reads.
	var storedOwnershipRaw []byte
	if err := rc.Tx.QueryRow(ctx, `SELECT ownership FROM incidents WHERE id = $1`, incidentID).Scan(&storedOwnershipRaw); err != nil {
		// Not fatal: the caveat is an extra, and an incident detail page that
		// 500s because a nicety could not be read would be a worse outcome.
		logger.ErrorContext(ctx, "reading the incident's stored ownership failed", logging.IncidentID(incidentID), logging.Err(err))
	}
	// Both paths read `findings`, which is now bounded per reason — harmless
	// here, and worth stating rather than leaving to be rediscovered: all they
	// take from it is the object identity and the set of namespaces the incident
	// is about, and every finding on one incident is about ONE object. Correlation
	// guarantees it from both ends (object_key is gvk|namespace|object_name,
	// migration 000036; the older fingerprint-only correlation hashed namespace
	// too), so the bounded list yields exactly the namespace set the full history
	// would, and findings[0] is still the newest finding overall.
	ownership := storedOwnership(storedOwnershipRaw, findings, analysis)
	if ownership == nil {
		ownership = deriveOwnership(analysis, findings)
	}

	// BACKLOG.md R3: BatchExecution's own visibility requirement — "a
	// held/paused state visible via the API". Null for the large majority of
	// incidents, which have never shared a fleet group and an unattended
	// action_type with anything else; see orchestrator.GetIncidentBatchInfo.
	// Queried on its own for the same reason ownership is: a per-incident
	// lookup that handleListIncidents' shared incidentSummary scan has no use
	// for on a fleet-wide listing.
	batchInfo, err := orchestrator.GetIncidentBatchInfo(ctx, rc.Tx, incidentID)
	if err != nil {
		// Not fatal, matching storedOwnershipRaw's own precedent just above:
		// this is an extra, and an incident detail page that 500s because a
		// nicety could not be read would be a worse outcome.
		logger.ErrorContext(ctx, "looking up the incident's unattended batch failed", logging.IncidentID(incidentID), logging.Err(err))
	}

	pullRequest, err := incidentPullRequestRecord(ctx, rc.Tx, incidentID)
	if err != nil {
		// Same not-fatal treatment as the two reads above.
		logger.ErrorContext(ctx, "reading the incident's pull-request record failed", logging.IncidentID(incidentID), logging.Err(err))
	}

	// BACKLOG.md D9's "the one that matters most" — see incidentRouteRecord's
	// own doc comment. Not fatal, matching every other extra read above: a
	// detail page that 500s because a nicety could not be read would be a
	// worse outcome than rendering without the route reason.
	route, routeReason, applier, err := incidentRouteRecord(ctx, rc.Tx, incidentID)
	if err != nil {
		logger.ErrorContext(ctx, "reading the incident's resolution route failed", logging.IncidentID(incidentID), logging.Err(err))
	}

	reopenedBy, err := incidentReopenCauseFor(ctx, rc.Tx, incidentID, inc.State)
	if err != nil {
		logger.ErrorContext(ctx, "reading the incident's reopen cause failed", logging.IncidentID(incidentID), logging.Err(err))
	}

	// PROJECT.md T14: the exact gate and reason the automatic-analysis sweep
	// (internal/autoanalyze) or the automatic-execution sweep
	// (internal/api/unattended.go) most recently refused this incident on —
	// read back verbatim from migration 000110's three columns, never
	// recomputed here. Not fatal, matching every other extra read above.
	automationGate, err := incidentAutomationGate(ctx, rc.Tx, incidentID)
	if err != nil {
		logger.ErrorContext(ctx, "reading the incident's automation gate failed", logging.IncidentID(incidentID), logging.Err(err))
	}

	// PROJECT.md M1: the current or most recent investigation run — when it
	// started, what it runs on, and why it failed if it did, read from the
	// incident's own timeline (latestInvestigationRun). POST /analyze
	// answers before the run finishes, so this is where its progress and a
	// failure are read. Not fatal, matching every other extra read above.
	analysisRun, err := incidentAnalysisRun(ctx, rc.Tx, incidentID)
	if err != nil {
		logger.ErrorContext(ctx, "reading the incident's analysis run failed", logging.IncidentID(incidentID), logging.Err(err))
	}

	// PROJECT.md T7: prior CLOSED incidents on this exact object — see
	// priorIncidentLinksFor's own doc comment. Not fatal, matching every
	// other extra read above: a detail page that 500s because a nicety
	// could not be read would be a worse outcome than rendering without it.
	priorIncidents := []priorIncidentLink{}
	if objectKey, ok := objectKeyOfIncident(inc); ok {
		workloadKey := ""
		if inc.WorkloadKey != nil {
			workloadKey = *inc.WorkloadKey
		}
		priorIncidents, err = priorIncidentLinksFor(ctx, rc.Tx, objectKey, workloadKey, incidentID)
		if err != nil {
			logger.ErrorContext(ctx, "looking up prior incidents on the same object failed", logging.IncidentID(incidentID), logging.Err(err))
			priorIncidents = []priorIncidentLink{}
		}
	}

	// The summary half of this response is DERIVED from incidentSummary rather
	// than re-listed field by field. The hand-written map that used to sit here
	// silently dropped a field three separate times — the group ids and the
	// object identity split, then `resolutionKind`, then `resolutionKind` again
	// after a branch merge — and each time the list endpoint stayed correct, so
	// the incident list and the incident page disagreed about the same incident.
	// The last one rendered an incident ARGUS had fixed through a merged pull
	// request as "Closed with no ARGUS fix linked".
	//
	// A test guarding a hand-maintained list cannot close that: the first
	// version of this guard compared the struct against a second list inside
	// the test, and passed while the handler was missing the field. Deriving
	// the keys from the one struct both endpoints already share removes the
	// divergence instead of policing it. omitempty then applies identically on
	// both, so detail and list agree byte for byte on the shared fields.
	body, err := incidentSummaryFields(inc)
	if err != nil {
		logger.ErrorContext(ctx, "encoding the incident summary failed", logging.IncidentID(incidentID), logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not encode incident", "")
		return
	}
	// Detail-only additions: everything handleListIncidents does not carry.
	body["findings"] = findings           // newest first, bounded to maxFindingsPerReason per reason — a slice of the history, never all of it
	body["findingGroups"] = findingGroups // every reason's TRUE count and time range, most recently seen reason first
	if objectsFolded > 0 {
		body["objectsFolded"] = objectsFolded
	}
	body["analysis"] = analysis           // null if none exists yet
	body["evidence"] = evidence           // null if no tool call was ever recorded — "not recorded", never "none happened"
	body["recentChanges"] = recentChanges // null if nothing was ever recorded to look through; non-null (possibly empty items) once we looked — see getRecentChanges
	body["ownership"] = ownership         // null unless the evidence positively identified an owner — "unknown", never "unmanaged"
	body["unattendedBatch"] = batchInfo   // null unless this incident is (or was) part of a staged rollout (BACKLOG.md R3)
	body["pullRequest"] = pullRequest     // null unless a pull request has been opened — the ONLY durable record of one on this payload
	body["reopenedBy"] = reopenedBy       // null unless state is Reopened AND a ValidationOutcome event says what recurred
	// route is also on incidentSummary now (the list's Route column), where it
	// is `omitempty`. Re-set explicitly here because this payload's contract
	// is that route/routeReason are always PRESENT and null when unknown —
	// omitting them on the detail page would change a documented required
	// field into an absent one.
	body["route"] = route // both null for an incident that predates routing or was never investigated
	body["routeReason"] = routeReason
	body["applier"] = applier                         // who applies a change to this object — null when never routed; `gitopsController` is what makes the pullRequest route a consequence rather than a policy
	body["automationGate"] = automationGate           // null unless an automatic analysis or execution was skipped or blocked for this incident right now (PROJECT.md T14)
	body["analysisStartedAt"] = analysisRun.StartedAt // PROJECT.md M1: when the current (state Investigating) or most recent investigation started, from its InvestigationStarted timeline event — null if none ever started
	body["analysisBackend"] = analysisRun.Backend     // "api" | "cli", recorded when a manual run was claimed — null when not recorded (an automatic run)
	body["analysisModel"] = analysisRun.Model         // the configured model when the run was claimed — null when not knowable before the run (cli) or not recorded
	body["analysisError"] = analysisRun.Error         // why the latest investigation, started manually, did not complete — null unless it failed; a new run starts null
	body["priorIncidents"] = priorIncidents           // PROJECT.md T7: prior CLOSED incidents on this exact object, newest first, capped at maxPriorIncidentLinks — empty (not null) when there are none or this incident names no object
	writeJSON(w, http.StatusOK, body)
}

// automationGateView is PROJECT.md T14's per-incident answer to "why isn't
// this happening automatically?" — read back verbatim from
// incidents.automation_gate/automation_gate_reason/automation_gate_at, the
// three columns migration 000110 added. Those columns are written ONLY by the
// enforcing code itself, at the moment it refuses (internal/autoanalyze's
// selectEligible/collectEligible for automatic analysis;
// internal/api/unattended.go's collectUnattended/sweepUnattended for
// automatic execution — see api.SetAutomationGate's own doc comment) — this
// function only ever reads them back, and internal/orchestrator.SetState
// clears all three on every state transition, so a reason can never outlive
// the state it was computed against. Nothing here re-derives which gate
// applied or why; that is the exact thing this task's own brief calls the
// central trap.
type automationGateView struct {
	// Gate is the closed AutomationGate identifier (see automation_gate.go) —
	// e.g. "circuit_breaker", "namespace_scope" — for the UI to key styling or
	// grouping off without parsing Reason's prose.
	Gate string `json:"gate"`
	// Reason is the exact human-readable sentence the enforcing sweeper wrote.
	// Rendered verbatim; never rebuilt from settings.
	Reason string `json:"reason"`
	// At is when the enforcing sweeper most recently reached this decision —
	// so the UI can say how fresh the answer is, since a sweep runs on an
	// interval rather than instantly.
	At string `json:"at"`
}

// incidentAutomationGate reads incidentID's current automation gate, or nil
// if none is set — either because no automatic path has ever refused this
// incident, or because internal/orchestrator.SetState already cleared it on
// a later transition.
func incidentAutomationGate(ctx context.Context, tx pgx.Tx, incidentID string) (*automationGateView, error) {
	var gate, reason *string
	var at *time.Time
	if err := tx.QueryRow(ctx,
		`SELECT automation_gate, automation_gate_reason, automation_gate_at FROM incidents WHERE id = $1`, incidentID,
	).Scan(&gate, &reason, &at); err != nil {
		return nil, err
	}
	if gate == nil {
		return nil, nil
	}
	view := automationGateView{Gate: *gate, Reason: deref(reason)}
	if at != nil {
		view.At = formatRFC3339(*at)
	}
	return &view, nil
}

// incidentSummaryFields turns one incidentSummary into the exact key/value set
// handleListIncidents puts on the wire for it, so handleGetIncident cannot
// drift from it. Round-tripping through the struct's own json tags is the
// point: it is the single source both endpoints share.
func incidentSummaryFields(inc incidentSummary) (map[string]any, error) {
	raw, err := json.Marshal(inc)
	if err != nil {
		return nil, err
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, err
	}
	return m, nil
}

// scanFindingWithReasonTotals scans one incidentFindingsQuery row.
//
// namespace/object_name/message are nullable columns
// (internal/migrations/000004_findings.up.sql) even though handleFinding's own
// INSERT (internal/gateway/finding.go) never writes NULL into them — scanned
// defensively via pointers anyway rather than assumed non-null, matching
// clusterSummary's treatment of its own nullable columns in clusters.go. reason
// is nullable too, but the query coalesces it to the empty string, precisely so
// that NULL and empty cannot become two separately-counted groups.
//
// The group's Reason is taken from the row rather than scanned twice: the query
// partitions on the same coalesced expression it selects, so a row and its
// totals are about the same reason by construction.
func scanFindingWithReasonTotals(row pgx.Row) (findingWithReasonTotals, error) {
	var out findingWithReasonTotals
	var namespace, objectName, message *string
	var occurredAt, reasonFirstSeen, reasonLastSeen time.Time
	if err := row.Scan(&out.Finding.ID, &out.Finding.DetectorID, &out.Finding.GVK, &namespace, &objectName,
		&out.Finding.Reason, &message, &out.Finding.Severity, &out.Finding.OccurrenceCount, &occurredAt,
		&out.Totals.Count, &reasonFirstSeen, &reasonLastSeen); err != nil {
		return findingWithReasonTotals{}, err
	}
	if namespace != nil {
		out.Finding.Namespace = *namespace
	}
	if objectName != nil {
		out.Finding.ObjectName = *objectName
	}
	if message != nil {
		out.Finding.Message = *message
	}
	out.Finding.OccurredAt = formatRFC3339(occurredAt)
	out.Totals.Reason = out.Finding.Reason
	out.Totals.FirstSeen = formatRFC3339(reasonFirstSeen)
	out.Totals.LastSeen = formatRFC3339(reasonLastSeen)
	return out, nil
}

// --- "will the fix hold": who owns the object, read back out of the
// investigation's own evidence ---
//
// The problem this answers: ARGUS can patch a live object, and on a
// Helm-managed or GitOps-managed cluster that patch survives until the next
// reconcile or helm upgrade and then quietly disappears, symptom and all. The
// investigation already learns this — get_gitops_ownership exists for exactly
// that question, and describe_resource returns the object's own Helm metadata —
// but the answer was buried in a tool result inside the causal chain, where the
// model reasoned about it and the operator never saw it.
//
// Derived from the recorded chain rather than by asking the cluster again, for
// three reasons: GET /incidents/{id} is refetched by the detail page on every
// event touching that incident (PROJECT.md P16) and must not turn into a tunnel
// round trip per refresh; the cluster may not
// even be connected when someone reads an old incident, while the recorded
// evidence is always readable; and nothing needs storing, so this ships without
// the migration a new column would need. The cost is that this reports only
// what the investigation happened to look at, which is also exactly why the
// absent case below is "unknown" rather than "unmanaged".

// managed_by's three values. The first two are internal/agent/tools.go's own
// spelling in the get_gitops_ownership result; the third is this file's, since
// no tool reports Helm (see collectOwnershipFacts).
const (
	managedByArgoCD = "argocd"
	managedByFlux   = "flux"
	managedByHelm   = "helm"
)

// The metadata Helm 3 itself writes onto every object it manages, at apply
// time, to claim ownership of it.
//
// Deliberately NOT the app.kubernetes.io/managed-by: Helm label, which looks
// like the same signal and is not: it is an ordinary template label, so any
// chart carries it even when the manifests were rendered with `helm template`
// and applied with kubectl — no release exists, nothing will ever overwrite the
// object, and a "this will be reverted" warning would be false. The annotation
// is written by Helm's own apply path, and it carries the release NAME, which
// is the thing an operator needs in order to find the values file to change.
const (
	helmReleaseNameAnnotation      = "meta.helm.sh/release-name"
	helmReleaseNamespaceAnnotation = "meta.helm.sh/release-namespace"
)

// ownershipSummary is what manages one live object: an Argo CD Application, a
// Flux Kustomization/HelmRelease, or a Helm release.
//
// The object it describes is named in full (ObjectGVK/ObjectNamespace/
// ObjectName) rather than left implicit as "this incident's object". The
// investigation may have checked ownership on the owning Deployment while the
// incident's own findings are about one of its Pods, and a warning that names
// the object it actually checked stays true in that case; one that silently
// implies it checked the finding's object does not.
type ownershipSummary struct {
	ManagedBy       string `json:"managedBy"` // "argocd" | "flux" | "helm"
	SourceKind      string `json:"sourceKind"`
	SourceName      string `json:"sourceName"`
	SourceNamespace string `json:"sourceNamespace"`
	ObjectGVK       string `json:"objectGvk"`
	ObjectNamespace string `json:"objectNamespace"`
	ObjectName      string `json:"objectName"`
	// Repo is WHERE the fix belongs — the repository, the path inside it, and
	// the exact commit the controller last synced.
	//
	// The agent has resolved this since WORKLOG §121 and the hub has stored it
	// in incidents.ownership ever since, and this view dropped it, so the UI
	// could tell an operator "a GitOps controller owns this, fix it at the
	// source" without being able to say *where the source is*. That is most of
	// the value of knowing at all, and it does not need the PR-writing path
	// (BACKLOG.md F15) to be useful: a human who is told the repository, the
	// path and the synced commit can go and fix it today.
	//
	// nil for a Helm release (no repository is recorded — Helm's metadata names
	// a release, not a source) and for any object whose controller has never
	// synced, so a caller must handle its absence rather than treating GitOps
	// ownership as implying a known repository.
	Repo *ownershipRepo `json:"repo,omitempty"`
}

// ownershipRepo mirrors the `repo` object the agent writes into
// incidents.ownership (internal/agent/tools.go's gitOpsRepoTarget).
type ownershipRepo struct {
	URL    string `json:"url"`
	Path   string `json:"path"`
	Branch string `json:"branch,omitempty"`
	// Revision is the commit the controller reports as last synced. Pinned says
	// whether it is a real resolved SHA or merely the branch/tag that was
	// requested — the distinction matters, because an unpinned revision means
	// nobody can say which commit is actually running.
	Revision string `json:"revision,omitempty"`
	Pinned   bool   `json:"pinned"`
	// ResolvedFrom names the object and field this came from, e.g.
	// "argoproj.io/Application argocd/my-app .status.sync.revision". Shown so a
	// reader can check the claim rather than take it on trust.
	ResolvedFrom string `json:"resolvedFrom,omitempty"`
}

// toolTargetArgs is the {gvk, namespace, name} argument triple every
// object-scoped tool in internal/llm's toolDefinitions takes — the only part of
// a recorded call's args this file reads, to know WHICH object a result is
// about.
type toolTargetArgs struct {
	GVK       string `json:"gvk"`
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
}

// gitOpsOwnershipToolResult and describeResourceToolResult are the two tool
// result shapes this derivation reads, transcribed from internal/agent/tools.go
// (gitOpsOwnershipResult, describeResourceResult) rather than imported: those
// types are unexported, they live in the cluster-agent package the hub does not
// depend on, and by the time the hub reads them here they have crossed the
// tunnel and a jsonb column anyway — this is wire data, not a shared Go type.
// describeResourceToolResult keeps only metadata.annotations, since the rest of
// a described object is irrelevant here and decoding it would be pure work.
type gitOpsOwnershipToolResult struct {
	ManagedBy string `json:"managed_by"`
	AppRef    *struct {
		Kind      string `json:"kind"`
		Namespace string `json:"namespace"`
		Name      string `json:"name"`
	} `json:"app_ref"`
}

type describeResourceToolResult struct {
	Object struct {
		Metadata struct {
			Annotations map[string]string `json:"annotations"`
		} `json:"metadata"`
	} `json:"object"`
}

// collectOwnershipFacts scans a causal chain for every recorded tool call that
// positively identified an owner, in the order the investigation made them.
//
// Two signals, read asymmetrically on purpose:
//
//   - get_gitops_ownership answering "argocd"/"flux" is taken at face value,
//     whatever object it was asked about. It is a question the model chose to
//     ask about an object it had already decided was load-bearing, so its
//     subject is as relevant as the investigation's own reasoning.
//   - Helm's annotation is a byproduct of a describe_resource the model made
//     for entirely other reasons, so it counts only when the described object
//     sits in a namespace this incident is actually about (relevantNamespaces).
//     Without that gate, an investigation that wandered into kube-system to
//     check a controller would report "your fix will be reverted" naming a
//     release the incident has nothing to do with — a warning an operator
//     learns to ignore, which is worse than no warning.
//
// A call that returned an error is skipped: a failed lookup is real evidence
// about many things, but never evidence of ownership.
//
// managed_by "none" is skipped for the same reason a nil return means unknown:
// it is a true statement about Argo CD and Flux specifically, and says nothing
// at all about Helm, which the tool cannot see.
func collectOwnershipFacts(chain []llm.CausalStep, relevantNamespaces map[string]bool) []ownershipSummary {
	facts := []ownershipSummary{}
	for _, step := range chain {
		for _, call := range step.ToolCalls {
			if call.Error != nil || len(call.Result) == 0 {
				continue
			}
			var target toolTargetArgs
			if err := json.Unmarshal(call.Args, &target); err != nil || target.Name == "" {
				continue
			}
			switch call.Tool {
			case "get_gitops_ownership":
				var res gitOpsOwnershipToolResult
				if json.Unmarshal(call.Result, &res) != nil {
					continue
				}
				if res.ManagedBy != managedByArgoCD && res.ManagedBy != managedByFlux {
					continue
				}
				fact := ownershipSummary{
					ManagedBy:       res.ManagedBy,
					ObjectGVK:       target.GVK,
					ObjectNamespace: target.Namespace,
					ObjectName:      target.Name,
				}
				if res.AppRef != nil {
					fact.SourceKind = res.AppRef.Kind
					fact.SourceName = res.AppRef.Name
					fact.SourceNamespace = res.AppRef.Namespace
				}
				facts = append(facts, fact)
			case "describe_resource":
				var res describeResourceToolResult
				if json.Unmarshal(call.Result, &res) != nil {
					continue
				}
				release := res.Object.Metadata.Annotations[helmReleaseNameAnnotation]
				if release == "" || !relevantNamespaces[target.Namespace] {
					continue
				}
				facts = append(facts, ownershipSummary{
					ManagedBy: managedByHelm,
					// "Release" is Helm's own noun for this, not a Kubernetes
					// Kind — there is no Release object to fetch, only the
					// release secret Helm keeps, which no tool here reads.
					SourceKind:      "Release",
					SourceName:      release,
					SourceNamespace: res.Object.Metadata.Annotations[helmReleaseNamespaceAnnotation],
					ObjectGVK:       target.GVK,
					ObjectNamespace: target.Namespace,
					ObjectName:      target.Name,
				})
			}
		}
	}
	return facts
}

// pickOwnershipFact chooses the one fact worth showing when an investigation
// touched several managed objects.
//
// Scored rather than "first wins" so the two things that make a fact more
// relevant compose: it describes the object the proposed plan would actually
// mutate (the fix an operator is about to approve, so this dominates), and it
// came from a deliberate ownership question rather than an incidental
// annotation. Ties go to the LAST fact recorded, because an investigation
// narrows as it runs — the object it was still checking at the end is the one
// it concluded about.
func pickOwnershipFact(facts []ownershipSummary, plan *planView) *ownershipSummary {
	best, bestScore := -1, -1
	for i, fact := range facts {
		score := 0
		if fact.ManagedBy != managedByHelm {
			score++
		}
		if plan != nil && fact.ObjectNamespace == plan.TargetNamespace && fact.ObjectName == plan.TargetName {
			score += 2
		}
		if score >= bestScore {
			best, bestScore = i, score
		}
	}
	if best < 0 {
		return nil
	}
	chosen := facts[best]
	return &chosen
}

// deriveOwnership is the whole feature's honesty rule in one place: it returns
// non-nil ONLY when the recorded evidence positively named an owner.
//
// nil therefore means "nothing gathered says", and covers several genuinely
// different situations that must all render as silence: no analysis has run;
// the analysis ran on the cli backend, which contributes no causal chain at all
// (see internal/llm/cli_investigator.go, and EvidenceSummary's doc comment in
// web/src/api/types.ts for the same gap); the model never asked about
// ownership; or it asked and got "none". A warning shown on an unmanaged object
// is not a small cosmetic error — it is the thing that teaches an operator to
// stop reading the warning, at which point the real ones stop working too.
//
// The relevant-namespace set is built from the incident's own findings plus the
// plan's target, which is what scopes the Helm signal (see
// collectOwnershipFacts).
func deriveOwnership(analysis *analysisResponse, findings []findingSummary) *ownershipSummary {
	if analysis == nil {
		return nil
	}
	relevantNamespaces := map[string]bool{}
	for _, f := range findings {
		if f.Namespace != "" {
			relevantNamespaces[f.Namespace] = true
		}
	}
	if analysis.Plan != nil && analysis.Plan.TargetNamespace != "" {
		relevantNamespaces[analysis.Plan.TargetNamespace] = true
	}
	return pickOwnershipFact(collectOwnershipFacts(analysis.CausalChain, relevantNamespaces), analysis.Plan)
}

// storedOwnership turns incidents.ownership (migration 000038 — what the hub
// itself asked the cluster at analysis time) into the response shape, or nil.
//
// nil for every "we do not actually know" case, which is the whole honesty rule
// of this feature: no stored value, unparseable JSON, and — importantly —
// managed_by "none" or anything unrecognised. A false "this will be reverted"
// on an unmanaged object teaches operators to ignore the warning, so silence is
// the correct output whenever the answer is not a controller or release we
// recognise.
//
// The object identity is filled from the incident's own findings/plan rather
// than re-derived, so the rendered sentence names the same object the rest of
// the page is about.
func storedOwnership(raw []byte, findings []findingSummary, analysis *analysisResponse) *ownershipSummary {
	if len(raw) == 0 {
		return nil
	}
	var stored struct {
		ManagedBy string `json:"managed_by"`
		AppRef    *struct {
			Kind      string `json:"kind"`
			Name      string `json:"name"`
			Namespace string `json:"namespace"`
		} `json:"app_ref"`
		Repo *struct {
			RepoURL        string `json:"repo_url"`
			Path           string `json:"path"`
			Branch         string `json:"branch"`
			Revision       string `json:"revision"`
			RevisionPinned bool   `json:"revision_pinned"`
			ResolvedFrom   string `json:"resolved_from"`
		} `json:"repo"`
	}
	if err := json.Unmarshal(raw, &stored); err != nil {
		return nil
	}
	switch stored.ManagedBy {
	case "argocd", "flux", "helm":
	default:
		return nil
	}
	out := &ownershipSummary{ManagedBy: stored.ManagedBy}
	if stored.AppRef != nil {
		out.SourceKind = stored.AppRef.Kind
		out.SourceName = stored.AppRef.Name
		out.SourceNamespace = stored.AppRef.Namespace
	}
	// Only when a URL is actually present: an empty repo object would render as
	// a source location that turns out to name nothing.
	if stored.Repo != nil && stored.Repo.RepoURL != "" {
		out.Repo = &ownershipRepo{
			URL:          stored.Repo.RepoURL,
			Path:         stored.Repo.Path,
			Branch:       stored.Repo.Branch,
			Revision:     stored.Repo.Revision,
			Pinned:       stored.Repo.RevisionPinned,
			ResolvedFrom: stored.Repo.ResolvedFrom,
		}
	}
	// Name the object this incident is about, preferring the plan's target
	// (what an operator is about to change) over the first finding.
	if analysis != nil && analysis.Plan != nil && analysis.Plan.TargetName != "" {
		out.ObjectGVK = analysis.Plan.TargetGVK
		out.ObjectNamespace = analysis.Plan.TargetNamespace
		out.ObjectName = analysis.Plan.TargetName
	} else if len(findings) > 0 {
		out.ObjectGVK = findings[0].GVK
		out.ObjectNamespace = findings[0].Namespace
		out.ObjectName = findings[0].ObjectName
	}
	return out
}

// --- PROJECT.md T15: bounded "recent changes" ---
//
// The acceptance bar is narrow on purpose: a chronological, source-labelled
// list of changes an incident's OWN investigation(s) already observed,
// immediately preceding its first finding — built from evidence that is
// already stored, never from a new live query. This is deliberately NOT a
// general event feed: it reads exactly two existing, already-bounded tables
// (evidence, mcp_tool_call_content), and only three already-offered
// read-only tool results (get_events, describe_resource, list_resources),
// which the tool surface itself already caps (maxEventResults per get_events
// call; list_resources' own 200-item hard cap; describe_resource returns one
// object). No agent tool is called from here, and no new collection path is
// introduced anywhere — see this function's own doc comment for the two
// additional bounds THIS reader applies on top of those.
//
// What was deliberately NOT used, and why:
//
//   - mcp_tool_calls (migration 000037): counts only, no args/result — the
//     exact reason evidenceSummary above is a count, not a list. Nothing to
//     extract a change from.
//   - Live re-querying (e.g. another get_gitops_ownership call, the way
//     pr_verify.go's VerifyMergedPullRequest re-checks a merge): that would be
//     a NEW live cluster call on a page-render path, not a read of existing
//     evidence, and is exactly the kind of unbounded, on-demand collection
//     PROJECT.md T15 rules out.
//   - Object spec snapshots (describe_resource's own container image list,
//     declared replica count): a snapshot is not a change without a prior
//     value to diff against, and this codebase has no stored prior value.
//     Reporting today's image or replica count as though it were "the
//     change that caused this" would be exactly the fabricated-fact failure
//     mode PROJECT.md T15 warns against. What IS used instead — the
//     controller's own ScalingReplicaSet/Pulling/Pulled events — states only
//     what was actually observed to happen, with its own timestamp.
//   - GitOps sync revision: reported already, elsewhere, on this same
//     response (`ownership`/`incidents.ownership`, migration 000038) — that
//     value carries no timestamp of when the revision last changed (see
//     gitOpsRepoTarget in internal/agent/tools.go), so it cannot honestly go
//     in a CHRONOLOGICAL list. Duplicating it here, mis-timestamped by the
//     tool call's own capture time, would misstate when the revision
//     actually changed. Left where it already is.
const (
	// recentChangeWindow bounds how far back before an incident's first
	// finding a recorded fact can be and still be surfaced. Not configurable
	// per incident or per tenant: a fixed, stated bound is the whole point —
	// see this section's own header.
	recentChangeWindow = 24 * time.Hour
	// maxRecentChangeContentRows bounds how many mcp_tool_call_content rows
	// getRecentChanges reads from Postgres for one incident, enforced by the
	// query's own LIMIT below. The tool-calling loop's own iteration cap
	// already keeps a single investigation's call count far under this; the
	// explicit LIMIT is what stops a pathological or future case (e.g. an
	// incident re-analysed many times) from turning this read into an
	// unbounded scan.
	maxRecentChangeContentRows = 200
	// maxRecentChangeItems bounds how many rows this endpoint ever renders,
	// after every other filter has run — the last line of defense against a
	// single call that legitimately reported many items (list_resources'
	// own 200-item cap chief among them). When more than this many facts
	// fall inside recentChangeWindow, the ones closest to the incident's
	// first finding are kept, because those are the ones most likely to be
	// the trigger.
	maxRecentChangeItems = 20
)

// recentChange is one fact this incident's own investigation(s) already
// observed, timestamped from the fact itself (a Kubernetes Event's own
// lastTimestamp, or an object's own creationTimestamp) — never from when the
// tool was called.
type recentChange struct {
	// Time is when the underlying Kubernetes fact itself occurred (RFC3339),
	// not when the investigation asked about it.
	Time string `json:"time"`
	// Category is one of a fixed, small vocabulary this function assigns —
	// never free text, and never a category invented from an event Reason
	// this function does not recognise: "created" (an object's own
	// creationTimestamp), "rollout_created" (SuccessfulCreate — a
	// Deployment/Job's controller created a new ReplicaSet/Pod),
	// "replica_change" (ScalingReplicaSet — the controller's own message
	// states the old and new counts), "image_pull" (Pulling/Pulled — a
	// container image was fetched, which a kubelet only does for an image it
	// does not already have cached locally), "warning_event" (any Warning
	// event, verbatim, whatever its Reason).
	Category string `json:"category"`
	// Source is the MCP tool whose already-recorded result this fact was
	// read from — "get_events", "list_resources", or "describe_resource" —
	// the source-labelling the acceptance bar requires. Never a paraphrase:
	// the literal tool name the investigation actually called.
	Source          string `json:"source"`
	ObjectKind      string `json:"objectKind,omitempty"`
	ObjectNamespace string `json:"objectNamespace,omitempty"`
	ObjectName      string `json:"objectName,omitempty"`
	// Reason/Message are the Kubernetes Event's own Reason/Message, verbatim,
	// set only for the four event-sourced categories. Already redacted at
	// capture (internal/redact's pattern layer runs on every event message
	// agent-side, before the tunnel — see internal/redact's package doc) —
	// this function reads stored, already-redacted bytes and adds no
	// redaction and no bypass of its own.
	Reason  string `json:"reason,omitempty"`
	Message string `json:"message,omitempty"`
}

// recentChangesView is the container getRecentChanges returns. Only ever
// handed back non-nil when SOME evidence existed to look through — see
// getRecentChanges' own doc comment for why nil vs. an empty Items are two
// different, both honest, answers.
type recentChangesView struct {
	Items []recentChange `json:"items"`
	// WindowHours is recentChangeWindow, echoed so the UI can render an
	// explicit "looked at the Nh before the first finding and found nothing"
	// rather than a bare empty list that reads as unexamined.
	WindowHours int `json:"windowHours"`
	// Truncated is true when more facts fell inside the window than
	// maxRecentChangeItems keeps — argus-design-system's own rule that "a
	// number over a capped list states its window": without this, a list
	// that happens to land exactly on the cap would silently read as
	// complete.
	Truncated bool `json:"truncated"`
}

// recentChangeEventResult mirrors internal/agent/tools.go's eventResult,
// transcribed rather than imported for the exact reason
// gitOpsOwnershipToolResult/describeResourceToolResult above already are:
// this is wire data crossing a jsonb column, not a shared Go type.
type recentChangeEventResult struct {
	InvolvedObjectKind string    `json:"involvedObjectKind"`
	InvolvedObjectName string    `json:"involvedObjectName"`
	Reason             string    `json:"reason"`
	Message            string    `json:"message"`
	Type               string    `json:"type"`
	LastTimestamp      time.Time `json:"lastTimestamp"`
}

// recentChangeListResult/recentChangeListItem mirror list_resources'
// listResourcesResult/listResourceItem — same transcription rationale.
type recentChangeListItem struct {
	Name              string    `json:"name"`
	CreationTimestamp time.Time `json:"creationTimestamp"`
}
type recentChangeListResult struct {
	GVK       string                 `json:"gvk"`
	Namespace string                 `json:"namespace"`
	Items     []recentChangeListItem `json:"items"`
}

// recentChangeDescribeResult mirrors describe_resource's describeResourceResult
// — Object kept as json.RawMessage there too, decoded further below into
// only the handful of generic fields (kind, metadata, creationTimestamp)
// every Kubernetes object carries, exactly as describeResourceToolResult
// above decodes only what it needs from the same shape.
type recentChangeDescribeResult struct {
	Object json.RawMessage           `json:"object"`
	Events []recentChangeEventResult `json:"events"`
}

// classifyRecentChangeEvent maps a Kubernetes Event's own Type/Reason to one
// of recentChange's fixed categories, or "" when this event is not one of
// the specific, well-known signals this feature surfaces. "" is the common
// case — most Normal events (Scheduled, Started, ...) are deliberately left
// unclassified, because surfacing every Normal event this incident's
// investigation happened to see would be exactly the general event feed
// PROJECT.md T15 forbids introducing.
func classifyRecentChangeEvent(evType, reason string) string {
	switch {
	case evType == "Warning":
		return "warning_event"
	case reason == "ScalingReplicaSet":
		return "replica_change"
	case reason == "SuccessfulCreate":
		return "rollout_created"
	case reason == "Pulling", reason == "Pulled":
		return "image_pull"
	default:
		return ""
	}
}

// truncateRecentChangeMessage bounds one displayed event message, matching
// maxToolCallErrorLen/maxEvidenceErrorLen's own reasoning elsewhere in this
// package: an Event's Message comes from whatever emitted it and has no
// guaranteed size, and this is a UI label, not a forensic record (the full,
// unredacted-further text is already available via the evidence this came
// from).
func truncateRecentChangeMessage(s string) string {
	const max = 500
	if len(s) <= max {
		return s
	}
	return s[:max]
}

// recentChangeSource is one already-recorded tool call this function reads
// facts out of, whichever of the two backend-specific tables it came from.
type recentChangeSource struct {
	tool   string
	result json.RawMessage
}

// extractRecentChangesFromEvents turns a get_events-shaped or a
// describe_resource-embedded event list into zero or more recentChange
// entries, tagged with source (the tool name the acceptance bar's
// "source-labelled" requirement asks for).
func extractRecentChangesFromEvents(events []recentChangeEventResult, source string) []recentChange {
	out := []recentChange{}
	for _, ev := range events {
		category := classifyRecentChangeEvent(ev.Type, ev.Reason)
		if category == "" || ev.LastTimestamp.IsZero() {
			continue
		}
		out = append(out, recentChange{
			Time:       formatRFC3339(ev.LastTimestamp),
			Category:   category,
			Source:     source,
			ObjectKind: ev.InvolvedObjectKind,
			ObjectName: ev.InvolvedObjectName,
			Reason:     ev.Reason,
			Message:    truncateRecentChangeMessage(ev.Message),
		})
	}
	return out
}

// extractRecentChanges reads one already-recorded tool call's result and
// returns zero or more candidate recentChange facts. Unparsable or
// unrecognised content is skipped, never an error — matching
// collectOwnershipFacts' own defensive posture just above: a malformed or
// unexpected result here should degrade this one nicety, not the incident
// page.
func extractRecentChanges(tool string, result json.RawMessage) []recentChange {
	if len(result) == 0 {
		return nil
	}
	switch tool {
	case "get_events":
		var events []recentChangeEventResult
		if json.Unmarshal(result, &events) != nil {
			return nil
		}
		return extractRecentChangesFromEvents(events, "get_events")

	case "list_resources":
		var res recentChangeListResult
		if json.Unmarshal(result, &res) != nil {
			return nil
		}
		kind := res.GVK
		if idx := strings.LastIndex(res.GVK, "/"); idx >= 0 {
			kind = res.GVK[idx+1:]
		}
		out := []recentChange{}
		for _, item := range res.Items {
			if item.CreationTimestamp.IsZero() {
				continue
			}
			out = append(out, recentChange{
				Time:            formatRFC3339(item.CreationTimestamp),
				Category:        "created",
				Source:          "list_resources",
				ObjectKind:      kind,
				ObjectNamespace: res.Namespace,
				ObjectName:      item.Name,
			})
		}
		return out

	case "describe_resource":
		var res recentChangeDescribeResult
		if json.Unmarshal(result, &res) != nil {
			return nil
		}
		out := []recentChange{}
		var obj struct {
			Kind     string `json:"kind"`
			Metadata struct {
				Name              string    `json:"name"`
				Namespace         string    `json:"namespace"`
				CreationTimestamp time.Time `json:"creationTimestamp"`
			} `json:"metadata"`
		}
		if json.Unmarshal(res.Object, &obj) == nil && !obj.Metadata.CreationTimestamp.IsZero() {
			out = append(out, recentChange{
				Time:            formatRFC3339(obj.Metadata.CreationTimestamp),
				Category:        "created",
				Source:          "describe_resource",
				ObjectKind:      obj.Kind,
				ObjectNamespace: obj.Metadata.Namespace,
				ObjectName:      obj.Metadata.Name,
			})
		}
		out = append(out, extractRecentChangesFromEvents(res.Events, "describe_resource")...)
		return out

	default:
		return nil
	}
}

// recentChangeContentRows reads the incident's already-recorded
// mcp_tool_call_content rows (migration 000099, PROJECT.md B151) — the cli
// backend's own tool-call content, the counterpart of the api backend's
// causal_chain this function's caller already has in hand. Bounded by
// maxRecentChangeContentRows via LIMIT, and to exactly the three tools this
// feature reads (get_events/list_resources/describe_resource) — never a scan
// of every tool call this incident ever made.
//
// Scoped by the caller's own request transaction (rc.Tx), the same RLS
// session this incident's own row was read under — no separate
// authorization decision, matching getEvidenceSummary's own reasoning.
func recentChangeContentRows(ctx context.Context, tx pgx.Tx, incidentID string) ([]recentChangeSource, error) {
	rows, err := tx.Query(ctx,
		`SELECT tool, result
		   FROM mcp_tool_call_content
		  WHERE incident_id = $1 AND outcome = 'ok'
		    AND tool IN ('get_events', 'list_resources', 'describe_resource')
		  ORDER BY created_at DESC
		  LIMIT $2`,
		incidentID, maxRecentChangeContentRows)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	sources := []recentChangeSource{}
	for rows.Next() {
		var s recentChangeSource
		if err := rows.Scan(&s.tool, &s.result); err != nil {
			return nil, err
		}
		sources = append(sources, s)
	}
	return sources, rows.Err()
}

// getRecentChanges builds PROJECT.md T15's bounded "recent changes" view.
//
// Reads from TWO already-stored places, covering both investigation
// backends (ADR-17): analysis.CausalChain (llm.ToolCallRecord — the api
// backend's own tool calls, Args/Result inline, exactly what persistEvidence
// in evidence.go already copies into the `evidence` table from the SAME
// slice — reading it here rather than querying `evidence` again is reading
// the one in-memory copy this handler already has, not a second source), and
// mcp_tool_call_content (the cli backend's tool calls, which contribute
// nothing to CausalChain — see migration 000069's header). Neither read
// calls the cluster or any agent tool; both are bounded reads of rows an
// investigation already wrote.
//
// THE HONESTY RULE THIS FUNCTION EXISTS TO ENFORCE: nil and "non-nil with
// empty Items" mean two different things, and collapsing them would fabricate
// a fact.
//
//   - nil: nothing was ever recorded to look through — no analysis ran, or
//     the analysis that did run made zero tool calls, or (for a cli-backend
//     run) neither mcp_tool_calls nor mcp_tool_call_content has a row. This
//     is "we have no evidence for this incident", never rendered as "nothing
//     changed."
//   - non-nil, Items possibly empty: an investigation happened AND made at
//     least one tool call — evidenceSummary != nil is proof of that, even
//     for a cli-backend run whose content failed to persist — so this
//     function genuinely looked. An empty Items is "we looked at the
//     evidence we have and nothing relevant preceded this," which is a
//     real, positive finding, not silence.
//
// firstSeen anchors the window: only facts timestamped inside
// [firstSeen-recentChangeWindow, firstSeen] are kept, and the result is
// sorted chronologically (oldest first) so the list reads as the lead-up to
// the incident's first finding, capped to maxRecentChangeItems keeping the
// entries closest to firstSeen when more were found.
func getRecentChanges(ctx context.Context, tx pgx.Tx, incidentID string, firstSeen time.Time, analysis *analysisResponse, evidence *evidenceSummary) (*recentChangesView, error) {
	looked := evidence != nil
	var candidates []recentChange

	if analysis != nil {
		for _, step := range analysis.CausalChain {
			for _, call := range step.ToolCalls {
				if call.Error != nil || len(call.Result) == 0 {
					continue
				}
				looked = true
				candidates = append(candidates, extractRecentChanges(call.Tool, call.Result)...)
			}
		}
	}

	contentRows, err := recentChangeContentRows(ctx, tx, incidentID)
	if err != nil {
		return nil, err
	}
	if len(contentRows) > 0 {
		looked = true
	}
	for _, row := range contentRows {
		candidates = append(candidates, extractRecentChanges(row.tool, row.result)...)
	}

	if !looked {
		return nil, nil
	}

	items, truncated := filterAndCapRecentChanges(candidates, firstSeen)
	return &recentChangesView{
		Items:       items,
		WindowHours: int(recentChangeWindow.Hours()),
		Truncated:   truncated,
	}, nil
}

// filterAndCapRecentChanges applies getRecentChanges' two stated bounds —
// the time window and the row cap — and orders the result chronologically.
// Split out as its own pure function (no DB, no context) so both bounds are
// directly unit-testable, matching this package's established pattern for
// keeping the rules that actually need testing out of SQL and in Go (see
// buildEvidenceSummary's own doc comment in evidence.go for the same
// argument).
//
// Only candidates timestamped inside [firstSeen-recentChangeWindow,
// firstSeen] survive — strictly PRECEDING the first finding, matching the
// acceptance bar's own wording, plus the moment of the finding itself.
// Sorted oldest-first, then capped to maxRecentChangeItems by keeping the
// entries CLOSEST to firstSeen (dropping from the front) when more were
// found — those are the ones most likely to be the trigger. The second
// return value says whether that drop actually happened, so the caller can
// state the cap rather than let a list that happens to land exactly on it
// read as complete (argus-design-system's anti-pattern rule: "a chart [or
// list] over a capped list states its window").
func filterAndCapRecentChanges(candidates []recentChange, firstSeen time.Time) ([]recentChange, bool) {
	windowStart := firstSeen.Add(-recentChangeWindow)
	items := []recentChange{}
	for _, c := range candidates {
		t, err := time.Parse(time.RFC3339, c.Time)
		if err != nil || t.Before(windowStart) || t.After(firstSeen) {
			continue
		}
		items = append(items, c)
	}
	sort.Slice(items, func(i, j int) bool { return items[i].Time < items[j].Time })
	truncated := len(items) > maxRecentChangeItems
	if truncated {
		items = items[len(items)-maxRecentChangeItems:]
	}
	return items, truncated
}

// incidentPullRequest is the durable record that a pull request exists for an
// incident. Reported on the incident DETAIL only.
//
// This existed nowhere on the API before (BUGS.md: "after making a PR there was
// no indication on the incident page that clearly showed a PR was generated").
// `incidents.pr_number` has been written by both routes for several migrations
// — approveByOpeningPullRequest (approvals.go) and
// handleOpenRepositoryChange (repository_change.go) — and read back by
// nothing except the merge sweeper. The web UI's only sign of a pull request was
// RepositoryChangePanel echoing the number out of its own mutation result, which
// is component state: it survived until the reader navigated away and then the
// incident showed no trace of the PR, permanently. An incident whose fix is
// sitting in a pull request is precisely the state where the reader most needs
// to be told so.
//
// FieldPath/ExpectedValue are the post-merge verification target, and they are
// nullable for a real reason rather than by oversight: a repository change is a
// set of whole-file edits, so there is no single field the hub could re-read to
// confirm the change landed. Since 2026-08-28 EVERY route leaves them NULL —
// they survive only for pull requests opened by earlier builds. Reported as
// absent so the UI can say which kind of verification is possible, instead of
// implying a check that cannot run.
type incidentPullRequest struct {
	Number int `json:"number"`
	// URL (migration 000089, BACKLOG.md D9 U6) is the provider's own link —
	// absent, not fabricated, on a pull request opened before this column
	// existed (see that migration's own doc comment for why this hub cannot
	// reconstruct one after the fact). A client renders the bare number when
	// this is absent, exactly as it always has.
	URL *string `json:"url,omitempty"`
	// OpenedAt (migration 000114) is when THIS pull request was opened — the
	// number's own open-time, replaced wholesale by a re-proposal, never the
	// first pull request's. It is what lets a reader in AwaitingMerge see how
	// long the merge they are being asked for has been outstanding, which is
	// the one question that state raises and nothing could previously answer.
	//
	// Absent for a pull request opened before that migration whose URL the
	// backfill could not match exactly. A client renders absence as absence: an
	// unknown age is not a zero age, and "opened just now" on a three-week-old
	// pull request would be a fabricated fact of exactly the kind that makes an
	// operator distrust the rest of the page.
	OpenedAt         *string `json:"openedAt,omitempty"`
	MergedAt         *string `json:"mergedAt,omitempty"`
	ClosedUnmergedAt *string `json:"closedUnmergedAt,omitempty"`
	RejectionReason  *string `json:"rejectionReason,omitempty"`
	FieldPath        *string `json:"fieldPath,omitempty"`
	ExpectedValue    *string `json:"expectedValue,omitempty"`
}

// incidentPullRequestRecord returns nil when no pull request has ever been
// opened for this incident — "none", which is different from "one whose number
// we lost", and the caller renders nothing at all in that case.
//
// Queried on its own rather than added to incidentListColumns, for the same
// reason ownership is: handleListIncidents shares that column list and has no
// use for six more columns on every row of a fleet-wide listing.
func incidentPullRequestRecord(ctx context.Context, tx pgx.Tx, incidentID string) (*incidentPullRequest, error) {
	var (
		number           *int
		url              *string
		openedAt         *time.Time
		mergedAt         *time.Time
		closedUnmergedAt *time.Time
		rejectionReason  *string
		fieldPath        *string
		expectedValue    *string
	)
	if err := tx.QueryRow(ctx,
		`SELECT pr_number, pr_url, pr_opened_at, pr_merged_at, pr_closed_unmerged_at, pr_rejection_reason,
		        pr_field_path, pr_expected_value
		   FROM incidents WHERE id = $1`, incidentID,
	).Scan(&number, &url, &openedAt, &mergedAt, &closedUnmergedAt, &rejectionReason, &fieldPath, &expectedValue); err != nil {
		return nil, err
	}
	if number == nil {
		return nil, nil
	}
	// nullIfEmpty (analyze.go) rather than a local helper: these columns are
	// nullable AND the free-form route writes them as blank, so "" and NULL both
	// have to collapse to absent or the UI would render an empty verification
	// target as though one existed.
	out := &incidentPullRequest{Number: *number}
	if url != nil {
		out.URL = nullIfEmpty(*url)
	}
	if rejectionReason != nil {
		out.RejectionReason = nullIfEmpty(*rejectionReason)
	}
	if fieldPath != nil {
		out.FieldPath = nullIfEmpty(*fieldPath)
	}
	if expectedValue != nil {
		out.ExpectedValue = nullIfEmpty(*expectedValue)
	}
	if openedAt != nil {
		out.OpenedAt = nullIfEmpty(openedAt.UTC().Format(time.RFC3339))
	}
	if mergedAt != nil {
		out.MergedAt = nullIfEmpty(mergedAt.UTC().Format(time.RFC3339))
	}
	if closedUnmergedAt != nil {
		out.ClosedUnmergedAt = nullIfEmpty(closedUnmergedAt.UTC().Format(time.RFC3339))
	}
	return out, nil
}

// incidentRouteRecord reads incidents.route/route_reason — BACKLOG.md D9's
// "the one that matters most" finding: ResolveIncidentRoute (routing.go)
// computes a real, operator-legible sentence for why ARGUS chose pull
// request / in-place / guidance (e.g. "a GitOps controller applies this
// object's manifest with automated sync enabled, so an in-place patch has a
// few-second half-life"), and orchestrator.ApplyAnalysisResult persists both
// columns — but until now nothing read them back out for the browser. The
// UI instead re-derived "Pull request / In place" purely from
// plan.actionType, which shows NOTHING for the `guidance` route: the one
// case with no plan at all, and exactly the case where the reason matters
// most, because there is no plan whose actionType could stand in for it.
//
// Still queried on its own, like pullRequest/ownership above, for the
// route_reason half only. **The `route` column itself IS in
// incidentListColumns now** (incidentSummary.Route) — the incidents list grew
// a Route column, and a list that can only say "pull request" by inspecting a
// plan's actionType reproduces this function's own bug one screen over. What
// is still deliberately detail-only is the PROSE: a fleet-wide list has no use
// for a reason sentence on every one of up to 1,000 rows, and the sentence is
// what the detail page is for. So this reads both columns rather than one
// purely because a second round trip for route_reason alone would buy nothing;
// handleGetIncident's own `body["route"]` assignment below is what keeps the
// detail payload's route explicitly `null` rather than omitted, which
// incidentSummary's `omitempty` would otherwise do.
//
// Both columns are NULL for any incident that
// predates lld/08 §12's routing step or has simply never been investigated
// — nullIfEmpty/nullIfEmptyRoute already collapse an empty write to NULL at
// write time (orchestrator/db.go), so no further collapsing is needed here.
//
// `applier` is read here too, from the third column of the same migration
// 000062 triple, for the same reason route_reason is: it is the fact that
// JUSTIFIES the route rather than restating it. `gitopsController` is what makes
// "a pull request, not a live patch" a consequence instead of a policy — it
// names who will actually apply the change, which is the difference between an
// operator reading the route as a rule ARGUS is enforcing on them and reading it
// as a description of how their own cluster works. Like route_reason it is
// detail-only and deliberately not on the list shape.
//
// It is `resolution.Applier`-valued, NOT free text (routing.go resolves it from
// the ownership facts), so a client may map its values to words; it is still
// returned verbatim rather than pre-rendered, because the same value already
// crosses this API under `ownership` and two spellings of one fact is the drift
// this package keeps paying for.
func incidentRouteRecord(ctx context.Context, tx pgx.Tx, incidentID string) (route, reason, applier *string, err error) {
	if err := tx.QueryRow(ctx, `SELECT route, route_reason, applier FROM incidents WHERE id = $1`, incidentID).Scan(&route, &reason, &applier); err != nil {
		return nil, nil, nil, err
	}
	return route, reason, applier, nil
}

// incidentReopenCause says WHAT recurred to reopen this incident, and — the
// part that matters — whether it was the same object the fix was applied to.
//
// The bug this fixes, observed live on inc_01m0xfwwjjgk1hexrsnqc00m7e:
// correlation runs at the WORKLOAD tier when the agent could resolve a Pod's
// owner (see gateway.correlationIdentity.tier), so every Pod of a Deployment
// shares one incident. That is deliberate — pod-level incidents multiply
// without bound. But it means a Validating incident can be reopened by a
// finding on a DIFFERENT object than the one that was fixed:
//
//   - the incident's own Pod was fixed by a merged pull request and its findings
//     stopped dead at the merge;
//   - the replacement Pod from the new ReplicaSet then reported a different
//     fault, correlated onto the same incident by workload_key, and reopened it.
//
// Every layer then told the operator their fix had failed, when it had held.
// gateway.reopenAfterRecurrence's own comment says "any symptom on the object
// reopens it", which is true at the object tier and false at the workload tier —
// the tier that actually fired.
//
// Nothing here changes the correlation or the reopen: both are working as
// designed, and a recurrence on a sibling Pod IS something the operator must
// see. What was wrong is the STORY, so this returns the facts the story needs
// and leaves the state machine alone.
type incidentReopenCause struct {
	ObjectGVK       *string `json:"objectGvk,omitempty"`
	ObjectNamespace *string `json:"objectNamespace,omitempty"`
	ObjectName      *string `json:"objectName,omitempty"`
	Reason          *string `json:"reason,omitempty"`
	OccurredAt      string  `json:"occurredAt"`
	// SameObject is the whole point. Computed here rather than left to the UI
	// so one place owns the comparison and both the API and every future client
	// agree about it.
	SameObject bool `json:"sameObject"`
}

// incidentReopenCauseFor reads the most recent ValidationOutcome timeline event
// (internal/timeline, BACKLOG D8 B1) and turns it into the attribution above.
//
// Returns nil for any incident that is not Reopened, and nil when the incident
// IS Reopened but no such event was recorded — an incident reopened before the
// timeline existed has no honest answer here, and inventing "the same object"
// as a default would be exactly the false claim this whole function exists to
// remove.
func incidentReopenCauseFor(ctx context.Context, tx pgx.Tx, incidentID, state string) (*incidentReopenCause, error) {
	if state != string(orchestrator.StateReopened) {
		return nil, nil
	}
	var (
		payload   []byte
		occurred  time.Time
		objectKey *string
	)
	err := tx.QueryRow(ctx,
		`SELECT payload, occurred_at, incidents.object_key
		   FROM timeline_events
		   JOIN incidents ON incidents.id = timeline_events.incident_id
		  WHERE timeline_events.incident_id = $1
		    AND timeline_events.event_type = $2
		  ORDER BY timeline_events.occurred_at DESC
		  LIMIT 1`,
		incidentID, string(timeline.EventValidationOutcome),
	).Scan(&payload, &occurred, &objectKey)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return nil, nil
	case err != nil:
		return nil, err
	}

	var detail struct {
		Outcome   string `json:"outcome"`
		ObjectKey string `json:"objectKey"`
		Reason    string `json:"reason"`
	}
	if err := json.Unmarshal(payload, &detail); err != nil {
		return nil, fmt.Errorf("decode ValidationOutcome payload: %w", err)
	}
	// A ValidationOutcome event is written for the Resolved promotion too. Only
	// the reopening one describes a recurrence.
	if detail.Outcome != string(orchestrator.StateReopened) {
		return nil, nil
	}

	out := &incidentReopenCause{
		OccurredAt: occurred.UTC().Format(time.RFC3339),
		Reason:     nullIfEmpty(detail.Reason),
		// Compared as whole keys, not by name: object_key is
		// `gvk|namespace|name` (migration 000036) and two Pods in different
		// namespaces can share a name.
		SameObject: objectKey != nil && detail.ObjectKey == *objectKey,
	}
	// Split for display, same three-part split incidentSummary does on
	// object_key. A malformed key yields no identity rather than a guess.
	if parts := strings.SplitN(detail.ObjectKey, "|", 3); len(parts) == 3 {
		out.ObjectGVK = nullIfEmpty(parts[0])
		out.ObjectNamespace = nullIfEmpty(parts[1])
		out.ObjectName = nullIfEmpty(parts[2])
	}
	return out, nil
}

// PROJECT.md T7: "a recurrence reuses what was learned rather than starting
// from zero." The owner's decided mechanism is LINK, not reopen — a
// recurrence opens a brand-new incident (Resolved/Dismissed/Expired all stay
// terminal in the state-machine sense that matters, orchestrator.SetState
// never writes an edge out of Resolved) and this is computed at READ time,
// via a join on incidents.object_key, rather than a stored edge on the new
// row. That is the owner's own stated cost/benefit: "how often does this
// recur" needs a join (this one), in exchange for Resolved staying terminal
// and every incident keeping a clean, single-incident audit trail.

// maxPriorIncidentLinks bounds the join below — an object that has recurred
// dozens of times must not make this endpoint's payload grow without bound;
// see incidentSummary's own similarly-bounded findings list for the same
// reasoning.
const maxPriorIncidentLinks = 5

// priorIncidentLinksQuery finds every CLOSED incident (orchestrator's own
// three closed states — Resolved, Dismissed, Expired) sharing this
// incident's exact object_key OR, when it has one, its workload_key, newest
// first. The workload half is what makes this work for the common case: a
// Deployment's pods get new names on every rollout, so an object_key-only
// match never linked a recurring Deployment fault to what was learned last
// time (found live on rke2, 2026-10-12, with a reverted image re-broken). Two LEFT JOIN LATERALs rather
// than an N+1 per row, matching tolerationListQuery's own precedent in
// tolerations.go:
//
//   - the prior incident's own latest analysis conclusion, if it was ever
//     analysed at all — "what was learned", the specific gap PROJECT.md T7
//     names ("each re-investigated from scratch"). Absent for the common
//     case of a quick dismiss with no investigation.
//   - the prior incident's most recent REJECTED plan decision, if any — the
//     other specific gap PROJECT.md T7 names ("0 rejection reasons have ever
//     been read back"). See internal/orchestrator/recurrence.go's
//     demoteIfPreviouslyRejected for the one thing that already ACTS on
//     this: an identical action type on this same object can no longer
//     auto-approve unattended on a LATER incident either, without a human
//     seeing it again.
const priorIncidentLinksQuery = `
	SELECT i.id, i.state, i.resolution_kind, i.first_seen, i.resolved_at,
	       a.root_cause_statement, a.confidence,
	       rj.action_type, rj.reason, rj.rejected_at
	  FROM incidents i
	  LEFT JOIN LATERAL (
	    SELECT root_cause ->> 'statement' AS root_cause_statement, confidence
	      FROM analyses
	     WHERE analyses.incident_id = i.id
	     ORDER BY created_at DESC
	     LIMIT 1
	  ) a ON true
	  LEFT JOIN LATERAL (
	    SELECT r.action_type, d.reason, d.created_at AS rejected_at
	      FROM remediation_approval_decisions d
	      JOIN remediation_recommendations r ON r.id = d.recommendation_id
	     WHERE d.incident_id = i.id AND d.verdict = 'rejected'
	     ORDER BY d.created_at DESC
	     LIMIT 1
	  ) rj ON true
	 WHERE i.id <> $2
	   AND (i.object_key = $1 OR ($4 <> '' AND i.workload_key = $4))
	   AND i.state IN ('` + orchestrator.StateResolved + `', '` + orchestrator.StateDismissed + `', '` + orchestrator.StateExpired + `')
	 ORDER BY i.first_seen DESC
	 LIMIT $3`

// priorIncidentLink is one row of priorIncidentLinksQuery, rendered for the
// client — see this block's own doc comment above.
type priorIncidentLink struct {
	IncidentID     string   `json:"incidentId"`
	State          string   `json:"state"`
	ResolutionKind *string  `json:"resolutionKind,omitempty"`
	FirstSeen      string   `json:"firstSeen"`
	ResolvedAt     *string  `json:"resolvedAt,omitempty"`
	RootCause      *string  `json:"rootCause,omitempty"`
	Confidence     *float64 `json:"confidence,omitempty"`
	// RejectedPlan is set when a human refused a proposed fix on THIS prior
	// incident. See priorIncidentLinksQuery's own doc comment for what
	// already acts on this fact.
	RejectedPlan *rejectedPlanSummary `json:"rejectedPlan,omitempty"`
}

type rejectedPlanSummary struct {
	ActionType string `json:"actionType"`
	Reason     string `json:"reason"`
	RejectedAt string `json:"rejectedAt"`
}

// objectKeyOfIncident reconstructs incidents.object_key from the three parts
// incidentSummary already split it into (ObjectGVK/ObjectNamespace/
// ObjectName), rather than a second query — those three are always set
// together, or not at all (see incidentSummary's own doc comment: "omitted
// when object_key is NULL"). ok is false when this incident names no
// object, which is the ordinary state for a fingerprint-only incident.
func objectKeyOfIncident(inc incidentSummary) (objectKey string, ok bool) {
	if inc.ObjectGVK == nil || inc.ObjectNamespace == nil || inc.ObjectName == nil {
		return "", false
	}
	return *inc.ObjectGVK + "|" + *inc.ObjectNamespace + "|" + *inc.ObjectName, true
}

// priorIncidentLinksFor runs priorIncidentLinksQuery and scans it into the
// client shape. Always returns a non-nil (possibly empty) slice — an empty
// array on the wire, never null, matching this file's own established
// "absent means nothing to say" convention for a slice field.
func priorIncidentLinksFor(ctx context.Context, tx pgx.Tx, objectKey, workloadKey, excludeIncidentID string) ([]priorIncidentLink, error) {
	rows, err := tx.Query(ctx, priorIncidentLinksQuery, objectKey, excludeIncidentID, maxPriorIncidentLinks, workloadKey)
	if err != nil {
		return nil, fmt.Errorf("query prior incidents: %w", err)
	}
	defer rows.Close()

	links := []priorIncidentLink{}
	for rows.Next() {
		var (
			l                                  priorIncidentLink
			firstSeen                          time.Time
			resolvedAt                         *time.Time
			rejectedActionType, rejectedReason *string
			rejectedAt                         *time.Time
		)
		if err := rows.Scan(&l.IncidentID, &l.State, &l.ResolutionKind, &firstSeen, &resolvedAt,
			&l.RootCause, &l.Confidence, &rejectedActionType, &rejectedReason, &rejectedAt); err != nil {
			return nil, fmt.Errorf("scan prior incident: %w", err)
		}
		l.FirstSeen = formatRFC3339(firstSeen)
		if resolvedAt != nil {
			f := formatRFC3339(*resolvedAt)
			l.ResolvedAt = &f
		}
		if rejectedActionType != nil && rejectedReason != nil && rejectedAt != nil {
			l.RejectedPlan = &rejectedPlanSummary{
				ActionType: *rejectedActionType,
				Reason:     *rejectedReason,
				RejectedAt: formatRFC3339(*rejectedAt),
			}
		}
		links = append(links, l)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate prior incidents: %w", err)
	}
	return links, nil
}
