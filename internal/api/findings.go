package api

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"argus/internal/gateway"
	"argus/internal/logging"
)

// GET /api/v1/findings — PROJECT.md F31.
//
// # Why this endpoint exists
//
// internal/gateway/promotion.go deliberately keeps risks and unverified
// anomalies as findings that never become incidents, and
// metrics.FindingsProcessedTotal counts eight dispositions, four of which are
// a kind of drop. Until this route existed, a finding appeared in the product
// only nested inside an incident that had already been opened — so an
// operator could see everything ARGUS RAISED and nothing it noticed and chose
// not to raise.
//
// In a detection product that gap is the whole trust question, and it is the
// first one a sceptical SRE asks: "what did you see and not tell me about?"
// A per-cluster panel answers it one cluster at a time, which at 200 clusters
// answers nothing, so this is fleet-wide with ?clusterId= as a narrowing
// filter rather than a required one.
//
// # What it can and cannot show, stated in the response itself
//
// Three of FindingsProcessedTotal's outcomes — dropped_detector_disabled,
// dropped_rule_disabled, dropped_polarity_healthy — return from handleFinding
// before any row is inserted. Those findings exist in no table and cannot
// appear here at any filter setting. Rather than let the list silently
// overstate itself, every response carries the promotion rule AND that
// caveat, from gateway.PromotionRule() — see promotionRule/notRecorded in the
// payload.
//
// # Disposition is derived, never stored
//
// findings has no disposition column, and adding one would be a second,
// lagging copy of a decision the evidence columns already determine. What the
// row does record is everything the decision was made from:
//
//   - incident_id IS NOT NULL — the finding reached correlation and is part
//     of an incident. "correlated".
//   - incident_id IS NULL, and today's boundary would not promote it —
//     the evidence boundary kept it as an observation. "retained_unpromoted",
//     the same name FindingsProcessedTotal's own label uses.
//   - incident_id IS NULL, and today's boundary WOULD promote it — it cleared
//     the boundary and something downstream stopped a new incident anyway.
//     Exactly two things do that (internal/gateway/finding.go's ErrNoRows
//     branch): a toleration, and storm protection. "suppressed".
//
// Migration 000124 (PROJECT.md F31) added findings.suppression_reason,
// written once at INSERT time by the same branch in
// internal/gateway/finding.go's handleFinding that already writes the
// audit_events row (finding_suppressed_by_toleration /
// storm_protection_suppressed_new_incident) — so the two can never disagree.
// It is surfaced below as SuppressionReason, but ONLY for rows written after
// that migration: it is never backfilled, so a suppressed row from before it
// still carries NULL, and the UI (and this comment) must keep pointing an
// operator at the audit log for one of those rather than assume "not set"
// means "not recorded anywhere."
//
// Because the verdict is derived from today's gate rather than from what the
// gate said at ingest time, a row's disposition can change when the boundary
// moves. That is the wanted behaviour and the same choice
// incident_promotion_reconcile.go already made: the question an operator is
// asking is "would ARGUS raise this", present tense.

const (
	// defaultFindingPageLimit is deliberately far below handleListIncidents'
	// 500. That default is large for a stated reason — IncidentsPage still
	// filters and counts over the array it receives, so a small page would
	// make its client-side search wrong rather than paginated. Nothing
	// filters findings client-side (there is no findings screen yet, and
	// every filter here is server-side), so the page size can be what a page
	// should be.
	defaultFindingPageLimit = 200
	maxFindingPageLimit     = 1000

	// defaultFindingWindow bounds ?since= when the caller does not set it.
	//
	// findings is the highest-volume table in the schema — every detector
	// re-sends its own fingerprint once per resend cooldown for as long as a
	// problem persists — and it is range-partitioned on occurred_at, so a
	// bounded window is the difference between reading a partition or two
	// and reading a month of them. An unbounded default would also make the
	// counts below (which are exact, by design) the most expensive thing on
	// the hub. Seven days is a window an operator can reason about, and the
	// response states it rather than leaving the caller to assume "all".
	defaultFindingWindow = 7 * 24 * time.Hour
)

// The three dispositions, and the ?disposition= vocabulary. correlated and
// suppressed are named for what happened; retained_unpromoted deliberately
// matches metrics.FindingsProcessedTotal's label byte-for-byte, so an
// operator reading a Prometheus graph and an operator reading this list are
// using the same word for the same thing.
const (
	findingDispositionCorrelated = "correlated"
	findingDispositionRetained   = "retained_unpromoted"
	findingDispositionSuppressed = "suppressed"
)

var validFindingDispositions = []string{
	findingDispositionCorrelated,
	findingDispositionRetained,
	findingDispositionSuppressed,
}

// findingPromotableSQL is internal/gateway's own gate, rendered to SQL by
// enumerating its input domain — see gateway.PromotableFindingSQL's doc
// comment for why that is not a second definition of the rule. Resolved once
// at package initialisation because it is a constant of the build.
var findingPromotableSQL = gateway.PromotableFindingSQL()

// findingDispositionClauses is the ONE definition of each disposition as SQL.
// The row query's ?disposition= filter and the counts query's FILTER clauses
// both read it, so a number on a tab and the rows a click on that tab returns
// can never describe two different sets — the same discipline
// requiresActionStateClause enforces for the incident queue.
var findingDispositionClauses = map[string]string{
	findingDispositionCorrelated: "(findings.incident_id IS NOT NULL)",
	findingDispositionRetained:   "(findings.incident_id IS NULL AND NOT " + findingPromotableSQL + ")",
	findingDispositionSuppressed: "(findings.incident_id IS NULL AND " + findingPromotableSQL + ")",
}

// findingListColumns/findingListFrom mirror incidentListColumns/
// incidentListFrom's split for the same reason: the counts query needs the
// same FROM and the same scope, and must not be able to drift from the row
// query's idea of which findings are in scope.
//
// reason and message are coalesced because both columns are nullable —
// internal/gateway/finding.go never writes NULL into either, but a legacy or
// hand-inserted row must not come back as a missing field rather than an
// empty one.
const findingListColumns = `findings.id, findings.cluster_id, clusters.display_name,
	       findings.detector_id, findings.rule_id, findings.gvk, findings.namespace,
	       findings.object_name, coalesce(findings.reason, ''), coalesce(findings.message, ''),
	       findings.severity, findings.occurrence_count, findings.occurred_at,
	       findings.fingerprint, findings.signal_class, findings.confidence, findings.impact,
	       findings.incident_id, findings.suppression_reason`

// The JOIN is carried by the counts query as well as the row query even
// though counts need no display name. findings.cluster_id is NOT NULL with a
// foreign key, so the join cannot change cardinality — but clusters carries
// its own RLS policy, and if a cluster row were ever invisible to a caller
// whose findings rows were not, a joined row query and an unjoined counts
// query would silently describe different sets. That is the exact bug class
// this endpoint's counts exist to avoid, so both sides join.
const findingListFrom = `
	  FROM findings
	  JOIN clusters ON clusters.id = findings.cluster_id
	 WHERE TRUE`

// findingScopeFilter builds the WHERE fragment shared by the row query and
// the counts query.
//
// Called once per query rather than once per request, exactly like
// incidentScopeFilter: each call starts its own args slice, so placeholder
// numbering is always correct for whichever query it is spliced into.
//
// ?disposition= is deliberately NOT part of it. The counts ARE the
// disposition breakdown; narrowing them by the disposition filter would leave
// two of the three at zero and destroy the comparison the operator came for.
// Applying ?disposition= to the rows alone means counts always answer "of
// everything in this cluster/reason/class/window scope, how much fell into
// each bucket", and the true total for the current filter is the one count
// naming it. Same reasoning as incidentCountsFor's exclusion of ?search=.
//
// invalid is non-empty (and clause/args unusable) only for a value out of a
// closed vocabulary — class, confidence, impact, and the timestamps. A
// ?clusterId= or ?reason= that matches nothing is not an error, matching
// handleListIncidents' treatment of a freely-generated id.
// since/until are resolved ONCE per request by the handler and passed in,
// never re-derived here. findingWindowFor defaults since to "now minus the
// default window", and calling it separately for the row query, the counts
// query and the response echo would give each of them a slightly different
// "now" — three answers to one question, which is the precise failure mode
// this endpoint's exact counts exist to rule out.
func findingScopeFilter(q url.Values, since time.Time, until *time.Time) (clause string, args []any, invalid string) {
	get := q.Get

	var b strings.Builder
	add := func(fragment string, value any) {
		args = append(args, value)
		fmt.Fprintf(&b, fragment, len(args))
	}

	if clusterID := get("clusterId"); clusterID != "" {
		add(" AND findings.cluster_id = $%d", clusterID)
	}
	if reason := get("reason"); reason != "" {
		add(" AND coalesce(findings.reason, '') = $%d", reason)
	}
	for _, dim := range []struct {
		param      string
		column     string
		vocabulary []string
	}{
		{"class", "findings.signal_class", gateway.FindingClasses()},
		{"confidence", "findings.confidence", gateway.FindingConfidences()},
		{"impact", "findings.impact", gateway.FindingImpacts()},
	} {
		value := get(dim.param)
		if value == "" {
			continue
		}
		if !slices.Contains(dim.vocabulary, value) {
			// A value outside the closed set is a 400, never a filter that
			// matches nothing: "there are no risk-class findings" and "risk
			// is not a word this API knows" look identical to an operator,
			// and only one of them is true.
			return "", nil, dim.param + " must be one of: " + strings.Join(dim.vocabulary, ", ")
		}
		add(" AND "+dim.column+" = $%d", value)
	}

	add(" AND findings.occurred_at >= $%d", since)
	if until != nil {
		add(" AND findings.occurred_at <= $%d", *until)
	}

	if disposition := get("disposition"); disposition != "" {
		if !slices.Contains(validFindingDispositions, disposition) {
			return "", nil, "disposition must be one of: " + strings.Join(validFindingDispositions, ", ")
		}
	}

	return b.String(), args, ""
}

// findingWindowFor resolves ?since=/?until=. Both are RFC 3339; since
// defaults to defaultFindingWindow ago, until to open-ended.
func findingWindowFor(sinceRaw, untilRaw string) (since time.Time, until *time.Time, invalid string) {
	since = time.Now().Add(-defaultFindingWindow)
	if sinceRaw != "" {
		parsed, err := time.Parse(time.RFC3339, sinceRaw)
		if err != nil {
			return time.Time{}, nil, "since must be an RFC 3339 timestamp"
		}
		since = parsed
	}
	if untilRaw != "" {
		parsed, err := time.Parse(time.RFC3339, untilRaw)
		if err != nil {
			return time.Time{}, nil, "until must be an RFC 3339 timestamp"
		}
		if parsed.Before(since) {
			return time.Time{}, nil, "until must not be earlier than since"
		}
		until = &parsed
	}
	return since, until, ""
}

// findingListItem is one row. Class/Confidence/Impact are the STORED evidence
// tuple; Promotion.class/confidence/impact are the EFFECTIVE one the gate
// judged, which differs only for a legacy generic row carrying migration
// 000092's column defaults (Promotion.evidenceCorrected says so). Both are
// present on purpose: hiding the stored values would make the list
// unreconcilable with the database, and hiding the effective ones would make
// a row read as "fault, verified, degraded — not promoted", which reads as a
// bug rather than as the correction it is.
type findingListItem struct {
	ID                 string  `json:"id"`
	ClusterID          string  `json:"clusterId"`
	ClusterDisplayName string  `json:"clusterDisplayName"`
	DetectorID         string  `json:"detectorId"`
	RuleID             *string `json:"ruleId,omitempty"`
	GVK                string  `json:"gvk"`
	Namespace          *string `json:"namespace,omitempty"`
	ObjectName         *string `json:"objectName,omitempty"`
	Reason             string  `json:"reason"`
	Message            string  `json:"message"`
	Severity           string  `json:"severity"`
	OccurrenceCount    int     `json:"occurrenceCount"`
	OccurredAt         string  `json:"occurredAt"`
	Fingerprint        string  `json:"fingerprint"`
	Class              string  `json:"class"`
	Confidence         string  `json:"confidence"`
	Impact             string  `json:"impact"`
	Disposition        string  `json:"disposition"`
	// IncidentID is present exactly when Disposition is "correlated" — it is
	// what makes that disposition true, not a separate fact.
	IncidentID *string `json:"incidentId,omitempty"`
	// SuppressionReason is present only when Disposition is "suppressed" AND
	// this row was written after migration 000124 — see this file's header.
	// One of "toleration"/"storm_protection". Absent (never a guessed value)
	// on a pre-migration suppressed row or on any other disposition.
	SuppressionReason *string                  `json:"suppressionReason,omitempty"`
	Promotion         gateway.PromotionVerdict `json:"promotion"`
}

// findingCounts is the disposition breakdown over the FULL scoped set.
//
// Never derived from len(findings). This repo has a recorded bug of exactly
// that shape (the overview's open count, and the incident quick-view tabs
// before incidentCountsFor existed): a number computed from the fetched page
// that silently understated itself the moment the list truncated, while
// continuing to look like a fact. All is therefore a second aggregate query
// in the same scope, never limited by ?limit= or ?cursor=.
type findingCounts struct {
	All                int `json:"all"`
	Correlated         int `json:"correlated"`
	RetainedUnpromoted int `json:"retainedUnpromoted"`
	Suppressed         int `json:"suppressed"`
}

// findingWindow echoes the resolved time bounds. Present always, because
// ?since= defaults rather than meaning "everything": a count is only honest
// alongside the window it counted.
type findingWindow struct {
	Since string  `json:"since"`
	Until *string `json:"until,omitempty"`
}

type findingsResponse struct {
	Findings   []findingListItem `json:"findings"`
	NextCursor string            `json:"nextCursor,omitempty"`
	Counts     findingCounts     `json:"counts"`
	Window     findingWindow     `json:"window"`
	// PromotionRule is the boundary itself, in every response. The acceptance
	// this route was built to is explicit that the rule must be readable from
	// the API rather than only from a comment in internal/gateway: an
	// operator looking at a list of things that were not raised has to be
	// able to see what would have raised them.
	PromotionRule gateway.PromotionRuleStatement `json:"promotionRule"`
}

var findingCountsQuery = `
	SELECT count(*) AS all_count,
	       count(*) FILTER (WHERE ` + findingDispositionClauses[findingDispositionCorrelated] + `) AS correlated_count,
	       count(*) FILTER (WHERE ` + findingDispositionClauses[findingDispositionRetained] + `) AS retained_count,
	       count(*) FILTER (WHERE ` + findingDispositionClauses[findingDispositionSuppressed] + `) AS suppressed_count` +
	findingListFrom

// findingCountsFor runs findingCountsQuery scoped exactly like the calling
// request's row query — a fresh findingScopeFilter call, not the caller's
// already-built clause, so placeholder numbering starts from $1 for this
// query independently of what the row query did with cursors and limits.
func findingCountsFor(ctx context.Context, rc *requestContext, q url.Values, since time.Time, until *time.Time) (findingCounts, error) {
	scopeClause, scopeArgs, invalid := findingScopeFilter(q, since, until)
	if invalid != "" {
		return findingCounts{}, fmt.Errorf("unexpected invalid scope filter: %s", invalid)
	}
	var counts findingCounts
	err := rc.Tx.QueryRow(ctx, findingCountsQuery+scopeClause, scopeArgs...).
		Scan(&counts.All, &counts.Correlated, &counts.RetainedUnpromoted, &counts.Suppressed)
	return counts, err
}

// handleListFindings is GET /api/v1/findings. Requires incident:read.
//
// # Why incident:read rather than a new capability
//
// A finding is the evidence an incident is made of, and GET /incidents/{id}
// already returns findings under incident:read. A separate finding:read would
// be a capability that every role holding incident:read would have to be
// granted anyway to keep the incident detail page working — a distinction with
// no authorisation decision behind it, and one more thing for an operator to
// get wrong when building a custom role.
//
// # Query parameters
//
// All optional, all independently ANDed:
//
//   - ?clusterId= — one cluster. An unknown id matches nothing rather than
//     erroring, same as handleListIncidents.
//   - ?reason= — exact match on the detector's reason (the vocabulary
//     internal/agent's detectors and rules emit). Exact, not ILIKE: this is a
//     closed vocabulary, and a substring match would silently conflate
//     GenericConditionAnomaly:Ready with GenericConditionAnomaly:ReadyReplicas.
//   - ?disposition= — one of correlated / retained_unpromoted / suppressed.
//   - ?class=, ?confidence=, ?impact= — the three evidence dimensions, which
//     are also the three criteria of the promotion rule, so they are how an
//     operator drills from "why was nothing raised" to the exact bucket.
//   - ?since=, ?until= — RFC 3339. See defaultFindingWindow.
//   - ?limit=, ?cursor= — see below.
//
// An out-of-vocabulary class/confidence/impact/disposition, or an
// unparseable timestamp, is a 400.
//
// # Pagination
//
// Keyset, copied from handleListIncidents' default-sort path rather than
// reinvented — the plain (timestamp, id) token, because this list has exactly
// one order and no ?sort=. occurred_at has one property the incident list's
// last_seen does not: it never changes after the row is written, so this
// cursor has none of the "a row moved to page 1 while you were on page 3"
// caveat that keyset over a mutating sort key carries.
//
// nextCursor is present only when a full page came back, so a client that
// ignores it keeps working. counts is always present and never bounded by
// ?limit=/?cursor=.
func (s *Server) handleListFindings(w http.ResponseWriter, r *http.Request, rc *requestContext) {
	q := r.URL.Query()
	since, until, invalid := findingWindowFor(q.Get("since"), q.Get("until"))
	if invalid != "" {
		writeProblem(w, http.StatusBadRequest, "https://argus.io/errors/invalid-request",
			"Invalid time window", invalid)
		return
	}
	scopeClause, args, invalid := findingScopeFilter(q, since, until)
	if invalid != "" {
		writeProblem(w, http.StatusBadRequest, "https://argus.io/errors/invalid-request",
			"Invalid filter", invalid)
		return
	}

	query := "SELECT " + findingListColumns + findingListFrom + scopeClause

	if disposition := q.Get("disposition"); disposition != "" {
		// Already validated by findingScopeFilter; the clause is looked up
		// rather than rebuilt so the rows and the counts share one definition.
		query += " AND " + findingDispositionClauses[disposition]
	}

	if cursor := q.Get("cursor"); cursor != "" {
		occurredAt, id, err := decodeFindingCursor(cursor)
		if err != nil {
			writeProblem(w, http.StatusBadRequest, "https://argus.io/errors/malformed-request",
				"Invalid cursor", "cursor is not a valid page-continuation token")
			return
		}
		args = append(args, occurredAt, id)
		query += fmt.Sprintf(" AND (findings.occurred_at, findings.id) < ($%d, $%d)", len(args)-1, len(args))
	}

	limit, err := findingPageLimit(q.Get("limit"))
	if err != nil {
		writeProblem(w, http.StatusBadRequest, "https://argus.io/errors/malformed-request",
			"Invalid limit", err.Error())
		return
	}
	args = append(args, limit)
	// id is the tiebreaker, not decoration: two detectors reporting the same
	// broken object in the same second is normal here (migration 000036's own
	// measured case), and a keyset cursor over a non-unique sort key drops or
	// repeats the tied rows without it.
	query += fmt.Sprintf(" ORDER BY findings.occurred_at DESC, findings.id DESC LIMIT $%d", len(args))

	ctx := r.Context()
	rows, err := rc.Tx.Query(ctx, query, args...)
	if err != nil {
		logger.ErrorContext(ctx, "querying findings failed", logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not list findings", "")
		return
	}
	defer rows.Close()

	findings := []findingListItem{}
	var lastOccurredAt time.Time
	var lastID string
	for rows.Next() {
		var item findingListItem
		var occurredAt time.Time
		if err := rows.Scan(&item.ID, &item.ClusterID, &item.ClusterDisplayName,
			&item.DetectorID, &item.RuleID, &item.GVK, &item.Namespace, &item.ObjectName,
			&item.Reason, &item.Message, &item.Severity, &item.OccurrenceCount, &occurredAt,
			&item.Fingerprint, &item.Class, &item.Confidence, &item.Impact, &item.IncidentID,
			&item.SuppressionReason); err != nil {
			logger.ErrorContext(ctx, "scanning a finding row failed", logging.Err(err))
			writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not list findings", "")
			return
		}
		item.OccurredAt = formatRFC3339(occurredAt)
		item.Promotion = gateway.ExplainStoredFinding(item.Reason, item.Class, item.Confidence, item.Impact)
		item.Disposition = findingDispositionOf(item.IncidentID, item.Promotion)
		findings = append(findings, item)
		lastOccurredAt, lastID = occurredAt, item.ID
	}
	if err := rows.Err(); err != nil {
		logger.ErrorContext(ctx, "iterating the finding rows failed", logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not list findings", "")
		return
	}

	counts, err := findingCountsFor(ctx, rc, q, since, until)
	if err != nil {
		logger.ErrorContext(ctx, "reading the finding counts failed", logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not count findings", "")
		return
	}

	window := findingWindow{Since: formatRFC3339(since)}
	if until != nil {
		formatted := formatRFC3339(*until)
		window.Until = &formatted
	}

	resp := findingsResponse{
		Findings:      findings,
		Counts:        counts,
		Window:        window,
		PromotionRule: gateway.PromotionRule(),
	}
	// A full page might not be the last page; handing back a cursor costs one
	// extra empty request in the exact-multiple case, which is cheaper than a
	// limit+1 fetch. Same trade handleListIncidents and handleListAuditEvents
	// both make.
	if len(findings) == limit {
		resp.NextCursor = encodeFindingCursor(lastOccurredAt, lastID)
	}

	writeJSON(w, http.StatusOK, resp)
}

// findingDispositionOf is the Go half of findingDispositionClauses, and the
// two must agree exactly — the SQL decides which rows a ?disposition= filter
// returns and what each count counts, this decides what each returned row
// SAYS it is. findings_db_test.go asserts they agree by filtering on every
// disposition and checking every row comes back labelled with it.
func findingDispositionOf(incidentID *string, verdict gateway.PromotionVerdict) string {
	switch {
	case incidentID != nil:
		return findingDispositionCorrelated
	case verdict.Promotable:
		// It cleared the boundary and still has no incident: a toleration or
		// storm protection stopped the new-incident creation. See this file's
		// header for why the row cannot say which.
		return findingDispositionSuppressed
	default:
		return findingDispositionRetained
	}
}

// findingPageLimit parses ?limit=, rejecting nonsense rather than clamping it
// silently — clamping quietly would let a caller keep asking for everything
// and never be told about the cap. Same shape as incidentPageLimit.
func findingPageLimit(raw string) (int, error) {
	if raw == "" {
		return defaultFindingPageLimit, nil
	}
	n, err := strconv.Atoi(raw)
	if err != nil {
		return 0, fmt.Errorf("limit must be a whole number")
	}
	if n < 1 {
		return 0, fmt.Errorf("limit must be at least 1")
	}
	if n > maxFindingPageLimit {
		return 0, fmt.Errorf("limit must be at most %d; use the nextCursor from the previous response to read further", maxFindingPageLimit)
	}
	return n, nil
}

// encodeFindingCursor/decodeFindingCursor: base64(occurred_at in RFC3339Nano
// + "|" + id).
//
// Deliberately the same shape and the same NOT-signed choice as the incident
// and audit cursors — a cursor carries nothing the caller cannot already read
// in the same response, so signing it would protect nothing. Kept as its own
// pair rather than shared with either so that changing one list's sort key
// cannot silently invalidate another's tokens.
func encodeFindingCursor(occurredAt time.Time, id string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(occurredAt.UTC().Format(time.RFC3339Nano) + "|" + id))
}

func decodeFindingCursor(cursor string) (time.Time, string, error) {
	raw, err := base64.RawURLEncoding.DecodeString(cursor)
	if err != nil {
		return time.Time{}, "", fmt.Errorf("decode cursor: %w", err)
	}
	occurredAtStr, id, ok := strings.Cut(string(raw), "|")
	if !ok || occurredAtStr == "" || id == "" {
		return time.Time{}, "", fmt.Errorf("malformed cursor payload")
	}
	occurredAt, err := time.Parse(time.RFC3339Nano, occurredAtStr)
	if err != nil {
		return time.Time{}, "", fmt.Errorf("parse cursor timestamp: %w", err)
	}
	return occurredAt, id, nil
}
