package api

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"argus/internal/authz"
	"argus/internal/logging"
)

// This file implements GET /api/v1/audit-events and GET /api/v1/audit-events/{id}
// — the first way to actually READ the hash-chained audit_events table
// (internal/audit, migration 000008) short of `psql` or the standalone
// `argusctl audit verify` tool (internal/argusctl/audit.go, cmd/argusctl/audit.go).
// This is a genuinely separate, additive capability from that verify tool, not a
// replacement for it: `audit verify` re-derives the hash chain to prove the log
// hasn't been tampered with and deliberately runs OUTSIDE the hub for that reason
// (see its own doc comments); this file just lists/reads rows through the hub's
// normal RLS-scoped, capability-gated request path, the same way every other
// "list X" endpoint in this codebase works. Read-only by design — no route here
// ever writes to audit_events, since the entire point of a hash chain is that
// it's append-only and tamper-evident; an edit/delete endpoint would undermine
// that on its face.
//
// GET /api/v1/audit-events/export (audit_export.go, BACKLOG.md S3's "audit
// export" slice) is a third, bulk-shaped way to read this same table — CSV or
// JSON, streamed rather than paginated — and shares this file's
// parseAuditEventFilters and scanAuditEventDetailRow rather than duplicating
// them.
//
// Both routes require audit:read (authz/permissions.go's CapAuditRead) — an
// org-only capability (orgOnlyCapabilities) deliberately granted to super-admin
// alone, NOT tenant-admin (permissions.go's explicit comment on that exclusion).
//
// A real, structural RLS gap in this table was found and already fixed by a
// prior task, not by this one: migration 000009's generic cluster_id-scoped RLS
// loop put audit_events on a policy keyed SOLELY on
// `cluster_id = ANY(app.accessible_cluster_ids)`, which — since nothing yet
// populates that session variable (requireAuth always passes nil scope) and most
// audit rows have a NULL cluster_id anyway (login, settings writes, capability
// denials, user/grant management, etc.) — would have made every query against
// this table via rc.Tx return zero rows for every caller, including a
// super-admin. Migration 000012_audit_events_tenant_scope.up.sql already added an
// additive, OR'd tenant_id-keyed policy (the same fix migration 000011 applied to
// `clusters`) before this task started, so rc.Tx queries below see every one of
// this tenant's rows correctly. Confirmed by reading both migrations before
// writing this file — flagging it here since a handler that silently returned
// zero rows against a "should be readable" table would otherwise look like a bug
// in THIS file rather than what it actually is: a schema-level fix that already
// landed.

// auditEventSummary is the shape returned by both handleListAuditEvents (as an
// element of "auditEvents") and as the base fields of handleGetAuditEvent's
// response — mirrors incidentSummary's role in incidents.go. Deliberately
// excludes the raw `details` JSON blob (shapes vary per write path — compare
// settings.go's handlePutSettings vs. clusters.go's handleCreateEnrollmentToken
// — and some are large enough that dumping every row's full details into a list
// response isn't worth it) in favor of detailsSummary, a short, generic
// stringified digest; the full, structured details are only in
// handleGetAuditEvent's response, matching the incidents-list-vs-incident-detail
// split already established by incidents.go.
type auditEventSummary struct {
	ID                 string  `json:"id"`
	OccurredAt         string  `json:"occurredAt"`
	ActorID            *string `json:"actorId"`
	ActorEmail         *string `json:"actorEmail"`
	ActorDisplayName   *string `json:"actorDisplayName"`
	ActorAuthMethod    string  `json:"actorAuthMethod"`
	SourceIP           *string `json:"sourceIp"`
	Capability         *string `json:"capability"`
	ClusterID          *string `json:"clusterId"`
	ClusterDisplayName *string `json:"clusterDisplayName"`
	Outcome            string  `json:"outcome"`
	// Action is what actually happened, for the column the UI labels "Action".
	//
	// That column used to render Capability, which is a different thing and is NULL
	// for every event the system raises on its own (a toleration suppressing a
	// finding, a certificate being issued) — so the column read "—" while the real
	// action name was only reachable inside the details summary beside it. Derived
	// here rather than in the client because the fallback order is a server-side
	// judgement about this schema, not presentation.
	Action         string `json:"action"`
	DetailsSummary string `json:"detailsSummary"`
}

// auditEventDetail is handleGetAuditEvent's response shape: every
// auditEventSummary field, plus the full `details`/`scope` JSON and this row's
// own two hash-chain fields (prevHash/hash) — included because they're
// non-secret and let an admin spot-check one row's own chain linkage inline,
// without reaching for `argusctl audit verify`'s full-table pass.
type auditEventDetail struct {
	auditEventSummary
	Scope    map[string]any `json:"scope"`
	Details  map[string]any `json:"details"`
	PrevHash string         `json:"prevHash"`
	Hash     string         `json:"hash"`
}

// auditEventBaseQuery is shared by handleListAuditEvents and
// handleGetAuditEvent's SELECT list for the fields both need — LEFT JOINs
// (never INNER) to users/clusters since actor_id and cluster_id are both
// nullable on audit_events (a login failure has no actor; most audit rows have
// no cluster at all — see this file's doc comment), and a LEFT JOIN degrades
// gracefully to a null display name rather than dropping the row entirely.
// source_ip is passed through host() in both queries below, not a bare
// ::text cast: audit_events.source_ip is a native Postgres `inet` column,
// and pgx's binary decoder for inet has no direct mapping onto a Go *string
// (it wants a netip.Addr) — SQL-side conversion sidesteps introducing that
// type just for display purposes here, since every consumer of this field
// (the JSON response, the summary string) only ever wants a plain address
// string anyway. host() specifically, not ::text: a bare ::text cast of an
// inet value renders WITH its netmask suffix (confirmed live against this
// project's own dev Postgres: '172.18.0.1'::inet::text -> "172.18.0.1/32",
// since every value defaults to a full-width /32 mask unless one was
// explicitly stored) — host() is the documented way to get just the address
// with no CIDR suffix, matching what clientIP() (middleware.go) actually
// stored and what a reader of this API would expect "the source IP" to mean.
const auditEventBaseQuery = `
	SELECT ae.id, ae.occurred_at, ae.actor_id, u.email, u.display_name,
	       ae.actor_auth_method, host(ae.source_ip), ae.capability, ae.cluster_id,
	       c.display_name, ae.outcome, ae.details
	  FROM audit_events ae
	  LEFT JOIN users u ON u.id = ae.actor_id
	  LEFT JOIN clusters c ON c.id = ae.cluster_id`

// auditEventDetailBaseQuery is the SELECT/FROM/JOIN portion shared by
// auditEventDetailQuery (handleGetAuditEvent's single-row lookup, WHERE
// ae.id = $1 below) and audit_export.go's handleExportAuditEvents (which
// appends parseAuditEventFilters' WHERE clause instead) — kept as one
// constant so the two never drift out of column-order sync with
// scanAuditEventDetailRow, which scans both by shared position.
const auditEventDetailBaseQuery = `
	SELECT ae.id, ae.occurred_at, ae.actor_id, u.email, u.display_name,
	       ae.actor_auth_method, host(ae.source_ip), ae.capability, ae.scope,
	       ae.cluster_id, c.display_name, ae.outcome, ae.details,
	       ae.prev_hash, ae.hash
	  FROM audit_events ae
	  LEFT JOIN users u ON u.id = ae.actor_id
	  LEFT JOIN clusters c ON c.id = ae.cluster_id`

const auditEventDetailQuery = auditEventDetailBaseQuery + `
	 WHERE ae.id = $1`

const (
	defaultAuditEventLimit = 50
	maxAuditEventLimit     = 200
	// detailsSummaryMaxRunes bounds how much of a stringified `details` blob
	// handleListAuditEvents' summary carries — generous enough for every
	// details shape this codebase currently writes (a handful of short
	// key/value pairs — see settings.go/clusters.go's audit.RecordEvent
	// calls), just a backstop against a pathologically large future one.
	detailsSummaryMaxRunes = 200
)

// auditEventFilterError is a validation failure from parseAuditEventFilters —
// carries just enough (title/detail) to write an RFC 9457 400 response,
// kept as its own type so a caller can't mistake it for an unexpected
// internal error and log it as one.
type auditEventFilterError struct {
	title  string
	detail string
}

// parseAuditEventFilters builds the WHERE clause + positional args for this
// table's common, ANDed query parameters — actor/capability/cluster/
// resource/outcome/since/until, exactly as handleListAuditEvents documents
// them below — shared with audit_export.go's handleExportAuditEvents so the
// two never duplicate (and drift out of sync on) this parsing and
// validation. Deliberately excludes `cursor`/`limit`, which only
// handleListAuditEvents' keyset pagination needs.
//
// Also returns the parsed since/until as *time.Time (nil if the caller didn't
// pass one) — handleListAuditEvents ignores these, but handleExportAuditEvents
// needs the parsed values themselves to enforce its own required-range bound,
// and re-parsing the same strings a second time would be exactly the
// duplication this function exists to avoid.
func parseAuditEventFilters(q url.Values) (whereSQL string, args []any, since, until *time.Time, ferr *auditEventFilterError) {
	whereSQL = " WHERE 1=1"

	if actor := q.Get("actor"); actor != "" {
		args = append(args, actor)
		n := len(args)
		whereSQL += fmt.Sprintf(" AND (ae.actor_id = $%d OR u.email ILIKE '%%' || $%d || '%%' OR u.display_name ILIKE '%%' || $%d || '%%')", n, n, n)
	}
	if capability := q.Get("capability"); capability != "" {
		args = append(args, capability)
		whereSQL += fmt.Sprintf(" AND ae.capability = $%d", len(args))
	}
	// cluster: exact match against ae.cluster_id, same convention as
	// `capability` above (an opaque id the caller picks from a list, not free
	// text) — and, unlike `actor`'s ILIKE, backed by audit_events_cluster_idx
	// (migration 000008), so this is the one new filter here that's actually
	// cheap regardless of table size.
	//
	// NULL cluster_id (an org-level event that isn't about any one cluster —
	// a settings write, a login, a user/grant change; see this file's doc
	// comment) is a real, common case on this table, and `ae.cluster_id = $n`
	// deliberately does NOT match it: SQL equality against NULL is never
	// true, so filtering to one cluster shows only events that are actually
	// about that cluster, and org-level events stay out of every cluster's
	// view. The alternative — folding NULL rows into every cluster filter —
	// would answer "what happened in production" by also showing events that
	// have nothing to do with production, which is worse than the current
	// gap this item was filed to close. There is deliberately no way to ask
	// for "this cluster's events plus the org-level ones" in the same
	// request; clearing the cluster filter (or filtering by capability
	// instead) already answers that.
	if clusterID := q.Get("cluster"); clusterID != "" {
		args = append(args, clusterID)
		whereSQL += fmt.Sprintf(" AND ae.cluster_id = $%d", len(args))
	}
	// resource: free text against the object this event was actually about,
	// substring/case-insensitive like `actor` above, so typing a namespace or
	// object name an operator already knows ("checkout-worker") is enough —
	// not required to be the full "gvk|namespace|name" key.
	//
	// What this can and can't match, decided by what's actually queryable on
	// this row rather than invented: audit_events has NO resource/object
	// column of its own (migration 000008) and no index over `details` at
	// all, and the object-shaped keys inside `details` are NOT one consistent
	// field across write paths — some events name their object directly as
	// `details.objectKey` (tolerate/remove-toleration, the
	// finding-suppressed-by-toleration event — internal/api/tolerations.go,
	// internal/gateway/finding.go), while the remediation/GitOps events that
	// are the actual "who changed production" case (approve_remediation,
	// execute_remediation, rollback_execution/committed,
	// open_repository_change) record only `details.incidentId`, not the
	// object itself. So this matches EITHER shape: `details.objectKey`
	// directly, or — via the incident that event names — that incident's own
	// `object_key` (incidents.object_key, migration 000036, the same
	// "gvk|namespace|name" format). An event with neither key (a settings
	// write, a login, a user/grant/AI-provider/IdP change, cluster
	// accept/decommission) has no resource concept at all and is correctly
	// never matched — not a gap this filter silently papers over, since
	// those events were never "about" a Kubernetes object to begin with.
	//
	// Cost, stated plainly rather than left implicit: neither disjunct is
	// index-backed. `ae.details->>'objectKey'` has no functional index, so
	// evaluating it costs a per-row JSON field extraction across whatever the
	// rest of the WHERE clause (cluster/actor/since/until) hasn't already
	// pruned. The EXISTS subquery is cheap PER ROW ONCE REACHED — it looks up
	// one incident by primary key (`inc.id = ...`), not a scan of incidents —
	// but it still runs once per audit_events row this query considers, for
	// the same reason. This is the same shape of cost the existing `actor`
	// filter's ILIKE branch already carries (also unindexed on this table),
	// not a new category of risk this filter introduces on its own — but
	// unlike `actor`, an unqualified `?resource=` with no `cluster`/`since`/
	// `until` alongside it has no index to fall back on at all. Pair it with
	// one of those when the table is large.
	if resource := q.Get("resource"); resource != "" {
		args = append(args, resource)
		n := len(args)
		whereSQL += fmt.Sprintf(` AND (ae.details->>'objectKey' ILIKE '%%' || $%d || '%%' OR EXISTS (
			SELECT 1 FROM incidents inc WHERE inc.id = ae.details->>'incidentId' AND inc.object_key ILIKE '%%' || $%d || '%%'
		))`, n, n)
	}
	if outcome := q.Get("outcome"); outcome != "" {
		if outcome != "success" && outcome != "denied" && outcome != "error" {
			return "", nil, nil, nil, &auditEventFilterError{"Invalid outcome", "outcome must be success, denied, or error"}
		}
		args = append(args, outcome)
		whereSQL += fmt.Sprintf(" AND ae.outcome = $%d", len(args))
	}
	if sinceRaw := q.Get("since"); sinceRaw != "" {
		t, err := time.Parse(time.RFC3339, sinceRaw)
		if err != nil {
			return "", nil, nil, nil, &auditEventFilterError{"Invalid since", "since must be an RFC 3339 timestamp"}
		}
		since = &t
		args = append(args, t)
		whereSQL += fmt.Sprintf(" AND ae.occurred_at >= $%d", len(args))
	}
	if untilRaw := q.Get("until"); untilRaw != "" {
		t, err := time.Parse(time.RFC3339, untilRaw)
		if err != nil {
			return "", nil, nil, nil, &auditEventFilterError{"Invalid until", "until must be an RFC 3339 timestamp"}
		}
		until = &t
		args = append(args, t)
		whereSQL += fmt.Sprintf(" AND ae.occurred_at <= $%d", len(args))
	}
	return whereSQL, args, since, until, nil
}

// handleListAuditEvents is GET /api/v1/audit-events. Requires audit:read.
// Most-recent-first (occurred_at DESC, id DESC — id as the tie-breaker for the
// same reason argusctl's LoadAuditEvents uses it: timestamptz is only
// microsecond-precision, and a ULID id is itself monotonic for rows minted in
// quick succession, so this ordering is deterministic even across a tie).
//
// On a cursor minted under a different filter set: incidents.go's list
// endpoint has to reject that outright (decodeIncidentSortCursor) because its
// `?sort=` changes which COLUMN and TYPE the keyset comparison is even
// over — a cursor minted under one sort is structurally meaningless under
// another. This endpoint has no such hazard to guard against: every filter
// this file adds (actor/capability/cluster/resource/outcome/since/until)
// narrows the WHERE clause only, never the ORDER BY, so the keyset
// comparison is always the same (occurred_at, id) pair regardless of which
// filters were active when the cursor was minted. Reusing a cursor after
// changing filters is well-defined here — "continue from this position in
// time under the new filters" — not silently wrong the way it would be for
// incidents.go's sort-keyed cursor. (The web client resets to page 1 on
// every filter change anyway — AuditLogPage.tsx's applyFilters — so this is
// about the API contract being sound, not something the shipped UI
// exercises.)
//
// Query params (all optional, ANDed together):
//   - actor: matches this tenant's actor_id exactly, OR a case-insensitive
//     substring of the actor's email/display name — free text an admin would
//     actually type ("who did this"), not required to be an exact ID.
//   - capability: exact match against the audit_events.capability column —
//     this schema's name for what an admin thinks of as "the action taken"
//     (mirrors authz.EffectiveGrant.Capability/audit.Event.Capability
//     elsewhere in this codebase; reusing that existing vocabulary here rather
//     than inventing a second name, "action", for the same concept).
//   - cluster: exact match against ae.cluster_id. Rows with a NULL
//     cluster_id (org-level events — see this file's doc comment) never
//     match a cluster filter, deliberately — see parseAuditEventFilters'
//     own comment on this param for why.
//   - resource: free text against the object this event was about, matched
//     either directly (details.objectKey) or through the incident the event
//     names (details.incidentId -> incidents.object_key). Events with
//     neither — most non-remediation, non-incident writes — have no
//     resource concept and are never matched. See parseAuditEventFilters'
//     own comment on this param for exactly what is and isn't covered, and
//     its cost with no cluster/time bound alongside it.
//   - outcome: exact match for success, denied, or error.
//   - since / until: RFC 3339 timestamps, inclusive, bounding occurred_at.
//   - limit: page size, 1..maxAuditEventLimit, default defaultAuditEventLimit.
//   - cursor: opaque keyset-pagination cursor from a previous response's
//     nextCursor — see encodeAuditCursor/decodeAuditCursor. Chosen over
//     limit/offset specifically because this table is append-only and can grow
//     unbounded in production (unlike e.g. the small `users` list) — an OFFSET
//     large enough to reach old rows would mean the database re-scanning and
//     discarding every row before it on every single page, an ever-growing
//     cost as the table grows; a keyset cursor's cost stays flat per page
//     regardless of table size or how deep the caller pages.
func (s *Server) handleListAuditEvents(w http.ResponseWriter, r *http.Request, rc *requestContext) {
	q := r.URL.Query()
	ctx := r.Context()

	limit := defaultAuditEventLimit
	if raw := q.Get("limit"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n <= 0 || n > maxAuditEventLimit {
			writeProblem(w, http.StatusBadRequest, "https://argus.io/errors/malformed-request",
				"Invalid limit", fmt.Sprintf("limit must be an integer between 1 and %d", maxAuditEventLimit))
			return
		}
		limit = n
	}

	whereSQL, args, _, _, ferr := parseAuditEventFilters(q)
	if ferr != nil {
		writeProblem(w, http.StatusBadRequest, "https://argus.io/errors/malformed-request", ferr.title, ferr.detail)
		return
	}
	query := auditEventBaseQuery + whereSQL

	if cursor := q.Get("cursor"); cursor != "" {
		cursorOccurredAt, cursorID, err := decodeAuditCursor(cursor)
		if err != nil {
			writeProblem(w, http.StatusBadRequest, "https://argus.io/errors/malformed-request",
				"Invalid cursor", "cursor is not a valid page-continuation token")
			return
		}
		args = append(args, cursorOccurredAt, cursorID)
		query += fmt.Sprintf(" AND (ae.occurred_at, ae.id) < ($%d, $%d)", len(args)-1, len(args))
	}

	args = append(args, limit)
	query += fmt.Sprintf(" ORDER BY ae.occurred_at DESC, ae.id DESC LIMIT $%d", len(args))

	rows, err := rc.Tx.Query(ctx, query, args...)
	if err != nil {
		logger.ErrorContext(ctx, "querying audit events failed", logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not list audit events", "")
		return
	}
	defer rows.Close()

	events := []auditEventSummary{}
	var lastOccurredAt time.Time
	var lastID string
	for rows.Next() {
		ev, occurredAt, err := scanAuditEventSummary(rows)
		if err != nil {
			logger.ErrorContext(ctx, "scanning an audit-event row failed", logging.Err(err))
			writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not list audit events", "")
			return
		}
		events = append(events, ev)
		lastOccurredAt, lastID = occurredAt, ev.ID
	}
	if err := rows.Err(); err != nil {
		logger.ErrorContext(ctx, "iterating the audit-event rows failed", logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not list audit events", "")
		return
	}

	resp := map[string]any{"auditEvents": events}
	// A full page might not be the last page — hand back a cursor so the
	// caller can ask for the next one. (Worst case if this table happens to
	// have exactly `limit` matching rows left: one extra request that comes
	// back empty — cheap, and simpler than a COUNT(*) or a limit+1 fetch just
	// to avoid it.)
	if len(events) == limit {
		resp["nextCursor"] = encodeAuditCursor(lastOccurredAt, lastID)
	}
	writeJSON(w, http.StatusOK, resp)
}

// scanAuditEventSummary scans one row shaped like auditEventBaseQuery's SELECT
// into an auditEventSummary, returning the row's raw occurred_at alongside it
// (needed at full, un-truncated precision for building a pagination cursor —
// auditEventSummary.OccurredAt itself is only second-precision, formatRFC3339's
// display format, which would corrupt keyset pagination across two rows that
// tie at that precision).
func scanAuditEventSummary(row pgx.Row) (auditEventSummary, time.Time, error) {
	var ev auditEventSummary
	var occurredAt time.Time
	var actorAuthMethod *string
	var detailsRaw []byte
	if err := row.Scan(&ev.ID, &occurredAt, &ev.ActorID, &ev.ActorEmail, &ev.ActorDisplayName,
		&actorAuthMethod, &ev.SourceIP, &ev.Capability, &ev.ClusterID, &ev.ClusterDisplayName,
		&ev.Outcome, &detailsRaw); err != nil {
		return auditEventSummary{}, time.Time{}, err
	}
	ev.OccurredAt = formatRFC3339(occurredAt)
	if actorAuthMethod != nil {
		ev.ActorAuthMethod = *actorAuthMethod
	}
	var details map[string]any
	if len(detailsRaw) > 0 {
		if err := json.Unmarshal(detailsRaw, &details); err != nil {
			return auditEventSummary{}, time.Time{}, fmt.Errorf("unmarshal details for row %s: %w", ev.ID, err)
		}
	}
	ev.Action = auditActionLabel(ev.Capability, details)
	ev.DetailsSummary = summarizeDetails(ev.Capability, details)
	return ev, occurredAt, nil
}

// handleGetAuditEvent is GET /api/v1/audit-events/{id}. Requires audit:read.
// The full-record counterpart to handleListAuditEvents' summary rows — see
// this file's doc comment for why the split exists.
func (s *Server) handleGetAuditEvent(w http.ResponseWriter, r *http.Request, rc *requestContext) {
	id := r.PathValue("id")

	row := rc.Tx.QueryRow(r.Context(), auditEventDetailQuery, id)

	ev, err := scanAuditEventDetailRow(row)
	if err != nil {
		if err == pgx.ErrNoRows {
			writeProblem(w, http.StatusNotFound, "https://argus.io/errors/not-found", "Audit event not found", "")
			return
		}
		logger.ErrorContext(r.Context(), "looking up the audit event failed", slog.String("audit_event_id", id), logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not look up audit event", "")
		return
	}

	writeJSON(w, http.StatusOK, ev)
}

// auditDetailRowScanner is satisfied by both pgx.Row (QueryRow, used by
// handleGetAuditEvent above) and pgx.Rows (Query, used by audit_export.go's
// streaming export, one row at a time via rows.Next()/rows.Scan()) — both
// expose Scan(dest ...any) error, and that's the only method either caller
// here needs, so a minimal shared interface is enough to let both reuse this
// one scan function rather than duplicating its field list and error
// handling.
type auditDetailRowScanner interface {
	Scan(dest ...any) error
}

// scanAuditEventDetailRow scans one row shaped like
// auditEventDetailBaseQuery's SELECT list (used by both auditEventDetailQuery
// and audit_export.go's export query) into an auditEventDetail, deriving
// Action/DetailsSummary the same way handleGetAuditEvent always has. Shared
// by handleGetAuditEvent and handleExportAuditEvents so the column order and
// the derivation logic can only go out of sync in one place, not two.
func scanAuditEventDetailRow(row auditDetailRowScanner) (auditEventDetail, error) {
	var ev auditEventDetail
	var occurredAt time.Time
	var actorAuthMethod *string
	var scopeRaw, detailsRaw []byte
	if err := row.Scan(&ev.ID, &occurredAt, &ev.ActorID, &ev.ActorEmail, &ev.ActorDisplayName,
		&actorAuthMethod, &ev.SourceIP, &ev.Capability, &scopeRaw, &ev.ClusterID, &ev.ClusterDisplayName,
		&ev.Outcome, &detailsRaw, &ev.PrevHash, &ev.Hash); err != nil {
		return auditEventDetail{}, err
	}

	ev.OccurredAt = formatRFC3339(occurredAt)
	if actorAuthMethod != nil {
		ev.ActorAuthMethod = *actorAuthMethod
	}
	if len(scopeRaw) > 0 {
		if err := json.Unmarshal(scopeRaw, &ev.Scope); err != nil {
			return auditEventDetail{}, fmt.Errorf("unmarshal scope for row %s: %w", ev.ID, err)
		}
	}
	if len(detailsRaw) > 0 {
		if err := json.Unmarshal(detailsRaw, &ev.Details); err != nil {
			return auditEventDetail{}, fmt.Errorf("unmarshal details for row %s: %w", ev.ID, err)
		}
	}
	ev.Action = auditActionLabel(ev.Capability, ev.Details)
	ev.DetailsSummary = summarizeDetails(ev.Capability, ev.Details)
	return ev, nil
}

// auditActionLabel is what the list's "Action" column shows.
//
// The two sources are genuinely different and neither alone is enough:
//
//   - `details.action` / `details.event` is the write path's own name for what it
//     did ("finding_suppressed_by_toleration", "reset_circuit_breaker"). Present on
//     system-raised events, which have no capability at all.
//   - `capability` is the permission a human exercised ("cluster:accept"). Present
//     on request-path events, many of which do not bother naming an action because
//     the capability already says it.
//
// Preferring the action and falling back to the capability means the column is
// populated for both kinds. Empty for the handful with neither — an enrollment
// attempt, a bare certificate issuance — where the client renders an em dash rather
// than this inventing a label the row does not support.
func auditActionLabel(capability *string, details map[string]any) string {
	if action, ok := details["action"].(string); ok && action != "" {
		return humanizeAuditToken(action)
	}
	if event, ok := details["event"].(string); ok && event != "" {
		return humanizeAuditToken(event)
	}
	if capability != nil {
		return *capability
	}
	return ""
}

// summarizeDetails renders a `details` blob (whose shape varies per write
// path — see this file's doc comment) into a short, generic "key=value,
// key=value" digest for list rows, sorted by key for determinism (map
// iteration order isn't). Never truncates mid-multi-byte-rune (splits on
// runes, not bytes). Empty/nil input returns "" rather than "{}" or similar —
// a row with no details at all (e.g. handleAcceptCluster's audit event) is
// common and should render as nothing, not a fake placeholder.
//
// Every value is rendered through formatDetailValue, never a bare
// fmt.Sprintf("%v", ...) — a `details` blob has round-tripped through
// json.Unmarshal into map[string]any by the time it reaches here (see
// scanAuditEventSummary/handleGetAuditEvent), so any value that was
// originally a nested struct/map (e.g. handleCreateUser's
// "initialGrantScope": authz.Scope{...}, or handleCreateGrant's "scope")
// comes back as a map[string]any, not a string. %v on a Go map renders as
// Go's own debug syntax (map[type:AllClusters]) — exactly the
// "random garbage" a live /api/v1/audit-events call surfaced — so any
// non-scalar value is marshaled to real JSON instead, e.g.
// {"type":"AllClusters"}, never map[type:AllClusters].
func summarizeDetails(capability *string, details map[string]any) string {
	if len(details) == 0 {
		return ""
	}
	// PUT /api/v1/admin/settings never sets details["action"]/["event"] (see
	// handlePutSettings), so without this it always fell through to the
	// generic dump below — a real, user-reported "weird text" complaint:
	// ten sorted camelCase booleans (analysisMaxIterationsChanged=false,
	// automationSectionProvided=true, ...) read as noise, not a summary.
	// Dispatched on the event's own real Capability column rather than
	// requiring every write path to also duplicate an "action" string
	// inside its own Details map just to be summarizable.
	if capability != nil && *capability == authz.CapOrgSettingsWrite {
		return summarizeSettingsWrite(details)
	}
	if action, ok := details["action"].(string); ok && action != "" {
		return summarizeActionDetails(action, details)
	}
	if event, ok := details["event"].(string); ok && event != "" {
		return summarizeActionDetails(event, details)
	}
	if _, ok := details["certSerial"]; ok && len(details) == 1 {
		return "Certificate issued"
	}
	// Same reasoning as certSerial above: handleEnroll's own audit event
	// (an unauthenticated agent presenting an enrollment token, so it has
	// no Capability to dispatch on) records the raw 64-character SHA-256
	// cluster_fingerprint as its entire Details map — a second real,
	// user-reported "weird text" complaint, since the generic fallback
	// below would otherwise show the whole hash inline
	// ("clusterFingerprint=c6c460b1...feab18"). The full value is still
	// available in the drill-down modal (GET /audit-events/{id}'s raw
	// `details`) for anyone who actually needs it.
	if _, ok := details["clusterFingerprint"]; ok && len(details) == 1 {
		return "Cluster enrollment attempted"
	}

	keys := make([]string, 0, len(details))
	for k := range details {
		if isNoisyAuditSummaryKey(k) {
			continue
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)
	if len(keys) == 0 {
		return ""
	}

	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s=%s", k, formatDetailValue(details[k])))
	}
	return truncateDetailsSummary(strings.Join(parts, ", "))
}

// settingsWriteSectionLabels maps each `*SectionProvided` detail key
// handlePutSettings' own audit Details map carries (internal/api/
// settings.go) to the human-readable section name shown in the summary —
// listed in the same order settings.go declares those fields, so multiple
// changed sections read in a stable, predictable order rather than
// whatever order a map/alphabetical sort of the raw camelCase keys would
// produce.
var settingsWriteSectionLabels = []struct {
	key   string
	label string
}{
	{"llmSectionProvided", "AI provider"},
	{"notifySectionProvided", "notifications"},
	{"analysisSectionProvided", "analysis bounds"},
	{"automationSectionProvided", "automatic investigation"},
	{"retentionSectionProvided", "retention"},
	{"detectionSectionProvided", "detection"},
	{"autonomySectionProvided", "autonomy policy"},
	{"costSectionProvided", "cost"},
}

// summarizeSettingsWrite turns PUT /api/v1/admin/settings' own audit
// Details — a flat set of `*SectionProvided`/`*Changed` booleans,
// deliberately recorded that way (rather than the actual new values) so a
// secret like the LLM API key is never written into the audit trail just
// to make a summary readable (see handlePutSettings' own Details map) —
// into a real human summary naming which sections were touched, instead of
// the generic fallback's raw, sorted key=value dump of all ten flags.
func summarizeSettingsWrite(details map[string]any) string {
	var sections []string
	for _, s := range settingsWriteSectionLabels {
		if changed, _ := details[s.key].(bool); changed {
			sections = append(sections, s.label)
		}
	}

	var sensitive []string
	if changed, _ := details["llmApiKeyChanged"].(bool); changed {
		sensitive = append(sensitive, "AI provider API key")
	}
	if changed, _ := details["notifyWebhookChanged"].(bool); changed {
		sensitive = append(sensitive, "notification webhook URL")
	}

	if len(sections) == 0 && len(sensitive) == 0 {
		return "Settings request accepted — no section changed"
	}

	summary := "Settings updated"
	if len(sections) > 0 {
		summary += ": " + strings.Join(sections, ", ")
	}
	if len(sensitive) > 0 {
		summary += " (" + strings.Join(sensitive, ", ") + ")"
	}
	return summary
}

func summarizeActionDetails(action string, details map[string]any) string {
	keys := make([]string, 0, len(details))
	for k := range details {
		if k == "action" || k == "event" || isNoisyAuditSummaryKey(k) {
			continue
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)

	parts := []string{humanizeAuditToken(action)}
	for _, k := range keys {
		v := formatDetailValue(details[k])
		// An empty value adds a key and says nothing: a real row reads
		// "Execute Remediation, error=, incidentId=..., stateNote=, ..." where
		// `error=` and `stateNote=` are the ordinary success case having
		// nothing to report. They cost the reader attention in a list whose
		// whole job is a glance, and they push genuinely informative keys past
		// the truncation point.
		//
		// This drops them from the SUMMARY only. The details blob is stored
		// untouched, so the drill-down still shows the empty key, and the
		// filters still match on it — which is what "record it always, even
		// the ordinary zero, so it is searchable" is actually protecting.
		// Nothing false is implied either way: an absent key in a digest is
		// not a claim that the field was absent.
		//
		// `false` and `0` format as "false" and "0", so they are kept — only a
		// genuinely empty rendering is dropped.
		if v == "" {
			continue
		}
		parts = append(parts, fmt.Sprintf("%s=%s", k, v))
	}
	return truncateDetailsSummary(strings.Join(parts, ", "))
}

func isNoisyAuditSummaryKey(key string) bool {
	switch key {
	case "certSerial":
		return true
	default:
		return false
	}
}

func truncateDetailsSummary(summary string) string {
	if runes := []rune(summary); len(runes) > detailsSummaryMaxRunes {
		summary = string(runes[:detailsSummaryMaxRunes]) + "…"
	}
	return summary
}

func humanizeAuditToken(token string) string {
	token = strings.TrimSpace(strings.ReplaceAll(token, "_", " "))
	token = strings.TrimSpace(strings.ReplaceAll(token, ".", " "))
	if token == "" {
		return ""
	}
	words := strings.Fields(token)
	for i, word := range words {
		if word == "" {
			continue
		}
		words[i] = strings.ToUpper(word[:1]) + word[1:]
	}
	return strings.Join(words, " ")
}

// formatDetailValue renders one `details`/`scope` value for human display.
// Scalars (string/float64/bool/nil — everything encoding/json ever produces
// for a JSON scalar) use their plain fmt.Sprintf("%v", ...) form, same as
// before: "usr_01m0..." stays "usr_01m0...", true stays "true". A
// map[string]any or []any — what a nested JSON object/array decodes into —
// is marshaled back to real JSON text instead (e.g. {"type":"AllClusters"}),
// so nested structure always reads as JSON, never as Go's fmt "%v" map/slice
// debug syntax (map[type:AllClusters], [1 2 3]). Falls back to %v only if
// json.Marshal itself errors, which given these inputs (already produced by
// a prior successful json.Unmarshal) should not happen in practice.
func formatDetailValue(v any) string {
	switch v.(type) {
	case map[string]any, []any:
		b, err := json.Marshal(v)
		if err != nil {
			return fmt.Sprintf("%v", v)
		}
		return string(b)
	default:
		return fmt.Sprintf("%v", v)
	}
}

// encodeAuditCursor/decodeAuditCursor implement handleListAuditEvents' keyset
// pagination token: base64(occurredAt in RFC3339Nano + "|" + id). Opaque to
// the caller by convention (treated as a black box, passed back verbatim as
// `?cursor=`), but not cryptographically sealed — there is nothing sensitive
// in an (occurred_at, id) pair a caller could otherwise already see in the
// same response, so no HMAC/signing is needed here, unlike e.g. the refresh
// token or approval-token formats elsewhere in this codebase that DO carry
// something worth protecting.
func encodeAuditCursor(occurredAt time.Time, id string) string {
	raw := occurredAt.UTC().Format(time.RFC3339Nano) + "|" + id
	return base64.RawURLEncoding.EncodeToString([]byte(raw))
}

func decodeAuditCursor(cursor string) (time.Time, string, error) {
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
