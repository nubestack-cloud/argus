package api

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"argus/internal/logging"
)

// This file implements GET /api/v1/audit-events/export — BACKLOG.md S3's
// "audit export" slice, the only piece of that grab-bag item this task
// builds. It is a third way to read audit_events (audit.go's
// handleListAuditEvents/handleGetAuditEvent are the other two): CSV or JSON,
// meant as one bulk file rather than a page at a time. Read-only, same as
// the rest of this table's surface — no route anywhere writes to
// audit_events.
//
// Reuses audit.go's parseAuditEventFilters (actor/capability/outcome/
// since/until — see handleListAuditEvents' doc comment for what each one
// means) and scanAuditEventDetailRow, rather than duplicating either.
//
// Requires audit:read (authz.CapAuditRead) — the SAME capability as the list
// and single-record endpoints, not a new one. An export is not a more
// sensitive OPERATION than reading the same rows one page at a time; it's a
// bulk-shaped way to read rows the caller could already read. audit:read is
// already org-only and super-admin-only (permissions.go's orgOnlyCapabilities
// and builtinRoleCapabilities, per lld/02-authz-spec.md §5's explicit note
// excluding tenant-admin) — exactly the audience an audit-log export should
// have, so there is nothing a second capability would gate that this one
// doesn't already.
const (
	// maxAuditEventExportRangeDays bounds the [since, until] window one
	// export request can cover. handleListAuditEvents is safe unbounded
	// because keyset pagination makes every page cost the same regardless of
	// how large the table is; an export has no page boundary of its own — it
	// is meant to be one complete file — so the bound has to come from the
	// request itself, checked before any query runs. 92 days (one quarter) is
	// picked as a plausible compliance/GRC export cadence, not derived from
	// any measured data.
	maxAuditEventExportRangeDays = 92

	// auditEventExportRowCap is a defense-in-depth backstop, NOT the primary
	// bound (that's maxAuditEventExportRangeDays above, enforced before this
	// query ever runs) — a plain SQL LIMIT so that even a pathological
	// within-range audit volume for one tenant can't turn a single export
	// request into an unbounded scan/stream. audit.go's own doc comment
	// describes this table's real per-event volume as "a handful of short
	// key/value pairs" per write path across logins, settings writes,
	// approvals, etc. — ordinary usage should never come close to this.
	auditEventExportRowCap = 500_000
)

// auditExportRow is the flattened shape one exported row takes in EITHER
// format — CSV columns and JSON object keys are the same fields, in the same
// order, so a caller diffing a CSV export against a JSON export of the same
// filters sees the same information either way.
//
// Column choice: every field of auditEventDetail (audit.go) is carried
// through, including the raw `details`/`scope` JSON blobs (each serialized
// to one text field, not flattened into per-key columns) and the hash-chain
// fields (prevHash/hash). This is a deliberate departure from
// handleListAuditEvents' summary shape, which deliberately DROPS the raw
// `details` blob in favor of a short digest (see auditEventSummary's doc
// comment) because that endpoint is an interactive, many-rows-on-screen list.
// An export's whole purpose is a complete, durable record — an auditor or a
// GRC tool consuming this file needs the full structured `details` an
// incident review might need later (e.g. exactly which settings section
// changed, which grant scope was created), and dropping it here would defeat
// the reason to export at all. Flattening specific well-known `details` keys
// into their own columns was considered and rejected: this table's write
// paths use genuinely different `details` shapes (see audit.go's own doc
// comment — settings writes, cluster accept, login denial, enrollment, etc.
// each set different keys), so a fixed set of flattened columns would be
// empty for most rows regardless of which keys were chosen, while a single
// JSON-text column loses nothing and needs no per-write-path maintenance as
// new ones are added. detailsSummary (the same human-readable digest the
// list view already computes) is included alongside the raw blob rather than
// instead of it, since it's cheap and saves a reader from having to parse
// JSON just to skim what happened.
type auditExportRow struct {
	ID                 string
	OccurredAt         string
	ActorID            string
	ActorEmail         string
	ActorDisplayName   string
	ActorAuthMethod    string
	SourceIP           string
	Capability         string
	Scope              string // raw `scope` JSON, serialized; "" if null
	ClusterID          string
	ClusterDisplayName string
	Outcome            string
	Action             string
	DetailsSummary     string
	Details            string // raw `details` JSON, serialized; "" if null
	PrevHash           string
	Hash               string
}

// auditExportColumns is the CSV header row and, in the same order, the field
// order auditExportRow.values() below produces — one place naming and
// ordering every exported column, so the header and the data can't drift
// apart.
var auditExportColumns = []string{
	"id", "occurredAt", "actorId", "actorEmail", "actorDisplayName",
	"actorAuthMethod", "sourceIp", "capability", "scope", "clusterId",
	"clusterDisplayName", "outcome", "action", "detailsSummary", "details",
	"prevHash", "hash",
}

func (row auditExportRow) values() []string {
	return []string{
		row.ID, row.OccurredAt, row.ActorID, row.ActorEmail, row.ActorDisplayName,
		row.ActorAuthMethod, row.SourceIP, row.Capability, row.Scope, row.ClusterID,
		row.ClusterDisplayName, row.Outcome, row.Action, row.DetailsSummary, row.Details,
		row.PrevHash, row.Hash,
	}
}

// toAuditExportRow flattens an auditEventDetail (audit.go's full-record
// shape, also used by handleGetAuditEvent) into the export shape: pointer
// fields become "" when nil/absent (a login failure has no actor; most rows
// have no cluster — see audit.go's doc comment), and the two JSON blobs are
// re-marshaled to compact text (never Go's %v map syntax — the exact bug
// audit.go's formatDetailValue was already written to avoid, so this reuses
// the same approach rather than reinventing it).
func toAuditExportRow(ev auditEventDetail) (auditExportRow, error) {
	row := auditExportRow{
		ID:              ev.ID,
		OccurredAt:      ev.OccurredAt,
		ActorAuthMethod: ev.ActorAuthMethod,
		Outcome:         ev.Outcome,
		Action:          ev.Action,
		DetailsSummary:  ev.DetailsSummary,
		PrevHash:        ev.PrevHash,
		Hash:            ev.Hash,
	}
	if ev.ActorID != nil {
		row.ActorID = *ev.ActorID
	}
	if ev.ActorEmail != nil {
		row.ActorEmail = *ev.ActorEmail
	}
	if ev.ActorDisplayName != nil {
		row.ActorDisplayName = *ev.ActorDisplayName
	}
	if ev.SourceIP != nil {
		row.SourceIP = *ev.SourceIP
	}
	if ev.Capability != nil {
		row.Capability = *ev.Capability
	}
	if ev.ClusterID != nil {
		row.ClusterID = *ev.ClusterID
	}
	if ev.ClusterDisplayName != nil {
		row.ClusterDisplayName = *ev.ClusterDisplayName
	}
	if len(ev.Scope) > 0 {
		b, err := json.Marshal(ev.Scope)
		if err != nil {
			return auditExportRow{}, fmt.Errorf("marshal scope for row %s: %w", ev.ID, err)
		}
		row.Scope = string(b)
	}
	if len(ev.Details) > 0 {
		b, err := json.Marshal(ev.Details)
		if err != nil {
			return auditExportRow{}, fmt.Errorf("marshal details for row %s: %w", ev.ID, err)
		}
		row.Details = string(b)
	}
	return row, nil
}

// handleExportAuditEvents is GET /api/v1/audit-events/export. Requires
// audit:read — see this file's doc comment.
//
// Query params:
//   - format: "csv" or "json". Optional, default "json" — matching how most
//     of this API's list endpoints already respond by default; CSV is the
//     explicit opt-in (?format=csv), since that shape exists for spreadsheet/
//     GRC tooling outside this codebase, not for anything inside it.
//   - actor / capability / outcome: same as handleListAuditEvents (audit.go),
//     via the shared parseAuditEventFilters.
//   - since / until: same RFC 3339 timestamps as handleListAuditEvents, but
//     BOTH ARE REQUIRED here (handleListAuditEvents leaves them optional),
//     and until-since must not exceed maxAuditEventExportRangeDays — see that
//     constant's doc comment for why an export needs this bound where the
//     paginated list endpoint does not.
//
// Streams its response rather than materializing it: rows are written to w
// as they are scanned off the wire (one auditEventDetail at a time via
// rows.Next()/scanAuditEventDetailRow), never collected into a slice first,
// so this handler's own memory use stays flat regardless of how many rows
// the requested range covers. The known, deliberate limitation that comes
// with streaming: once the first byte is written, the response is
// committed to a 200 — a scan or write failure partway through can only be
// logged server-side and end the stream early (the client sees a truncated
// body, not a clean error), never rewritten into an RFC 9457 error response.
// That's an accepted trade for not buffering a potentially large export in
// memory, not an oversight; auditEventExportRowCap above (checked as a SQL
// LIMIT before any output is written) is what keeps "partway through" bounded
// rather than open-ended.
func (s *Server) handleExportAuditEvents(w http.ResponseWriter, r *http.Request, rc *requestContext) {
	q := r.URL.Query()
	ctx := r.Context()

	format := q.Get("format")
	if format == "" {
		format = "json"
	}
	if format != "json" && format != "csv" {
		writeProblem(w, http.StatusBadRequest, "https://argus.io/errors/malformed-request",
			"Invalid format", `format must be "json" or "csv"`)
		return
	}

	whereSQL, args, since, until, ferr := parseAuditEventFilters(q)
	if ferr != nil {
		writeProblem(w, http.StatusBadRequest, "https://argus.io/errors/malformed-request", ferr.title, ferr.detail)
		return
	}
	if since == nil || until == nil {
		writeProblem(w, http.StatusBadRequest, "https://argus.io/errors/malformed-request",
			"since and until are required",
			"audit export must be bounded by both ?since= and ?until= (RFC 3339 timestamps), each at most "+
				fmt.Sprintf("%d days apart", maxAuditEventExportRangeDays))
		return
	}
	if until.Before(*since) {
		writeProblem(w, http.StatusBadRequest, "https://argus.io/errors/malformed-request",
			"Invalid range", "until must not be before since")
		return
	}
	if until.Sub(*since) > maxAuditEventExportRangeDays*24*time.Hour {
		writeProblem(w, http.StatusBadRequest, "https://argus.io/errors/malformed-request",
			"Range too large",
			fmt.Sprintf("the since/until range must not exceed %d days; narrow it and export in multiple requests", maxAuditEventExportRangeDays))
		return
	}

	args = append(args, auditEventExportRowCap)
	query := auditEventDetailBaseQuery + whereSQL + fmt.Sprintf(" ORDER BY ae.occurred_at ASC, ae.id ASC LIMIT $%d", len(args))

	rows, err := rc.Tx.Query(ctx, query, args...)
	if err != nil {
		logger.ErrorContext(ctx, "querying audit events for export failed", logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not export audit events", "")
		return
	}
	defer rows.Close()

	filenameStamp := fmt.Sprintf("%s_%s", since.UTC().Format("20060102T150405Z"), until.UTC().Format("20060102T150405Z"))

	if format == "csv" {
		streamAuditEventsCSV(ctx, w, rows, filenameStamp)
		return
	}
	streamAuditEventsJSON(ctx, w, rows, filenameStamp)
}

// streamAuditEventsCSV writes the CSV response header, then one row at a
// time as rows is walked — see handleExportAuditEvents' doc comment for why
// a mid-stream failure can only be logged, not turned into an error
// response.
func streamAuditEventsCSV(ctx context.Context, w http.ResponseWriter, rows pgxRowsScanner, filenameStamp string) {
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="audit-events_%s.csv"`, filenameStamp))
	w.WriteHeader(http.StatusOK)

	cw := csv.NewWriter(w)
	if err := cw.Write(auditExportColumns); err != nil {
		logger.ErrorContext(ctx, "writing the audit-event CSV header failed", logging.Err(err))
		return
	}
	for rows.Next() {
		ev, err := scanAuditEventDetailRow(rows)
		if err != nil {
			logger.ErrorContext(ctx, "scanning an audit-event row for a CSV export failed", logging.Err(err))
			return
		}
		row, err := toAuditExportRow(ev)
		if err != nil {
			logger.ErrorContext(ctx, "flattening an audit-event row for a CSV export failed", logging.Err(err))
			return
		}
		if err := cw.Write(row.values()); err != nil {
			logger.ErrorContext(ctx, "writing an audit-event CSV row failed", logging.Err(err))
			return
		}
	}
	if err := rows.Err(); err != nil {
		logger.ErrorContext(ctx, "iterating the audit-event rows during a CSV export failed", logging.Err(err))
		return
	}
	cw.Flush()
	if err := cw.Error(); err != nil {
		logger.ErrorContext(ctx, "flushing the audit-event CSV export failed", logging.Err(err))
	}
}

// streamAuditEventsJSON writes the JSON response as a streamed array — "[",
// one json.Marshal'd auditExportRow per iteration (comma-separated), then
// "]" — rather than json.Marshal-ing a fully collected slice, for the same
// flat-memory reason the CSV path streams (see handleExportAuditEvents' doc
// comment). Emits fields as a plain object (map key order isn't guaranteed,
// so a struct is used instead) matching auditExportColumns' naming.
func streamAuditEventsJSON(ctx context.Context, w http.ResponseWriter, rows pgxRowsScanner, filenameStamp string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="audit-events_%s.json"`, filenameStamp))
	w.WriteHeader(http.StatusOK)

	if _, err := w.Write([]byte("[")); err != nil {
		return
	}
	enc := json.NewEncoder(w)
	first := true
	for rows.Next() {
		ev, err := scanAuditEventDetailRow(rows)
		if err != nil {
			logger.ErrorContext(ctx, "scanning an audit-event row for a JSON export failed", logging.Err(err))
			return
		}
		row, err := toAuditExportRow(ev)
		if err != nil {
			logger.ErrorContext(ctx, "flattening an audit-event row for a JSON export failed", logging.Err(err))
			return
		}
		if !first {
			if _, err := w.Write([]byte(",")); err != nil {
				return
			}
		}
		first = false
		if err := enc.Encode(auditExportJSONRow{
			ID: row.ID, OccurredAt: row.OccurredAt, ActorID: row.ActorID, ActorEmail: row.ActorEmail,
			ActorDisplayName: row.ActorDisplayName, ActorAuthMethod: row.ActorAuthMethod, SourceIP: row.SourceIP,
			Capability: row.Capability, Scope: row.Scope, ClusterID: row.ClusterID,
			ClusterDisplayName: row.ClusterDisplayName, Outcome: row.Outcome, Action: row.Action,
			DetailsSummary: row.DetailsSummary, Details: row.Details, PrevHash: row.PrevHash, Hash: row.Hash,
		}); err != nil {
			logger.ErrorContext(ctx, "encoding an audit event as JSON failed", logging.Err(err))
			return
		}
	}
	if err := rows.Err(); err != nil {
		logger.ErrorContext(ctx, "iterating the audit-event rows during a JSON export failed", logging.Err(err))
	}
	_, _ = w.Write([]byte("]"))
}

// auditExportJSONRow is auditExportRow's JSON encoding — a separate type
// (rather than json tags on auditExportRow itself) only because
// auditExportRow's field order also drives the CSV column order via
// values(), and Go struct literals in that function are positional;
// keeping the JSON-tagged copy separate means a future CSV column reorder
// can't silently reorder JSON keys it wasn't meant to touch.
type auditExportJSONRow struct {
	ID                 string `json:"id"`
	OccurredAt         string `json:"occurredAt"`
	ActorID            string `json:"actorId"`
	ActorEmail         string `json:"actorEmail"`
	ActorDisplayName   string `json:"actorDisplayName"`
	ActorAuthMethod    string `json:"actorAuthMethod"`
	SourceIP           string `json:"sourceIp"`
	Capability         string `json:"capability"`
	Scope              string `json:"scope"`
	ClusterID          string `json:"clusterId"`
	ClusterDisplayName string `json:"clusterDisplayName"`
	Outcome            string `json:"outcome"`
	Action             string `json:"action"`
	DetailsSummary     string `json:"detailsSummary"`
	Details            string `json:"details"`
	PrevHash           string `json:"prevHash"`
	Hash               string `json:"hash"`
}

// pgxRowsScanner is the subset of pgx.Rows the two streaming functions above
// need (Next/Err plus Scan via auditDetailRowScanner, audit.go) — named here
// so those functions don't have to import pgx just to spell out pgx.Rows.
type pgxRowsScanner interface {
	auditDetailRowScanner
	Next() bool
	Err() error
}
