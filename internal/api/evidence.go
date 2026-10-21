package api

// The evidence an investigation actually gathered — both halves of migration
// 000037's mcp_tool_calls: the per-incident aggregate GET /incidents/{id}
// returns, and the insert the MCP listener makes while an investigation is
// still running. Since BACKLOG.md B2, also the `evidence` table (migration
// 000005, given a real writer/reader by 000069): persistEvidence writes one
// row per tool call an api-backend investigation's causal chain carries an
// EvidenceID for, and handleGetEvidence is GET
// /api/v1/incidents/{id}/evidence/{evId} (lld/11-ui-design.md §4) reading it
// back. The mcp_tool_calls aggregate above and the evidence rows below answer
// different questions on purpose — "how much work happened" (every backend,
// counts only) versus "what exactly did this one tool call see" (api backend
// only, full content) — and stay two mechanisms rather than merging into one,
// per mcp_tool_calls' own migration comment on why it holds no content.
//
// WHY BOTH LIVE HERE, in the HTTP-handler package, when one of them is not
// triggered by an HTTP request at all: this file is the single place that
// knows this table's row shape, exactly as PersistAnalysis (analyze.go) is the
// single place that knows an analyses row's shape even though its second
// caller is a background poller in another package. The write's real caller is
// cmd/hub's MCP wiring, which already imports this package. The alternatives
// were worse in specific ways rather than merely different:
//
//   - Putting the insert in internal/mcp would give that package a database
//     handle it has deliberately never had (see ObserveFunc's doc comment
//     there): it takes its side effects as injected functions precisely so its
//     own tests need no Postgres, and its whole security surface is easier to
//     audit for it.
//   - Putting it in cmd/hub would put SQL in main(), and would separate the
//     insert from the query that reads it — the two have to agree about
//     outcome's 'ok'/'error' spelling, and agreeing is easier when they are
//     twenty lines apart.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"

	"argus/internal/data"
	"argus/internal/domain"
	"argus/internal/llm"
	"argus/internal/logging"
)

// mcp_tool_calls.outcome's two values, matching migration 000037's CHECK
// constraint. Named rather than inlined because the writer and the aggregate
// reader below both depend on spelling them identically.
const (
	toolCallOutcomeOK    = "ok"
	toolCallOutcomeError = "error"
)

// maxToolCallErrorLen bounds what goes in the error column. A tool failure's
// text comes from the cluster's own API server via the tunnel and has no
// guaranteed size (an admission-webhook rejection can carry a whole manifest),
// and nothing reads this column except a human debugging one call — so the
// first 2KB is all of it that is ever useful, and an unbounded row on a hot
// path is a real cost for no benefit.
const maxToolCallErrorLen = 2000

// evidenceSummary is the compact, per-incident aggregate the incident detail
// response carries. Compact is the requirement, not a simplification: a
// per-call list would be dozens of rows of "describe_resource at 14:02:11"
// that no operator reads, whereas "14 tool calls — 5 events, 4 describe
// resource, …" answers the only question the UI is asking, which is whether
// there was real work behind the verdict.
//
// FailedCalls is counted separately and INCLUDED in TotalCalls rather than
// being carved out of it: a call that failed was still a question asked, and
// failures are frequently the informative part of an investigation (a
// get_logs against an already-restarted pod failing is why the model went
// looking at the owner chain). Reporting 13 of 14 succeeded is honest;
// reporting 13 and silently dropping one is not.
type evidenceSummary struct {
	TotalCalls  int            `json:"totalCalls"`
	FailedCalls int            `json:"failedCalls"`
	ByTool      map[string]int `json:"byTool"`
}

// toolCallGroup is one row of the GROUP BY (tool, outcome) aggregate — the
// seam between the SQL and the folding below.
//
// The database could have produced the whole evidenceSummary on its own with
// count(*) FILTER clauses, and that was rejected: the folding carries the two
// rules that actually need testing (failures counted separately, and zero
// recorded calls meaning "absent" rather than "0"), and a hermetic test suite
// (no Postgres in CI, by design — see .github/workflows/ci.yml) can only
// exercise them if they live in Go. Same split, for the same reason, as
// insights.go's fillDailyTrend.
type toolCallGroup struct {
	Tool    string
	Outcome string
	Count   int
}

// buildEvidenceSummary folds the grouped rows into the response shape.
//
// Returns nil — not an empty summary — when there is nothing recorded. This is
// the load-bearing case, not an edge case: every analysis produced before
// migration 000037 gathered real evidence that simply was not recorded, so
// rendering "0 tool calls" for one would state something false about an
// investigation that made thirteen. nil means "unknown", the caller omits the
// block entirely, and the UI keeps the same contract on its side.
func buildEvidenceSummary(groups []toolCallGroup) *evidenceSummary {
	summary := evidenceSummary{ByTool: map[string]int{}}
	for _, g := range groups {
		summary.ByTool[g.Tool] += g.Count
		summary.TotalCalls += g.Count
		if g.Outcome == toolCallOutcomeError {
			summary.FailedCalls += g.Count
		}
	}
	if summary.TotalCalls == 0 {
		return nil
	}
	return &summary
}

// getEvidenceSummary reads one incident's recorded MCP tool calls.
//
// Runs on the caller's request transaction, so it is scoped by the same RLS
// session variables (and therefore the same tenant, and the same
// app.accessible_cluster_ids narrowing) as the incident row it accompanies —
// no separate authorization decision to keep in sync. The route's existing
// incident:read gate is likewise the whole gate: this is a count of questions
// asked about one incident, strictly less revealing than the analysis text and
// the findings already on the same response, so a second capability would gate
// nothing that is not already visible.
func getEvidenceSummary(ctx context.Context, tx pgx.Tx, incidentID string) (*evidenceSummary, error) {
	rows, err := tx.Query(ctx,
		`SELECT tool, outcome, count(*)
		   FROM mcp_tool_calls
		  WHERE incident_id = $1
		  GROUP BY tool, outcome`, incidentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	groups := []toolCallGroup{}
	for rows.Next() {
		var g toolCallGroup
		if err := rows.Scan(&g.Tool, &g.Outcome, &g.Count); err != nil {
			return nil, err
		}
		groups = append(groups, g)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return buildEvidenceSummary(groups), nil
}

// txBeginner is the narrow slice of *pgxpool.Pool RecordMCPToolCall needs.
// Taken as an interface rather than a *data.DB for one concrete reason: it
// makes "the database is unavailable and this must still not break the
// investigation" a testable path in a suite that has no Postgres. Everything
// past Begin already works against pgx.Tx, which is itself an interface, so
// this adds no new abstraction layer — only a seam at the one place a test
// cannot otherwise reach.
type txBeginner interface {
	Begin(ctx context.Context) (pgx.Tx, error)
}

// RecordMCPToolCall persists one MCP tool call against its incident.
//
// Called from cmd/hub's mcp.RecordFunc wiring, once per call the hub actually
// dispatched to a cluster, while the investigation is still running. Exported
// for that reason (the callers of this package's other DB helpers are HTTP
// handlers in-package; this one is not).
//
// The contract that matters: an error returned here is for the caller to LOG,
// never to propagate. internal/mcp's RecordFunc cannot return one at all — the
// tool call has already succeeded or failed on its own merits by the time this
// runs, and an investigation that broke because bookkeeping broke would be a
// strictly worse outcome than an investigation with a gap in its evidence
// summary. That is also why nothing here retries: a lost row costs one line of
// a count, and retrying on the hot path would spend the investigation's own
// wall clock on it.
//
// Two deliberate details:
//
//   - The context is detached from the caller's with context.WithoutCancel.
//     The caller's context is the MCP request's, which is already cancelled in
//     exactly the case most worth recording: a tool call that failed because
//     the CLI hung up or the deadline expired. Recording is the last thing
//     that happens in that request, and the work being recorded is already
//     done, so inheriting the cancellation would drop precisely the failures
//     the summary should show. A short timeout of its own replaces it, so this
//     can never hold the response open on a wedged pool.
//   - tenant_id comes from data.SingleOrganisationID, the established
//     out-of-request pattern (gateway/health.go's sweep, orchestrator/
//     validation.go, notify/notifier.go): the MCP grant carries cluster and
//     incident but no tenant, and reading the tenant off the incident row
//     would need RLS scope already set, which needs the tenant. When real
//     multi-tenancy arrives, the tenant belongs in mcp.Grant (minted from the
//     session that started the investigation), and that is the change to make
//     then rather than a lookup that cannot be right yet.
func RecordMCPToolCall(ctx context.Context, pool txBeginner, clusterID, incidentID, tool string, dur time.Duration, callErr error) error {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()

	if incidentID == "" {
		// A grant with no incident cannot happen through
		// internal/llm.CLIInvestigator (it always mints per investigation),
		// but the token store only enforces a non-empty CLUSTER (mcp.Store's
		// Mint). Refused rather than stored against an empty string, which
		// would silently accumulate rows no incident page can ever show.
		return errors.New("refusing to record an MCP tool call with no incident id")
	}

	outcome := toolCallOutcomeOK
	var errText *string
	if callErr != nil {
		outcome = toolCallOutcomeError
		text := callErr.Error()
		if len(text) > maxToolCallErrorLen {
			text = text[:maxToolCallErrorLen]
		}
		errText = &text
	}

	tx, err := pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	tenantID, err := data.SingleOrganisationID(ctx, tx)
	if err != nil {
		return fmt.Errorf("resolve organisation: %w", err)
	}
	// The cluster is passed to SetRequestScope, not left empty: this write
	// genuinely concerns exactly one cluster, so it satisfies migration
	// 000037's restrictive cluster policy explicitly rather than by relying on
	// the "empty list means no narrowing" branch. Same choice
	// internal/gateway's per-cluster writes make.
	if err := data.SetRequestScope(ctx, tx, tenantID, []string{clusterID}); err != nil {
		return fmt.Errorf("set request scope: %w", err)
	}

	if _, err := tx.Exec(ctx,
		`INSERT INTO mcp_tool_calls (id, tenant_id, cluster_id, incident_id, tool, outcome, error, duration_ms, created_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, now())`,
		domain.NewID(domain.PrefixMCPToolCall), tenantID, clusterID, incidentID, tool, outcome, errText,
		dur.Milliseconds()); err != nil {
		return fmt.Errorf("insert mcp tool call: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit mcp tool call: %w", err)
	}
	return nil
}

// RecordMCPToolCallContent is PROJECT.md B151's writer, wired by cmd/hub as
// an mcp.RecordContentFunc — the content RecordMCPToolCall's own row
// deliberately never carries (see mcp_tool_calls' migration 000037). Written
// to a SEPARATE table (000099) rather than added as new columns on
// mcp_tool_calls itself, so that table's existing callers (the blast-radius
// budget, the circuit breaker) are byte-for-byte unaffected — they never
// query columns that do not exist for them.
//
// Same fail-safe posture as RecordMCPToolCall: errors are the caller's to log
// (see RecordContentFunc's own doc comment), a failed write here must never
// fail the tool call it describes, and args/result have already been
// redacted agent-side (argus-context non-negotiable 9) before this process
// ever saw them — this function adds no redaction of its own because none is
// needed, not because it was skipped.
func RecordMCPToolCallContent(ctx context.Context, pool txBeginner, clusterID, incidentID, tool string, args, result json.RawMessage, callErr error) error {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()

	if incidentID == "" {
		return errors.New("refusing to record MCP tool call content with no incident id")
	}

	outcome := toolCallOutcomeOK
	var errText *string
	var resultArg any = result
	if callErr != nil {
		outcome = toolCallOutcomeError
		text := callErr.Error()
		if len(text) > maxToolCallErrorLen {
			text = text[:maxToolCallErrorLen]
		}
		errText = &text
		resultArg = nil
	}
	if len(args) == 0 {
		args = json.RawMessage(`{}`)
	}

	tx, err := pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	tenantID, err := data.SingleOrganisationID(ctx, tx)
	if err != nil {
		return fmt.Errorf("resolve organisation: %w", err)
	}
	if err := data.SetRequestScope(ctx, tx, tenantID, []string{clusterID}); err != nil {
		return fmt.Errorf("set request scope: %w", err)
	}

	if _, err := tx.Exec(ctx,
		`INSERT INTO mcp_tool_call_content (id, tenant_id, cluster_id, incident_id, tool, outcome, args, result, error, created_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, now())`,
		domain.NewID(domain.PrefixMCPToolCallContent), tenantID, clusterID, incidentID, tool, outcome, args, resultArg, errText); err != nil {
		return fmt.Errorf("insert mcp tool call content: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit mcp tool call content: %w", err)
	}
	return nil
}

// ListMCPToolCalls reads every MCP tool call the hub actually recorded
// serving for one incident — the same mcp_tool_calls rows getEvidenceSummary
// aggregates above, at per-row (tool, outcome) granularity instead of
// grouped counts, LEFT JOINed against mcp_tool_call_content's real
// args/result (PROJECT.md B151) for the same (incident, tool) pair. This is
// BACKLOG.md C10's cross-check ledger: wired by cmd/hub as an
// llm.ToolCallLedger, it lets the cli backend verify a self-reported causal
// chain against calls the hub actually served, without internal/llm ever
// importing this package or a database driver — the same seam
// RecordMCPToolCall/RecordMCPToolCallContent cross in the opposite direction
// (writing a call rather than reading them back).
//
// # Why a positional join rather than a shared id
//
// mcp_tool_calls and mcp_tool_call_content are two independent inserts, at
// two independent call sites in the SAME handleToolCall invocation
// (internal/mcp/server.go) — there is no FK between them, deliberately
// (mcp_tool_calls' own migration explains why that table carries none to
// anything). Matched here by ROW_NUMBER() PARTITION BY tool ORDER BY
// created_at on each side, joined position-for-position within each tool
// name — the two writes happen back-to-back for the same call, so the Nth
// mcp_tool_calls row for a tool and the Nth mcp_tool_call_content row for
// that same tool describe the same real call, in practice. If either write
// ever fails independently (both log their own failure and never fail the
// tool call — see each Func's own doc comment) the LEFT JOIN simply yields
// no content for that position onward rather than mismatching it to the
// wrong call: crossCheckCausalChain's value-agreement check treats missing
// content as "unchecked", never as a false match.
//
// Scoped exactly like the writers: a fresh, out-of-request transaction with
// RLS scope set to this one cluster (data.SingleOrganisationID +
// SetRequestScope), so a lost race on tenant resolution fails closed — an
// error, not silently zero rows or another cluster's rows — rather than
// trusting a caller-supplied scope. Ordered by created_at so a chain that
// describes its tool calls in the order it made them lines up with the order
// they were actually served, though crossCheckCausalChain's own matching
// does not depend on that order (it matches per tool name, not position).
func ListMCPToolCalls(ctx context.Context, pool txBeginner, clusterID, incidentID string) ([]llm.RecordedToolCall, error) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()

	if clusterID == "" || incidentID == "" {
		return nil, errors.New("refusing to list MCP tool calls with no cluster or incident id")
	}

	tx, err := pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin transaction: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	tenantID, err := data.SingleOrganisationID(ctx, tx)
	if err != nil {
		return nil, fmt.Errorf("resolve organisation: %w", err)
	}
	if err := data.SetRequestScope(ctx, tx, tenantID, []string{clusterID}); err != nil {
		return nil, fmt.Errorf("set request scope: %w", err)
	}

	rows, err := tx.Query(ctx,
		`WITH counts AS (
		   SELECT tool, outcome, created_at,
		          row_number() OVER (PARTITION BY tool ORDER BY created_at) AS rn
		     FROM mcp_tool_calls
		    WHERE incident_id = $1
		 ), content AS (
		   SELECT tool, args, result,
		          row_number() OVER (PARTITION BY tool ORDER BY created_at) AS rn
		     FROM mcp_tool_call_content
		    WHERE incident_id = $1
		 )
		 SELECT c.tool, c.outcome, ct.args, ct.result
		   FROM counts c
		   LEFT JOIN content ct ON ct.tool = c.tool AND ct.rn = c.rn
		  ORDER BY c.created_at`, incidentID)
	if err != nil {
		return nil, fmt.Errorf("query mcp tool calls: %w", err)
	}
	defer rows.Close()

	calls := []llm.RecordedToolCall{}
	for rows.Next() {
		var c llm.RecordedToolCall
		if err := rows.Scan(&c.Tool, &c.Outcome, &c.Args, &c.Result); err != nil {
			return nil, fmt.Errorf("scan mcp tool call: %w", err)
		}
		calls = append(calls, c)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit: %w", err)
	}
	return calls, nil
}

// evidenceKindToolCall is the only `evidence.kind` value this codebase writes
// today. Left as an open text column rather than a CHECK-constrained enum
// (matching the table's original migration 000005 design) because
// lld/05-data-model.md's broader evidence taxonomy — a log excerpt distinct
// from the tool call that fetched it, a diff, a manifest snapshot — is wider
// than BACKLOG.md B2 scopes this pass to; a future kind is a new value, not a
// migration.
const evidenceKindToolCall = "tool_call"

// maxEvidenceErrorLen bounds evidence.error exactly like maxToolCallErrorLen
// bounds mcp_tool_calls.error above, for the same reason: a tool failure's
// text is free-form text from the cluster's own API server (an
// admission-webhook rejection can carry a whole manifest) with no guaranteed
// size, and nothing reads this column except a human drilling into one call.
const maxEvidenceErrorLen = 2000

// persistEvidence writes one `evidence` row (migration 000069) per tool call
// causalChain carries a non-empty EvidenceID for — every call the api-backend
// investigation loop actually dispatched to a cluster, success or failure
// (llm.ToolCallRecord's own doc comment explains why a refused call has no
// EvidenceID and is skipped here). Called from PersistAnalysis, inside the
// SAME transaction as the analyses insert, so an evidence row and the
// analysis it belongs to either both commit or neither does.
//
// THE SAFETY PROPERTY THIS FUNCTION DEPENDS ON, STATED EXPLICITLY: args/
// result/error here are call.Args/call.Result/call.Error exactly as
// llm's investigate() received them from the ToolCallback it was given
// (internal/api/analyze.go's callTool closure, i.e. s.gw.CallTool) — the
// SAME bytes that already went into analyses.causal_chain, which
// BUGS.md 84 verified are the tunnel's already-redacted output
// (internal/redact's agent-side chokepoints, ToolExecutor.Execute for every
// tool). This function does no second fetch, calls no cluster, and reads no
// path other than the causalChain value its caller already has in hand — so
// it cannot introduce a route to pre-redaction data even by accident: there
// is no OTHER data available to it that redaction has not already run on.
// The `redacted` column is set true unconditionally below to record that
// fact, not to assert it independently of the write path that makes it true.
func persistEvidence(ctx context.Context, tx pgx.Tx, tenantID, clusterID, incidentID, analysisID string, causalChain []llm.CausalStep) error {
	for _, step := range causalChain {
		for _, call := range step.ToolCalls {
			if call.EvidenceID == "" {
				// Refused-tool-call case (isOfferedTool was false): nothing was
				// dispatched, so there is nothing a cluster answered to record —
				// see ToolCallRecord's own doc comment.
				continue
			}

			args := call.Args
			if len(args) == 0 {
				args = json.RawMessage(`{}`)
			}

			outcome := toolCallOutcomeOK
			var result json.RawMessage
			var errText *string
			if call.Error != nil {
				outcome = toolCallOutcomeError
				text := *call.Error
				if len(text) > maxEvidenceErrorLen {
					text = text[:maxEvidenceErrorLen]
				}
				errText = &text
			} else {
				result = call.Result
				if len(result) == 0 {
					result = json.RawMessage(`null`)
				}
			}

			sizeBytes := len(args) + len(result)
			if errText != nil {
				sizeBytes += len(*errText)
			}

			if _, err := tx.Exec(ctx,
				`INSERT INTO evidence (
				   id, analysis_id, tenant_id, cluster_id, incident_id, kind, tool, outcome,
				   args, result, error, size_bytes, redacted, captured_at
				 ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, now())`,
				call.EvidenceID, analysisID, tenantID, clusterID, incidentID, evidenceKindToolCall, call.Tool, outcome,
				args, nullIfEmptyRaw(result), errText, sizeBytes, true); err != nil {
				return fmt.Errorf("insert evidence %s: %w", call.EvidenceID, err)
			}
		}
	}
	return nil
}

// nullIfEmptyRaw is nullIfEmpty's json.RawMessage counterpart: a nil/empty
// raw message is passed to pgx as untyped nil so the jsonb column gets a real
// SQL NULL rather than attempting to store zero bytes as invalid JSON.
func nullIfEmptyRaw(raw json.RawMessage) any {
	if len(raw) == 0 {
		return nil
	}
	return raw
}

// handleGetEvidence is GET /api/v1/incidents/{id}/evidence/{evId}
// (lld/11-ui-design.md §4, BACKLOG.md B2). Requires incident:read — the same,
// and only, gate GET /incidents/{id} itself applies, and deliberately no
// stricter: everything this endpoint can return (one tool call's own
// args/result/error) is already visible in full, inline, in that same
// incident's analysis.causalChain (llm.ToolCallRecord) to anyone who already
// holds incident:read — matching getEvidenceSummary's own reasoning just
// above. This is the lazy-fetch half of that same data, not a new exposure.
//
// RLS (migration 000069) is what actually enforces that the caller's
// tenant/cluster scope covers this row at all; the `incident_id = $2` in the
// query below is a SEPARATE, additional check on top of that, not a
// replacement for it — it is what turns "right cluster, wrong incident" (an
// evidence id that is real and belongs to a cluster this caller can read, but
// to a DIFFERENT incident on it) into the same 404 a stolen id from a cluster
// outside the caller's scope already gets from RLS, rather than quietly
// serving one incident's tool-call content through another incident's URL.
func (s *Server) handleGetEvidence(w http.ResponseWriter, r *http.Request, rc *requestContext) {
	incidentID := r.PathValue("id")
	evidenceID := r.PathValue("evId")
	ctx := r.Context()

	var (
		tool       string
		outcome    string
		args       []byte
		result     []byte
		errText    *string
		redacted   bool
		capturedAt time.Time
	)
	err := rc.Tx.QueryRow(ctx,
		`SELECT tool, outcome, args, result, error, redacted, captured_at
		   FROM evidence
		  WHERE id = $1 AND incident_id = $2`,
		evidenceID, incidentID,
	).Scan(&tool, &outcome, &args, &result, &errText, &redacted, &capturedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			writeProblem(w, http.StatusNotFound, "https://argus.io/errors/not-found", "Evidence not found", "")
			return
		}
		logger.ErrorContext(ctx, "looking up the evidence record failed",
			logging.IncidentID(incidentID), slog.String("evidence_id", evidenceID), logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not look up evidence", "")
		return
	}

	resp := map[string]any{
		"id":         evidenceID,
		"incidentId": incidentID,
		"tool":       tool,
		"outcome":    outcome,
		"args":       json.RawMessage(args),
		// Always true today (persistEvidence sets it unconditionally), carried
		// on the wire anyway rather than assumed client-side: a future evidence
		// kind that is NOT redaction-eligible (BACKLOG.md B2's own warning about
		// the pattern layer being best-effort) should be able to say so without
		// a contract change on this endpoint.
		"redacted":   redacted,
		"capturedAt": capturedAt.UTC().Format(time.RFC3339),
	}
	if result != nil {
		resp["result"] = json.RawMessage(result)
	}
	if errText != nil {
		resp["error"] = *errText
	}
	writeJSON(w, http.StatusOK, resp)
}
