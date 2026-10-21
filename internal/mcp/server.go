package mcp

// The hub's MCP server — the inbound half of lld/01-threat-model.md's B12
// boundary, and the piece that makes lld/14-adrs.md ADR-17's inversion real:
// for a CLI-agent backend, ARGUS is the MCP *server* and the CLI is the host,
// the exact opposite of the api backend's arrangement (where ARGUS is the MCP
// host per DESIGN.md §8.6).
//
// Speaks MCP over HTTP with JSON-RPC 2.0 framing, handling the three methods
// a tool-only server needs: initialize, tools/list, tools/call. Notifications
// (a request with no id, e.g. notifications/initialized) are accepted and
// answered with 202 and no body, per JSON-RPC's own rule that notifications
// get no response.
//
// Mounted on its own listener, never the public API listener — see
// lld/12-deployment-design.md §12.6. This file does not enforce that (a
// package cannot know which listener it was mounted on); cmd/hub does, and
// the requirement is restated at the mount site.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"argus/internal/logging"
)

// logger is internal/mcp's package-local structured logger (PROJECT.md T22).
var logger = logging.For("mcp")

// Protocol versions this server implements, newest first. MCP negotiates by
// string: a client asking for one of these gets it echoed back, and a client
// asking for anything else gets the newest — declaring what we actually speak
// is more useful than echoing an unknown request back and pretending to match
// it.
//
// All three are listed because this server's surface (tools only, JSON
// responses to POSTed JSON-RPC, no batching, no server-initiated messages) is
// wire-identical across them: 2025-03-26 introduced the Streamable HTTP
// transport this already is (a POST answered with application/json is one of
// its two permitted response shapes, and GET may be refused with 405), and
// 2025-06-18 removed JSON-RPC batching, which this server never accepted.
// Current MCP clients (Claude Code, Cursor, VS Code) ask for the newest; the
// CLI runner's pinned claude binary may ask for the oldest.
var supportedProtocolVersions = []string{"2025-06-18", "2025-03-26", "2024-11-05"}

// negotiateProtocolVersion picks the version to answer initialize with.
func negotiateProtocolVersion(params json.RawMessage) string {
	var p struct {
		ProtocolVersion string `json:"protocolVersion"`
	}
	_ = json.Unmarshal(params, &p)
	for _, v := range supportedProtocolVersions {
		if v == p.ProtocolVersion {
			return v
		}
	}
	return supportedProtocolVersions[0]
}

// JSON-RPC 2.0 error codes used here. Only the standard ones, plus a single
// application code for authorization failures.
const (
	codeParseError     = -32700
	codeInvalidRequest = -32600
	codeMethodNotFound = -32601
	codeInvalidParams  = -32602
	codeInternalError  = -32603
	// codeUnauthorized is application-defined (JSON-RPC reserves only
	// -32768..-32000 for itself).
	codeUnauthorized = -31001
)

// ToolFunc executes one tool for one grant. Passed in rather than imported so
// this package stays independent of both the tunnel layer and internal/api.
//
// It takes the whole GRANT rather than a bare cluster id — changed for
// BACKLOG.md F22, which added the first tools not served by a cluster agent at
// all. The repository tools are scoped to an INCIDENT (its object's GitOps
// ownership decides which repository, at which commit, under which directory),
// and cmd/hub's implementation dispatches on the tool name to either the tunnel
// or the hub-side repository reader. Handing over the grant rather than
// widening the parameter list keeps the rule intact that everything a tool call
// is scoped to comes from the token, and nothing from the request payload.
type ToolFunc func(ctx context.Context, grant Grant, tool string, args json.RawMessage) (json.RawMessage, error)

// ObserveFunc is called once per attempted tool call, successful or not. The
// hub wires this to a real audit write (lld/07-analysis-contracts.md §10.4
// requires every tool call over this boundary to be audited identically to
// the api path); it is a function rather than a hard dependency on
// internal/audit so this package needs no database handle.
//
// Called after the attempt completes, never in place of it, and its own errors
// are the caller's problem to log — a failed audit write must not silently
// convert into a failed tool call, nor vice versa.
type ObserveFunc func(ctx context.Context, grant Grant, tool string, args json.RawMessage, err error)

// RecordFunc persists the fact that one tool call happened, so an
// investigation's gathered evidence can be shown to an operator afterwards.
// The hub wires this to an insert into mcp_tool_calls (migration 000037,
// internal/api.RecordMCPToolCall); it is an injected function for the same
// reason ObserveFunc is one — this package holds no database handle.
//
// Kept separate from ObserveFunc rather than folded into it, despite the
// overlapping arguments, because the two have different jobs and different
// consequences:
//
//   - observe is the security/audit trail. It gets the tool ARGUMENTS, and it
//     fires for a refused call too, because "something asked for a tool it was
//     not granted" is the event it exists to capture.
//   - record is operator-facing bookkeeping. It deliberately gets no
//     arguments and no result (see the call site), and it fires only for calls
//     actually dispatched to a cluster.
//
// Returns nothing, on purpose. An investigation must not break because
// bookkeeping failed, and a signature with no error to ignore makes that
// structural rather than a rule the call site has to remember: the
// implementation logs its own failures and this package cannot even observe
// them. dur is how long the tool call took, measured around the executor.
type RecordFunc func(ctx context.Context, grant Grant, tool string, dur time.Duration, callErr error)

// RecordContentFunc is PROJECT.md B151's addition: unlike RecordFunc, this
// DOES get the real arguments and result — the content RecordFunc's own doc
// comment explains was deliberately omitted from mcp_tool_calls (migration
// 000037). The reason for omitting it there was cost/blast-radius for THAT
// table's own callers (the budget, the circuit breaker), not a blanket rule
// that this content must never be persisted — the api backend's own
// `evidence` table already persists exactly this for every dispatched call
// it makes. RecordContentFunc is the cli-backend equivalent: without it, a
// self-reported causal-chain citation can never be checked for more than
// "a call of this name happened" (crossCheckCausalChain, internal/llm),
// which is exactly the gap that let a live CreateResource execution write
// factually wrong data past a step marked "corroborated": true.
//
// Optional, like RecordFunc (nil disables it) — and separate from RecordFunc
// rather than folded in, for the identical reason RecordFunc is separate
// from ObserveFunc: a caller that wants call-counting but not content
// (a test, or a future deployment that wants the cheaper guarantee back)
// can wire RecordFunc alone. args/result are exactly what was passed to and
// returned from ToolFunc — already redacted by the agent before this
// process ever saw them (argus-context non-negotiable 9), same as every
// other tool result this hub handles.
type RecordContentFunc func(ctx context.Context, grant Grant, tool string, args, result json.RawMessage, callErr error)

// Tool is one tool this server offers, in MCP's own wire shape.
type Tool struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	InputSchema json.RawMessage `json:"inputSchema"`
	// Annotations are MCP's optional tool hints (readOnlyHint and friends,
	// protocol 2025-03-26). Advisory to the CLIENT only — a client may use
	// readOnlyHint to skip a confirmation prompt — and never trusted by this
	// server, which enforces read-only-ness by what the surface contains.
	Annotations map[string]any `json:"annotations,omitempty"`
}

// Authenticator resolves the credential on one request to the Grant it
// carries. It is the only thing that differs between the two mounts of this
// server: the CLI runner's listener authenticates with Store.Lookup (a
// per-investigation, single-cluster token), and the user-facing endpoint
// (internal/api/mcp_user.go, PROJECT.md AD3) with a person's own access token.
// Everything after authentication — the JSON-RPC handling, the allowlist
// check, observe/record — is the same code for both.
//
// A non-nil error refuses the request. A *RefusalError's message is shown to
// the client (a rate limit, say, which the caller needs to understand); any
// other error is reported as the generic "invalid or expired MCP token", so
// "that token existed but expired" is never free information.
type Authenticator func(r *http.Request) (Grant, error)

// RefusalError is an authentication-stage refusal whose message is safe and
// useful to show the client. Status is the HTTP status it is sent with (0
// means 403: a valid credential refused); RetryAfterSeconds, when set, is sent
// as Retry-After so a client can back off (a rate limit is 429 with it).
type RefusalError struct {
	Message           string
	Status            int
	RetryAfterSeconds int
}

func (e *RefusalError) Error() string { return e.Message }

// Server is the MCP endpoint. Construct with NewServer (or NewServerWithAuth)
// and mount Handler.
type Server struct {
	auth          Authenticator
	tools         []Tool
	call          ToolFunc
	observe       ObserveFunc
	record        RecordFunc
	recordContent RecordContentFunc
}

// NewServer wires the token store, the fixed tool surface, and the tool
// executor. tools is the complete set this server will ever offer; a grant
// may narrow it further but never widen it. Almost every entry is read-only
// investigation evidence — the one exception, as of BACKLOG.md C4, is
// dry_run_patch, which is write-capable but restricted to dryRun=All by the
// cluster's own ValidatingAdmissionPolicy, and even that one is only ever
// GRANTED (present in a minted token's allowedTools) when the target
// cluster reported holding the argus-dryrun grant — see
// internal/llm.CLIInvestigator.Investigate's toolNamesForTarget. Real
// remediation execution actions (scale_deployment, etc.) are never in this
// list at all, regardless of grant.
//
// The surface is injected rather than declared here, and that is where a new
// tool belongs: cmd/hub builds it by projecting internal/llm's toolDefinitions
// through llm.InvestigationToolSchemas, so the api backend's tool list and
// this server's list are one list by construction. Declaring a tool in this
// file instead would give the cli backend a capability the api backend does
// not have — the exact drift that projection exists to make impossible — and
// it would also be unreachable, since the agent-side executor
// (internal/agent/tools.go's Execute) is the only thing that can actually run
// one. The "%d tools registered" line ListenAndServe logs is len(tools) for
// the same reason: it reports the surface it was handed, never a hardcoded
// count that could quietly disagree with it.
//
// observe, record and recordContent are all optional (nil disables that
// hook), which is what keeps this package's tests free of an audit sink and
// a database.
func NewServer(store *Store, tools []Tool, call ToolFunc, observe ObserveFunc, record RecordFunc, recordContent RecordContentFunc) *Server {
	return NewServerWithAuth(func(r *http.Request) (Grant, error) {
		grant, ok := store.Lookup(bearerToken(r))
		if !ok {
			return Grant{}, errInvalidToken
		}
		return grant, nil
	}, tools, call, observe, record, recordContent)
}

// NewServerWithAuth is NewServer with the credential check supplied by the
// caller — the seam the user-facing mount uses (see Authenticator). The
// contract on tools is unchanged: it is the complete surface, and a grant
// may narrow it but never widen it.
func NewServerWithAuth(auth Authenticator, tools []Tool, call ToolFunc, observe ObserveFunc, record RecordFunc, recordContent RecordContentFunc) *Server {
	return &Server{auth: auth, tools: tools, call: call, observe: observe, record: record, recordContent: recordContent}
}

var errInvalidToken = errors.New("invalid or expired MCP token")

// BearerToken reads the presented token the way this server does —
// Authorization: Bearer, falling back to X-Argus-MCP-Token — so an
// Authenticator supplied from outside this package reads the same headers.
func BearerToken(r *http.Request) string { return bearerToken(r) }

// ToolNames is the set of tool names this server offers — what a caller
// passes to Store.Mint so a grant's allowlist matches what actually exists.
func (s *Server) ToolNames() []string {
	names := make([]string, 0, len(s.tools))
	for _, t := range s.tools {
		names = append(names, t.Name)
	}
	return names
}

type rpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

// Handler serves the MCP endpoint.
func (s *Server) Handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			// No GET/SSE transport here: this server is only ever driven by a
			// CLI making request/response tool calls, so the streaming half
			// of MCP's HTTP transport would be dead code.
			w.Header().Set("Allow", http.MethodPost)
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var req rpcRequest
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
			writeRPC(w, rpcResponse{JSONRPC: "2.0", Error: &rpcError{Code: codeParseError, Message: "malformed JSON-RPC request"}})
			return
		}
		if req.JSONRPC != "2.0" || req.Method == "" {
			writeRPC(w, rpcResponse{JSONRPC: "2.0", ID: req.ID, Error: &rpcError{Code: codeInvalidRequest, Message: `expected jsonrpc "2.0" and a method`}})
			return
		}

		// A notification (no id) gets no response body, per JSON-RPC 2.0.
		// notifications/initialized is the one the MCP handshake actually
		// sends, and answering it with a result would be a protocol error.
		if len(req.ID) == 0 {
			w.WriteHeader(http.StatusAccepted)
			return
		}

		// Every method below this point requires a valid scoped token —
		// including initialize and tools/list, deliberately. An unauthenticated
		// caller learning the exact tool surface and schemas is free
		// reconnaissance, and there is no legitimate client that needs it
		// before it has a token.
		grant, err := s.auth(r)
		if err != nil {
			// An authentication failure is the one error that is NOT HTTP 200:
			// the MCP authorization spec requires 401 for a missing, invalid or
			// expired token, and clients rely on it to tell the person their
			// credential is wrong instead of reporting a working server whose
			// every call fails. A refusal of a valid credential (a withdrawn
			// capability) is 403, a rate limit 429 with Retry-After, and a
			// failure to check permissions 503. The JSON-RPC error body is the
			// same either way.
			msg := errInvalidToken.Error()
			status := http.StatusUnauthorized
			var refusal *RefusalError
			if errors.As(err, &refusal) {
				msg = refusal.Message
				status = http.StatusForbidden
				if refusal.Status != 0 {
					status = refusal.Status
				}
				if refusal.RetryAfterSeconds > 0 {
					w.Header().Set("Retry-After", strconv.Itoa(refusal.RetryAfterSeconds))
				}
			} else {
				w.Header().Set("WWW-Authenticate", `Bearer realm="argus-mcp"`)
			}
			writeRPCStatus(w, status, rpcResponse{JSONRPC: "2.0", ID: req.ID, Error: &rpcError{Code: codeUnauthorized, Message: msg}})
			return
		}

		switch req.Method {
		case "initialize":
			writeRPC(w, rpcResponse{JSONRPC: "2.0", ID: req.ID, Result: map[string]any{
				"protocolVersion": negotiateProtocolVersion(req.Params),
				"capabilities":    map[string]any{"tools": map[string]any{}},
				"serverInfo":      map[string]any{"name": "argus-hub", "version": "v1"},
			}})
		case "tools/list":
			writeRPC(w, rpcResponse{JSONRPC: "2.0", ID: req.ID, Result: map[string]any{"tools": s.grantedTools(grant)}})
		case "tools/call":
			s.handleToolCall(r.Context(), w, req, grant)
		case "ping":
			// MCP's liveness check; a client may send it at any time and
			// expects an empty result.
			writeRPC(w, rpcResponse{JSONRPC: "2.0", ID: req.ID, Result: map[string]any{}})
		default:
			writeRPC(w, rpcResponse{JSONRPC: "2.0", ID: req.ID, Error: &rpcError{Code: codeMethodNotFound, Message: fmt.Sprintf("unsupported method %q", req.Method)}})
		}
	}
}

// grantedTools is the offered surface intersected with what this grant
// allows — so a token minted with a narrower allowlist genuinely cannot see
// the rest, rather than seeing them and being refused at call time.
func (s *Server) grantedTools(grant Grant) []Tool {
	out := make([]Tool, 0, len(s.tools))
	for _, t := range s.tools {
		if grant.Allows(t.Name) {
			out = append(out, t)
		}
	}
	return out
}

func (s *Server) handleToolCall(ctx context.Context, w http.ResponseWriter, req rpcRequest, grant Grant) {
	var params struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	}
	if err := json.Unmarshal(req.Params, &params); err != nil || params.Name == "" {
		writeRPC(w, rpcResponse{JSONRPC: "2.0", ID: req.ID, Error: &rpcError{Code: codeInvalidParams, Message: "tools/call requires a name and arguments"}})
		return
	}

	// The authorization check, and the reason T21 is containable: the tool
	// must be in this grant's allowlist. A CLI that has been talked into
	// asking for something outside it — by injected evidence content or
	// otherwise — gets refused here, by the hub, not by the CLI's own
	// good behaviour.
	if !grant.Allows(params.Name) {
		if s.observe != nil {
			s.observe(ctx, grant, params.Name, params.Arguments, errors.New("tool not permitted by grant"))
		}
		logger.WarnContext(ctx, "refused an MCP tool call: not permitted by this grant",
			slog.String("tool", params.Name), logging.ClusterID(grant.ClusterID))
		writeRPC(w, rpcResponse{JSONRPC: "2.0", ID: req.ID, Error: &rpcError{Code: codeUnauthorized, Message: fmt.Sprintf("tool %q is not permitted", params.Name)}})
		return
	}

	args := params.Arguments
	if len(args) == 0 {
		args = json.RawMessage(`{}`)
	}

	// The GRANT, never anything from params — SR-24's core requirement. There
	// is deliberately no cluster field (nor, since F22, an incident field) in
	// the params struct above to read even by accident.
	start := time.Now()
	result, err := s.call(ctx, grant, params.Name, args)
	dur := time.Since(start)
	if s.observe != nil {
		s.observe(ctx, grant, params.Name, args, err)
	}
	// Persist the fact of the call, so the analysis this investigation produces
	// can be shown with the work behind it instead of arriving as an
	// unsupported verdict (the cli backend contributes no causal chain — see
	// internal/llm/cli_investigator.go's own comment on why inventing one is
	// worse than showing none).
	//
	// `result` is deliberately NOT passed and deliberately not stored. It is
	// raw cluster data and can be large; the point of this record is which
	// questions were asked, not what the cluster answered — an operator
	// auditing an analysis needs "it looked at the owner chain three times",
	// and the answers already exist in the cluster itself. Storing them would
	// also copy customer cluster state into the hub's database for the sake of
	// a count.
	//
	// Runs after the response has been decided but before it is written, and
	// cannot change it: RecordFunc returns nothing (see its doc comment), so a
	// failed insert cannot become a failed tool call. A refused call never
	// reaches here — that path is an authorization event for observe, not
	// evidence gathered, and counting it among an incident's tool calls would
	// misreport a blocked request as work done.
	if s.record != nil {
		s.record(ctx, grant, params.Name, dur, err)
	}
	// PROJECT.md B151: the real content, unlike record above — see
	// RecordContentFunc's own doc comment for why this is now captured
	// where it never was before. Same "runs after the response is decided,
	// cannot change it, logs its own failures" posture as record.
	if s.recordContent != nil {
		s.recordContent(ctx, grant, params.Name, args, result, err)
	}
	if err != nil {
		// Returned as an MCP tool error (isError on a normal result), not a
		// JSON-RPC transport error: "the tool ran and failed" is a normal
		// investigative outcome the model should see and reason about, the
		// same way the api backend feeds a failed tool result back into the
		// loop rather than aborting the investigation.
		writeRPC(w, rpcResponse{JSONRPC: "2.0", ID: req.ID, Result: map[string]any{
			"content": []map[string]any{{"type": "text", "text": fmt.Sprintf("tool error: %v", err)}},
			"isError": true,
		}})
		return
	}

	writeRPC(w, rpcResponse{JSONRPC: "2.0", ID: req.ID, Result: map[string]any{
		"content": []map[string]any{{"type": "text", "text": string(result)}},
		"isError": false,
	}})
}

// bearerToken reads the token from Authorization: Bearer, falling back to the
// X-Argus-MCP-Token header. Both are supported because CLI MCP client configs
// vary in which custom headers they can set.
func bearerToken(r *http.Request) string {
	if h := r.Header.Get("Authorization"); h != "" {
		if after, ok := cutPrefixFold(h, "bearer "); ok {
			return strings.TrimSpace(after)
		}
	}
	return strings.TrimSpace(r.Header.Get("X-Argus-MCP-Token"))
}

func cutPrefixFold(s, prefix string) (string, bool) {
	if len(s) < len(prefix) || !strings.EqualFold(s[:len(prefix)], prefix) {
		return "", false
	}
	return s[len(prefix):], true
}

func writeRPC(w http.ResponseWriter, resp rpcResponse) {
	// HTTP 200 for everything past authentication: in JSON-RPC the error
	// lives in the body, and a non-200 would make some MCP clients treat a
	// tool error as a transport failure and retry rather than surfacing it to
	// the model. Authentication failures use writeRPCStatus (see the caller).
	writeRPCStatus(w, http.StatusOK, resp)
}

func writeRPCStatus(w http.ResponseWriter, status int, resp rpcResponse) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		logger.Warn("writing an MCP response failed", logging.Err(err))
	}
}

// ListenAndServe runs the MCP server on its own listener. Separate from the
// public API listener by design (lld/12-deployment-design.md §12.6): nothing
// on this port is reachable with a user session, and nothing on the public
// port can reach these tools.
func (s *Server) ListenAndServe(ctx context.Context, addr string) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/mcp", s.Handler())
	srv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()
	// BACKLOG.md C4: no longer "read-only tools" unconditionally — as of
	// dry_run_patch, the registered surface includes one write-capable
	// (dryRun=All-restricted) tool. What is still true, and what this log
	// line now says instead, is that every tool a given TOKEN can actually
	// call is bounded by that token's own grant (Store.Mint's allowedTools),
	// never by everything registered here.
	logger.Info("serving the MCP tool surface (scoped-token auth; the per-token grant decides what is callable)",
		slog.String("addr", addr), slog.Int("tools", len(s.tools)))
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}
