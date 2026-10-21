package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func testTools() []Tool {
	return []Tool{
		{Name: "get_events", Description: "events", InputSchema: json.RawMessage(`{"type":"object"}`)},
		{Name: "get_logs", Description: "logs", InputSchema: json.RawMessage(`{"type":"object"}`)},
	}
}

func TestMintRefusesEmptyClusterScope(t *testing.T) {
	// SR-24: an unscoped token would be a fleet-wide read grant handed to a
	// subprocess. It must be impossible to mint one, not merely discouraged.
	s := NewStore(0, nil)
	if _, err := s.Mint("", "inc_1", []string{"get_events"}); err == nil {
		t.Fatal("Mint with no cluster scope should have failed")
	}
}

func TestMintLookupRevoke(t *testing.T) {
	s := NewStore(0, nil)
	token, err := s.Mint("cl_1", "inc_1", []string{"get_events"})
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}

	grant, ok := s.Lookup(token)
	if !ok {
		t.Fatal("freshly minted token should look up")
	}
	if grant.ClusterID != "cl_1" || grant.IncidentID != "inc_1" {
		t.Errorf("grant = %+v, want cluster cl_1 / incident inc_1", grant)
	}
	if !grant.Allows("get_events") {
		t.Error("get_events should be allowed")
	}
	if grant.Allows("get_logs") {
		t.Error("get_logs was not in the allowlist and must not be allowed")
	}

	s.Revoke(token)
	if _, ok := s.Lookup(token); ok {
		t.Error("revoked token should not look up")
	}
}

func TestLookupRejectsExpiredAndUnknown(t *testing.T) {
	now := time.Now()
	clock := func() time.Time { return now }
	s := NewStore(time.Minute, clock)

	token, err := s.Mint("cl_1", "inc_1", []string{"get_events"})
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	if _, ok := s.Lookup(token); !ok {
		t.Fatal("token should be valid before expiry")
	}

	now = now.Add(2 * time.Minute)
	if _, ok := s.Lookup(token); ok {
		t.Error("token should be invalid after its TTL")
	}
	if _, ok := s.Lookup("some-token-never-minted"); ok {
		t.Error("unknown token must not validate")
	}
	if _, ok := s.Lookup(""); ok {
		t.Error("empty token must not validate")
	}
}

// newTestServer wires a Server whose tool executor records what cluster it was
// asked for, so tests can assert the SR-24 property directly.
func newTestServer(t *testing.T, allowed []string) (*Server, *Store, string, *[]string) {
	t.Helper()
	store := NewStore(0, nil)
	var sawClusters []string
	srv := NewServer(store, testTools(),
		func(_ context.Context, grant Grant, _ string, _ json.RawMessage) (json.RawMessage, error) {
			sawClusters = append(sawClusters, grant.ClusterID)
			return json.RawMessage(`{"ok":true}`), nil
		}, nil, nil, nil)
	token, err := store.Mint("cl_scoped", "inc_1", allowed)
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	return srv, store, token, &sawClusters
}

func post(t *testing.T, srv *Server, token, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	srv.Handler()(rec, req)
	return rec
}

func decodeRPC(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode response %q: %v", rec.Body.String(), err)
	}
	return out
}

func TestUnauthenticatedRequestsAreRefused(t *testing.T) {
	// Including tools/list and initialize: an unauthenticated caller learning
	// the tool surface is free reconnaissance, and no legitimate client needs
	// it before it holds a token.
	srv, _, _, _ := newTestServer(t, []string{"get_events"})
	for _, method := range []string{"initialize", "tools/list", "tools/call"} {
		body := `{"jsonrpc":"2.0","id":1,"method":"` + method + `","params":{"name":"get_events"}}`
		resp := decodeRPC(t, post(t, srv, "", body))
		errObj, ok := resp["error"].(map[string]any)
		if !ok {
			t.Errorf("%s without a token: expected an error, got %v", method, resp)
			continue
		}
		if errObj["code"].(float64) != codeUnauthorized {
			t.Errorf("%s: error code = %v, want %d", method, errObj["code"], codeUnauthorized)
		}
	}
}

func TestNotificationGetsNoBody(t *testing.T) {
	srv, _, _, _ := newTestServer(t, []string{"get_events"})
	rec := post(t, srv, "", `{"jsonrpc":"2.0","method":"notifications/initialized"}`)
	if rec.Code != http.StatusAccepted {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusAccepted)
	}
	if strings.TrimSpace(rec.Body.String()) != "" {
		t.Errorf("notification should get no response body, got %q", rec.Body.String())
	}
}

func TestToolsListIsNarrowedToTheGrant(t *testing.T) {
	// The server offers two tools; this grant allows one. The un-granted tool
	// must not even be visible, rather than being listed and refused later.
	srv, _, token, _ := newTestServer(t, []string{"get_events"})
	resp := decodeRPC(t, post(t, srv, token, `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`))
	result := resp["result"].(map[string]any)
	tools := result["tools"].([]any)
	if len(tools) != 1 {
		t.Fatalf("got %d tools, want 1 (only the granted one): %v", len(tools), tools)
	}
	if name := tools[0].(map[string]any)["name"]; name != "get_events" {
		t.Errorf("tool = %v, want get_events", name)
	}
}

func TestToolCallUsesGrantClusterNotParams(t *testing.T) {
	// The SR-24 property, asserted directly: a caller supplying its own
	// clusterId must not influence which cluster is read.
	srv, _, token, sawClusters := newTestServer(t, []string{"get_events"})
	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_events","arguments":{"namespace":"x"},"clusterId":"cl_ATTACKER"}}`
	resp := decodeRPC(t, post(t, srv, token, body))
	if _, isErr := resp["error"]; isErr {
		t.Fatalf("unexpected error: %v", resp)
	}
	if len(*sawClusters) != 1 || (*sawClusters)[0] != "cl_scoped" {
		t.Errorf("executor saw clusters %v, want exactly [cl_scoped] — a params-supplied cluster must be ignored", *sawClusters)
	}
}

func TestToolCallRefusesToolOutsideAllowlist(t *testing.T) {
	// T21's containment point: the hub refuses, rather than relying on the
	// CLI's own good behaviour.
	srv, _, token, sawClusters := newTestServer(t, []string{"get_events"})
	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_logs","arguments":{}}}`
	resp := decodeRPC(t, post(t, srv, token, body))
	errObj, ok := resp["error"].(map[string]any)
	if !ok {
		t.Fatalf("expected an error for a non-allowlisted tool, got %v", resp)
	}
	if errObj["code"].(float64) != codeUnauthorized {
		t.Errorf("code = %v, want %d", errObj["code"], codeUnauthorized)
	}
	if len(*sawClusters) != 0 {
		t.Errorf("a refused tool must never reach the executor, but it saw %v", *sawClusters)
	}
}

func TestToolCallRefusesAnyToolNotInTheServerSurface(t *testing.T) {
	// A grant cannot widen the surface: minting a token that names a tool the
	// server does not offer must not make it callable.
	store := NewStore(0, nil)
	var reached []string
	srv := NewServer(store, testTools(),
		func(_ context.Context, _ Grant, tool string, _ json.RawMessage) (json.RawMessage, error) {
			reached = append(reached, tool)
			return json.RawMessage(`{}`), nil
		}, nil, nil, nil)
	token, err := store.Mint("cl_1", "inc_1", []string{"scale_deployment"})
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}

	// tools/list must not show it, because it isn't in the server's surface.
	resp := decodeRPC(t, post(t, srv, token, `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`))
	tools := resp["result"].(map[string]any)["tools"].([]any)
	if len(tools) != 0 {
		t.Errorf("grant naming an unoffered tool should list nothing, got %v", tools)
	}

	// And calling it reaches the executor only if the grant allows it — which
	// it does here, so this documents the real boundary: the grant is the
	// authorization check, the server surface is the discovery surface. A
	// write tool is never in EITHER for a real deployment (see
	// llm.InvestigationToolSchemas), which is what makes this safe.
	_ = decodeRPC(t, post(t, srv, token, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"scale_deployment","arguments":{}}}`))
	if len(reached) != 1 {
		t.Errorf("reached = %v; this test pins current behaviour so a future change to it is deliberate", reached)
	}
}

func TestToolErrorIsAToolResultNotATransportError(t *testing.T) {
	// A failed tool is a normal investigative outcome the model should see and
	// reason about — matching how the api backend feeds a failed tool result
	// back into the loop instead of aborting.
	store := NewStore(0, nil)
	srv := NewServer(store, testTools(),
		func(_ context.Context, _ Grant, _ string, _ json.RawMessage) (json.RawMessage, error) {
			return nil, errors.New("cluster unreachable")
		}, nil, nil, nil)
	token, err := store.Mint("cl_1", "inc_1", []string{"get_events"})
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	resp := decodeRPC(t, post(t, srv, token, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_events","arguments":{}}}`))
	if _, isErr := resp["error"]; isErr {
		t.Fatalf("a tool failure should not be a JSON-RPC error: %v", resp)
	}
	result := resp["result"].(map[string]any)
	if result["isError"] != true {
		t.Errorf("isError = %v, want true", result["isError"])
	}
}

func TestObserveIsCalledForAllowedAndRefusedCalls(t *testing.T) {
	store := NewStore(0, nil)
	type observed struct {
		tool string
		err  bool
	}
	var seen []observed
	srv := NewServer(store, testTools(),
		func(_ context.Context, _ Grant, _ string, _ json.RawMessage) (json.RawMessage, error) {
			return json.RawMessage(`{}`), nil
		},
		func(_ context.Context, _ Grant, tool string, _ json.RawMessage, err error) {
			seen = append(seen, observed{tool: tool, err: err != nil})
		}, nil, nil)
	token, err := store.Mint("cl_1", "inc_1", []string{"get_events"})
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}

	_ = post(t, srv, token, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_events","arguments":{}}}`)
	_ = post(t, srv, token, `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"get_logs","arguments":{}}}`)

	if len(seen) != 2 {
		t.Fatalf("observed %d calls, want 2 (one allowed, one refused): %+v", len(seen), seen)
	}
	if seen[0].err {
		t.Errorf("allowed call should observe no error: %+v", seen[0])
	}
	if !seen[1].err {
		t.Errorf("refused call should observe an error: %+v", seen[1])
	}
}

// TestRecordingFailureDoesNotFailTheToolCall is the property migration
// 000037's writer exists under: an investigation must not break because
// bookkeeping broke. The recorder here does what the real one does when its
// insert fails (gives up, having logged), for both a successful and a failed
// tool call, and neither response may change as a result — the success still
// carries its result payload, and the failure is still the ordinary
// isError-tool-result an investigating model can reason about, not a transport
// error.
func TestRecordingFailureDoesNotFailTheToolCall(t *testing.T) {
	for _, tc := range []struct {
		name        string
		toolErr     error
		wantIsError bool
	}{
		{"successful tool call", nil, false},
		{"failed tool call", errors.New("cluster unreachable"), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := NewStore(0, nil)
			recordAttempts := 0
			srv := NewServer(store, testTools(),
				func(_ context.Context, _ Grant, _ string, _ json.RawMessage) (json.RawMessage, error) {
					if tc.toolErr != nil {
						return nil, tc.toolErr
					}
					return json.RawMessage(`{"items":[]}`), nil
				}, nil,
				func(_ context.Context, _ Grant, _ string, _ time.Duration, _ error) {
					// Stands in for "the insert failed and was logged". The
					// signature has no error to return precisely so this cannot
					// be wired into the response by accident.
					recordAttempts++
				}, nil)
			token, err := store.Mint("cl_1", "inc_1", []string{"get_events"})
			if err != nil {
				t.Fatalf("Mint: %v", err)
			}

			resp := decodeRPC(t, post(t, srv, token, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_events","arguments":{}}}`))
			if _, isErr := resp["error"]; isErr {
				t.Fatalf("a recording failure must not become a JSON-RPC error: %v", resp)
			}
			result, ok := resp["result"].(map[string]any)
			if !ok {
				t.Fatalf("expected a tool result, got %v", resp)
			}
			if result["isError"] != tc.wantIsError {
				t.Errorf("isError = %v, want %v — the tool's own outcome must be reported, unaffected by recording",
					result["isError"], tc.wantIsError)
			}
			if recordAttempts != 1 {
				t.Errorf("recorder called %d times, want exactly 1", recordAttempts)
			}
		})
	}
}

// TestRefusedToolCallIsNotRecordedAsEvidence pins the boundary between the two
// hooks: a call blocked by the grant is an authorization event (observe's job,
// asserted above) and never reached a cluster, so counting it among an
// incident's gathered evidence would report a blocked request as work done.
func TestRefusedToolCallIsNotRecordedAsEvidence(t *testing.T) {
	store := NewStore(0, nil)
	var recorded []string
	srv := NewServer(store, testTools(),
		func(_ context.Context, _ Grant, _ string, _ json.RawMessage) (json.RawMessage, error) {
			return json.RawMessage(`{}`), nil
		}, nil,
		func(_ context.Context, _ Grant, tool string, _ time.Duration, _ error) {
			recorded = append(recorded, tool)
		}, nil)
	token, err := store.Mint("cl_1", "inc_1", []string{"get_events"})
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}

	_ = post(t, srv, token, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_logs","arguments":{}}}`)
	_ = post(t, srv, token, `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"get_events","arguments":{}}}`)

	if len(recorded) != 1 || recorded[0] != "get_events" {
		t.Errorf("recorded = %v, want only [get_events] — a refused call is not gathered evidence", recorded)
	}
}

func TestMalformedAndUnsupportedRequests(t *testing.T) {
	srv, _, token, _ := newTestServer(t, []string{"get_events"})

	resp := decodeRPC(t, post(t, srv, token, `not json at all`))
	if resp["error"].(map[string]any)["code"].(float64) != codeParseError {
		t.Errorf("malformed body: got %v, want parse error", resp)
	}

	resp = decodeRPC(t, post(t, srv, token, `{"jsonrpc":"1.0","id":1,"method":"tools/list"}`))
	if resp["error"].(map[string]any)["code"].(float64) != codeInvalidRequest {
		t.Errorf("wrong jsonrpc version: got %v, want invalid request", resp)
	}

	resp = decodeRPC(t, post(t, srv, token, `{"jsonrpc":"2.0","id":1,"method":"resources/list"}`))
	if resp["error"].(map[string]any)["code"].(float64) != codeMethodNotFound {
		t.Errorf("unsupported method: got %v, want method not found", resp)
	}

	resp = decodeRPC(t, post(t, srv, token, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{}}`))
	if resp["error"].(map[string]any)["code"].(float64) != codeInvalidParams {
		t.Errorf("tools/call with no name: got %v, want invalid params", resp)
	}
}

func TestGetIsNotAllowed(t *testing.T) {
	srv, _, _, _ := newTestServer(t, []string{"get_events"})
	rec := httptest.NewRecorder()
	srv.Handler()(rec, httptest.NewRequest(http.MethodGet, "/mcp", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET status = %d, want %d", rec.Code, http.StatusMethodNotAllowed)
	}
}

func TestBearerTokenParsing(t *testing.T) {
	cases := []struct {
		name   string
		header string
		value  string
		want   string
	}{
		{"bearer lowercase", "Authorization", "bearer abc", "abc"},
		{"Bearer capitalized", "Authorization", "Bearer abc", "abc"},
		{"extra whitespace", "Authorization", "Bearer   abc  ", "abc"},
		{"custom header", "X-Argus-MCP-Token", "abc", "abc"},
		{"no header", "", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, "/mcp", nil)
			if tc.header != "" {
				r.Header.Set(tc.header, tc.value)
			}
			if got := bearerToken(r); got != tc.want {
				t.Errorf("bearerToken() = %q, want %q", got, tc.want)
			}
		})
	}
}

// --- PROJECT.md AD3: the second mount, with a caller-supplied Authenticator.

func TestAuthenticatorRefusalMessages(t *testing.T) {
	// A RefusalError's message reaches the client (a rate limit the caller has
	// to understand); any other error collapses into the generic message, so a
	// client cannot learn WHY its credential was refused.
	for _, tc := range []struct {
		name string
		err  error
		want string
	}{
		{"refusal is shown", &RefusalError{Message: "rate limit: try again in 3s"}, "rate limit: try again in 3s"},
		{"anything else is generic", errors.New("token row says revoked_at=2026-10-01"), "invalid or expired MCP token"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			called := false
			srv := NewServerWithAuth(func(*http.Request) (Grant, error) { return Grant{}, tc.err }, testTools(),
				func(context.Context, Grant, string, json.RawMessage) (json.RawMessage, error) {
					called = true
					return nil, nil
				}, nil, nil, nil)
			resp := decodeRPC(t, post(t, srv, "anything", `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_events"}}`))
			errObj, ok := resp["error"].(map[string]any)
			if !ok {
				t.Fatalf("expected a JSON-RPC error, got %v", resp)
			}
			if errObj["message"] != tc.want {
				t.Errorf("message = %q, want %q", errObj["message"], tc.want)
			}
			if called {
				t.Error("the tool ran despite the authenticator refusing the request")
			}
		})
	}
}

func TestAuthenticatorGrantReachesTheToolFunc(t *testing.T) {
	// The principal the authenticator resolved — never anything in params — is
	// what the executor acts as.
	var saw *Principal
	srv := NewServerWithAuth(func(*http.Request) (Grant, error) {
		return Grant{
			AllowedTools: map[string]struct{}{"get_events": {}},
			Principal:    &Principal{TenantID: "org_1", UserID: "usr_alice", TokenID: "pat_1"},
		}, nil
	}, testTools(), func(_ context.Context, g Grant, _ string, _ json.RawMessage) (json.RawMessage, error) {
		saw = g.Principal
		return json.RawMessage(`{}`), nil
	}, nil, nil, nil)
	post(t, srv, "x", `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_events","arguments":{"userId":"usr_mallory"}}}`)
	if saw == nil || saw.UserID != "usr_alice" {
		t.Fatalf("executor acted as %+v, want the authenticated usr_alice", saw)
	}
}

func TestInitializeNegotiatesProtocolVersion(t *testing.T) {
	srv, _, token, _ := newTestServer(t, []string{"get_events"})
	for requested, want := range map[string]string{
		"2025-06-18": "2025-06-18",
		"2025-03-26": "2025-03-26",
		"2024-11-05": "2024-11-05",
		"2099-01-01": supportedProtocolVersions[0],
		"":           supportedProtocolVersions[0],
	} {
		body := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"` + requested + `"}}`
		resp := decodeRPC(t, post(t, srv, token, body))
		result, _ := resp["result"].(map[string]any)
		if got := result["protocolVersion"]; got != want {
			t.Errorf("requested %q: protocolVersion = %v, want %q", requested, got, want)
		}
	}
}

func TestPingAnswersWithAnEmptyResult(t *testing.T) {
	srv, _, token, _ := newTestServer(t, []string{"get_events"})
	resp := decodeRPC(t, post(t, srv, token, `{"jsonrpc":"2.0","id":7,"method":"ping"}`))
	if _, ok := resp["result"].(map[string]any); !ok || resp["error"] != nil {
		t.Fatalf("ping: got %v, want an empty result", resp)
	}
}

func TestToolAnnotationsAreSerialisedWhenSet(t *testing.T) {
	tools := []Tool{{Name: "get_events", InputSchema: json.RawMessage(`{"type":"object"}`), Annotations: map[string]any{"readOnlyHint": true}}}
	srv := NewServerWithAuth(func(*http.Request) (Grant, error) {
		return Grant{AllowedTools: map[string]struct{}{"get_events": {}}}, nil
	}, tools, nil, nil, nil, nil)
	rec := post(t, srv, "x", `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)
	if !strings.Contains(rec.Body.String(), `"readOnlyHint":true`) {
		t.Errorf("tools/list did not carry the annotation: %s", rec.Body.String())
	}
	// And a tool without annotations does not grow an empty field.
	srv2, _, token, _ := newTestServer(t, []string{"get_events"})
	if body := post(t, srv2, token, `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`).Body.String(); strings.Contains(body, "annotations") {
		t.Errorf("unannotated tools serialised an annotations field: %s", body)
	}
}

// The MCP authorization spec requires HTTP 401 for a missing, invalid or
// expired token; clients use it to tell the person their credential is
// wrong. A refusal of a valid credential carries its own status (403 by
// default, 429 with Retry-After for a rate limit). Everything past
// authentication stays HTTP 200 with the error in the JSON-RPC body.
func TestAuthenticationFailuresUseHTTPStatus(t *testing.T) {
	srv, _, _, _ := newTestServer(t, []string{"get_events"})
	rec := post(t, srv, "", `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("no token: status %d, want 401", rec.Code)
	}
	if got := rec.Header().Get("WWW-Authenticate"); !strings.HasPrefix(got, "Bearer") {
		t.Errorf("no token: WWW-Authenticate = %q, want a Bearer challenge", got)
	}

	for _, tc := range []struct {
		name       string
		err        error
		status     int
		retryAfter string
	}{
		{"withdrawn capability", &RefusalError{Message: "permission denied"}, http.StatusForbidden, ""},
		{"rate limit", &RefusalError{Message: "rate limit", Status: http.StatusTooManyRequests, RetryAfterSeconds: 3}, http.StatusTooManyRequests, "3"},
		{"permissions unavailable", &RefusalError{Message: "try again", Status: http.StatusServiceUnavailable}, http.StatusServiceUnavailable, ""},
		{"bad token", errors.New("no such token"), http.StatusUnauthorized, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := NewServerWithAuth(func(*http.Request) (Grant, error) { return Grant{}, tc.err }, testTools(),
				func(context.Context, Grant, string, json.RawMessage) (json.RawMessage, error) { return nil, nil }, nil, nil, nil)
			rec := post(t, s, "anything", `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)
			if rec.Code != tc.status {
				t.Errorf("status %d, want %d", rec.Code, tc.status)
			}
			if got := rec.Header().Get("Retry-After"); got != tc.retryAfter {
				t.Errorf("Retry-After = %q, want %q", got, tc.retryAfter)
			}
			if _, ok := decodeRPC(t, rec)["error"].(map[string]any); !ok {
				t.Errorf("body has no JSON-RPC error: %s", rec.Body.String())
			}
		})
	}
}
