package api

// PROJECT.md AD3 against a real, RLS-forced Postgres: the personal-token
// lifecycle through the real routes, hash-only storage, expiry/revocation/
// disabled-owner refusal, per-tool capability enforcement on the MCP
// endpoint, the audit rows each call writes, and RLS isolation of the token
// table. Every request goes through s.mux — the same registration the hub
// serves — so the routes' own requireAuth/requireCapability wiring is under
// test too, not just the handlers.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"argus/internal/audit"
	"argus/internal/authz"
	"argus/internal/data"
	"argus/internal/dbtest"
	"argus/internal/domain"
	"argus/internal/gateway"
)

type mcpFixture struct {
	// lastStatus is the HTTP status of the most recent rpc call: 200 for
	// everything past authentication, 401/403/429/503 for an authentication
	// failure (internal/mcp writeRPCStatus).
	lastStatus int
	pool       *pgxpool.Pool
	s          *Server
	signer     *authz.TokenSigner
	tenantID   string
	clusterA   string
	clusterB   string
	nameA      string
	fixture    *dbtest.Fixture
	grantIDs   []string
	clusterID  []string
}

func newMCPFixture(t *testing.T) *mcpFixture {
	t.Helper()
	pool := authTestPool(t)
	signer, err := authz.NewEphemeralTokenSigner()
	if err != nil {
		t.Fatalf("token signer: %v", err)
	}
	s := &Server{db: &data.DB{Pool: pool}, signer: signer, gw: gateway.NewGateway(nil, nil, nil), mux: http.NewServeMux()}
	s.routes()

	f := &mcpFixture{pool: pool, s: s, signer: signer, fixture: dbtest.New(t)}
	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if f.tenantID, err = resolveTenantScope(ctx, tx); err != nil {
		t.Fatalf("scope: %v", err)
	}
	f.clusterA, f.clusterB = domain.NewID(domain.PrefixCluster), domain.NewID(domain.PrefixCluster)
	f.nameA = "mcp-test-a-" + f.clusterA[len(f.clusterA)-6:]
	for _, c := range []struct{ id, name string }{{f.clusterA, f.nameA}, {f.clusterB, "mcp-test-b-" + f.clusterB[len(f.clusterB)-6:]}} {
		if _, err := tx.Exec(ctx,
			`INSERT INTO clusters (id, tenant_id, display_name, state, shard_id, cluster_fingerprint)
			 VALUES ($1, $2, $3, 'Active', 'shard-test', $4)`, c.id, f.tenantID, c.name, "fp-"+c.id); err != nil {
			t.Fatalf("insert cluster: %v", err)
		}
		f.fixture.Created("clusters", 1)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit: %v", err)
	}
	f.clusterID = []string{f.clusterA, f.clusterB}
	// Registered BEFORE any user is created: t.Cleanup runs last-registered
	// first, so the users (and, by ON DELETE CASCADE, their tokens) go
	// before this fixture deletes the grants and clusters.
	f.fixture.Cleanup(pool,
		func(ctx context.Context, tx pgx.Tx) error { return data.SetRequestScope(ctx, tx, f.tenantID, nil) },
		[]dbtest.TableDelete{
			{Table: "grants", SQL: `DELETE FROM grants WHERE id = ANY($1)`, Args: []any{&f.grantIDs}},
			{Table: "clusters", SQL: `DELETE FROM clusters WHERE id = ANY($1)`, Args: []any{f.clusterID}},
		})
	return f
}

// user creates a throwaway user holding exactly caps, scoped to scope.
func (f *mcpFixture) user(t *testing.T, scope string, caps ...string) string {
	t.Helper()
	_, userID, _, _ := authTestUser(t, f.pool, "mcp-test-password-correct-horse")
	ctx := context.Background()
	tx, err := f.pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if err := data.SetRequestScope(ctx, tx, f.tenantID, nil); err != nil {
		t.Fatalf("scope: %v", err)
	}
	capJSON, _ := json.Marshal(caps)
	grantID := domain.NewID(domain.PrefixGrant)
	if _, err := tx.Exec(ctx,
		`INSERT INTO grants (id, tenant_id, principal_type, principal_id, capability_set, scope, granted_by)
		 VALUES ($1, $2, 'user', $3, $4, $5::jsonb, $3)`, grantID, f.tenantID, userID, capJSON, scope); err != nil {
		t.Fatalf("insert grant: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit: %v", err)
	}
	f.grantIDs = append(f.grantIDs, grantID)
	f.fixture.Created("grants", 1)
	return userID
}

const allClusters = `{"type":"AllClusters"}`

func (f *mcpFixture) jwt(t *testing.T, userID string) string {
	t.Helper()
	token, err := f.signer.IssueAccessToken(userID, currentGenerationForTest(t, f.pool, userID))
	if err != nil {
		t.Fatalf("issue access token: %v", err)
	}
	return token
}

func (f *mcpFixture) rest(t *testing.T, method, path, bearer string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var buf bytes.Buffer
	if body != nil {
		_ = json.NewEncoder(&buf).Encode(body)
	}
	req := httptest.NewRequest(method, path, &buf)
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	rec := httptest.NewRecorder()
	f.s.mux.ServeHTTP(rec, req)
	return rec
}

func (f *mcpFixture) createToken(t *testing.T, userID, name string) (createPersonalTokenResponse, *httptest.ResponseRecorder) {
	t.Helper()
	rec := f.rest(t, http.MethodPost, "/api/v1/users/me/mcp-tokens", f.jwt(t, userID), map[string]any{"name": name, "expiresInDays": 30})
	var out createPersonalTokenResponse
	if rec.Code == http.StatusCreated {
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("decode create response: %v", err)
		}
	}
	return out, rec
}

// rpc posts one JSON-RPC request to the MCP endpoint and returns the decoded
// response object.
func (f *mcpFixture) rpc(t *testing.T, token, method string, params any) map[string]any {
	t.Helper()
	body, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/mcp", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json, text/event-stream")
	rec := httptest.NewRecorder()
	f.s.mux.ServeHTTP(rec, req)
	f.lastStatus = rec.Code
	switch rec.Code {
	case http.StatusOK, http.StatusUnauthorized, http.StatusForbidden, http.StatusTooManyRequests, http.StatusServiceUnavailable:
	default:
		t.Fatalf("%s: HTTP %d %s", method, rec.Code, rec.Body.String())
	}
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("%s: decode %q: %v", method, rec.Body.String(), err)
	}
	return out
}

// call runs tools/call and returns (text, isError), failing on a JSON-RPC
// error.
func (f *mcpFixture) call(t *testing.T, token, tool string, args map[string]any) (string, bool) {
	t.Helper()
	resp := f.rpc(t, token, "tools/call", map[string]any{"name": tool, "arguments": args})
	if e, ok := resp["error"].(map[string]any); ok {
		t.Fatalf("tools/call %s: JSON-RPC error %v", tool, e)
	}
	result := resp["result"].(map[string]any)
	content := result["content"].([]any)
	return content[0].(map[string]any)["text"].(string), result["isError"].(bool)
}

type auditRow struct {
	outcome, method string
	capability      *string
	clusterID       *string
	details         map[string]any
}

// lastAudit returns the newest audit row for userID whose details.action is action.
func (f *mcpFixture) lastAudit(t *testing.T, userID, action string) auditRow {
	t.Helper()
	ctx := context.Background()
	tx, err := f.pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if err := data.SetRequestScope(ctx, tx, f.tenantID, nil); err != nil {
		t.Fatalf("scope: %v", err)
	}
	var row auditRow
	var details []byte
	err = tx.QueryRow(ctx,
		`SELECT outcome, coalesce(actor_auth_method, ''), capability, cluster_id, details FROM audit_events
		  WHERE actor_id = $1 AND details->>'action' = $2 ORDER BY occurred_at DESC, id DESC LIMIT 1`,
		userID, action).Scan(&row.outcome, &row.method, &row.capability, &row.clusterID, &details)
	if err != nil {
		t.Fatalf("read audit row for %s/%s: %v", userID, action, err)
	}
	_ = json.Unmarshal(details, &row.details)
	return row
}

func TestPersonalTokenLifecycleThroughTheRealRoutes(t *testing.T) {
	f := newMCPFixture(t)
	alice := f.user(t, allClusters, authz.CapMCPUse, authz.CapClusterRead, authz.CapClusterInspect, authz.CapIncidentRead)
	bob := f.user(t, allClusters, authz.CapMCPUse, authz.CapClusterRead)

	created, rec := f.createToken(t, alice, "laptop claude code")
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", rec.Code, rec.Body.String())
	}
	if !strings.HasPrefix(created.Secret, personalTokenPrefix) || created.Token.Status != personalTokenActive {
		t.Fatalf("create returned %+v", created)
	}
	if got := created.Token.ExpiresAt.Sub(created.Token.CreatedAt); got != 30*24*time.Hour {
		t.Errorf("lifetime = %v, want the requested 30 days", got)
	}

	// Hash-only storage: the secret appears nowhere in the row.
	ctx := context.Background()
	tx, _ := f.pool.Begin(ctx)
	_ = data.SetRequestScope(ctx, tx, f.tenantID, nil)
	var rowText string
	if err := tx.QueryRow(ctx, `SELECT row_to_json(t)::text FROM mcp_personal_tokens t WHERE id = $1`, created.Token.ID).Scan(&rowText); err != nil {
		t.Fatalf("read token row: %v", err)
	}
	_ = tx.Rollback(ctx)
	_, secret, _ := parsePersonalToken(created.Secret)
	if strings.Contains(rowText, secret) || strings.Contains(rowText, created.Secret) {
		t.Fatalf("the stored row contains the secret: %s", rowText)
	}
	if !strings.Contains(rowText, hashPersonalTokenSecret(secret)) {
		t.Fatalf("the stored row does not hold the secret's hash: %s", rowText)
	}
	if a := f.lastAudit(t, alice, "mcp_token:create"); a.outcome != audit.OutcomeSuccess || a.details["tokenId"] != created.Token.ID {
		t.Errorf("creation audit row = %+v", a)
	}

	// The list shows it, without the secret; another user's list does not.
	list := f.rest(t, http.MethodGet, "/api/v1/users/me/mcp-tokens", f.jwt(t, alice), nil)
	if list.Code != http.StatusOK || !strings.Contains(list.Body.String(), created.Token.ID) || strings.Contains(list.Body.String(), secret) {
		t.Fatalf("alice's list: %d %s", list.Code, list.Body.String())
	}
	if other := f.rest(t, http.MethodGet, "/api/v1/users/me/mcp-tokens", f.jwt(t, bob), nil); strings.Contains(other.Body.String(), created.Token.ID) {
		t.Fatalf("bob's list shows alice's token: %s", other.Body.String())
	}

	// The token works on the MCP endpoint ...
	init := f.rpc(t, created.Secret, "initialize", map[string]any{"protocolVersion": "2025-06-18"})
	if init["result"].(map[string]any)["protocolVersion"] != "2025-06-18" {
		t.Errorf("initialize: %v", init)
	}
	tools := f.rpc(t, created.Secret, "tools/list", map[string]any{})["result"].(map[string]any)["tools"].([]any)
	if len(tools) != len(userMCPCatalogue()) {
		t.Errorf("tools/list returned %d tools, want the whole personal surface (%d)", len(tools), len(userMCPCatalogue()))
	}
	text, isErr := f.call(t, created.Secret, "list_clusters", nil)
	if isErr || !strings.Contains(text, f.clusterA) {
		t.Fatalf("list_clusters: isError=%v %s", isErr, text)
	}
	text, isErr = f.call(t, created.Secret, "get_cluster", map[string]any{"clusterId": f.nameA})
	if isErr || !strings.Contains(text, f.clusterA) {
		t.Fatalf("get_cluster by display name: isError=%v %s", isErr, text)
	}
	if a := f.lastAudit(t, alice, "mcp:tool_call"); a.outcome != audit.OutcomeSuccess || a.method != mcpAuthMethod ||
		a.clusterID == nil || *a.clusterID != f.clusterA || a.details["tool"] != "get_cluster" || a.details["tokenId"] != created.Token.ID {
		t.Errorf("get_cluster audit row = %+v (cluster %v)", a, a.clusterID)
	}

	// ... but is not a REST credential, and a REST JWT is not an MCP one.
	if r := f.rest(t, http.MethodGet, "/api/v1/users/me", created.Secret, nil); r.Code != http.StatusUnauthorized {
		t.Errorf("a personal token on a REST route: %d, want 401", r.Code)
	}
	if e, ok := f.rpc(t, f.jwt(t, alice), "tools/list", nil)["error"].(map[string]any); !ok || e["message"] != "invalid or expired MCP token" || f.lastStatus != http.StatusUnauthorized {
		t.Errorf("a JWT on the MCP endpoint was not refused: %v", e)
	}

	// Bob cannot revoke alice's token; alice can.
	if r := f.rest(t, http.MethodDelete, "/api/v1/users/me/mcp-tokens/"+created.Token.ID, f.jwt(t, bob), nil); r.Code != http.StatusNotFound {
		t.Fatalf("bob revoking alice's token: %d, want 404", r.Code)
	}
	if r := f.rest(t, http.MethodDelete, "/api/v1/users/me/mcp-tokens/"+created.Token.ID, f.jwt(t, alice), nil); r.Code != http.StatusNoContent {
		t.Fatalf("alice revoking her token: %d %s", r.Code, r.Body.String())
	}
	if e, ok := f.rpc(t, created.Secret, "tools/list", nil)["error"].(map[string]any); !ok || e["message"] != "invalid or expired MCP token" || f.lastStatus != http.StatusUnauthorized {
		t.Errorf("a revoked token still works: %v", e)
	}
	list = f.rest(t, http.MethodGet, "/api/v1/users/me/mcp-tokens", f.jwt(t, alice), nil)
	if !strings.Contains(list.Body.String(), `"status":"revoked"`) {
		t.Errorf("revoked token's status: %s", list.Body.String())
	}
	if a := f.lastAudit(t, alice, "mcp_token:revoke"); a.outcome != audit.OutcomeSuccess {
		t.Errorf("revocation audit row = %+v", a)
	}
}

func TestPersonalTokenCapabilityEnforcementPerTool(t *testing.T) {
	f := newMCPFixture(t)

	// Holds cluster:read but neither incident:read nor cluster:inspect.
	reader := f.user(t, allClusters, authz.CapMCPUse, authz.CapClusterRead)
	tok, rec := f.createToken(t, reader, "reader")
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", rec.Code, rec.Body.String())
	}
	if _, isErr := f.call(t, tok.Secret, "list_clusters", nil); isErr {
		t.Error("list_clusters refused to a cluster:read holder")
	}
	for tool, want := range map[string]struct {
		args map[string]any
		cap  string
	}{
		"list_incidents":       {nil, authz.CapIncidentRead},
		"list_findings":        {nil, authz.CapIncidentRead},
		"search_fleet_objects": {map[string]any{"query": "web"}, authz.CapClusterInspect},
		"describe_resource":    {map[string]any{"clusterId": f.clusterA, "gvk": "v1/Pod", "namespace": "default", "name": "x"}, authz.CapClusterInspect},
		"get_logs":             {map[string]any{"clusterId": f.clusterA, "namespace": "default", "pod": "x"}, authz.CapClusterInspect},
	} {
		text, isErr := f.call(t, tok.Secret, tool, want.args)
		if !isErr || !strings.Contains(text, "permission denied") || !strings.Contains(text, want.cap) {
			t.Errorf("%s without %s: isError=%v %q — want a denial naming the capability", tool, want.cap, isErr, text)
			continue
		}
		a := f.lastAudit(t, reader, "mcp:tool_call")
		if a.outcome != audit.OutcomeDenied || a.capability == nil || *a.capability != want.cap || a.details["tool"] != tool {
			t.Errorf("%s denial audit row = %+v", tool, a)
		}
	}

	// A tool off the surface — a remediation action — is refused before any
	// executor runs, and the attempt is audited as a denial.
	resp := f.rpc(t, tok.Secret, "tools/call", map[string]any{"name": "scale_deployment", "arguments": map[string]any{"clusterId": f.clusterA}})
	if e, ok := resp["error"].(map[string]any); !ok || !strings.Contains(e["message"].(string), "not permitted") {
		t.Errorf("scale_deployment: %v", resp)
	}
	if a := f.lastAudit(t, reader, "mcp:tool_call"); a.outcome != audit.OutcomeDenied || a.details["tool"] != "scale_deployment" {
		t.Errorf("off-surface denial audit row = %+v", a)
	}

	// An inspector reaches the agent (here: the cluster is not connected, an
	// honest error rather than a denial).
	inspector := f.user(t, allClusters, authz.CapMCPUse, authz.CapClusterRead, authz.CapClusterInspect)
	itok, _ := f.createToken(t, inspector, "inspector")
	text, isErr := f.call(t, itok.Secret, "get_logs", map[string]any{"clusterId": f.clusterA, "namespace": "default", "pod": "x"})
	if !isErr || !strings.Contains(text, "not connected") {
		t.Errorf("get_logs on a disconnected cluster: %v %q", isErr, text)
	}
	if a := f.lastAudit(t, inspector, "mcp:tool_call"); a.outcome != audit.OutcomeError || a.details["tool"] != "get_logs" ||
		a.details["args"].(map[string]any)["pod"] != "x" {
		t.Errorf("get_logs audit row = %+v", a)
	}
}

func TestPersonalTokenClusterScopeIsTheOwnersScope(t *testing.T) {
	f := newMCPFixture(t)
	// Inspect on cluster A only.
	scoped := f.user(t, fmt.Sprintf(`{"type":"Cluster","clusterId":%q}`, f.clusterA),
		authz.CapMCPUse, authz.CapClusterRead, authz.CapClusterInspect)
	tok, rec := f.createToken(t, scoped, "scoped")
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", rec.Code, rec.Body.String())
	}
	text, _ := f.call(t, tok.Secret, "list_clusters", nil)
	if !strings.Contains(text, f.clusterA) || strings.Contains(text, f.clusterB) {
		t.Errorf("list_clusters for a cluster-A-only grant: %s", text)
	}
	// Cluster B is not visible at all — the same answer as a cluster that
	// does not exist.
	text, isErr := f.call(t, tok.Secret, "describe_resource", map[string]any{"clusterId": f.clusterB, "gvk": "v1/Pod", "namespace": "default", "name": "x"})
	if !isErr || !strings.Contains(text, "no active cluster") {
		t.Errorf("describe on an out-of-scope cluster: %v %q", isErr, text)
	}
}

func TestPersonalTokenRefusedWhenExpiredRevokedDisabledOrWithoutMCPUse(t *testing.T) {
	f := newMCPFixture(t)
	ctx := context.Background()

	// Without mcp:use a token cannot be minted ...
	noMCP := f.user(t, allClusters, authz.CapClusterRead)
	if _, rec := f.createToken(t, noMCP, "x"); rec.Code != http.StatusForbidden {
		t.Errorf("create without mcp:use: %d, want 403", rec.Code)
	}
	// ... and one minted before it was withdrawn stops working.
	stale := insertTokenForTest(t, f, noMCP, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	if e, ok := f.rpc(t, stale, "tools/list", nil)["error"].(map[string]any); !ok || !strings.Contains(e["message"].(string), "mcp:use") || f.lastStatus != http.StatusForbidden {
		t.Errorf("token whose owner lacks mcp:use: %v", e)
	}

	holder := f.user(t, allClusters, authz.CapMCPUse, authz.CapClusterRead)
	expired := insertTokenForTest(t, f, holder, time.Now().Add(-48*time.Hour), time.Now().Add(-time.Hour))
	if _, err := f.s.lookupPersonalToken(ctx, expired); err != errPersonalTokenInvalid {
		t.Errorf("expired token: err = %v, want errPersonalTokenInvalid", err)
	}

	live := insertTokenForTest(t, f, holder, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	owner, err := f.s.lookupPersonalToken(ctx, live)
	if err != nil || owner.UserID != holder {
		t.Fatalf("live token: %+v %v", owner, err)
	}
	// A wrong secret for a real id is refused.
	id, _, _ := parsePersonalToken(live)
	forged := personalTokenPrefix + strings.TrimPrefix(id, "pat_") + "_" + strings.Repeat("0", 64)
	if _, err := f.s.lookupPersonalToken(ctx, forged); err != errPersonalTokenInvalid {
		t.Errorf("forged secret: err = %v", err)
	}
	// Disabling the owner stops the token.
	execAsTenant(t, f, `UPDATE users SET disabled_at = now() WHERE id = $1`, holder)
	if _, err := f.s.lookupPersonalToken(ctx, live); err != errPersonalTokenInvalid {
		t.Errorf("token of a disabled user: err = %v", err)
	}
	// last_used_at was stamped by the successful lookup.
	tx, _ := f.pool.Begin(ctx)
	defer tx.Rollback(ctx) //nolint:errcheck
	_ = data.SetRequestScope(ctx, tx, f.tenantID, nil)
	var used *time.Time
	_ = tx.QueryRow(ctx, `SELECT last_used_at FROM mcp_personal_tokens WHERE id = $1`, id).Scan(&used)
	if used == nil {
		t.Error("last_used_at was not stamped")
	}
}

func TestPersonalTokenTableIsTenantScoped(t *testing.T) {
	f := newMCPFixture(t)
	u := f.user(t, allClusters, authz.CapMCPUse)
	insertTokenForTest(t, f, u, time.Now(), time.Now().Add(time.Hour))
	ctx := context.Background()
	for _, tc := range []struct {
		tenant string
		want   bool
	}{{f.tenantID, true}, {"org_someone_else", false}, {"", false}} {
		tx, err := f.pool.Begin(ctx)
		if err != nil {
			t.Fatalf("begin: %v", err)
		}
		_ = data.SetRequestScope(ctx, tx, tc.tenant, nil)
		var n int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM mcp_personal_tokens WHERE user_id = $1`, u).Scan(&n); err != nil {
			t.Fatalf("count: %v", err)
		}
		_ = tx.Rollback(ctx)
		if (n > 0) != tc.want {
			t.Errorf("tenant %q sees %d of the user's tokens, want visible=%v", tc.tenant, n, tc.want)
		}
	}
}

// insertTokenForTest writes a token row directly (bypassing the create
// route's capability gate and lifetime bounds) and returns its secret.
func insertTokenForTest(t *testing.T, f *mcpFixture, userID string, created, expires time.Time) string {
	t.Helper()
	id := domain.NewID(domain.PrefixPersonalToken)
	token, hash, hint, err := newPersonalTokenSecret(id)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	execAsTenant(t, f, `INSERT INTO mcp_personal_tokens (id, tenant_id, user_id, name, token_hash, token_hint, created_at, expires_at)
		VALUES ($1, $2, $3, 'test', $4, $5, $6, $7)`, id, f.tenantID, userID, hash, hint, created, expires)
	return token
}

func execAsTenant(t *testing.T, f *mcpFixture, sql string, args ...any) {
	t.Helper()
	ctx := context.Background()
	tx, err := f.pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if err := data.SetRequestScope(ctx, tx, f.tenantID, nil); err != nil {
		t.Fatalf("scope: %v", err)
	}
	if _, err := tx.Exec(ctx, sql, args...); err != nil {
		t.Fatalf("exec %q: %v", sql, err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit: %v", err)
	}
}

// resolveTenantScope resolves the single organisation and scopes tx to it —
// the step every path with no session behind it takes first.
func resolveTenantScope(ctx context.Context, tx pgx.Tx) (string, error) {
	tenantID, err := data.SingleOrganisationID(ctx, tx)
	if err != nil {
		return "", fmt.Errorf("resolve organisation: %w", err)
	}
	if err := data.SetRequestScope(ctx, tx, tenantID, nil); err != nil {
		return "", fmt.Errorf("set request scope: %w", err)
	}
	return tenantID, nil
}
