package api

// PROJECT.md AD3 — the parts of the personal-token MCP surface that need no
// database: token format, the request bounds, the tool surface's read-only
// shape, argument checking and the rate limiter. The DB-backed half
// (lifecycle, RLS, capability enforcement per tool, audit rows) is
// mcp_user_db_test.go.

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"

	"argus/internal/authz"
	"argus/internal/domain"
)

func TestPersonalTokenRoundTrip(t *testing.T) {
	id := domain.NewID(domain.PrefixPersonalToken)
	token, hash, hint, err := newPersonalTokenSecret(id)
	if err != nil {
		t.Fatalf("newPersonalTokenSecret: %v", err)
	}
	if !strings.HasPrefix(token, personalTokenPrefix) {
		t.Errorf("token %q does not start with %q — secret scanners key on the prefix", token, personalTokenPrefix)
	}
	gotID, secret, ok := parsePersonalToken(token)
	if !ok || gotID != id {
		t.Fatalf("parsePersonalToken(%q) = %q, ok=%v; want id %q", token, gotID, ok, id)
	}
	if hashPersonalTokenSecret(secret) != hash {
		t.Error("the stored hash is not the hash of the presented secret")
	}
	if strings.Contains(hash, secret) || hash == secret {
		t.Error("the stored value contains the secret")
	}
	if !strings.HasSuffix(secret, hint) || len(hint) != 4 {
		t.Errorf("hint %q is not the secret's last four characters", hint)
	}

	// Two tokens never share a secret.
	other, _, _, _ := newPersonalTokenSecret(id)
	if other == token {
		t.Error("two mints produced the same token")
	}
}

func TestParsePersonalTokenRejectsAnythingElse(t *testing.T) {
	id := domain.NewID(domain.PrefixPersonalToken)
	good, _, _, _ := newPersonalTokenSecret(id)
	ulid := strings.TrimPrefix(id, "pat_")
	for name, tok := range map[string]string{
		"empty":             "",
		"no prefix":         strings.TrimPrefix(good, personalTokenPrefix),
		"a JWT":             "eyJhbGciOiJFUzI1NiJ9.e30.sig",
		"short secret":      personalTokenPrefix + ulid + "_abcd",
		"non-hex secret":    personalTokenPrefix + ulid + "_" + strings.Repeat("z", 64),
		"uppercase ulid":    personalTokenPrefix + strings.ToUpper(ulid) + "_" + strings.Repeat("a", 64),
		"short ulid":        personalTokenPrefix + ulid[:10] + "_" + strings.Repeat("a", 64),
		"sql in ulid slot":  personalTokenPrefix + "'or'1'='1'--aaaaaaaaaaaaaa_" + strings.Repeat("a", 64),
		"extra underscore":  good + "_x",
		"CLI runner tokens": "q2Y7k1Jx9z0aBcDeFgHiJkLmNoPqRsTuVwXyZ012345",
	} {
		if _, _, ok := parsePersonalToken(tok); ok {
			t.Errorf("%s: parsePersonalToken(%q) accepted it", name, tok)
		}
	}
}

func TestValidatePersonalTokenRequest(t *testing.T) {
	days := func(n int) *int { return &n }
	if name, d, p := validatePersonalTokenRequest(createPersonalTokenRequest{Name: "  laptop claude  "}); p != "" || name != "laptop claude" || d != personalTokenDefaultDays {
		t.Errorf("default: got %q %d %q, want trimmed name and %d days", name, d, p, personalTokenDefaultDays)
	}
	if _, d, p := validatePersonalTokenRequest(createPersonalTokenRequest{Name: "x", ExpiresInDays: days(personalTokenMaxDays)}); p != "" || d != personalTokenMaxDays {
		t.Errorf("a year exactly must be allowed: %d %q", d, p)
	}
	for name, req := range map[string]createPersonalTokenRequest{
		"blank name":       {Name: "   "},
		"long name":        {Name: strings.Repeat("n", maxPersonalTokenNameLen+1)},
		"zero days":        {Name: "x", ExpiresInDays: days(0)},
		"negative days":    {Name: "x", ExpiresInDays: days(-5)},
		"more than a year": {Name: "x", ExpiresInDays: days(personalTokenMaxDays + 1)},
	} {
		if _, _, p := validatePersonalTokenRequest(req); p == "" {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestPersonalTokenStatus(t *testing.T) {
	now := time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC)
	revoked := now.Add(-time.Hour)
	if s := personalTokenStatusAt(now, now.Add(time.Hour), nil); s != personalTokenActive {
		t.Errorf("unexpired, unrevoked = %q", s)
	}
	if s := personalTokenStatusAt(now, now, nil); s != personalTokenExpired {
		t.Errorf("expiring exactly now = %q, want expired", s)
	}
	if s := personalTokenStatusAt(now, now.Add(time.Hour), &revoked); s != personalTokenRevoked {
		t.Errorf("revoked = %q", s)
	}
}

// The surface's whole safety argument is what it contains. A remediation
// action, approval or anything that writes appearing here would be reachable
// by every person's AI tool.
func TestUserMCPSurfaceIsReadOnly(t *testing.T) {
	// Matched against whole name segments, so "diagnose_autoscaler" is not
	// mistaken for "scale".
	writeWords := []string{"scale", "restart", "patch", "delete", "create", "annotate", "label", "revert",
		"approve", "reject", "rollback", "dry", "execute", "apply", "dismiss", "resolve", "tolerate",
		"open", "close", "reevaluate", "update", "set", "write", "exec"}
	allowedCaps := map[string]bool{authz.CapClusterRead: true, authz.CapClusterInspect: true, authz.CapIncidentRead: true}
	seen := map[string]bool{}
	for _, tool := range userMCPCatalogue() {
		if seen[tool.name] {
			t.Errorf("tool %q listed twice", tool.name)
		}
		seen[tool.name] = true
		for _, w := range writeWords {
			if slices.Contains(strings.Split(tool.name, "_"), w) {
				t.Errorf("tool %q looks like a write (%q) — the personal surface is read-only", tool.name, w)
			}
		}
		if !allowedCaps[tool.capability] {
			t.Errorf("tool %q is gated on %q; every personal-surface tool must need one of the read capabilities", tool.name, tool.capability)
		}
		if tool.run == nil {
			t.Errorf("tool %q has no executor", tool.name)
		}
		var schema map[string]any
		if err := json.Unmarshal(tool.toolSchema(), &schema); err != nil || schema["type"] != "object" {
			t.Errorf("tool %q: schema is not an object schema: %s", tool.name, tool.toolSchema())
		}
		if tool.clusterScoped {
			req, _ := schema["required"].([]any)
			if len(req) == 0 || req[0] != "clusterId" {
				t.Errorf("cluster tool %q does not require clusterId: %v", tool.name, schema["required"])
			}
		}
	}
	// Exactly the inspect allowlist, no more: the same set POST
	// /clusters/{id}/inspect serves.
	for name := range inspectableTools {
		if !seen[name] {
			t.Errorf("inspect tool %q is missing from the personal surface", name)
		}
	}
	for _, name := range []string{"list_clusters", "get_cluster", "list_incidents", "get_incident", "get_incident_timeline", "list_findings", "search_fleet_objects"} {
		if !seen[name] {
			t.Errorf("hub-side tool %q is missing", name)
		}
	}
	for _, name := range []string{"list_resources", "dry_run_patch", "scale_deployment", "query_metrics", "read_repo_file"} {
		if seen[name] {
			t.Errorf("%q is on the personal surface but not on the inspect allowlist", name)
		}
	}
}

func TestInspectToolSchemasMatchTheAgentArguments(t *testing.T) {
	// The hand-written schemas are the model's only guide to the agent's
	// argument structs; spot-check the ones a typo would break silently.
	byName := map[string]userMCPTool{}
	for _, tool := range userMCPCatalogue() {
		byName[tool.name] = tool
	}
	for tool, args := range map[string][]string{
		"get_logs":           {"namespace", "pod", "container", "previous", "tailLines"},
		"describe_resource":  {"gvk", "namespace", "name"},
		"explain_scheduling": {"namespace", "pod"},
		"get_neighborhood":   {"kind", "apiGroup", "namespace", "name", "hops", "maxNodes", "profile"},
		"search_objects":     {"query", "namespace", "limit"},
	} {
		for _, a := range args {
			if _, ok := byName[tool].properties[a]; !ok {
				t.Errorf("%s: schema has no %q argument", tool, a)
			}
		}
	}
	if !strings.Contains(byName["get_logs"].description, "audit log") {
		t.Error("get_logs' description should say every read is audited")
	}
}

func TestCheckUserMCPArgs(t *testing.T) {
	var listIncidents, getLogs userMCPTool
	for _, tool := range userMCPCatalogue() {
		switch tool.name {
		case "list_incidents":
			listIncidents = tool
		case "get_logs":
			getLogs = tool
		}
	}
	ok := func(tool userMCPTool, raw string) {
		t.Helper()
		if _, err := checkUserMCPArgs(tool, json.RawMessage(raw)); err != nil {
			t.Errorf("%s %s: unexpected refusal %v", tool.name, raw, err)
		}
	}
	bad := func(tool userMCPTool, raw, want string) {
		t.Helper()
		_, err := checkUserMCPArgs(tool, json.RawMessage(raw))
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s %s: err = %v, want one mentioning %q", tool.name, raw, err, want)
		}
	}
	ok(listIncidents, ``)
	ok(listIncidents, `{}`)
	ok(listIncidents, `{"state":"Detected","severity":"high","limit":10}`)
	bad(listIncidents, `{"status":"Detected"}`, `does not take "status"`)
	bad(listIncidents, `{"severity":"apocalyptic"}`, "severity must be one of")
	bad(listIncidents, `{"limit":5000}`, "at most 200")
	bad(listIncidents, `[1,2]`, "JSON object")

	ok(getLogs, `{"clusterId":"rke2","namespace":"default","pod":"web-1"}`)
	bad(getLogs, `{"namespace":"default","pod":"web-1"}`, "clusterId is required")
	bad(getLogs, `{"clusterId":"rke2","namespace":"default"}`, "pod is required")
}

func TestTokenRateLimiter(t *testing.T) {
	now := time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC)
	l := newTokenRateLimiter(3, 60, func() time.Time { return now })
	for i := 0; i < 3; i++ {
		if ok, _ := l.allow("pat_a"); !ok {
			t.Fatalf("call %d of the burst refused", i+1)
		}
	}
	ok, wait := l.allow("pat_a")
	if ok || wait <= 0 || wait > time.Second {
		t.Fatalf("4th call: ok=%v wait=%v; want refused with a wait of at most 1s at 60/min", ok, wait)
	}
	// Another token has its own bucket.
	if ok, _ := l.allow("pat_b"); !ok {
		t.Error("a different token was refused by pat_a's bucket")
	}
	now = now.Add(time.Second)
	if ok, _ := l.allow("pat_a"); !ok {
		t.Error("one second at 60/min should refill one call")
	}
}
