package api

// route_coverage_test.go is the second half of PROJECT.md F33, and the half
// openapi_contract_test.go could never provide.
//
// That file (and its _db_test.go sibling) is a genuinely good drift detector
// for the routes docs/openapi.yaml already describes: it decodes real handler
// responses and validates them against the spec's own JSON Schema, so a
// handler that renames or retypes a DOCUMENTED field fails a test. What it
// cannot see is a route the spec never mentions. On 2026-09-24 that was 56 of
// the 103 routes internal/api/server.go registers — every one of them free to
// change shape, or to be added in the first place, with nothing anywhere going
// red.
//
// So this file asserts coverage rather than shape: every registered route is
// either documented in docs/openapi.yaml or named in undocumentedRoutes below
// with a written reason. What it buys is the ratchet. An entry can be deleted
// (by documenting the route); adding one is a visible, reviewable line in a
// diff rather than a silent omission.
//
// The retro-documenting pass F33 called for has since been done: 49 of those
// 56 are now in docs/openapi.yaml, as are the routes added since, and the
// seven that remain are the ones that should never be there — two probes and
// a Prometheus scrape target, the SPA catch-all and the WebSocket upgrade,
// and the two demo-data routes a real deployment does not register at all. Every one of their categories is marked
// "(permanent)" and says why in the entry itself, so the next reader does not
// spend an afternoon re-deciding what was already decided. A future addition to
// this list is a new decision and is held to that same standard.
//
// Like internal/migrations/schema_coverage_test.go and
// internal/data/scope_structural_test.go — whose shape this file follows on
// purpose — it fails in BOTH directions:
//
//   - a registered route that is neither documented nor declared fails, so a
//     new handler cannot join the undocumented set quietly;
//   - a declared route that IS now documented fails, so the list cannot
//     over-claim;
//   - a declared route that is no longer registered fails, so the list cannot
//     rot into a description of a codebase that no longer exists;
//   - a documented operation with no registered route fails, so the spec
//     cannot describe an endpoint that was deleted.
//
// # How the registered routes are enumerated
//
// By PARSING internal/api's own source with go/ast — every string literal
// handed to a .HandleFunc(...) call in a non-test file of this package — not
// by keeping a second hand-written list here. A hand-written list would be
// exactly the drift this test exists to catch, one file over. A route
// registered with a computed (non-literal) pattern is reported as an error
// rather than skipped, because a pattern this test cannot read is a hole in
// the enumeration, not an exemption from it.

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// undocumentedRouteCategories are the reasons a registered route may be
// absent from docs/openapi.yaml. Every entry in undocumentedRoutes below
// starts with one of these, so the list stays readable as a set of
// *decisions* rather than 56 unrelated sentences — the same thing
// notImplementedTables' three grouped reasons do for the schema registry.
//
// A category is not an excuse on its own: the text after it must say what is
// true of THIS route. TestEveryUndocumentedRouteGivesAReason enforces both
// halves, and TestEveryUndocumentedRouteCategoryIsUsed deletes a category
// that stops applying.
var undocumentedRouteCategories = map[string]string{
	"operational (permanent)": "a probe or telemetry surface, deliberately outside the product API a client codes against. SETTLED rather than pending: all three also sit outside docs/openapi.yaml's own servers[0].url of /api/v1, so this spec has no path they could be written at even if someone wanted to",

	"transport (permanent)": "the go:embed'd SPA and the WebSocket upgrade. SETTLED rather than pending: neither has a JSON request or response to describe, both sit outside /api/v1 and therefore outside this spec's server prefix, and OpenAPI 3.1 has no vocabulary for frames. The one half of that handshake which IS a JSON contract, POST /api/v1/ws/ticket, is documented",

	"dev-only (permanent)": "registered only behind s.demoDataEnabled (ARGUS_ENABLE_DEMO_DATA), so it does not exist at all in a real deployment. SETTLED rather than pending: a generated client offering a call that 404s everywhere it matters would be worse than the silence — the same reasoning TestEveryDocumentedOperationIsRegistered enforces in the other direction",
}

// undocumentedRoutes is what is left of F33's snapshot: the routes
// internal/api/server.go registers that docs/openapi.yaml deliberately does
// not describe, each with why. Keyed by the route pattern exactly as
// server.go registers it.
//
// It started at 56 and is now seven, and those seven are a decision rather
// than a backlog — see the categories above, all of which say so in the word
// "(permanent)".
//
// THIS LIST IS A RATCHET. Deleting an entry (because the route is now
// documented) is always welcome and needs no other change. Adding one is
// allowed — some routes genuinely should not be in a client contract — but it
// is a deliberate line in a diff that a reviewer sees, which is the entire
// point of the mechanism.
var undocumentedRoutes = map[string]string{
	// --- operational -----------------------------------------------------
	"GET /healthz": "operational (permanent) — liveness probe for the container runtime and compose/Helm healthchecks. Fixed body, no client codes against it.",
	"GET /readyz":  "operational (permanent) — readiness probe. Its answer is derived from migration state and data.DB.CheckRLSPreconditions; consumed by Kubernetes and by ci.yml's bootstrap step, never by the web UI.",
	"GET /metrics": "operational (permanent) — Prometheus text exposition, not JSON. Its real contract is the metric names in internal/api/metrics.go plus a scrape config, which an OpenAPI response schema cannot express.",

	// --- transport -------------------------------------------------------
	"GET /":          "transport (permanent) — the catch-all that serves the go:embed'd SPA and its history fallback (internal/api/static.go). There is no request or response schema to describe.",
	"GET /ws/events": "transport (permanent) — a WebSocket upgrade, deliberately outside /api/v1. What it then carries is a filtered event stream (ws.go's wsEventScope), and OpenAPI 3.1 has no vocabulary for frames.",

	// --- dev-only ---------------------------------------------------------
	"POST /api/v1/demo-data":   "dev-only (permanent) — registered only when s.demoDataEnabled (ARGUS_ENABLE_DEMO_DATA, PROJECT.md D14). On a real install the mux has no pattern for it and the request 404s before auth; a documented route that does not exist would be worse than an undocumented one.",
	"DELETE /api/v1/demo-data": "dev-only (permanent) — the teardown half of the pair above, registered under the same flag and absent for the same reason.",
}

// --- enumeration -----------------------------------------------------------

// registeredRoute is one pattern handed to .HandleFunc in this package.
type registeredRoute struct {
	Pattern string // "GET /api/v1/incidents/{id}", verbatim from the source
	File    string
	Line    int
}

// registeredRoutes parses every non-test .go file in this package and returns
// the route pattern of each .HandleFunc call. Source parsing rather than a
// second hand-maintained list: a list here would drift from server.go exactly
// the way docs/openapi.yaml already has, and this test would then be checking
// one stale artifact against another.
//
// The whole package is scanned, not just server.go, so moving a group of
// routes into a file of their own does not silently empty this test.
func registeredRoutes(t *testing.T) []registeredRoute {
	t.Helper()

	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package directory: %v", err)
	}
	var files []string
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		files = append(files, name)
	}
	sort.Strings(files)

	var routes []registeredRoute
	for _, name := range files {
		src, err := os.ReadFile(name)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, name, src, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "HandleFunc" || len(call.Args) == 0 {
				return true
			}
			line := fset.Position(call.Pos()).Line
			lit, ok := call.Args[0].(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				// A computed pattern is a hole in this enumeration, not an
				// exemption from it: the route would be invisible to every
				// check below and could never be matched by an allowlist
				// entry either. Fail loudly and make the author write a
				// literal.
				t.Errorf("%s:%d registers a route with a non-literal pattern. This test enumerates routes by reading the source, so a computed pattern cannot be checked for documentation at all — register it with a string literal.", name, line)
				return true
			}
			pattern, err := strconv.Unquote(lit.Value)
			if err != nil {
				t.Errorf("%s:%d: cannot unquote route pattern %s: %v", name, line, lit.Value, err)
				return true
			}
			routes = append(routes, registeredRoute{Pattern: pattern, File: name, Line: line})
			return true
		})
	}

	if len(routes) == 0 {
		t.Fatal("found no .HandleFunc calls in internal/api at all — the parser or the package layout changed, and every check in this file would pass vacuously")
	}
	return routes
}

// pathParam matches one templated path segment, in either a Go 1.22 ServeMux
// pattern or an OpenAPI path.
var pathParam = regexp.MustCompile(`\{[^}/]*\}`)

// routeKey is the comparable form of a route: method plus path with every
// path parameter reduced to `{}`.
//
// Parameter NAMES are normalised away on purpose. server.go and
// docs/openapi.yaml name the same parameter independently, so requiring them
// to agree would make a documentation nit ("evId" vs "evidenceId") report
// itself as a coverage hole — two errors, neither of them true. The shape of
// the path is what decides whether a route is documented; the raw pattern is
// what gets printed in every failure below.
func routeKey(method, path string) string {
	return strings.ToUpper(method) + " " + pathParam.ReplaceAllString(path, "{}")
}

// documentedOperations maps the routeKey of every operation in
// docs/openapi.yaml to a printable "METHOD /path" for error messages. Paths
// are prefixed with the spec's own server URL, read from the spec rather than
// hardcoded as "/api/v1", so re-versioning the API moves both sides at once.
func documentedOperations(t *testing.T) map[string]string {
	t.Helper()
	doc := loadOpenAPISpec(t)

	if len(doc.Servers) == 0 || doc.Servers[0].URL == "" {
		t.Fatal("docs/openapi.yaml declares no servers[0].url — every path below is relative to it, so this test cannot build a comparable route without it")
	}
	prefix := strings.TrimSuffix(doc.Servers[0].URL, "/")

	ops := map[string]string{}
	for path, item := range doc.Paths.Map() {
		for method := range item.Operations() {
			full := prefix + path
			ops[routeKey(method, full)] = strings.ToUpper(method) + " " + full
		}
	}
	if len(ops) == 0 {
		t.Fatal("docs/openapi.yaml declares no operations — the spec failed to load in a way Validate did not catch")
	}
	return ops
}

// --- the checks ------------------------------------------------------------

// TestEveryRegisteredRouteIsDocumentedOrDeclared is F33's first acceptance
// criterion: a handler cannot be added without either a spec entry or an
// explicit, reasoned exemption.
func TestEveryRegisteredRouteIsDocumentedOrDeclared(t *testing.T) {
	documented := documentedOperations(t)

	var undeclared []string
	for _, r := range registeredRoutes(t) {
		key := routeKey(methodAndPath(r.Pattern))
		_, isDocumented := documented[key]
		reason, isDeclared := undocumentedRoutes[r.Pattern]

		switch {
		case isDocumented && isDeclared:
			t.Errorf("%s:%d: %q is documented in docs/openapi.yaml AND listed in undocumentedRoutes (%q) — drop the entry, so the list stays a true index of what is NOT covered", r.File, r.Line, r.Pattern, reason)
		case !isDocumented && !isDeclared:
			undeclared = append(undeclared, fmt.Sprintf("  %s   (%s:%d)", r.Pattern, r.File, r.Line))
		}
	}

	if len(undeclared) > 0 {
		sort.Strings(undeclared)
		t.Errorf(`%d registered route(s) are neither documented in docs/openapi.yaml nor declared in undocumentedRoutes:

%s

A route that is in neither place is invisible: openapi_contract_test.go cannot
check a shape it has never been told about, and web/src/api/generated.ts will
never mention it. Do one of two things:

  - add the path and operation to docs/openapi.yaml (the contract test will
    then hold its response shape to what you wrote); or
  - add it to undocumentedRoutes in %s with a reason
    beginning with one of the categories listed above it.

Adding an entry is a legitimate answer — probes and WebSocket upgrades are on
that list for good reasons. Leaving a route in neither place is not.`,
			len(undeclared), strings.Join(undeclared, "\n"), "internal/api/route_coverage_test.go")
	}
}

// TestUndocumentedRoutesHaveNoGhosts is the other direction, and the reason
// this file is a test rather than a paragraph in docs/openapi.yaml: an entry
// naming a route that no longer exists reads as coverage of something real.
// The prose route list in that spec's own description had already gone stale
// twice before F33 ("roughly 70 routes") — that is the failure mode.
func TestUndocumentedRoutesHaveNoGhosts(t *testing.T) {
	registered := map[string]bool{}
	for _, r := range registeredRoutes(t) {
		registered[r.Pattern] = true
	}
	for pattern, reason := range undocumentedRoutes {
		if !registered[pattern] {
			t.Errorf("undocumentedRoutes lists %q (%q), which internal/api no longer registers — the route was renamed or deleted; drop the entry", pattern, reason)
		}
	}
}

// TestEveryUndocumentedRouteGivesAReason keeps the list from degenerating
// into 56 bare route names, which would carry exactly as much information as
// having no list. A category alone is not enough either: the sentence after
// it has to say something about THIS route.
func TestEveryUndocumentedRouteGivesAReason(t *testing.T) {
	for pattern, reason := range undocumentedRoutes {
		category, rest, ok := strings.Cut(reason, " — ")
		if !ok {
			t.Errorf("undocumentedRoutes[%q]: reason %q does not start with a category. Write it as \"<category> — <why this route>\", where <category> is one of the keys of undocumentedRouteCategories.", pattern, reason)
			continue
		}
		if _, known := undocumentedRouteCategories[category]; !known {
			t.Errorf("undocumentedRoutes[%q]: %q is not one of the declared categories (%s). Either use one, or add a new category to undocumentedRouteCategories saying what it means.", pattern, category, strings.Join(sortedKeys(undocumentedRouteCategories), ", "))
		}
		if len(strings.TrimSpace(rest)) < 30 {
			t.Errorf("undocumentedRoutes[%q]: %q is a category with no explanation after it — say what is true of this route, not just which bucket it is in", pattern, reason)
		}
	}
}

// TestEveryUndocumentedRouteCategoryIsUsed stops the category list rotting
// the same way the route list could. A category nothing is in any more is a
// decision that no longer applies, and leaving it reads as though some route
// still needs it.
func TestEveryUndocumentedRouteCategoryIsUsed(t *testing.T) {
	used := map[string]bool{}
	for _, reason := range undocumentedRoutes {
		if category, _, ok := strings.Cut(reason, " — "); ok {
			used[category] = true
		}
	}
	for category, meaning := range undocumentedRouteCategories {
		if !used[category] {
			t.Errorf("undocumentedRouteCategories declares %q (%q) and no route uses it — every route in that bucket has been documented, so drop the category too", category, meaning)
		}
	}
}

// TestEveryDocumentedOperationIsRegistered is the fourth direction: the spec
// must not describe an endpoint that does not exist. A client generated from
// docs/openapi.yaml (web/src/api/generated.ts is exactly that) would offer a
// call that 404s, and the shape-checking contract test cannot notice, because
// there is no handler for it to compare against.
func TestEveryDocumentedOperationIsRegistered(t *testing.T) {
	registered := map[string]bool{}
	for _, r := range registeredRoutes(t) {
		registered[routeKey(methodAndPath(r.Pattern))] = true
	}
	var orphans []string
	for key, display := range documentedOperations(t) {
		if !registered[key] {
			orphans = append(orphans, display)
		}
	}
	if len(orphans) > 0 {
		sort.Strings(orphans)
		t.Errorf(`docs/openapi.yaml documents %d operation(s) that internal/api does not register:

  %s

Either the route was renamed or removed and the spec was not updated, or the
spec's path has a typo. Both produce a generated client with a method that
404s.`, len(orphans), strings.Join(orphans, "\n  "))
	}
}

// methodAndPath splits a Go 1.22 ServeMux pattern ("GET /api/v1/incidents")
// into its two halves. A pattern with no method registers for every method;
// none exist in this package today, and the empty method it would produce
// cannot match any documented operation, which is the safe direction.
func methodAndPath(pattern string) (method, path string) {
	method, path, ok := strings.Cut(pattern, " ")
	if !ok {
		return "", pattern
	}
	return method, path
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
