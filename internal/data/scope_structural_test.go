package data_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// This file is the enforcement half of PROJECT.md G11, and it is a test rather
// than a convention for the same reason internal/agent/redact_egress_test.go
// is: the thing that failed was never "somebody wrote a wrong query," it was
// "somebody added a path and nothing made them think about scope."
//
// Four RLS mistakes are on the record here — the bootstrap insert,
// refresh-token issuance, refresh-token rotation, and PROJECT.md B175's DELETE
// that ran unscoped, matched nothing under FORCE ROW LEVEL SECURITY, removed
// 0 rows and reported no error. Every one of them was fixed correctly. None
// of the fixes stopped the next one.
//
// Two rules, checked separately because they are different promises:
//
//   - TestEveryRawBeginEitherScopesItselfOrIsDeclaredPreScope is the
//     repo-wide floor. Anywhere in internal/ or cmd/, a function that opens
//     its own transaction off the pool has to set scope on it. The exceptions
//     are code that genuinely runs before any tenant exists, and they are
//     listed below with the reason each one is allowed.
//
//   - TestBackgroundWorkersCannotOpenAnUnscopedTransaction is the stronger
//     promise G11 was actually about. In the sweepers and reconcilers there
//     is no raw Begin at all: they go through data.InScope / InFleetScope /
//     ReadInScope, which hand out an already-scoped pgx.Tx and own the
//     commit, so there is no moment at which an unscoped transaction exists
//     for a future author to use by accident.
//
// Both fail in both directions. An allowlist entry that has been converted,
// or whose function has been renamed or deleted, fails too — otherwise the
// list rots into a description of a codebase that no longer exists, which is
// how the stale claims in argus-context happened.

// preScopeBegins are the functions that may open a transaction off the pool
// without setting RLS scope on it, and why each one may.
//
// Keyed by "<path from repo root>:<function name>". A method's key uses its
// bare name (handleEnroll, not (*Server).handleEnroll) — there is no
// overloading in Go, and the path already disambiguates.
var preScopeBegins = map[string]string{
	"internal/authz/bootstrap.go:EnsureBootstrap": "first boot. This runs before any organisation row exists, so there is no tenant_id to scope by — it is the code that creates the thing every other tenant_id references. lld/02-authz-spec.md §10.2 and migration 000016's comment both name it as the precedent for this category.",

	"internal/data/signingkeys.go:LoadOrCreateSigningKey": "signing_keys has no RLS policy and deliberately so — migration 000016's comment spells it out: the keys are organisation-wide (one signer per purpose, not one per tenant) and every read/write happens from hub startup before any request scope exists. A tenant_id-keyed policy here would be actively wrong, not merely unnecessary.",

	"internal/api/enroll.go:handleEnroll": "the unauthenticated agent-enrollment route: there is no session, so there is nothing to resolve a tenant from yet. Scope IS set inside this transaction, one call later — enrollmentSigner.RedeemEnrollmentToken resolves the token's tenant and calls SetRequestScope itself, then returns that tenant to the handler. Same no-prior-session pattern as authz.RotateRefreshToken.",

	"internal/gateway/polarity_gate.go:applyConditionPolarityGate": "condition_polarity has no RLS policy, for the reason migration 000087's comment gives: a condition's polarity is a property of a Kubernetes Kind's own API, identical for every tenant, and this gate runs on the finding-ingestion path before an incident (and therefore a tenant scope) exists. Scoping it would buy nothing and would reintroduce the startup/call-ordering bug class this codebase has already hit.",

	"internal/dbtest/fixture.go:runCleanup": "test infrastructure, and the one place that is allowed to be generic about scope: runCleanup takes the setScope callback as a parameter precisely so each fixture supplies its own. This package exists because hand-written cleanup DELETEs destroyed real development data twice; routing it through data.InScope would fix the tenant at fixture-construction time and defeat that.",
}

// backgroundTransactionPaths are the files whose transactions must all come
// from data.InScope / InFleetScope / ReadInScope. A path is matched as a
// prefix, so naming a directory covers the package.
//
// These are the jobs with no request behind them: nothing upstream has set
// scope, nobody is watching a 500, and a query that silently matches zero
// rows looks exactly like a quiet fleet.
var backgroundTransactionPaths = []string{
	"internal/orchestrator/",
	"internal/notify/",
	"internal/autoanalyze/",
	"internal/gateway/health.go",
	// The execution reconciler, which moved to internal/execution with
	// PROJECT.md P23 (it was internal/execution/reconcile.go). Only the
	// reconciler: the rest of internal/execution runs under a caller's
	// already-scoped transaction (execution.Scope), and the three functions
	// there that deliberately open their own — recordExecutingTransition,
	// recordExecutionOutcome and recordUndoIntent, which must commit
	// separately from the request — set scope themselves and are held to that
	// by the repo-wide test above.
	"internal/execution/reconcile.go",
	"internal/api/unattended.go",
}

// backgroundRawBegins are the background call sites still opening their own
// transaction, and why each has not been converted. Same key format as
// preScopeBegins. Both of these set scope correctly today — they are on this
// list because the helper does not express their shape, not because they are
// wrong.
var backgroundRawBegins = map[string]string{
	"internal/autoanalyze/autoanalyze.go:investigateOne": "resolves the single organisation and then narrows scope to one cluster, which is neither InScope (no tenant in hand) nor InFleetScope (which widens to nil). It also commits mid-function on one branch and then keeps using the same transaction on the other, across the LLM investigation — restructuring that is a change to how long a transaction is held open during an investigation, which is its own decision and not this one. Sets scope correctly today.",

	"internal/autoanalyze/autoanalyze.go:closeStaleIncident": "same resolve-then-narrow-to-one-cluster shape as investigateOne above, and left with it so the two stale-sweep halves keep matching each other. Convertible once the helper grows a resolve-org-then-narrow form; sets scope correctly today.",
}

// repoRoot walks up from this package to the directory holding go.mod.
func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := filepath.Abs(".")
	if err != nil {
		t.Fatalf("resolve working directory: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("no go.mod above %s", dir)
		}
		dir = parent
	}
}

// beginSite is one call that opens a database transaction.
type beginSite struct {
	Key    string // "<relative path>:<enclosing function>"
	Rel    string
	Line   int
	Scoped bool // the enclosing function also sets scope, or uses a scoping helper
}

// scopingCalls are the names that count as "this function does set scope."
// SetRequestScope is the primitive; the three helpers call it and cannot be
// made not to.
var scopingCalls = map[string]bool{
	"SetRequestScope": true,
	"InScope":         true,
	"InFleetScope":    true,
	"ReadInScope":     true,
}

// looksLikeAPool reports whether the receiver of a .Begin() call is a
// connection pool rather than something else that happens to have a Begin
// method (internal/api's readLogs registry has one).
//
// Matched on the rendered receiver text rather than resolved types on
// purpose: this test must keep working without a type-checked build of every
// package, and the permissive direction is the dangerous one here, so it
// errs wide — "db" and "beginner" are included so that a future
// s.db.Begin(ctx) or a Beginner-typed parameter is caught rather than
// silently exempt.
func looksLikeAPool(recv string) bool {
	r := strings.ToLower(recv)
	return strings.Contains(r, "pool") || strings.Contains(r, "beginner") ||
		strings.Contains(r, "db.") || r == "db"
}

func exprText(src []byte, fset *token.FileSet, e ast.Expr) string {
	return string(src[fset.Position(e.Pos()).Offset:fset.Position(e.End()).Offset])
}

// collectAllGoFiles returns the repo-root-relative path of every non-test
// .go file under internal/ and cmd/ — the same file set collectBeginSites
// walks, without the AST parse. It backs the backgroundTransactionPaths
// ghost-entry check: a prefix that matches none of these paths names a file
// or directory that no longer exists.
func collectAllGoFiles(t *testing.T) []string {
	t.Helper()
	root := repoRoot(t)
	var files []string
	for _, top := range []string{"internal", "cmd"} {
		err := filepath.Walk(filepath.Join(root, top), func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if info.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			rel, err := filepath.Rel(root, path)
			if err != nil {
				return err
			}
			files = append(files, filepath.ToSlash(rel))
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", top, err)
		}
	}
	return files
}

// collectBeginSites parses every non-test .go file under internal/ and cmd/
// and returns each transaction-opening call it finds.
func collectBeginSites(t *testing.T) []beginSite {
	t.Helper()
	root := repoRoot(t)
	var sites []beginSite

	for _, top := range []string{"internal", "cmd"} {
		err := filepath.Walk(filepath.Join(root, top), func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if info.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			src, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			fset := token.NewFileSet()
			file, err := parser.ParseFile(fset, path, src, 0)
			if err != nil {
				return err
			}
			rel, err := filepath.Rel(root, path)
			if err != nil {
				return err
			}
			rel = filepath.ToSlash(rel)

			for _, decl := range file.Decls {
				fn, ok := decl.(*ast.FuncDecl)
				if !ok || fn.Body == nil {
					continue
				}
				var begins []*ast.CallExpr
				scoped := false
				ast.Inspect(fn.Body, func(n ast.Node) bool {
					call, ok := n.(*ast.CallExpr)
					if !ok {
						return true
					}
					sel, ok := call.Fun.(*ast.SelectorExpr)
					if !ok {
						// data.InScope(...) is a SelectorExpr too; a bare
						// SetRequestScope(...) inside package data is an Ident.
						if id, ok := call.Fun.(*ast.Ident); ok && scopingCalls[id.Name] {
							scoped = true
						}
						return true
					}
					if scopingCalls[sel.Sel.Name] {
						scoped = true
						return true
					}
					if sel.Sel.Name == "Begin" && looksLikeAPool(exprText(src, fset, sel.X)) {
						begins = append(begins, call)
					}
					return true
				})
				for _, b := range begins {
					sites = append(sites, beginSite{
						Key:    rel + ":" + fn.Name.Name,
						Rel:    rel,
						Line:   fset.Position(b.Pos()).Line,
						Scoped: scoped,
					})
				}
			}
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", top, err)
		}
	}
	if len(sites) == 0 {
		t.Fatal("found no pool.Begin call sites at all — the parser or the pool-receiver match is broken, and this test would pass vacuously")
	}
	return sites
}

func TestEveryRawBeginEitherScopesItselfOrIsDeclaredPreScope(t *testing.T) {
	sites := collectBeginSites(t)

	seen := map[string]bool{}
	scopedButListed := map[string]bool{}
	var unexplained []string

	for _, s := range sites {
		if reason, listed := preScopeBegins[s.Key]; listed {
			seen[s.Key] = true
			if s.Scoped {
				scopedButListed[s.Key] = true
				t.Errorf("%s:%d (%s) is listed in preScopeBegins (%q) but its function now sets scope — remove the entry so the list stays a true index of what runs before any tenant exists",
					s.Rel, s.Line, s.Key, reason)
			}
			continue
		}
		if !s.Scoped {
			unexplained = append(unexplained, s.Rel+":"+strconv.Itoa(s.Line)+" in "+s.Key)
		}
	}

	if len(unexplained) > 0 {
		sort.Strings(unexplained)
		t.Errorf(`%d transaction(s) are opened off the pool by a function that never sets RLS scope:

  %s

Under FORCE ROW LEVEL SECURITY an unscoped transaction does not fail — it
matches no row, so a SELECT returns nothing and a DELETE removes nothing,
both without an error. That is PROJECT.md B175 exactly.

Fix it one of two ways:
  - route the transaction through data.InScope / data.InFleetScope /
    data.ReadInScope, which hand back an already-scoped pgx.Tx and own the
    commit; or
  - if this really does run before any tenant exists, add it to
    preScopeBegins in %s with the reason it is safe.`,
			len(unexplained), strings.Join(unexplained, "\n  "), "internal/data/scope_structural_test.go")
	}

	for key, reason := range preScopeBegins {
		if !seen[key] && !scopedButListed[key] {
			t.Errorf("preScopeBegins lists %q (%q) but nothing there opens a transaction any more — the function was renamed, deleted or converted; drop the entry", key, reason)
		}
	}
}

func TestBackgroundWorkersCannotOpenAnUnscopedTransaction(t *testing.T) {
	sites := collectBeginSites(t)

	inBackground := func(rel string) bool {
		for _, p := range backgroundTransactionPaths {
			if strings.HasPrefix(rel, p) {
				return true
			}
		}
		return false
	}

	seen := map[string]bool{}
	var raw []string
	for _, s := range sites {
		if !inBackground(s.Rel) {
			continue
		}
		if _, listed := backgroundRawBegins[s.Key]; listed {
			seen[s.Key] = true
			continue
		}
		raw = append(raw, s.Rel+":"+strconv.Itoa(s.Line)+" in "+s.Key)
	}

	if len(raw) > 0 {
		sort.Strings(raw)
		t.Errorf(`%d background transaction(s) are opened directly off the pool:

  %s

Background work has no requireAuth above it to have scoped the transaction
already, and no operator watching a 500 — a sweep that silently matches zero
rows looks exactly like a quiet fleet. These go through data.InScope,
data.InFleetScope or data.ReadInScope, which never hand out an unscoped
transaction. If one genuinely cannot, add it to backgroundRawBegins with the
reason.`, len(raw), strings.Join(raw, "\n  "))
	}

	for key, reason := range backgroundRawBegins {
		if !seen[key] {
			t.Errorf("backgroundRawBegins lists %q (%q) but it no longer opens its own transaction — drop the entry", key, reason)
		}
	}

	// Ghost-entry detection for backgroundTransactionPaths itself: unlike
	// preScopeBegins and backgroundRawBegins above, this registry names
	// files/directories rather than functions, so "no longer matches
	// anything real" means "no file under internal/ or cmd/ has this
	// prefix" rather than "the function was renamed."
	allFiles := collectAllGoFiles(t)
	for _, p := range backgroundTransactionPaths {
		matched := false
		for _, f := range allFiles {
			if strings.HasPrefix(f, p) {
				matched = true
				break
			}
		}
		if !matched {
			t.Errorf("backgroundTransactionPaths lists %q but no file under internal/ or cmd/ matches that prefix — it was renamed, moved or deleted; update or drop the entry", p)
		}
	}
}

// TestTheScopingHelpersAreTheOnlyBeginInsideThem pins the property the two
// tests above are built on: the helpers themselves set scope, so "went
// through a helper" and "is scoped" are the same statement. If somebody
// removes the SetRequestScope call from InScope, this fails — and so does
// TestEveryRawBeginEitherScopesItselfOrIsDeclaredPreScope, because the
// helper's own Begin then has no scope call in its function either.
func TestTheScopingHelpersAreTheOnlyBeginInsideThem(t *testing.T) {
	for _, s := range collectBeginSites(t) {
		if s.Rel != "internal/data/scope.go" {
			continue
		}
		if !s.Scoped {
			t.Errorf("%s:%d (%s) opens a transaction and does not set scope — this IS the scoping helper; every caller's guarantee comes from this function", s.Rel, s.Line, s.Key)
		}
	}
}
