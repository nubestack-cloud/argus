package migrations_test

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"testing"
)

// BACKLOG P2: "16 tables have zero Go references. Drop them or mark them clearly
// ... it stops every future audit re-deriving the same confusion — that
// unreferenced-table set is currently the most reliable index of what is not
// built, which is useful, but only if the deliberately-empty ones are
// distinguishable from the merely-unbuilt ones."
//
// Marking them in prose would have gone stale the same way the backlog's own list
// did: it named `pull_requests` and `repository_bindings` as unreferenced, and both
// have had code since the Git integration landed. So this is a TEST, and it fails
// in BOTH directions:
//
//   - a table with no SQL usage and no registry entry fails, so a new table cannot
//     quietly join the dead set;
//   - a table in the registry that HAS grown SQL usage also fails, so the registry
//     cannot rot into a list of things that are actually built.
//
// # Why SQL usage rather than "does the name appear in a .go file"
//
// The obvious grep is wrong in the permissive direction, which is the dangerous
// one. `timeline_events` appears in a comment in internal/orchestrator/breaker.go
// (explaining that nothing writes it); `executions` appears in prose about
// executions and in the URL path /api/v1/executions/{id}/rollback. A
// does-the-word-appear check calls both of those "referenced" and the dead set
// silently shrinks. Matching FROM/JOIN/INTO/UPDATE/DELETE FROM instead means only
// an actual query counts.

// notImplementedTables are tables the schema defines that no query touches, each
// with WHY and what would change it. Sorted by the reason they exist, because the
// three reasons are genuinely different and lumping them together is what made the
// original set unreadable.
var notImplementedTables = map[string]string{
	// --- Created, then orphaned by a reset. ------------------------------------
	"patchfield_enabled_fields": "created by migration 000057 for a per-tenant PatchField policy tier whose Go code was reset out of the tree on 2026-08-24 (internal/settings/patchfield.go and the /api/v1/admin/patchfield-fields routes). The MIGRATION is deliberately kept rather than reverted: the dev database was already at 57, and rolling back means re-adding a CHECK constraint that existing PatchField recommendation and execution rows violate, so undoing it would mean deleting real audit records to tidy up a schema. Empty and unread until a direction is chosen for in-place field remediation — see PRODUCT_DIRECTION.md.",

	// --- Specified and genuinely not built yet. These should stay: DESIGN.md is
	// deliberately ahead of the code, and dropping them would mean re-deriving the
	// schema when the feature lands.
	"token_usage":               "BACKLOG H2. Per-call token accounting is summed onto the analyses row instead; nothing writes a per-call ledger.",
	"remediation_policies":      "BACKLOG S4. The autonomy policy lives in org_settings columns; the policy:* capabilities have no handler.",
	"policy_versions":           "BACKLOG S4, alongside remediation_policies.",
	"breakglass_policies":       "BACKLOG G7 / lld/02. Break-glass is specified with no handler.",
	"identities":                "BACKLOG S2 (SSO, on hold). An external-IdP identity linked to a user; local password accounts need no row here.",
	"identity_mappings":         "BACKLOG S2 (SSO, on hold). Local accounts only.",
	"service_principals":        "BACKLOG S2/S3. No non-human principals exist yet.",
	"local_guardrail_snapshots": "BACKLOG S4. The LocalGuardrail CR and its cluster-side controller are unbuilt, so there is no self-reported hash to store. DESIGN.md §18.4 wants freeze windows locally owned; WORKLOG §147 records shipping them hub-side instead, and says so.",
}

func TestEverySchemaTableIsEitherUsedOrDeclaredUnimplemented(t *testing.T) {
	created, partitions := tablesFromMigrations(t)
	sqlUsage := tablesUsedInQueries(t)

	var missingFromRegistry []string
	for _, table := range created {
		// Partitions are created by internal/partition generically and never named
		// in a query, so "no SQL usage" is correct for them and says nothing.
		if partitions[table] {
			continue
		}
		if sqlUsage[table] {
			if reason, ok := notImplementedTables[table]; ok {
				t.Errorf("table %q is listed as not implemented (%q) but a query now touches it — remove it from notImplementedTables so the list stays a true index of what is unbuilt", table, reason)
			}
			continue
		}
		if _, declared := notImplementedTables[table]; !declared {
			missingFromRegistry = append(missingFromRegistry, table)
		}
	}

	if len(missingFromRegistry) > 0 {
		sort.Strings(missingFromRegistry)
		t.Errorf(`no query touches these tables and they are not declared in notImplementedTables:

  %s

Either point a query at them, or add an entry saying WHY they are empty and which
backlog item would change that. An undeclared empty table is indistinguishable
from a feature somebody forgot to wire up, which is exactly the confusion BACKLOG
P2 exists to end.`, strings.Join(missingFromRegistry, "\n  "))
	}
}

// TestNotImplementedRegistryHasNoGhosts: an entry for a table the schema no longer
// creates is worse than no entry, because it reads as coverage.
func TestNotImplementedRegistryHasNoGhosts(t *testing.T) {
	created, _ := tablesFromMigrations(t)
	for table := range notImplementedTables {
		if !slices.Contains(created, table) {
			t.Errorf("notImplementedTables lists %q, which no migration creates — drop the entry", table)
		}
	}
}

// TestEveryNotImplementedEntryNamesWhatWouldChangeIt keeps the registry useful
// rather than a bare list of names. A reason with no pointer is the same dead end
// the original audit hit.
func TestEveryNotImplementedEntryNamesWhatWouldChangeIt(t *testing.T) {
	for table, reason := range notImplementedTables {
		if len(reason) < 30 {
			t.Errorf("table %q: reason %q is too short to be useful", table, reason)
		}
		if !registryPointer.MatchString(reason) {
			t.Errorf("table %q: reason %q names no backlog item, design section or superseding migration — without one, the next reader has to re-derive why it is empty", table, reason)
		}
	}
}

// registryPointer is what both registries below require of a reason: a
// pointer to where the decision lives, so the next reader does not have to
// re-derive why something is empty or unread. PROJECT.md was added when it
// became the single board (BACKLOG.md/STATUS.md/DESIGN.md are deleted; the
// older alternatives stay because ~2,200 comments still cite them as
// provenance and those citations are the real record for anything predating
// the consolidation).
var registryPointer = regexp.MustCompile(`BACKLOG [A-Z][0-9]|PROJECT\.md|lld/|DESIGN\.md|WORKLOG §|migration [0-9]|superseded`)

// writeOnlyColumns is the column-level counterpart to notImplementedTables: a
// column the product WRITES on every relevant path but does not yet READ
// anywhere. The table-level test above cannot see these at all — a table stays
// "used" on the strength of any query touching any of its columns — so without
// this registry a deliberately-ahead-of-its-reader column is indistinguishable
// from one somebody forgot to finish wiring up, which is the exact confusion
// the table registry exists to end.
//
// What the test below can and cannot check, stated plainly so nobody trusts it
// for more than it does. It checks that the column really exists in the schema
// (no ghosts) and that something really writes it (a declared write-only column
// that is not even written is a dead column, not a pending one). It does NOT
// check that nothing reads it: a column name is not unique across tables —
// analysis_id exists on remediation_recommendations, evidence and
// analysis_embeddings too, and is read on all three — so a mechanical
// read-detector would be a coin flip. The entry is removed by hand when a
// reader lands, which is the same discipline notImplementedTables already asks
// for.
var writeOnlyColumns = map[string]string{
	"remediation_approval_decisions.analysis_id": "added by migration 000116 for PROJECT.md L8: pins the analysis an approval/rejection was a judgement OF, so the verdict and its reason stay interpretable once the prompt version, model and permitted action set have moved on. Written by all three decision paths (approvals.go's approveByOpeningPullRequest and handleRejectIncident, internal/execution's recordExecutingTransition) and read by nothing yet ON PURPOSE — the reader is PROJECT.md L1's knowledge base, and L8 is the cheap insurance that keeps L1 possible rather than L1 itself. Deliberately recorded ahead of its reader, because feedback that was not anchored at decision time cannot be anchored afterwards.",
}

// TestDeclaredWriteOnlyColumnsAreRealAndWritten enforces writeOnlyColumns the
// same way TestNotImplementedRegistryHasNoGhosts and
// TestEveryNotImplementedEntryNamesWhatWouldChangeIt enforce the table
// registry: the entry must name something that exists, something that is
// actually written, and where the decision lives.
func TestDeclaredWriteOnlyColumnsAreRealAndWritten(t *testing.T) {
	columns := columnsFromMigrations(t)
	for qualified, reason := range writeOnlyColumns {
		table, column, ok := strings.Cut(qualified, ".")
		if !ok {
			t.Errorf("writeOnlyColumns key %q is not in table.column form", qualified)
			continue
		}
		if !columns[qualified] {
			t.Errorf("writeOnlyColumns lists %q, which no migration creates (or a later one drops) — drop the entry", qualified)
			continue
		}
		if !columnIsWritten(t, table, column) {
			t.Errorf(`writeOnlyColumns declares %q as written-but-not-yet-read, and no INSERT or UPDATE in internal/, cmd/ or scripts/ names it.

A column nothing writes is not "ahead of its reader", it is dead schema. Either
point a write path at it, or drop the column and the entry together.`, qualified)
		}
		if len(reason) < 30 {
			t.Errorf("column %q: reason %q is too short to be useful", qualified, reason)
		}
		if !registryPointer.MatchString(reason) {
			t.Errorf("column %q: reason %q names no board item, design section or migration — without one, the next reader has to re-derive why nothing reads it", qualified, reason)
		}
	}
}

// columnsFromMigrations returns every "table.column" the up-migrations leave in
// place, applied in filename order so a column that is added and later dropped
// (or whose table is dropped) comes out absent — the same ordered-presence
// approach tablesFromMigrations uses, and for the same reason.
func columnsFromMigrations(t *testing.T) map[string]bool {
	t.Helper()
	files, err := filepath.Glob("*.up.sql")
	if err != nil || len(files) == 0 {
		t.Fatalf("found no up-migrations to read (%v)", err)
	}
	sort.Strings(files)
	createRe := regexp.MustCompile(`(?is)CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?"?([a-z0-9_]+)"?\s*\(([^;]*)\)`)
	addRe := regexp.MustCompile(`(?is)ALTER\s+TABLE\s+(?:IF\s+EXISTS\s+)?"?([a-z0-9_]+)"?\s+ADD\s+COLUMN\s+(?:IF\s+NOT\s+EXISTS\s+)?"?([a-z0-9_]+)"?`)
	dropColRe := regexp.MustCompile(`(?is)ALTER\s+TABLE\s+(?:IF\s+EXISTS\s+)?"?([a-z0-9_]+)"?\s+DROP\s+COLUMN\s+(?:IF\s+EXISTS\s+)?"?([a-z0-9_]+)"?`)
	dropTableRe := regexp.MustCompile(`(?is)DROP\s+TABLE\s+(?:IF\s+EXISTS\s+)?"?([a-z0-9_]+)"?`)

	present := map[string]bool{}
	for _, f := range files {
		body, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		text := string(body)
		for _, m := range createRe.FindAllStringSubmatch(text, -1) {
			for _, col := range topLevelColumnNames(m[2]) {
				present[m[1]+"."+col] = true
			}
		}
		for _, m := range addRe.FindAllStringSubmatch(text, -1) {
			present[m[1]+"."+m[2]] = true
		}
		for _, m := range dropColRe.FindAllStringSubmatch(text, -1) {
			delete(present, m[1]+"."+m[2])
		}
		for _, m := range dropTableRe.FindAllStringSubmatch(text, -1) {
			for k := range present {
				if strings.HasPrefix(k, m[1]+".") {
					delete(present, k)
				}
			}
		}
	}
	return present
}

// topLevelColumnNames pulls the column names out of a CREATE TABLE body: the
// first word of each comma-separated clause at paren depth 0, skipping the
// table-level constraint clauses, which are not columns.
func topLevelColumnNames(body string) []string {
	var names []string
	depth := 0
	start := 0
	clauses := []string{}
	for i, r := range body {
		switch r {
		case '(':
			depth++
		case ')':
			depth--
		case ',':
			if depth == 0 {
				clauses = append(clauses, body[start:i])
				start = i + 1
			}
		}
	}
	clauses = append(clauses, body[start:])
	notAColumn := map[string]bool{
		"primary": true, "foreign": true, "unique": true, "check": true,
		"constraint": true, "exclude": true, "like": true,
	}
	word := regexp.MustCompile(`^[a-z0-9_]+$`)
	for _, clause := range clauses {
		// Strip whole-line comments so a `-- note, with a comma` inside the body
		// cannot be mistaken for a clause of its own.
		var stripped []string
		for _, line := range strings.Split(clause, "\n") {
			if idx := strings.Index(line, "--"); idx >= 0 {
				line = line[:idx]
			}
			stripped = append(stripped, line)
		}
		fields := strings.Fields(strings.Join(stripped, " "))
		if len(fields) == 0 {
			continue
		}
		name := strings.ToLower(strings.Trim(fields[0], `"`))
		if notAColumn[name] || !word.MatchString(name) {
			continue
		}
		names = append(names, name)
	}
	return names
}

// columnIsWritten reports whether any non-test Go file writes this column: an
// INSERT naming it in the column list, or an UPDATE ... SET assigning it. Test
// files are excluded for tablesUsedInQueries' own reason — a column only a
// fixture writes is not a column the product writes.
func columnIsWritten(t *testing.T, table, column string) bool {
	t.Helper()
	insertRe := regexp.MustCompile(`(?is)INSERT\s+INTO\s+"?` + regexp.QuoteMeta(table) + `"?\s*\(([^)]*)\)`)
	updateRe := regexp.MustCompile(`(?is)UPDATE\s+"?` + regexp.QuoteMeta(table) + `"?\s+SET\s+([^;` + "`" + `]*)`)
	named := regexp.MustCompile(`(?i)\b` + regexp.QuoteMeta(column) + `\b`)
	found := false
	for _, root := range []string{"../../internal", "../../cmd", "../../scripts"} {
		err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			body, err := os.ReadFile(path)
			if err != nil {
				return fmt.Errorf("read %s: %w", path, err)
			}
			for _, re := range []*regexp.Regexp{insertRe, updateRe} {
				for _, m := range re.FindAllStringSubmatch(string(body), -1) {
					if named.MatchString(m[1]) {
						found = true
					}
				}
			}
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", root, err)
		}
	}
	return found
}

// tablesFromMigrations returns every table the up-migrations create, plus which of
// them are partitions.
func tablesFromMigrations(t *testing.T) (created []string, partitions map[string]bool) {
	t.Helper()
	files, err := filepath.Glob("*.up.sql")
	if err != nil || len(files) == 0 {
		t.Fatalf("found no up-migrations to read (%v) — this test cannot protect anything without them", err)
	}
	partitions = map[string]bool{}
	// CREATE TABLE [IF NOT EXISTS] name, optionally quoted, optionally partitioned.
	re := regexp.MustCompile(`(?i)CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?"?([a-z0-9_]+)"?([^;]*)`)
	// DROP TABLE [IF EXISTS] name. Added when incident_feedback became the first
	// table this schema has ever dropped (migration 000061, WISHLIST.md W1):
	// without it a dropped table still counted as created, so this test demanded a
	// query against a table that no longer exists — and the only ways to satisfy
	// it were both lies (declare it unimplemented, or point a query at nothing).
	dropRe := regexp.MustCompile(`(?i)DROP\s+TABLE\s+(?:IF\s+EXISTS\s+)?"?([a-z0-9_]+)"?`)
	// Migrations are applied in filename order, so a table can legitimately be
	// created, dropped, and created again. Tracking presence in order — rather
	// than collecting creates and subtracting drops — is what makes that case come
	// out right.
	sort.Strings(files)
	present := map[string]bool{}
	for _, f := range files {
		body, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		for _, m := range re.FindAllStringSubmatch(string(body), -1) {
			name, rest := m[1], m[2]
			if name == "schema_migrations" {
				continue
			}
			present[name] = true
			if regexp.MustCompile(`(?i)PARTITION\s+OF`).MatchString(rest) {
				partitions[name] = true
			}
		}
		for _, m := range dropRe.FindAllStringSubmatch(string(body), -1) {
			name := m[1]
			delete(present, name)
			delete(partitions, name)
		}
	}
	for name := range present {
		created = append(created, name)
	}
	sort.Strings(created)
	return created, partitions
}

// tablesUsedInQueries finds table names appearing where SQL actually names a
// table. Comments and URL paths do not count, which is the whole point.
func tablesUsedInQueries(t *testing.T) map[string]bool {
	t.Helper()
	used := map[string]bool{}
	// FROM/JOIN/INTO/UPDATE/DELETE FROM/TABLE. Also matches inside comments that
	// happen to contain SQL, which is an acceptable false positive: a comment
	// quoting a real query is evidence the query exists somewhere.
	re := regexp.MustCompile(`(?is)\b(?:FROM|JOIN|INTO|UPDATE|TABLE)\s+"?([a-z_][a-z0-9_]*)"?`)
	roots := []string{"../../internal", "../../cmd", "../../scripts"}
	for _, root := range roots {
		err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() || !strings.HasSuffix(path, ".go") {
				return nil
			}
			// Test files are excluded: a table used only by a test fixture is not a
			// table the product uses, and counting it would hide a real gap.
			if strings.HasSuffix(path, "_test.go") {
				return nil
			}
			body, err := os.ReadFile(path)
			if err != nil {
				return fmt.Errorf("read %s: %w", path, err)
			}
			for _, m := range re.FindAllStringSubmatch(string(body), -1) {
				used[strings.ToLower(m[1])] = true
			}
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", root, err)
		}
	}
	return used
}
