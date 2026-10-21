package api

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"argus/internal/data"
	"argus/internal/domain"
)

// auditExportFixture inserts rows for the real (single) organisation
// alongside rows for a SECOND, synthetic tenant id, to exercise
// audit_events_tenant_scope (migration 000012) — the actual RLS policy that
// protects this table — with a real cross-tenant read attempt, not just a
// cross-cluster one. This is possible specifically because
// audit_events.tenant_id (migration 000008) is a plain `text NOT NULL`
// column with NO REFERENCES organisations(id) — unlike almost every other
// tenant_id column in this schema — so a second tenant id needs no matching
// `organisations` row to exist first (confirmed by reading
// 000008_audit_and_cost.up.sql before writing this test).
type auditExportFixture struct {
	tenantID      string
	otherTenantID string
	visibleIDs    []string // this tenant's own rows -- must always be visible
	hiddenID      string   // otherTenantID's row -- must NEVER be visible
}

func setupAuditExportFixture(t *testing.T, pool *pgxpool.Pool) auditExportFixture {
	t.Helper()
	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin setup transaction: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	tenantID, err := data.SingleOrganisationID(ctx, tx)
	if err != nil {
		t.Fatalf("resolve organisation: %v", err)
	}

	f := auditExportFixture{
		tenantID:      tenantID,
		otherTenantID: domain.NewID(domain.PrefixOrganisation),
		visibleIDs: []string{
			domain.NewID(domain.PrefixAuditEvent),
			domain.NewID(domain.PrefixAuditEvent),
		},
		hiddenID: domain.NewID(domain.PrefixAuditEvent),
	}

	now := time.Now().UTC().Truncate(time.Second)
	insert := func(tenant, id, capability, outcome string, occurredAt time.Time, details map[string]any) {
		// Each insert re-scopes app.tenant_id to the row's OWN tenant before
		// writing it -- migration 000009's generic policies have no separate
		// FOR clause, so the USING expression governs INSERT (WITH CHECK) too;
		// a row can only ever be inserted under the tenant scope it will later
		// be read back under. set_config's third argument (SetRequestScope's
		// call) is transaction-local (is_local=true), so switching it
		// mid-transaction like this is safe and doesn't leak across the two
		// tenants' inserts below.
		if err := data.SetRequestScope(ctx, tx, tenant, nil); err != nil {
			t.Fatalf("set request scope to %s: %v", tenant, err)
		}
		var detailsJSON []byte
		if details != nil {
			detailsJSON, err = json.Marshal(details)
			if err != nil {
				t.Fatalf("marshal details: %v", err)
			}
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO audit_events (id, tenant_id, capability, outcome, occurred_at, details, prev_hash, hash)
			 VALUES ($1, $2, $3, $4, $5, $6, 'genesis-test', $7)`,
			id, tenant, capability, outcome, occurredAt, detailsJSON, "hash-"+id); err != nil {
			t.Fatalf("insert audit event %s: %v", id, err)
		}
	}

	// Deliberately out of occurred_at order on insert (older second) so a
	// passing test proves the export is actually ORDER BY occurred_at ASC,
	// not just insertion order.
	insert(tenantID, f.visibleIDs[1], "p10export:second", "success", now.Add(-1*time.Minute),
		map[string]any{"action": "second_event", "note": "visible"})
	insert(tenantID, f.visibleIDs[0], "p10export:first", "success", now.Add(-5*time.Minute),
		map[string]any{"action": "first_event", "nested": map[string]any{"k": "v"}})
	// Same time window as the visible rows -- isolation below comes from the
	// tenant_id policy, not from the since/until filter excluding it.
	insert(f.otherTenantID, f.hiddenID, "p10export:hidden", "success", now.Add(-3*time.Minute), nil)

	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit setup transaction: %v", err)
	}

	t.Cleanup(func() {
		cleanupCtx := context.Background()
		for _, tenant := range []string{tenantID, f.otherTenantID} {
			tx, err := pool.Begin(cleanupCtx)
			if err != nil {
				t.Logf("cleanup: begin: %v", err)
				continue
			}
			if err := data.SetRequestScope(cleanupCtx, tx, tenant, nil); err != nil {
				t.Logf("cleanup: set request scope: %v", err)
				tx.Rollback(cleanupCtx) //nolint:errcheck
				continue
			}
			ids := f.visibleIDs
			if tenant == f.otherTenantID {
				ids = []string{f.hiddenID}
			}
			if _, err := tx.Exec(cleanupCtx, `DELETE FROM audit_events WHERE id = ANY($1)`, ids); err != nil {
				t.Logf("cleanup: delete audit events: %v", err)
				tx.Rollback(cleanupCtx) //nolint:errcheck
				continue
			}
			if err := tx.Commit(cleanupCtx); err != nil {
				t.Logf("cleanup: commit: %v", err)
			}
		}
	})

	return f
}

// callExportAuditEvents opens its own transaction scoped ONLY to
// f.tenantID (never f.otherTenantID) and calls the real handler directly --
// the same by-hand request-scoping this package's other DB-backed handler
// tests use (see incidents_test.go's callListIncidents) in place of going
// through the full requireAuth HTTP middleware chain.
func callExportAuditEvents(t *testing.T, pool *pgxpool.Pool, f auditExportFixture, rawQuery string) *httptest.ResponseRecorder {
	t.Helper()
	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin request transaction: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if err := data.SetRequestScope(ctx, tx, f.tenantID, nil); err != nil {
		t.Fatalf("set request scope: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/audit-events/export?"+rawQuery, nil)
	rec := httptest.NewRecorder()
	s := &Server{}
	s.handleExportAuditEvents(rec, req, &requestContext{Tx: tx, TenantID: f.tenantID})
	return rec
}

func exportTimeWindow() string {
	now := time.Now().UTC()
	since := now.Add(-1 * time.Hour).Format(time.RFC3339)
	until := now.Add(1 * time.Hour).Format(time.RFC3339)
	return "since=" + since + "&until=" + until
}

// TestHandleExportAuditEventsJSONScopesToTenantAndOrdersByOccurredAt is the
// positive case plus the RLS-isolation case for ?format=json (the default):
// a real audit:read-equivalent caller (capability gating is middleware --
// see requireCapability -- and is exercised by scripts/smoke-test.sh instead
// of duplicated at this layer) gets exactly this tenant's rows, correctly
// scoped, and never the other tenant's row that shares the same time window.
func TestHandleExportAuditEventsJSONScopesToTenantAndOrdersByOccurredAt(t *testing.T) {
	pool := authTestPool(t)
	f := setupAuditExportFixture(t, pool)

	rec := callExportAuditEvents(t, pool, f, "format=json&"+exportTimeWindow())
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body: %s)", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want %q", ct, "application/json")
	}
	if cd := rec.Header().Get("Content-Disposition"); !strings.Contains(cd, "attachment") || !strings.HasSuffix(cd, `.json"`) {
		t.Errorf("Content-Disposition = %q, want an attachment with a .json filename", cd)
	}

	var rows []auditExportJSONRow
	if err := json.Unmarshal(rec.Body.Bytes(), &rows); err != nil {
		t.Fatalf("unmarshal response body %s: %v", rec.Body.String(), err)
	}

	// Assertions below check PRESENCE/ABSENCE/ORDER, never an exact total
	// row count: this is a live, shared dev Postgres (this package's other
	// DB-backed tests, and possibly other concurrently running test/agent
	// sessions, can write real audit_events rows for this SAME organisation
	// inside the +/-1h window exportTimeWindow() uses), so "exactly 2 rows"
	// would be flaky for reasons that have nothing to do with whether this
	// handler is correct.
	var gotIDs []string
	indexOf := make(map[string]int)
	for i, r := range rows {
		gotIDs = append(gotIDs, r.ID)
		indexOf[r.ID] = i
	}
	if _, ok := indexOf[f.hiddenID]; ok {
		t.Fatalf("export leaked the other tenant's row %s into this tenant's export: %v", f.hiddenID, gotIDs)
	}
	firstIdx, firstOK := indexOf[f.visibleIDs[0]]
	secondIdx, secondOK := indexOf[f.visibleIDs[1]]
	if !firstOK || !secondOK {
		t.Fatalf("export = %v, want it to contain both of this tenant's fixture rows %v", gotIDs, f.visibleIDs)
	}
	// visibleIDs[0] was inserted with the OLDER occurred_at (-5m) and
	// visibleIDs[1] the newer one (-1m) -- see setupAuditExportFixture --
	// despite being inserted in the opposite order, so this only passes
	// under a real ORDER BY occurred_at ASC, not insertion order.
	if firstIdx >= secondIdx {
		t.Errorf("row order: %s (older, occurred_at -5m) at index %d, %s (newer, occurred_at -1m) at index %d -- want the older row first (occurred_at ASC)",
			f.visibleIDs[0], firstIdx, f.visibleIDs[1], secondIdx)
	}

	// The full `details` JSON blob must survive intact (not just the
	// summary) -- this is the whole justification for exporting it raw
	// rather than a truncated digest (see auditExportRow's doc comment).
	oldRow := rows[firstIdx]
	if oldRow.Details == "" || !strings.Contains(oldRow.Details, `"nested":{"k":"v"}`) {
		t.Errorf("Details for %s = %q, want it to contain the full nested details blob", f.visibleIDs[0], oldRow.Details)
	}
}

// TestHandleExportAuditEventsCSVMatchesJSONRowsAndHasTheDeclaredHeader
// exercises the explicit-opt-in ?format=csv path against the same fixture:
// same row set, same tenant isolation, correct header, real
// encoding/csv-escaped output.
func TestHandleExportAuditEventsCSVMatchesJSONRowsAndHasTheDeclaredHeader(t *testing.T) {
	pool := authTestPool(t)
	f := setupAuditExportFixture(t, pool)

	rec := callExportAuditEvents(t, pool, f, "format=csv&"+exportTimeWindow())
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body: %s)", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/csv") {
		t.Errorf("Content-Type = %q, want a text/csv prefix", ct)
	}
	if cd := rec.Header().Get("Content-Disposition"); !strings.Contains(cd, "attachment") || !strings.HasSuffix(cd, `.csv"`) {
		t.Errorf("Content-Disposition = %q, want an attachment with a .csv filename", cd)
	}

	records, err := csv.NewReader(rec.Body).ReadAll()
	if err != nil {
		t.Fatalf("parse csv response: %v (body: %s)", err, rec.Body.String())
	}
	if len(records) == 0 {
		t.Fatal("csv response has no rows at all, not even a header")
	}
	if got := records[0]; !equalStrings(got, auditExportColumns) {
		t.Fatalf("csv header = %v, want %v", got, auditExportColumns)
	}

	// Same presence/absence/order checks as the JSON test above, for the
	// same reason (a live, shared dev Postgres can hold other rows in this
	// window that have nothing to do with this fixture).
	dataRows := records[1:]
	idCol := -1
	for i, c := range auditExportColumns {
		if c == "id" {
			idCol = i
		}
	}
	indexOf := make(map[string]int)
	for i, row := range dataRows {
		indexOf[row[idCol]] = i
	}
	if _, ok := indexOf[f.hiddenID]; ok {
		t.Fatalf("csv export leaked the other tenant's row %s", f.hiddenID)
	}
	firstIdx, firstOK := indexOf[f.visibleIDs[0]]
	secondIdx, secondOK := indexOf[f.visibleIDs[1]]
	if !firstOK || !secondOK {
		t.Fatalf("csv export rows = %v, want it to contain both of this tenant's fixture row ids %v", dataRows, f.visibleIDs)
	}
	if firstIdx >= secondIdx {
		t.Errorf("csv row order: %s (older) at row %d, %s (newer) at row %d -- want the older row first (occurred_at ASC)",
			f.visibleIDs[0], firstIdx, f.visibleIDs[1], secondIdx)
	}
}

// TestHandleExportAuditEventsNarrowerWindowExcludesOlderRow confirms the
// since/until filters actually reach the query (not just the required-ness
// check) by narrowing the window to cover only one of the two fixture rows.
func TestHandleExportAuditEventsNarrowerWindowExcludesOlderRow(t *testing.T) {
	pool := authTestPool(t)
	f := setupAuditExportFixture(t, pool)

	now := time.Now().UTC()
	since := now.Add(-2 * time.Minute).Format(time.RFC3339) // excludes the -5m row
	until := now.Add(1 * time.Minute).Format(time.RFC3339)

	rec := callExportAuditEvents(t, pool, f, "format=json&since="+since+"&until="+until)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body: %s)", rec.Code, rec.Body.String())
	}
	var rows []auditExportJSONRow
	if err := json.Unmarshal(rec.Body.Bytes(), &rows); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	// Presence/absence, not an exact count -- see the JSON scoping test's
	// comment for why an exact total would be flaky against a live, shared
	// dev Postgres. What this test actually needs to prove is that ?since=
	// really reaches the query: the -1m row (inside the window) must be
	// present, and the -5m row (outside it) must be absent.
	present := make(map[string]bool)
	for _, r := range rows {
		present[r.ID] = true
	}
	if !present[f.visibleIDs[1]] {
		t.Errorf("narrowed window is missing %s (occurred_at -1m, inside [since,until])", f.visibleIDs[1])
	}
	if present[f.visibleIDs[0]] {
		t.Errorf("narrowed window still contains %s (occurred_at -5m, outside [since,until]) -- since= is not reaching the query", f.visibleIDs[0])
	}
}
