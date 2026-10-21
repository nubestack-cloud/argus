package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"argus/internal/data"
	"argus/internal/dbtest"
	"argus/internal/domain"
	"argus/internal/orchestrator"
)

// This file proves GET /api/v1/audit-events' two new filters — `cluster` and
// `resource` (internal/api/audit.go's parseAuditEventFilters) — actually
// narrow the query, compose with each other and with pagination, and make
// the NULL-cluster_id decision an assertion rather than something incidental
// (see parseAuditEventFilters' own doc comment on both params for the
// reasoning this locks in).
//
// Fixture shape, deliberately built so no single assertion could pass by
// accident:
//
//   - clusterA / clusterB: two real clusters (incidents.cluster_id has a
//     REFERENCES clusters(id) — confirmed by reading
//     000005_incidents_and_analysis.up.sql before writing this fixture — so
//     an incident needs a real cluster row; audit_events.cluster_id has no
//     such FK, migration 000008, but rows are still tagged with real ids
//     here so the cluster filter test means something).
//   - incidentWithObjectKey: one real incident row on clusterA, carrying
//     object_key — the join target for the `resource` filter's
//     incident-linked branch.
//   - six audit_events rows, each isolating exactly one thing the tests
//     below check: a plain clusterA event, a plain clusterB event, an
//     org-level event with a NULL cluster_id, an event that names its object
//     DIRECTLY via details.objectKey (the tolerate_incident/
//     finding_suppressed_by_toleration shape), an event that names NO object
//     of its own but references incidentWithObjectKey via
//     details.incidentId (the execute_remediation/approve_remediation
//     shape — the one this filter exists to reach), and a same-object event
//     on clusterB (proves `cluster`+`resource` actually compose, not just
//     each independently).
type auditFilterFixture struct {
	tenantID              string
	clusterA, clusterB    string
	incidentWithObjectKey string
	objectKey             string

	eventClusterA                 string // clusterA, no resource of its own
	eventClusterB                 string // clusterB, no resource of its own
	eventOrgLevel                 string // cluster_id IS NULL
	eventDirectResource           string // clusterA, details.objectKey = objectKey
	eventViaIncident              string // clusterA, details.incidentId = incidentWithObjectKey (no objectKey of its own)
	eventSameResourceOtherCluster string // clusterB, details.objectKey = objectKey -- for the compose test
}

func setupAuditFilterFixture(t *testing.T, pool *pgxpool.Pool) auditFilterFixture {
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

	f := auditFilterFixture{
		tenantID:              tenantID,
		clusterA:              domain.NewID(domain.PrefixCluster),
		clusterB:              domain.NewID(domain.PrefixCluster),
		incidentWithObjectKey: domain.NewID(domain.PrefixIncident),
		objectKey:             "apps/v1/Deployment|checkout|p10audit-checkout-worker",

		eventClusterA:                 domain.NewID(domain.PrefixAuditEvent),
		eventClusterB:                 domain.NewID(domain.PrefixAuditEvent),
		eventOrgLevel:                 domain.NewID(domain.PrefixAuditEvent),
		eventDirectResource:           domain.NewID(domain.PrefixAuditEvent),
		eventViaIncident:              domain.NewID(domain.PrefixAuditEvent),
		eventSameResourceOtherCluster: domain.NewID(domain.PrefixAuditEvent),
	}

	if err := data.SetRequestScope(ctx, tx, tenantID, []string{f.clusterA, f.clusterB}); err != nil {
		t.Fatalf("set request scope: %v", err)
	}

	fixture := dbtest.New(t)

	for _, c := range []string{f.clusterA, f.clusterB} {
		if _, err := tx.Exec(ctx,
			`INSERT INTO clusters (id, tenant_id, display_name, state, shard_id, cluster_fingerprint)
			 VALUES ($1, $2, $3, 'Active', 'shard-test', $4)`,
			c, tenantID, "p10audit-"+c, "fp-"+c); err != nil {
			t.Fatalf("insert cluster %s: %v", c, err)
		}
	}
	fixture.Created("clusters", 2)

	now := time.Now()
	if _, err := tx.Exec(ctx,
		`INSERT INTO incidents (id, tenant_id, cluster_id, fingerprint, severity, state, first_seen, last_seen, occurrence_count, object_key)
		 VALUES ($1, $2, $3, $4, 'high', $5, $6, $6, 1, $7)`,
		f.incidentWithObjectKey, tenantID, f.clusterA, "p10audit-fp-"+f.incidentWithObjectKey,
		orchestrator.StateDetected, now, f.objectKey); err != nil {
		t.Fatalf("insert incident: %v", err)
	}
	fixture.Created("incidents", 1)

	// Deliberately spaced a minute apart, oldest first, so the pagination
	// test below has a real, deterministic (occurred_at DESC, id DESC) order
	// to walk rather than relying on same-instant ties.
	base := time.Now().UTC().Add(-1 * time.Hour)
	type eventSpec struct {
		id        string
		clusterID string // "" -> NULL
		offset    time.Duration
		details   map[string]any
	}
	specs := []eventSpec{
		{f.eventClusterA, f.clusterA, 1 * time.Minute, map[string]any{"action": "p10audit_cluster_a_event"}},
		{f.eventClusterB, f.clusterB, 2 * time.Minute, map[string]any{"action": "p10audit_cluster_b_event"}},
		{f.eventOrgLevel, "", 3 * time.Minute, map[string]any{"action": "p10audit_org_level_event"}},
		// The tolerate_incident/finding_suppressed_by_toleration shape:
		// names its object directly, no incidentId needed to resolve it.
		{f.eventDirectResource, f.clusterA, 4 * time.Minute, map[string]any{
			"action": "p10audit_tolerate_incident", "objectKey": f.objectKey,
		}},
		// The execute_remediation/approve_remediation shape: the event this
		// filter exists to reach. NO objectKey of its own -- only resolvable
		// through the incident it names.
		{f.eventViaIncident, f.clusterA, 5 * time.Minute, map[string]any{
			"action": "p10audit_execute_remediation", "incidentId": f.incidentWithObjectKey,
		}},
		// Same object as eventDirectResource, but on clusterB -- the fixture
		// row that makes "cluster and resource actually compose" a real
		// assertion instead of two filters that each merely narrow alone.
		{f.eventSameResourceOtherCluster, f.clusterB, 6 * time.Minute, map[string]any{
			"action": "p10audit_tolerate_incident_other_cluster", "objectKey": f.objectKey,
		}},
	}
	for _, s := range specs {
		var clusterArg any
		if s.clusterID != "" {
			clusterArg = s.clusterID
		}
		detailsJSON, err := json.Marshal(s.details)
		if err != nil {
			t.Fatalf("marshal details for %s: %v", s.id, err)
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO audit_events (id, tenant_id, cluster_id, capability, outcome, occurred_at, details, prev_hash, hash)
			 VALUES ($1, $2, $3, $4, 'success', $5, $6, 'genesis-test', $7)`,
			s.id, tenantID, clusterArg, "p10audit:probe", base.Add(s.offset), detailsJSON, "hash-"+s.id); err != nil {
			t.Fatalf("insert audit event %s: %v", s.id, err)
		}
	}
	fixture.Created("audit_events", len(specs))

	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit setup transaction: %v", err)
	}

	allEventIDs := make([]string, 0, len(specs))
	for _, s := range specs {
		allEventIDs = append(allEventIDs, s.id)
	}
	fixture.Cleanup(pool, func(ctx context.Context, tx pgx.Tx) error {
		return data.SetRequestScope(ctx, tx, tenantID, []string{f.clusterA, f.clusterB})
	}, []dbtest.TableDelete{
		{Table: "audit_events", SQL: `DELETE FROM audit_events WHERE id = ANY($1)`, Args: []any{allEventIDs}},
		{Table: "incidents", SQL: `DELETE FROM incidents WHERE id = $1`, Args: []any{f.incidentWithObjectKey}},
		{Table: "clusters", SQL: `DELETE FROM clusters WHERE id = ANY($1)`, Args: []any{[]string{f.clusterA, f.clusterB}}},
	})

	return f
}

// callListAuditEvents opens its own transaction -- unrestricted, nil-scoped
// like a real audit:read caller's (that capability is org-only,
// super-admin-only; see audit.go's own doc comment and
// audit_export_db_test.go's callExportAuditEvents, which uses the same nil
// scope for the same reason) -- and calls the real handler directly.
func callListAuditEvents(t *testing.T, pool *pgxpool.Pool, tenantID, rawQuery string) (int, map[string]any) {
	t.Helper()
	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin request transaction: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if err := data.SetRequestScope(ctx, tx, tenantID, nil); err != nil {
		t.Fatalf("set request scope: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/audit-events?"+rawQuery, nil)
	rec := httptest.NewRecorder()
	s := &Server{}
	s.handleListAuditEvents(rec, req, &requestContext{Tx: tx, TenantID: tenantID})

	var body map[string]any
	if rec.Body.Len() > 0 {
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatalf("unmarshal response (status %d, body %s): %v", rec.Code, rec.Body.String(), err)
		}
	}
	return rec.Code, body
}

func auditEventIDsFrom(body map[string]any) []string {
	raw, _ := body["auditEvents"].([]any)
	ids := make([]string, 0, len(raw))
	for _, item := range raw {
		row, _ := item.(map[string]any)
		id, _ := row["id"].(string)
		ids = append(ids, id)
	}
	return ids
}

func containsString(ids []string, want string) bool {
	for _, id := range ids {
		if id == want {
			return true
		}
	}
	return false
}

// TestHandleListAuditEventsClusterFilterNarrowsAndExcludesNullCluster is both
// the `cluster` filter's narrowing test and the NULL-cluster_id decision's
// regression test in one: filtering to clusterA must surface clusterA's own
// event, must never surface clusterB's, and -- the deliberate decision this
// asserts rather than leaves incidental -- must never surface the org-level
// event either, even though that event has nothing to do with ANY cluster
// and so is not "wrongly on the other side" the way clusterB's event is.
func TestHandleListAuditEventsClusterFilterNarrowsAndExcludesNullCluster(t *testing.T) {
	pool := authTestPool(t)
	f := setupAuditFilterFixture(t, pool)

	code, body := callListAuditEvents(t, pool, f.tenantID, "cluster="+f.clusterA+"&limit=50")
	if code != http.StatusOK {
		t.Fatalf("status = %d, body: %+v", code, body)
	}
	ids := auditEventIDsFrom(body)

	if !containsString(ids, f.eventClusterA) {
		t.Errorf("cluster=%s missing its own event %s; got %v", f.clusterA, f.eventClusterA, ids)
	}
	if containsString(ids, f.eventClusterB) {
		t.Errorf("cluster=%s leaked clusterB's event %s; got %v", f.clusterA, f.eventClusterB, ids)
	}
	// The decision under test: an org-level event (cluster_id IS NULL) is
	// not "about" clusterA and must not appear just because SOME cluster was
	// asked for -- see parseAuditEventFilters' doc comment on `cluster`.
	if containsString(ids, f.eventOrgLevel) {
		t.Errorf("cluster=%s must not include the org-level (NULL cluster_id) event %s -- see the NULL-cluster decision in parseAuditEventFilters; got %v",
			f.clusterA, f.eventOrgLevel, ids)
	}
}

// TestHandleListAuditEventsNoClusterFilterStillShowsOrgLevelEvent is the
// other half of the same decision: with NO cluster filter applied, the
// org-level event must still be visible at all -- proving the exclusion
// above is specifically about the `cluster` filter, not the org-level event
// being unreachable from this endpoint in general.
func TestHandleListAuditEventsNoClusterFilterStillShowsOrgLevelEvent(t *testing.T) {
	pool := authTestPool(t)
	f := setupAuditFilterFixture(t, pool)

	// Narrowed by `capability`, not by time: this is a live, shared dev
	// Postgres with enough real, concurrent traffic (this package's other
	// DB-backed tests, other agents' sessions, background jobs) that even
	// windowSince/windowUntil's few-minute bracket can hold more than
	// defaultAuditEventLimit real rows -- confirmed live while writing this
	// test, which is exactly the flakiness this filter avoids. Every fixture
	// row above was inserted with capability="p10audit:probe", a value no
	// real write path uses, so filtering on it isolates precisely this
	// fixture's own six rows regardless of how much unrelated traffic shares
	// their time window -- proving the point of this test (the org-level
	// event is reachable at all, absent a cluster filter) without depending
	// on page-size luck against live data.
	code, body := callListAuditEvents(t, pool, f.tenantID, "capability=p10audit:probe&limit=50")
	if code != http.StatusOK {
		t.Fatalf("status = %d, body: %+v", code, body)
	}
	ids := auditEventIDsFrom(body)
	if !containsString(ids, f.eventOrgLevel) {
		t.Errorf("unfiltered-by-cluster list is missing the org-level event %s -- it should only ever be excluded by an explicit cluster filter; got %v", f.eventOrgLevel, ids)
	}
}

// TestHandleListAuditEventsResourceFilterMatchesDirectAndIncidentLinkedEvents
// proves the `resource` filter's two backing sources both actually work: an
// event that names its object directly via details.objectKey, AND an event
// that names only an incident (details.incidentId) whose OWN object_key
// resolves to the same object -- the shape execute_remediation/
// approve_remediation/rollback_* actually use, and the whole reason this
// filter is worth more than a single-key lookup. An unrelated event must not
// match just because a resource filter was applied at all.
func TestHandleListAuditEventsResourceFilterMatchesDirectAndIncidentLinkedEvents(t *testing.T) {
	pool := authTestPool(t)
	f := setupAuditFilterFixture(t, pool)

	code, body := callListAuditEvents(t, pool, f.tenantID, "resource=p10audit-checkout-worker&limit=50")
	if code != http.StatusOK {
		t.Fatalf("status = %d, body: %+v", code, body)
	}
	ids := auditEventIDsFrom(body)

	if !containsString(ids, f.eventDirectResource) {
		t.Errorf("resource filter missed the direct-objectKey event %s; got %v", f.eventDirectResource, ids)
	}
	if !containsString(ids, f.eventViaIncident) {
		t.Errorf("resource filter missed the incident-linked event %s (details.incidentId -> incidents.object_key); got %v", f.eventViaIncident, ids)
	}
	if !containsString(ids, f.eventSameResourceOtherCluster) {
		t.Errorf("resource filter (with no cluster filter alongside it) missed %s on clusterB; got %v", f.eventSameResourceOtherCluster, ids)
	}
	if containsString(ids, f.eventClusterA) {
		t.Errorf("resource filter matched %s, which names no object at all; got %v", f.eventClusterA, ids)
	}
}

// TestHandleListAuditEventsClusterAndResourceFiltersCompose is the
// acceptance criterion's explicit "the two compose" requirement: the same
// object exists on both clusterA (eventDirectResource) and clusterB
// (eventSameResourceOtherCluster). Asking for the object on clusterA alone
// must return the clusterA row and must NOT return the clusterB row --
// proving this is a real AND, not two filters that each pass independently
// while the combination silently behaves like an OR.
func TestHandleListAuditEventsClusterAndResourceFiltersCompose(t *testing.T) {
	pool := authTestPool(t)
	f := setupAuditFilterFixture(t, pool)

	code, body := callListAuditEvents(t, pool, f.tenantID, "cluster="+f.clusterA+"&resource=p10audit-checkout-worker&limit=50")
	if code != http.StatusOK {
		t.Fatalf("status = %d, body: %+v", code, body)
	}
	ids := auditEventIDsFrom(body)

	if !containsString(ids, f.eventDirectResource) {
		t.Errorf("cluster+resource compose: missing %s (on clusterA, matches the resource); got %v", f.eventDirectResource, ids)
	}
	if containsString(ids, f.eventSameResourceOtherCluster) {
		t.Errorf("cluster+resource compose: leaked %s (same resource, but on clusterB, not clusterA) -- filters are not composing as AND; got %v",
			f.eventSameResourceOtherCluster, ids)
	}
	if containsString(ids, f.eventClusterB) {
		t.Errorf("cluster+resource compose: leaked clusterB's unrelated event %s; got %v", f.eventClusterB, ids)
	}
}

// TestHandleListAuditEventsPaginationUnderClusterFilter proves a filtered
// view still paginates correctly: walking every page at limit=1 with
// cluster=clusterA applied must, across all pages, surface every clusterA
// fixture event exactly once, in (occurred_at DESC, id DESC) order, and
// never a clusterB or org-level row -- not just that page 1 alone looks
// right.
func TestHandleListAuditEventsPaginationUnderClusterFilter(t *testing.T) {
	pool := authTestPool(t)
	f := setupAuditFilterFixture(t, pool)

	// clusterA's fixture events, oldest to newest by construction (see
	// setupAuditFilterFixture's `base.Add(offset)` spacing): eventClusterA
	// (+1m), eventDirectResource (+4m), eventViaIncident (+5m). Newest-first
	// is this endpoint's contract, so the expected walk order is the reverse.
	wantOrder := []string{f.eventViaIncident, f.eventDirectResource, f.eventClusterA}

	var got []string
	cursor := ""
	for page := 0; page < len(wantOrder)+1; page++ {
		query := "cluster=" + f.clusterA + "&limit=1"
		if cursor != "" {
			query += "&cursor=" + cursor
		}
		code, body := callListAuditEvents(t, pool, f.tenantID, query)
		if code != http.StatusOK {
			t.Fatalf("page %d: status = %d, body: %+v", page, code, body)
		}
		ids := auditEventIDsFrom(body)
		if containsString(ids, f.eventClusterB) || containsString(ids, f.eventOrgLevel) {
			t.Fatalf("page %d leaked an out-of-filter row: %v", page, ids)
		}
		if len(ids) == 0 {
			break
		}
		if len(ids) != 1 {
			t.Fatalf("page %d returned %d rows, want at most 1 (limit=1): %v", page, len(ids), ids)
		}
		got = append(got, ids[0])

		next, _ := body["nextCursor"].(string)
		if next == "" {
			break
		}
		cursor = next
	}

	if len(got) != len(wantOrder) {
		t.Fatalf("paginated through %v (%d rows), want exactly %v (%d rows) -- a filtered page either dropped or duplicated a row", got, len(got), wantOrder, len(wantOrder))
	}
	for i, want := range wantOrder {
		if got[i] != want {
			t.Errorf("page %d = %s, want %s (order: %v)", i, got[i], want, got)
		}
	}
}
