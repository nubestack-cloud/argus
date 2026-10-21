package api

// GET /api/v1/clusters' `?archived=` filter, against a real Postgres.
//
// WHAT WAS BROKEN. handleListClusters hard-coded `WHERE archived_at IS NULL`,
// so a decommissioned cluster was not merely de-emphasised in the UI — it was
// unreachable through the API at all. The Archived state existed, the gateway
// enforced it (internal/gateway/server.go refuses a tunnel from an Archived
// or Rejected cluster), and handleDecommissionCluster wrote it, but nothing
// could ever read one back. On the development instance at the time of this
// change that was 352 rows with no route to them.
//
// WHY THE DEFAULT IS TESTED AS HARD AS THE NEW BEHAVIOUR. The fix has two
// halves and the second is the one that can regress silently: retired
// clusters must become *visible on request* without becoming visible
// *everywhere*. Every cluster picker, count and scope control in the web UI
// calls this route with no parameters, so the no-parameter response is the
// contract that keeps a dead cluster out of all of them. A future change that
// flipped the default to `include` would pass any test that only checked
// "?archived=only returns the archived rows".

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"argus/internal/authz"
	"argus/internal/data"
	"argus/internal/dbtest"
	"argus/internal/domain"
)

// archivedFilterFixture inserts one live and one already-decommissioned
// cluster and returns their ids.
//
// It creates its OWN retired row rather than decommissioning anything that
// already exists: this package's tests run against the shared development
// database, where archiving a real cluster would disconnect a real agent and
// dismiss its open incidents (handleDecommissionCluster closes them). The row
// is inserted directly in the end state, with archived_at set the same way
// that handler sets it, and dbtest refuses to commit a cleanup that would
// delete anything other than these exact two rows.
func archivedFilterFixture(t *testing.T, pool *pgxpool.Pool, tenantID string) (liveID, retiredID string) {
	t.Helper()
	ctx := context.Background()
	fixture := dbtest.New(t)

	liveID = domain.NewID(domain.PrefixCluster)
	retiredID = domain.NewID(domain.PrefixCluster)

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if err := data.SetRequestScope(ctx, tx, tenantID, nil); err != nil {
		t.Fatalf("set request scope: %v", err)
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO clusters (id, tenant_id, display_name, state, shard_id, cluster_fingerprint)
		 VALUES ($1, $2, $3, 'Active', 'shard-test', $4)`,
		liveID, tenantID, "archived-filter-live-"+liveID, "fp-"+liveID); err != nil {
		t.Fatalf("insert live cluster: %v", err)
	}
	fixture.Created("clusters", 1)
	if _, err := tx.Exec(ctx,
		`INSERT INTO clusters (id, tenant_id, display_name, state, shard_id, cluster_fingerprint, archived_at)
		 VALUES ($1, $2, $3, 'Archived', 'shard-test', $4, $5)`,
		retiredID, tenantID, "archived-filter-retired-"+retiredID, "fp-"+retiredID,
		time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)); err != nil {
		t.Fatalf("insert retired cluster: %v", err)
	}
	fixture.Created("clusters", 1)
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit: %v", err)
	}

	fixture.Cleanup(pool,
		func(ctx context.Context, tx pgx.Tx) error {
			return data.SetRequestScope(ctx, tx, tenantID, []string{liveID, retiredID})
		},
		[]dbtest.TableDelete{{
			Table: "clusters",
			SQL:   `DELETE FROM clusters WHERE id = ANY($1)`,
			Args:  []any{[]string{liveID, retiredID}},
		}},
	)
	return liveID, retiredID
}

// listClustersViaHandler runs a real GET /api/v1/clusters through
// handleListClusters against a real transaction and returns the recorder, so
// a caller can assert on a non-200 as well as on the body.
func listClustersViaHandler(t *testing.T, s *Server, pool *pgxpool.Pool, tenantID, rawQuery string) *httptest.ResponseRecorder {
	t.Helper()
	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin request tx: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if err := data.SetRequestScope(ctx, tx, tenantID, nil); err != nil {
		t.Fatalf("set request scope: %v", err)
	}
	rc := &requestContext{Tx: tx, TenantID: tenantID, Grants: grantsFor(authz.CapClusterRead)}

	url := "/api/v1/clusters"
	if rawQuery != "" {
		url += "?" + rawQuery
	}
	rec := httptest.NewRecorder()
	s.handleListClusters(rec, httptest.NewRequest(http.MethodGet, url, nil), rc)
	return rec
}

// listedClusters decodes a 200 body into id -> the raw cluster object.
func listedClusters(t *testing.T, rec *httptest.ResponseRecorder) map[string]map[string]any {
	t.Helper()
	if rec.Code != http.StatusOK {
		t.Fatalf("handleListClusters status = %d, body: %s", rec.Code, rec.Body.String())
	}
	var body struct {
		Clusters []map[string]any `json:"clusters"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal %s: %v", rec.Body.String(), err)
	}
	byID := make(map[string]map[string]any, len(body.Clusters))
	for _, c := range body.Clusters {
		id, _ := c["id"].(string)
		byID[id] = c
	}
	return byID
}

// TestListClustersDefaultStillExcludesRetiredClusters is the half that must
// not regress. No parameter means the live fleet, which is what every cluster
// picker and cluster count in the web UI asks for.
func TestListClustersDefaultStillExcludesRetiredClusters(t *testing.T) {
	pool := authTestPool(t)
	ctx := context.Background()
	tenantID, err := singleOrgIDForTest(ctx, pool)
	if err != nil {
		t.Fatalf("resolve tenant: %v", err)
	}
	s := &Server{}
	liveID, retiredID := archivedFilterFixture(t, pool, tenantID)

	got := listedClusters(t, listClustersViaHandler(t, s, pool, tenantID, ""))
	if _, ok := got[liveID]; !ok {
		t.Errorf("the live cluster is missing from the default list")
	}
	if _, ok := got[retiredID]; ok {
		t.Errorf("a decommissioned cluster came back from GET /clusters with no ?archived= — " +
			"every cluster picker, count and scope control in the UI calls this route " +
			"exactly that way, so this leaks a dead cluster into all of them at once")
	}
}

// TestListClustersArchivedOnlyReturnsOnlyRetiredClusters is the new
// behaviour, and fails against the pre-change handler: it ignored the
// parameter entirely and returned the LIVE fleet for this request, so the
// retirement view would have been populated with the clusters it is supposed
// to exclude.
func TestListClustersArchivedOnlyReturnsOnlyRetiredClusters(t *testing.T) {
	pool := authTestPool(t)
	ctx := context.Background()
	tenantID, err := singleOrgIDForTest(ctx, pool)
	if err != nil {
		t.Fatalf("resolve tenant: %v", err)
	}
	s := &Server{}
	liveID, retiredID := archivedFilterFixture(t, pool, tenantID)

	got := listedClusters(t, listClustersViaHandler(t, s, pool, tenantID, "archived=only"))
	retired, ok := got[retiredID]
	if !ok {
		t.Fatalf("?archived=only did not return the decommissioned cluster — " +
			"the Archived state exists and the hub writes it, so a retirement view has nothing to show")
	}
	if _, ok := got[liveID]; ok {
		t.Errorf("?archived=only returned a live cluster too — the retirement view would " +
			"show clusters that are still running, which is the opposite of what it claims")
	}
	if got := retired["archivedAt"]; got != "2026-03-04T05:06:07Z" {
		t.Errorf("archivedAt = %v, want the stored timestamp — a retirement list is consulted "+
			"for WHEN a cluster was taken out, and the UI must not have to infer that from the state string", got)
	}
	if got := retired["state"]; got != "Archived" {
		t.Errorf("state = %v, want Archived", got)
	}
}

// TestListClustersArchivedIncludeReturnsBoth covers the third value, and the
// live row's archivedAt in the same pass: null, explicitly present, never
// absent — a client that treats a missing key as "not archived" and a null as
// an error would behave differently against the two, so the wire shape has to
// be one of them, decided here.
func TestListClustersArchivedIncludeReturnsBoth(t *testing.T) {
	pool := authTestPool(t)
	ctx := context.Background()
	tenantID, err := singleOrgIDForTest(ctx, pool)
	if err != nil {
		t.Fatalf("resolve tenant: %v", err)
	}
	s := &Server{}
	liveID, retiredID := archivedFilterFixture(t, pool, tenantID)

	got := listedClusters(t, listClustersViaHandler(t, s, pool, tenantID, "archived=include"))
	live, ok := got[liveID]
	if !ok {
		t.Fatalf("?archived=include dropped the live cluster")
	}
	if _, ok := got[retiredID]; !ok {
		t.Errorf("?archived=include dropped the retired cluster")
	}
	archivedAt, present := live["archivedAt"]
	if !present {
		t.Errorf("a live cluster's archivedAt key is absent; the spec marks it required, so it must be present and null")
	}
	if archivedAt != nil {
		t.Errorf("a live cluster's archivedAt = %v, want null", archivedAt)
	}
}

// TestListClustersRejectsUnknownArchivedFilter: a misspelled value must not
// fall back to the default. Silently answering a different question than the
// one asked is how "the retirement view is empty, so nothing has been
// decommissioned" gets believed.
func TestListClustersRejectsUnknownArchivedFilter(t *testing.T) {
	pool := authTestPool(t)
	ctx := context.Background()
	tenantID, err := singleOrgIDForTest(ctx, pool)
	if err != nil {
		t.Fatalf("resolve tenant: %v", err)
	}
	s := &Server{}
	archivedFilterFixture(t, pool, tenantID)

	rec := listClustersViaHandler(t, s, pool, tenantID, "archived=archived")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for an unrecognised ?archived= value; body: %s", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/problem+json" {
		t.Errorf("Content-Type = %q, want application/problem+json (RFC 9457)", ct)
	}
}
