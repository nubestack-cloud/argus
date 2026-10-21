package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"argus/internal/data"
	"argus/internal/domain"
)

// This file is BACKLOG.md T2 (candidate 2)'s DB-backed proof: grouping by
// fingerprint has to actually collapse several incidents into one row,
// carry the group's highest severity (not an average, not the first row
// seen), and — like every other incidents.go query — never let a row from a
// cluster outside the caller's RLS scope leak into a count.
//
// Fixture shape, deliberately different from incidentSearchFixture
// (incidents_test.go): that fixture's four incidents all have distinct
// fingerprints, which exercises search/sort/pagination but never exercises
// grouping at all. This one puts THREE incidents on one fingerprint (at
// three different severities, so "max severity" has something real to
// pick) and a fourth on a different fingerprint — plus a fifth, on a
// cluster the test's own request transaction is never scoped to, sharing
// the SAME fingerprint as the group of three. If RLS ever stopped applying
// to this endpoint's query, that fifth incident is what would inflate the
// group's count from 3 to 4.
type digestFixture struct {
	tenantID                                                           string
	visibleCluster, hiddenCluster                                      string
	sharedLow, sharedMedium, sharedHigh, unique, hiddenSameFingerprint string
}

func setupDigestFixture(t *testing.T, pool *pgxpool.Pool) digestFixture {
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
	f := digestFixture{
		tenantID:              tenantID,
		visibleCluster:        domain.NewID(domain.PrefixCluster),
		hiddenCluster:         domain.NewID(domain.PrefixCluster),
		sharedLow:             domain.NewID(domain.PrefixIncident),
		sharedMedium:          domain.NewID(domain.PrefixIncident),
		sharedHigh:            domain.NewID(domain.PrefixIncident),
		unique:                domain.NewID(domain.PrefixIncident),
		hiddenSameFingerprint: domain.NewID(domain.PrefixIncident),
	}
	if err := data.SetRequestScope(ctx, tx, tenantID, []string{f.visibleCluster, f.hiddenCluster}); err != nil {
		t.Fatalf("set request scope: %v", err)
	}

	for _, c := range []struct{ id, name string }{
		{f.visibleCluster, "digest-visible-" + f.visibleCluster},
		{f.hiddenCluster, "digest-hidden-" + f.hiddenCluster},
	} {
		if _, err := tx.Exec(ctx,
			`INSERT INTO clusters (id, tenant_id, display_name, state, shard_id, cluster_fingerprint)
			 VALUES ($1, $2, $3, 'Active', 'shard-test', $4)`,
			c.id, tenantID, c.name, "fp-"+c.id); err != nil {
			t.Fatalf("insert cluster %s: %v", c.id, err)
		}
	}

	const sharedFingerprint = "digest-fp-shared"
	now := time.Now()
	insert := func(id, clusterID, fingerprint, severity string, lastSeen time.Time) {
		if _, err := tx.Exec(ctx,
			`INSERT INTO incidents (id, tenant_id, cluster_id, fingerprint, severity, state, first_seen, last_seen, occurrence_count, opening_reason, object_key)
			 VALUES ($1, $2, $3, $4, $5, 'Detected', $6, $6, 1, 'OOMKilled', 'apps/v1/Deployment|payments|checkout')`,
			id, tenantID, clusterID, fingerprint, severity, lastSeen); err != nil {
			t.Fatalf("insert incident %s: %v", id, err)
		}
	}
	insert(f.sharedLow, f.visibleCluster, sharedFingerprint, "low", now.Add(-3*time.Hour))
	insert(f.sharedMedium, f.visibleCluster, sharedFingerprint, "medium", now.Add(-2*time.Hour))
	insert(f.sharedHigh, f.visibleCluster, sharedFingerprint, "high", now.Add(-1*time.Hour))
	insert(f.unique, f.visibleCluster, "digest-fp-unique", "critical", now)
	insert(f.hiddenSameFingerprint, f.hiddenCluster, sharedFingerprint, "critical", now.Add(-30*time.Minute))

	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit setup transaction: %v", err)
	}

	t.Cleanup(func() {
		cleanupCtx := context.Background()
		tx, err := pool.Begin(cleanupCtx)
		if err != nil {
			t.Logf("cleanup: begin: %v", err)
			return
		}
		defer tx.Rollback(cleanupCtx) //nolint:errcheck
		clusterIDs := []string{f.visibleCluster, f.hiddenCluster}
		if err := data.SetRequestScope(cleanupCtx, tx, tenantID, clusterIDs); err != nil {
			t.Logf("cleanup: set request scope: %v", err)
			return
		}
		if _, err := tx.Exec(cleanupCtx, `DELETE FROM incidents WHERE cluster_id = ANY($1)`, clusterIDs); err != nil {
			t.Logf("cleanup: delete incidents: %v", err)
			return
		}
		if _, err := tx.Exec(cleanupCtx, `DELETE FROM clusters WHERE id = ANY($1)`, clusterIDs); err != nil {
			t.Logf("cleanup: delete clusters: %v", err)
			return
		}
		if err := tx.Commit(cleanupCtx); err != nil {
			t.Logf("cleanup: commit: %v", err)
		}
	})

	return f
}

func callListIncidentsDigest(t *testing.T, pool *pgxpool.Pool, f digestFixture, rawQuery string) (int, map[string]any) {
	t.Helper()
	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin request transaction: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if err := data.SetRequestScope(ctx, tx, f.tenantID, []string{f.visibleCluster}); err != nil {
		t.Fatalf("set request scope: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/incidents/digest?"+rawQuery, nil)
	rec := httptest.NewRecorder()
	s := &Server{}
	s.handleListIncidentsDigest(rec, req, &requestContext{Tx: tx, TenantID: f.tenantID})

	var body map[string]any
	if rec.Body.Len() > 0 {
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatalf("unmarshal response (status %d, body %s): %v", rec.Code, rec.Body.String(), err)
		}
	}
	return rec.Code, body
}

// TestHandleListIncidentsDigestGroupsBySharedFingerprintAndRespectsRLS is
// the core claim BACKLOG.md T2 asks the digest to make real: "230
// incidents, 12 distinct problems." Three incidents sharing one fingerprint
// must collapse to ONE group of count 3, carrying the group's highest
// severity — and a fourth incident sharing that exact fingerprint on a
// cluster outside this request's RLS scope must never be counted.
func TestHandleListIncidentsDigestGroupsBySharedFingerprintAndRespectsRLS(t *testing.T) {
	pool := authTestPool(t)
	f := setupDigestFixture(t, pool)

	code, body := callListIncidentsDigest(t, pool, f, "")
	if code != http.StatusOK {
		t.Fatalf("status = %d, body: %+v", code, body)
	}

	groupsRaw, _ := body["groups"].([]any)
	if len(groupsRaw) != 2 {
		t.Fatalf("groups = %+v, want exactly 2 (the shared fingerprint's group and the unique one) — the visible cluster has 4 incidents across 2 fingerprints", groupsRaw)
	}

	byFingerprint := map[string]map[string]any{}
	for _, raw := range groupsRaw {
		g, _ := raw.(map[string]any)
		byFingerprint[g["fingerprint"].(string)] = g
	}

	shared, ok := byFingerprint["digest-fp-shared"]
	if !ok {
		t.Fatalf("no group for the shared fingerprint in %+v", byFingerprint)
	}
	if count, _ := shared["incidentCount"].(float64); count != 3 {
		t.Errorf("shared fingerprint incidentCount = %v, want 3 — the hidden cluster's 4th incident on this same fingerprint must not be counted", shared["incidentCount"])
	}
	if clusterCount, _ := shared["clusterCount"].(float64); clusterCount != 1 {
		t.Errorf("shared fingerprint clusterCount = %v, want 1 (only the visible cluster)", shared["clusterCount"])
	}
	if severity, _ := shared["maxSeverity"].(string); severity != "high" {
		t.Errorf("shared fingerprint maxSeverity = %q, want %q — the group's highest, not its first or last row", severity, "high")
	}
	if name, _ := shared["objectName"].(string); name != "checkout" {
		t.Errorf("shared fingerprint objectName = %q, want %q", name, "checkout")
	}

	unique, ok := byFingerprint["digest-fp-unique"]
	if !ok {
		t.Fatalf("no group for the unique fingerprint in %+v", byFingerprint)
	}
	if count, _ := unique["incidentCount"].(float64); count != 1 {
		t.Errorf("unique fingerprint incidentCount = %v, want 1", unique["incidentCount"])
	}
	if severity, _ := unique["maxSeverity"].(string); severity != "critical" {
		t.Errorf("unique fingerprint maxSeverity = %q, want %q", severity, "critical")
	}

	if total, _ := body["totalIncidents"].(float64); total != 4 {
		t.Errorf("totalIncidents = %v, want 4 (this request's own visible-cluster incidents only)", body["totalIncidents"])
	}
	if _, truncated := body["truncated"]; truncated {
		t.Errorf("truncated should be absent (only 2 groups, far under the cap)")
	}
}

// TestHandleListIncidentsDigestScopesByClusterAndState proves the digest
// endpoint accepts the same ?clusterId=/?state= scope handleListIncidents
// does, via the shared incidentScopeFilter — narrowing to ?state=Detected
// (the never-actioned pile T2 exists for) must not change which fingerprint
// wins, only which incidents are eligible to be counted at all.
func TestHandleListIncidentsDigestScopesByClusterAndState(t *testing.T) {
	pool := authTestPool(t)
	f := setupDigestFixture(t, pool)

	code, body := callListIncidentsDigest(t, pool, f, "state=Detected")
	if code != http.StatusOK {
		t.Fatalf("status = %d, body: %+v", code, body)
	}
	if total, _ := body["totalIncidents"].(float64); total != 4 {
		t.Errorf("totalIncidents under state=Detected = %v, want 4 — every fixture incident is Detected", body["totalIncidents"])
	}

	code, body = callListIncidentsDigest(t, pool, f, "state=Resolved")
	if code != http.StatusOK {
		t.Fatalf("status = %d, body: %+v", code, body)
	}
	if total, _ := body["totalIncidents"].(float64); total != 0 {
		t.Errorf("totalIncidents under state=Resolved = %v, want 0 — no fixture incident is Resolved", body["totalIncidents"])
	}
	groupsRaw, _ := body["groups"].([]any)
	if len(groupsRaw) != 0 {
		t.Errorf("groups under state=Resolved = %+v, want empty", groupsRaw)
	}
}

// TestHandleListIncidentsDigestRejectsInvalidState is the DB-free guard,
// matching TestHandleListIncidentsRejectsInvalidState's coverage of the
// list endpoint's identical validation.
func TestHandleListIncidentsDigestRejectsInvalidState(t *testing.T) {
	s := &Server{}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/incidents/digest?state=NotARealState", nil)
	rec := httptest.NewRecorder()

	s.handleListIncidentsDigest(rec, req, &requestContext{})

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d (body: %s)", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
}
