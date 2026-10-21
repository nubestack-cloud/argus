package api

// PROJECT.md T13's API-layer proof: handleGetCluster's `facts` field is a
// raw passthrough of the cluster_facts.facts jsonb column (see
// handleGetCluster's own comment — it never decodes ClusterFacts into a Go
// struct, so an additive field on the wire type needs no handler change to
// reach the browser). What actually needs proving here is that this stays
// true against a REAL Postgres row, for both the new-agent shape (a
// "detectors" key present) and the old-agent shape (no such key at all) —
// the absent-vs-present distinction this feature's whole "unknown, not
// failing" contract depends on must survive the DB round trip untouched,
// not just survive json.Marshal/Unmarshal in a pure Go test.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"argus/internal/authz"
	"argus/internal/data"
)

// insertClusterFactsFixtureRaw upserts a cluster_facts row with the exact
// raw JSON bytes given — deliberately raw rather than built from
// tunnel.ClusterFacts, so a test can construct the pre-T13 (no "detectors"
// key at all) shape an older agent would have sent, which a Go struct
// literal with omitempty can't represent (Go can't express "this field is
// absent" via a typed zero value the way the wire contract needs).
func insertClusterFactsFixtureRaw(t *testing.T, pool *pgxpool.Pool, tenantID, clusterID, factsJSON string) {
	t.Helper()
	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if err := data.SetRequestScope(ctx, tx, tenantID, []string{clusterID}); err != nil {
		t.Fatalf("set request scope: %v", err)
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO cluster_facts (cluster_id, facts, updated_at) VALUES ($1, $2, now())
		 ON CONFLICT (cluster_id) DO UPDATE SET facts = EXCLUDED.facts, updated_at = now()`,
		clusterID, []byte(factsJSON)); err != nil {
		t.Fatalf("insert cluster_facts: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit: %v", err)
	}
	t.Cleanup(func() {
		cleanupCtx := context.Background()
		tx, err := pool.Begin(cleanupCtx)
		if err != nil {
			return
		}
		defer tx.Rollback(cleanupCtx) //nolint:errcheck
		if err := data.SetRequestScope(cleanupCtx, tx, tenantID, []string{clusterID}); err != nil {
			return
		}
		_, _ = tx.Exec(cleanupCtx, `DELETE FROM cluster_facts WHERE cluster_id = $1`, clusterID)
		_ = tx.Commit(cleanupCtx)
	})
}

// getClusterViaHandler runs a real GET /api/v1/clusters/{id} through
// handleGetCluster against a real Postgres transaction (AllClusters-scoped
// grant, matching grantsFor's existing convention elsewhere in this
// package), and returns the decoded JSON body.
func getClusterViaHandler(t *testing.T, s *Server, pool *pgxpool.Pool, tenantID, clusterID string) map[string]any {
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

	req := httptest.NewRequest(http.MethodGet, "/api/v1/clusters/"+clusterID, nil)
	req.SetPathValue("id", clusterID)
	rec := httptest.NewRecorder()
	s.handleGetCluster(rec, req, rc)

	if rec.Code != http.StatusOK {
		t.Fatalf("handleGetCluster status = %d, body: %s", rec.Code, rec.Body.String())
	}
	var got map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal response body %s: %v", rec.Body.String(), err)
	}
	return got
}

// TestHandleGetClusterCarriesDetectorsFieldThroughUntouched proves the
// happy path end to end: an agent build new enough to report per-detector
// run health (tunnel.ClusterFacts.Detectors) has that fact reach the API
// response exactly as stored — same keys, same values — through a REAL
// cluster_facts row, not a mocked DB.
func TestHandleGetClusterCarriesDetectorsFieldThroughUntouched(t *testing.T) {
	pool := authTestPool(t)
	ctx := context.Background()
	tenantID, err := singleOrgIDForTest(ctx, pool)
	if err != nil {
		t.Fatalf("resolve tenant: %v", err)
	}
	clusterID := clusterGroupTestCluster(t, pool, tenantID)

	factsJSON := `{
		"kubernetesVersion": "v1.30.0",
		"nodeCount": 3,
		"nodes": [],
		"reachable": true,
		"detectors": {
			"warningEvents": {"lastSuccessAt": "2026-09-18T09:00:00Z"},
			"podConditions": {"lastSuccessAt": "2026-09-18T09:00:00Z"},
			"sweep": {"error": "jobs: forbidden", "errorAt": "2026-09-18T08:55:00Z", "deniedReads": ["jobs"]}
		}
	}`
	insertClusterFactsFixtureRaw(t, pool, tenantID, clusterID, factsJSON)

	s := &Server{db: &data.DB{Pool: pool}}
	body := getClusterViaHandler(t, s, pool, tenantID, clusterID)

	facts, ok := body["facts"].(map[string]any)
	if !ok {
		t.Fatalf(`body["facts"] = %v (%T), want an object`, body["facts"], body["facts"])
	}
	detectors, ok := facts["detectors"].(map[string]any)
	if !ok {
		t.Fatalf(`facts["detectors"] = %v (%T), want an object`, facts["detectors"], facts["detectors"])
	}

	sweep, ok := detectors["sweep"].(map[string]any)
	if !ok {
		t.Fatalf(`detectors["sweep"] = %v, want an object`, detectors["sweep"])
	}
	if sweep["error"] != "jobs: forbidden" {
		t.Errorf(`sweep["error"] = %v, want %q`, sweep["error"], "jobs: forbidden")
	}
	denied, _ := sweep["deniedReads"].([]any)
	if len(denied) != 1 || denied[0] != "jobs" {
		t.Errorf(`sweep["deniedReads"] = %v, want ["jobs"]`, sweep["deniedReads"])
	}

	warningEvents, ok := detectors["warningEvents"].(map[string]any)
	if !ok || warningEvents["lastSuccessAt"] != "2026-09-18T09:00:00Z" {
		t.Errorf(`detectors["warningEvents"] = %v, want lastSuccessAt 2026-09-18T09:00:00Z`, detectors["warningEvents"])
	}
}

// TestHandleGetClusterOmitsDetectorsForAnOlderAgentsFacts is the
// absent-field half of the same contract: a cluster_facts row shaped
// exactly like one an agent that PREDATES this feature would have sent (no
// "detectors" key anywhere) must come back with no "detectors" key either —
// never a fabricated all-healthy or all-failing object, and never dropped
// silently in a way that's indistinguishable from an error. This is the
// trap CLAUDE.md and internal/tunnel/protocol.go's own doc comments name
// explicitly: an absent field must read as unknown, not as healthy or
// failing.
func TestHandleGetClusterOmitsDetectorsForAnOlderAgentsFacts(t *testing.T) {
	pool := authTestPool(t)
	ctx := context.Background()
	tenantID, err := singleOrgIDForTest(ctx, pool)
	if err != nil {
		t.Fatalf("resolve tenant: %v", err)
	}
	clusterID := clusterGroupTestCluster(t, pool, tenantID)

	// Exactly the shape an agent built before this feature sends: no
	// "detectors" key at all (as opposed to, say, an explicit null).
	factsJSON := `{"kubernetesVersion": "v1.28.0", "nodeCount": 1, "nodes": [], "reachable": true}`
	insertClusterFactsFixtureRaw(t, pool, tenantID, clusterID, factsJSON)

	s := &Server{db: &data.DB{Pool: pool}}
	body := getClusterViaHandler(t, s, pool, tenantID, clusterID)

	facts, ok := body["facts"].(map[string]any)
	if !ok {
		t.Fatalf(`body["facts"] = %v (%T), want an object`, body["facts"], body["facts"])
	}
	if _, present := facts["detectors"]; present {
		t.Fatalf(`facts["detectors"] = %v, want the key entirely absent for an older agent's facts, not null or a fabricated value`, facts["detectors"])
	}
}
