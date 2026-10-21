package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"argus/internal/authz"
	"argus/internal/data"
	"argus/internal/domain"
)

// GET /api/v1/fleet/summary against a real Postgres, in one rolled-back
// transaction. Two throwaway clusters, both with facts and a stored check;
// the viewer holds cluster:inspect on only one. The other must still be
// listed with its facts, with its checks withheld and checksReadable false —
// the same answer the inspect route would give for that cluster.
func TestFleetSummaryWithholdsChecksWithoutInspect(t *testing.T) {
	pool := authTestPool(t)
	ctx := context.Background()
	tenantID, err := singleOrgIDForTest(ctx, pool)
	if err != nil {
		t.Fatalf("resolve tenant: %v", err)
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if err := data.SetRequestScope(ctx, tx, tenantID, nil); err != nil {
		t.Fatalf("set scope: %v", err)
	}
	seen, hidden := domain.NewID(domain.PrefixCluster), domain.NewID(domain.PrefixCluster)
	// cluster_facts' policy wants the cluster named in scope to write it.
	if err := data.SetRequestScope(ctx, tx, tenantID, []string{seen, hidden}); err != nil {
		t.Fatalf("set scope: %v", err)
	}
	for _, id := range []string{seen, hidden} {
		if _, err := tx.Exec(ctx, `INSERT INTO clusters (id, tenant_id, display_name, state, shard_id, cluster_fingerprint)
			VALUES ($1, $2, $3, 'Active', 'shard-test', $4)`, id, tenantID, "fleet-summary-test-"+id, "fp-"+id); err != nil {
			t.Fatalf("insert cluster: %v", err)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO cluster_facts (cluster_id, facts)
			VALUES ($1, '{"kubernetesVersion":"v1.30.2","nodeCount":1,"reachable":true,"nodes":[{"name":"n1","ready":true}],"objectCache":{"kinds":[]}}')`, id); err != nil {
			t.Fatalf("insert facts: %v", err)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO fleet_check_snapshots (tenant_id, cluster_id, check_name, summary, summary_at)
			VALUES ($1, $2, 'helm', '{"total":2,"listed":2,"failing":1,"truncated":false}', now())`, tenantID, id); err != nil {
			t.Fatalf("insert snapshot: %v", err)
		}
	}

	// The request itself runs as requireAuth sets it for an AllClusters
	// reader: tenant scope, no cluster narrowing.
	if err := data.SetRequestScope(ctx, tx, tenantID, nil); err != nil {
		t.Fatalf("set scope: %v", err)
	}
	rc := &requestContext{Tx: tx, TenantID: tenantID, Grants: []authz.EffectiveGrant{
		{Capability: authz.CapClusterRead, Scope: authz.Scope{Type: "AllClusters"}},
		{Capability: authz.CapClusterInspect, Scope: authz.Scope{Type: "Cluster", ClusterID: seen}},
	}}
	rec := httptest.NewRecorder()
	(&Server{}).handleFleetSummary(rec, httptest.NewRequest(http.MethodGet, "/api/v1/fleet/summary", nil), rc)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	var body struct {
		IntervalSeconds int `json:"intervalSeconds"`
		Clusters        []struct {
			ClusterID      string                     `json:"clusterId"`
			Facts          map[string]json.RawMessage `json:"facts"`
			ChecksReadable bool                       `json:"checksReadable"`
			Checks         map[string]json.RawMessage `json:"checks"`
		} `json:"clusters"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.IntervalSeconds <= 0 {
		t.Errorf("intervalSeconds = %d", body.IntervalSeconds)
	}
	found := 0
	for _, c := range body.Clusters {
		switch c.ClusterID {
		case seen:
			found++
			if !c.ChecksReadable || c.Checks["helm"] == nil {
				t.Errorf("inspectable cluster: readable=%v checks=%v", c.ChecksReadable, c.Checks)
			}
		case hidden:
			found++
			if c.ChecksReadable || len(c.Checks) != 0 {
				t.Errorf("cluster without inspect leaked checks: readable=%v checks=%v", c.ChecksReadable, c.Checks)
			}
		default:
			continue
		}
		if string(c.Facts["kubernetesVersion"]) != `"v1.30.2"` || c.Facts["nodes"] == nil {
			t.Errorf("facts digest missing fields: %v", c.Facts)
		}
		if _, ok := c.Facts["objectCache"]; ok {
			t.Errorf("facts digest carried the object cache report")
		}
	}
	if found != 2 {
		t.Fatalf("found %d of the 2 fixture clusters", found)
	}

	// A viewer whose cluster:read is scoped to one cluster is not shown the
	// other at all — neither its facts nor its existence.
	if err := data.SetRequestScope(ctx, tx, tenantID, nil); err != nil {
		t.Fatalf("reset scope: %v", err)
	}
	rc = &requestContext{Tx: tx, TenantID: tenantID, Grants: []authz.EffectiveGrant{
		{Capability: authz.CapClusterRead, Scope: authz.Scope{Type: "Cluster", ClusterID: seen}},
	}}
	rec = httptest.NewRecorder()
	(&Server{}).handleFleetSummary(rec, httptest.NewRequest(http.MethodGet, "/api/v1/fleet/summary", nil), rc)
	if rec.Code != http.StatusOK {
		t.Fatalf("scoped status %d: %s", rec.Code, rec.Body.String())
	}
	body.Clusters = nil
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(body.Clusters) != 1 || body.Clusters[0].ClusterID != seen || body.Clusters[0].ChecksReadable {
		t.Fatalf("scoped reader: got %+v, want only %s, with checks withheld (no cluster:inspect)", body.Clusters, seen)
	}
}
