package api

// PROJECT.md B177's API-layer half. Everything inside `facts` is an
// absolute-state snapshot — a detector's last success, the reads RBAC
// denies, the node count — and a snapshot carries no evidence of its own
// age. Before the agent re-sent its facts periodically, the stored snapshot
// was whatever the last tunnel reconnect happened to produce, and a reader
// had no way to tell "the sweep detector succeeded two minutes ago" from the
// same sentence recorded an hour earlier and never revisited.
//
// `factsUpdatedAt` is that missing evidence: when the HUB last received the
// payload, on the hub's own clock. These tests pin both halves of its
// contract — present and truthful when there is a facts row, absent rather
// than a fabricated zero time when there is not.
//
// Skips cleanly with no ARGUS_TEST_DATABASE_URL. Point it at argus_app, not
// postgres, for the reason RUNBOOK.md gives.

import (
	"context"
	"testing"
	"time"

	"argus/internal/data"
)

// TestHandleGetClusterReportsWhenItLastHeardTheFacts is the present case: a
// facts row written just now must come back with a parseable, recent
// factsUpdatedAt beside it.
func TestHandleGetClusterReportsWhenItLastHeardTheFacts(t *testing.T) {
	pool := authTestPool(t)
	ctx := context.Background()
	tenantID, err := singleOrgIDForTest(ctx, pool)
	if err != nil {
		t.Fatalf("resolve tenant: %v", err)
	}
	clusterID := clusterGroupTestCluster(t, pool, tenantID)

	before := time.Now().UTC().Add(-time.Minute)
	insertClusterFactsFixtureRaw(t, pool, tenantID, clusterID,
		`{"kubernetesVersion":"v1.30.0","nodeCount":1,"nodes":[],"reachable":true,
		  "detectors":{"sweep":{"lastSuccessAt":"2026-09-18T09:00:00Z"}}}`)

	s := &Server{db: &data.DB{Pool: pool}}
	body := getClusterViaHandler(t, s, pool, tenantID, clusterID)

	raw, ok := body["factsUpdatedAt"].(string)
	if !ok || raw == "" {
		t.Fatalf(`body["factsUpdatedAt"] = %v (%T), want an RFC 3339 timestamp — without it a detector status of any age reads as current`, body["factsUpdatedAt"], body["factsUpdatedAt"])
	}
	got, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		t.Fatalf("factsUpdatedAt %q does not parse as RFC 3339: %v", raw, err)
	}
	if got.Before(before) || got.After(time.Now().UTC().Add(time.Minute)) {
		t.Errorf("factsUpdatedAt = %v, want roughly now — it must report when the hub RECEIVED the facts, not a value taken from inside them", got)
	}
}

// TestHandleGetClusterOmitsFactsFreshnessWhenNoFactsExist is the absent
// case, and the one that matters most: a cluster whose agent has never
// completed an inventory sync has no freshness to report, and a zero
// timestamp would be a fabricated one — the same discipline that forbids
// rendering a missing count as 0.
func TestHandleGetClusterOmitsFactsFreshnessWhenNoFactsExist(t *testing.T) {
	pool := authTestPool(t)
	ctx := context.Background()
	tenantID, err := singleOrgIDForTest(ctx, pool)
	if err != nil {
		t.Fatalf("resolve tenant: %v", err)
	}
	clusterID := clusterGroupTestCluster(t, pool, tenantID) // deliberately no cluster_facts row

	s := &Server{db: &data.DB{Pool: pool}}
	body := getClusterViaHandler(t, s, pool, tenantID, clusterID)

	if body["facts"] != nil {
		t.Fatalf(`body["facts"] = %v, want null for a cluster that never synced`, body["facts"])
	}
	value, present := body["factsUpdatedAt"]
	if !present {
		t.Fatalf(`body has no "factsUpdatedAt" key at all; the field is required by docs/openapi.yaml's ClusterDetail`)
	}
	if value != nil {
		t.Fatalf(`body["factsUpdatedAt"] = %v, want null — a cluster with no facts has no freshness to claim`, value)
	}
}
