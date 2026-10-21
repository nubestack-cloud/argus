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

	"argus/internal/authz"
	"argus/internal/clustertimeline"
	"argus/internal/data"
	"argus/internal/dbtest"
	"argus/internal/domain"
)

// PROJECT.md AD1 — GET /api/v1/clusters/{id}/timeline through the handler:
// the response matches docs/openapi.yaml's ClusterTimeline, and a caller
// with cluster:read but not incident:read gets the changes and a named
// restriction rather than findings and incidents. The assembly itself is
// covered against a real Postgres in internal/clustertimeline.

func timelineHandlerFixture(t *testing.T, pool *pgxpool.Pool) (tenantID, clusterID string) {
	t.Helper()
	ctx := context.Background()
	clusterID = domain.NewID(domain.PrefixCluster)
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if tenantID, err = data.SingleOrganisationID(ctx, tx); err != nil {
		t.Fatal(err)
	}
	if err := data.SetRequestScope(ctx, tx, tenantID, []string{clusterID}); err != nil {
		t.Fatal(err)
	}
	fx := dbtest.New(t)
	now := time.Now()
	for _, q := range []struct {
		table string
		sql   string
		args  []any
	}{
		{"clusters", `INSERT INTO clusters (id, tenant_id, display_name, state, shard_id, cluster_fingerprint) VALUES ($1,$2,$3,'Active','shard-test',$3)`,
			[]any{clusterID, tenantID, "timeline-api-" + clusterID}},
		{"resource_changes", `INSERT INTO resource_changes (id, tenant_id, cluster_id, observed_at, kind, api_group, namespace, name, op, summary) VALUES ($1,$2,$3,$4,'Deployment','apps','shop','web','update','image web:1 → web:2')`,
			[]any{domain.NewID(domain.PrefixResourceChange), tenantID, clusterID, now.Add(-30 * time.Minute)}},
		{"findings", `INSERT INTO findings (id, tenant_id, cluster_id, detector_id, detector_version, fingerprint, gvk, namespace, object_name, reason, message, severity, occurred_at, signal_class, confidence, impact)
			VALUES ($1,$2,$3,'k8s-warning-events','v1',$4,'apps/v1/Deployment','shop','web','ProgressDeadlineExceeded','rollout stalled','high',$5,'fault','verified','degraded')`,
			[]any{domain.NewID(domain.PrefixFinding), tenantID, clusterID, "fp-ad1-" + clusterID, now.Add(-20 * time.Minute)}},
		{"incidents", `INSERT INTO incidents (id, tenant_id, cluster_id, fingerprint, severity, state, first_seen, last_seen, occurrence_count, opening_reason, object_key)
			VALUES ($1,$2,$3,$4,'high','Detected',$5,$5,1,'ProgressDeadlineExceeded','apps/v1/Deployment|shop|web')`,
			[]any{domain.NewID(domain.PrefixIncident), tenantID, clusterID, "fp-inc-ad1-" + clusterID, now.Add(-20 * time.Minute)}},
	} {
		if _, err := tx.Exec(ctx, q.sql, q.args...); err != nil {
			t.Fatalf("insert %s: %v", q.table, err)
		}
		fx.Created(q.table, 1)
	}
	fx.OwnsCluster(tenantID, clusterID)
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	fx.Cleanup(pool, func(ctx context.Context, tx pgx.Tx) error {
		return data.SetRequestScope(ctx, tx, tenantID, []string{clusterID})
	}, []dbtest.TableDelete{
		{Table: "resource_changes", SQL: `DELETE FROM resource_changes WHERE cluster_id = $1`, Args: []any{clusterID}},
		{Table: "findings", SQL: `DELETE FROM findings WHERE cluster_id = $1`, Args: []any{clusterID}},
		{Table: "incidents", SQL: `DELETE FROM incidents WHERE cluster_id = $1`, Args: []any{clusterID}},
		{Table: "clusters", SQL: `DELETE FROM clusters WHERE id = $1`, Args: []any{clusterID}},
	})
	return tenantID, clusterID
}

func callClusterTimeline(t *testing.T, pool *pgxpool.Pool, tenantID, clusterID, query string, caps ...string) (int, []byte) {
	t.Helper()
	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if err := data.SetRequestScope(ctx, tx, tenantID, nil); err != nil {
		t.Fatal(err)
	}
	var grants []authz.EffectiveGrant
	for _, c := range caps {
		grants = append(grants, authz.EffectiveGrant{Capability: c, Scope: authz.Scope{Type: "Cluster", ClusterID: clusterID}})
	}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/clusters/"+clusterID+"/timeline?"+query, nil)
	req.SetPathValue("id", clusterID)
	rec := httptest.NewRecorder()
	(&Server{}).handleClusterTimeline(rec, req, &requestContext{Tx: tx, TenantID: tenantID, UserID: "usr_ad1_test", Grants: grants})
	return rec.Code, rec.Body.Bytes()
}

func TestClusterTimelineHandlerMatchesSpecAndRestrictsBySource(t *testing.T) {
	pool := authTestPool(t)
	tenantID, clusterID := timelineHandlerFixture(t, pool)

	code, body := callClusterTimeline(t, pool, tenantID, clusterID, "", authz.CapClusterRead, authz.CapIncidentRead)
	if code != http.StatusOK {
		t.Fatalf("status %d: %s", code, body)
	}
	assertMatchesSchema(t, "ClusterTimeline", body)
	var full clustertimeline.Response
	if err := json.Unmarshal(body, &full); err != nil {
		t.Fatal(err)
	}
	if full.Totals.Changes != 1 || full.Totals.FindingRuns != 1 || full.Totals.Incidents != 1 || len(full.Restricted) != 0 || len(full.Rows) != 1 {
		t.Fatalf("full = %+v", full)
	}

	code, body = callClusterTimeline(t, pool, tenantID, clusterID, "", authz.CapClusterRead)
	if code != http.StatusOK {
		t.Fatalf("status %d: %s", code, body)
	}
	assertMatchesSchema(t, "ClusterTimeline", body)
	var limited clustertimeline.Response
	if err := json.Unmarshal(body, &limited); err != nil {
		t.Fatal(err)
	}
	if len(limited.Restricted) != 2 || limited.Restricted[0].Capability != authz.CapIncidentRead {
		t.Errorf("restricted = %+v, want findings and incidents named with incident:read", limited.Restricted)
	}
	if limited.Totals.FindingRuns != 0 || limited.Totals.Incidents != 0 || len(limited.Types) != 1 || limited.Types[0] != "changes" {
		t.Errorf("a caller without incident:read was sent findings or incidents: %+v", limited)
	}
	if len(limited.Rows) != 1 || len(limited.Rows[0].Spans) != 0 {
		t.Errorf("rows = %+v", limited.Rows)
	}
}

func TestClusterTimelineHandlerRejectsBadParameters(t *testing.T) {
	pool := authTestPool(t)
	tenantID, clusterID := timelineHandlerFixture(t, pool)
	now := time.Now().UTC()
	for name, q := range map[string]string{
		"window over 7 days": "since=" + now.Add(-8*24*time.Hour).Format(time.RFC3339) + "&until=" + now.Format(time.RFC3339),
		"since after until":  "since=" + now.Format(time.RFC3339) + "&until=" + now.Add(-time.Hour).Format(time.RFC3339),
		"bad since":          "since=yesterday",
		"unknown type":       "types=changes,events",
		"bad onlyIncidents":  "onlyIncidents=yes",
	} {
		code, body := callClusterTimeline(t, pool, tenantID, clusterID, q, authz.CapClusterRead, authz.CapIncidentRead)
		if code != http.StatusBadRequest {
			t.Errorf("%s: status %d, want 400: %s", name, code, body)
			continue
		}
		assertMatchesProblemSchema(t, body)
	}
}
