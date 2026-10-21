package api

// openapi_contract_db_test.go is openapi_contract_test.go's DB-backed half:
// where that file proves the validator works and covers every
// no-database validation branch, this file proves the actual SUCCESS-path
// JSON a real handler sends over a real Postgres connection matches
// docs/openapi.yaml — the exact case PROJECT.md T12's motivating bug
// (B158, a list/detail shape divergence) lived in. It deliberately reuses
// this package's OWN existing fixtures (setupIncidentSearchFixture,
// setupApprovalQueryFixture, clusterGroupTestCluster) rather than inventing
// new ones — see CLAUDE.md/RUNBOOK.md's own "internal/dbtest exists because
// hand-written fixture cleanup has twice destroyed real data" warning;
// reusing an already-reviewed fixture is strictly safer than a new one for
// a suite whose entire point is catching drift, not creating it.
//
// Skips cleanly with no ARGUS_TEST_DATABASE_URL set, matching every other
// `*_db_test.go` in this package (see authTestPool). CI does not set it
// (this repo deliberately runs no Postgres service in CI — see
// .github/workflows/ci.yml's own comment) so this half runs wherever a
// developer or a release check points ARGUS_TEST_DATABASE_URL at
// argus_app.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"argus/internal/data"
)

func TestOpenAPIContract_IncidentsListMatchesSchema(t *testing.T) {
	pool := authTestPool(t)
	f := setupIncidentSearchFixture(t, pool)

	code, body := callListIncidents(t, pool, f, "sort=lastSeen&direction=desc")
	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %+v", code, body)
	}
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("re-marshal decoded body: %v", err)
	}
	assertMatchesSchema(t, "IncidentsResponse", raw)
}

func TestOpenAPIContract_IncidentDetailMatchesSchema(t *testing.T) {
	pool := authTestPool(t)
	f := setupIncidentSearchFixture(t, pool)

	body := callGetIncident(t, pool, f.tenantID, f.visibleCluster, f.critical)
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("re-marshal decoded body: %v", err)
	}
	assertMatchesSchema(t, "IncidentDetail", raw)
}

// callGetIncident mirrors callListIncidents' own shape (this file's sibling
// test files already establish the convention: open a request-scoped
// transaction, call the handler directly, decode the body) for
// handleGetIncident specifically, which none of this package's existing
// test files already had a reusable helper for.
func callGetIncident(t *testing.T, pool *pgxpool.Pool, tenantID, clusterID, incidentID string) map[string]any {
	t.Helper()
	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin request transaction: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if err := data.SetRequestScope(ctx, tx, tenantID, []string{clusterID}); err != nil {
		t.Fatalf("set request scope: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/incidents/"+incidentID, nil)
	req.SetPathValue("id", incidentID)
	rec := httptest.NewRecorder()
	s := &Server{}
	s.handleGetIncident(rec, req, &requestContext{Tx: tx, TenantID: tenantID})

	if rec.Code != http.StatusOK {
		t.Fatalf("handleGetIncident status = %d, body: %s", rec.Code, rec.Body.String())
	}
	var got map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal response body %s: %v", rec.Body.String(), err)
	}
	return got
}

func TestOpenAPIContract_ApprovalsListMatchesSchema(t *testing.T) {
	pool := authTestPool(t)
	f := setupApprovalQueryFixture(t, pool)

	code, body := callListApprovals(t, pool, f.tenantID, []string{f.clusterA, f.clusterB}, "")
	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %+v", code, body)
	}
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("re-marshal decoded body: %v", err)
	}
	assertMatchesSchema(t, "ApprovalsResponse", raw)
}

func TestOpenAPIContract_ClustersListAndDetailMatchSchema(t *testing.T) {
	pool := authTestPool(t)
	ctx := context.Background()
	tenantID, err := singleOrgIDForTest(ctx, pool)
	if err != nil {
		t.Fatalf("resolve tenant: %v", err)
	}
	clusterID := clusterGroupTestCluster(t, pool, tenantID)

	s := &Server{db: &data.DB{Pool: pool}}

	t.Run("detail", func(t *testing.T) {
		body := getClusterViaHandler(t, s, pool, tenantID, clusterID)
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("re-marshal decoded body: %v", err)
		}
		assertMatchesSchema(t, "ClusterDetail", raw)
	})

	t.Run("list", func(t *testing.T) {
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatalf("begin request transaction: %v", err)
		}
		defer tx.Rollback(ctx) //nolint:errcheck
		if err := data.SetRequestScope(ctx, tx, tenantID, []string{clusterID}); err != nil {
			t.Fatalf("set request scope: %v", err)
		}
		req := httptest.NewRequest(http.MethodGet, "/api/v1/clusters", nil)
		rec := httptest.NewRecorder()
		s.handleListClusters(rec, req, &requestContext{Tx: tx, TenantID: tenantID})
		if rec.Code != http.StatusOK {
			t.Fatalf("handleListClusters status = %d, body: %s", rec.Code, rec.Body.String())
		}
		var body map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatalf("unmarshal response body %s: %v", rec.Body.String(), err)
		}
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("re-marshal decoded body: %v", err)
		}
		assertMatchesSchema(t, "ClustersResponse", raw)
	})
}
