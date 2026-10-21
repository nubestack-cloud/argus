package api

// A failed audited inspection (get_logs) must leave an audit row, against a
// real Postgres. Audit rows are append-only (hash chain), so the rows this
// writes stay, like every other audited test path; they belong to a
// throwaway user id and a cluster id that exists nowhere else.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"argus/internal/authz"
	"argus/internal/data"
	"argus/internal/domain"
	"argus/internal/gateway"
	"argus/internal/upgradescans"
)

// The live defect: successful get_logs reads were audited but failed ones
// were not, because the audit row was written in the request transaction and
// every error response rolls that transaction back.
func TestFailedLogReadIsAuditedDespiteTheRollback(t *testing.T) {
	pool := authTestPool(t)
	ctx := context.Background()
	s := &Server{db: &data.DB{Pool: pool}}

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	tenantID, err := data.SingleOrganisationID(ctx, tx)
	if err != nil {
		t.Fatalf("organisation: %v", err)
	}
	if err := data.SetRequestScope(ctx, tx, tenantID, nil); err != nil {
		t.Fatalf("scope: %v", err)
	}
	userID := domain.NewID(domain.PrefixUser)
	clusterID := domain.NewID(domain.PrefixCluster)
	rc := &requestContext{Tx: tx, TenantID: tenantID, UserID: userID}
	r := httptest.NewRequest(http.MethodPost, "/api/v1/clusters/"+clusterID+"/inspect/get_logs", nil)
	args := json.RawMessage(`{"namespace":"apps","name":"web-1","container":"app"}`)
	callErr := &gateway.ToolError{ClusterID: clusterID, Tool: "get_logs",
		Message: "container app in pod apps/web-1 has not started yet (ContainerCreating), so it has no logs"}

	s.auditInspection(r, rc, clusterID, "get_logs", args, callErr)
	// What completeRequest does to the request transaction on a 502.
	if err := tx.Rollback(ctx); err != nil {
		t.Fatalf("rollback: %v", err)
	}

	read, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin read: %v", err)
	}
	defer read.Rollback(ctx) //nolint:errcheck
	if err := data.SetRequestScope(ctx, read, tenantID, nil); err != nil {
		t.Fatalf("scope: %v", err)
	}
	var outcome string
	var details []byte
	if err := read.QueryRow(ctx, `SELECT outcome, details FROM audit_events WHERE actor_id = $1 AND cluster_id = $2`, userID, clusterID).
		Scan(&outcome, &details); err != nil {
		t.Fatalf("the failed read left no audit row: %v", err)
	}
	var d map[string]any
	_ = json.Unmarshal(details, &d)
	if outcome != "error" || d["tool"] != "get_logs" || d["action"] != "cluster:inspect" {
		t.Fatalf("audit row: outcome=%q details=%v", outcome, d)
	}
	if e, _ := d["error"].(string); e == "" {
		t.Fatalf("the audit row does not say why the read failed: %v", d)
	}
}

// An on-demand upgrade scan stores a verdict other people read, so every scan
// request sent to the agent is audited, including one that failed.
func TestUpgradeScanRequestIsAudited(t *testing.T) {
	pool := authTestPool(t)
	ctx := context.Background()
	s := &Server{db: &data.DB{Pool: pool}}
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	tenantID, err := data.SingleOrganisationID(ctx, tx)
	if err != nil {
		t.Fatalf("organisation: %v", err)
	}
	userID := domain.NewID(domain.PrefixUser)
	clusterID := domain.NewID(domain.PrefixCluster)
	rc := &requestContext{Tx: tx, TenantID: tenantID, UserID: userID}
	r := httptest.NewRequest(http.MethodPost, "/api/v1/clusters/"+clusterID+"/upgrade-scans", nil)
	s.auditUpgradeScan(r, rc, clusterID, "1.35", upgradescans.Scan{}, &gateway.ToolError{Message: "target Kubernetes version must be newer than the current version"})

	read, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin read: %v", err)
	}
	defer read.Rollback(ctx) //nolint:errcheck
	if err := data.SetRequestScope(ctx, read, tenantID, nil); err != nil {
		t.Fatalf("scope: %v", err)
	}
	var outcome string
	var details []byte
	if err := read.QueryRow(ctx, `SELECT outcome, details FROM audit_events WHERE actor_id = $1 AND cluster_id = $2`, userID, clusterID).
		Scan(&outcome, &details); err != nil {
		t.Fatalf("no audit row for the scan request: %v", err)
	}
	var d map[string]any
	_ = json.Unmarshal(details, &d)
	if outcome != "error" || d["action"] != "upgrade_scan:run" || d["requestedTarget"] != "1.35" {
		t.Fatalf("audit row: outcome=%q details=%v", outcome, d)
	}
}

// A scan request the hub refuses before asking the agent — a malformed body,
// a target that does not parse, a disconnected agent — still leaves a row
// saying what was asked and why it was turned away. Only completed and failed
// scans used to be audited.
func TestRefusedUpgradeScanRequestsAreAudited(t *testing.T) {
	pool := authTestPool(t)
	ctx := context.Background()
	s := &Server{db: &data.DB{Pool: pool}}
	cases := []struct {
		name, body, outcome string
		status              int
	}{
		{"malformed body", `{`, "denied", http.StatusBadRequest},
		{"unparseable target", `{"targetVersion":"latest"}`, "denied", http.StatusBadRequest},
		{"agent not connected", `{}`, "error", http.StatusServiceUnavailable},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tx, err := pool.Begin(ctx)
			if err != nil {
				t.Fatalf("begin: %v", err)
			}
			tenantID, err := data.SingleOrganisationID(ctx, tx)
			if err != nil {
				t.Fatalf("organisation: %v", err)
			}
			if err := data.SetRequestScope(ctx, tx, tenantID, nil); err != nil {
				t.Fatalf("scope: %v", err)
			}
			userID := domain.NewID(domain.PrefixUser)
			clusterID := domain.NewID(domain.PrefixCluster)
			rc := &requestContext{Tx: tx, TenantID: tenantID, UserID: userID,
				Grants: []authz.EffectiveGrant{{Capability: authz.CapClusterRead, Scope: authz.Scope{Type: "Cluster", ClusterID: clusterID}}}}
			r := httptest.NewRequest(http.MethodPost, "/api/v1/clusters/"+clusterID+"/upgrade-scans", strings.NewReader(tc.body))
			r.SetPathValue("id", clusterID)
			w := httptest.NewRecorder()
			s.handleRunUpgradeScan(w, r, rc)
			_ = tx.Rollback(ctx) // what completeRequest does on an error status
			if w.Code != tc.status {
				t.Fatalf("status = %d, want %d (%s)", w.Code, tc.status, w.Body.String())
			}
			read, err := pool.Begin(ctx)
			if err != nil {
				t.Fatalf("begin read: %v", err)
			}
			defer read.Rollback(ctx) //nolint:errcheck
			if err := data.SetRequestScope(ctx, read, tenantID, nil); err != nil {
				t.Fatalf("scope: %v", err)
			}
			var outcome string
			var details []byte
			if err := read.QueryRow(ctx, `SELECT outcome, details FROM audit_events WHERE actor_id = $1 AND cluster_id = $2`, userID, clusterID).
				Scan(&outcome, &details); err != nil {
				t.Fatalf("the refused request left no audit row: %v", err)
			}
			var d map[string]any
			_ = json.Unmarshal(details, &d)
			if outcome != tc.outcome || d["action"] != "upgrade_scan:run" || d["status"] != float64(tc.status) || d["refused"] == "" {
				t.Fatalf("audit row: outcome=%q details=%v", outcome, d)
			}
		})
	}
}
