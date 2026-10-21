package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"argus/internal/authz"
	"argus/internal/data"
	"argus/internal/domain"
)

// DB-backed coverage for internal/api/cluster_groups.go's 5 routes —
// mirroring custom_roles_db_test.go's structure and evidence_db_test.go's
// pattern for a real Postgres, RLS included.

// clusterGroupTestUser mirrors customRoleTestUser (custom_roles_db_test.go).
func clusterGroupTestUser(t *testing.T, pool *pgxpool.Pool, tenantID string) string {
	t.Helper()
	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if err := data.SetRequestScope(ctx, tx, tenantID, nil); err != nil {
		t.Fatalf("set request scope: %v", err)
	}
	userID := domain.NewID(domain.PrefixUser)
	if _, err := tx.Exec(ctx,
		`INSERT INTO users (id, tenant_id, email, display_name, password_hash) VALUES ($1, $2, $3, $4, $5)`,
		userID, tenantID, userID+"@test.invalid", "cluster group test user", dummyLoginPasswordHash); err != nil {
		t.Fatalf("insert test user: %v", err)
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
		if err := data.SetRequestScope(cleanupCtx, tx, tenantID, nil); err != nil {
			return
		}
		_, _ = tx.Exec(cleanupCtx, `DELETE FROM users WHERE id = $1`, userID)
		_ = tx.Commit(cleanupCtx)
	})
	return userID
}

// clusterGroupTestCluster inserts a throwaway cluster row and registers
// cleanup, matching evidenceFixture's own cluster-insertion shape
// (evidence_db_test.go).
func clusterGroupTestCluster(t *testing.T, pool *pgxpool.Pool, tenantID string) string {
	t.Helper()
	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if err := data.SetRequestScope(ctx, tx, tenantID, nil); err != nil {
		t.Fatalf("set request scope: %v", err)
	}
	clusterID := domain.NewID(domain.PrefixCluster)
	if _, err := tx.Exec(ctx,
		`INSERT INTO clusters (id, tenant_id, display_name, state, shard_id, cluster_fingerprint)
		 VALUES ($1, $2, $3, 'Active', 'shard-test', $4)`,
		clusterID, tenantID, "cg-test-"+clusterID, "fp-"+clusterID); err != nil {
		t.Fatalf("insert cluster: %v", err)
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
		_, _ = tx.Exec(cleanupCtx, `DELETE FROM clusters WHERE id = $1`, clusterID)
		_ = tx.Commit(cleanupCtx)
	})
	return clusterID
}

// insertClusterGroupFixture inserts a cluster_groups row directly and
// registers cleanup.
func insertClusterGroupFixture(t *testing.T, pool *pgxpool.Pool, tenantID, name string) string {
	t.Helper()
	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if err := data.SetRequestScope(ctx, tx, tenantID, nil); err != nil {
		t.Fatalf("set request scope: %v", err)
	}
	id := domain.NewID(domain.PrefixClusterGroup)
	if _, err := tx.Exec(ctx,
		`INSERT INTO cluster_groups (id, tenant_id, name, label_selector) VALUES ($1, $2, $3, '{}'::jsonb)`,
		id, tenantID, name); err != nil {
		t.Fatalf("insert cluster group: %v", err)
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
		if err := data.SetRequestScope(cleanupCtx, tx, tenantID, nil); err != nil {
			return
		}
		_, _ = tx.Exec(cleanupCtx, `DELETE FROM grants WHERE scope->>'clusterGroupId' = $1`, id)
		_, _ = tx.Exec(cleanupCtx, `DELETE FROM cluster_groups WHERE id = $1`, id) // ON DELETE CASCADE takes members
		_ = tx.Commit(cleanupCtx)
	})
	return id
}

func TestHandleCreateClusterGroupEndToEnd(t *testing.T) {
	pool := authTestPool(t)
	ctx := context.Background()
	tenantID, err := singleOrgIDForTest(ctx, pool)
	if err != nil {
		t.Fatalf("resolve tenant: %v", err)
	}
	userID := clusterGroupTestUser(t, pool, tenantID)
	s := &Server{db: &data.DB{Pool: pool}}
	grants := grantsFor(authz.CapClusterGroupManage)

	create := func(body string) (int, map[string]any) {
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatalf("begin request tx: %v", err)
		}
		defer tx.Rollback(ctx) //nolint:errcheck
		if err := data.SetRequestScope(ctx, tx, tenantID, nil); err != nil {
			t.Fatalf("set request scope: %v", err)
		}
		rc := &requestContext{Tx: tx, UserID: userID, TenantID: tenantID, Grants: grants}

		req := httptest.NewRequest(http.MethodPost, "/api/v1/cluster-groups", strings.NewReader(body))
		rec := httptest.NewRecorder()
		s.handleCreateClusterGroup(rec, req, rc)
		if rec.Code < 400 {
			if err := tx.Commit(ctx); err != nil {
				t.Fatalf("commit: %v", err)
			}
		}

		var got map[string]any
		if rec.Body.Len() > 0 {
			if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
				t.Fatalf("unmarshal response (status %d, body %s): %v", rec.Code, rec.Body.String(), err)
			}
		}
		return rec.Code, got
	}

	t.Run("success", func(t *testing.T) {
		name := "group-" + domain.NewID(domain.PrefixClusterGroup)
		code, body := create(`{"name":"` + name + `"}`)
		if code != http.StatusCreated {
			t.Fatalf("status = %d, want 201 (body: %+v)", code, body)
		}
		if body["name"] != name {
			t.Errorf(`body["name"] = %v, want %q`, body["name"], name)
		}
		clusterIDs, _ := body["clusterIds"].([]any)
		if len(clusterIDs) != 0 {
			t.Errorf(`body["clusterIds"] = %v, want an empty list on creation`, body["clusterIds"])
		}
		t.Cleanup(func() {
			cleanupTx, err := pool.Begin(ctx)
			if err != nil {
				return
			}
			defer cleanupTx.Rollback(ctx) //nolint:errcheck
			if err := data.SetRequestScope(ctx, cleanupTx, tenantID, nil); err != nil {
				return
			}
			_, _ = cleanupTx.Exec(ctx, `DELETE FROM cluster_groups WHERE name = $1`, name)
			_ = cleanupTx.Commit(ctx)
		})
	})

	t.Run("rejects a blank name", func(t *testing.T) {
		code, body := create(`{"name":"   "}`)
		if code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400 (body: %+v)", code, body)
		}
	})
}

func TestHandleAddAndRemoveClusterFromGroupEndToEnd(t *testing.T) {
	pool := authTestPool(t)
	ctx := context.Background()
	tenantID, err := singleOrgIDForTest(ctx, pool)
	if err != nil {
		t.Fatalf("resolve tenant: %v", err)
	}
	userID := clusterGroupTestUser(t, pool, tenantID)
	clusterID := clusterGroupTestCluster(t, pool, tenantID)
	s := &Server{db: &data.DB{Pool: pool}}
	grants := grantsFor(authz.CapClusterGroupManage)

	add := func(groupID, body string) (int, map[string]any) {
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatalf("begin request tx: %v", err)
		}
		defer tx.Rollback(ctx) //nolint:errcheck
		if err := data.SetRequestScope(ctx, tx, tenantID, nil); err != nil {
			t.Fatalf("set request scope: %v", err)
		}
		rc := &requestContext{Tx: tx, UserID: userID, TenantID: tenantID, Grants: grants}

		req := httptest.NewRequest(http.MethodPost, "/api/v1/cluster-groups/"+groupID+"/clusters", strings.NewReader(body))
		req.SetPathValue("id", groupID)
		rec := httptest.NewRecorder()
		s.handleAddClusterToGroup(rec, req, rc)
		if rec.Code < 400 {
			if err := tx.Commit(ctx); err != nil {
				t.Fatalf("commit: %v", err)
			}
		}
		var got map[string]any
		if rec.Body.Len() > 0 {
			if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
				t.Fatalf("unmarshal response (status %d, body %s): %v", rec.Code, rec.Body.String(), err)
			}
		}
		return rec.Code, got
	}

	remove := func(groupID, memberClusterID string) (int, map[string]any) {
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatalf("begin request tx: %v", err)
		}
		defer tx.Rollback(ctx) //nolint:errcheck
		if err := data.SetRequestScope(ctx, tx, tenantID, nil); err != nil {
			t.Fatalf("set request scope: %v", err)
		}
		rc := &requestContext{Tx: tx, UserID: userID, TenantID: tenantID, Grants: grants}

		req := httptest.NewRequest(http.MethodDelete, "/api/v1/cluster-groups/"+groupID+"/clusters/"+memberClusterID, nil)
		req.SetPathValue("id", groupID)
		req.SetPathValue("clusterId", memberClusterID)
		rec := httptest.NewRecorder()
		s.handleRemoveClusterFromGroup(rec, req, rc)
		if rec.Code < 400 {
			if err := tx.Commit(ctx); err != nil {
				t.Fatalf("commit: %v", err)
			}
		}
		var got map[string]any
		if rec.Body.Len() > 0 {
			if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
				t.Fatalf("unmarshal response (status %d, body %s): %v", rec.Code, rec.Body.String(), err)
			}
		}
		return rec.Code, got
	}

	t.Run("adding an unknown cluster is rejected", func(t *testing.T) {
		groupID := insertClusterGroupFixture(t, pool, tenantID, "group-unknown-cluster-"+domain.NewID(domain.PrefixClusterGroup))
		code, body := add(groupID, `{"clusterId":"cl_does_not_exist"}`)
		if code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400 for a nonexistent cluster (body: %+v)", code, body)
		}
	})

	t.Run("adding to an unknown group is 404", func(t *testing.T) {
		code, body := add(domain.NewID(domain.PrefixClusterGroup), `{"clusterId":"`+clusterID+`"}`)
		if code != http.StatusNotFound {
			t.Fatalf("status = %d, want 404 (body: %+v)", code, body)
		}
	})

	t.Run("success adds a real cluster, duplicate add conflicts, then remove succeeds", func(t *testing.T) {
		groupID := insertClusterGroupFixture(t, pool, tenantID, "group-add-remove-"+domain.NewID(domain.PrefixClusterGroup))

		code, body := add(groupID, `{"clusterId":"`+clusterID+`"}`)
		if code != http.StatusCreated {
			t.Fatalf("status = %d, want 201 (body: %+v)", code, body)
		}

		dupCode, dupBody := add(groupID, `{"clusterId":"`+clusterID+`"}`)
		if dupCode != http.StatusConflict {
			t.Fatalf("duplicate add: status = %d, want 409 (body: %+v)", dupCode, dupBody)
		}

		removeCode, removeBody := remove(groupID, clusterID)
		if removeCode != http.StatusOK {
			t.Fatalf("remove: status = %d, want 200 (body: %+v)", removeCode, removeBody)
		}

		removeAgainCode, removeAgainBody := remove(groupID, clusterID)
		if removeAgainCode != http.StatusNotFound {
			t.Fatalf("remove a second time: status = %d, want 404 (body: %+v)", removeAgainCode, removeAgainBody)
		}
	})
}

// TestHandleListClusterGroupsScopesMembersToAccessibleClusters is the
// regression test for the cross-scope leak cluster_groups.go's own package
// comment calls out by name: a caller whose RLS scope does not include a
// group member's cluster must not see that cluster's raw id in the group's
// clusterIds, even though cluster_group_members itself is tenant-scoped, not
// cluster-scoped, and would otherwise return every member row in the tenant.
func TestHandleListClusterGroupsScopesMembersToAccessibleClusters(t *testing.T) {
	pool := authTestPool(t)
	ctx := context.Background()
	tenantID, err := singleOrgIDForTest(ctx, pool)
	if err != nil {
		t.Fatalf("resolve tenant: %v", err)
	}
	userID := clusterGroupTestUser(t, pool, tenantID)
	visibleCluster := clusterGroupTestCluster(t, pool, tenantID)
	hiddenCluster := clusterGroupTestCluster(t, pool, tenantID)
	groupID := insertClusterGroupFixture(t, pool, tenantID, "group-scoping-"+domain.NewID(domain.PrefixClusterGroup))

	// Insert both memberships directly (unrestricted scope), then read the
	// list back through a request transaction narrowed to visibleCluster only
	// — mirroring evidence_db_test.go's own "insert unrestricted, read
	// scoped" shape.
	memberTx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin member tx: %v", err)
	}
	if err := data.SetRequestScope(ctx, memberTx, tenantID, nil); err != nil {
		t.Fatalf("set request scope: %v", err)
	}
	for _, clusterID := range []string{visibleCluster, hiddenCluster} {
		if _, err := memberTx.Exec(ctx,
			`INSERT INTO cluster_group_members (id, tenant_id, cluster_group_id, cluster_id, added_by)
			 VALUES ($1, $2, $3, $4, $5)`,
			domain.NewID(domain.PrefixClusterGroupMember), tenantID, groupID, clusterID, userID); err != nil {
			t.Fatalf("insert member %s: %v", clusterID, err)
		}
	}
	if err := memberTx.Commit(ctx); err != nil {
		t.Fatalf("commit member tx: %v", err)
	}

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin request tx: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	// Narrowed to visibleCluster only — hiddenCluster is never in scope,
	// matching an ordinary caller whose grants do not reach it.
	if err := data.SetRequestScope(ctx, tx, tenantID, []string{visibleCluster}); err != nil {
		t.Fatalf("set request scope: %v", err)
	}
	rc := &requestContext{Tx: tx, UserID: userID, TenantID: tenantID, Grants: grantsFor(authz.CapClusterRead)}

	s := &Server{db: &data.DB{Pool: pool}}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/cluster-groups", nil)
	rec := httptest.NewRecorder()
	s.handleListClusterGroups(rec, req, rc)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body: %s)", rec.Code, rec.Body.String())
	}
	var body struct {
		ClusterGroups []clusterGroupView `json:"clusterGroups"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal: %v (body: %s)", err, rec.Body.String())
	}

	var found *clusterGroupView
	for i := range body.ClusterGroups {
		if body.ClusterGroups[i].ID == groupID {
			found = &body.ClusterGroups[i]
			break
		}
	}
	if found == nil {
		t.Fatalf("group %s not present in the list response: %+v", groupID, body.ClusterGroups)
	}
	if len(found.ClusterIDs) != 1 || found.ClusterIDs[0] != visibleCluster {
		t.Errorf("clusterIds = %v, want exactly [%s] — a cluster outside this caller's RLS scope must not appear", found.ClusterIDs, visibleCluster)
	}
	for _, id := range found.ClusterIDs {
		if id == hiddenCluster {
			t.Fatal("hiddenCluster's id leaked into the response despite being outside this caller's accessible_cluster_ids scope")
		}
	}
}

func TestHandleDeleteClusterGroupEndToEnd(t *testing.T) {
	pool := authTestPool(t)
	ctx := context.Background()
	tenantID, err := singleOrgIDForTest(ctx, pool)
	if err != nil {
		t.Fatalf("resolve tenant: %v", err)
	}
	userID := clusterGroupTestUser(t, pool, tenantID)
	s := &Server{db: &data.DB{Pool: pool}}
	grants := grantsFor(authz.CapClusterGroupManage)

	deleteGroup := func(id string) (int, map[string]any) {
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatalf("begin request tx: %v", err)
		}
		defer tx.Rollback(ctx) //nolint:errcheck
		if err := data.SetRequestScope(ctx, tx, tenantID, nil); err != nil {
			t.Fatalf("set request scope: %v", err)
		}
		rc := &requestContext{Tx: tx, UserID: userID, TenantID: tenantID, Grants: grants}

		req := httptest.NewRequest(http.MethodDelete, "/api/v1/cluster-groups/"+id, nil)
		req.SetPathValue("id", id)
		rec := httptest.NewRecorder()
		s.handleDeleteClusterGroup(rec, req, rc)
		if rec.Code < 400 {
			if err := tx.Commit(ctx); err != nil {
				t.Fatalf("commit: %v", err)
			}
		}
		var got map[string]any
		if rec.Body.Len() > 0 {
			if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
				t.Fatalf("unmarshal response (status %d, body %s): %v", rec.Code, rec.Body.String(), err)
			}
		}
		return rec.Code, got
	}

	t.Run("not found", func(t *testing.T) {
		code, body := deleteGroup(domain.NewID(domain.PrefixClusterGroup))
		if code != http.StatusNotFound {
			t.Fatalf("status = %d, want 404 (body: %+v)", code, body)
		}
	})

	t.Run("success deletes an unreferenced group", func(t *testing.T) {
		groupID := insertClusterGroupFixture(t, pool, tenantID, "delete-target-"+domain.NewID(domain.PrefixClusterGroup))
		code, body := deleteGroup(groupID)
		if code != http.StatusOK {
			t.Fatalf("status = %d, want 200 (body: %+v)", code, body)
		}

		verifyTx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatalf("begin verify tx: %v", err)
		}
		defer verifyTx.Rollback(ctx) //nolint:errcheck
		if err := data.SetRequestScope(ctx, verifyTx, tenantID, nil); err != nil {
			t.Fatalf("set request scope: %v", err)
		}
		var exists bool
		if err := verifyTx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM cluster_groups WHERE id = $1)`, groupID).Scan(&exists); err != nil {
			t.Fatalf("verify deleted: %v", err)
		}
		if exists {
			t.Error("cluster_groups row still exists after a 200 delete response")
		}
	})

	t.Run("refuses to delete a group still referenced by an active ClusterGroup-scoped grant, then succeeds once revoked", func(t *testing.T) {
		groupID := insertClusterGroupFixture(t, pool, tenantID, "inuse-target-"+domain.NewID(domain.PrefixClusterGroup))

		grantID := domain.NewID(domain.PrefixGrant)
		grantTx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatalf("begin grant tx: %v", err)
		}
		if err := data.SetRequestScope(ctx, grantTx, tenantID, nil); err != nil {
			t.Fatalf("set request scope: %v", err)
		}
		scopeJSON, err := json.Marshal(authz.Scope{Type: "ClusterGroup", GroupID: groupID})
		if err != nil {
			t.Fatalf("marshal scope: %v", err)
		}
		if _, err := grantTx.Exec(ctx,
			`INSERT INTO grants (id, tenant_id, principal_type, principal_id, role_id, scope, granted_by)
			 VALUES ($1, $2, 'user', $3, 'viewer', $4, $3)`,
			grantID, tenantID, userID, scopeJSON); err != nil {
			t.Fatalf("insert grant: %v", err)
		}
		if err := grantTx.Commit(ctx); err != nil {
			t.Fatalf("commit grant: %v", err)
		}

		code, body := deleteGroup(groupID)
		if code != http.StatusConflict {
			t.Fatalf("status = %d, want 409 while a grant is still scoped to the group (body: %+v)", code, body)
		}

		revokeTx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatalf("begin revoke tx: %v", err)
		}
		if err := data.SetRequestScope(ctx, revokeTx, tenantID, nil); err != nil {
			t.Fatalf("set request scope: %v", err)
		}
		if _, err := revokeTx.Exec(ctx, `UPDATE grants SET revoked_at = now() WHERE id = $1`, grantID); err != nil {
			t.Fatalf("revoke grant: %v", err)
		}
		if err := revokeTx.Commit(ctx); err != nil {
			t.Fatalf("commit revoke: %v", err)
		}

		code2, body2 := deleteGroup(groupID)
		if code2 != http.StatusOK {
			t.Fatalf("status = %d, want 200 once the referencing grant is revoked (body: %+v)", code2, body2)
		}
	})
}
