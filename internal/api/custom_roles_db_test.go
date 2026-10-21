package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"argus/internal/authz"
	"argus/internal/data"
	"argus/internal/domain"
)

// DB-backed coverage for internal/api/custom_roles.go's 4 routes — the
// success, validation-failure, escalation-guard and in-use-guard paths that
// custom_roles_test.go's DB-free auth/capability tests above cannot exercise
// (they need a real custom_roles/grants row and RLS-scoped transaction),
// following evidence_db_test.go's pattern: authTestPool(t) for the gated
// connection, a manually built *requestContext carrying a real transaction,
// calling the handler directly rather than through the mux.

// customRoleTestUser inserts a throwaway enabled user (grants.granted_by and
// custom_roles.created_by both reference a real users.id via no FK, but
// staying realistic costs nothing) and returns its id.
func customRoleTestUser(t *testing.T, pool *pgxpool.Pool, tenantID string) string {
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
		userID, tenantID, userID+"@test.invalid", "custom role test user", dummyLoginPasswordHash); err != nil {
		t.Fatalf("insert test user: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit: %v", err)
	}
	t.Cleanup(func() {
		cleanupCtx := context.Background()
		tx, err := pool.Begin(cleanupCtx)
		if err != nil {
			t.Logf("cleanup user: begin: %v", err)
			return
		}
		defer tx.Rollback(cleanupCtx) //nolint:errcheck
		if err := data.SetRequestScope(cleanupCtx, tx, tenantID, nil); err != nil {
			t.Logf("cleanup user: set scope: %v", err)
			return
		}
		if _, err := tx.Exec(cleanupCtx, `DELETE FROM users WHERE id = $1`, userID); err != nil {
			t.Logf("cleanup user: delete: %v", err)
			return
		}
		if err := tx.Commit(cleanupCtx); err != nil {
			t.Logf("cleanup user: commit: %v", err)
		}
	})
	return userID
}

func TestHandleCreateCustomRoleEndToEnd(t *testing.T) {
	pool := authTestPool(t)
	ctx := context.Background()
	tenantID, err := singleOrgIDForTest(ctx, pool)
	if err != nil {
		t.Fatalf("resolve tenant: %v", err)
	}
	userID := customRoleTestUser(t, pool, tenantID)
	s := &Server{db: &data.DB{Pool: pool}}

	create := func(body string, grants []authz.EffectiveGrant) (int, map[string]any) {
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatalf("begin request tx: %v", err)
		}
		defer tx.Rollback(ctx) //nolint:errcheck
		if err := data.SetRequestScope(ctx, tx, tenantID, nil); err != nil {
			t.Fatalf("set request scope: %v", err)
		}
		rc := &requestContext{Tx: tx, UserID: userID, TenantID: tenantID, Grants: grants}

		req := httptest.NewRequest(http.MethodPost, "/api/v1/custom-roles", bytes.NewReader([]byte(body)))
		rec := httptest.NewRecorder()
		s.handleCreateCustomRole(rec, req, rc)
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

	fullGrants := grantsFor(authz.CapRoleManage, authz.CapClusterRead, authz.CapIncidentRead)

	t.Run("success creates a role with the requested capabilities", func(t *testing.T) {
		roleName := "role-" + domain.NewID(domain.PrefixCustomRole)
		code, body := create(`{"name":"`+roleName+`","capabilities":["cluster:read","incident:read"]}`, fullGrants)
		if code != http.StatusCreated {
			t.Fatalf("status = %d, want 201 (body: %+v)", code, body)
		}
		if body["name"] != roleName {
			t.Errorf(`body["name"] = %v, want %q`, body["name"], roleName)
		}
		caps, _ := body["capabilities"].([]any)
		if len(caps) != 2 {
			t.Errorf(`body["capabilities"] = %v, want 2 entries`, body["capabilities"])
		}
		if body["id"] == nil || body["id"] == "" {
			t.Error(`body["id"] is empty`)
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
			_, _ = cleanupTx.Exec(ctx, `DELETE FROM custom_roles WHERE name = $1`, roleName)
			_ = cleanupTx.Commit(ctx)
		})
	})

	t.Run("rejects a reserved builtin role name", func(t *testing.T) {
		code, body := create(`{"name":"viewer","capabilities":["cluster:read"]}`, fullGrants)
		if code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400 (body: %+v)", code, body)
		}
	})

	t.Run("rejects an unknown capability string", func(t *testing.T) {
		roleName := "role-" + domain.NewID(domain.PrefixCustomRole)
		code, body := create(`{"name":"`+roleName+`","capabilities":["not:a:real:capability"]}`, fullGrants)
		if code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400 (body: %+v)", code, body)
		}
	})

	t.Run("rejects an empty capability set", func(t *testing.T) {
		roleName := "role-" + domain.NewID(domain.PrefixCustomRole)
		code, body := create(`{"name":"`+roleName+`","capabilities":[]}`, fullGrants)
		if code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400 (body: %+v)", code, body)
		}
	})

	t.Run("rejects a blank name", func(t *testing.T) {
		code, body := create(`{"name":"   ","capabilities":["cluster:read"]}`, fullGrants)
		if code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400 (body: %+v)", code, body)
		}
	})

	t.Run("escalation guard: cannot compose a role with a capability the caller does not hold", func(t *testing.T) {
		roleName := "role-" + domain.NewID(domain.PrefixCustomRole)
		limitedGrants := grantsFor(authz.CapRoleManage, authz.CapClusterRead) // no cluster:delete
		code, body := create(`{"name":"`+roleName+`","capabilities":["cluster:read","cluster:delete"]}`, limitedGrants)
		if code != http.StatusForbidden {
			t.Fatalf("status = %d, want 403 (body: %+v)", code, body)
		}
		if detail, _ := body["detail"].(string); detail == "" {
			t.Error(`body["detail"] is empty, want it to name the missing capability`)
		}
	})

	t.Run("duplicate name (case-insensitive) conflicts", func(t *testing.T) {
		roleName := "role-" + domain.NewID(domain.PrefixCustomRole)
		code, body := create(`{"name":"`+roleName+`","capabilities":["cluster:read"]}`, fullGrants)
		if code != http.StatusCreated {
			t.Fatalf("first create: status = %d, want 201 (body: %+v)", code, body)
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
			_, _ = cleanupTx.Exec(ctx, `DELETE FROM custom_roles WHERE lower(name) = lower($1)`, roleName)
			_ = cleanupTx.Commit(ctx)
		})

		code2, body2 := create(`{"name":"`+roleName+`","capabilities":["incident:read"]}`, fullGrants)
		if code2 != http.StatusConflict {
			t.Fatalf("second create with same name: status = %d, want 409 (body: %+v)", code2, body2)
		}
	})
}

func TestHandleUpdateCustomRoleEndToEnd(t *testing.T) {
	pool := authTestPool(t)
	ctx := context.Background()
	tenantID, err := singleOrgIDForTest(ctx, pool)
	if err != nil {
		t.Fatalf("resolve tenant: %v", err)
	}
	userID := customRoleTestUser(t, pool, tenantID)
	s := &Server{db: &data.DB{Pool: pool}}

	roleID := insertCustomRoleFixture(t, pool, tenantID, userID, "update-target-"+domain.NewID(domain.PrefixCustomRole), []string{authz.CapClusterRead})

	update := func(id, body string, grants []authz.EffectiveGrant) (int, map[string]any) {
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatalf("begin request tx: %v", err)
		}
		defer tx.Rollback(ctx) //nolint:errcheck
		if err := data.SetRequestScope(ctx, tx, tenantID, nil); err != nil {
			t.Fatalf("set request scope: %v", err)
		}
		rc := &requestContext{Tx: tx, UserID: userID, TenantID: tenantID, Grants: grants}

		req := httptest.NewRequest(http.MethodPut, "/api/v1/custom-roles/"+id, bytes.NewReader([]byte(body)))
		req.SetPathValue("id", id)
		rec := httptest.NewRecorder()
		s.handleUpdateCustomRole(rec, req, rc)
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

	fullGrants := grantsFor(authz.CapRoleManage, authz.CapClusterRead, authz.CapIncidentRead)

	t.Run("not found", func(t *testing.T) {
		code, body := update(domain.NewID(domain.PrefixCustomRole), `{"capabilities":["cluster:read"]}`, fullGrants)
		if code != http.StatusNotFound {
			t.Fatalf("status = %d, want 404 (body: %+v)", code, body)
		}
	})

	t.Run("escalation guard on update", func(t *testing.T) {
		limitedGrants := grantsFor(authz.CapRoleManage, authz.CapClusterRead) // no incident:read
		code, body := update(roleID, `{"capabilities":["cluster:read","incident:read"]}`, limitedGrants)
		if code != http.StatusForbidden {
			t.Fatalf("status = %d, want 403 (body: %+v)", code, body)
		}
	})

	t.Run("rejects an unknown capability", func(t *testing.T) {
		code, body := update(roleID, `{"capabilities":["bogus:capability"]}`, fullGrants)
		if code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400 (body: %+v)", code, body)
		}
	})

	t.Run("success updates the capability set and does not change the name", func(t *testing.T) {
		code, body := update(roleID, `{"capabilities":["incident:read"]}`, fullGrants)
		if code != http.StatusOK {
			t.Fatalf("status = %d, want 200 (body: %+v)", code, body)
		}
		caps, _ := body["capabilities"].([]any)
		if len(caps) != 1 || caps[0] != authz.CapIncidentRead {
			t.Errorf(`body["capabilities"] = %v, want exactly ["incident:read"]`, body["capabilities"])
		}
	})
}

func TestHandleDeleteCustomRoleEndToEnd(t *testing.T) {
	pool := authTestPool(t)
	ctx := context.Background()
	tenantID, err := singleOrgIDForTest(ctx, pool)
	if err != nil {
		t.Fatalf("resolve tenant: %v", err)
	}
	userID := customRoleTestUser(t, pool, tenantID)
	s := &Server{db: &data.DB{Pool: pool}}
	fullGrants := grantsFor(authz.CapRoleManage, authz.CapClusterRead)

	deleteRole := func(id string) (int, map[string]any) {
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatalf("begin request tx: %v", err)
		}
		defer tx.Rollback(ctx) //nolint:errcheck
		if err := data.SetRequestScope(ctx, tx, tenantID, nil); err != nil {
			t.Fatalf("set request scope: %v", err)
		}
		rc := &requestContext{Tx: tx, UserID: userID, TenantID: tenantID, Grants: fullGrants}

		req := httptest.NewRequest(http.MethodDelete, "/api/v1/custom-roles/"+id, nil)
		req.SetPathValue("id", id)
		rec := httptest.NewRecorder()
		s.handleDeleteCustomRole(rec, req, rc)
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
		code, body := deleteRole(domain.NewID(domain.PrefixCustomRole))
		if code != http.StatusNotFound {
			t.Fatalf("status = %d, want 404 (body: %+v)", code, body)
		}
	})

	t.Run("success deletes an unreferenced role", func(t *testing.T) {
		roleID := insertCustomRoleFixture(t, pool, tenantID, userID, "delete-target-"+domain.NewID(domain.PrefixCustomRole), []string{authz.CapClusterRead})
		code, body := deleteRole(roleID)
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
		if err := verifyTx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM custom_roles WHERE id = $1)`, roleID).Scan(&exists); err != nil {
			t.Fatalf("verify deleted: %v", err)
		}
		if exists {
			t.Error("custom_roles row still exists after a 200 delete response")
		}
	})

	t.Run("refuses to delete a role still referenced by an active grant, then succeeds once the grant is revoked", func(t *testing.T) {
		roleID := insertCustomRoleFixture(t, pool, tenantID, userID, "inuse-target-"+domain.NewID(domain.PrefixCustomRole), []string{authz.CapClusterRead})

		grantID := domain.NewID(domain.PrefixGrant)
		grantTx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatalf("begin grant tx: %v", err)
		}
		if err := data.SetRequestScope(ctx, grantTx, tenantID, nil); err != nil {
			t.Fatalf("set request scope: %v", err)
		}
		if _, err := grantTx.Exec(ctx,
			`INSERT INTO grants (id, tenant_id, principal_type, principal_id, role_id, scope, granted_by)
			 VALUES ($1, $2, 'user', $3, $4, '{"type":"AllClusters"}'::jsonb, $3)`,
			grantID, tenantID, userID, roleID); err != nil {
			t.Fatalf("insert grant: %v", err)
		}
		if err := grantTx.Commit(ctx); err != nil {
			t.Fatalf("commit grant: %v", err)
		}

		code, body := deleteRole(roleID)
		if code != http.StatusConflict {
			t.Fatalf("status = %d, want 409 while a grant still references the role (body: %+v)", code, body)
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

		code2, body2 := deleteRole(roleID)
		if code2 != http.StatusOK {
			t.Fatalf("status = %d, want 200 once the referencing grant is revoked (body: %+v)", code2, body2)
		}
	})
}

// insertCustomRoleFixture inserts a custom_roles row directly (bypassing the
// handler, since these tests need a role to already exist before exercising
// update/delete) and registers cleanup.
func insertCustomRoleFixture(t *testing.T, pool *pgxpool.Pool, tenantID, userID, name string, capabilities []string) string {
	t.Helper()
	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin fixture tx: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if err := data.SetRequestScope(ctx, tx, tenantID, nil); err != nil {
		t.Fatalf("set request scope: %v", err)
	}
	capJSON, err := json.Marshal(capabilities)
	if err != nil {
		t.Fatalf("marshal capabilities: %v", err)
	}
	id := domain.NewID(domain.PrefixCustomRole)
	if _, err := tx.Exec(ctx,
		`INSERT INTO custom_roles (id, tenant_id, name, capability_set, created_by) VALUES ($1, $2, $3, $4, $5)`,
		id, tenantID, name, capJSON, userID); err != nil {
		t.Fatalf("insert custom role fixture: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit fixture: %v", err)
	}
	t.Cleanup(func() {
		cleanupCtx := context.Background()
		cleanupTx, err := pool.Begin(cleanupCtx)
		if err != nil {
			return
		}
		defer cleanupTx.Rollback(cleanupCtx) //nolint:errcheck
		if err := data.SetRequestScope(cleanupCtx, cleanupTx, tenantID, nil); err != nil {
			return
		}
		_, _ = cleanupTx.Exec(cleanupCtx, `DELETE FROM grants WHERE role_id = $1`, id)
		_, _ = cleanupTx.Exec(cleanupCtx, `DELETE FROM custom_roles WHERE id = $1`, id)
		_ = cleanupTx.Commit(cleanupCtx)
	})
	return id
}

// singleOrgIDForTest resolves the single organisation id via its own
// short-lived transaction — every DB-backed test file in this package that
// needs a tenant id opens one rather than sharing auth_test.go's private
// helper, so this is the shared entry point for custom_roles_db_test.go and
// cluster_groups_db_test.go.
func singleOrgIDForTest(ctx context.Context, pool *pgxpool.Pool) (string, error) {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return "", err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	return data.SingleOrganisationID(ctx, tx)
}
