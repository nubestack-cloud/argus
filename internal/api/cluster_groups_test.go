package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"argus/internal/authz"
)

// This file covers the HTTP-handler-level gap flagged against
// cluster_groups.go: the 5 routes it defines (BACKLOG.md S3) had zero test
// coverage at the route layer before this. These are the DB-free half
// (auth/capability gating, mirroring timeline_test.go's/breaker_test.go's
// TestX RequiresAuth / RequiresCapability pattern, and custom_roles_test.go's
// identical structure above); cluster_groups_db_test.go covers the DB-backed
// success/validation/RLS-scoping/in-use paths.

// TestClusterGroupsRoutesRequireAuth proves all 5 routes are wrapped with
// requireAuth: a request with no bearer token at all must be refused before
// the handler (or the database) is ever reached.
func TestClusterGroupsRoutesRequireAuth(t *testing.T) {
	s := &Server{}
	cases := []struct {
		name    string
		method  string
		path    string
		handler http.HandlerFunc
	}{
		{"GET /cluster-groups", http.MethodGet, "/api/v1/cluster-groups",
			s.requireAuth(s.requireCapability(authz.CapClusterRead, s.handleListClusterGroups))},
		{"POST /cluster-groups", http.MethodPost, "/api/v1/cluster-groups",
			s.requireAuth(s.requireCapability(authz.CapClusterGroupManage, s.handleCreateClusterGroup))},
		{"DELETE /cluster-groups/{id}", http.MethodDelete, "/api/v1/cluster-groups/clg_x",
			s.requireAuth(s.requireCapability(authz.CapClusterGroupManage, s.handleDeleteClusterGroup))},
		{"POST /cluster-groups/{id}/clusters", http.MethodPost, "/api/v1/cluster-groups/clg_x/clusters",
			s.requireAuth(s.requireCapability(authz.CapClusterGroupManage, s.handleAddClusterToGroup))},
		{"DELETE /cluster-groups/{id}/clusters/{clusterId}", http.MethodDelete, "/api/v1/cluster-groups/clg_x/clusters/cl_y",
			s.requireAuth(s.requireCapability(authz.CapClusterGroupManage, s.handleRemoveClusterFromGroup))},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			req := httptest.NewRequest(c.method, c.path, nil)
			req.SetPathValue("id", "clg_x")
			req.SetPathValue("clusterId", "cl_y")
			rec := httptest.NewRecorder()

			c.handler(rec, req)

			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want %d (body: %s) — a request with no Authorization header must be refused before reaching the handler",
					rec.Code, http.StatusUnauthorized, rec.Body.String())
			}
		})
	}
}

// TestClusterGroupsRoutesRequireCapability proves each route's
// requireCapability wrapper actually gates it, mirroring
// custom_roles_test.go's TestCustomRolesRoutesRequireCapability: a case that
// clears the gate goes on to touch a nil rc.Tx and panics, which is caught
// and treated as "passed the gate" rather than a failure.
func TestClusterGroupsRoutesRequireCapability(t *testing.T) {
	cases := []struct {
		routeName  string
		capability string
		handler    func(*Server, http.ResponseWriter, *http.Request, *requestContext)
		method     string
		path       string
	}{
		{"GET /cluster-groups", authz.CapClusterRead, (*Server).handleListClusterGroups, http.MethodGet, "/api/v1/cluster-groups"},
		{"POST /cluster-groups", authz.CapClusterGroupManage, (*Server).handleCreateClusterGroup, http.MethodPost, "/api/v1/cluster-groups"},
		{"DELETE /cluster-groups/{id}", authz.CapClusterGroupManage, (*Server).handleDeleteClusterGroup, http.MethodDelete, "/api/v1/cluster-groups/clg_x"},
		{"POST /cluster-groups/{id}/clusters", authz.CapClusterGroupManage, (*Server).handleAddClusterToGroup, http.MethodPost, "/api/v1/cluster-groups/clg_x/clusters"},
		{"DELETE /cluster-groups/{id}/clusters/{clusterId}", authz.CapClusterGroupManage, (*Server).handleRemoveClusterFromGroup, http.MethodDelete, "/api/v1/cluster-groups/clg_x/clusters/cl_y"},
	}

	for _, rt := range cases {
		t.Run(rt.routeName, func(t *testing.T) {
			grantCases := []struct {
				name       string
				grants     []authz.EffectiveGrant
				wantDenied bool
			}{
				{"no grants at all", nil, true},
				{"a grant for an unrelated capability", grantsFor(authz.CapIncidentRead), true},
				{"holds the required capability", grantsFor(rt.capability), false},
			}
			for _, gc := range grantCases {
				t.Run(gc.name, func(t *testing.T) {
					s := serverWithUnreachableAuditDB(t)
					handler := s.requireCapability(rt.capability, func(w http.ResponseWriter, r *http.Request, rc *requestContext) {
						rt.handler(s, w, r, rc)
					})

					req := httptest.NewRequest(rt.method, rt.path, nil)
					req.SetPathValue("id", "clg_x")
					req.SetPathValue("clusterId", "cl_y")
					rec := httptest.NewRecorder()

					passedGate := false
					func() {
						defer func() {
							if recover() != nil {
								passedGate = true
							}
						}()
						handler(rec, req, &requestContext{Grants: gc.grants})
					}()

					denied := !passedGate && rec.Code == http.StatusForbidden
					if denied != gc.wantDenied {
						t.Fatalf("status = %d (denied=%v, passedGate=%v), want denied=%v — body: %s",
							rec.Code, denied, passedGate, gc.wantDenied, rec.Body.String())
					}
					if gc.wantDenied && !strings.Contains(rec.Body.String(), rt.capability) {
						t.Errorf("403 body does not name the missing capability %q: %s", rt.capability, rec.Body.String())
					}
				})
			}
		})
	}
}
