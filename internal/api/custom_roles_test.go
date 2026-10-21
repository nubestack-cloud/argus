package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"argus/internal/authz"
)

// This file covers the HTTP-handler-level gap flagged against custom_roles.go:
// custom_roles.go and server.go's registration (both BACKLOG.md S3) had zero
// test coverage at the route layer before this — the RLS/escalation logic
// they call into is covered by internal/authz/permissions_db_test.go, but
// nothing proved the 4 routes actually wire requireAuth/requireCapability the
// way server.go's registration comment claims. These are the DB-free half
// (auth/capability gating, mirroring timeline_test.go's/breaker_test.go's
// TestX RequiresAuth / RequiresCapability pattern); custom_roles_db_test.go
// covers the DB-backed success/validation/escalation/in-use paths.

// TestCustomRolesRoutesRequireAuth proves all 4 routes are wrapped with
// requireAuth: a request with no bearer token at all must be refused before
// the handler (or the database) is ever reached, mirroring
// TestHandleGetIncidentTimelineRequiresAuth (timeline_test.go).
func TestCustomRolesRoutesRequireAuth(t *testing.T) {
	s := &Server{}
	cases := []struct {
		name    string
		method  string
		path    string
		handler http.HandlerFunc
	}{
		{"GET /custom-roles", http.MethodGet, "/api/v1/custom-roles",
			s.requireAuth(s.requireCapability(authz.CapUserRead, s.handleListCustomRoles))},
		{"POST /custom-roles", http.MethodPost, "/api/v1/custom-roles",
			s.requireAuth(s.requireCapability(authz.CapRoleManage, s.handleCreateCustomRole))},
		{"PUT /custom-roles/{id}", http.MethodPut, "/api/v1/custom-roles/crole_x",
			s.requireAuth(s.requireCapability(authz.CapRoleManage, s.handleUpdateCustomRole))},
		{"DELETE /custom-roles/{id}", http.MethodDelete, "/api/v1/custom-roles/crole_x",
			s.requireAuth(s.requireCapability(authz.CapRoleManage, s.handleDeleteCustomRole))},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			req := httptest.NewRequest(c.method, c.path, nil)
			req.SetPathValue("id", "crole_x")
			rec := httptest.NewRecorder()

			c.handler(rec, req)

			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want %d (body: %s) — a request with no Authorization header must be refused before reaching the handler",
					rec.Code, http.StatusUnauthorized, rec.Body.String())
			}
		})
	}
}

// TestCustomRolesRoutesRequireCapability proves each route's requireCapability
// wrapper actually gates it, mirroring clusters_test.go's
// TestHandleGetClusterRefusesOutOfScopeCluster / breaker_test.go's
// TestPutBreakerRouteRequiresCapability: a case that clears the gate goes on
// to touch a nil rc.Tx and panics, which is caught and treated as "passed the
// gate" rather than a failure — proving the gate lets the right capability
// through is as much the point as proving it blocks everything else.
func TestCustomRolesRoutesRequireCapability(t *testing.T) {
	cases := []struct {
		routeName  string
		capability string
		handler    func(*Server, http.ResponseWriter, *http.Request, *requestContext)
		method     string
		path       string
	}{
		{"GET /custom-roles", authz.CapUserRead, (*Server).handleListCustomRoles, http.MethodGet, "/api/v1/custom-roles"},
		{"POST /custom-roles", authz.CapRoleManage, (*Server).handleCreateCustomRole, http.MethodPost, "/api/v1/custom-roles"},
		{"PUT /custom-roles/{id}", authz.CapRoleManage, (*Server).handleUpdateCustomRole, http.MethodPut, "/api/v1/custom-roles/crole_x"},
		{"DELETE /custom-roles/{id}", authz.CapRoleManage, (*Server).handleDeleteCustomRole, http.MethodDelete, "/api/v1/custom-roles/crole_x"},
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
					req.SetPathValue("id", "crole_x")
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
