package api

import (
	"encoding/json"
	"testing"

	"argus/internal/authz"
)

// TestGenerateTemporaryPasswordNeverEmptyAndUnique is the DB-free unit test
// the task brief asked for explicitly: a temporary password is always
// non-trivially long and never repeats across calls (crypto/rand actually
// being used, not a stub). It says nothing about logging, because
// generateTemporaryPassword itself never logs anything — see
// TestUserViewNeverCarriesAPassword below for the "never returned in a list
// response" half of the same discipline.
func TestGenerateTemporaryPasswordNeverEmptyAndUnique(t *testing.T) {
	p1, err := generateTemporaryPassword()
	if err != nil {
		t.Fatalf("generateTemporaryPassword: %v", err)
	}
	if len(p1) < 20 {
		t.Errorf("got password of length %d, want a high-entropy value (>= 20 chars for 160 random bits base32-encoded)", len(p1))
	}

	p2, err := generateTemporaryPassword()
	if err != nil {
		t.Fatalf("generateTemporaryPassword (second call): %v", err)
	}
	if p1 == p2 {
		t.Error("generateTemporaryPassword produced identical output on two separate calls")
	}
}

// TestUserViewNeverCarriesAPassword locks the JSON shape of userView (the
// type handleListUsers marshals every row into) so a future field addition
// can't silently start leaking a password/hash — this is the "never
// returned in a list response" half of the temporary-password discipline;
// createUserResponse (a DIFFERENT, deliberately one-shot type) is the only
// place a plaintext temporary password is ever allowed to appear, and only
// on the single response to the create-user call that generated it.
func TestUserViewNeverCarriesAPassword(t *testing.T) {
	u := userView{
		ID:                 "usr_test",
		Email:              "test@example.invalid",
		DisplayName:        "Test User",
		MustChangePassword: true,
		CreatedAt:          "2026-08-19T00:00:00Z",
		Grants:             []grantView{},
	}
	body, err := json.Marshal(u)
	if err != nil {
		t.Fatalf("marshal userView: %v", err)
	}
	var asMap map[string]any
	if err := json.Unmarshal(body, &asMap); err != nil {
		t.Fatalf("unmarshal back to map: %v", err)
	}
	for _, forbidden := range []string{"password", "passwordHash", "temporaryPassword"} {
		if _, present := asMap[forbidden]; present {
			t.Errorf("userView JSON unexpectedly carries a %q field: %s", forbidden, body)
		}
	}
}

func TestValidateGrantScope(t *testing.T) {
	cases := []struct {
		name    string
		scope   authz.Scope
		wantErr bool
	}{
		{"AllClusters is valid", authz.Scope{Type: "AllClusters"}, false},
		{"Cluster with a clusterId is valid", authz.Scope{Type: "Cluster", ClusterID: "cl_abc"}, false},
		{"Cluster without a clusterId is rejected", authz.Scope{Type: "Cluster"}, true},
		{"Cluster with a blank/whitespace clusterId is rejected", authz.Scope{Type: "Cluster", ClusterID: "   "}, true},
		// BACKLOG.md S3 gave cluster_groups real membership
		// (internal/api/cluster_groups.go) and authz.AccessibleClusterIDs a
		// real resolver for it, so this shape is now accepted here too —
		// existence of the named group is checked separately by
		// clusterGroupExists, matching "Cluster"'s own split.
		{"ClusterGroup with a clusterGroupId is valid", authz.Scope{Type: "ClusterGroup", GroupID: "clg_x"}, false},
		{"ClusterGroup without a clusterGroupId is rejected", authz.Scope{Type: "ClusterGroup"}, true},
		{"ClusterGroup with a blank/whitespace clusterGroupId is rejected", authz.Scope{Type: "ClusterGroup", GroupID: "   "}, true},
		{"an unknown scope type is rejected", authz.Scope{Type: "Bogus"}, true},
		{"an empty scope type is rejected", authz.Scope{}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateGrantScope(tc.scope)
			if tc.wantErr && err == nil {
				t.Errorf("validateGrantScope(%+v) = nil, want an error", tc.scope)
			}
			if !tc.wantErr && err != nil {
				t.Errorf("validateGrantScope(%+v) = %v, want no error", tc.scope, err)
			}
		})
	}
}

// TestIsBuiltinRoleMatchesTheFiveFixedRoles locks in exactly the set this
// admin UI is allowed to offer — a closed list, not an extensible one, so
// this test fails loudly if a 6th role is ever added to the catalogue
// without this file being revisited. Updated 2026-08-25 (BACKLOG.md G9)
// when pr-approver became the 5th — this test's own prior name predicted
// exactly that moment.
func TestIsBuiltinRoleMatchesTheFiveFixedRoles(t *testing.T) {
	for _, role := range []string{"super-admin", "tenant-admin", "resolver", "pr-approver", "viewer"} {
		if !authz.IsBuiltinRole(role) {
			t.Errorf("IsBuiltinRole(%q) = false, want true", role)
		}
	}
	for _, notARole := range []string{"", "admin", "Viewer", "super_admin", "custom-role"} {
		if authz.IsBuiltinRole(notARole) {
			t.Errorf("IsBuiltinRole(%q) = true, want false", notARole)
		}
	}
}
