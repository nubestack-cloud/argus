package authz

import (
	"context"
	"strings"
	"testing"
)

// TestCapabilitiesNotHeldBy is the regression guard for a real
// privilege-escalation hole (found in review 2026-08-21): POST
// /users/{id}/grants validated only that the role name was a known builtin, so
// any holder of user:manage could grant any role — including super-admin.
func TestCapabilitiesNotHeldBy(t *testing.T) {
	grantsFor := func(role string) []EffectiveGrant {
		var out []EffectiveGrant
		for _, c := range builtinRoleCapabilities[role] {
			out = append(out, EffectiveGrant{Capability: c})
		}
		return out
	}

	// The exact attack: tenant-admin has user:manage, so it could reach the
	// endpoint, but lacks audit:read and org:settings:write.
	missing := CapabilitiesNotHeldBy(grantsFor("tenant-admin"), "super-admin")
	if len(missing) == 0 {
		t.Fatal("a tenant-admin must NOT be able to grant super-admin — this is the escalation path")
	}
	got := map[string]bool{}
	for _, c := range missing {
		got[c] = true
	}
	for _, want := range []string{CapAuditRead, CapOrgSettingsWrite} {
		if !got[want] {
			t.Errorf("expected %q among the capabilities a tenant-admin cannot confer, got %v", want, missing)
		}
	}

	// A super-admin holds everything, so may grant anything.
	for role := range builtinRoleCapabilities {
		if m := CapabilitiesNotHeldBy(grantsFor("super-admin"), role); len(m) > 0 {
			t.Errorf("super-admin should be able to grant %q, missing %v", role, m)
		}
	}

	// Granting your own role is always allowed (identical capability set).
	for role := range builtinRoleCapabilities {
		if m := CapabilitiesNotHeldBy(grantsFor(role), role); len(m) > 0 {
			t.Errorf("%q should be able to grant its own role, missing %v", role, m)
		}
	}

	// No grants at all: every capability of any role is unheld.
	if m := CapabilitiesNotHeldBy(nil, "viewer"); len(m) == 0 {
		t.Error("an actor with no grants must not be able to confer viewer")
	}

	// Unknown role returns nil — the caller validates role existence separately.
	if m := CapabilitiesNotHeldBy(grantsFor("super-admin"), "not-a-role"); m != nil {
		t.Errorf("unknown role should return nil, got %v", m)
	}
}

// TestPRApproverCanApproveButNeverExecuteInPlace is BACKLOG.md G9's
// acceptance test: "may approve a pull request, may never touch a cluster
// in place" must be a real, grantable role, not just theoretically
// expressible via a capability set no endpoint can create.
func TestPRApproverCanApproveButNeverExecuteInPlace(t *testing.T) {
	caps := builtinRoleCapabilities["pr-approver"]
	held := map[string]bool{}
	for _, c := range caps {
		held[c] = true
	}

	for _, want := range []string{CapRemediationApprove, CapRemediationReject, CapRemediationExecPR} {
		if !held[want] {
			t.Errorf("pr-approver must hold %q", want)
		}
	}
	for _, forbidden := range []string{CapRemediationExecInplace, CapRemediationRollback} {
		if held[forbidden] {
			t.Errorf("pr-approver must NOT hold %q — that is the entire point of the role", forbidden)
		}
	}

	if !IsBuiltinRole("pr-approver") {
		t.Error("pr-approver must be recognised as a builtin role")
	}
}

// The property that makes S1 safe to ship: every existing installation has an
// AllClusters grant (bootstrap creates one), so nothing narrows until somebody
// deliberately creates a scoped grant.
func TestAllClustersGrantIsUnrestricted(t *testing.T) {
	grants := []EffectiveGrant{
		{Capability: CapIncidentRead, Scope: Scope{Type: "AllClusters"}},
		{Capability: CapRemediationApprove, Scope: Scope{Type: "Cluster", ClusterID: "cl_a"}},
	}
	// nil tx is safe here: an AllClusters grant returns before this function
	// ever touches the database (see TestUnresolvableScopesError's own note
	// on the same point for why that's true generally, not just here).
	ids, unrestricted, err := AccessibleClusterIDs(context.Background(), nil, grants)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !unrestricted {
		t.Error("a principal holding ANY AllClusters grant was reported as restricted — RLS would then hide clusters they can legitimately read")
	}
	if ids != nil {
		t.Errorf("ids = %v, want nil alongside unrestricted", ids)
	}
}

// The union, because RLS is one session-level setting and cannot be
// per-capability. Reading is bounded by "every cluster any grant reaches";
// per-capability precision is HasCapabilityForCluster's job.
func TestAccessibleClusterIDsUnionsAndSorts(t *testing.T) {
	grants := []EffectiveGrant{
		{Capability: CapIncidentRead, Scope: Scope{Type: "Cluster", ClusterID: "cl_b"}},
		{Capability: CapRemediationApprove, Scope: Scope{Type: "Cluster", ClusterID: "cl_a"}},
		{Capability: CapIncidentTriage, Scope: Scope{Type: "Cluster", ClusterID: "cl_b"}},
	}
	ids, unrestricted, err := AccessibleClusterIDs(context.Background(), nil, grants)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if unrestricted {
		t.Fatal("cluster-scoped grants were reported as unrestricted, which is the bug this whole feature exists to fix")
	}
	if len(ids) != 2 || ids[0] != "cl_a" || ids[1] != "cl_b" {
		t.Errorf("ids = %v, want [cl_a cl_b] deduplicated and sorted", ids)
	}
}

// No grants must mean no clusters, never all clusters. This is the direction that
// would be a silent privilege escalation.
func TestNoGrantsReachesNothing(t *testing.T) {
	ids, unrestricted, err := AccessibleClusterIDs(context.Background(), nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if unrestricted {
		t.Fatal("a principal with NO grants was reported as unrestricted — that is a silent escalation to full fleet access")
	}
	if len(ids) != 0 {
		t.Errorf("ids = %v, want empty", ids)
	}
}

// A grant this build cannot interpret must fail loudly. Contributing nothing
// silently denies; widening silently grants. Both are worse than an error.
//
// ClusterGroup with a real group id is no longer in this list — BACKLOG.md S3
// made it resolvable (via cluster_group_members), and exercising the
// resolved path honestly needs a real Postgres connection; see
// permissions_db_test.go's TestAccessibleClusterIDs_ClusterGroup* for that
// side. A ClusterGroup grant naming NO group at all is still a pure,
// DB-free error case and stays here (mirroring the "Cluster with no
// clusterId" case immediately below it).
func TestUnresolvableScopesError(t *testing.T) {
	for _, tc := range []struct {
		name   string
		grant  EffectiveGrant
		wantIn string
	}{
		{"cluster group with no group id", EffectiveGrant{Capability: CapIncidentRead, Scope: Scope{Type: "ClusterGroup"}}, "names no cluster group"},
		{"cluster scope with no cluster", EffectiveGrant{Capability: CapIncidentRead, Scope: Scope{Type: "Cluster"}}, "names no cluster"},
		{"unknown type", EffectiveGrant{Capability: CapIncidentRead, Scope: Scope{Type: "Galaxy"}}, "unrecognised scope type"},
	} {
		_, unrestricted, err := AccessibleClusterIDs(context.Background(), nil, []EffectiveGrant{tc.grant})
		if err == nil {
			t.Errorf("%s: accepted silently", tc.name)
			continue
		}
		if unrestricted {
			t.Errorf("%s: errored AND reported unrestricted — an uninterpretable grant must never widen access", tc.name)
		}
		if !strings.Contains(err.Error(), tc.wantIn) {
			t.Errorf("%s: %v, want a message containing %q", tc.name, err, tc.wantIn)
		}
	}
}

// Holding a capability on one cluster is not holding it on another. This is the
// check that was entirely absent: HasCapability compared names and ignored scope,
// so a grant scoped to one cluster authorised actions on every cluster.
func TestHasCapabilityForClusterRespectsScope(t *testing.T) {
	ctx := context.Background()
	// AllClusters/Cluster grants never touch tx (only a ClusterGroup grant
	// needs a membership lookup — see the db-backed test for that case), so
	// a nil pgx.Tx is safe for every case here.
	has := func(grants []EffectiveGrant, capability, clusterID string) bool {
		t.Helper()
		allowed, err := HasCapabilityForCluster(ctx, nil, grants, capability, clusterID)
		if err != nil {
			t.Fatalf("HasCapabilityForCluster(%q, %q): unexpected error: %v", capability, clusterID, err)
		}
		return allowed
	}

	scoped := []EffectiveGrant{{Capability: CapRemediationApprove, Scope: Scope{Type: "Cluster", ClusterID: "cl_a"}}}

	if !has(scoped, CapRemediationApprove, "cl_a") {
		t.Error("a grant on cl_a did not authorise cl_a")
	}
	if has(scoped, CapRemediationApprove, "cl_b") {
		t.Fatal("a grant scoped to cl_a authorised an action on cl_b — the exact hole this closes")
	}
	if has(scoped, CapIncidentTriage, "cl_a") {
		t.Error("a grant for one capability authorised a different one")
	}
	// An org-level action (no cluster) needs AllClusters. Treating "" as a
	// wildcard would turn every scoped grant fleet-wide on any route that does not
	// know its cluster — the failure mode most likely to be introduced by accident.
	if has(scoped, CapRemediationApprove, "") {
		t.Fatal("a cluster-scoped grant authorised an org-level action with no cluster; \"\" must not be a wildcard")
	}

	all := []EffectiveGrant{{Capability: CapRemediationApprove, Scope: Scope{Type: "AllClusters"}}}
	for _, cluster := range []string{"cl_a", "cl_b", ""} {
		if !has(all, CapRemediationApprove, cluster) {
			t.Errorf("an AllClusters grant did not authorise cluster %q", cluster)
		}
	}
}

// HasCapability's scope-blind behaviour is kept for genuinely org-level routes,
// but it must not be mistaken for the scoped check. Asserted so the difference is
// visible to whoever reads these two functions next.
func TestHasCapabilityRemainsScopeBlindByDesign(t *testing.T) {
	scoped := []EffectiveGrant{{Capability: CapAuditRead, Scope: Scope{Type: "Cluster", ClusterID: "cl_a"}}}
	if !HasCapability(scoped, CapAuditRead) {
		t.Error("HasCapability stopped matching on capability name alone; routes that are genuinely org-level rely on that")
	}
	if allowed, err := HasCapabilityForCluster(context.Background(), nil, scoped, CapAuditRead, ""); err != nil {
		t.Fatalf("unexpected error: %v", err)
	} else if allowed {
		t.Error("the scoped check treated an org-level request as satisfied by a cluster-scoped grant")
	}
}
