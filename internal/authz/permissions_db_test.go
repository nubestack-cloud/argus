package authz

import (
	"context"
	"encoding/json"
	"os"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"argus/internal/data"
	"argus/internal/domain"
)

// AccessibleClusterIDs' ClusterGroup case and ResolveRoleCapabilities' custom
// role case are both properties of FORCE ROW LEVEL SECURITY, not of Go code —
// see internal/scm/objectmapping_db_test.go's own doc comment for the
// identical reasoning. Real Postgres, gated behind ARGUS_TEST_DATABASE_URL,
// argus_app (never the postgres superuser, which has BYPASSRLS and would
// make this pass regardless of whether the policy actually works).
//
//	export ARGUS_TEST_DATABASE_URL="postgres://argus_app:dev-local-password@localhost:5432/argus?sslmode=disable"
func permTestPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	connString := os.Getenv("ARGUS_TEST_DATABASE_URL")
	if connString == "" {
		t.Skip("ARGUS_TEST_DATABASE_URL not set; skipping DB-backed cluster-group/custom-role RLS test (see this file's doc comment)")
	}
	pool, err := pgxpool.New(context.Background(), connString)
	if err != nil {
		t.Fatalf("connect to test database: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

// insertTestOrganisation inserts a genuinely separate organisations row —
// needed here (unlike internal/scm/objectmapping_db_test.go's fake tenant
// IDs) because clusters.tenant_id carries a real foreign key to
// organisations(id), and this file's isolation tests need a real cluster row
// under each of two tenants. Cleaned up (and every dependent row this file
// creates under it) before the test ends. Harmless to other concurrently
// running tests: nothing in this codebase asserts organisations holds
// exactly one row or a specific id, only data.SingleOrganisationID's own
// (undocumented-but-tolerant) "any row" semantics — see that function's own
// LIMIT 1 with no ORDER BY.
func insertTestOrganisation(t *testing.T, pool *pgxpool.Pool) string {
	t.Helper()
	ctx := context.Background()
	id := domain.NewID("f19org")
	if _, err := pool.Exec(ctx, `INSERT INTO organisations (id, name) VALUES ($1, $2)`, id, "RLS test org "+id); err != nil {
		t.Fatalf("insert test organisation: %v", err)
	}
	t.Cleanup(func() {
		if _, err := pool.Exec(context.Background(), `DELETE FROM organisations WHERE id = $1`, id); err != nil {
			t.Errorf("cleanup delete organisation %s: %v", id, err)
		}
	})
	return id
}

// execScoped runs one write inside its own transaction with request scope
// set — every table this file touches has FORCE ROW LEVEL SECURITY with no
// separate WITH CHECK clause, so Postgres reuses the USING expression as the
// INSERT/DELETE check too: a bare pool.Exec with no session variables set
// (current_setting returns NULL) fails every one of them, not just SELECT.
// accessibleClusterIDs is only needed for `clusters` itself (its policy
// keys on id, not tenant_id — migration 000009's special case) — nil for
// every tenant-scoped table (cluster_groups, cluster_group_members,
// custom_roles), which key on app.tenant_id alone.
func execScoped(t *testing.T, pool *pgxpool.Pool, tenantID string, accessibleClusterIDs []string, sql string, args ...any) {
	t.Helper()
	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if err := data.SetRequestScope(ctx, tx, tenantID, accessibleClusterIDs); err != nil {
		t.Fatalf("set request scope: %v", err)
	}
	if _, err := tx.Exec(ctx, sql, args...); err != nil {
		t.Fatalf("exec %q: %v", sql, err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit: %v", err)
	}
}

// insertTestCluster inserts a minimal, throwaway Active cluster under
// tenantID — cluster_fingerprint is set to the cluster's own id, which is
// always unique, since clusters_fingerprint_active_idx (migration 000002) is
// unique across the WHOLE table, not per tenant. The insert scopes
// accessible_cluster_ids to the cluster's own not-yet-existing id: `clusters`'
// RLS policy is id = ANY(accessible_cluster_ids) with no separate WITH CHECK,
// so that IS the check a new row's own id must satisfy.
func insertTestCluster(t *testing.T, pool *pgxpool.Pool, tenantID string) string {
	t.Helper()
	id := domain.NewID(domain.PrefixCluster)
	execScoped(t, pool, tenantID, []string{id},
		`INSERT INTO clusters (id, tenant_id, display_name, state, shard_id, cluster_fingerprint)
		 VALUES ($1, $2, $3, 'Active', 'shard-0', $1)`,
		id, tenantID, "RLS test cluster "+id)
	t.Cleanup(func() {
		execScoped(t, pool, tenantID, []string{id}, `DELETE FROM clusters WHERE id = $1`, id)
	})
	return id
}

// insertTestClusterGroup and addTestClusterToGroup write through the same
// tenant-scoped tables internal/api/cluster_groups.go's handlers do.
func insertTestClusterGroup(t *testing.T, pool *pgxpool.Pool, tenantID string) string {
	t.Helper()
	id := domain.NewID(domain.PrefixClusterGroup)
	execScoped(t, pool, tenantID, nil,
		`INSERT INTO cluster_groups (id, tenant_id, name, label_selector) VALUES ($1, $2, $3, '{}')`,
		id, tenantID, "RLS test group "+id)
	t.Cleanup(func() {
		execScoped(t, pool, tenantID, nil, `DELETE FROM cluster_groups WHERE id = $1`, id)
	})
	return id
}

func addTestClusterToGroup(t *testing.T, pool *pgxpool.Pool, tenantID, groupID, clusterID string) {
	t.Helper()
	id := domain.NewID(domain.PrefixClusterGroupMember)
	execScoped(t, pool, tenantID, nil,
		`INSERT INTO cluster_group_members (id, tenant_id, cluster_group_id, cluster_id, added_by) VALUES ($1, $2, $3, $4, 'test')`,
		id, tenantID, groupID, clusterID)
	t.Cleanup(func() {
		execScoped(t, pool, tenantID, nil, `DELETE FROM cluster_group_members WHERE id = $1`, id)
	})
}

func insertTestCustomRole(t *testing.T, pool *pgxpool.Pool, tenantID string, capSet []string) string {
	t.Helper()
	id := domain.NewID(domain.PrefixCustomRole)
	capJSON, err := json.Marshal(capSet)
	if err != nil {
		t.Fatalf("marshal capability set: %v", err)
	}
	execScoped(t, pool, tenantID, nil,
		`INSERT INTO custom_roles (id, tenant_id, name, capability_set, created_by) VALUES ($1, $2, $3, $4, 'test')`,
		id, tenantID, "RLS test role "+id, capJSON)
	t.Cleanup(func() {
		execScoped(t, pool, tenantID, nil, `DELETE FROM custom_roles WHERE id = $1`, id)
	})
	return id
}

// scopedTx begins a transaction scoped to tenantID (tenant scope only,
// accessible_cluster_ids left empty) — the exact state
// internal/api/middleware.go's requireAuth is in when it calls
// AccessibleClusterIDs, and why cluster_group_members/custom_roles are
// tenant-scoped rather than cluster_id-scoped (see migration 000078's
// comment): both must be readable in precisely this state.
func scopedTx(t *testing.T, pool *pgxpool.Pool, tenantID string) (context.Context, pgx.Tx) {
	t.Helper()
	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	if err := data.SetRequestScope(ctx, tx, tenantID, nil); err != nil {
		t.Fatalf("set request scope: %v", err)
	}
	t.Cleanup(func() { tx.Rollback(ctx) }) //nolint:errcheck
	return ctx, tx
}

func TestAccessibleClusterIDs_ClusterGroupResolvesMembership(t *testing.T) {
	pool := permTestPool(t)
	tenantA := insertTestOrganisation(t, pool)
	clusterA1 := insertTestCluster(t, pool, tenantA)
	_ = insertTestCluster(t, pool, tenantA) // clusterA2: deliberately never added to the group
	groupA := insertTestClusterGroup(t, pool, tenantA)
	addTestClusterToGroup(t, pool, tenantA, groupA, clusterA1)

	ctx, tx := scopedTx(t, pool, tenantA)
	grants := []EffectiveGrant{{Capability: CapIncidentRead, Scope: Scope{Type: "ClusterGroup", GroupID: groupA}}}
	ids, unrestricted, err := AccessibleClusterIDs(ctx, tx, grants)
	if err != nil {
		t.Fatalf("AccessibleClusterIDs: %v", err)
	}
	if unrestricted {
		t.Fatal("a ClusterGroup grant was reported as unrestricted — only AllClusters may ever be")
	}
	if len(ids) != 1 || ids[0] != clusterA1 {
		t.Errorf("ids = %v, want exactly [%s] (the one cluster actually added to the group)", ids, clusterA1)
	}
}

func TestAccessibleClusterIDs_ClusterGroupIsolatesTenants(t *testing.T) {
	pool := permTestPool(t)
	tenantA := insertTestOrganisation(t, pool)
	tenantB := insertTestOrganisation(t, pool)
	clusterA1 := insertTestCluster(t, pool, tenantA)
	groupA := insertTestClusterGroup(t, pool, tenantA)
	addTestClusterToGroup(t, pool, tenantA, groupA, clusterA1)

	t.Run("tenant A's own scope sees the membership", func(t *testing.T) {
		ctx, tx := scopedTx(t, pool, tenantA)
		grants := []EffectiveGrant{{Capability: CapIncidentRead, Scope: Scope{Type: "ClusterGroup", GroupID: groupA}}}
		ids, _, err := AccessibleClusterIDs(ctx, tx, grants)
		if err != nil {
			t.Fatalf("AccessibleClusterIDs: %v", err)
		}
		if len(ids) != 1 || ids[0] != clusterA1 {
			t.Fatalf("ids = %v, want [%s]", ids, clusterA1)
		}
	})

	t.Run("a DIFFERENT tenant's scope must never see tenant A's membership", func(t *testing.T) {
		// Same group id, resolved under tenant B's scope. If RLS is doing its
		// job, tenant B's transaction cannot even see tenant A's
		// cluster_group_members row — this must come back as "reaches
		// nothing", never as an error and never as tenant A's cluster.
		ctx, tx := scopedTx(t, pool, tenantB)
		grants := []EffectiveGrant{{Capability: CapIncidentRead, Scope: Scope{Type: "ClusterGroup", GroupID: groupA}}}
		ids, unrestricted, err := AccessibleClusterIDs(ctx, tx, grants)
		if err != nil {
			t.Fatalf("AccessibleClusterIDs: %v", err)
		}
		if unrestricted {
			t.Fatal("an uninterpretable/foreign group must never widen to unrestricted")
		}
		if len(ids) != 0 {
			t.Fatalf("tenant B resolved tenant A's cluster group membership: ids = %v — RLS isolation is broken", ids)
		}
	})
}

func TestAccessibleClusterIDs_UnknownClusterGroupReachesNothing(t *testing.T) {
	pool := permTestPool(t)
	tenantA := insertTestOrganisation(t, pool)

	ctx, tx := scopedTx(t, pool, tenantA)
	grants := []EffectiveGrant{{Capability: CapIncidentRead, Scope: Scope{Type: "ClusterGroup", GroupID: domain.NewID(domain.PrefixClusterGroup)}}}
	ids, unrestricted, err := AccessibleClusterIDs(ctx, tx, grants)
	if err != nil {
		t.Fatalf("AccessibleClusterIDs: %v", err)
	}
	if unrestricted {
		t.Fatal("an unknown group must never widen to unrestricted")
	}
	if len(ids) != 0 {
		t.Errorf("ids = %v, want empty for a group id nothing created", ids)
	}
}

// ScopeIncludesCluster is BACKLOG.md F30's own primitive: unlike
// AccessibleClusterIDs (a principal's whole grant set), this answers the
// question for ONE stored Scope against ONE candidate cluster —
// scm.ObjectMapping's own Scope field, checked at resolution time, is its
// first real caller. The ClusterGroup branch reuses the exact same
// clusterGroupMemberIDs this file's own AccessibleClusterIDs tests already
// exercise, so this pins the wrapper, not a second copy of the membership
// query.
func TestScopeIncludesCluster(t *testing.T) {
	pool := permTestPool(t)
	tenantA := insertTestOrganisation(t, pool)
	clusterA1 := insertTestCluster(t, pool, tenantA)
	clusterA2 := insertTestCluster(t, pool, tenantA)
	groupA := insertTestClusterGroup(t, pool, tenantA)
	addTestClusterToGroup(t, pool, tenantA, groupA, clusterA1)

	t.Run("AllClusters covers any cluster", func(t *testing.T) {
		ctx, tx := scopedTx(t, pool, tenantA)
		covers, err := ScopeIncludesCluster(ctx, tx, Scope{Type: "AllClusters"}, clusterA2)
		if err != nil || !covers {
			t.Fatalf("ScopeIncludesCluster(AllClusters, %s) = %v, %v, want true, nil", clusterA2, covers, err)
		}
	})

	// F30's own backward-compatibility default: every ObjectMapping written
	// before Scope existed decodes with a zero-value Scope, and that MUST
	// keep matching every cluster exactly as it always did — see
	// scm.ObjectMapping's own doc comment on why an empty Type cannot become
	// a validation error or a "matches nothing" result.
	t.Run("the zero-value (unset) scope also covers any cluster", func(t *testing.T) {
		ctx, tx := scopedTx(t, pool, tenantA)
		covers, err := ScopeIncludesCluster(ctx, tx, Scope{}, clusterA2)
		if err != nil || !covers {
			t.Fatalf("ScopeIncludesCluster({}, %s) = %v, %v, want true, nil", clusterA2, covers, err)
		}
	})

	t.Run("Cluster covers only the named cluster, not a sibling", func(t *testing.T) {
		ctx, tx := scopedTx(t, pool, tenantA)
		covers, err := ScopeIncludesCluster(ctx, tx, Scope{Type: "Cluster", ClusterID: clusterA1}, clusterA1)
		if err != nil || !covers {
			t.Fatalf("ScopeIncludesCluster(Cluster:%s, %s) = %v, %v, want true, nil", clusterA1, clusterA1, covers, err)
		}
		covers, err = ScopeIncludesCluster(ctx, tx, Scope{Type: "Cluster", ClusterID: clusterA1}, clusterA2)
		if err != nil || covers {
			t.Fatalf("ScopeIncludesCluster(Cluster:%s, %s) = %v, %v, want false, nil — this is F30's actual bug: a Cluster-scoped mapping must never leak to a different cluster", clusterA1, clusterA2, covers, err)
		}
	})

	t.Run("ClusterGroup covers only its members", func(t *testing.T) {
		ctx, tx := scopedTx(t, pool, tenantA)
		covers, err := ScopeIncludesCluster(ctx, tx, Scope{Type: "ClusterGroup", GroupID: groupA}, clusterA1)
		if err != nil || !covers {
			t.Fatalf("ScopeIncludesCluster(ClusterGroup:%s, %s) = %v, %v, want true, nil (clusterA1 is a member)", groupA, clusterA1, covers, err)
		}
		covers, err = ScopeIncludesCluster(ctx, tx, Scope{Type: "ClusterGroup", GroupID: groupA}, clusterA2)
		if err != nil || covers {
			t.Fatalf("ScopeIncludesCluster(ClusterGroup:%s, %s) = %v, %v, want false, nil (clusterA2 was never added)", groupA, clusterA2, covers, err)
		}
	})
}

// HasCapabilityForCluster's ClusterGroup case was entirely untested until
// this test — found in a whole-repo review pass (2026-09-27): the function
// had no case for "ClusterGroup" at all, so a grant scoped to a cluster
// group fell through to false for every cluster in it, on every write-side
// gate that calls this function (preflight, approve, rollback, repository
// writes, cluster reads, the resolution route). AccessibleClusterIDs
// resolved group membership correctly for READING (the grant appeared in
// fleet listings), so the holder saw the cluster and believed they had the
// capability, then got a 403 on every action. Fails closed, so not an
// escalation — but a real correctness gap in exactly the scope model this
// package's own header comment describes as needing both halves to work.
func TestHasCapabilityForCluster_ClusterGroupScope(t *testing.T) {
	pool := permTestPool(t)
	tenantA := insertTestOrganisation(t, pool)
	clusterA1 := insertTestCluster(t, pool, tenantA)
	clusterA2 := insertTestCluster(t, pool, tenantA)
	groupA := insertTestClusterGroup(t, pool, tenantA)
	addTestClusterToGroup(t, pool, tenantA, groupA, clusterA1)

	grants := []EffectiveGrant{{Capability: CapRemediationApprove, Scope: Scope{Type: "ClusterGroup", GroupID: groupA}}}

	t.Run("a ClusterGroup grant authorises a member cluster", func(t *testing.T) {
		ctx, tx := scopedTx(t, pool, tenantA)
		allowed, err := HasCapabilityForCluster(ctx, tx, grants, CapRemediationApprove, clusterA1)
		if err != nil || !allowed {
			t.Fatalf("HasCapabilityForCluster(ClusterGroup:%s, %s) = %v, %v, want true, nil — clusterA1 is a member", groupA, clusterA1, allowed, err)
		}
	})

	t.Run("a ClusterGroup grant does not authorise a non-member cluster", func(t *testing.T) {
		ctx, tx := scopedTx(t, pool, tenantA)
		allowed, err := HasCapabilityForCluster(ctx, tx, grants, CapRemediationApprove, clusterA2)
		if err != nil || allowed {
			t.Fatalf("HasCapabilityForCluster(ClusterGroup:%s, %s) = %v, %v, want false, nil — clusterA2 was never added", groupA, clusterA2, allowed, err)
		}
	})

	t.Run("a ClusterGroup grant does not satisfy an org-level (no cluster) action", func(t *testing.T) {
		ctx, tx := scopedTx(t, pool, tenantA)
		allowed, err := HasCapabilityForCluster(ctx, tx, grants, CapRemediationApprove, "")
		if err != nil || allowed {
			t.Fatalf("HasCapabilityForCluster(ClusterGroup:%s, \"\") = %v, %v, want false, nil — \"\" must not be a wildcard", groupA, allowed, err)
		}
	})
}

func TestResolveRoleCapabilities_CustomRole(t *testing.T) {
	pool := permTestPool(t)
	tenantA := insertTestOrganisation(t, pool)
	roleA := insertTestCustomRole(t, pool, tenantA, []string{CapIncidentRead, CapAnalysisRead})

	ctx, tx := scopedTx(t, pool, tenantA)
	caps, ok, err := ResolveRoleCapabilities(ctx, tx, roleA)
	if err != nil {
		t.Fatalf("ResolveRoleCapabilities: %v", err)
	}
	if !ok {
		t.Fatal("a real custom role under the caller's own tenant was not found")
	}
	got := map[string]bool{}
	for _, c := range caps {
		got[c] = true
	}
	if !got[CapIncidentRead] || !got[CapAnalysisRead] || len(caps) != 2 {
		t.Errorf("caps = %v, want exactly [%s %s]", caps, CapIncidentRead, CapAnalysisRead)
	}
}

func TestResolveRoleCapabilities_CustomRoleIsolatesTenants(t *testing.T) {
	pool := permTestPool(t)
	tenantA := insertTestOrganisation(t, pool)
	tenantB := insertTestOrganisation(t, pool)
	roleA := insertTestCustomRole(t, pool, tenantA, []string{CapIncidentRead})

	ctx, tx := scopedTx(t, pool, tenantB)
	caps, ok, err := ResolveRoleCapabilities(ctx, tx, roleA)
	if err != nil {
		t.Fatalf("ResolveRoleCapabilities: %v", err)
	}
	if ok {
		t.Fatalf("tenant B resolved tenant A's custom role: caps = %v — RLS isolation is broken", caps)
	}
}

func TestResolveRoleCapabilities_UnknownRoleIDIsNotFoundNotError(t *testing.T) {
	pool := permTestPool(t)
	tenantA := insertTestOrganisation(t, pool)

	ctx, tx := scopedTx(t, pool, tenantA)
	_, ok, err := ResolveRoleCapabilities(ctx, tx, domain.NewID(domain.PrefixCustomRole))
	if err != nil {
		t.Fatalf("ResolveRoleCapabilities: %v", err)
	}
	if ok {
		t.Fatal("a role id nothing created must not resolve")
	}
}
