package scm

import (
	"context"
	"encoding/json"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"argus/internal/authz"
	"argus/internal/data"
	"argus/internal/domain"
	"argus/internal/secretbox"
)

// FindObjectMapping's whole reason for taking a pgx.Tx rather than opening its
// own connection is that it must run inside the CALLER's already RLS-scoped
// transaction (internal/scm/store.go's own package doc comment on Store makes
// the identical point for every other method here) — a mapping registered
// under one tenant must never be visible to a different tenant's
// investigation. That guarantee is a property of a live Postgres with FORCE
// ROW LEVEL SECURITY, not of Go code, so — matching internal/authz/
// session_test.go and internal/orchestrator/db_test.go's own precedent —
// this talks to a real database, gated behind ARGUS_TEST_DATABASE_URL, and a
// machine without one gets a clean skip rather than a failure.
//
//	export ARGUS_TEST_DATABASE_URL="postgres://argus_app:dev-local-password@localhost:5432/argus?sslmode=disable"
//
// argus_app, not the postgres superuser: that role has BYPASSRLS and would
// make this test pass regardless of whether the policy actually works.
func testPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	connString := os.Getenv("ARGUS_TEST_DATABASE_URL")
	if connString == "" {
		t.Skip("ARGUS_TEST_DATABASE_URL not set; skipping DB-backed FindObjectMapping RLS test (see this file's doc comment)")
	}
	pool, err := pgxpool.New(context.Background(), connString)
	if err != nil {
		t.Fatalf("connect to test database: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

// insertBindingWithMapping inserts one throwaway repository_bindings row,
// scoped to tenantID, whose spec carries exactly one ObjectMapping — and
// registers cleanup of that row, scoped to the SAME tenant (a transaction
// scoped to a different tenant could not see it to delete it, by the very
// policy this test exists to prove).
func insertBindingWithMapping(t *testing.T, pool *pgxpool.Pool, tenantID string, mapping ObjectMapping) {
	t.Helper()
	ctx := context.Background()

	id := domain.NewID(domain.PrefixRepositoryBinding)
	repoKey := "github.com/f19-rls-test/" + id
	spec, err := json.Marshal(map[string]any{"objectMappings": []ObjectMapping{mapping}})
	if err != nil {
		t.Fatalf("marshal spec: %v", err)
	}

	insert := func() {
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatalf("begin: %v", err)
		}
		defer tx.Rollback(ctx) //nolint:errcheck
		if err := data.SetRequestScope(ctx, tx, tenantID, nil); err != nil {
			t.Fatalf("set request scope: %v", err)
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO repository_bindings (id, tenant_id, provider, url, repo_key, credential_ref, spec)
			 VALUES ($1, $2, 'github', $3, $4, $5, $6)`,
			id, tenantID, "https://github.com/f19-rls-test/"+id, repoKey, "sec_f19-rls-test-"+id, spec); err != nil {
			t.Fatalf("insert binding: %v", err)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatalf("commit: %v", err)
		}
	}
	insert()

	t.Cleanup(func() {
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Errorf("cleanup begin: %v", err)
			return
		}
		defer tx.Rollback(ctx) //nolint:errcheck
		if err := data.SetRequestScope(ctx, tx, tenantID, nil); err != nil {
			t.Errorf("cleanup set request scope: %v", err)
			return
		}
		if _, err := tx.Exec(ctx, `DELETE FROM repository_bindings WHERE id = $1`, id); err != nil {
			t.Errorf("cleanup delete binding: %v", err)
			return
		}
		if err := tx.Commit(ctx); err != nil {
			t.Errorf("cleanup commit: %v", err)
		}
	})
}

// findScopedTo runs FindObjectMapping inside a fresh transaction scoped to
// tenantID — the thing under test is entirely in which rows that scope makes
// visible.
func findScopedTo(t *testing.T, pool *pgxpool.Pool, tenantID, releaseName, releaseNamespace string, labels map[string]string) (MatchedObjectMapping, bool) {
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
	matched, found, err := FindObjectMapping(ctx, tx, "cl_any", releaseName, releaseNamespace, labels)
	if err != nil {
		t.Fatalf("FindObjectMapping: %v", err)
	}
	return matched, found
}

// findScopedToCluster is findScopedTo with an explicit clusterID rather than
// the fixed "cl_any" placeholder — BACKLOG.md F30's own tests, which are
// entirely about which CLUSTER a mapping is visible to (once the tenant
// scope already lets it through), need to vary that.
func findScopedToCluster(t *testing.T, pool *pgxpool.Pool, tenantID, clusterID, releaseName, releaseNamespace string) (MatchedObjectMapping, bool) {
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
	matched, found, err := FindObjectMapping(ctx, tx, clusterID, releaseName, releaseNamespace, nil)
	if err != nil {
		t.Fatalf("FindObjectMapping: %v", err)
	}
	return matched, found
}

// BACKLOG.md F30's actual bug, reproduced and fixed: MatchesRelease itself
// takes no cluster, so before Scope existed, a mapping for "shop-apps in
// default" matched that release/namespace on EVERY cluster in the fleet — a
// dev/prod split fed from different overlays got one (wrong, for one of
// them) path for both. This proves the fix: a Cluster-scoped mapping is
// found on the cluster it names, and is invisible — not an error, just
// "no match", exactly as if it were never registered — on any other
// cluster, even though the release/namespace identity matches perfectly.
func TestFindObjectMapping_ClusterScopeDoesNotLeakToAnotherCluster(t *testing.T) {
	pool := testPool(t)
	tenantA := domain.NewID("f30testtenant")
	clusterProd := domain.NewID("f30testclusterprod")
	clusterDev := domain.NewID("f30testclusterdev")

	insertBindingWithMapping(t, pool, tenantA, ObjectMapping{
		ReleaseName: "shop-apps", Namespace: "default", Path: "envs/prod/shop-apps",
		Scope: authz.Scope{Type: "Cluster", ClusterID: clusterProd},
	})

	t.Run("found on the cluster the scope names", func(t *testing.T) {
		matched, found := findScopedToCluster(t, pool, tenantA, clusterProd, "shop-apps", "default")
		if !found || matched.Mapping.Path != "envs/prod/shop-apps" {
			t.Fatalf("FindObjectMapping(clusterProd) = %+v, %v, want a match on envs/prod/shop-apps", matched, found)
		}
	})

	t.Run("NOT found on a different cluster, even with an identical release/namespace", func(t *testing.T) {
		if _, found := findScopedToCluster(t, pool, tenantA, clusterDev, "shop-apps", "default"); found {
			t.Fatal("a Cluster-scoped mapping for clusterProd matched on clusterDev too — this is exactly BACKLOG.md F30's bug: MatchesRelease alone cannot tell clusters apart")
		}
	})
}

// The explicit AllClusters scope, and the backward-compatible zero-value
// scope (every mapping written before this field existed), both still
// match on every cluster — F30 changes the DEFAULT bug, not the intended
// fleet-wide case (200 clusters running one chart stays ONE confirmation).
func TestFindObjectMapping_AllClustersAndUnscopedMatchEveryCluster(t *testing.T) {
	pool := testPool(t)
	tenantA := domain.NewID("f30testtenant")
	clusterA := domain.NewID("f30testclustera")
	clusterB := domain.NewID("f30testclusterb")

	t.Run("explicit AllClusters", func(t *testing.T) {
		insertBindingWithMapping(t, pool, tenantA, ObjectMapping{
			ReleaseName: "coredns", Namespace: "kube-system", Path: "envs/all/coredns",
			Scope: authz.Scope{Type: "AllClusters"},
		})
		for _, cluster := range []string{clusterA, clusterB} {
			if _, found := findScopedToCluster(t, pool, tenantA, cluster, "coredns", "kube-system"); !found {
				t.Errorf("AllClusters-scoped mapping not found on cluster %s", cluster)
			}
		}
	})

	t.Run("unscoped (pre-F30) mapping", func(t *testing.T) {
		insertBindingWithMapping(t, pool, tenantA, ObjectMapping{
			ReleaseName: "legacy-release", Namespace: "default", Path: "envs/legacy",
		})
		for _, cluster := range []string{clusterA, clusterB} {
			if _, found := findScopedToCluster(t, pool, tenantA, cluster, "legacy-release", "default"); !found {
				t.Errorf("unscoped mapping (written before Scope existed) not found on cluster %s — this must never regress, every existing mapping relies on it", cluster)
			}
		}
	})
}

func TestFindObjectMapping_RLSIsolatesTenants(t *testing.T) {
	pool := testPool(t)

	tenantA := domain.NewID("f19testtenanta")
	tenantB := domain.NewID("f19testtenantb")

	insertBindingWithMapping(t, pool, tenantA, ObjectMapping{
		ReleaseName: "payments", Namespace: "prod", Path: "envs/prod/payments",
	})

	t.Run("the registering tenant's own scope sees the match", func(t *testing.T) {
		matched, found := findScopedTo(t, pool, tenantA, "payments", "prod", nil)
		if !found {
			t.Fatal("FindObjectMapping found nothing under the tenant that registered the mapping")
		}
		if matched.Mapping.Path != "envs/prod/payments" {
			t.Errorf("matched mapping = %+v, want path envs/prod/payments", matched.Mapping)
		}
	})

	t.Run("a DIFFERENT tenant's scope must never see it", func(t *testing.T) {
		// Same release name and namespace, looked up under tenantB's scope
		// instead of tenantA's. If RLS is doing its job, tenantB's
		// transaction cannot even SEE tenantA's row to check its mappings
		// against — this must come back exactly as "no operator mapping
		// configured", never as an error and never as tenantA's match.
		_, found := findScopedTo(t, pool, tenantB, "payments", "prod", nil)
		if found {
			t.Fatal("FindObjectMapping under tenantB matched a mapping registered under tenantA — RLS isolation is broken")
		}
	})

	t.Run("a genuinely unrelated release under the registering tenant does not match either", func(t *testing.T) {
		_, found := findScopedTo(t, pool, tenantA, "checkout", "prod", nil)
		if found {
			t.Fatal("FindObjectMapping matched a release it was never told about")
		}
	})
}

func TestFindObjectMapping_RLSIsolatesLabelSelectorToo(t *testing.T) {
	pool := testPool(t)

	tenantA := domain.NewID("f19testtenanta")
	tenantB := domain.NewID("f19testtenantb")

	insertBindingWithMapping(t, pool, tenantA, ObjectMapping{
		LabelSelector: map[string]string{"team": "payments"}, Path: "envs/prod/shared",
	})

	labels := map[string]string{"team": "payments", "tier": "backend"}

	matched, found := findScopedTo(t, pool, tenantA, "", "", labels)
	if !found || matched.Mapping.Path != "envs/prod/shared" {
		t.Fatalf("FindObjectMapping(tenantA) = %+v, %v, want a match on envs/prod/shared", matched, found)
	}

	if _, found := findScopedTo(t, pool, tenantB, "", "", labels); found {
		t.Fatal("FindObjectMapping under tenantB matched a label-selector mapping registered under tenantA — RLS isolation is broken")
	}
}

// TestSaveBinding_ObjectMappings is the write path's own DB-backed coverage:
// SaveBinding is where BACKLOG.md F19's validation actually lives (see
// store.go — it runs before the first tx call), and the only way to prove a
// well-formed objectMappings list is actually STORED and comes back out
// again is to write it for real and read it back through ProviderFor's own
// applySpec decode, exactly as the PR-opening path would.
func TestSaveBinding_ObjectMappings(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	keeper := testKeeper(t)
	store := NewStore(keeper)

	tenantID := domain.NewID("f19testtenant")
	url := "https://github.com/f19-savebinding-test/" + domain.NewID("repo")

	t.Run("a well-formed list is written and reads back unchanged", func(t *testing.T) {
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatalf("begin: %v", err)
		}
		defer tx.Rollback(ctx) //nolint:errcheck
		if err := data.SetRequestScope(ctx, tx, tenantID, nil); err != nil {
			t.Fatalf("set request scope: %v", err)
		}

		mappings := []ObjectMapping{
			{ReleaseName: "payments", Namespace: "prod", Path: "envs/prod/payments"},
			{LabelSelector: map[string]string{"team": "checkout"}, Path: "envs/prod/checkout"},
		}
		saved, err := store.SaveBinding(ctx, tx, tenantID, Binding{
			Provider: "github", URL: url, ObjectMappings: mappings,
		}, []byte("faketoken-not-a-real-credential-1234567890"))
		if err != nil {
			t.Fatalf("SaveBinding: %v", err)
		}
		if len(saved.ObjectMappings) != 2 {
			t.Fatalf("SaveBinding returned ObjectMappings = %+v, want 2", saved.ObjectMappings)
		}

		// Read back through the same path a real PR-opening call uses.
		_, _, binding, err := store.ProviderFor(ctx, tx, url)
		if err != nil {
			t.Fatalf("ProviderFor: %v", err)
		}
		if len(binding.ObjectMappings) != 2 {
			t.Fatalf("ProviderFor round-trip ObjectMappings = %+v, want 2", binding.ObjectMappings)
		}
		foundRelease, foundLabel := false, false
		for _, m := range binding.ObjectMappings {
			if m.MatchesRelease("payments", "prod") && m.Path == "envs/prod/payments" {
				foundRelease = true
			}
			if m.MatchesLabels(map[string]string{"team": "checkout"}) && m.Path == "envs/prod/checkout" {
				foundLabel = true
			}
		}
		if !foundRelease || !foundLabel {
			t.Fatalf("round-tripped ObjectMappings = %+v, missing one of the two written entries", binding.ObjectMappings)
		}

		if err := tx.Commit(ctx); err != nil {
			t.Fatalf("commit: %v", err)
		}
		t.Cleanup(func() { cleanupBindingByURL(t, pool, tenantID, url) })
	})

	t.Run("re-registering the same URL REPLACES objectMappings — supplying it updates it", func(t *testing.T) {
		url := "https://github.com/f19-savebinding-test/" + domain.NewID("repo")
		t.Cleanup(func() { cleanupBindingByURL(t, pool, tenantID, url) })

		write := func(mappings []ObjectMapping) Binding {
			tx, err := pool.Begin(ctx)
			if err != nil {
				t.Fatalf("begin: %v", err)
			}
			defer tx.Rollback(ctx) //nolint:errcheck
			if err := data.SetRequestScope(ctx, tx, tenantID, nil); err != nil {
				t.Fatalf("set request scope: %v", err)
			}
			saved, err := store.SaveBinding(ctx, tx, tenantID, Binding{
				Provider: "github", URL: url, ObjectMappings: mappings,
			}, []byte("faketoken-not-a-real-credential-1234567890"))
			if err != nil {
				t.Fatalf("SaveBinding: %v", err)
			}
			if err := tx.Commit(ctx); err != nil {
				t.Fatalf("commit: %v", err)
			}
			return saved
		}

		write([]ObjectMapping{{ReleaseName: "payments", Namespace: "prod", Path: "envs/prod/payments"}})
		write([]ObjectMapping{{ReleaseName: "checkout", Namespace: "prod", Path: "envs/prod/checkout"}})

		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatalf("begin: %v", err)
		}
		defer tx.Rollback(ctx) //nolint:errcheck
		if err := data.SetRequestScope(ctx, tx, tenantID, nil); err != nil {
			t.Fatalf("set request scope: %v", err)
		}
		matched, found, err := FindObjectMapping(ctx, tx, "cl_any", "payments", "prod", nil)
		if err != nil {
			t.Fatalf("FindObjectMapping: %v", err)
		}
		if found {
			t.Fatalf("the FIRST registration's mapping (%+v) is still there after re-registering — re-registering did not replace it", matched.Mapping)
		}
		matched, found, err = FindObjectMapping(ctx, tx, "cl_any", "checkout", "prod", nil)
		if err != nil {
			t.Fatalf("FindObjectMapping: %v", err)
		}
		if !found || matched.Mapping.Path != "envs/prod/checkout" {
			t.Fatalf("the SECOND registration's mapping was not found after re-registering: %+v, %v", matched, found)
		}
	})

	t.Run("an invalid entry refuses the whole registration before any write", func(t *testing.T) {
		url := "https://github.com/f19-savebinding-test/" + domain.NewID("repo")
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatalf("begin: %v", err)
		}
		defer tx.Rollback(ctx) //nolint:errcheck
		if err := data.SetRequestScope(ctx, tx, tenantID, nil); err != nil {
			t.Fatalf("set request scope: %v", err)
		}

		_, err = store.SaveBinding(ctx, tx, tenantID, Binding{
			Provider: "github", URL: url,
			ObjectMappings: []ObjectMapping{{ReleaseName: "payments", Namespace: "prod"}}, // no path
		}, []byte("faketoken-not-a-real-credential-1234567890"))
		if err == nil {
			t.Fatal("SaveBinding accepted an object mapping with no path")
		}

		// Nothing should have been written — same transaction, rolled back
		// below, but check now that no row is even visible within it.
		var count int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM repository_bindings WHERE url = $1`, url).Scan(&count); err != nil {
			t.Fatalf("count: %v", err)
		}
		if count != 0 {
			t.Fatalf("a binding row was written despite the invalid object mapping: %d rows", count)
		}
	})
}

// testKeeper builds a throwaway secretbox.Keeper so SaveBinding's Seal step
// has something real to call — the RLS/matching tests above never reach it
// (they insert rows directly, or use a nil keeper is not needed since they
// don't call SaveBinding), but TestSaveBinding_ObjectMappings does.
func testKeeper(t *testing.T) *secretbox.Keeper {
	t.Helper()
	kek, err := secretbox.GenerateLocalKEK()
	if err != nil {
		t.Fatalf("generate test KEK: %v", err)
	}
	keeper, err := secretbox.NewLocalKeeper(kek)
	if err != nil {
		t.Fatalf("build test keeper: %v", err)
	}
	return keeper
}

// cleanupBindingByURL deletes a binding (and its credential) written by
// TestSaveBinding_ObjectMappings, scoped to the tenant that wrote it —
// mirrors insertBindingWithMapping's own cleanup pattern.
func cleanupBindingByURL(t *testing.T, pool *pgxpool.Pool, tenantID, url string) {
	t.Helper()
	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Errorf("cleanup begin: %v", err)
		return
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if err := data.SetRequestScope(ctx, tx, tenantID, nil); err != nil {
		t.Errorf("cleanup set request scope: %v", err)
		return
	}
	var credentialRef string
	if err := tx.QueryRow(ctx, `DELETE FROM repository_bindings WHERE url = $1 RETURNING credential_ref`, url).Scan(&credentialRef); err != nil {
		t.Errorf("cleanup delete binding: %v", err)
		return
	}
	if _, err := tx.Exec(ctx, `DELETE FROM encrypted_secrets WHERE id = $1`, credentialRef); err != nil {
		t.Errorf("cleanup delete credential: %v", err)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		t.Errorf("cleanup commit: %v", err)
	}
}
