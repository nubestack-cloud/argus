package api

// TestCallRepoTool_ReadLogRegistryBridgesToTheCliBackend is BACKLOG.md F28
// finding 1's DB-backed proof of the cli-backend gap fix: a real Postgres-
// backed incident/binding fixture, a real CallRepoTool dispatch (the exact
// path a cli-backend investigation's MCP tool calls reach — internal/mcp's
// server has no Go closure into analyze.go's Reader, only cluster/incident
// ids), and a real repotools.ReadLogRegistry — proving that a read served
// through THIS path becomes visible to RefuseUnreadRepositoryProposals via
// the SAME registry a manual/unattended caller began, even though the two
// never share a Reader, a goroutine, or a call stack.
//
// Before this fix, F25's own doc comment recorded this as a real, disclosed
// gap: "the cli backend's tool calls reach internal/api.CallRepoTool through
// a fresh *repotools.Reader per MCP call with no ReadLog attached, so this
// guard does not yet cover it." Without the registry, this test's own
// "read, then check" half would fail — CallRepoTool's Reader would never
// see the shared log at all.

import (
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"argus/internal/data"
	"argus/internal/dbtest"
	"argus/internal/domain"
	"argus/internal/gitops"
	"argus/internal/llm"
	"argus/internal/orchestrator"
	"argus/internal/remediation"
	"argus/internal/repotools"
	"argus/internal/scm"
	"argus/internal/secretbox"
)

func f28RegistryTestPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	connString := os.Getenv("ARGUS_TEST_DATABASE_URL")
	if connString == "" {
		t.Skip("ARGUS_TEST_DATABASE_URL not set; skipping BACKLOG.md F28 DB-backed test")
	}
	pool, err := pgxpool.New(context.Background(), connString)
	if err != nil {
		t.Fatalf("connect to test database: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

// f28TestKeeper mirrors internal/scm/objectmapping_db_test.go's own
// testKeeper — SaveBinding's Seal step needs a real secretbox.Keeper, and
// that helper is unexported in a different package.
func f28TestKeeper(t *testing.T) *secretbox.Keeper {
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

// f28RegistryFixture opens one transaction, seeds a throwaway cluster and
// incident (repoLocateIdentityFixture's own pattern), a real repository
// binding with a real, decryptable (fake) credential via SaveBinding, and
// points the incident's own `ownership` column at that repository, pinned
// at a fake but well-formed revision — the exact shape parseRepoTarget
// expects (repository_change.go), so IncidentRepoScope resolves a genuinely
// Valid() Scope.
func f28RegistryFixture(t *testing.T, pool *pgxpool.Pool) (tx pgx.Tx, incidentID string, scmStore *scm.Store, repoURL string) {
	t.Helper()
	ctx := context.Background()

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	t.Cleanup(func() { _ = tx.Rollback(context.Background()) })

	tenantID, err := data.SingleOrganisationID(ctx, tx)
	if err != nil {
		t.Fatalf("resolve organisation: %v", err)
	}
	clusterID := domain.NewID(domain.PrefixCluster)
	if err := data.SetRequestScope(ctx, tx, tenantID, []string{clusterID}); err != nil {
		t.Fatalf("set request scope: %v", err)
	}

	// The fixture is COMMITTED partway through the test (CallRepoTool opens
	// its own transaction and cannot see an uncommitted one), so removing its
	// rows needs a second, separately-scoped transaction. Registered here
	// rather than at the commit site because this is the only scope that
	// knows both ids.
	//
	// # What the previous version did instead, and what it cost
	//
	// It ran `DELETE FROM incidents WHERE id = $1` on an UNSCOPED transaction
	// and discarded both return values. incidents has FORCE ROW LEVEL
	// SECURITY and argus_app cannot bypass it, so with app.tenant_id unset the
	// statement matched zero rows — no error, because a DELETE that removes
	// nothing is not one. It also never deleted the throwaway clusters row at
	// all. Every run therefore leaked one cluster and one incident into
	// whatever database it ran against, and because that cluster can never
	// connect, nothing could ever progress or close the incident: it sits in
	// the operator's queue permanently. On the development database
	// (2026-09-05) that was 22 of the 37 remaining open incidents, which is
	// enough to make any measurement of that queue wrong.
	//
	// Deliberately not something the promotion reconciliation
	// (internal/api/incident_promotion_reconcile.go) will ever clear either —
	// these incidents have no findings at all, and an empty finding history is
	// not a non-promotable one.
	//
	// dbtest.Fixture (BUGS.md, 2026-09-05) now enforces this instead of
	// relying on the count above being read correctly by every future
	// reader: it requires each delete below to affect EXACTLY the number of
	// rows this fixture created, in either direction, and refuses to commit
	// otherwise.
	// The repository binding and its sealed credential are tracked through
	// pointers filled in below, because SaveBinding mints both ids and this
	// list has to be registered before the first insert. Leaving them out is
	// how this fixture went on leaking one repository_bindings row and one
	// encrypted_secrets row per run after the cluster/incident half was
	// fixed (PROJECT.md B175) — dbtest can only check a table a fixture
	// actually names.
	var bindingID, credentialRef string
	fixture := dbtest.New(t)
	fixture.Created("clusters", 1)
	fixture.Created("incidents", 1)
	fixture.Created("repository_bindings", 1)
	fixture.Created("encrypted_secrets", 1)
	// repository_bindings and encrypted_secrets are tenant-scoped, not
	// cluster-scoped, so the residue check below cannot see them — they are
	// covered by the two Created/TableDelete pairs instead. Everything else
	// this fixture touches belongs to the throwaway cluster.
	fixture.OwnsCluster(tenantID, clusterID)
	fixture.Cleanup(pool, func(ctx context.Context, tx pgx.Tx) error {
		return data.SetRequestScope(ctx, tx, tenantID, []string{clusterID})
	}, []dbtest.TableDelete{
		{Table: "incidents", SQL: `DELETE FROM incidents WHERE cluster_id = $1`, Args: []any{clusterID}},
		{Table: "repository_bindings", SQL: `DELETE FROM repository_bindings WHERE id = $1`, Args: []any{&bindingID}},
		{Table: "encrypted_secrets", SQL: `DELETE FROM encrypted_secrets WHERE id = $1`, Args: []any{&credentialRef}},
		{Table: "clusters", SQL: `DELETE FROM clusters WHERE id = $1`, Args: []any{clusterID}},
	})
	if _, err := tx.Exec(ctx,
		`INSERT INTO clusters (id, tenant_id, display_name, state, shard_id, cluster_fingerprint)
		 VALUES ($1, $2, $3, 'Active', 'shard-test', $4)`,
		clusterID, tenantID, "f28-registry-test-"+clusterID, "fp-"+clusterID); err != nil {
		t.Fatalf("insert throwaway cluster: %v", err)
	}

	incidentID = domain.NewID(domain.PrefixIncident)
	now := time.Now()
	if _, err := tx.Exec(ctx,
		`INSERT INTO incidents (id, tenant_id, cluster_id, fingerprint, severity, state, first_seen, last_seen, occurrence_count)
		 VALUES ($1, $2, $3, $4, 'high', $5, $6, $6, 1)`,
		incidentID, tenantID, clusterID, "test-f28-"+incidentID, orchestrator.StateDetected, now); err != nil {
		t.Fatalf("insert test incident: %v", err)
	}

	repoURL = "https://github.com/f28-test/" + domain.NewID(domain.PrefixCluster)
	scmStore = scm.NewStore(f28TestKeeper(t))
	saved, err := scmStore.SaveBinding(ctx, tx, tenantID, scm.Binding{
		Provider: "github",
		URL:      repoURL,
	}, []byte("faketoken-not-a-real-credential-1234567890"))
	if err != nil {
		t.Fatalf("SaveBinding: %v", err)
	}
	// Fills the two ids the cleanup list above holds pointers to. repoURL is
	// freshly generated per run, so this is always an INSERT of exactly one
	// binding and one credential, never an upsert of somebody else's.
	bindingID, credentialRef = saved.ID, saved.CredentialRef

	ownership := map[string]any{
		"managed_by": "argocd",
		"repo": map[string]any{
			"repo_url":        repoURL,
			"path":            "charts/web",
			"revision":        "0123456789abcdef0123456789abcdef01234567",
			"revision_pinned": true,
		},
	}
	ownershipJSON, err := json.Marshal(ownership)
	if err != nil {
		t.Fatalf("marshal ownership: %v", err)
	}
	if _, err := tx.Exec(ctx, `UPDATE incidents SET ownership = $2 WHERE id = $1`, incidentID, ownershipJSON); err != nil {
		t.Fatalf("set incident ownership: %v", err)
	}

	return tx, incidentID, scmStore, repoURL
}

// TestCallRepoTool_ReadLogRegistryBridgesToTheCliBackend is the fix's own
// proof: begin a ReadLog the way analyze.go/autoanalyze.go do (via the
// registry), serve a real read_repo_file call through CallRepoTool (the
// cli backend's own call path — no Reader, no callback, nothing shared with
// analyze.go except the incident id and the registry), and confirm the
// SAME log — fetched back out however a caller likes — now shows that path
// as read. Then, as the negative half, confirm a DIFFERENT, never-read path
// is still refused by RefuseUnreadRepositoryProposals even after that call.
func TestCallRepoTool_ReadLogRegistryBridgesToTheCliBackend(t *testing.T) {
	pool := f28RegistryTestPool(t)
	tx, incidentID, scmStore, repoURL := f28RegistryFixture(t, pool)

	s := &Server{
		db:       &data.DB{Pool: pool},
		scmStore: scmStore,
		checkouts: repotools.NewCheckoutsForTest(t.TempDir(), func(_ context.Context, opts gitops.CloneOptions) error {
			if opts.RepoURL != repoURL {
				t.Fatalf("clone called for the wrong repo: got %s, want %s", opts.RepoURL, repoURL)
			}
			// scope.SourceDir is "charts/web" — the file must land under
			// that, exactly where a real sparse clone would put it, since
			// read_repo_file's own path resolution (gitops.ReadCheckoutFile)
			// joins dir+SourceDir+path.
			dir := opts.Dir + "/charts/web"
			if err := os.MkdirAll(dir, 0o755); err != nil {
				return err
			}
			return os.WriteFile(dir+"/values.yaml", []byte("memory: 64Mi\n"), 0o600)
		}),
		readLogs: repotools.NewReadLogRegistry(),
	}

	// Confirm the scope actually resolves before trusting anything below —
	// if it didn't, CallRepoTool would return ErrNoRepository and the rest
	// of this test would prove nothing.
	scope := IncidentRepoScope(context.Background(), tx, scmStore, incidentID)
	if !scope.Valid() {
		t.Fatalf("fixture did not produce a valid repository scope: %+v", scope)
	}
	// CallRepoTool opens its OWN transaction against the pool — it cannot
	// see this test's uncommitted tx. Commit the fixture so CallRepoTool's
	// own read of incidents.ownership/repository_bindings can see it, then
	// roll back everything at the end via a second cleanup transaction so
	// nothing outlives this test. (Mirrors the "committed fixture needs a
	// second, separately-scoped cleanup" shape analyze_detach_db_test.go
	// already uses for the identical reason.)
	if err := tx.Commit(context.Background()); err != nil {
		t.Fatalf("commit fixture: %v", err)
	}

	// This is what internal/api/analyze.go and internal/autoanalyze do at
	// the START of an investigation.
	readLog := s.readLogs.Begin(incidentID)
	defer s.readLogs.End(incidentID)

	// This is what a cli-backend investigation does MID-investigation: the
	// MCP server dispatches to CallRepoTool with nothing but the grant's
	// cluster/incident ids — no Reader, no closure, no shared call stack
	// with analyze.go at all.
	args, _ := json.Marshal(map[string]string{"path": "values.yaml"})
	if _, err := s.CallRepoTool(context.Background(), "", incidentID, repotools.ToolReadRepoFile, args); err != nil {
		t.Fatalf("CallRepoTool(read_repo_file): %v", err)
	}

	// The bridge: readLog (built by the "analyze.go" half above) must now
	// show values.yaml as read, even though CallRepoTool built its own,
	// separate *repotools.Reader to serve the call.
	if bad := readLog.Unread(scope.SourceDir, []string{"values.yaml"}); len(bad) != 0 {
		t.Fatalf("the registry did not bridge CallRepoTool's read into analyze.go's own ReadLog: Unread = %v", bad)
	}

	// Positive proof end to end: a plan proposing new content for the path
	// that WAS read (via the cli backend) must survive.
	got := RefuseUnreadRepositoryProposals(llm.Investigation{
		ProposedPlan: openPRPlan(remediation.ProposedFile{Path: scope.SourceDir + "/values.yaml", Content: "memory: 128Mi\n"}),
	}, scope.SourceDir, readLog)
	if got.ProposedPlan == nil {
		t.Error("a path read through CallRepoTool (the cli backend's own path) must count as read for RefuseUnreadRepositoryProposals")
	}

	// Negative proof: a DIFFERENT path, never read by anyone, must still be
	// refused — the registry closing the gap must not turn into a guard
	// that stops checking anything.
	got2 := RefuseUnreadRepositoryProposals(llm.Investigation{
		ProposedPlan: openPRPlan(remediation.ProposedFile{Path: scope.SourceDir + "/Chart.yaml", Content: "name: web\n"}),
	}, scope.SourceDir, readLog)
	if got2.ProposedPlan != nil {
		t.Error("a path never read by either backend must still be refused")
	}
}
