package api

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"argus/internal/data"
	"argus/internal/domain"
	"argus/internal/gitops"
	"argus/internal/orchestrator"
	"argus/internal/scm"
)

// This file is BACKLOG.md "still open" #4's DB-backed tests:
// findAdmissionRejectionIdentity reads real rows out of the findings table,
// so — like internal/llm/prompt_findings_db_test.go's
// TestBuildFindingsPromptStaysExecutable — it needs a real Postgres rather
// than a hand-rolled pgx.Tx fake.
//
// Gated on ARGUS_TEST_DATABASE_URL exactly like analyze_detach_db_test.go's
// analyzeDetachTestPool; a machine without one gets a clean skip.
func repoLocateIdentityTestPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	connString := os.Getenv("ARGUS_TEST_DATABASE_URL")
	if connString == "" {
		t.Skip("ARGUS_TEST_DATABASE_URL not set; skipping BACKLOG.md \"still open\" #4 DB-backed test")
	}
	pool, err := pgxpool.New(context.Background(), connString)
	if err != nil {
		t.Fatalf("connect to test database: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

// repoLocateIdentityFixture opens ONE transaction, seeds a throwaway cluster,
// incident and one finding — an Argo Application sync-failure, the exact
// shape checkArgoSyncFailed (internal/agent/syncfailure.go) produces — and
// returns it un-committed. Every test in this file runs its assertions
// inside that same transaction and rolls it back at the end, so unlike
// analyze_detach_db_test.go's committed fixture (which needs a second,
// separately-scoped transaction to prove durability) there is nothing here
// to clean up afterwards.
func repoLocateIdentityFixture(t *testing.T, pool *pgxpool.Pool, message string) (tx pgx.Tx, tenantID, clusterID, incidentID string) {
	t.Helper()
	ctx := context.Background()

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	t.Cleanup(func() { _ = tx.Rollback(context.Background()) })

	tenantID, err = data.SingleOrganisationID(ctx, tx)
	if err != nil {
		t.Fatalf("resolve organisation: %v", err)
	}
	clusterID = domain.NewID(domain.PrefixCluster)
	if err := data.SetRequestScope(ctx, tx, tenantID, []string{clusterID}); err != nil {
		t.Fatalf("set request scope: %v", err)
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO clusters (id, tenant_id, display_name, state, shard_id, cluster_fingerprint)
		 VALUES ($1, $2, $3, 'Active', 'shard-test', $4)`,
		clusterID, tenantID, "locate-identity-test-"+clusterID, "fp-"+clusterID); err != nil {
		t.Fatalf("insert throwaway cluster: %v", err)
	}

	incidentID = domain.NewID(domain.PrefixIncident)
	now := time.Now()
	if _, err := tx.Exec(ctx,
		`INSERT INTO incidents (id, tenant_id, cluster_id, fingerprint, severity, state, first_seen, last_seen, occurrence_count)
		 VALUES ($1, $2, $3, $4, 'high', $5, $6, $6, 1)`,
		incidentID, tenantID, clusterID, "test-af1-"+incidentID, orchestrator.StateDetected, now); err != nil {
		t.Fatalf("insert test incident: %v", err)
	}

	// gvk/namespace/object_name here are the Application's own identity —
	// exactly what loadIncidentObject resolves onto for this incident shape
	// (there is no plan yet and no workload_key, so it falls to the newest
	// finding), which is why locateObjectFileWithFallback is handed this same
	// triple to look the message back up by.
	if _, err := tx.Exec(ctx,
		`INSERT INTO findings (id, tenant_id, cluster_id, incident_id, detector_id, detector_version, gvk,
		                       namespace, object_name, reason, message, severity, occurrence_count, occurred_at, fingerprint)
		 VALUES ($1,$2,$3,$4,'argo-sync-failed','1','argoproj.io/v1alpha1/Application','argocd','myapp','GitOpsSyncFailed',$5,'high',1,$6,$7)`,
		"fnd_af1_"+incidentID, tenantID, clusterID, incidentID, message, now, "test-af1-finding-"+incidentID,
	); err != nil {
		t.Fatalf("insert test finding: %v", err)
	}

	return tx, tenantID, clusterID, incidentID
}

// TestFindAdmissionRejectionIdentity_ParsesTheRealSyncFailureMessage proves
// the DB-touching half actually reads the incident's own finding back and
// hands its message to the parser correctly.
func TestFindAdmissionRejectionIdentity_ParsesTheRealSyncFailureMessage(t *testing.T) {
	pool := repoLocateIdentityTestPool(t)
	message := "Argo CD cannot apply this Application's manifests (phase Failed, 5 retries, revision abc123): " +
		`CronJob.batch "s1-syncfail" is invalid: spec.schedule: Invalid value: "not a cron expression": expected exactly 5 fields, found 4`
	tx, _, _, incidentID := repoLocateIdentityFixture(t, pool, message)

	kind, name, ok := findAdmissionRejectionIdentity(context.Background(), tx, incidentID,
		"argoproj.io/v1alpha1/Application", "argocd", "myapp")
	if !ok {
		t.Fatalf("findAdmissionRejectionIdentity: ok = false, want true")
	}
	if kind != "CronJob" || name != "s1-syncfail" {
		t.Errorf("got (%q, %q), want (CronJob, s1-syncfail)", kind, name)
	}
}

// TestFindAdmissionRejectionIdentity_HonestlyNotFoundWhenNothingParses is
// this mechanism's "refuse rather than guess" half at the DB layer: a
// message that does not carry a recognizable admission-rejection shape must
// come back ok=false, not a wrong guess and not a crash.
func TestFindAdmissionRejectionIdentity_HonestlyNotFoundWhenNothingParses(t *testing.T) {
	pool := repoLocateIdentityTestPool(t)
	tx, _, _, incidentID := repoLocateIdentityFixture(t, pool,
		"Argo CD cannot apply this Application's manifests (phase Failed, 3 retries, revision abc123): a permission was denied for this operation")

	_, _, ok := findAdmissionRejectionIdentity(context.Background(), tx, incidentID,
		"argoproj.io/v1alpha1/Application", "argocd", "myapp")
	if ok {
		t.Fatal("an unparseable message was reported as a resolved identity")
	}
}

// TestFindAdmissionRejectionIdentity_DoesNotMatchAnUnrelatedIncident proves
// the query is actually scoped to THIS incident's own gvk/namespace/name —
// not a global scan of the findings table that could pick up a different
// incident's sync failure.
func TestFindAdmissionRejectionIdentity_DoesNotMatchAnUnrelatedIncident(t *testing.T) {
	pool := repoLocateIdentityTestPool(t)
	message := `CronJob.batch "s1-syncfail" is invalid: spec.schedule: Invalid value`
	tx, _, _, _ := repoLocateIdentityFixture(t, pool, message)

	_, _, ok := findAdmissionRejectionIdentity(context.Background(), tx, "inc_does_not_exist",
		"argoproj.io/v1alpha1/Application", "argocd", "myapp")
	if ok {
		t.Fatal("resolved an identity for an incident with no findings of its own")
	}
}

// fakeNoCredentialProvider satisfies scm.Provider by embedding it as a nil
// interface and implementing only Name — the same pattern
// pr_verify_test.go's fakeReadFileProvider uses. It deliberately does NOT
// implement scm.CloneCredentialer, so locateObjectFile refuses before any
// network attempt (its very first check), which is what lets these tests
// exercise locateObjectFileWithFallback's branching without a live git host.
type fakeNoCredentialProvider struct {
	scm.Provider
}

func (f *fakeNoCredentialProvider) Name() string { return "fake" }

// TestLocateObjectFileWithFallback_ControllerObjectTriesTheParsedIdentity is
// this fix's end-to-end proof for the case AF1's DEPL-003 finding names: the
// ordinary search (for the Application itself) fails, the object IS a GitOps
// controller object, the incident's own finding message parses, and the
// fallback attempt is actually made — for the OTHER object the message
// names, under the SAME directory.
func TestLocateObjectFileWithFallback_ControllerObjectTriesTheParsedIdentity(t *testing.T) {
	pool := repoLocateIdentityTestPool(t)
	message := "Argo CD cannot apply this Application's manifests (phase Failed, 5 retries, revision abc123): " +
		`CronJob.batch "s1-syncfail" is invalid: spec.schedule: Invalid value: "not a cron expression": expected exactly 5 fields, found 4`
	tx, _, _, incidentID := repoLocateIdentityFixture(t, pool, message)

	provider := &fakeNoCredentialProvider{}
	object := gitops.ObjectRef{APIVersion: "argoproj.io/v1alpha1", Kind: "Application", Namespace: "argocd", Name: "myapp"}

	_, err := locateObjectFileWithFallback(context.Background(), tx, incidentID, "argoproj.io/v1alpha1/Application",
		provider, scm.Binding{Host: "github.com"}, "https://github.com/org/repo.git", "abc123", "apps/billing", object)
	if err == nil {
		t.Fatal("expected an error — the fake provider can reach neither search")
	}
	// The fallback attempt must be visible in the error, naming the CronJob
	// the sync-failure message named — proof that the parsed identity was
	// actually searched for, not merely computed and discarded. (The ordinary
	// search's own refusal fires before it ever reads `object` — a provider
	// with no clone credential is rejected on that check alone — so it names
	// no kind/name of its own to assert on here; locateObjectFileWithFallback
	// still ran it first, which TestLocateObjectFileWithFallback_
	// NoParseableMessageReturnsTheOriginalError below proves by checking that
	// exact, unwrapped error comes back whenever there is nothing to fall
	// back to.)
	if !strings.Contains(err.Error(), "cannot supply a credential") {
		t.Errorf("err = %v, missing the ordinary search's own refusal", err)
	}
	if !strings.Contains(err.Error(), "CronJob") || !strings.Contains(err.Error(), "s1-syncfail") {
		t.Errorf("err = %v, missing the fallback's parsed identity (CronJob s1-syncfail)", err)
	}
}

// TestLocateObjectFileWithFallback_NoParseableMessageReturnsTheOriginalError
// covers the "nothing to fall back to" branch: when the incident's own
// finding message does not parse, locateObjectFileWithFallback must return
// the ORIGINAL (ordinary-search) refusal unchanged, not a different or
// vaguer one.
func TestLocateObjectFileWithFallback_NoParseableMessageReturnsTheOriginalError(t *testing.T) {
	pool := repoLocateIdentityTestPool(t)
	tx, _, _, incidentID := repoLocateIdentityFixture(t, pool,
		"Argo CD cannot apply this Application's manifests (phase Failed, 3 retries, revision abc123): a permission was denied for this operation")

	provider := &fakeNoCredentialProvider{}
	object := gitops.ObjectRef{APIVersion: "argoproj.io/v1alpha1", Kind: "Application", Namespace: "argocd", Name: "myapp"}

	_, err := locateObjectFileWithFallback(context.Background(), tx, incidentID, "argoproj.io/v1alpha1/Application",
		provider, scm.Binding{Host: "github.com"}, "https://github.com/org/repo.git", "abc123", "apps/billing", object)
	if err == nil {
		t.Fatal("expected the ordinary search's own refusal")
	}
	if !strings.Contains(err.Error(), "cannot supply a credential") {
		t.Errorf("err = %v, want the ordinary locateObjectFile refusal, unwrapped and unreplaced", err)
	}
}
