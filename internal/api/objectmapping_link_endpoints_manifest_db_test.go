package api

// BACKLOG.md F30's plain-manifest mode, exercised end to end against the
// real Postgres: resolveHelmReleaseTarget's mode dispatch, a full
// handleConfirmRepositoryLink round trip (the ObjectMapping it stores is a
// LabelSelector taken verbatim from the object's own reported labels — never
// operator-typed — per owner decision 2026-09-09), and a full
// handleDeclineRepositoryLink round trip against migration 000113's new
// object_gvk/object_namespace/object_name columns.

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jackc/pgx/v5"

	"argus/internal/data"
	"argus/internal/dbtest"
	"argus/internal/domain"
	"argus/internal/events"
	"argus/internal/gateway"
	"argus/internal/orchestrator"
	"argus/internal/scm"
	"argus/internal/secretbox"
)

// manifestLinkTestServer builds a Server with everything
// handleConfirmRepositoryLink/handleDeclineRepositoryLink touch: a real
// scm.Store (in-memory keeper — no real repository credential is ever
// decrypted by either handler) and a Gateway with no connected clusters, so
// handleConfirmRepositoryLink's best-effort "re-resolve ownership live" step
// (gatherOwnershipFacts) fails gracefully exactly the way it already does
// against a genuinely disconnected cluster — never a panic, matching that
// call's own "best-effort" doc comment.
func manifestLinkTestServer(t *testing.T) *Server {
	t.Helper()
	kek, err := secretbox.GenerateLocalKEK()
	if err != nil {
		t.Fatalf("GenerateLocalKEK: %v", err)
	}
	keeper, err := secretbox.NewLocalKeeper(kek)
	if err != nil {
		t.Fatalf("NewLocalKeeper: %v", err)
	}
	ca, err := gateway.NewEphemeralDevCA()
	if err != nil {
		t.Fatalf("NewEphemeralDevCA: %v", err)
	}
	return &Server{scmStore: scm.NewStore(keeper), gw: gateway.NewGateway(nil, ca, events.NewBus())}
}

// manifestLinkInsertIncident inserts a throwaway incident whose ownership
// and object_key columns carry exactly what a plain-manifest object's
// get_gitops_ownership answer looks like: managed_by "none" plus labels, and
// an object_key resolveHelmReleaseTarget's own ownershipQueryTarget call can
// actually parse ("<gvk>|<namespace>|<name>", repository_change.go's own
// wire convention).
func manifestLinkInsertIncident(t *testing.T, ctx context.Context, tx pgx.Tx, tenantID, clusterID, gvk, namespace, name string, labels map[string]string) string {
	t.Helper()
	incidentID := domain.NewID(domain.PrefixIncident)
	now := "now()"
	labelsJSON, err := json.Marshal(labels)
	if err != nil {
		t.Fatalf("marshal labels: %v", err)
	}
	ownership := []byte(`{"managed_by":"none","labels":` + string(labelsJSON) + `}`)
	objectKey := gvk + "|" + namespace + "|" + name
	if _, err := tx.Exec(ctx,
		`INSERT INTO incidents (id, tenant_id, cluster_id, fingerprint, severity, state, first_seen, last_seen, occurrence_count, ownership, object_key)
		 VALUES ($1, $2, $3, $4, 'high', $5, `+now+`, `+now+`, 1, $6, $7)`,
		incidentID, tenantID, clusterID, "test-f30-manifest-"+incidentID, orchestrator.StateDetected, ownership, objectKey); err != nil {
		t.Fatalf("insert test incident: %v", err)
	}
	return incidentID
}

func TestResolveHelmReleaseTarget_ManifestModeDispatch(t *testing.T) {
	pool := helmLinkTestPool(t)
	ctx, tx, tenantID := helmLinkTx(t, pool)
	clusterID := helmLinkInsertCluster(t, ctx, tx, tenantID)

	labels := map[string]string{"app": "nolimits", "team": "shop"}
	incidentID := manifestLinkInsertIncident(t, ctx, tx, tenantID, clusterID, "apps/v1/Deployment", "shop", "nolimits", labels)

	rc := &requestContext{Tx: tx, TenantID: tenantID}
	target, reason, err := resolveHelmReleaseTarget(ctx, rc, incidentID)
	if err != nil {
		t.Fatalf("resolveHelmReleaseTarget: %v", err)
	}
	if reason != "" {
		t.Fatalf("reason = %q, want none — a plain-manifest object with labels and no known repo must resolve", reason)
	}
	if target.mode != linkModeManifest {
		t.Fatalf("mode = %q, want %q", target.mode, linkModeManifest)
	}
	if target.releaseName != "" || target.releaseNamespace != "" {
		t.Fatalf("a manifest-mode target must carry no release identity, got releaseName=%q releaseNamespace=%q", target.releaseName, target.releaseNamespace)
	}
	if len(target.labels) != len(labels) || target.labels["app"] != "nolimits" || target.labels["team"] != "shop" {
		t.Fatalf("labels = %+v, want exactly %+v — never a subset or a guess", target.labels, labels)
	}
	if target.objectGVK != "apps/v1/Deployment" || target.objectNamespace != "shop" || target.objectName != "nolimits" {
		t.Fatalf("object identity = %s/%s/%s, want apps/v1/Deployment/shop/nolimits", target.objectGVK, target.objectNamespace, target.objectName)
	}
}

// TestResolveHelmReleaseTarget_PlainObjectWithNoLabelsIsNotApplicable proves
// F30's own "no fallback to matching by namespace+name alone" rule: a
// plain-manifest object with zero reported labels has no identity this
// feature can safely register a mapping against, so it must be refused, not
// silently offered with an empty selector (which scm.ObjectMapping.Validate
// would reject anyway, but the refusal belongs here, before any render is
// attempted).
func TestResolveHelmReleaseTarget_PlainObjectWithNoLabelsIsNotApplicable(t *testing.T) {
	pool := helmLinkTestPool(t)
	ctx, tx, tenantID := helmLinkTx(t, pool)
	clusterID := helmLinkInsertCluster(t, ctx, tx, tenantID)

	incidentID := manifestLinkInsertIncident(t, ctx, tx, tenantID, clusterID, "v1/ConfigMap", "shop", "bare", nil)

	rc := &requestContext{Tx: tx, TenantID: tenantID}
	_, reason, err := resolveHelmReleaseTarget(ctx, rc, incidentID)
	if err != nil {
		t.Fatalf("resolveHelmReleaseTarget: %v", err)
	}
	if reason != "not-applicable" {
		t.Fatalf("reason = %q, want not-applicable", reason)
	}
}

// TestHandleConfirmRepositoryLink_ManifestMode is the write-side proof: a
// plain-manifest object's confirmation stores a LabelSelector ObjectMapping
// built from EXACTLY the labels resolveHelmReleaseTarget read off the
// incident's own stored ownership — never typed by the test, matching what a
// human operator would do (click "Link", never type a selector).
func TestHandleConfirmRepositoryLink_ManifestMode(t *testing.T) {
	pool := helmLinkTestPool(t)
	ctx, tx, tenantID := helmLinkTx(t, pool)
	clusterID := helmLinkInsertCluster(t, ctx, tx, tenantID)

	labels := map[string]string{"app.kubernetes.io/name": "nolimits", "app.kubernetes.io/instance": "nolimits-prod"}
	incidentID := manifestLinkInsertIncident(t, ctx, tx, tenantID, clusterID, "apps/v1/Deployment", "shop", "nolimits", labels)

	s := manifestLinkTestServer(t)
	binding, err := s.scmStore.SaveBinding(ctx, tx, tenantID, scm.Binding{
		Provider: "github", URL: "https://github.com/example/f30-manifest-test",
	}, []byte("throwaway-test-token-not-real"))
	if err != nil {
		t.Fatalf("SaveBinding: %v", err)
	}

	body, _ := json.Marshal(confirmRepositoryLinkRequest{BindingID: binding.ID, Path: "apps/nolimits/deployment.yaml"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/incidents/"+incidentID+"/confirm-repository-link", bytes.NewReader(body))
	req.SetPathValue("id", incidentID)
	w := httptest.NewRecorder()
	rc := &requestContext{Tx: tx, TenantID: tenantID, UserID: "usr_test"}

	s.handleConfirmRepositoryLink(w, req, rc)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}

	// Read the binding back — not from the handler's own response, which
	// would only prove the handler agrees with itself — via the SAME
	// FindObjectMapping a later incident's routing actually calls, so this
	// proves the mapping is not just stored but MATCHABLE.
	matched, found, err := scm.FindObjectMapping(ctx, tx, clusterID, "", "", labels)
	if err != nil {
		t.Fatalf("FindObjectMapping: %v", err)
	}
	if !found {
		t.Fatal("confirmed manifest-mode mapping did not match its own object's labels back")
	}
	if matched.Mapping.Path != "apps/nolimits/deployment.yaml" {
		t.Errorf("Path = %q, want apps/nolimits/deployment.yaml", matched.Mapping.Path)
	}
	if matched.Mapping.ReleaseName != "" || matched.Mapping.Namespace != "" {
		t.Errorf("a manifest-mode mapping must carry no release identity, got ReleaseName=%q Namespace=%q", matched.Mapping.ReleaseName, matched.Mapping.Namespace)
	}
	if len(matched.Mapping.LabelSelector) != len(labels) {
		t.Errorf("LabelSelector = %+v, want exactly %+v", matched.Mapping.LabelSelector, labels)
	}
	if matched.Mapping.Scope.Type != "Cluster" || matched.Mapping.Scope.ClusterID != clusterID {
		t.Errorf("Scope = %+v, want the default Cluster scope for %s", matched.Mapping.Scope, clusterID)
	}

	// A DIFFERENT cluster must not see this Cluster-scoped mapping — the
	// same multi-cluster distinctness F30's owner correction requires for
	// the Helm case applies here too.
	otherCluster := helmLinkInsertCluster(t, ctx, tx, tenantID)
	_, foundOnOtherCluster, err := scm.FindObjectMapping(ctx, tx, otherCluster, "", "", labels)
	if err != nil {
		t.Fatalf("FindObjectMapping (other cluster): %v", err)
	}
	if foundOnOtherCluster {
		t.Fatal("a Cluster-scoped manifest mapping leaked onto a different cluster")
	}
}

// TestHandleDeclineRepositoryLink_ManifestMode proves a decline for a
// plain-manifest object is recorded on the SAME helm_link_declines table a
// Helm release's decline uses (migration 000113's object_gvk/
// object_namespace/object_name columns), is idempotent (declining twice
// must not error — an operator re-opening the same incident and declining
// again is a normal action, not a conflict), and does not silence a
// DIFFERENT object's identical labels on the same cluster.
func TestHandleDeclineRepositoryLink_ManifestMode(t *testing.T) {
	pool := helmLinkTestPool(t)
	ctx, tx, tenantID := helmLinkTx(t, pool)
	clusterID := helmLinkInsertCluster(t, ctx, tx, tenantID)

	incidentID := manifestLinkInsertIncident(t, ctx, tx, tenantID, clusterID, "apps/v1/Deployment", "shop", "nolimits", map[string]string{"app": "nolimits"})

	s := manifestLinkTestServer(t)
	rc := &requestContext{Tx: tx, TenantID: tenantID, UserID: "usr_test"}

	for i := 0; i < 2; i++ { // idempotent: declining twice must not error
		req := httptest.NewRequest(http.MethodPost, "/api/v1/incidents/"+incidentID+"/decline-repository-link", nil)
		req.SetPathValue("id", incidentID)
		w := httptest.NewRecorder()
		s.handleDeclineRepositoryLink(w, req, rc)
		if w.Code != http.StatusNoContent {
			t.Fatalf("attempt %d: status = %d, body = %s", i, w.Code, w.Body.String())
		}
	}

	declined, err := manifestLinkAlreadyDeclined(ctx, tx, clusterID, "apps/v1/Deployment", "shop", "nolimits")
	if err != nil {
		t.Fatalf("manifestLinkAlreadyDeclined: %v", err)
	}
	if !declined {
		t.Fatal("decline was not recorded")
	}

	// A different object's identical GVK+namespace must not read as
	// declined — this is an object-identity decline, not a namespace-wide
	// one.
	declined, err = manifestLinkAlreadyDeclined(ctx, tx, clusterID, "apps/v1/Deployment", "shop", "some-other-object")
	if err != nil {
		t.Fatalf("manifestLinkAlreadyDeclined (different object): %v", err)
	}
	if declined {
		t.Fatal("a decline for one object leaked onto a different object in the same namespace")
	}

	// The row itself carries the object identity, not a release identity —
	// the CHECK constraint migration 000113 added is what enforces this is
	// the only way it CAN be stored.
	var releaseName, namespace *string
	var objectGVK, objectNamespace, objectName *string
	if err := tx.QueryRow(ctx,
		`SELECT release_name, namespace, object_gvk, object_namespace, object_name FROM helm_link_declines WHERE cluster_id = $1 AND object_gvk = 'apps/v1/Deployment'`,
		clusterID).Scan(&releaseName, &namespace, &objectGVK, &objectNamespace, &objectName); err != nil {
		t.Fatalf("read decline row: %v", err)
	}
	if releaseName != nil || namespace != nil {
		t.Errorf("a manifest-mode decline must carry no release_name/namespace, got %v/%v", releaseName, namespace)
	}
	if objectGVK == nil || *objectGVK != "apps/v1/Deployment" || objectNamespace == nil || *objectNamespace != "shop" || objectName == nil || *objectName != "nolimits" {
		t.Errorf("object identity columns = %v/%v/%v, want apps/v1/Deployment/shop/nolimits", objectGVK, objectNamespace, objectName)
	}
}

// TestHelmLinkDeclines_ExactlyOneFormConstraint is a direct proof of
// migration 000113's CHECK constraint — the same "exactly one form, never
// both, never neither" discipline scm.ObjectMapping.Validate already
// enforces for a CONFIRMED link, now enforced by Postgres itself for a
// DECLINE too.
func TestHelmLinkDeclines_ExactlyOneFormConstraint(t *testing.T) {
	pool := helmLinkTestPool(t)
	ctx, setupTx, tenantID := helmLinkTx(t, pool)
	clusterID := helmLinkInsertCluster(t, ctx, setupTx, tenantID)
	// This is the ONE test in the helmLink* family that COMMITS its fixture
	// (every other one lives entirely inside helmLinkTx's rolled-back
	// transaction), so it is the one that needs real cleanup — and the hand
	// written cleanup it used to carry is exactly why PROJECT.md B175 existed.
	//
	// # What the previous version did, and what it cost
	//
	// It opened a bare transaction, ran `DELETE FROM clusters WHERE id = $1`
	// on it, and discarded every return value — the Begin error, the command
	// tag, and the Exec error. clusters has FORCE ROW LEVEL SECURITY and
	// argus_app cannot bypass it, so with app.tenant_id unset the predicate
	// evaluated `tenant_id = NULL` for every row, matched nothing, and
	// reported no error, because a DELETE that removes nothing is not one.
	// Every run of this test therefore committed one `f30-test-<id>` cluster
	// in state Active and left it there forever. It never heartbeats, so it
	// settles as Disconnected and is counted as a real, unreachable member of
	// the fleet: 51 of the development database's 415 clusters by
	// 2026-09-19, and enough of the disconnected ones to dominate the
	// partial-fleet banner that exists to make a genuine coverage gap
	// noticeable.
	//
	// dbtest.Fixture removes both halves of that failure by construction: it
	// takes the scope callback as a required argument rather than leaving it
	// to be remembered, and it refuses to commit a cleanup whose DELETE did
	// not affect exactly the number of rows this fixture created — so a
	// silently-zero delete fails the test instead of leaking.
	//
	// Registered BEFORE the commit but AFTER helmLinkTx's own rollback
	// cleanup, so t.Cleanup's LIFO order runs this first, while the pool is
	// still open.
	fixture := dbtest.New(t)
	fixture.Created("clusters", 1)
	fixture.Cleanup(pool, func(ctx context.Context, tx pgx.Tx) error {
		return data.SetRequestScope(ctx, tx, tenantID, nil)
	}, []dbtest.TableDelete{
		// helm_link_declines has ON DELETE CASCADE to clusters (migration
		// 000104), and every decline this test writes is rolled back with
		// its own transaction anyway, so the cluster row is the only thing
		// that can outlive the test.
		{Table: "clusters", SQL: `DELETE FROM clusters WHERE id = $1`, Args: []any{clusterID}},
	})
	if err := setupTx.Commit(ctx); err != nil {
		t.Fatalf("commit setup: %v", err)
	}

	// Each attempt gets its OWN transaction: Postgres aborts the whole
	// transaction on a constraint violation, so a "must be refused" case run
	// in the same transaction as a later "must be accepted" case would make
	// that second case fail for an unrelated reason.
	insert := func(releaseName, namespace, objectGVK, objectNamespace, objectName any) error {
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatalf("begin: %v", err)
		}
		defer tx.Rollback(ctx) //nolint:errcheck
		if err := data.SetRequestScope(ctx, tx, tenantID, nil); err != nil {
			t.Fatalf("scope: %v", err)
		}
		id := domain.NewID(domain.PrefixHelmLinkDecline)
		_, err = tx.Exec(ctx,
			`INSERT INTO helm_link_declines (id, tenant_id, cluster_id, release_name, namespace, object_gvk, object_namespace, object_name, declined_by)
			 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'test')`,
			id, tenantID, clusterID, releaseName, namespace, objectGVK, objectNamespace, objectName)
		return err
	}

	// Neither form: must be refused.
	if err := insert(nil, nil, nil, nil, nil); err == nil {
		t.Error("a decline with NEITHER a release nor an object identity was accepted")
	}
	// Both forms at once: must be refused — matches ObjectMapping.Validate's
	// own "never both" rule.
	if err := insert("shop-apps", "shop", "apps/v1/Deployment", "shop", "nolimits"); err == nil {
		t.Error("a decline with BOTH a release and an object identity was accepted")
	}
	// Exactly the release form: accepted.
	if err := insert("shop-apps", "shop", nil, nil, nil); err != nil {
		t.Errorf("a release-only decline was refused: %v", err)
	}
	// Exactly the object form: accepted.
	if err := insert(nil, nil, "apps/v1/Deployment", "shop", "nolimits"); err != nil {
		t.Errorf("an object-only decline was refused: %v", err)
	}
}
