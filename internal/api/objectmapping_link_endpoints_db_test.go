package api

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"argus/internal/data"
	"argus/internal/domain"
	"argus/internal/orchestrator"
)

// Gated on ARGUS_TEST_DATABASE_URL exactly like this package's other
// *_db_test.go files (repository_locate_identity_db_test.go's own doc
// comment explains why); a machine without one gets a clean skip.
func helmLinkTestPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	connString := os.Getenv("ARGUS_TEST_DATABASE_URL")
	if connString == "" {
		t.Skip("ARGUS_TEST_DATABASE_URL not set; skipping BACKLOG.md F30 DB-backed test")
	}
	pool, err := pgxpool.New(context.Background(), connString)
	if err != nil {
		t.Fatalf("connect to test database: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

// helmLinkTx opens one transaction scoped to the real (single) organisation
// — migration 000104's helm_link_declines.cluster_id has a real FK to
// clusters(id), so, like repository_locate_identity_db_test.go's own
// fixture, this needs the real tenant rather than a fabricated one. Rolled
// back at the end; nothing here needs cross-transaction durability.
func helmLinkTx(t *testing.T, pool *pgxpool.Pool) (context.Context, pgx.Tx, string) {
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
	if err := data.SetRequestScope(ctx, tx, tenantID, nil); err != nil {
		t.Fatalf("set request scope: %v", err)
	}
	return ctx, tx, tenantID
}

func helmLinkInsertCluster(t *testing.T, ctx context.Context, tx pgx.Tx, tenantID string) string {
	t.Helper()
	id := domain.NewID(domain.PrefixCluster)
	if _, err := tx.Exec(ctx,
		`INSERT INTO clusters (id, tenant_id, display_name, state, shard_id, cluster_fingerprint)
		 VALUES ($1, $2, $3, 'Active', 'shard-test', $1)`,
		id, tenantID, "f30-test-"+id); err != nil {
		t.Fatalf("insert throwaway cluster: %v", err)
	}
	return id
}

// helmLinkInsertHelmIncident inserts a throwaway incident whose ownership
// column carries exactly the wire shape resolveHelmReleaseTarget/
// otherClustersRunningRelease both read: managed_by "helm" plus an
// app_ref{name, namespace} — the same shape internal/agent/tools.go's
// ownershipFromMetadata produces and internal/api/routing.go's
// ownershipWire decodes.
func helmLinkInsertHelmIncident(t *testing.T, ctx context.Context, tx pgx.Tx, tenantID, clusterID, releaseName, releaseNamespace string) string {
	t.Helper()
	incidentID := domain.NewID(domain.PrefixIncident)
	now := time.Now()
	ownership := []byte(`{"managed_by":"helm","app_ref":{"kind":"Release","name":"` + releaseName + `","namespace":"` + releaseNamespace + `"}}`)
	if _, err := tx.Exec(ctx,
		`INSERT INTO incidents (id, tenant_id, cluster_id, fingerprint, severity, state, first_seen, last_seen, occurrence_count, ownership)
		 VALUES ($1, $2, $3, $4, 'high', $5, $6, $6, 1, $7)`,
		incidentID, tenantID, clusterID, "test-f30-"+incidentID, orchestrator.StateDetected, now, ownership); err != nil {
		t.Fatalf("insert test incident: %v", err)
	}
	return incidentID
}

func TestHelmLinkAlreadyDeclined(t *testing.T) {
	pool := helmLinkTestPool(t)
	ctx, tx, tenantID := helmLinkTx(t, pool)
	clusterID := helmLinkInsertCluster(t, ctx, tx, tenantID)

	declined, err := helmLinkAlreadyDeclined(ctx, tx, clusterID, "shop-apps", "shop")
	if err != nil {
		t.Fatalf("helmLinkAlreadyDeclined (before any decline): %v", err)
	}
	if declined {
		t.Fatal("reported declined before anything was ever declined")
	}

	id := domain.NewID(domain.PrefixHelmLinkDecline)
	if _, err := tx.Exec(ctx,
		`INSERT INTO helm_link_declines (id, tenant_id, cluster_id, release_name, namespace, declined_by) VALUES ($1,$2,$3,'shop-apps','shop','test')`,
		id, tenantID, clusterID); err != nil {
		t.Fatalf("insert decline: %v", err)
	}

	declined, err = helmLinkAlreadyDeclined(ctx, tx, clusterID, "shop-apps", "shop")
	if err != nil {
		t.Fatalf("helmLinkAlreadyDeclined (after decline): %v", err)
	}
	if !declined {
		t.Fatal("did not report declined after an explicit decline was recorded")
	}

	// A DIFFERENT release on the same cluster must not be silenced by this
	// decline — F30 decision 4 is "do not re-ask for the same release", not
	// "stop asking about anything on this cluster".
	declined, err = helmLinkAlreadyDeclined(ctx, tx, clusterID, "results", "shop")
	if err != nil {
		t.Fatalf("helmLinkAlreadyDeclined (different release): %v", err)
	}
	if declined {
		t.Fatal("a decline for shop-apps leaked onto a different release (results) on the same cluster")
	}
}

func TestOtherClustersRunningRelease(t *testing.T) {
	pool := helmLinkTestPool(t)
	ctx, tx, tenantID := helmLinkTx(t, pool)

	clusterA := helmLinkInsertCluster(t, ctx, tx, tenantID)
	clusterB := helmLinkInsertCluster(t, ctx, tx, tenantID)
	clusterC := helmLinkInsertCluster(t, ctx, tx, tenantID)

	helmLinkInsertHelmIncident(t, ctx, tx, tenantID, clusterA, "shop-apps", "shop")
	helmLinkInsertHelmIncident(t, ctx, tx, tenantID, clusterB, "shop-apps", "shop")
	// A different release on clusterC must not show up as "running shop-apps".
	helmLinkInsertHelmIncident(t, ctx, tx, tenantID, clusterC, "results", "shop")

	others, err := otherClustersRunningRelease(ctx, tx, clusterA, "shop-apps", "shop")
	if err != nil {
		t.Fatalf("otherClustersRunningRelease: %v", err)
	}
	if len(others) != 1 || others[0].ClusterID != clusterB {
		t.Fatalf("others = %+v, want exactly clusterB (%s) — the querying cluster (A) excluded, the different-release cluster (C) excluded", others, clusterB)
	}
}
