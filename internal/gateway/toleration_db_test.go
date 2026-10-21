package gateway

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"argus/internal/data"
	"argus/internal/domain"
)

func insertToleration(t *testing.T, ctx context.Context, tx pgx.Tx, tenantID, clusterID, objectKey string, reasons []string, expiresAt *time.Time) string {
	t.Helper()
	id := domain.NewID(domain.PrefixToleration)
	var reasonsArg any
	if reasons != nil {
		reasonsArg = reasons
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO incident_tolerations (id, tenant_id, cluster_id, object_key, reasons, note, created_by, expires_at)
		 VALUES ($1, $2, $3, $4, $5, 'test toleration', 'usr_test', $6)`,
		id, tenantID, clusterID, objectKey, reasonsArg, expiresAt); err != nil {
		t.Fatalf("insert toleration: %v", err)
	}
	return id
}

func TestFindingToleratedMatchesSpecificReason(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()

	clusterID := domain.NewID(domain.PrefixCluster)

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	tenantID, err := data.SingleOrganisationID(ctx, tx)
	if err != nil {
		t.Fatalf("resolve organisation: %v", err)
	}
	if err := data.SetRequestScope(ctx, tx, tenantID, []string{clusterID}); err != nil {
		t.Fatalf("set request scope: %v", err)
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO clusters (id, tenant_id, display_name, state, shard_id, cluster_fingerprint)
		 VALUES ($1, $2, $3, 'Active', 'shard-test', $4)`,
		clusterID, tenantID, "toleration-test-"+clusterID, "fp-"+clusterID); err != nil {
		t.Fatalf("insert throwaway cluster: %v", err)
	}

	objectKey := "v1/Service|cattle-monitoring-system|rancher-monitoring-windows-exporter"
	insertToleration(t, ctx, tx, tenantID, clusterID, objectKey, []string{"ServiceNoEndpoints"}, nil)

	got, err := FindingTolerated(ctx, tx, clusterID, objectKey, "ServiceNoEndpoints")
	if err != nil {
		t.Fatalf("FindingTolerated (matching reason): %v", err)
	}
	if got == "" {
		t.Errorf("FindingTolerated returned no match for the exact tolerated reason")
	}

	got, err = FindingTolerated(ctx, tx, clusterID, objectKey, "OOMKilled")
	if err != nil {
		t.Fatalf("FindingTolerated (different reason): %v", err)
	}
	if got != "" {
		t.Errorf("FindingTolerated matched a reason (%q) the rule never listed — a reason-scoped toleration must not silence unrelated future problems on the same object", "OOMKilled")
	}

	got, err = FindingTolerated(ctx, tx, clusterID, "v1/Service|other-ns|other-svc", "ServiceNoEndpoints")
	if err != nil {
		t.Fatalf("FindingTolerated (different object): %v", err)
	}
	if got != "" {
		t.Errorf("FindingTolerated matched an object it was never scoped to")
	}
}

func TestFindingToleratedWildcardMatchesAnyReason(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()

	clusterID := domain.NewID(domain.PrefixCluster)

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	tenantID, err := data.SingleOrganisationID(ctx, tx)
	if err != nil {
		t.Fatalf("resolve organisation: %v", err)
	}
	if err := data.SetRequestScope(ctx, tx, tenantID, []string{clusterID}); err != nil {
		t.Fatalf("set request scope: %v", err)
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO clusters (id, tenant_id, display_name, state, shard_id, cluster_fingerprint)
		 VALUES ($1, $2, $3, 'Active', 'shard-test', $4)`,
		clusterID, tenantID, "toleration-test-"+clusterID, "fp-"+clusterID); err != nil {
		t.Fatalf("insert throwaway cluster: %v", err)
	}

	objectKey := "apps/v1/Deployment|dev|known-broken-app"
	insertToleration(t, ctx, tx, tenantID, clusterID, objectKey, nil, nil)

	for _, reason := range []string{"CrashLoopBackOff", "OOMKilled", "AnythingAtAll"} {
		got, err := FindingTolerated(ctx, tx, clusterID, objectKey, reason)
		if err != nil {
			t.Fatalf("FindingTolerated(%q): %v", reason, err)
		}
		if got == "" {
			t.Errorf("wildcard toleration (nil reasons) did not match reason %q", reason)
		}
	}
}

func TestFindingToleratedIgnoresExpiredRule(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()

	clusterID := domain.NewID(domain.PrefixCluster)

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	tenantID, err := data.SingleOrganisationID(ctx, tx)
	if err != nil {
		t.Fatalf("resolve organisation: %v", err)
	}
	if err := data.SetRequestScope(ctx, tx, tenantID, []string{clusterID}); err != nil {
		t.Fatalf("set request scope: %v", err)
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO clusters (id, tenant_id, display_name, state, shard_id, cluster_fingerprint)
		 VALUES ($1, $2, $3, 'Active', 'shard-test', $4)`,
		clusterID, tenantID, "toleration-test-"+clusterID, "fp-"+clusterID); err != nil {
		t.Fatalf("insert throwaway cluster: %v", err)
	}

	objectKey := "v1/Pod|dev|maintenance-window-pod"
	expired := time.Now().Add(-time.Hour)
	insertToleration(t, ctx, tx, tenantID, clusterID, objectKey, nil, &expired)

	got, err := FindingTolerated(ctx, tx, clusterID, objectKey, "AnyReason")
	if err != nil {
		t.Fatalf("FindingTolerated: %v", err)
	}
	if got != "" {
		t.Errorf("FindingTolerated matched a rule whose expires_at (%s) is in the past — an expired toleration must stop suppressing", expired)
	}
}

func TestFindingToleratedIgnoresRemovedRule(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()

	clusterID := domain.NewID(domain.PrefixCluster)

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	tenantID, err := data.SingleOrganisationID(ctx, tx)
	if err != nil {
		t.Fatalf("resolve organisation: %v", err)
	}
	if err := data.SetRequestScope(ctx, tx, tenantID, []string{clusterID}); err != nil {
		t.Fatalf("set request scope: %v", err)
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO clusters (id, tenant_id, display_name, state, shard_id, cluster_fingerprint)
		 VALUES ($1, $2, $3, 'Active', 'shard-test', $4)`,
		clusterID, tenantID, "toleration-test-"+clusterID, "fp-"+clusterID); err != nil {
		t.Fatalf("insert throwaway cluster: %v", err)
	}

	objectKey := "v1/Pod|dev|removed-rule-pod"
	id := insertToleration(t, ctx, tx, tenantID, clusterID, objectKey, nil, nil)
	if _, err := tx.Exec(ctx, `UPDATE incident_tolerations SET removed_at = now(), removed_by = 'usr_test' WHERE id = $1`, id); err != nil {
		t.Fatalf("soft-delete toleration: %v", err)
	}

	got, err := FindingTolerated(ctx, tx, clusterID, objectKey, "AnyReason")
	if err != nil {
		t.Fatalf("FindingTolerated: %v", err)
	}
	if got != "" {
		t.Errorf("FindingTolerated matched a removed (soft-deleted) rule")
	}
}
