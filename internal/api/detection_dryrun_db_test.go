package api

import (
	"context"
	"testing"
	"time"

	"argus/internal/data"
	"argus/internal/domain"
)

// TestQueryDetectionDryRunFindings_DanglingIncidentIDDoesNotCrash guards a
// real bug found and fixed live 2026-08-30: a real findings row (found live:
// fnd_01m0gj9gbfar8tjh9vm8y7mr4r,
// incident_id inc_sweep_reopen1) whose incident_id names no resolvable
// incidents row 500'd this whole endpoint, because the LEFT JOIN's
// i.first_seen is NULL for that row and `f.incident_id IS NOT NULL AND
// f.occurred_at = i.first_seen` evaluates to SQL NULL under three-valued
// logic — which pgx cannot scan into detectionDryRunFindingRow's plain,
// non-pointer CreatedNewIncident bool. Nothing in this schema has a foreign
// key from findings.incident_id to incidents(id) (confirmed by inspecting
// the real constraint list), so this is a real, reachable shape — an
// incident becoming unreachable (deleted, or excluded by RLS scope) while a
// findings row still names it — not a hypothetical.
func TestQueryDetectionDryRunFindings_DanglingIncidentIDDoesNotCrash(t *testing.T) {
	pool := authTestPool(t)
	ctx := context.Background()

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	tenantID, err := data.SingleOrganisationID(ctx, tx)
	if err != nil {
		t.Fatalf("tenant: %v", err)
	}
	clusterID := domain.NewID(domain.PrefixCluster)
	if err := data.SetRequestScope(ctx, tx, tenantID, []string{clusterID}); err != nil {
		t.Fatalf("scope: %v", err)
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO clusters (id, tenant_id, display_name, state, shard_id, cluster_fingerprint)
		 VALUES ($1, $2, $3, 'Active', 'shard-test', $4)`,
		clusterID, tenantID, "dryrun-dangling-"+clusterID, "fp-"+clusterID); err != nil {
		t.Fatalf("insert throwaway cluster: %v", err)
	}

	occurredAt := time.Now().Add(-time.Hour)
	findingID := domain.NewID(domain.PrefixFinding)
	danglingIncidentID := "inc_test_dangling_" + findingID
	if _, err := tx.Exec(ctx, `
		INSERT INTO findings (id, tenant_id, cluster_id, detector_id, detector_version, fingerprint,
		                       gvk, occurred_at, ingested_at, severity, incident_id)
		VALUES ($1, $2, $3, 'k8s-warning-events', 'v1', 'fp-dangling', 'v1/Pod', $4, $4, 'medium', $5)`,
		findingID, tenantID, clusterID, occurredAt, danglingIncidentID); err != nil {
		t.Fatalf("insert dangling finding: %v", err)
	}

	rows, err := queryDetectionDryRunFindings(ctx, tx, occurredAt.Add(-time.Minute), occurredAt.Add(-time.Minute))
	if err != nil {
		t.Fatalf("queryDetectionDryRunFindings must not error on a dangling incident_id: %v", err)
	}

	var found *detectionDryRunFindingRow
	for i := range rows {
		if rows[i].ClusterID == clusterID {
			found = &rows[i]
			break
		}
	}
	if found == nil {
		t.Fatalf("expected the dangling-incident finding row back, got %d rows for other clusters only", len(rows))
	}
	if !found.HadIncident {
		t.Errorf("HadIncident = false, want true — incident_id was set even though it doesn't resolve")
	}
	if found.CreatedNewIncident {
		t.Errorf("CreatedNewIncident = true, want false — a finding whose incident_id doesn't resolve cannot have visibly created it")
	}
}
