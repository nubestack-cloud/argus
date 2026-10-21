package api

import (
	"context"
	"testing"
	"time"

	"argus/internal/data"
	"argus/internal/domain"
)

// TestRelatedWorkloadQueryTarget_ParsesTheStoredKey is BUGS.md 118's fix:
// gatherOwnershipFacts (routing.go) needs a real way to read
// incidents.related_workload_key back out and split it into the
// gvk/namespace/name tuple checkOrphanedPVC's own write
// (internal/gateway/finding.go's relatedWorkloadCorrelationKey) encodes it
// as — "<gvk>|<namespace>|<name>", the exact same convention
// pickOwnershipQueryTuple already uses for object_key/workload_key. Gated on
// ARGUS_TEST_DATABASE_URL exactly like this package's other *_db_test.go
// files (see evidence_db_test.go's own doc comment) — a machine without one
// gets a clean skip.
func TestRelatedWorkloadQueryTarget_ParsesTheStoredKey(t *testing.T) {
	pool := authTestPool(t)
	ctx := context.Background()

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin setup: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	tenantID, err := data.SingleOrganisationID(ctx, tx)
	if err != nil {
		t.Fatalf("resolve organisation: %v", err)
	}
	clusterID := domain.NewID(domain.PrefixCluster)
	if err := data.SetRequestScope(ctx, tx, tenantID, []string{clusterID}); err != nil {
		t.Fatalf("set request scope: %v", err)
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO clusters (id, tenant_id, display_name, state, shard_id, cluster_fingerprint)
		 VALUES ($1, $2, 'b118-cluster', 'Active', 'shard-test', $3)`,
		clusterID, tenantID, "fp-"+clusterID); err != nil {
		t.Fatalf("insert cluster: %v", err)
	}

	now := time.Now()
	withRelated := domain.NewID(domain.PrefixIncident)
	noRelated := domain.NewID(domain.PrefixIncident)
	malformedRelated := domain.NewID(domain.PrefixIncident)

	insert := func(id string, objectKey string, relatedKey *string) {
		if _, err := tx.Exec(ctx,
			`INSERT INTO incidents (id, tenant_id, cluster_id, fingerprint, severity, state, first_seen, last_seen, occurrence_count, opening_reason, object_key, related_workload_key)
			 VALUES ($1, $2, $3, $4, 'high', 'Detected', $5, $5, 1, 'PersistentVolumeClaimOrphaned', $6, $7)`,
			id, tenantID, clusterID, "b118fp-"+id, now, objectKey, relatedKey); err != nil {
			t.Fatalf("insert incident %s: %v", id, err)
		}
	}
	related := "apps/v1/StatefulSet|argus-b118-sts8|sts8-victim"
	malformed := "apps/v1/StatefulSet|argus-b118-sts8" // missing the name segment
	insert(withRelated, "v1/PersistentVolumeClaim|argus-b118-sts8|data-sts8-victim-2", &related)
	insert(noRelated, "v1/PersistentVolumeClaim|argus-b118-sts8|data-sts8-victim-2", nil)
	insert(malformedRelated, "v1/PersistentVolumeClaim|argus-b118-sts8|data-sts8-victim-2", &malformed)

	cases := []struct {
		name            string
		incidentID      string
		wantOK          bool
		wantGVK, wantNS string
		wantName        string
	}{
		{"populated related_workload_key parses into all three parts", withRelated, true, "apps/v1/StatefulSet", "argus-b118-sts8", "sts8-victim"},
		{"no related_workload_key at all", noRelated, false, "", "", ""},
		{"a related_workload_key missing its name segment does not parse", malformedRelated, false, "", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gvk, ns, name, ok := relatedWorkloadQueryTarget(ctx, tx, tc.incidentID)
			if ok != tc.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tc.wantOK)
			}
			if !ok {
				return
			}
			if gvk != tc.wantGVK || ns != tc.wantNS || name != tc.wantName {
				t.Errorf("got (%q, %q, %q), want (%q, %q, %q)", gvk, ns, name, tc.wantGVK, tc.wantNS, tc.wantName)
			}
		})
	}
}
