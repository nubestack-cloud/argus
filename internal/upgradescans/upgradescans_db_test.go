package upgradescans

// LatestPerCluster against a real Postgres. Everything is written inside one
// transaction that is rolled back, so nothing touches the database's real
// rows and there is nothing to clean up.
//
//	export ARGUS_TEST_DATABASE_URL="postgres://argus_app:dev-local-password@localhost:5432/argus?sslmode=disable"

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"argus/internal/data"
	"argus/internal/domain"
)

// The live defect: a one-off scan for 1.99 became the cluster's "next
// upgrade" verdict in the Clusters list and on the Overview, because the
// fleet read the newest scan of ANY target. It must read the newest scan
// whose target is the minor right after the scanned version.
func TestLatestPerClusterReadsOnlyNextMinorScans(t *testing.T) {
	conn := os.Getenv("ARGUS_TEST_DATABASE_URL")
	if conn == "" {
		t.Skip("ARGUS_TEST_DATABASE_URL not set; skipping the DB-backed upgrade-scan test")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, conn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer pool.Close()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	tenantID, err := data.SingleOrganisationID(ctx, tx)
	if err != nil {
		t.Fatalf("organisation: %v", err)
	}
	withNext := domain.NewID(domain.PrefixCluster)
	onlyOneOff := domain.NewID(domain.PrefixCluster)
	if err := data.SetRequestScope(ctx, tx, tenantID, []string{withNext, onlyOneOff}); err != nil {
		t.Fatalf("scope: %v", err)
	}
	for _, id := range []string{withNext, onlyOneOff} {
		if _, err := tx.Exec(ctx, `INSERT INTO clusters (id, tenant_id, display_name, state, shard_id, cluster_fingerprint)
			VALUES ($1, $2, $3, 'Active', 'shard-test', $4)`, id, tenantID, "upgrade-scan-test-"+id, "fp-"+id); err != nil {
			t.Fatalf("insert cluster: %v", err)
		}
	}
	base := time.Date(2026, 10, 11, 9, 0, 0, 0, time.UTC)
	insert := func(clusterID, current, target, verdict string, at time.Time) string {
		id := domain.NewID(domain.PrefixUpgradeScan)
		if _, err := tx.Exec(ctx, `INSERT INTO upgrade_scans (id, tenant_id, cluster_id, current_version, target_version, verdict, reviewed_through, result, scanned_at)
			VALUES ($1, $2, $3, $4, $5, $6, '1.37', '{}', $7)`, id, tenantID, clusterID, current, target, verdict, at); err != nil {
			t.Fatalf("insert scan: %v", err)
		}
		return id
	}
	insert(withNext, "1.33", "1.34", "blocked", base)
	want := insert(withNext, "1.33", "1.34", "review", base.Add(time.Hour))
	insert(withNext, "1.33", "1.99", "unknown", base.Add(2*time.Hour))  // the one-off, newest
	insert(withNext, "1.33", "1.36", "warning", base.Add(3*time.Hour))  // a multi-minor one-off
	insert(withNext, "bogus", "1.34", "warning", base.Add(4*time.Hour)) // malformed: not a next-minor scan
	insert(onlyOneOff, "1.33", "1.99", "unknown", base)

	scans, err := LatestPerCluster(ctx, tx)
	if err != nil {
		t.Fatalf("LatestPerCluster: %v", err)
	}
	got := map[string]Scan{}
	for _, s := range scans {
		got[s.ClusterID] = s
	}
	if s, ok := got[withNext]; !ok || s.ID != want || s.TargetVersion != "1.34" || s.Verdict != "review" {
		t.Fatalf("withNext: got %+v, want the newest 1.33→1.34 scan %s", s, want)
	}
	if s, ok := got[onlyOneOff]; ok {
		t.Fatalf("a cluster with only a one-off scan must have no next-upgrade verdict, got %+v", s)
	}
}
