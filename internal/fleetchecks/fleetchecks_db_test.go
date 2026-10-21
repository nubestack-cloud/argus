package fleetchecks

// The store against a real Postgres, inside one transaction that is rolled
// back, so nothing touches the database's real rows.

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"argus/internal/data"
	"argus/internal/domain"
)

// A failed read must not erase the last good answer: the Overview says "as
// of <then>, the latest read failed" rather than losing the figure.
func TestUpsertKeepsTheLastGoodSummaryThroughAFailure(t *testing.T) {
	conn := os.Getenv("ARGUS_TEST_DATABASE_URL")
	if conn == "" {
		t.Skip("ARGUS_TEST_DATABASE_URL not set; skipping the DB-backed fleet check test")
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
	cl := domain.NewID(domain.PrefixCluster)
	if err := data.SetRequestScope(ctx, tx, tenantID, []string{cl}); err != nil {
		t.Fatalf("scope: %v", err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO clusters (id, tenant_id, display_name, state, shard_id, cluster_fingerprint)
		VALUES ($1, $2, $3, 'Active', 'shard-test', $4)`, cl, tenantID, "fleet-check-test-"+cl, "fp-"+cl); err != nil {
		t.Fatalf("insert cluster: %v", err)
	}

	if err := upsert(ctx, tx, tenantID, cl, CheckHelm, HelmSummary{Total: 4, Listed: 4, Failing: 1}, nil); err != nil {
		t.Fatalf("upsert ok: %v", err)
	}
	if err := upsert(ctx, tx, tenantID, cl, CheckHelm, nil, errors.New("agent did not answer")); err != nil {
		t.Fatalf("upsert failure: %v", err)
	}
	all, err := ReadAll(ctx, tx)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	snap := all[cl][CheckHelm]
	var h HelmSummary
	if err := json.Unmarshal(snap.Summary, &h); err != nil || h.Failing != 1 || snap.SummaryAt == nil {
		t.Fatalf("summary lost: %+v (%v)", snap, err)
	}
	if snap.Error == nil || *snap.Error != "agent did not answer" || snap.ErrorAt == nil {
		t.Fatalf("failure not recorded: %+v", snap)
	}

	// A later success clears the failure.
	if err := upsert(ctx, tx, tenantID, cl, CheckHelm, HelmSummary{Total: 4, Listed: 4}, nil); err != nil {
		t.Fatalf("upsert ok again: %v", err)
	}
	all, _ = ReadAll(ctx, tx)
	if s := all[cl][CheckHelm]; s.Error != nil || s.ErrorAt != nil {
		t.Fatalf("failure not cleared: %+v", s)
	}
}

// A cluster is due until all four of its checks have been attempted inside
// the window — a failed attempt counts as attempted, so a broken agent is
// retried once an interval rather than every tick.
func TestDueIDsWantsAllFourChecksFresh(t *testing.T) {
	conn := os.Getenv("ARGUS_TEST_DATABASE_URL")
	if conn == "" {
		t.Skip("ARGUS_TEST_DATABASE_URL not set; skipping the DB-backed fleet check test")
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
	fresh, partial, failing, never := domain.NewID(domain.PrefixCluster), domain.NewID(domain.PrefixCluster), domain.NewID(domain.PrefixCluster), domain.NewID(domain.PrefixCluster)
	ids := []string{fresh, partial, failing, never}
	if err := data.SetRequestScope(ctx, tx, tenantID, ids); err != nil {
		t.Fatalf("scope: %v", err)
	}
	for _, id := range ids {
		if _, err := tx.Exec(ctx, `INSERT INTO clusters (id, tenant_id, display_name, state, shard_id, cluster_fingerprint)
			VALUES ($1, $2, $3, 'Active', 'shard-test', $4)`, id, tenantID, "fleet-due-test-"+id, "fp-"+id); err != nil {
			t.Fatalf("insert cluster: %v", err)
		}
	}
	for _, ct := range checkTools {
		_ = upsert(ctx, tx, tenantID, fresh, ct.check, map[string]int{}, nil)
		_ = upsert(ctx, tx, tenantID, failing, ct.check, nil, errors.New("down"))
	}
	_ = upsert(ctx, tx, tenantID, partial, CheckHelm, map[string]int{}, nil)

	due, err := dueIDs(ctx, tx, time.Hour)
	if err != nil {
		t.Fatalf("dueIDs: %v", err)
	}
	got := map[string]bool{}
	for _, id := range due {
		got[id] = true
	}
	if got[fresh] || got[failing] || !got[partial] || !got[never] {
		t.Fatalf("due = %v; want partial and never, not fresh or the freshly failed one", due)
	}
}
