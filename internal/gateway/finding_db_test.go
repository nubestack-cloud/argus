package gateway

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"argus/internal/data"
	"argus/internal/domain"
)

// The storm-protection bug this file guards is not visible in pure Go: the
// broken part was a SQL predicate (`first_seen >= $2`) comparing a
// hub-computed window start against an AGENT-stamped column, and the only
// honest way to show the fix is to put rows in a real table whose id clock
// and first_seen clock deliberately disagree, then run the actual query.
// Same ARGUS_TEST_DATABASE_URL gating and same rationale as
// internal/orchestrator/db_test.go and internal/authz/session_test.go — a
// machine with no test database gets a clean skip.
func testPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	connString := os.Getenv("ARGUS_TEST_DATABASE_URL")
	if connString == "" {
		t.Skip("ARGUS_TEST_DATABASE_URL not set; skipping DB-backed storm-protection test (see this file's doc comment)")
	}
	pool, err := pgxpool.New(context.Background(), connString)
	if err != nil {
		t.Fatalf("connect to test database: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

// TestCountIncidentsCreatedSinceIgnoresAgentSuppliedTimestamps is the
// regression test for storm protection never firing.
//
// The three incidents below are the two clock-skew cases that mattered, plus
// a control:
//
//   - backfilled: created by this hub JUST NOW (its id is minted now, as
//     handleFinding does) but carrying a first_seen 30 days in the past —
//     exactly what an agent whose clock trails the hub, or one draining a
//     queue after a reconnect, produces. This is a brand-new incident and
//     MUST count towards the ceiling. The old `first_seen >= windowStart`
//     predicate excluded it, which is why the count stayed 0 and the
//     configured ceiling never engaged.
//   - alsoBackfilled: a second one of the same, so the count is a number
//     rather than a boolean.
//   - stale: created an HOUR ago (its id carries that hub timestamp) but
//     carrying a first_seen of now — an agent whose clock runs ahead. This
//     is NOT a new incident and must NOT count; the old predicate counted
//     it.
//
// So the correct answer is 2 and the old predicate's answer is 1 — and this
// test asserts both, so it fails loudly if the fix is reverted rather than
// silently agreeing by coincidence.
func TestCountIncidentsCreatedSinceIgnoresAgentSuppliedTimestamps(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()

	clusterID := domain.NewID(domain.PrefixCluster)
	now := time.Now()

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	// Never committed: everything this test writes disappears with the
	// rollback, so it leaves no incidents behind on a live dev database.
	defer tx.Rollback(ctx) //nolint:errcheck

	tenantID, err := data.SingleOrganisationID(ctx, tx)
	if err != nil {
		t.Fatalf("resolve organisation: %v", err)
	}
	// The same narrow, single-cluster scope handleFinding itself sets.
	if err := data.SetRequestScope(ctx, tx, tenantID, []string{clusterID}); err != nil {
		t.Fatalf("set request scope: %v", err)
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO clusters (id, tenant_id, display_name, state, shard_id, cluster_fingerprint)
		 VALUES ($1, $2, $3, 'Active', 'shard-test', $4)`,
		clusterID, tenantID, "storm-test-"+clusterID, "fp-"+clusterID); err != nil {
		t.Fatalf("insert throwaway cluster: %v", err)
	}

	insert := func(incidentID string, firstSeen time.Time) {
		if _, err := tx.Exec(ctx,
			`INSERT INTO incidents (id, tenant_id, cluster_id, fingerprint, severity, state, first_seen, last_seen, occurrence_count)
			 VALUES ($1, $2, $3, $4, 'high', 'Detected', $5, $5, 1)`,
			incidentID, tenantID, clusterID, "fp-"+incidentID, firstSeen); err != nil {
			t.Fatalf("insert incident %s: %v", incidentID, err)
		}
	}

	// Minted now, stamped 30 days ago by the agent.
	insert(domain.NewID(domain.PrefixIncident), now.Add(-30*24*time.Hour))
	insert(domain.NewID(domain.PrefixIncident), now.Add(-30*24*time.Hour))
	// Minted an hour ago, stamped now by the agent.
	// StormProtectionWindowStartIncidentID doubles as a convenient way to
	// mint a valid incident id carrying a chosen hub timestamp.
	insert(StormProtectionWindowStartIncidentID(now.Add(-time.Hour)), now)

	windowStart := StormProtectionWindowStart(now, 300)

	got, err := countIncidentsCreatedSince(ctx, tx, clusterID, windowStart)
	if err != nil {
		t.Fatalf("countIncidentsCreatedSince: %v", err)
	}
	if got != 2 {
		t.Errorf("countIncidentsCreatedSince = %d, want 2 (the two incidents this hub actually created inside the window, regardless of the agent-supplied first_seen they carry)", got)
	}

	// The pre-fix predicate, run here purely to prove the rows above really
	// do discriminate between the two clocks — if this ever returns 2 as
	// well, the test data has stopped exercising the bug and the assertion
	// above has become meaningless.
	var oldPredicateCount int
	if err := tx.QueryRow(ctx,
		`SELECT count(*) FROM incidents WHERE cluster_id = $1 AND first_seen >= $2`,
		clusterID, windowStart).Scan(&oldPredicateCount); err != nil {
		t.Fatalf("count via the old first_seen predicate: %v", err)
	}
	if oldPredicateCount != 1 {
		t.Errorf("the old `first_seen >= windowStart` predicate counted %d, expected it to count 1 (only the stale incident an agent mis-stamped as current) — this test's fixtures no longer distinguish the agent clock from the hub clock", oldPredicateCount)
	}
}

// TestCountIncidentsCreatedSinceScopesToOneCluster guards the other half of
// the predicate: storm protection is a PER-CLUSTER ceiling, so a burst on one
// cluster must never suppress new incidents on another.
func TestCountIncidentsCreatedSinceScopesToOneCluster(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()

	clusterA := domain.NewID(domain.PrefixCluster)
	clusterB := domain.NewID(domain.PrefixCluster)
	now := time.Now()

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	tenantID, err := data.SingleOrganisationID(ctx, tx)
	if err != nil {
		t.Fatalf("resolve organisation: %v", err)
	}
	if err := data.SetRequestScope(ctx, tx, tenantID, []string{clusterA, clusterB}); err != nil {
		t.Fatalf("set request scope: %v", err)
	}
	for _, id := range []string{clusterA, clusterB} {
		if _, err := tx.Exec(ctx,
			`INSERT INTO clusters (id, tenant_id, display_name, state, shard_id, cluster_fingerprint)
			 VALUES ($1, $2, $3, 'Active', 'shard-test', $4)`,
			id, tenantID, "storm-test-"+id, "fp-"+id); err != nil {
			t.Fatalf("insert throwaway cluster %s: %v", id, err)
		}
	}
	for i := 0; i < 3; i++ {
		incidentID := domain.NewID(domain.PrefixIncident)
		if _, err := tx.Exec(ctx,
			`INSERT INTO incidents (id, tenant_id, cluster_id, fingerprint, severity, state, first_seen, last_seen, occurrence_count)
			 VALUES ($1, $2, $3, $4, 'high', 'Detected', $5, $5, 1)`,
			incidentID, tenantID, clusterA, "fp-"+incidentID, now); err != nil {
			t.Fatalf("insert incident on cluster A: %v", err)
		}
	}

	windowStart := StormProtectionWindowStart(now, 300)
	if got, err := countIncidentsCreatedSince(ctx, tx, clusterA, windowStart); err != nil || got != 3 {
		t.Errorf("count for cluster A = %d (err %v), want 3", got, err)
	}
	if got, err := countIncidentsCreatedSince(ctx, tx, clusterB, windowStart); err != nil || got != 0 {
		t.Errorf("count for cluster B = %d (err %v), want 0 — a storm on one cluster must not suppress another's incidents", got, err)
	}
}

// TestCountIncidentsCreatedSinceIgnoresMalformedLegacyIDs is the regression
// test for BUGS.md 93, found live on rke2's own "personal test" cluster while
// verifying BACKLOG.md E6's storm-protection scenario: that cluster had
// accumulated ~19 incidents.id values hand-written by earlier manual SQL test
// fixtures (e.g. "inc_v1validate00000001", "inc_repolink0000000other001") —
// violating argus-context's "IDs are always domain.NewID-minted ULIDs"
// convention — and every one of them sorted ABOVE any realistic near-term
// ULID lower bound under COLLATE "C", so they counted as "created within the
// window" for every window, permanently, regardless of when they were
// actually inserted. That pinned storm protection into always-suppressing on
// that cluster, whether or not it had produced any real recent burst at all.
//
// wellFormed is a real domain.NewID incident, minted (and thus timestamped)
// right now — it MUST count. malformed carries a hand-written, non-ULID
// suffix and no real creation-time signal at all — it must NEVER count,
// however the window is sized, because there is no honest way to say it was
// "created since" anything.
func TestCountIncidentsCreatedSinceIgnoresMalformedLegacyIDs(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()

	clusterID := domain.NewID(domain.PrefixCluster)
	now := time.Now()

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
		clusterID, tenantID, "storm-test-"+clusterID, "fp-"+clusterID); err != nil {
		t.Fatalf("insert throwaway cluster: %v", err)
	}

	insert := func(incidentID string) {
		if _, err := tx.Exec(ctx,
			`INSERT INTO incidents (id, tenant_id, cluster_id, fingerprint, severity, state, first_seen, last_seen, occurrence_count)
			 VALUES ($1, $2, $3, $4, 'high', 'Detected', $5, $5, 1)`,
			incidentID, tenantID, clusterID, "fp-"+incidentID, now); err != nil {
			t.Fatalf("insert incident %s: %v", incidentID, err)
		}
	}

	wellFormed := domain.NewID(domain.PrefixIncident)
	insert(wellFormed)
	// Shaped exactly like the real debris this bug was found from — a
	// hand-written suffix, not a ULID, sorting above "inc_01..." under
	// COLLATE "C" for as long as ULID timestamps keep starting with '0'
	// (decades).
	insert("inc_v1validate00000001")
	insert("inc_repolink0000000other001")

	windowStart := StormProtectionWindowStart(now, 300)
	got, err := countIncidentsCreatedSince(ctx, tx, clusterID, windowStart)
	if err != nil {
		t.Fatalf("countIncidentsCreatedSince: %v", err)
	}
	if got != 1 {
		t.Errorf("countIncidentsCreatedSince = %d, want 1 (only the real domain.NewID incident — the two hand-written legacy ids must never count, regardless of window)", got)
	}

	// Same query, no id-shape guard: proves the fixtures above really do
	// exercise the bug rather than happening to also satisfy a stricter
	// predicate for an unrelated reason.
	var unguardedCount int
	if err := tx.QueryRow(ctx,
		`SELECT count(*) FROM incidents WHERE cluster_id = $1 AND id COLLATE "C" >= $2`,
		clusterID, StormProtectionWindowStartIncidentID(windowStart)).Scan(&unguardedCount); err != nil {
		t.Fatalf("count via the unguarded predicate: %v", err)
	}
	if unguardedCount != 3 {
		t.Errorf("the unguarded `id COLLATE \"C\" >= ...` predicate counted %d, expected 3 (all three rows, including the two malformed ones) — this test's fixtures no longer reproduce the bug", unguardedCount)
	}
}
