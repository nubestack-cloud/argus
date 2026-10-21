package orchestrator

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"argus/internal/data"
	"argus/internal/dbtest"
	"argus/internal/domain"
)

// approvalFixture inserts a throwaway cluster, an AwaitingApproval incident,
// and one remediation_recommendations row backdated to recCreatedAt —
// approvalStintStartQuery's fallback source of "when did this AwaitingApproval
// stint begin" for an incident with no timeline_events row (this fixture
// deliberately writes none, so every test here exercises that fallback
// explicitly rather than depending on timeline plumbing tested elsewhere).
// Mirrors breakerFixture's shape (breaker_db_test.go) and testIncident's
// cleanup discipline (db_test.go).
func approvalFixture(t *testing.T, pool *pgxpool.Pool, recCreatedAt time.Time) (tenantID, clusterID, incidentID, recID string) {
	t.Helper()
	ctx := context.Background()

	clusterID = domain.NewID(domain.PrefixCluster)
	incidentID = domain.NewID(domain.PrefixIncident)
	recID = domain.NewID(domain.PrefixPlan)

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin setup: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	tenantID, err = data.SingleOrganisationID(ctx, tx)
	if err != nil {
		t.Fatalf("resolve organisation: %v", err)
	}
	if err := data.SetRequestScope(ctx, tx, tenantID, []string{clusterID}); err != nil {
		t.Fatalf("set request scope: %v", err)
	}

	if _, err := tx.Exec(ctx,
		`INSERT INTO clusters (id, tenant_id, display_name, state, shard_id, cluster_fingerprint)
		 VALUES ($1, $2, $3, 'Active', 'shard-test', $4)`,
		clusterID, tenantID, "approvalwatch-test-"+clusterID, "fp-"+clusterID); err != nil {
		t.Fatalf("insert cluster: %v", err)
	}
	now := time.Now()
	if _, err := tx.Exec(ctx,
		`INSERT INTO incidents (id, tenant_id, cluster_id, fingerprint, severity, state, first_seen, last_seen, occurrence_count)
		 VALUES ($1, $2, $3, $4, 'high', $5, $6, $6, 1)`,
		incidentID, tenantID, clusterID, "test-approvalwatch-"+incidentID, StateAwaitingApproval, now); err != nil {
		t.Fatalf("insert incident: %v", err)
	}

	analysisID := domain.NewID(domain.PrefixAnalysis)
	if _, err := tx.Exec(ctx,
		`INSERT INTO analyses
		   (id, tenant_id, incident_id, cluster_id, prompt_version, model, causal_chain,
		    iterations, duration_ms, tokens_billed_in, tokens_cache_read, tokens_out, cost_usd)
		 VALUES ($1, $2, $3, $4, 'test', 'test-model', '[]'::jsonb, 1, 1, 0, 0, 0, 0)`,
		analysisID, tenantID, incidentID, clusterID); err != nil {
		t.Fatalf("insert analysis: %v", err)
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO remediation_recommendations
		   (id, incident_id, tenant_id, cluster_id, analysis_id, action_type, target_gvk,
		    target_namespace, target_name, params, reversible, risk_level, gate_outcome, gate_reason, created_at)
		 VALUES ($1, $2, $3, $4, $5, 'ScaleDeployment', 'apps/v1/Deployment',
		         'default', 'approvalwatch-test', '{}'::jsonb, true, 'low', 'NeedsApproval', 'test', $6)`,
		recID, incidentID, tenantID, clusterID, analysisID, recCreatedAt); err != nil {
		t.Fatalf("insert recommendation: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit setup: %v", err)
	}

	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		// PROJECT.md B188: the catalogue-driven half of the leak check, the
		// same one dbtest.Fixture.OwnsCluster wires up. This fixture is not
		// on dbtest.Fixture because its deletes are all keyed on a single
		// freshly-minted ULID, so the over-deletion half Fixture exists to
		// prevent is already structurally impossible here — what it is
		// missing is the other half: a table nobody thought to name.
		// AssertNoClusterResidue asks pg_class rather than this delete
		// list, so a migration that adds a cluster-scoped table joins the
		// check the day it lands.
		//
		// Deferred here, BEFORE tx.Rollback's own defer, so LIFO runs the
		// rollback first and this reads a settled database — and so it runs
		// even when a delete above returned early, which is precisely the
		// case where something has been left behind.
		defer dbtest.AssertNoClusterResidue(t, pool, tenantID, clusterID)
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Errorf("cleanup: begin: %v", err)
			return
		}
		defer tx.Rollback(ctx) //nolint:errcheck
		if err := data.SetRequestScope(ctx, tx, tenantID, []string{clusterID}); err != nil {
			t.Errorf("cleanup: scope: %v", err)
			return
		}
		for _, stmt := range []string{
			`DELETE FROM incident_notifications WHERE incident_id = $1`,
			`DELETE FROM timeline_events WHERE incident_id = $1`,
			`DELETE FROM remediation_recommendations WHERE incident_id = $1`,
			`DELETE FROM analyses WHERE incident_id = $1`,
			`DELETE FROM incidents WHERE id = $1`,
		} {
			if _, err := tx.Exec(ctx, stmt, incidentID); err != nil {
				t.Errorf("cleanup: %s: %v", stmt, err)
				return
			}
		}
		if _, err := tx.Exec(ctx, `DELETE FROM clusters WHERE id = $1`, clusterID); err != nil {
			t.Errorf("cleanup: delete cluster: %v", err)
			return
		}
		if err := tx.Commit(ctx); err != nil {
			t.Errorf("cleanup: commit: %v", err)
		}
	})

	return tenantID, clusterID, incidentID, recID
}

// TestApprovalSweeperDoesNotEscalateFreshPlan is the negative case: a plan
// that just became ready must not be escalated — escalation is for a plan
// nobody has decided on YET, not every plan.
func TestApprovalSweeperDoesNotEscalateFreshPlan(t *testing.T) {
	pool := testPool(t)
	tenantID, clusterID, incidentID, _ := approvalFixture(t, pool, time.Now())
	ctx := context.Background()

	sweeper := NewApprovalSweeper(&data.DB{Pool: pool})
	if err := sweeper.sweep(ctx); err != nil {
		t.Fatalf("sweep: %v", err)
	}

	if _, _, found := readNotification(t, pool, tenantID, clusterID, incidentID); found {
		t.Fatal("a freshly-ready plan must not be escalated")
	}
}

// TestApprovalSweeperEscalatesStalePlanWithoutRefiringOnRepeatedTicks mirrors
// TestMergeSweeperEscalatesStalePRWithoutRefiringOnRepeatedTicks for the
// AwaitingApproval half BACKLOG.md T3 adds: a plan stale enough to cross the
// first escalation tier gets exactly one notification, and a second sweep
// that observes the SAME still-current tier must not re-arm it.
func TestApprovalSweeperEscalatesStalePlanWithoutRefiringOnRepeatedTicks(t *testing.T) {
	pool := testPool(t)
	tenantID, clusterID, incidentID, _ := approvalFixture(t, pool, time.Now().Add(-2*mergeStalenessThreshold))
	ctx := context.Background()

	sweeper := NewApprovalSweeper(&data.DB{Pool: pool})
	wantKey := "AwaitingApproval:Stale:" + escalationTierLabel(mergeStalenessThreshold)

	if err := sweeper.sweep(ctx); err != nil {
		t.Fatalf("first sweep: %v", err)
	}
	key1, pending, found := readNotification(t, pool, tenantID, clusterID, incidentID)
	if !found || !pending || key1 != wantKey {
		t.Fatalf("after first sweep: key=%q pending=%v found=%v, want a pending row keyed %q", key1, pending, found, wantKey)
	}

	// Simulate internal/notify's own sweep having actually sent it.
	setNotificationPending(t, pool, tenantID, clusterID, incidentID, false)

	// A second tick observing the exact same still-stale plan must be a
	// no-op — repeated observation of an unchanged condition must not
	// re-arm the notification.
	if err := sweeper.sweep(ctx); err != nil {
		t.Fatalf("second sweep: %v", err)
	}
	key2, pending, found := readNotification(t, pool, tenantID, clusterID, incidentID)
	if !found || pending || key2 != key1 {
		t.Fatalf("after a second sweep of the same still-stale plan: key=%q pending=%v found=%v, want (%q, false, true)", key2, pending, found, key1)
	}

	// This sweep never changes incident state.
	if got := currentState(t, pool, tenantID, clusterID, incidentID); got != StateAwaitingApproval {
		t.Fatalf("incident state = %q, want %q — escalation must not change the incident's state", got, StateAwaitingApproval)
	}
}

// TestApprovalAndMergeEscalationCrossTierBoundary is the "done" bar T3's
// brief calls for explicitly: a DB-backed test proving a real stuck
// incident crosses a tier boundary and gets a genuinely NEW notification
// row, for BOTH AwaitingApproval and AwaitingMerge. Age is advanced by
// updating the underlying timestamp (remediation_recommendations.created_at
// for the approval half, PullRequestOutcome.CreatedAt for the merge half)
// between two sweeps, exactly as a real 48h-then-5d passage of time would.
func TestApprovalAndMergeEscalationCrossTierBoundary(t *testing.T) {
	day := 24 * time.Hour

	t.Run("AwaitingApproval", func(t *testing.T) {
		pool := testPool(t)
		tenantID, clusterID, incidentID, recID := approvalFixture(t, pool, time.Now().Add(-2*mergeStalenessThreshold))
		ctx := context.Background()
		sweeper := NewApprovalSweeper(&data.DB{Pool: pool})

		if err := sweeper.sweep(ctx); err != nil {
			t.Fatalf("first sweep: %v", err)
		}
		key1, _, found := readNotification(t, pool, tenantID, clusterID, incidentID)
		if !found {
			t.Fatal("expected a notification after the first sweep")
		}
		setNotificationPending(t, pool, tenantID, clusterID, incidentID, false)

		// Advance the plan's age past the second tier (5d) by backdating the
		// recommendation's created_at further — the same effect real elapsed
		// time would have, without the test actually sleeping five days.
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatalf("begin: %v", err)
		}
		if err := data.SetRequestScope(ctx, tx, tenantID, []string{clusterID}); err != nil {
			t.Fatalf("set request scope: %v", err)
		}
		if _, err := tx.Exec(ctx, `UPDATE remediation_recommendations SET created_at = $2 WHERE id = $1`,
			recID, time.Now().Add(-6*day)); err != nil {
			t.Fatalf("backdate recommendation: %v", err)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatalf("commit: %v", err)
		}

		if err := sweeper.sweep(ctx); err != nil {
			t.Fatalf("second sweep: %v", err)
		}
		key2, pending, found := readNotification(t, pool, tenantID, clusterID, incidentID)
		if !found || !pending {
			t.Fatalf("after crossing into the second tier: pending=%v found=%v, want a freshly-pending row", pending, found)
		}
		if key2 == key1 {
			t.Fatalf("crossing a tier boundary produced the SAME key (%q) as the previous tier — must be a genuinely new key", key1)
		}
		wantKey2 := "AwaitingApproval:Stale:" + escalationTierLabel(5*day)
		if key2 != wantKey2 {
			t.Fatalf("key after crossing into the second tier = %q, want %q", key2, wantKey2)
		}
	})

	t.Run("AwaitingMerge", func(t *testing.T) {
		pool := testPool(t)
		tenantID, clusterID, incidentID, _ := testIncident(t, pool, StateAwaitingMerge)
		ctx := context.Background()

		prCreatedAt := time.Now().Add(-2 * mergeStalenessThreshold)
		checker := &mutableMergeChecker{incidentID: incidentID, outcome: PullRequestOutcome{
			Merged: false, Closed: false, CreatedAt: prCreatedAt,
		}}
		sweeper := NewMergeSweeper(&data.DB{Pool: pool}, nil, checker)

		if err := sweeper.sweep(ctx); err != nil {
			t.Fatalf("first sweep: %v", err)
		}
		key1, _, found := readNotification(t, pool, tenantID, clusterID, incidentID)
		if !found {
			t.Fatal("expected a notification after the first sweep")
		}
		setNotificationPending(t, pool, tenantID, clusterID, incidentID, false)

		// The pull request is still open, just older now — 13 days in, past
		// the third tier (12d).
		checker.outcome.CreatedAt = time.Now().Add(-13 * day)

		if err := sweeper.sweep(ctx); err != nil {
			t.Fatalf("second sweep: %v", err)
		}
		key2, pending, found := readNotification(t, pool, tenantID, clusterID, incidentID)
		if !found || !pending {
			t.Fatalf("after crossing into a later tier: pending=%v found=%v, want a freshly-pending row", pending, found)
		}
		if key2 == key1 {
			t.Fatalf("crossing a tier boundary produced the SAME key (%q) as the previous tier — must be a genuinely new key", key1)
		}
		wantKey2 := "AwaitingMerge:StalePR:" + escalationTierLabel(12*day)
		if key2 != wantKey2 {
			t.Fatalf("key after crossing into the third tier = %q, want %q", key2, wantKey2)
		}
	})
}

// mutableMergeChecker is scopedMergeChecker (mergewatch_db_test.go) with an
// outcome the test can mutate BETWEEN two sweeps on the same sweeper — the
// fixed-at-construction scopedMergeChecker can't model "the same incident,
// a later tick, more time has passed" on its own.
type mutableMergeChecker struct {
	incidentID string
	outcome    PullRequestOutcome
}

func (m *mutableMergeChecker) CheckPullRequestMerged(_ context.Context, incidentID string) (PullRequestOutcome, error) {
	if incidentID != m.incidentID {
		return PullRequestOutcome{}, fmt.Errorf("mutableMergeChecker: not scoped to incident %s", incidentID)
	}
	return m.outcome, nil
}
