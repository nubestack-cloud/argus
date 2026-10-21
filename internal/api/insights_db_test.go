package api

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"argus/internal/data"
	"argus/internal/domain"
)

// BACKLOG.md L4's three new aggregates (queryUnstableClusters,
// queryFrequentlyRejectedRecommendations, queryAutomationCandidates) are
// plain GROUP BY/COUNT SQL, but the risk in that SQL is real: a wrong JOIN
// type or a misplaced HAVING silently produces a divide-by-zero rate or an
// invented one, exactly the fabricated-figure failure mode this codebase's
// own conventions are allergic to. fillDailyTrend-style pure unit tests
// can't exercise that — only a real Postgres running the actual query can.
// Gated on ARGUS_TEST_DATABASE_URL exactly like this package's authTestPool
// (auth_test.go) and internal/orchestrator/db_test.go; a machine without one
// gets a clean skip.

// l4Fixture is a small, throwaway fleet spanning two clusters, built once per
// test and cleaned up afterward. Two clusters (not one) so every query below
// can also be checked with and without the clusterId filter narrowing it.
type l4Fixture struct {
	tenantID               string
	clusterA, clusterB     string
	incidentA1, incidentA2 string
}

func setupL4Fixture(t *testing.T, pool *pgxpool.Pool) l4Fixture {
	t.Helper()
	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin setup transaction: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	tenantID, err := data.SingleOrganisationID(ctx, tx)
	if err != nil {
		t.Fatalf("resolve organisation: %v", err)
	}
	f := l4Fixture{
		tenantID:   tenantID,
		clusterA:   domain.NewID(domain.PrefixCluster),
		clusterB:   domain.NewID(domain.PrefixCluster),
		incidentA1: domain.NewID(domain.PrefixIncident),
		incidentA2: domain.NewID(domain.PrefixIncident),
	}
	if err := data.SetRequestScope(ctx, tx, tenantID, []string{f.clusterA, f.clusterB}); err != nil {
		t.Fatalf("set request scope: %v", err)
	}

	for _, c := range []struct{ id, name string }{
		{f.clusterA, "l4-cluster-a-" + f.clusterA},
		{f.clusterB, "l4-cluster-b-" + f.clusterB},
	} {
		if _, err := tx.Exec(ctx,
			`INSERT INTO clusters (id, tenant_id, display_name, state, shard_id, cluster_fingerprint)
			 VALUES ($1, $2, $3, 'Active', 'shard-test', $4)`,
			c.id, tenantID, c.name, "fp-"+c.id); err != nil {
			t.Fatalf("insert cluster %s: %v", c.id, err)
		}
	}

	now := time.Now()
	insertIncident := func(id, clusterID, state string) {
		if _, err := tx.Exec(ctx,
			`INSERT INTO incidents (id, tenant_id, cluster_id, fingerprint, severity, state, first_seen, last_seen, occurrence_count)
			 VALUES ($1, $2, $3, $4, 'high', $5, $6, $6, 1)`,
			id, tenantID, clusterID, "l4fp-"+id, state, now); err != nil {
			t.Fatalf("insert incident %s: %v", id, err)
		}
	}
	// Cluster A: two Reopened + one Detected = 3 total, 2 reopened-or-failed.
	insertIncident(f.incidentA1, f.clusterA, "Reopened")
	insertIncident(f.incidentA2, f.clusterA, "Reopened")
	insertIncident(domain.NewID(domain.PrefixIncident), f.clusterA, "Detected")
	// Cluster B: one Resolved = 1 total, 0 reopened-or-failed.
	insertIncident(domain.NewID(domain.PrefixIncident), f.clusterB, "Resolved")

	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit setup transaction: %v", err)
	}

	t.Cleanup(func() {
		cleanupCtx := context.Background()
		tx, err := pool.Begin(cleanupCtx)
		if err != nil {
			t.Logf("cleanup: begin: %v", err)
			return
		}
		defer tx.Rollback(cleanupCtx) //nolint:errcheck
		clusterIDs := []string{f.clusterA, f.clusterB}
		if err := data.SetRequestScope(cleanupCtx, tx, tenantID, clusterIDs); err != nil {
			t.Logf("cleanup: set request scope: %v", err)
			return
		}
		if _, err := tx.Exec(cleanupCtx, `DELETE FROM remediation_approval_decisions WHERE cluster_id = ANY($1)`, clusterIDs); err != nil {
			t.Logf("cleanup: delete approval decisions: %v", err)
			return
		}
		if _, err := tx.Exec(cleanupCtx, `DELETE FROM remediation_recommendations WHERE cluster_id = ANY($1)`, clusterIDs); err != nil {
			t.Logf("cleanup: delete recommendations: %v", err)
			return
		}
		if _, err := tx.Exec(cleanupCtx, `DELETE FROM incidents WHERE cluster_id = ANY($1)`, clusterIDs); err != nil {
			t.Logf("cleanup: delete incidents: %v", err)
			return
		}
		if _, err := tx.Exec(cleanupCtx, `DELETE FROM clusters WHERE id = ANY($1)`, clusterIDs); err != nil {
			t.Logf("cleanup: delete clusters: %v", err)
			return
		}
		if err := tx.Commit(cleanupCtx); err != nil {
			t.Logf("cleanup: commit: %v", err)
		}
	})

	return f
}

// openL4Tx opens a fresh, request-scoped transaction against the fixture's
// tenant/clusters — a new transaction each time, like a real request would
// get, rather than reusing setup's own (already committed/rolled back).
func openL4Tx(t *testing.T, pool *pgxpool.Pool, f l4Fixture) (context.Context, pgx.Tx) {
	t.Helper()
	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin transaction: %v", err)
	}
	t.Cleanup(func() { tx.Rollback(ctx) }) //nolint:errcheck
	if err := data.SetRequestScope(ctx, tx, f.tenantID, []string{f.clusterA, f.clusterB}); err != nil {
		t.Fatalf("set request scope: %v", err)
	}
	return ctx, tx
}

func TestQueryUnstableClusters(t *testing.T) {
	pool := authTestPool(t)
	f := setupL4Fixture(t, pool)
	ctx, tx := openL4Tx(t, pool, f)

	got, err := queryUnstableClusters(ctx, tx, "", 0)
	if err != nil {
		t.Fatalf("queryUnstableClusters: %v", err)
	}

	byCluster := map[string]unstableClusterSummary{}
	for _, u := range got {
		byCluster[u.ClusterID] = u
	}

	a, ok := byCluster[f.clusterA]
	if !ok {
		t.Fatalf("cluster A missing from result: %+v", got)
	}
	if a.TotalIncidents != 3 {
		t.Errorf("cluster A TotalIncidents = %d, want 3", a.TotalIncidents)
	}
	if a.ReopenedOrFailedCount != 2 {
		t.Errorf("cluster A ReopenedOrFailedCount = %d, want 2", a.ReopenedOrFailedCount)
	}
	if a.OpenCount != 3 {
		t.Errorf("cluster A OpenCount = %d, want 3 (none Resolved/Dismissed)", a.OpenCount)
	}

	b, ok := byCluster[f.clusterB]
	if !ok {
		t.Fatalf("cluster B missing from result: %+v", got)
	}
	if b.TotalIncidents != 1 || b.ReopenedOrFailedCount != 0 || b.OpenCount != 0 {
		t.Errorf("cluster B = %+v, want {total:1 reopenedOrFailed:0 open:0}", b)
	}

	// Cluster A has more reopened/failed incidents, so it must rank first.
	if got[0].ClusterID != f.clusterA {
		t.Errorf("got[0].ClusterID = %s, want cluster A ranked first (more reopened/failed)", got[0].ClusterID)
	}

	// The clusterId filter narrows to exactly one cluster.
	filtered, err := queryUnstableClusters(ctx, tx, f.clusterB, 0)
	if err != nil {
		t.Fatalf("queryUnstableClusters (filtered): %v", err)
	}
	if len(filtered) != 1 || filtered[0].ClusterID != f.clusterB {
		t.Errorf("queryUnstableClusters(clusterId=B) = %+v, want exactly cluster B", filtered)
	}
}

// l4GVK builds a target_gvk value that is unique to this fixture's run —
// this is exercised against the real dev Postgres (RUNBOOK.md's compose
// stack), which already carries real remediation_recommendations rows from
// actual usage sharing ordinary GVKs like "apps/v1/Deployment". Grouping by
// a marked GVK (rather than a bare kind literal) is what lets the `clusterId:
// ""` (fleet-wide, unfiltered) assertions below count ONLY this fixture's own
// rows — the cluster-scoped assertions don't need this trick, since a freshly
// generated cluster id can never collide with a pre-existing row, but the
// unfiltered ones would otherwise silently sum in whatever unrelated data the
// database already had.
func l4GVK(kind string, f l4Fixture) string {
	return kind + "#" + f.clusterA
}

// remediationFixture layers remediation_recommendations/
// remediation_approval_decisions rows onto an l4Fixture's clusters —
// separated from setupL4Fixture itself so TestQueryUnstableClusters (which
// needs none of this) stays a plain incidents/clusters fixture.
func setupRemediationFixture(t *testing.T, pool *pgxpool.Pool, f l4Fixture) {
	t.Helper()
	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin remediation setup: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if err := data.SetRequestScope(ctx, tx, f.tenantID, []string{f.clusterA, f.clusterB}); err != nil {
		t.Fatalf("set request scope: %v", err)
	}

	insertPlan := func(clusterID, incidentID, actionType, targetGVK, riskLevel, gateOutcome string, createdAt time.Time) string {
		id := domain.NewID(domain.PrefixPlan)
		if _, err := tx.Exec(ctx,
			`INSERT INTO remediation_recommendations
			   (id, incident_id, tenant_id, cluster_id, analysis_id, action_type, target_gvk, target_name,
			    params, reversible, risk_level, gate_outcome, gate_reason, created_at)
			 VALUES ($1, $2, $3, $4, $5, $6, $7, 'test-object', '{}', true, $8, $9, 'test fixture', $10)`,
			id, incidentID, f.tenantID, clusterID, "an_l4test", actionType, targetGVK, riskLevel, gateOutcome, createdAt); err != nil {
			t.Fatalf("insert remediation_recommendations: %v", err)
		}
		return id
	}
	insertDecision := func(clusterID, incidentID, recommendationID, verdict, reason string) {
		if _, err := tx.Exec(ctx,
			`INSERT INTO remediation_approval_decisions
			   (id, recommendation_id, incident_id, tenant_id, cluster_id, actor_id, verdict, reason)
			 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
			domain.NewID(domain.PrefixApproval), recommendationID, incidentID, f.tenantID, clusterID,
			"usr_l4test", verdict, nullableReason(reason)); err != nil {
			t.Fatalf("insert remediation_approval_decisions: %v", err)
		}
	}

	now := time.Now()
	scaleGVK := l4GVK("apps/v1/Deployment", f)
	podGVK := l4GVK("v1/Pod", f)

	// r1, r2: ScaleDeployment/(marked Deployment)/low/NeedsApproval on
	// cluster A — 2 approved + 1 rejected across the pair, so the
	// (action,gvk) group has decided=3, rejected=1 (a partial rate, not a
	// clean 0 or 100%).
	r1 := insertPlan(f.clusterA, f.incidentA1, "ScaleDeployment", scaleGVK, "low", "NeedsApproval", now)
	insertDecision(f.clusterA, f.incidentA1, r1, "approved", "")
	r2 := insertPlan(f.clusterA, f.incidentA1, "ScaleDeployment", scaleGVK, "low", "NeedsApproval", now)
	insertDecision(f.clusterA, f.incidentA1, r2, "approved", "")
	insertDecision(f.clusterA, f.incidentA1, r2, "rejected", "would breach maxReplicas policy")

	// r3: RestartPod/(marked Pod)/medium/NeedsApproval on cluster A — 3
	// approved, 0 rejected: a clean 100%-approved automation candidate, and
	// it must be ABSENT from "frequently rejected" (HAVING excludes
	// zero-rejection groups).
	r3 := insertPlan(f.clusterA, f.incidentA2, "RestartPod", podGVK, "medium", "NeedsApproval", now)
	insertDecision(f.clusterA, f.incidentA2, r3, "approved", "")
	insertDecision(f.clusterA, f.incidentA2, r3, "approved", "")
	insertDecision(f.clusterA, f.incidentA2, r3, "approved", "")

	// r4: OpenPR/(marked Deployment)/high/AutoApprove on cluster A — has a
	// rejection (so it belongs in "frequently rejected"), but gate_outcome
	// is AutoApprove, not NeedsApproval, so it must be ABSENT from
	// "automation candidates" regardless of its decision history.
	r4 := insertPlan(f.clusterA, f.incidentA2, "OpenPR", scaleGVK, "high", "AutoApprove", now)
	insertDecision(f.clusterA, f.incidentA2, r4, "rejected", "policy already covers this")

	// r5: same (action,gvk) group as r1/r2, but on cluster B — proves the
	// clusterId filter actually narrows the aggregate, not just labels it.
	r5 := insertPlan(f.clusterB, f.incidentA1, "ScaleDeployment", scaleGVK, "low", "NeedsApproval", now)
	insertDecision(f.clusterB, f.incidentA1, r5, "rejected", "cluster B specific rejection")

	// r6: RestartPod/(marked Pod)/medium/NeedsApproval on cluster A with
	// ZERO decisions — still awaiting a human. Must be invisible to
	// automation candidates (INNER JOIN), not counted as either approved or
	// rejected.
	insertPlan(f.clusterA, f.incidentA2, "RestartPod", podGVK, "medium", "NeedsApproval", now)

	// r7: outside a 30-day window but well inside the all-time default —
	// created 40 days ago, to prove the `days` filter actually excludes an
	// old recommendation rather than ignoring the parameter.
	r7 := insertPlan(f.clusterA, f.incidentA1, "ScaleDeployment", scaleGVK, "low", "NeedsApproval", now.AddDate(0, 0, -40))
	insertDecision(f.clusterA, f.incidentA1, r7, "rejected", "old rejection outside the 30-day window")

	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit remediation setup: %v", err)
	}
}

func nullableReason(reason string) *string {
	if reason == "" {
		return nil
	}
	return &reason
}

func TestQueryFrequentlyRejectedRecommendations(t *testing.T) {
	pool := authTestPool(t)
	f := setupL4Fixture(t, pool)
	setupRemediationFixture(t, pool, f)
	ctx, tx := openL4Tx(t, pool, f)

	got, err := queryFrequentlyRejectedRecommendations(ctx, tx, "", 0)
	if err != nil {
		t.Fatalf("queryFrequentlyRejectedRecommendations: %v", err)
	}

	scaleGVK := l4GVK("apps/v1/Deployment", f)
	podGVK := l4GVK("v1/Pod", f)

	byGroup := map[string]rejectedRecommendationSummary{}
	for _, s := range got {
		byGroup[s.ActionType+"|"+s.TargetGVK] = s
	}

	// RestartPod/(marked Pod) (r3, zero rejections) must be entirely absent.
	if _, ok := byGroup["RestartPod|"+podGVK]; ok {
		t.Errorf("RestartPod/%s has zero rejections and must not appear in frequentlyRejected: %+v", podGVK, byGroup)
	}

	// ScaleDeployment/(marked Deployment) spans r1+r2 (cluster A) + r5
	// (cluster B) + r7 (40 days ago): with no cluster/day filter, all four
	// recommendations count: recommended=4, decided=5 (r1 approved, r2
	// approved+rejected, r5 rejected, r7 rejected), rejected=3.
	scale, ok := byGroup["ScaleDeployment|"+scaleGVK]
	if !ok {
		t.Fatalf("ScaleDeployment/%s missing: %+v", scaleGVK, got)
	}
	if scale.RecommendedCount != 4 {
		t.Errorf("RecommendedCount = %d, want 4", scale.RecommendedCount)
	}
	if scale.DecidedCount != 5 {
		t.Errorf("DecidedCount = %d, want 5", scale.DecidedCount)
	}
	if scale.RejectedCount != 3 {
		t.Errorf("RejectedCount = %d, want 3", scale.RejectedCount)
	}
	wantRate := 3.0 / 5.0
	if scale.RejectionRate != wantRate {
		t.Errorf("RejectionRate = %v, want %v", scale.RejectionRate, wantRate)
	}
	if scale.SampleRejectionReason == nil {
		t.Error("SampleRejectionReason is nil, want a real rejection reason")
	}

	// OpenPR/(marked Deployment) (r4) is its own group, separate from
	// ScaleDeployment despite sharing a target_gvk.
	openPR, ok := byGroup["OpenPR|"+scaleGVK]
	if !ok {
		t.Fatalf("OpenPR/%s missing: %+v", scaleGVK, got)
	}
	if openPR.RejectedCount != 1 || openPR.DecidedCount != 1 {
		t.Errorf("OpenPR group = %+v, want decided=1 rejected=1", openPR)
	}

	// Narrowing to cluster A excludes r5 (cluster B): recommended=3
	// (r1,r2,r7), decided=4, rejected=2 (r2's rejection + r7's).
	scopedToA, err := queryFrequentlyRejectedRecommendations(ctx, tx, f.clusterA, 0)
	if err != nil {
		t.Fatalf("queryFrequentlyRejectedRecommendations (cluster A): %v", err)
	}
	var scaleA *rejectedRecommendationSummary
	for i := range scopedToA {
		if scopedToA[i].ActionType == "ScaleDeployment" {
			scaleA = &scopedToA[i]
		}
	}
	if scaleA == nil {
		t.Fatalf("ScaleDeployment missing when scoped to cluster A: %+v", scopedToA)
	}
	if scaleA.RecommendedCount != 3 || scaleA.DecidedCount != 4 || scaleA.RejectedCount != 2 {
		t.Errorf("cluster-A-scoped ScaleDeployment = %+v, want recommended=3 decided=4 rejected=2", scaleA)
	}

	// A 30-day window excludes r7 (created 40 days ago): recommended=3
	// (r1,r2,r5), decided=4, rejected=2 (r2's + r5's).
	within30Days, err := queryFrequentlyRejectedRecommendations(ctx, tx, "", 30)
	if err != nil {
		t.Fatalf("queryFrequentlyRejectedRecommendations (30 days): %v", err)
	}
	var scale30 *rejectedRecommendationSummary
	for i := range within30Days {
		if within30Days[i].ActionType == "ScaleDeployment" && within30Days[i].TargetGVK == scaleGVK {
			scale30 = &within30Days[i]
		}
	}
	if scale30 == nil {
		t.Fatalf("ScaleDeployment missing within 30 days: %+v", within30Days)
	}
	if scale30.RecommendedCount != 3 || scale30.DecidedCount != 4 || scale30.RejectedCount != 2 {
		t.Errorf("30-day-windowed ScaleDeployment = %+v, want recommended=3 decided=4 rejected=2 (r7 excluded)", scale30)
	}
}

func TestQueryAutomationCandidates(t *testing.T) {
	pool := authTestPool(t)
	f := setupL4Fixture(t, pool)
	setupRemediationFixture(t, pool, f)
	ctx, tx := openL4Tx(t, pool, f)

	got, err := queryAutomationCandidates(ctx, tx, "", 0)
	if err != nil {
		t.Fatalf("queryAutomationCandidates: %v", err)
	}

	scaleGVK := l4GVK("apps/v1/Deployment", f)
	podGVK := l4GVK("v1/Pod", f)

	type key struct{ actionType, gvk, risk string }
	byGroup := map[key]automationCandidateSummary{}
	for _, s := range got {
		byGroup[key{s.ActionType, s.TargetGVK, s.RiskLevel}] = s
	}

	// OpenPR (r4) must be entirely absent — gate_outcome is AutoApprove, not
	// NeedsApproval, regardless of its (real) rejection.
	if _, ok := byGroup[key{"OpenPR", scaleGVK, "high"}]; ok {
		t.Error("OpenPR/AutoApprove must not appear in automation candidates")
	}

	// RestartPod/(marked Pod)/medium: r3 (3 approved) + r6 (0 decisions,
	// INNER JOIN drops it entirely) — decided must be exactly 3, not padded
	// by r6.
	restart, ok := byGroup[key{"RestartPod", podGVK, "medium"}]
	if !ok {
		t.Fatalf("RestartPod/%s/medium missing: %+v", podGVK, got)
	}
	if restart.DecidedCount != 3 || restart.ApprovedCount != 3 || restart.RejectedCount != 0 {
		t.Errorf("RestartPod candidate = %+v, want decided=3 approved=3 rejected=0", restart)
	}
	if restart.ApprovalRate != 1.0 {
		t.Errorf("RestartPod ApprovalRate = %v, want 1.0", restart.ApprovalRate)
	}

	// ScaleDeployment/(marked Deployment)/low spans r1+r2 (cluster A) + r5
	// (cluster B) + r7 (40 days ago): decided=5, approved=2, rejected=3 —
	// a real partial rate, not a fabricated round number.
	scale, ok := byGroup[key{"ScaleDeployment", scaleGVK, "low"}]
	if !ok {
		t.Fatalf("ScaleDeployment/%s/low missing: %+v", scaleGVK, got)
	}
	if scale.DecidedCount != 5 || scale.ApprovedCount != 2 || scale.RejectedCount != 3 {
		t.Errorf("ScaleDeployment candidate = %+v, want decided=5 approved=2 rejected=3", scale)
	}
	wantRate := 2.0 / 5.0
	if scale.ApprovalRate != wantRate {
		t.Errorf("ApprovalRate = %v, want %v", scale.ApprovalRate, wantRate)
	}

	// Narrowing to cluster A excludes r5: decided=4, approved=2, rejected=2.
	scopedToA, err := queryAutomationCandidates(ctx, tx, f.clusterA, 0)
	if err != nil {
		t.Fatalf("queryAutomationCandidates (cluster A): %v", err)
	}
	var scaleA *automationCandidateSummary
	for i := range scopedToA {
		if scopedToA[i].ActionType == "ScaleDeployment" {
			scaleA = &scopedToA[i]
		}
	}
	if scaleA == nil {
		t.Fatalf("ScaleDeployment missing when scoped to cluster A: %+v", scopedToA)
	}
	if scaleA.DecidedCount != 4 || scaleA.ApprovedCount != 2 || scaleA.RejectedCount != 2 {
		t.Errorf("cluster-A-scoped ScaleDeployment = %+v, want decided=4 approved=2 rejected=2", scaleA)
	}
}
