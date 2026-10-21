package api

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"argus/internal/data"
	"argus/internal/dbtest"
	"argus/internal/domain"
)

// The DB-backed half of internal/api/changes.go, against a real Postgres with
// RLS in force. Run with ARGUS_TEST_DATABASE_URL pointed at argus_app — NOT
// postgres, which carries BYPASSRLS and would make the cluster-scope assertion
// below vacuous (see this package's auth_test.go and RUNBOOK.md).
//
// What only a real database can prove here:
//
//   - The two sources really do merge into one time-ordered list.
//   - Cluster scope is enforced by the JOIN to `incidents`, which is the only
//     thing standing between a cluster-scoped grant and every other cluster's
//     executions — `remediation_executions` itself carries only a tenant-scope
//     policy.
//   - hasAnyChanges answers "ever", independent of the window, so the screen
//     can tell "nothing yet" from "nothing recently".

type changesFixture struct {
	tenantID string
	// clusterVisible is the cluster the test's request scope includes.
	clusterVisible string
	// clusterHidden holds an execution the caller must NOT be able to see.
	clusterHidden string

	incRecent string // an in-place execution 1h ago, undoable
	incOld    string // an in-place execution 30 days ago, outside a short window
	incFailed string // a failed execution 2h ago — a change attempt, not undoable
	incMerged string // a merged pull request 3h ago
	incHidden string // an execution on clusterHidden

	execRecent string
	execOld    string
	execFailed string
	execHidden string

	now time.Time
}

func setupChangesFixture(t *testing.T, pool *pgxpool.Pool) changesFixture {
	t.Helper()
	ctx := context.Background()

	f := changesFixture{
		clusterVisible: domain.NewID(domain.PrefixCluster),
		clusterHidden:  domain.NewID(domain.PrefixCluster),
		incRecent:      domain.NewID(domain.PrefixIncident),
		incOld:         domain.NewID(domain.PrefixIncident),
		incFailed:      domain.NewID(domain.PrefixIncident),
		incMerged:      domain.NewID(domain.PrefixIncident),
		incHidden:      domain.NewID(domain.PrefixIncident),
		execRecent:     domain.NewID(domain.PrefixExecution),
		execOld:        domain.NewID(domain.PrefixExecution),
		execFailed:     domain.NewID(domain.PrefixExecution),
		execHidden:     domain.NewID(domain.PrefixExecution),
		now:            time.Now().UTC().Truncate(time.Second),
	}

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin setup: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	f.tenantID, err = data.SingleOrganisationID(ctx, tx)
	if err != nil {
		t.Fatalf("resolve organisation: %v", err)
	}
	// Setup writes to BOTH clusters, so the setup transaction's scope has to
	// include both. The tests below deliberately scope to clusterVisible only.
	if err := data.SetRequestScope(ctx, tx, f.tenantID, []string{f.clusterVisible, f.clusterHidden}); err != nil {
		t.Fatalf("scope: %v", err)
	}

	insertCluster := func(id string) {
		if _, err := tx.Exec(ctx,
			`INSERT INTO clusters (id, tenant_id, display_name, state, shard_id, cluster_fingerprint)
			 VALUES ($1, $2, $3, 'Active', 'shard-test', $4)`,
			id, f.tenantID, "changes-"+id, "fp-"+id); err != nil {
			t.Fatalf("insert cluster %s: %v", id, err)
		}
	}
	insertCluster(f.clusterVisible)
	insertCluster(f.clusterHidden)

	insertIncident := func(id, clusterID string, firstSeen time.Time) {
		if _, err := tx.Exec(ctx,
			`INSERT INTO incidents (id, tenant_id, cluster_id, fingerprint, severity, state, first_seen, last_seen, occurrence_count)
			 VALUES ($1, $2, $3, $4, 'high', 'Validating', $5, $5, 1)`,
			id, f.tenantID, clusterID, "chfp-"+id, firstSeen); err != nil {
			t.Fatalf("insert incident %s: %v", id, err)
		}
	}
	insertIncident(f.incRecent, f.clusterVisible, f.now.Add(-2*time.Hour))
	insertIncident(f.incOld, f.clusterVisible, f.now.Add(-31*24*time.Hour))
	insertIncident(f.incFailed, f.clusterVisible, f.now.Add(-3*time.Hour))
	insertIncident(f.incMerged, f.clusterVisible, f.now.Add(-4*time.Hour))
	insertIncident(f.incHidden, f.clusterHidden, f.now.Add(-2*time.Hour))

	// The merged pull request. pr_merged_at is the ordering key for this kind
	// of change; pr_proposed_files is read for its PATHS only.
	if _, err := tx.Exec(ctx,
		`UPDATE incidents
		    SET pr_number = 103, pr_url = 'https://example.invalid/pr/103',
		        pr_merged_at = $2,
		        pr_proposed_files = '[{"path":"apps/web/deployment.yaml","content":"x"}]'::jsonb
		  WHERE id = $1`, f.incMerged, f.now.Add(-3*time.Hour)); err != nil {
		t.Fatalf("mark merged pull request: %v", err)
	}

	insertPlan := func(id, incidentID, clusterID, actionType string) {
		if _, err := tx.Exec(ctx,
			`INSERT INTO remediation_recommendations
			   (id, incident_id, tenant_id, cluster_id, analysis_id, action_type,
			    target_gvk, target_namespace, target_name, params, reversible, risk_level,
			    gate_outcome, gate_reason)
			 VALUES ($1,$2,$3,$4,$5,$6,'apps/v1/Deployment','prod','web','{"replicas":3}'::jsonb,true,'low','NeedsApproval','test')`,
			id, incidentID, f.tenantID, clusterID, domain.NewID(domain.PrefixAnalysis), actionType); err != nil {
			t.Fatalf("insert recommendation %s: %v", id, err)
		}
	}
	planRecent := domain.NewID(domain.PrefixPlan)
	planOld := domain.NewID(domain.PrefixPlan)
	planFailed := domain.NewID(domain.PrefixPlan)
	planHidden := domain.NewID(domain.PrefixPlan)
	insertPlan(planRecent, f.incRecent, f.clusterVisible, "ScaleDeployment")
	insertPlan(planOld, f.incOld, f.clusterVisible, "ScaleDeployment")
	insertPlan(planFailed, f.incFailed, f.clusterVisible, "ScaleDeployment")
	insertPlan(planHidden, f.incHidden, f.clusterHidden, "ScaleDeployment")

	insertExecution := func(id, planID, incidentID, clusterID, outcome string, at time.Time, withRollback bool) {
		rollbackType, rollbackParams, rollbackDesc := any(nil), any(nil), any(nil)
		if withRollback {
			rollbackType = "ScaleDeployment"
			rollbackParams = `{"replicas":1}`
			rollbackDesc = "scale back to 1 replica(s)"
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO remediation_executions
			   (id, recommendation_id, incident_id, tenant_id, cluster_id, outcome, executed_at,
			    rollback_action_type, rollback_params, rollback_description)
			 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb,$10)`,
			id, planID, incidentID, f.tenantID, clusterID, outcome, at,
			rollbackType, rollbackParams, rollbackDesc); err != nil {
			t.Fatalf("insert execution %s: %v", id, err)
		}
	}
	insertExecution(f.execRecent, planRecent, f.incRecent, f.clusterVisible, "succeeded", f.now.Add(-1*time.Hour), true)
	insertExecution(f.execOld, planOld, f.incOld, f.clusterVisible, "succeeded", f.now.Add(-30*24*time.Hour), true)
	insertExecution(f.execFailed, planFailed, f.incFailed, f.clusterVisible, "failed", f.now.Add(-2*time.Hour), false)
	insertExecution(f.execHidden, planHidden, f.incHidden, f.clusterHidden, "succeeded", f.now.Add(-1*time.Hour), true)

	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit setup: %v", err)
	}

	fixture := dbtest.New(t)
	fixture.Created("clusters", 2)
	fixture.Created("incidents", 5)
	fixture.Created("remediation_recommendations", 4)
	fixture.Created("remediation_executions", 4)
	fixture.Cleanup(pool, func(ctx context.Context, tx pgx.Tx) error {
		return data.SetRequestScope(ctx, tx, f.tenantID, []string{f.clusterVisible, f.clusterHidden})
	}, []dbtest.TableDelete{
		{Table: "remediation_executions", SQL: `DELETE FROM remediation_executions WHERE cluster_id = ANY($1)`, Args: []any{[]string{f.clusterVisible, f.clusterHidden}}},
		{Table: "remediation_recommendations", SQL: `DELETE FROM remediation_recommendations WHERE cluster_id = ANY($1)`, Args: []any{[]string{f.clusterVisible, f.clusterHidden}}},
		{Table: "incidents", SQL: `DELETE FROM incidents WHERE cluster_id = ANY($1)`, Args: []any{[]string{f.clusterVisible, f.clusterHidden}}},
		{Table: "clusters", SQL: `DELETE FROM clusters WHERE id = ANY($1)`, Args: []any{[]string{f.clusterVisible, f.clusterHidden}}},
	})

	return f
}

// scopedChangesTx opens a transaction scoped to the VISIBLE cluster only —
// the shape a per-cluster grant produces (internal/api/middleware.go resolves
// app.accessible_cluster_ids from the caller's grants).
func scopedChangesTx(t *testing.T, pool *pgxpool.Pool, f changesFixture) pgx.Tx {
	t.Helper()
	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	t.Cleanup(func() { _ = tx.Rollback(ctx) })
	if err := data.SetRequestScope(ctx, tx, f.tenantID, []string{f.clusterVisible}); err != nil {
		t.Fatalf("scope: %v", err)
	}
	return tx
}

func TestChangesMergesExecutionsAndMergedPullRequestsNewestFirst(t *testing.T) {
	pool := authTestPool(t)
	f := setupChangesFixture(t, pool)
	ctx := context.Background()
	tx := scopedChangesTx(t, pool, f)

	since := f.now.Add(-24 * time.Hour)
	execs, err := queryExecutionChanges(ctx, tx, since, f.clusterVisible, 50)
	if err != nil {
		t.Fatalf("queryExecutionChanges: %v", err)
	}
	prs, err := queryPullRequestChanges(ctx, tx, since, f.clusterVisible, 50)
	if err != nil {
		t.Fatalf("queryPullRequestChanges: %v", err)
	}

	byID := map[string]changeItem{}
	for _, c := range append(execs, prs...) {
		byID[c.ID] = c
	}

	recent, ok := byID[f.execRecent]
	if !ok {
		t.Fatalf("the succeeded execution 1h ago is missing from the list; got %v", keysOf(byID))
	}
	if recent.Kind != changeKindInPlace {
		t.Errorf("kind = %q, want %q", recent.Kind, changeKindInPlace)
	}
	if recent.Summary != "Scale prod/web to 3 replicas" {
		t.Errorf("summary = %q — want the same plain-language rendering the approval queue shows, never a raw action type", recent.Summary)
	}
	if !recent.Undo.Available || recent.Undo.ExecutionID != f.execRecent {
		t.Errorf("undo = %+v, want an available undo addressed by this execution's id", recent.Undo)
	}

	failed, ok := byID[f.execFailed]
	if !ok {
		t.Fatal("the failed execution is missing — a change that was ATTEMPTED is still something an operator has to know about")
	}
	if failed.Undo.Available {
		t.Error("a failed execution is offered an undo; POST /executions/{id}/rollback would refuse it")
	}
	if failed.Undo.Reason == "" {
		t.Error("a refused undo must carry the reason, or the control is unexplainable on screen")
	}

	pr, ok := byID["pr:"+f.incMerged]
	if !ok {
		t.Fatalf("the merged pull request is missing from the list; got %v", keysOf(byID))
	}
	if pr.Kind != changeKindPullRequest {
		t.Errorf("kind = %q, want %q", pr.Kind, changeKindPullRequest)
	}
	if pr.PullRequestNumber != 103 || pr.PullRequestURL == "" {
		t.Errorf("pull request identity = #%d %q, want both recorded", pr.PullRequestNumber, pr.PullRequestURL)
	}
	if len(pr.FilePaths) != 1 || pr.FilePaths[0] != "apps/web/deployment.yaml" {
		t.Errorf("filePaths = %v, want the one recorded path", pr.FilePaths)
	}
	if pr.Undo.Available {
		t.Error("a merged pull request is offered an in-cluster undo — the reversal is a revert in the repository, which ARGUS does not open")
	}

	// The 30-day-old execution is outside a 24h window.
	if _, present := byID[f.execOld]; present {
		t.Error("an execution 30 days old came back inside a 24h window")
	}
	// And the other cluster's execution is invisible under this request scope.
	if _, present := byID[f.execHidden]; present {
		t.Error("an execution on a cluster outside this request's scope was returned — the JOIN to `incidents` is the only thing enforcing cluster scope here, since remediation_executions carries no cluster-scope policy of its own")
	}
}

// The clusterId filter is applied by the QUERY, not by the caller filtering a
// capped page — a client-side filter would show the selection's share of the
// global most-recent-N, which is a different and smaller answer.
func TestChangesClusterFilterIsServerSide(t *testing.T) {
	pool := authTestPool(t)
	f := setupChangesFixture(t, pool)
	ctx := context.Background()
	tx := scopedChangesTx(t, pool, f)

	// Filtering to the hidden cluster returns nothing even though the caller
	// named it: RLS refuses it before the filter is even relevant.
	got, err := queryExecutionChanges(ctx, tx, f.now.Add(-24*time.Hour), f.clusterHidden, 50)
	if err != nil {
		t.Fatalf("queryExecutionChanges: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("got %d change(s) for a cluster outside this request's scope, want 0", len(got))
	}
}

// hasAnyChanges must answer "has ARGUS ever changed anything", not "in this
// window" — it is what separates "nothing yet" from "nothing recently", which
// are two different screens.
func TestChangesHasAnyChangesIgnoresTheWindow(t *testing.T) {
	pool := authTestPool(t)
	f := setupChangesFixture(t, pool)
	ctx := context.Background()
	tx := scopedChangesTx(t, pool, f)

	// A one-minute window: every change in the fixture is older than that.
	inWindow, err := queryExecutionChanges(ctx, tx, f.now.Add(-time.Minute), "", 50)
	if err != nil {
		t.Fatalf("queryExecutionChanges: %v", err)
	}
	for _, c := range inWindow {
		if c.ClusterID == f.clusterVisible {
			t.Fatalf("this fixture's change %s came back inside a one-minute window", c.ID)
		}
	}

	hasAny, err := anyChangeExists(ctx, tx)
	if err != nil {
		t.Fatalf("anyChangeExists: %v", err)
	}
	if !hasAny {
		t.Error("hasAnyChanges = false while this fixture's own executions exist — the screen would say \"ARGUS has not changed anything yet\", which is the wrong empty state and the wrong advice")
	}
}

func keysOf(m map[string]changeItem) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
