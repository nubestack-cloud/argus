package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"argus/internal/data"
	"argus/internal/dbtest"
	"argus/internal/domain"
	"argus/internal/orchestrator"
	"argus/internal/remediation"
)

// This file is PROJECT.md B167's own regression suite: GET /api/v1/approvals
// moved filtering, sorting, counting and pagination server-side (approvals.go's
// approvalScopeFilter/approvalSortSpecs/approvalCountsFor), mirroring
// incidents.go's own P9/P10 shapes. Three things get proven here that a green
// build alone would not show:
//
//  1. approvalRiskRankExpr — the SQL rendering of
//     internal/remediation.EffectiveRiskLevel — agrees with the real Go
//     function across every reachable action type, a stateful-kind target, a
//     protected namespace, and a declared risk level above the floor.
//  2. counts.pending/approved/high/medium/low narrow together WITH the rows
//     under the exact same filters — the incidentScopeFilter regression this
//     endpoint is deliberately built to avoid repeating.
//  3. The endpoint hands back a bounded page, not the whole queue, and a
//     small ?limit= forces exactly the pagination behaviour ApprovalsPage
//     now relies on instead of fetching everything and slicing client-side.

func skipIfNoTestDB(t *testing.T) string {
	t.Helper()
	connString := os.Getenv("ARGUS_TEST_DATABASE_URL")
	if connString == "" {
		t.Skip("ARGUS_TEST_DATABASE_URL not set; skipping approvals query/pagination DB test")
	}
	return connString
}

// --- 1. approvalRiskRankExpr parity with remediation.EffectiveRiskLevel ---

func TestApprovalRiskRankExprMatchesEffectiveRiskLevel(t *testing.T) {
	connString := skipIfNoTestDB(t)
	pool, err := pgxpool.New(context.Background(), connString)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer pool.Close()

	type testCase struct {
		name            string
		actionType      remediation.ActionType
		targetGVK       string
		targetNamespace string
		declaredRisk    remediation.RiskLevel
	}

	cases := []testCase{}
	// Every reachable action type (AllActionTypes minus StructuredPatch — see
	// approvalRiskRankExpr's own doc comment for why that one is excluded),
	// declared at exactly its own floor, in a plain namespace against a
	// non-stateful Kind: effective risk must equal the floor unmodified.
	for _, actionType := range remediation.AllActionTypes() {
		if actionType == remediation.ActionStructuredPatch {
			continue
		}
		floor := remediation.BaseRiskFloors()[actionType]
		cases = append(cases, testCase{
			name:            "floor/" + string(actionType),
			actionType:      actionType,
			targetGVK:       "apps/v1/Deployment",
			targetNamespace: "default",
			declaredRisk:    floor,
		})
	}
	// A stateful-kind target raises the floor to high regardless of the
	// action's own base floor.
	cases = append(cases,
		testCase{name: "stateful-kind-raises-floor", actionType: remediation.ActionScaleDeployment,
			targetGVK: "apps/v1/StatefulSet", targetNamespace: "default", declaredRisk: remediation.RiskLow},
		testCase{name: "pvc-raises-floor", actionType: remediation.ActionScaleDeployment,
			targetGVK: "v1/PersistentVolumeClaim", targetNamespace: "default", declaredRisk: remediation.RiskLow},
		// A protected namespace raises the floor the same way.
		testCase{name: "protected-namespace-raises-floor", actionType: remediation.ActionRestartPod,
			targetGVK: "v1/Pod", targetNamespace: "kube-system", declaredRisk: remediation.RiskMedium},
		// A declared level ABOVE the floor is honoured as-is (the "judgement is
		// for nuance" half of EffectiveRiskLevel) — ScaleDeployment's floor is
		// low, declaring high must still come out high.
		testCase{name: "declared-above-floor-wins", actionType: remediation.ActionScaleDeployment,
			targetGVK: "apps/v1/Deployment", targetNamespace: "default", declaredRisk: remediation.RiskHigh},
		// No namespace at all (NULL in the real column; empty string here) —
		// must not error, and must not spuriously match a protected namespace.
		testCase{name: "no-namespace", actionType: remediation.ActionOpenPR,
			targetGVK: "argus.io/RepositoryChange", targetNamespace: "", declaredRisk: remediation.RiskLow},
	)

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			plan := remediation.RemediationPlan{
				ActionType:      tc.actionType,
				TargetGVK:       tc.targetGVK,
				TargetNamespace: tc.targetNamespace,
				RiskLevel:       tc.declaredRisk,
			}
			wantRank := approvalRiskLevelRank[remediation.EffectiveRiskLevel(plan)]

			var gotRank int
			query := `SELECT (` + approvalRiskRankExpr + `) FROM (VALUES ($1::text, $2::text, $3::text, $4::text)) AS rr(action_type, target_gvk, target_namespace, risk_level)`
			if err := pool.QueryRow(context.Background(), query,
				string(tc.actionType), tc.targetGVK, tc.targetNamespace, string(tc.declaredRisk)).Scan(&gotRank); err != nil {
				t.Fatalf("SQL rank query: %v", err)
			}
			if gotRank != wantRank {
				t.Errorf("SQL rank = %d, Go EffectiveRiskLevel rank = %d (Go value %q) for %+v", gotRank, wantRank, remediation.EffectiveRiskLevel(plan), tc)
			}
		})
	}
}

// --- 2/3. handleListApprovals: filter/sort/cursor/counts fixture ---

type approvalQueryFixture struct {
	tenantID   string
	clusterA   string
	clusterB   string
	incidents  []string // clusterA's six pending incidents (inc1..inc6), oldest first_seen first
	approvedID string   // clusterA's already-approved incident
	otherID    string   // clusterB's pending incident
}

// setupApprovalQueryFixture builds, on clusterA: six pending incidents
// (AwaitingApproval x5 + one AwaitingMerge) spread across ascending
// first_seen and a low/medium/high risk mix (three ScaleDeployment=low, two
// RestartPod=medium, one DeleteResource=high — each declared AT its own
// floor, so effective risk is unambiguous without touching any modifier),
// plus one already-approved plan. On clusterB: one pending incident, purely
// so ?clusterId= has something real to exclude.
func setupApprovalQueryFixture(t *testing.T, pool *pgxpool.Pool) approvalQueryFixture {
	t.Helper()
	ctx := context.Background()

	f := approvalQueryFixture{
		clusterA: domain.NewID(domain.PrefixCluster),
		clusterB: domain.NewID(domain.PrefixCluster),
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
	if err := data.SetRequestScope(ctx, tx, f.tenantID, []string{f.clusterA, f.clusterB}); err != nil {
		t.Fatalf("scope: %v", err)
	}

	fixture := dbtest.New(t)

	for _, c := range []string{f.clusterA, f.clusterB} {
		if _, err := tx.Exec(ctx,
			`INSERT INTO clusters (id, tenant_id, display_name, state, shard_id, cluster_fingerprint)
			 VALUES ($1, $2, $3, 'Active', 'shard-test', $4)`,
			c, f.tenantID, "approval-query-test-"+c, "fp-"+c); err != nil {
			t.Fatalf("insert cluster %s: %v", c, err)
		}
		fixture.Created("clusters", 1)
	}

	now := time.Now()

	type row struct {
		state      string
		severity   string
		actionType remediation.ActionType
		targetGVK  string
		riskLevel  string
		paramsJSON string
	}
	rows := []row{
		{orchestrator.StateAwaitingApproval, "critical", remediation.ActionScaleDeployment, "apps/v1/Deployment", "low", `{"replicas":3}`},
		{orchestrator.StateAwaitingApproval, "high", remediation.ActionRestartPod, "v1/Pod", "medium", `{}`},
		{orchestrator.StateAwaitingApproval, "medium", remediation.ActionDeleteResource, "v1/ConfigMap", "high", `{}`},
		{orchestrator.StateAwaitingApproval, "low", remediation.ActionScaleDeployment, "apps/v1/Deployment", "low", `{"replicas":2}`},
		{orchestrator.StateAwaitingApproval, "critical", remediation.ActionRestartPod, "v1/Pod", "medium", `{}`},
		{orchestrator.StateAwaitingMerge, "medium", remediation.ActionScaleDeployment, "apps/v1/Deployment", "low", `{"replicas":4}`},
	}

	for i, rw := range rows {
		incidentID := domain.NewID(domain.PrefixIncident)
		firstSeen := now.Add(time.Duration(i-len(rows)) * time.Hour) // strictly ascending, all in the past
		if _, err := tx.Exec(ctx,
			`INSERT INTO incidents (id, tenant_id, cluster_id, fingerprint, severity, state, first_seen, last_seen, occurrence_count)
			 VALUES ($1, $2, $3, $4, $5, $6, $7, $7, 1)`,
			incidentID, f.tenantID, f.clusterA, "approval-query-"+incidentID, rw.severity, rw.state, firstSeen); err != nil {
			t.Fatalf("insert incident %d: %v", i, err)
		}
		fixture.Created("incidents", 1)

		analysisID := domain.NewID(domain.PrefixAnalysis)
		if _, err := tx.Exec(ctx,
			`INSERT INTO analyses (id, tenant_id, incident_id, cluster_id, prompt_version, model, causal_chain, ruled_out, confidence, iterations, duration_ms, tokens_billed_in, tokens_cache_read, tokens_out, cost_usd)
			 VALUES ($1,$2,$3,$4,'test','test-model','[]'::jsonb,'[]'::jsonb,0.9,1,1,0,0,0,0)`,
			analysisID, f.tenantID, incidentID, f.clusterA); err != nil {
			t.Fatalf("insert analysis %d: %v", i, err)
		}
		fixture.Created("analyses", 1)

		planID := domain.NewID(domain.PrefixPlan)
		if _, err := tx.Exec(ctx,
			`INSERT INTO remediation_recommendations (
			   id, incident_id, tenant_id, cluster_id, analysis_id, action_type,
			   target_gvk, target_namespace, target_name, params, reversible, risk_level,
			   gate_outcome, gate_reason
			 ) VALUES ($1,$2,$3,$4,$5,$6,$7,'default','target',$8::jsonb,true,$9,'NeedsApproval','test')`,
			planID, incidentID, f.tenantID, f.clusterA, analysisID, string(rw.actionType), rw.targetGVK, rw.paramsJSON, rw.riskLevel); err != nil {
			t.Fatalf("insert recommendation %d: %v", i, err)
		}
		fixture.Created("remediation_recommendations", 1)

		f.incidents = append(f.incidents, incidentID)
	}

	// The already-approved plan: a normal AwaitingApproval row (approving
	// never moves an OpenPR-shaped decision off this queue — see approvals.go's
	// own doc comment) with a matching remediation_approval_decisions row.
	f.approvedID = domain.NewID(domain.PrefixIncident)
	if _, err := tx.Exec(ctx,
		`INSERT INTO incidents (id, tenant_id, cluster_id, fingerprint, severity, state, first_seen, last_seen, occurrence_count)
		 VALUES ($1, $2, $3, $4, 'high', $5, $6, $6, 1)`,
		f.approvedID, f.tenantID, f.clusterA, "approval-query-approved-"+f.approvedID, orchestrator.StateAwaitingApproval, now); err != nil {
		t.Fatalf("insert approved incident: %v", err)
	}
	fixture.Created("incidents", 1)
	approvedAnalysisID := domain.NewID(domain.PrefixAnalysis)
	if _, err := tx.Exec(ctx,
		`INSERT INTO analyses (id, tenant_id, incident_id, cluster_id, prompt_version, model, causal_chain, ruled_out, confidence, iterations, duration_ms, tokens_billed_in, tokens_cache_read, tokens_out, cost_usd)
		 VALUES ($1,$2,$3,$4,'test','test-model','[]'::jsonb,'[]'::jsonb,0.9,1,1,0,0,0,0)`,
		approvedAnalysisID, f.tenantID, f.approvedID, f.clusterA); err != nil {
		t.Fatalf("insert approved analysis: %v", err)
	}
	fixture.Created("analyses", 1)
	approvedPlanID := domain.NewID(domain.PrefixPlan)
	if _, err := tx.Exec(ctx,
		`INSERT INTO remediation_recommendations (
		   id, incident_id, tenant_id, cluster_id, analysis_id, action_type,
		   target_gvk, target_namespace, target_name, params, reversible, risk_level,
		   gate_outcome, gate_reason
		 ) VALUES ($1,$2,$3,$4,$5,'ScaleDeployment','apps/v1/Deployment','default','target','{"replicas":1}'::jsonb,true,'low','NeedsApproval','test')`,
		approvedPlanID, f.approvedID, f.tenantID, f.clusterA, approvedAnalysisID); err != nil {
		t.Fatalf("insert approved recommendation: %v", err)
	}
	fixture.Created("remediation_recommendations", 1)
	decisionID := domain.NewID(domain.PrefixApproval)
	if _, err := tx.Exec(ctx,
		`INSERT INTO remediation_approval_decisions (id, recommendation_id, incident_id, tenant_id, cluster_id, actor_id, verdict, reason)
		 VALUES ($1,$2,$3,$4,$5,$6,'approved',NULL)`,
		decisionID, approvedPlanID, f.approvedID, f.tenantID, f.clusterA, "usr_approval_query_test"); err != nil {
		t.Fatalf("insert approval decision: %v", err)
	}
	fixture.Created("remediation_approval_decisions", 1)

	// clusterB's own pending incident, purely so ?clusterId=clusterA has
	// something real to exclude.
	f.otherID = domain.NewID(domain.PrefixIncident)
	if _, err := tx.Exec(ctx,
		`INSERT INTO incidents (id, tenant_id, cluster_id, fingerprint, severity, state, first_seen, last_seen, occurrence_count)
		 VALUES ($1, $2, $3, $4, 'high', $5, $6, $6, 1)`,
		f.otherID, f.tenantID, f.clusterB, "approval-query-other-"+f.otherID, orchestrator.StateAwaitingApproval, now); err != nil {
		t.Fatalf("insert clusterB incident: %v", err)
	}
	fixture.Created("incidents", 1)
	otherAnalysisID := domain.NewID(domain.PrefixAnalysis)
	if _, err := tx.Exec(ctx,
		`INSERT INTO analyses (id, tenant_id, incident_id, cluster_id, prompt_version, model, causal_chain, ruled_out, confidence, iterations, duration_ms, tokens_billed_in, tokens_cache_read, tokens_out, cost_usd)
		 VALUES ($1,$2,$3,$4,'test','test-model','[]'::jsonb,'[]'::jsonb,0.9,1,1,0,0,0,0)`,
		otherAnalysisID, f.tenantID, f.otherID, f.clusterB); err != nil {
		t.Fatalf("insert clusterB analysis: %v", err)
	}
	fixture.Created("analyses", 1)
	otherPlanID := domain.NewID(domain.PrefixPlan)
	if _, err := tx.Exec(ctx,
		`INSERT INTO remediation_recommendations (
		   id, incident_id, tenant_id, cluster_id, analysis_id, action_type,
		   target_gvk, target_namespace, target_name, params, reversible, risk_level,
		   gate_outcome, gate_reason
		 ) VALUES ($1,$2,$3,$4,$5,'RestartPod','v1/Pod','default','target','{}'::jsonb,true,'medium','NeedsApproval','test')`,
		otherPlanID, f.otherID, f.tenantID, f.clusterB, otherAnalysisID); err != nil {
		t.Fatalf("insert clusterB recommendation: %v", err)
	}
	fixture.Created("remediation_recommendations", 1)

	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit setup: %v", err)
	}

	fixture.Cleanup(pool, func(ctx context.Context, tx pgx.Tx) error {
		return data.SetRequestScope(ctx, tx, f.tenantID, []string{f.clusterA, f.clusterB})
	}, []dbtest.TableDelete{
		{Table: "remediation_approval_decisions", SQL: `DELETE FROM remediation_approval_decisions WHERE cluster_id IN ($1, $2)`, Args: []any{f.clusterA, f.clusterB}},
		{Table: "remediation_recommendations", SQL: `DELETE FROM remediation_recommendations WHERE cluster_id IN ($1, $2)`, Args: []any{f.clusterA, f.clusterB}},
		{Table: "analyses", SQL: `DELETE FROM analyses WHERE cluster_id IN ($1, $2)`, Args: []any{f.clusterA, f.clusterB}},
		{Table: "incidents", SQL: `DELETE FROM incidents WHERE cluster_id IN ($1, $2)`, Args: []any{f.clusterA, f.clusterB}},
		{Table: "clusters", SQL: `DELETE FROM clusters WHERE id IN ($1, $2)`, Args: []any{f.clusterA, f.clusterB}},
	})

	return f
}

// callListApprovals runs handleListApprovals against a fresh request-scoped
// transaction — the same shape incidents_importance_db_test.go's
// callListIncidentsScoped uses for handleListIncidents.
func callListApprovals(t *testing.T, pool *pgxpool.Pool, tenantID string, clusterIDs []string, rawQuery string) (int, map[string]any) {
	t.Helper()
	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin request transaction: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if err := data.SetRequestScope(ctx, tx, tenantID, clusterIDs); err != nil {
		t.Fatalf("set request scope: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/approvals?"+rawQuery, nil)
	rec := httptest.NewRecorder()
	s := &Server{}
	s.handleListApprovals(rec, req, &requestContext{Tx: tx, TenantID: tenantID})

	var body map[string]any
	if len(rec.Body.Bytes()) > 0 {
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatalf("unmarshal response: %v (body: %s)", err, rec.Body.String())
		}
	}
	return rec.Code, body
}

func approvalIDs(t *testing.T, body map[string]any) []string {
	t.Helper()
	rows, _ := body["approvals"].([]any)
	ids := make([]string, 0, len(rows))
	for _, item := range rows {
		row, ok := item.(map[string]any)
		if !ok {
			t.Fatalf("approvals row is not an object: %v", item)
		}
		ids = append(ids, row["incidentId"].(string))
	}
	return ids
}

func TestHandleListApprovals_ScopeFilterAndCounts(t *testing.T) {
	connString := skipIfNoTestDB(t)
	pool, err := pgxpool.New(context.Background(), connString)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(pool.Close)

	f := setupApprovalQueryFixture(t, pool)

	// clusterId alone: exactly clusterA's 6 pending rows, none of clusterB's.
	code, body := callListApprovals(t, pool, f.tenantID, []string{f.clusterA, f.clusterB}, "clusterId="+f.clusterA+"&limit=100")
	if code != http.StatusOK {
		t.Fatalf("status = %d, body: %+v", code, body)
	}
	ids := approvalIDs(t, body)
	if len(ids) != 6 {
		t.Fatalf("clusterId=clusterA returned %d rows, want 6 (got %v)", len(ids), ids)
	}
	for _, id := range ids {
		if id == f.otherID {
			t.Errorf("clusterId=clusterA row set includes clusterB's incident %s", f.otherID)
		}
	}
	counts, _ := body["counts"].(map[string]any)
	if counts == nil {
		t.Fatalf("counts missing from response: %+v", body)
	}
	// THE regression: counts.pending must equal the number of rows actually
	// returned under this exact scope, not a number computed some other way.
	if got := int(counts["pending"].(float64)); got != len(ids) {
		t.Errorf("counts.pending = %d, want %d (must equal the returned row count under the same filter)", got, len(ids))
	}
	if got := int(counts["approved"].(float64)); got != 1 {
		t.Errorf("counts.approved = %v, want 1", counts["approved"])
	}
	if got, want := int(counts["high"].(float64)), 1; got != want {
		t.Errorf("counts.high = %d, want %d", got, want)
	}
	if got, want := int(counts["medium"].(float64)), 2; got != want {
		t.Errorf("counts.medium = %d, want %d", got, want)
	}
	if got, want := int(counts["low"].(float64)), 3; got != want {
		t.Errorf("counts.low = %d, want %d", got, want)
	}

	// actionType narrows both rows AND counts.pending together (they share
	// approvalScopeFilter) — three ScaleDeployment rows on clusterA.
	code, body = callListApprovals(t, pool, f.tenantID, []string{f.clusterA}, "clusterId="+f.clusterA+"&actionType=ScaleDeployment&limit=100")
	if code != http.StatusOK {
		t.Fatalf("status = %d, body: %+v", code, body)
	}
	ids = approvalIDs(t, body)
	if len(ids) != 3 {
		t.Fatalf("actionType=ScaleDeployment returned %d rows, want 3 (got %v)", len(ids), ids)
	}
	counts, _ = body["counts"].(map[string]any)
	if got := int(counts["pending"].(float64)); got != 3 {
		t.Errorf("counts.pending under actionType=ScaleDeployment = %d, want 3 (must match the 3 returned rows)", got)
	}
	// The risk breakdown is scoped by actionType too (approvalScopeFilter's
	// includeRiskLevel=false path still applies clusterId/actionType) — every
	// ScaleDeployment row here is low risk.
	if got := int(counts["high"].(float64)); got != 0 {
		t.Errorf("counts.high under actionType=ScaleDeployment = %d, want 0", got)
	}
	if got := int(counts["low"].(float64)); got != 3 {
		t.Errorf("counts.low under actionType=ScaleDeployment = %d, want 3", got)
	}

	// riskLevel narrows the ROWS to exactly the one DeleteResource(high)
	// incident, and counts.pending must equal that same narrowed set — while
	// counts.high (the breakdown, deliberately NOT scoped by riskLevel) still
	// reports the whole cluster's real high-risk total (also 1, here, but for
	// an independent reason: it is a total, not an echo of the filter).
	code, body = callListApprovals(t, pool, f.tenantID, []string{f.clusterA}, "clusterId="+f.clusterA+"&riskLevel=high&limit=100")
	if code != http.StatusOK {
		t.Fatalf("status = %d, body: %+v", code, body)
	}
	ids = approvalIDs(t, body)
	if len(ids) != 1 {
		t.Fatalf("riskLevel=high returned %d rows, want 1 (got %v)", len(ids), ids)
	}
	if ids[0] != f.incidents[2] {
		t.Errorf("riskLevel=high returned incident %s, want the DeleteResource incident %s", ids[0], f.incidents[2])
	}
	counts, _ = body["counts"].(map[string]any)
	if got := int(counts["pending"].(float64)); got != 1 {
		t.Errorf("counts.pending under riskLevel=high = %d, want 1 (must match the 1 returned row)", got)
	}

	// alreadyApproved=true switches buckets entirely: exactly the approved
	// incident, and only it.
	code, body = callListApprovals(t, pool, f.tenantID, []string{f.clusterA}, "clusterId="+f.clusterA+"&alreadyApproved=true&limit=100")
	if code != http.StatusOK {
		t.Fatalf("status = %d, body: %+v", code, body)
	}
	ids = approvalIDs(t, body)
	if len(ids) != 1 || ids[0] != f.approvedID {
		t.Errorf("alreadyApproved=true returned %v, want exactly [%s]", ids, f.approvedID)
	}
}

func TestHandleListApprovals_SortAndCursorPagination(t *testing.T) {
	connString := skipIfNoTestDB(t)
	pool, err := pgxpool.New(context.Background(), connString)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(pool.Close)

	f := setupApprovalQueryFixture(t, pool)

	// Default sort ("waiting"): oldest first_seen first. Walk the whole
	// clusterA pending set two rows at a time via ?cursor=, and confirm it
	// comes back in exactly the ascending order the fixture inserted, with no
	// duplicates and no omissions — proving the endpoint (not the browser)
	// now owns both the ordering and the page boundary.
	var collected []string
	cursor := ""
	pages := 0
	for {
		q := "clusterId=" + f.clusterA + "&limit=2"
		if cursor != "" {
			q += "&cursor=" + cursor
		}
		code, body := callListApprovals(t, pool, f.tenantID, []string{f.clusterA}, q)
		if code != http.StatusOK {
			t.Fatalf("status = %d, body: %+v", code, body)
		}
		ids := approvalIDs(t, body)
		if len(ids) > 2 {
			t.Fatalf("page returned %d rows, want at most the requested limit of 2 — the endpoint must stop fetching rows it will not show", len(ids))
		}
		collected = append(collected, ids...)
		pages++
		if pages > 10 {
			t.Fatalf("did not terminate after 10 pages — cursor is not advancing")
		}
		next, ok := body["nextCursor"].(string)
		if !ok || next == "" {
			break
		}
		cursor = next
	}
	if len(collected) != 6 {
		t.Fatalf("collected %d incidents across %d pages, want the fixture's 6 pending incidents (got %v)", len(collected), pages, collected)
	}
	if pages < 3 {
		t.Errorf("collected everything in %d page(s) at limit=2 for 6 rows — pagination is not actually bounding the response", pages)
	}
	for i, id := range collected {
		if id != f.incidents[i] {
			t.Errorf("waiting-sort position %d = incident %s, want %s (fixture's ascending first_seen order)", i, id, f.incidents[i])
		}
	}

	// ?sort=risk, default direction (desc — highest risk first): the one
	// DeleteResource(high) row must lead every ScaleDeployment/RestartPod row.
	_, body := callListApprovals(t, pool, f.tenantID, []string{f.clusterA}, "clusterId="+f.clusterA+"&sort=risk&limit=100")
	ids := approvalIDs(t, body)
	if len(ids) == 0 || ids[0] != f.incidents[2] {
		t.Errorf("sort=risk order = %v, want the high-risk incident %s first", ids, f.incidents[2])
	}

	// ?sort=severity, default direction (desc — most severe first): the two
	// "critical" incidents (index 0 and 4) must both sort ahead of the "low"
	// one (index 3).
	_, body = callListApprovals(t, pool, f.tenantID, []string{f.clusterA}, "clusterId="+f.clusterA+"&sort=severity&limit=100")
	ids = approvalIDs(t, body)
	pos := map[string]int{}
	for i, id := range ids {
		pos[id] = i
	}
	if pos[f.incidents[3]] < pos[f.incidents[0]] || pos[f.incidents[3]] < pos[f.incidents[4]] {
		t.Errorf("sort=severity order = %v, want the low-severity incident %s after both critical incidents (%s, %s)",
			ids, f.incidents[3], f.incidents[0], f.incidents[4])
	}

	// A cursor minted for one sort key must be refused under a different one
	// — the same "cursor/sort must agree" rule incidents.go enforces.
	riskCursor := encodeIncidentSortCursor(f.incidents[0], "risk", "1")
	code, badBody := callListApprovals(t, pool, f.tenantID, []string{f.clusterA}, "clusterId="+f.clusterA+"&sort=severity&cursor="+riskCursor)
	if code != http.StatusBadRequest {
		t.Errorf("sort=severity with a risk-minted cursor: status = %d, want 400 (body: %+v)", code, badBody)
	}
}

func TestHandleListApprovals_InvalidParameters(t *testing.T) {
	connString := skipIfNoTestDB(t)
	pool, err := pgxpool.New(context.Background(), connString)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(pool.Close)

	f := setupApprovalQueryFixture(t, pool)

	cases := []string{
		"clusterId=" + f.clusterA + "&actionType=NotARealAction",
		"clusterId=" + f.clusterA + "&riskLevel=extreme",
		"clusterId=" + f.clusterA + "&alreadyApproved=maybe",
		"clusterId=" + f.clusterA + "&sort=alphabetical",
		"clusterId=" + f.clusterA + "&direction=sideways",
		"clusterId=" + f.clusterA + "&limit=0",
		"clusterId=" + f.clusterA + "&limit=999999",
		"clusterId=" + f.clusterA + "&cursor=not-a-real-cursor",
	}
	for _, q := range cases {
		code, body := callListApprovals(t, pool, f.tenantID, []string{f.clusterA}, q)
		if code != http.StatusBadRequest {
			t.Errorf("query %q: status = %d, want 400 (body: %+v)", q, code, body)
		}
	}
}
