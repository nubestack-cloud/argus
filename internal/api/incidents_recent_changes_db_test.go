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

// PROJECT.md T15 against a real Postgres, RLS included. Run with
// ARGUS_TEST_DATABASE_URL pointed at argus_app (not postgres — see this
// package's own auth_test.go and RUNBOOK.md: the postgres role carries
// BYPASSRLS and would make every RLS assertion here vacuous).
//
// This proves the two halves of the acceptance bar that a pure-Go test
// cannot: that getRecentChanges reads REAL analyses.causal_chain and REAL
// mcp_tool_call_content rows — the two backends' own stored evidence, never
// a live cluster call — and that "no evidence at all" and "evidence, but
// nothing relevant" render as the two DIFFERENT answers PROJECT.md T15
// requires (nil vs. non-nil-with-empty-items).

type recentChangesFixture struct {
	tenantID  string
	clusterID string
	// incNoAnalysis never had an analysis run at all — state A ("we have no
	// evidence for this incident").
	incNoAnalysis string
	// incLookedNothing has a real analysis that made a real tool call, whose
	// result carries nothing this feature recognises as a change — state B
	// ("we looked and found nothing relevant").
	incLookedNothing string
	// incWithChange has a real analysis whose causal chain carries a
	// ScalingReplicaSet event inside the window — the positive case.
	incWithChange string
	// incCliBackend has NO causal chain content (mirrors the cli backend,
	// migration 000069's header) but a real mcp_tool_call_content row with a
	// Pulling event inside the window — proves the second backend's own
	// storage is read too.
	incCliBackend string
	firstSeen     time.Time
}

func setupRecentChangesFixture(t *testing.T, pool *pgxpool.Pool) recentChangesFixture {
	t.Helper()
	ctx := context.Background()

	f := recentChangesFixture{
		clusterID:        domain.NewID(domain.PrefixCluster),
		incNoAnalysis:    domain.NewID(domain.PrefixIncident),
		incLookedNothing: domain.NewID(domain.PrefixIncident),
		incWithChange:    domain.NewID(domain.PrefixIncident),
		incCliBackend:    domain.NewID(domain.PrefixIncident),
		firstSeen:        time.Now().UTC().Truncate(time.Second),
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
	if err := data.SetRequestScope(ctx, tx, f.tenantID, []string{f.clusterID}); err != nil {
		t.Fatalf("scope: %v", err)
	}

	if _, err := tx.Exec(ctx,
		`INSERT INTO clusters (id, tenant_id, display_name, state, shard_id, cluster_fingerprint)
		 VALUES ($1, $2, $3, 'Active', 'shard-test', $4)`,
		f.clusterID, f.tenantID, "t15-recent-changes-"+f.clusterID, "fp-"+f.clusterID); err != nil {
		t.Fatalf("insert cluster: %v", err)
	}

	insertIncident := func(id string) {
		if _, err := tx.Exec(ctx,
			`INSERT INTO incidents (id, tenant_id, cluster_id, fingerprint, severity, state, first_seen, last_seen, occurrence_count)
			 VALUES ($1, $2, $3, $4, 'high', 'Investigating', $5, $5, 1)`,
			id, f.tenantID, f.clusterID, "t15fp-"+id, f.firstSeen); err != nil {
			t.Fatalf("insert incident %s: %v", id, err)
		}
	}
	insertIncident(f.incNoAnalysis)
	insertIncident(f.incLookedNothing)
	insertIncident(f.incWithChange)
	insertIncident(f.incCliBackend)

	// incLookedNothing: a real describe_resource call whose object was
	// created 100h before first_seen — real evidence, outside the
	// 24h window, and carrying no event.
	outsideWindow := f.firstSeen.Add(-100 * time.Hour).Format(time.RFC3339)
	lookedNothingChain := `[{
		"step": 1, "hypothesis": "check the deployment", "finding": "",
		"toolCalls": [{
			"tool": "describe_resource",
			"args": {"gvk": "apps/v1/Deployment", "namespace": "prod", "name": "web"},
			"result": {"object": {"kind": "Deployment", "metadata": {"name": "web", "namespace": "prod", "creationTimestamp": "` + outsideWindow + `"}}, "events": []},
			"evidenceId": "ev_test1"
		}]
	}]`

	// incWithChange: a get_events call carrying one ScalingReplicaSet event
	// 2h before first_seen (inside the window) and one Scheduled event that
	// must NOT be surfaced.
	insideWindow := f.firstSeen.Add(-2 * time.Hour).Format(time.RFC3339)
	withChangeChain := `[{
		"step": 1, "hypothesis": "check recent events", "finding": "",
		"toolCalls": [{
			"tool": "get_events",
			"args": {"namespace": "prod"},
			"result": [
				{"namespace": "prod", "involvedObjectKind": "Deployment", "involvedObjectName": "web", "reason": "ScalingReplicaSet", "message": "Scaled up replica set web-abc123 to 3 from 1", "type": "Normal", "lastTimestamp": "` + insideWindow + `"},
				{"namespace": "prod", "involvedObjectKind": "Pod", "involvedObjectName": "web-1", "reason": "Scheduled", "message": "Successfully assigned prod/web-1 to node-3", "type": "Normal", "lastTimestamp": "` + insideWindow + `"}
			],
			"evidenceId": "ev_test2"
		}]
	}]`

	insertAnalysis := func(id, incidentID, causalChain string) {
		if _, err := tx.Exec(ctx,
			`INSERT INTO analyses (id, tenant_id, incident_id, cluster_id, prompt_version, model,
			    causal_chain, iterations, duration_ms, tokens_billed_in, tokens_cache_read, tokens_out, cost_usd)
			 VALUES ($1,$2,$3,$4,'test','test-model',$5::jsonb,1,1,0,0,0,0)`,
			id, f.tenantID, incidentID, f.clusterID, causalChain); err != nil {
			t.Fatalf("insert analysis for %s: %v", incidentID, err)
		}
	}
	insertAnalysis(domain.NewID(domain.PrefixAnalysis), f.incLookedNothing, lookedNothingChain)
	insertAnalysis(domain.NewID(domain.PrefixAnalysis), f.incWithChange, withChangeChain)
	// incCliBackend: an analysis row exists (as a real cli-backend run would
	// leave), but with an EMPTY causal chain — migration 000069's own point.
	insertAnalysis(domain.NewID(domain.PrefixAnalysis), f.incCliBackend, `[]`)

	// incCliBackend's real evidence lives here instead — a Pulling event 1h
	// before first_seen.
	pullingAt := f.firstSeen.Add(-1 * time.Hour).Format(time.RFC3339)
	if _, err := tx.Exec(ctx,
		`INSERT INTO mcp_tool_call_content (id, tenant_id, cluster_id, incident_id, tool, outcome, args, result)
		 VALUES ($1, $2, $3, $4, 'get_events', 'ok', '{}'::jsonb, $5::jsonb)`,
		domain.NewID(domain.PrefixMCPToolCallContent), f.tenantID, f.clusterID, f.incCliBackend,
		`[{"namespace":"prod","involvedObjectKind":"Pod","involvedObjectName":"web-1","reason":"Pulling","message":"Pulling image \"nginx:1.26\"","type":"Normal","lastTimestamp":"`+pullingAt+`"}]`,
	); err != nil {
		t.Fatalf("insert mcp_tool_call_content: %v", err)
	}

	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit setup: %v", err)
	}

	fixture := dbtest.New(t)
	fixture.Created("clusters", 1)
	fixture.Created("incidents", 4)
	fixture.Created("analyses", 3)
	fixture.Created("mcp_tool_call_content", 1)
	fixture.Cleanup(pool, func(ctx context.Context, tx pgx.Tx) error {
		return data.SetRequestScope(ctx, tx, f.tenantID, []string{f.clusterID})
	}, []dbtest.TableDelete{
		{Table: "mcp_tool_call_content", SQL: `DELETE FROM mcp_tool_call_content WHERE cluster_id = $1`, Args: []any{f.clusterID}},
		{Table: "analyses", SQL: `DELETE FROM analyses WHERE cluster_id = $1`, Args: []any{f.clusterID}},
		{Table: "incidents", SQL: `DELETE FROM incidents WHERE cluster_id = $1`, Args: []any{f.clusterID}},
		{Table: "clusters", SQL: `DELETE FROM clusters WHERE id = $1`, Args: []any{f.clusterID}},
	})

	return f
}

func TestGetRecentChangesNoAnalysisIsNilNotEmpty(t *testing.T) {
	pool := authTestPool(t)
	f := setupRecentChangesFixture(t, pool)
	ctx := context.Background()

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if err := data.SetRequestScope(ctx, tx, f.tenantID, []string{f.clusterID}); err != nil {
		t.Fatalf("scope: %v", err)
	}

	got, err := getRecentChanges(ctx, tx, f.incNoAnalysis, f.firstSeen, nil, nil)
	if err != nil {
		t.Fatalf("getRecentChanges: %v", err)
	}
	if got != nil {
		t.Fatalf("getRecentChanges for an incident with no analysis and no recorded tool calls = %+v, want nil — this is state A (\"we have no evidence\"), and rendering it as an empty list would fabricate a fact", got)
	}
}

func TestGetRecentChangesLookedButNothingRelevantIsEmptyNotNil(t *testing.T) {
	pool := authTestPool(t)
	f := setupRecentChangesFixture(t, pool)
	ctx := context.Background()

	analysis, err := getLatestAnalysisForTest(t, pool, f.tenantID, f.clusterID, f.incLookedNothing)
	if err != nil {
		t.Fatalf("getLatestAnalysis: %v", err)
	}
	if analysis == nil {
		t.Fatal("test setup bug: expected a stored analysis")
	}

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if err := data.SetRequestScope(ctx, tx, f.tenantID, []string{f.clusterID}); err != nil {
		t.Fatalf("scope: %v", err)
	}

	got, err := getRecentChanges(ctx, tx, f.incLookedNothing, f.firstSeen, analysis, nil)
	if err != nil {
		t.Fatalf("getRecentChanges: %v", err)
	}
	if got == nil {
		t.Fatal("getRecentChanges = nil, want non-nil — a real tool call WAS recorded (describe_resource), so this must be state B (\"looked, found nothing relevant\"), not state A")
	}
	if len(got.Items) != 0 {
		t.Errorf("Items = %+v, want empty — the only recorded fact (an object created 100h before first_seen) is outside the 24h window and carries no event", got.Items)
	}
	if got.WindowHours != 24 {
		t.Errorf("WindowHours = %d, want 24", got.WindowHours)
	}
}

func TestGetRecentChangesFindsAndLabelsARealChange(t *testing.T) {
	pool := authTestPool(t)
	f := setupRecentChangesFixture(t, pool)
	ctx := context.Background()

	analysis, err := getLatestAnalysisForTest(t, pool, f.tenantID, f.clusterID, f.incWithChange)
	if err != nil {
		t.Fatalf("getLatestAnalysis: %v", err)
	}

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if err := data.SetRequestScope(ctx, tx, f.tenantID, []string{f.clusterID}); err != nil {
		t.Fatalf("scope: %v", err)
	}

	got, err := getRecentChanges(ctx, tx, f.incWithChange, f.firstSeen, analysis, nil)
	if err != nil {
		t.Fatalf("getRecentChanges: %v", err)
	}
	if got == nil {
		t.Fatal("getRecentChanges = nil, want a populated view")
	}
	if len(got.Items) != 1 {
		t.Fatalf("Items = %+v, want exactly 1 (the Scheduled event must be dropped, only ScalingReplicaSet counts)", got.Items)
	}
	item := got.Items[0]
	if item.Category != "replica_change" {
		t.Errorf("Category = %q, want %q", item.Category, "replica_change")
	}
	if item.Source != "get_events" {
		t.Errorf("Source = %q, want %q — source-labelled means the exact tool it came from", item.Source, "get_events")
	}
	if item.ObjectName != "web" || item.ObjectKind != "Deployment" {
		t.Errorf("object identity = %q/%q, want web/Deployment", item.ObjectKind, item.ObjectName)
	}
}

func TestGetRecentChangesReadsCliBackendContentTable(t *testing.T) {
	pool := authTestPool(t)
	f := setupRecentChangesFixture(t, pool)
	ctx := context.Background()

	// incCliBackend's analysis has an EMPTY causal chain (mirrors the real
	// cli backend). Its only evidence lives in mcp_tool_call_content.
	analysis, err := getLatestAnalysisForTest(t, pool, f.tenantID, f.clusterID, f.incCliBackend)
	if err != nil {
		t.Fatalf("getLatestAnalysis: %v", err)
	}
	if analysis == nil || len(analysis.CausalChain) != 0 {
		t.Fatalf("test setup bug: expected an analysis with an empty causal chain, got %+v", analysis)
	}

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if err := data.SetRequestScope(ctx, tx, f.tenantID, []string{f.clusterID}); err != nil {
		t.Fatalf("scope: %v", err)
	}

	got, err := getRecentChanges(ctx, tx, f.incCliBackend, f.firstSeen, analysis, nil)
	if err != nil {
		t.Fatalf("getRecentChanges: %v", err)
	}
	if got == nil {
		t.Fatal("getRecentChanges = nil, want a populated view built from mcp_tool_call_content")
	}
	if len(got.Items) != 1 {
		t.Fatalf("Items = %+v, want exactly 1 (the Pulling event recorded for the cli backend)", got.Items)
	}
	if got.Items[0].Category != "image_pull" || got.Items[0].Source != "get_events" {
		t.Errorf("Items[0] = %+v, want category=image_pull source=get_events", got.Items[0])
	}
}

// getLatestAnalysisForTest wraps getLatestAnalysis in its own scoped
// transaction — a thin helper so each test above can read the analysis it
// needs without duplicating the begin/scope/commit boilerplate.
func getLatestAnalysisForTest(t *testing.T, pool *pgxpool.Pool, tenantID, clusterID, incidentID string) (*analysisResponse, error) {
	t.Helper()
	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if err := data.SetRequestScope(ctx, tx, tenantID, []string{clusterID}); err != nil {
		return nil, err
	}
	rc := &requestContext{Tx: tx, TenantID: tenantID}
	return getLatestAnalysis(ctx, rc, incidentID)
}
