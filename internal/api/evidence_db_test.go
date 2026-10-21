package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"argus/internal/data"
	"argus/internal/domain"
	"argus/internal/llm"
	"argus/internal/redact"
)

// --- BACKLOG.md B2: persistEvidence and GET /incidents/{id}/evidence/{evId}
// against a real Postgres, RLS included ---
//
// Gated on ARGUS_TEST_DATABASE_URL exactly like this package's authTestPool
// (auth_test.go) and internal/orchestrator/db_test.go — a machine without one
// gets a clean skip. What the DB-free toolloop_test.go coverage (EvidenceID
// assignment) cannot show: that persistEvidence's INSERT and
// handleGetEvidence's SELECT actually agree on the evidence table's real
// shape (migration 000069), that RLS genuinely hides another cluster's row
// rather than merely being configured to, and that a redacted value survives
// the round trip through Postgres unchanged — never re-exposed, never
// re-derived from anything else.

// evidenceFixture is three incidents across two clusters: A and B both on the
// cluster the test's own request transaction will be scoped to, H on a
// SECOND cluster it never is. A and B exist specifically to prove
// handleGetEvidence's incident_id equality check — RLS alone would not catch
// "the right cluster, but the wrong incident's evidence id" (B2 belongs to
// A's cluster, so RLS admits it; the handler must refuse it anyway). H is
// what proves RLS itself: if that policy or its predicate ever stopped
// applying, H's evidence is exactly what would leak into a caller scoped to
// the other cluster.
type evidenceFixture struct {
	tenantID                        string
	visibleCluster, hiddenCluster   string
	incidentA, incidentB, incidentH string
	analysisA, analysisB, analysisH string
}

func setupEvidenceFixture(t *testing.T, pool *pgxpool.Pool) evidenceFixture {
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
	f := evidenceFixture{
		tenantID:       tenantID,
		visibleCluster: domain.NewID(domain.PrefixCluster),
		hiddenCluster:  domain.NewID(domain.PrefixCluster),
		incidentA:      domain.NewID(domain.PrefixIncident),
		incidentB:      domain.NewID(domain.PrefixIncident),
		incidentH:      domain.NewID(domain.PrefixIncident),
		analysisA:      domain.NewID(domain.PrefixAnalysis),
		analysisB:      domain.NewID(domain.PrefixAnalysis),
		analysisH:      domain.NewID(domain.PrefixAnalysis),
	}

	if err := data.SetRequestScope(ctx, tx, tenantID, []string{f.visibleCluster, f.hiddenCluster}); err != nil {
		t.Fatalf("set request scope: %v", err)
	}

	for _, c := range []struct{ id, name string }{
		{f.visibleCluster, "b2-evidence-visible-" + f.visibleCluster},
		{f.hiddenCluster, "b2-evidence-hidden-" + f.hiddenCluster},
	} {
		if _, err := tx.Exec(ctx,
			`INSERT INTO clusters (id, tenant_id, display_name, state, shard_id, cluster_fingerprint)
			 VALUES ($1, $2, $3, 'Active', 'shard-test', $4)`,
			c.id, tenantID, c.name, "fp-"+c.id); err != nil {
			t.Fatalf("insert cluster %s: %v", c.id, err)
		}
	}

	now := time.Now()
	insertIncident := func(id, clusterID string) {
		if _, err := tx.Exec(ctx,
			`INSERT INTO incidents (id, tenant_id, cluster_id, fingerprint, severity, state, first_seen, last_seen, occurrence_count, opening_reason, object_key)
			 VALUES ($1, $2, $3, $4, 'high', 'Investigating', $5, $5, 1, 'OOMKilled', $6)`,
			id, tenantID, clusterID, "b2fp-"+id, now, "v1/Pod|default|b2-"+id); err != nil {
			t.Fatalf("insert incident %s: %v", id, err)
		}
	}
	insertIncident(f.incidentA, f.visibleCluster)
	insertIncident(f.incidentB, f.visibleCluster)
	insertIncident(f.incidentH, f.hiddenCluster)

	insertAnalysis := func(id, incidentID, clusterID string) {
		if _, err := tx.Exec(ctx,
			`INSERT INTO analyses (
			   id, incident_id, tenant_id, cluster_id, prompt_version, model, causal_chain, ruled_out,
			   iterations, duration_ms, tokens_billed_in, tokens_cache_read, tokens_out, cost_usd, cost_basis, created_at
			 ) VALUES ($1, $2, $3, $4, 'v1', 'fake-model', '[]'::jsonb, '[]'::jsonb, 1, 100, 0, 0, 0, 0, 'metered', now())`,
			id, incidentID, tenantID, clusterID); err != nil {
			t.Fatalf("insert analysis %s: %v", id, err)
		}
	}
	insertAnalysis(f.analysisA, f.incidentA, f.visibleCluster)
	insertAnalysis(f.analysisB, f.incidentB, f.visibleCluster)
	insertAnalysis(f.analysisH, f.incidentH, f.hiddenCluster)

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
		clusterIDs := []string{f.visibleCluster, f.hiddenCluster}
		if err := data.SetRequestScope(cleanupCtx, tx, tenantID, clusterIDs); err != nil {
			t.Logf("cleanup: set request scope: %v", err)
			return
		}
		for _, stmt := range []string{
			`DELETE FROM evidence WHERE cluster_id = ANY($1)`,
			`DELETE FROM analyses WHERE cluster_id = ANY($1)`,
			`DELETE FROM incidents WHERE cluster_id = ANY($1)`,
			`DELETE FROM clusters WHERE id = ANY($1)`,
		} {
			if _, err := tx.Exec(cleanupCtx, stmt, clusterIDs); err != nil {
				t.Logf("cleanup: %s: %v", stmt, err)
				return
			}
		}
		if err := tx.Commit(cleanupCtx); err != nil {
			t.Logf("cleanup: commit: %v", err)
		}
	})

	return f
}

// TestPersistEvidenceWritesOneRowPerDispatchedCallAndRedactionSurvives is
// this task's central safety proof: a value that would have been secret
// pre-redaction must be absent from the stored row, and the write path must
// not somehow reconstruct or re-fetch it. The result fed to persistEvidence
// here is built with redact.Object — the SAME function
// internal/agent/tools.go's ToolExecutor.Execute calls agent-side, before the
// tunnel — so this test proves the exact bytes persistEvidence stores are
// what a real investigation's causalChain would actually carry: the secret
// literal never enters this test's Go process in any form persistEvidence
// touches, only the already-redacted result does.
func TestPersistEvidenceWritesOneRowPerDispatchedCallAndRedactionSurvives(t *testing.T) {
	pool := authTestPool(t)
	f := setupEvidenceFixture(t, pool)
	ctx := context.Background()

	const secret = "s3cr3t-db-password-do-not-persist"
	rawDescribe := json.RawMessage(`{
		"kind": "Pod",
		"spec": {"containers": [{"name": "app", "env": [{"name": "DB_PASSWORD", "value": "` + secret + `"}]}]}
	}`)
	redacted := redact.Object(rawDescribe)
	if strings.Contains(string(redacted), secret) {
		t.Fatalf("test setup bug: redact.Object did not actually strip the secret from the fixture — got %s", redacted)
	}

	errMsg := "context deadline exceeded"
	causalChain := []llm.CausalStep{
		{
			Step:       1,
			Hypothesis: "check the pod spec",
			ToolCalls: []llm.ToolCallRecord{
				{
					Tool:       "describe_resource",
					Args:       json.RawMessage(`{"gvk":"v1/Pod","namespace":"default","name":"x"}`),
					Result:     redacted,
					EvidenceID: domain.NewID(domain.PrefixEvidence),
				},
				{
					Tool:       "get_logs",
					Args:       json.RawMessage(`{"namespace":"default","pod":"x"}`),
					Error:      &errMsg,
					EvidenceID: domain.NewID(domain.PrefixEvidence),
				},
				{
					// Shaped like a refused tool call (llm.ToolCallRecord's own
					// doc comment): no EvidenceID, because isOfferedTool would
					// have refused it before callTool ever ran. Included here to
					// prove persistEvidence itself skips it, independent of
					// toolloop_test.go's coverage of WHY it has no id.
					Tool:  "scale_deployment",
					Args:  json.RawMessage(`{}`),
					Error: strPtrForTest("tool \"scale_deployment\" is not available to this investigation"),
				},
			},
		},
	}

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin request transaction: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if err := data.SetRequestScope(ctx, tx, f.tenantID, []string{f.visibleCluster}); err != nil {
		t.Fatalf("set request scope: %v", err)
	}
	if err := persistEvidence(ctx, tx, f.tenantID, f.visibleCluster, f.incidentA, f.analysisA, causalChain); err != nil {
		t.Fatalf("persistEvidence: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit: %v", err)
	}

	// Read back with a superuser-shaped check bypassed by RLS the normal way
	// (still through argus_app, scoped to the visible cluster) — this is the
	// same access path a real caller gets, not a privileged back door.
	tx2, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin verify transaction: %v", err)
	}
	defer tx2.Rollback(ctx) //nolint:errcheck
	if err := data.SetRequestScope(ctx, tx2, f.tenantID, []string{f.visibleCluster}); err != nil {
		t.Fatalf("set request scope: %v", err)
	}

	rows, err := tx2.Query(ctx, `SELECT tool, outcome, args, result, error FROM evidence WHERE analysis_id = $1 ORDER BY tool`, f.analysisA)
	if err != nil {
		t.Fatalf("query evidence: %v", err)
	}
	defer rows.Close()

	type row struct {
		tool, outcome string
		args, result  []byte
		errText       *string
	}
	var got []row
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.tool, &r.outcome, &r.args, &r.result, &r.errText); err != nil {
			t.Fatalf("scan: %v", err)
		}
		got = append(got, r)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("rows: %v", err)
	}

	// Exactly two rows: the refused-shaped call (no EvidenceID) must not have
	// produced a third.
	if len(got) != 2 {
		t.Fatalf("evidence rows for analysis %s = %d, want exactly 2 (the refused call must not persist one)", f.analysisA, len(got))
	}

	byTool := map[string]row{}
	for _, r := range got {
		byTool[r.tool] = r
	}

	describeRow, ok := byTool["describe_resource"]
	if !ok {
		t.Fatal("no evidence row for describe_resource")
	}
	if describeRow.outcome != "ok" {
		t.Errorf("describe_resource outcome = %q, want ok", describeRow.outcome)
	}
	if strings.Contains(string(describeRow.result), secret) {
		t.Errorf("SECRET LEAKED: evidence.result for describe_resource contains the raw secret value: %s", describeRow.result)
	}
	if !strings.Contains(string(describeRow.result), redact.Marker) {
		t.Errorf("evidence.result for describe_resource = %s, want it to contain the redaction marker %q", describeRow.result, redact.Marker)
	}
	if strings.Contains(string(describeRow.args), secret) {
		t.Errorf("SECRET LEAKED: evidence.args for describe_resource contains the raw secret value: %s", describeRow.args)
	}

	logsRow, ok := byTool["get_logs"]
	if !ok {
		t.Fatal("no evidence row for get_logs")
	}
	if logsRow.outcome != "error" {
		t.Errorf("get_logs outcome = %q, want error", logsRow.outcome)
	}
	if logsRow.errText == nil || *logsRow.errText != errMsg {
		t.Errorf("get_logs error = %v, want %q", logsRow.errText, errMsg)
	}
	if logsRow.result != nil {
		t.Errorf("get_logs result = %s, want NULL for an errored call", logsRow.result)
	}

	if _, ok := byTool["scale_deployment"]; ok {
		t.Error("a refused tool call (no EvidenceID) produced an evidence row — it should have been skipped")
	}
}

// strPtrForTest avoids importing strings just for one &s in the fixture
// above (this file already imports strings for the Contains assertions;
// named distinctly from toolloop.go's own strPtr since that lives in a
// different package this test does not import for it).
func strPtrForTest(s string) *string { return &s }

// TestHandleGetEvidenceEnforcesIncidentMatchAndRLS exercises the actual HTTP
// handler (not just persistEvidence) against the three-incident fixture
// above, through a request transaction scoped ONLY to visibleCluster — the
// same construction callListIncidents (incidents_test.go) uses to prove RLS
// against a real handler rather than against SQL run by hand.
func TestHandleGetEvidenceEnforcesIncidentMatchAndRLS(t *testing.T) {
	pool := authTestPool(t)
	f := setupEvidenceFixture(t, pool)
	ctx := context.Background()

	insertEvidence := func(id, analysisID, incidentID, clusterID string) {
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatalf("begin: %v", err)
		}
		defer tx.Rollback(ctx) //nolint:errcheck
		if err := data.SetRequestScope(ctx, tx, f.tenantID, []string{clusterID}); err != nil {
			t.Fatalf("set request scope: %v", err)
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO evidence (id, analysis_id, tenant_id, cluster_id, incident_id, kind, tool, outcome, args, result, size_bytes, redacted, captured_at)
			 VALUES ($1, $2, $3, $4, $5, 'tool_call', 'get_events', 'ok', '{}'::jsonb, '{"items":[]}'::jsonb, 12, true, now())`,
			id, analysisID, f.tenantID, clusterID, incidentID); err != nil {
			t.Fatalf("insert evidence %s: %v", id, err)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatalf("commit: %v", err)
		}
	}

	evA := domain.NewID(domain.PrefixEvidence)
	evB := domain.NewID(domain.PrefixEvidence)
	evH := domain.NewID(domain.PrefixEvidence)
	insertEvidence(evA, f.analysisA, f.incidentA, f.visibleCluster)
	insertEvidence(evB, f.analysisB, f.incidentB, f.visibleCluster)
	insertEvidence(evH, f.analysisH, f.incidentH, f.hiddenCluster)

	call := func(incidentID, evidenceID string) (int, map[string]any) {
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatalf("begin request transaction: %v", err)
		}
		defer tx.Rollback(ctx) //nolint:errcheck
		// Scoped ONLY to visibleCluster — hiddenCluster is never in scope for
		// any of these calls, matching an ordinary caller whose grants do not
		// reach it.
		if err := data.SetRequestScope(ctx, tx, f.tenantID, []string{f.visibleCluster}); err != nil {
			t.Fatalf("set request scope: %v", err)
		}

		req := httptest.NewRequest(http.MethodGet, "/api/v1/incidents/"+incidentID+"/evidence/"+evidenceID, nil)
		req.SetPathValue("id", incidentID)
		req.SetPathValue("evId", evidenceID)
		rec := httptest.NewRecorder()
		s := &Server{}
		s.handleGetEvidence(rec, req, &requestContext{Tx: tx, TenantID: f.tenantID})

		var body map[string]any
		if rec.Body.Len() > 0 {
			if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
				t.Fatalf("unmarshal response (status %d, body %s): %v", rec.Code, rec.Body.String(), err)
			}
		}
		return rec.Code, body
	}

	t.Run("own incident's evidence is readable and shaped correctly", func(t *testing.T) {
		code, body := call(f.incidentA, evA)
		if code != http.StatusOK {
			t.Fatalf("status = %d, body: %+v", code, body)
		}
		if body["tool"] != "get_events" {
			t.Errorf(`body["tool"] = %v, want "get_events"`, body["tool"])
		}
		if body["outcome"] != "ok" {
			t.Errorf(`body["outcome"] = %v, want "ok"`, body["outcome"])
		}
		if body["redacted"] != true {
			t.Errorf(`body["redacted"] = %v, want true`, body["redacted"])
		}
		if body["result"] == nil {
			t.Error(`body["result"] is nil, want the stored result content`)
		}
		if body["incidentId"] != f.incidentA {
			t.Errorf(`body["incidentId"] = %v, want %q`, body["incidentId"], f.incidentA)
		}
	})

	t.Run("right cluster, wrong incident is 404, not the other incident's evidence", func(t *testing.T) {
		code, _ := call(f.incidentA, evB)
		if code != http.StatusNotFound {
			t.Errorf("status = %d, want 404 — evB belongs to incidentB, not incidentA, even though both are on the visible cluster", code)
		}
	})

	t.Run("a hidden cluster's evidence is invisible even when addressed by its own real incident id", func(t *testing.T) {
		code, _ := call(f.incidentH, evH)
		if code != http.StatusNotFound {
			t.Errorf("status = %d, want 404 — RLS must hide evH because hiddenCluster is outside this caller's scope", code)
		}
	})

	t.Run("an id that does not exist at all is 404", func(t *testing.T) {
		code, _ := call(f.incidentA, domain.NewID(domain.PrefixEvidence))
		if code != http.StatusNotFound {
			t.Errorf("status = %d, want 404", code)
		}
	})
}
