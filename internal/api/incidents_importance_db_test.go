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
)

// TestHandleListIncidents_ImportanceSort is PROJECT.md T1's own regression:
// a widely-shared, long-open, frequently-recurring, confidently-diagnosed
// incident must outrank an isolated, fresh, one-off, unanalyzed one under
// ?sort=importance — and the response must say WHY, from the real factors
// the SQL ORDER BY expression scored, not a guess.
func TestHandleListIncidents_ImportanceSort(t *testing.T) {
	pool := authTestPool(t)
	f := setupImportanceFixture(t, pool)

	// Scoped to BOTH clusters, not just f.clusterID: blast radius via
	// fleet_group_id is deliberately cross-cluster (internal/fleetgroup's
	// whole point), and RLS applies to the correlated subquery just like
	// any other query in this transaction's scope — a request scoped to
	// only one cluster would legitimately (and correctly, for that
	// requester) undercount it. This test wants the full-fleet-visibility
	// case T1 is actually about, so it scopes to both.
	code, body := callListIncidentsScoped(t, pool, f.tenantID, []string{f.clusterID, f.fleetPeerCluster}, "sort=importance&direction=desc")
	if code != http.StatusOK {
		t.Fatalf("status = %d, body: %+v", code, body)
	}
	// Both clusters are in scope (needed for blast radius's RLS visibility
	// above), so the fleet-peer incident itself also appears in the list —
	// only the relative order of important/unimportant is asserted, not
	// the full row set.
	got := incidentIDsFrom(body)
	importantAt, unimportantAt := -1, -1
	for i, id := range got {
		if id == f.important {
			importantAt = i
		}
		if id == f.unimportant {
			unimportantAt = i
		}
	}
	if importantAt == -1 || unimportantAt == -1 {
		t.Fatalf("sort=importance&direction=desc = %v, want both %s and %s present", got, f.important, f.unimportant)
	}
	if importantAt >= unimportantAt {
		t.Fatalf("sort=importance&direction=desc = %v, want %s (important) ranked before %s (unimportant)", got, f.important, f.unimportant)
	}

	rows, _ := body["incidents"].([]any)
	var explanation []any
	for _, item := range rows {
		row, _ := item.(map[string]any)
		if row["id"] == f.important {
			explanation, _ = row["importanceExplanation"].([]any)
		}
	}
	if len(explanation) == 0 {
		t.Fatalf("the important incident's importanceExplanation is empty — an operator asking why this ranked first gets no real answer")
	}
	joined := ""
	for _, r := range explanation {
		joined += r.(string) + " | "
	}
	for _, want := range []string{"other open incident", "day(s)", "recurring", "confident"} {
		if !strings.Contains(joined, want) {
			t.Errorf("importanceExplanation = %q, want it to mention %q", joined, want)
		}
	}

	// The unimportant incident's explanation must be absent or empty — it
	// genuinely has nothing standing out on any factor (fresh, isolated,
	// one occurrence, never analysed), and a non-empty explanation here
	// would be a fabricated reason.
	for _, item := range rows {
		row, _ := item.(map[string]any)
		if row["id"] == f.unimportant {
			if exp, ok := row["importanceExplanation"].([]any); ok && len(exp) != 0 {
				t.Errorf("unimportant incident's importanceExplanation = %v, want empty/absent", exp)
			}
		}
	}
}

// TestHandleListIncidents_ImportanceSortOmittedForOtherSorts confirms
// importanceExplanation is never computed (and so never present) for a sort
// mode that isn't importance — the field only means something when THAT
// ranking is the one that actually ran.
func TestHandleListIncidents_ImportanceSortOmittedForOtherSorts(t *testing.T) {
	pool := authTestPool(t)
	f := setupImportanceFixture(t, pool)

	code, body := callListIncidents(t, pool, f.asSearchFixture(), "sort=lastSeen&direction=desc")
	if code != http.StatusOK {
		t.Fatalf("status = %d, body: %+v", code, body)
	}
	rows, _ := body["incidents"].([]any)
	for _, item := range rows {
		row, _ := item.(map[string]any)
		if _, present := row["importanceExplanation"]; present {
			t.Errorf("importanceExplanation present under ?sort=lastSeen for incident %v, want omitted entirely", row["id"])
		}
	}
}

type importanceFixture struct {
	tenantID         string
	clusterID        string
	fleetPeerCluster string
	important        string
	unimportant      string
}

// asSearchFixture adapts importanceFixture to callListIncidents'
// incidentSearchFixture parameter shape for a single-cluster-scoped
// request (used by the "omitted for other sorts" test, which does not care
// about blast radius) — reusing that helper avoids a third near-identical
// request-scoped-transaction wrapper for that case.
func (f importanceFixture) asSearchFixture() incidentSearchFixture {
	return incidentSearchFixture{tenantID: f.tenantID, visibleCluster: f.clusterID}
}

// callListIncidentsScoped mirrors callListIncidents exactly, except it
// scopes the request transaction to an arbitrary cluster ID list rather
// than a single incidentSearchFixture.visibleCluster — needed here because
// blast radius (fleet_group_id) is deliberately cross-cluster, and a
// same-tenant, multi-cluster-scoped requester (e.g. an admin with
// full-fleet visibility) is the realistic case this sort mode is for.
func callListIncidentsScoped(t *testing.T, pool *pgxpool.Pool, tenantID string, clusterIDs []string, rawQuery string) (int, map[string]any) {
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

	req := httptest.NewRequest(http.MethodGet, "/api/v1/incidents?"+rawQuery, nil)
	rec := httptest.NewRecorder()
	s := &Server{}
	s.handleListIncidents(rec, req, &requestContext{Tx: tx, TenantID: tenantID})

	var body map[string]any
	if rec.Code == http.StatusOK {
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatalf("unmarshal response: %v (body: %s)", err, rec.Body.String())
		}
	}
	return rec.Code, body
}

// setupImportanceFixture builds exactly two incidents on ONE cluster:
//
//   - important: occurrence_count=100, first_seen 3 days ago (a real
//     duration/trend signal), sharing a fleet_group_id with ANOTHER
//     (already-resolved) incident on a second cluster (blast radius > 1),
//     and a completed analysis at 0.9 confidence (evidence learned during
//     analysis).
//   - unimportant: occurrence_count=1, first_seen 2 minutes ago, no group,
//     no analysis — genuinely unremarkable on every factor.
func setupImportanceFixture(t *testing.T, pool *pgxpool.Pool) importanceFixture {
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

	f := importanceFixture{
		tenantID:         tenantID,
		clusterID:        domain.NewID(domain.PrefixCluster),
		fleetPeerCluster: domain.NewID(domain.PrefixCluster),
		important:        domain.NewID(domain.PrefixIncident),
		unimportant:      domain.NewID(domain.PrefixIncident),
	}
	fleetPeerCluster := f.fleetPeerCluster
	fleetPeerIncident := domain.NewID(domain.PrefixIncident)
	fleetGroupID := domain.NewID(domain.PrefixIncident) // any distinct string works — this column is freely-generated, not a foreign key to a real table

	if err := data.SetRequestScope(ctx, tx, tenantID, []string{f.clusterID, fleetPeerCluster}); err != nil {
		t.Fatalf("set request scope: %v", err)
	}

	for _, c := range []string{f.clusterID, fleetPeerCluster} {
		if _, err := tx.Exec(ctx,
			`INSERT INTO clusters (id, tenant_id, display_name, state, shard_id, cluster_fingerprint)
			 VALUES ($1, $2, $3, 'Active', 'shard-test', $4)`,
			c, tenantID, "importance-test-"+c, "fp-"+c); err != nil {
			t.Fatalf("insert cluster %s: %v", c, err)
		}
	}

	now := time.Now()
	if _, err := tx.Exec(ctx,
		`INSERT INTO incidents (id, tenant_id, cluster_id, fingerprint, severity, state, first_seen, last_seen, occurrence_count, fleet_group_id)
		 VALUES ($1, $2, $3, $4, 'high', 'Detected', $5, $6, $7, $8)`,
		f.important, tenantID, f.clusterID, "importance-fp-"+f.important,
		now.Add(-72*time.Hour), now, 100, fleetGroupID); err != nil {
		t.Fatalf("insert important incident: %v", err)
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO incidents (id, tenant_id, cluster_id, fingerprint, severity, state, first_seen, last_seen, occurrence_count, fleet_group_id)
		 VALUES ($1, $2, $3, $4, 'high', 'Resolved', $5, $5, 1, $6)`,
		fleetPeerIncident, tenantID, fleetPeerCluster, "importance-fp-peer-"+fleetPeerIncident,
		now.Add(-96*time.Hour), fleetGroupID); err != nil {
		t.Fatalf("insert fleet-peer incident: %v", err)
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO incidents (id, tenant_id, cluster_id, fingerprint, severity, state, first_seen, last_seen, occurrence_count)
		 VALUES ($1, $2, $3, $4, 'high', 'Detected', $5, $5, 1)`,
		f.unimportant, tenantID, f.clusterID, "importance-fp-"+f.unimportant, now.Add(-2*time.Minute)); err != nil {
		t.Fatalf("insert unimportant incident: %v", err)
	}

	analysisID := domain.NewID(domain.PrefixAnalysis)
	if _, err := tx.Exec(ctx,
		`INSERT INTO analyses (id, tenant_id, incident_id, cluster_id, prompt_version, model, causal_chain, ruled_out, confidence, iterations, duration_ms, tokens_billed_in, tokens_cache_read, tokens_out, cost_usd)
		 VALUES ($1,$2,$3,$4,'test','test-model','[]'::jsonb,'[]'::jsonb,0.9,1,1,0,0,0,0)`,
		analysisID, tenantID, f.important, f.clusterID); err != nil {
		t.Fatalf("insert analysis for important incident: %v", err)
	}

	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit setup transaction: %v", err)
	}

	t.Cleanup(func() {
		cctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		tx, err := pool.Begin(cctx)
		if err != nil {
			t.Logf("cleanup: begin: %v", err)
			return
		}
		defer tx.Rollback(cctx) //nolint:errcheck
		clusterIDs := []string{f.clusterID, fleetPeerCluster}
		if err := data.SetRequestScope(cctx, tx, tenantID, clusterIDs); err != nil {
			t.Logf("cleanup: set request scope: %v", err)
			return
		}
		if _, err := tx.Exec(cctx, `DELETE FROM analyses WHERE id = $1`, analysisID); err != nil {
			t.Logf("cleanup: delete analysis: %v", err)
		}
		if _, err := tx.Exec(cctx, `DELETE FROM incidents WHERE cluster_id = ANY($1)`, clusterIDs); err != nil {
			t.Logf("cleanup: delete incidents: %v", err)
			return
		}
		if _, err := tx.Exec(cctx, `DELETE FROM clusters WHERE id = ANY($1)`, clusterIDs); err != nil {
			t.Logf("cleanup: delete clusters: %v", err)
			return
		}
		if err := tx.Commit(cctx); err != nil {
			t.Logf("cleanup: commit: %v", err)
		}
	})

	return f
}
