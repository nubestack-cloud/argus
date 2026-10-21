package api

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"argus/internal/data"
	"argus/internal/domain"
	"argus/internal/llm"
)

// TestPersistAnalysis_CompleteRoute_SuggestedNextStepsSurvives is BUGS.md
// 107: a Status "complete" investigation from the guidance route (lld/08
// §12.7 — ownership resolved to a GitOps-owned object, so no plan is
// possible, but the model still returns real, actionable
// SuggestedNextSteps) returned those steps once in the live POST
// /incidents/{id}/analyze response (toAnalysisResponse, which has always
// copied them for both branches) and then lost them permanently on the very
// next GET /incidents/{id}, because PersistAnalysis's "complete" branch
// never put SuggestedNextSteps into the rootCauseStored value it marshalled
// into analyses.root_cause — confirmed live against rke2 with
// analyses.root_cause containing no "suggestedNextSteps" key at all despite
// the same request's response body carrying five real steps a moment
// earlier.
//
// This proves the full round trip a real client depends on: PersistAnalysis
// writes it, a FRESH transaction (never the one that wrote it — same
// discipline as TestPersistAnalysis_TriggeredBy_ManualVsAuto) reads the raw
// column back showing the key present, and getLatestAnalysis — the function
// GET /incidents/{id} calls — surfaces it on the response object, not just
// on the column.
func TestPersistAnalysis_CompleteRoute_SuggestedNextStepsSurvives(t *testing.T) {
	pool := analyzeDetachTestPool(t)
	tenantID, clusterID, incidentID := analyzeDetachTestIncident(t, pool)
	ctx := context.Background()

	confidence := 0.98
	wantSteps := []string{
		"Clone the GitOps source repository",
		"Edit charts/cache's livenessProbe to a port the container listens on",
		"Push the fix",
		"Let Argo CD reconcile",
		"Confirm the Pod becomes Ready",
	}
	result := llm.Investigation{
		Model:              "test-model",
		Status:             "complete",
		RootCause:          &llm.RootCause{Statement: "BUGS.md 107 regression test root cause"},
		Confidence:         &confidence,
		SuggestedNextSteps: wantSteps,
	}

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if err := data.SetRequestScope(ctx, tx, tenantID, []string{clusterID}); err != nil {
		t.Fatalf("set request scope: %v", err)
	}

	analysisID := domain.NewID(domain.PrefixAnalysis)
	if _, err := PersistAnalysis(ctx, tx, tenantID, analysisID, incidentID, clusterID, result, time.Now(), TriggeredByManual); err != nil {
		t.Fatalf("PersistAnalysis: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit: %v", err)
	}

	// Read back in a FRESH transaction — proves this is durable, not an
	// artifact of reading inside the same transaction that wrote it.
	readTx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin read tx: %v", err)
	}
	defer func() { _ = readTx.Rollback(context.Background()) }()
	if err := data.SetRequestScope(ctx, readTx, tenantID, []string{clusterID}); err != nil {
		t.Fatalf("set request scope: %v", err)
	}

	var rootCauseJSON []byte
	if err := readTx.QueryRow(ctx, `SELECT root_cause FROM analyses WHERE id = $1`, analysisID).Scan(&rootCauseJSON); err != nil {
		t.Fatalf("read root_cause column: %v", err)
	}
	var stored rootCauseStored
	if err := json.Unmarshal(rootCauseJSON, &stored); err != nil {
		t.Fatalf("unmarshal root_cause: %v", err)
	}
	if stored.Status != "complete" {
		t.Fatalf("stored.Status = %q, want %q", stored.Status, "complete")
	}
	if !equalStringSlices(stored.SuggestedNextSteps, wantSteps) {
		t.Errorf("stored.SuggestedNextSteps = %v, want %v — analyses.root_cause must carry the same steps the live POST /analyze response returned, not drop them for a \"complete\" result", stored.SuggestedNextSteps, wantSteps)
	}

	rc := &requestContext{Tx: readTx, TenantID: tenantID}
	resp, err := getLatestAnalysis(ctx, rc, incidentID)
	if err != nil {
		t.Fatalf("getLatestAnalysis: %v", err)
	}
	if resp == nil {
		t.Fatal("getLatestAnalysis returned nil, want the analysis just persisted")
	}
	if !equalStringSlices(resp.SuggestedNextSteps, wantSteps) {
		t.Errorf("getLatestAnalysis SuggestedNextSteps = %v, want %v — GET /incidents/{id}'s embedded analysis must surface this for a \"complete\" result too, not just a \"partial\" one", resp.SuggestedNextSteps, wantSteps)
	}
}

func equalStringSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
