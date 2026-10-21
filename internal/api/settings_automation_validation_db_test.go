package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"argus/internal/data"
)

// TestHandlePutSettings_RejectsAutoAnalysisEnabledWithEmptySeverities is
// BACKLOG.md C12's first named defect, part 2: nothing at the API rejected
// autoAnalysisEnabled=true paired with an empty (or all-invalid, which
// collapses to empty after the per-entry check just above this one)
// autoAnalysisSeverities. Before this fix that combination was accepted as
// a 200, leaving org_settings in a state where automatic investigation
// reads as "on" everywhere in the UI/API but internal/autoanalyze's own
// selectEligible excludes every single incident — silently investigating
// nothing, which is exactly the state this whole backlog entry was opened
// to catch.
//
// Runs inside one transaction that is rolled back, never committed —
// org_settings is a shared singleton row (migration 000018_org_settings) on
// a live, shared dev database — mirroring
// settings_require_reversible_db_test.go's own pattern for the identical
// reason.
func TestHandlePutSettings_RejectsAutoAnalysisEnabledWithEmptySeverities(t *testing.T) {
	pool := analyzeDetachTestPool(t)
	ctx := context.Background()

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()

	if err := data.SetRequestScope(ctx, tx, "tenant_test_c12", nil); err != nil {
		t.Fatalf("set request scope: %v", err)
	}

	s := &Server{}
	rc := &requestContext{Tx: tx, UserID: "usr_test_c12", TenantID: "tenant_test_c12"}

	do := func(t *testing.T, body string) *httptest.ResponseRecorder {
		t.Helper()
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPut, "/api/v1/admin/settings", strings.NewReader(body))
		s.handlePutSettings(rec, req, rc)
		return rec
	}

	t.Run("enabled true with an explicit empty severities array is rejected", func(t *testing.T) {
		rec := do(t, `{"automation": {"autoAnalysisEnabled": true, "autoAnalysisSeverities": []}}`)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400 (body: %s)", rec.Code, rec.Body.String())
		}
		var problem map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &problem); err != nil {
			t.Fatalf("decode RFC 9457 problem body: %v (body: %s)", err, rec.Body.String())
		}
		if problem["type"] != "https://argus.io/errors/malformed-request" {
			t.Errorf("problem type = %v, want https://argus.io/errors/malformed-request", problem["type"])
		}
		if detail, _ := problem["detail"].(string); !strings.Contains(detail, "never analyzes anything") {
			t.Errorf("problem detail = %q, want a clear explanation of the empty-severities-while-enabled foot-gun", detail)
		}
	})

	t.Run("enabled true with severities omitted entirely (nil) is rejected the same way", func(t *testing.T) {
		rec := do(t, `{"automation": {"autoAnalysisEnabled": true}}`)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400 (body: %s)", rec.Code, rec.Body.String())
		}
	})

	t.Run("enabled false with an empty severities array is accepted — disabled is a valid, unrelated state", func(t *testing.T) {
		rec := do(t, `{"automation": {"autoAnalysisEnabled": false, "autoAnalysisSeverities": []}}`)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200 (body: %s)", rec.Code, rec.Body.String())
		}
	})

	t.Run("enabled true with at least one real severity is accepted", func(t *testing.T) {
		rec := do(t, `{"automation": {"autoAnalysisEnabled": true, "autoAnalysisSeverities": ["high", "critical"]}}`)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200 (body: %s)", rec.Code, rec.Body.String())
		}
		var resp map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decode response: %v (body: %s)", err, rec.Body.String())
		}
		automation, ok := resp["automation"].(map[string]any)
		if !ok {
			t.Fatalf("response has no automation object: %+v", resp)
		}
		if automation["autoAnalysisEnabled"] != true {
			t.Errorf("autoAnalysisEnabled = %v, want true", automation["autoAnalysisEnabled"])
		}
	})
}
