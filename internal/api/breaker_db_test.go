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

// TestHandlePutBreaker_PartialUpdateLeavesOtherFieldsUnchanged is BACKLOG.md
// R5's core contract, proved against a real Postgres: PUT
// /api/v1/admin/circuit-breaker must let an operator change ONE threshold
// without silently resetting the others — the exact class of bug BUGS.md 97
// found on the sibling "autonomy" section's (at the time) non-pointer
// RequireReversibleForAutoApprove field. internal/settings.BreakerUpdate
// establishes the correct contract instead: every field is a pointer, and
// Update's SQL COALESCEs against the existing column, so an omitted field
// never even reaches the database as a write.
//
// Everything here runs inside ONE transaction that is rolled back, never
// committed — org_settings is a shared singleton row (migration
// 000018_org_settings), and this is a live, shared dev database (other
// sessions/services may be reading it concurrently), so this test must never
// leave a durable change behind. Reading back mid-transaction is sufficient
// to prove Update's behavior: everything handlePutBreaker does (the write,
// the audit event, and the read-back response) happens on rc.Tx before
// anything commits, exactly like the real handler chain (requireAuth's
// completeRequest commits only after the handler returns).
func TestHandlePutBreaker_PartialUpdateLeavesOtherFieldsUnchanged(t *testing.T) {
	pool := analyzeDetachTestPool(t)
	ctx := context.Background()

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()

	if err := data.SetRequestScope(ctx, tx, "tenant_test_r5", nil); err != nil {
		t.Fatalf("set request scope: %v", err)
	}

	s := &Server{}
	rc := &requestContext{Tx: tx, UserID: "usr_test_r5", TenantID: "tenant_test_r5"}

	put := func(t *testing.T, body string) map[string]any {
		t.Helper()
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPut, "/api/v1/admin/circuit-breaker", strings.NewReader(body))
		s.handlePutBreaker(rec, req, rc)
		if rec.Code != http.StatusOK {
			t.Fatalf("PUT %s: status = %d, want 200 (body: %s)", body, rec.Code, rec.Body.String())
		}
		var resp map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decode response: %v (body: %s)", err, rec.Body.String())
		}
		return resp
	}

	// First PUT: set all four fields explicitly, from whatever the row
	// currently holds.
	resp := put(t, `{"enabled":true,"maxPerCluster":5,"maxFleetWide":9,"windowSeconds":1800}`)
	assertBreakerField(t, resp, "enabled", true)
	assertBreakerField(t, resp, "maxPerCluster", float64(5))
	assertBreakerField(t, resp, "maxFleetWide", float64(9))
	assertBreakerField(t, resp, "windowSeconds", float64(1800))

	// Second PUT: touch ONLY windowSeconds. enabled/maxPerCluster/maxFleetWide
	// are omitted from the body entirely, so per BreakerUpdate's documented
	// contract they must come back exactly as the first PUT left them, never
	// reset to false/nil or DefaultBreakerLimits' 2/4.
	resp = put(t, `{"windowSeconds":60}`)
	assertBreakerField(t, resp, "enabled", true)
	assertBreakerField(t, resp, "maxPerCluster", float64(5))
	assertBreakerField(t, resp, "maxFleetWide", float64(9))
	assertBreakerField(t, resp, "windowSeconds", float64(60))

	// Third PUT: flip only enabled, in the other direction, proving the
	// bool field (despite the underlying column being NOT NULL, unlike its
	// int siblings) gets the identical leave-unchanged treatment.
	resp = put(t, `{"enabled":false}`)
	assertBreakerField(t, resp, "enabled", false)
	assertBreakerField(t, resp, "maxPerCluster", float64(5))
	assertBreakerField(t, resp, "maxFleetWide", float64(9))
	assertBreakerField(t, resp, "windowSeconds", float64(60))
}

func assertBreakerField(t *testing.T, resp map[string]any, field string, want any) {
	t.Helper()
	if got := resp[field]; got != want {
		t.Errorf("%s = %v (%T), want %v (%T)", field, got, got, want, want)
	}
}

// TestHandlePutBreaker_RejectsInvalidThresholds is the negative half of
// BACKLOG.md R5's test requirement: a PUT with an invalid value never
// reaches settings.Update at all, so the row is left completely untouched
// (also verified here, not just the status code) — matching
// handlePutSettings' identical "validate before touching the database"
// discipline for every other settings-writing route.
func TestHandlePutBreaker_RejectsInvalidThresholds(t *testing.T) {
	pool := analyzeDetachTestPool(t)
	ctx := context.Background()

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()

	if err := data.SetRequestScope(ctx, tx, "tenant_test_r5", nil); err != nil {
		t.Fatalf("set request scope: %v", err)
	}

	s := &Server{}
	rc := &requestContext{Tx: tx, UserID: "usr_test_r5", TenantID: "tenant_test_r5"}

	// A known-good baseline the invalid requests below must not disturb.
	rec := httptest.NewRecorder()
	s.handlePutBreaker(rec, httptest.NewRequest(http.MethodPut, "/api/v1/admin/circuit-breaker",
		strings.NewReader(`{"enabled":true,"maxPerCluster":3,"maxFleetWide":6,"windowSeconds":900}`)), rc)
	if rec.Code != http.StatusOK {
		t.Fatalf("baseline PUT: status = %d, want 200 (body: %s)", rec.Code, rec.Body.String())
	}

	invalid := []string{
		`{"maxPerCluster":-1}`,
		`{"maxPerCluster":0}`,
		`{"maxFleetWide":0}`,
		`{"windowSeconds":0}`,
		`{"windowSeconds":-30}`,
		`{"maxPerCluster":10,"maxFleetWide":5}`, // unreachable: per-cluster above fleet-wide
		`not json`,
	}
	for _, body := range invalid {
		t.Run(body, func(t *testing.T) {
			rec := httptest.NewRecorder()
			s.handlePutBreaker(rec, httptest.NewRequest(http.MethodPut, "/api/v1/admin/circuit-breaker", strings.NewReader(body)), rc)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400 (body: %s)", rec.Code, rec.Body.String())
			}
		})
	}

	// Prove the baseline is genuinely untouched by any of the rejected
	// requests above, not just that they returned 400.
	getRec := httptest.NewRecorder()
	s.handleGetBreaker(getRec, httptest.NewRequest(http.MethodGet, "/api/v1/admin/circuit-breaker", nil), rc)
	if getRec.Code != http.StatusOK {
		t.Fatalf("GET: status = %d, want 200 (body: %s)", getRec.Code, getRec.Body.String())
	}
	var resp map[string]any
	if err := json.Unmarshal(getRec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode GET response: %v", err)
	}
	assertBreakerField(t, resp, "maxPerCluster", float64(3))
	assertBreakerField(t, resp, "maxFleetWide", float64(6))
	assertBreakerField(t, resp, "windowSeconds", float64(900))
}
