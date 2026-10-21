package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"argus/internal/data"
	"argus/internal/orchestrator"
)

// The incident list's status tabs and severity dropdown: ?status= narrows the
// rows by disposition, and `breakdown` counts status × severity with both of
// those filters lifted, so each control counts what clicking it would show.
func TestIncidentStatusFilterAndBreakdown(t *testing.T) {
	pool := authTestPool(t)
	f := setupDispositionFixture(t, pool)

	for status, want := range map[string]int{"open": 7, "requiresAction": 3, "inProgress": 4, "closed": 2} {
		if got := len(incidentIDsFrom(f.list(t, pool, "limit=100&status="+status))); got != want {
			t.Errorf("?status=%s returned %d rows, want %d", status, got, want)
		}
	}
	closed := map[string]bool{}
	for _, id := range incidentIDsFrom(f.list(t, pool, "limit=100&status=closed")) {
		closed[id] = true
	}
	if !closed[f.byState[orchestrator.StateResolved]] || !closed[f.byState[orchestrator.StateDismissed]] {
		t.Errorf("?status=closed is missing Resolved or Dismissed: %v", closed)
	}

	// The breakdown ignores the status and severity being counted, so a
	// filtered request still returns every cell.
	body := f.list(t, pool, "limit=100&status=closed&severity=low")
	cells, _ := body["breakdown"].([]any)
	got := map[string]float64{}
	for _, c := range cells {
		m, _ := c.(map[string]any)
		got[m["status"].(string)+"/"+m["severity"].(string)] = m["count"].(float64)
	}
	for key, want := range map[string]float64{"requiresAction/low": 3, "inProgress/low": 4, "closed/low": 2} {
		if got[key] != want {
			t.Errorf("breakdown[%s] = %v, want %v (all cells: %v)", key, got[key], want, got)
		}
	}

	// But it honours the search, unlike `counts`.
	body = f.list(t, pool, "limit=100&search="+f.byState[orchestrator.StateDetected])
	total := 0.0
	for _, c := range body["breakdown"].([]any) {
		total += c.(map[string]any)["count"].(float64)
	}
	if total != 1 {
		t.Errorf("breakdown under a search matching one incident totals %v, want 1", total)
	}

	t.Run("an unknown status is a 400", func(t *testing.T) {
		ctx := context.Background()
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatalf("begin: %v", err)
		}
		defer tx.Rollback(ctx) //nolint:errcheck
		if err := data.SetRequestScope(ctx, tx, f.tenantID, []string{f.clusterID}); err != nil {
			t.Fatalf("scope: %v", err)
		}
		rec := httptest.NewRecorder()
		(&Server{}).handleListIncidents(rec, httptest.NewRequest(http.MethodGet, "/api/v1/incidents?status=stuck", nil), &requestContext{Tx: tx, TenantID: f.tenantID})
		if rec.Code != http.StatusBadRequest {
			t.Errorf("status %d, want 400", rec.Code)
		}
	})
}
