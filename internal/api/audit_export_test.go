package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// The four cases below all resolve to a 400 before handleExportAuditEvents
// ever touches rc.Tx — exactly the same "resolves before touching the
// database" shape TestHandleListIncidentsRejectsInvalidState (incidents_test.go)
// already relies on, so a nil Tx on the requestContext would panic if any of
// these fell through to the real query. The positive/RLS-isolation case needs
// a live Postgres and lives in audit_export_db_test.go.

func TestHandleExportAuditEventsRejectsInvalidFormat(t *testing.T) {
	s := &Server{}
	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/audit-events/export?format=xml&since=2026-01-01T00:00:00Z&until=2026-01-02T00:00:00Z", nil)
	rec := httptest.NewRecorder()

	s.handleExportAuditEvents(rec, req, &requestContext{})

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d (body: %s)", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
}

func TestHandleExportAuditEventsRequiresSinceAndUntil(t *testing.T) {
	cases := []struct {
		name  string
		query string
	}{
		{"neither provided", "format=json"},
		{"only since provided", "format=json&since=2026-01-01T00:00:00Z"},
		{"only until provided", "format=json&until=2026-01-02T00:00:00Z"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := &Server{}
			req := httptest.NewRequest(http.MethodGet, "/api/v1/audit-events/export?"+tc.query, nil)
			rec := httptest.NewRecorder()

			s.handleExportAuditEvents(rec, req, &requestContext{})

			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want %d (body: %s) — export must require both since and until, unlike the paginated list endpoint", rec.Code, http.StatusBadRequest, rec.Body.String())
			}
		})
	}
}

func TestHandleExportAuditEventsRejectsUntilBeforeSince(t *testing.T) {
	s := &Server{}
	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/audit-events/export?since=2026-01-02T00:00:00Z&until=2026-01-01T00:00:00Z", nil)
	rec := httptest.NewRecorder()

	s.handleExportAuditEvents(rec, req, &requestContext{})

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d (body: %s)", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
}

func TestHandleExportAuditEventsRejectsRangeTooLarge(t *testing.T) {
	s := &Server{}
	// maxAuditEventExportRangeDays is 92; 93 days apart must be rejected
	// before any query runs.
	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/audit-events/export?since=2026-01-01T00:00:00Z&until=2026-04-04T00:00:00Z", nil)
	rec := httptest.NewRecorder()

	s.handleExportAuditEvents(rec, req, &requestContext{})

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d (body: %s) — a 93-day range exceeds maxAuditEventExportRangeDays and must be rejected up front, not silently truncated", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
}

func TestHandleExportAuditEventsAcceptsRangeAtTheBoundary(t *testing.T) {
	// Exactly maxAuditEventExportRangeDays apart must pass validation (and
	// therefore reach rc.Tx.Query) — asserted here by expecting a PANIC from
	// the nil Tx, which is the same technique this package already uses
	// (see TestHandleListIncidentsRejectsInvalidSortKey's sibling cases) to
	// prove a case falls through validation without a live database.
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected a panic from the nil Tx once validation passed and the handler tried to query — got none, meaning the 92-day boundary was wrongly rejected before reaching the query")
		}
	}()
	s := &Server{}
	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/audit-events/export?since=2026-01-01T00:00:00Z&until=2026-04-03T00:00:00Z", nil)
	rec := httptest.NewRecorder()
	s.handleExportAuditEvents(rec, req, &requestContext{})
}

func TestToAuditExportRowFlattensNilPointersAndSerializesJSON(t *testing.T) {
	actorID := "usr_test"
	ev := auditEventDetail{
		auditEventSummary: auditEventSummary{
			ID:         "aud_test",
			OccurredAt: "2026-01-01T00:00:00Z",
			ActorID:    &actorID,
			// ActorEmail, ActorDisplayName, SourceIP, Capability, ClusterID,
			// ClusterDisplayName deliberately left nil — a login failure or a
			// cluster-less action is the common case (see audit.go's doc
			// comment), and toAuditExportRow must degrade to "" rather than
			// panic on a nil dereference.
			Outcome:        "success",
			Action:         "Test Action",
			DetailsSummary: "key=value",
		},
		Scope:    map[string]any{"type": "AllClusters"},
		Details:  map[string]any{"action": "test_action", "nested": map[string]any{"a": 1}},
		PrevHash: "prevhash",
		Hash:     "hash",
	}

	row, err := toAuditExportRow(ev)
	if err != nil {
		t.Fatalf("toAuditExportRow: %v", err)
	}
	if row.ActorID != actorID {
		t.Errorf("ActorID = %q, want %q", row.ActorID, actorID)
	}
	for name, got := range map[string]string{
		"ActorEmail": row.ActorEmail, "ActorDisplayName": row.ActorDisplayName,
		"SourceIP": row.SourceIP, "Capability": row.Capability,
		"ClusterID": row.ClusterID, "ClusterDisplayName": row.ClusterDisplayName,
	} {
		if got != "" {
			t.Errorf("%s = %q, want \"\" for a nil source field", name, got)
		}
	}
	if want := `{"type":"AllClusters"}`; row.Scope != want {
		t.Errorf("Scope = %q, want %q", row.Scope, want)
	}
	if want := `{"action":"test_action","nested":{"a":1}}`; row.Details != want {
		t.Errorf("Details = %q, want %q", row.Details, want)
	}
	// values() must stay in exactly auditExportColumns' order — asserted
	// positionally so a future field reorder that forgets to update one of
	// the two fails loudly here rather than silently shipping a header/data
	// mismatch in a real exported file.
	values := row.values()
	if len(values) != len(auditExportColumns) {
		t.Fatalf("values() has %d entries, auditExportColumns has %d — must match", len(values), len(auditExportColumns))
	}
	wantByColumn := map[string]string{
		"id": "aud_test", "actorId": actorID, "outcome": "success",
		"action": "Test Action", "detailsSummary": "key=value",
		"prevHash": "prevhash", "hash": "hash",
	}
	for col, want := range wantByColumn {
		idx := -1
		for i, c := range auditExportColumns {
			if c == col {
				idx = i
				break
			}
		}
		if idx == -1 {
			t.Fatalf("auditExportColumns has no %q entry", col)
		}
		if values[idx] != want {
			t.Errorf("values()[%d] (column %q) = %q, want %q", idx, col, values[idx], want)
		}
	}
}
