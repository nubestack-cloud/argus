package api

// The endpoint must serve parseable Prometheus exposition. Exercises the actual GET /metrics handler
// (handleMetrics, metrics.go) end to end — real HTTP request/response,
// real DB pool, real orchestrator.RefreshIncidentStateMetrics call — rather
// than only the lower-level metrics package unit tests
// (internal/metrics/metrics_test.go), which cover the exposition FORMAT but
// not that this hub's own route actually serves it.

import (
	"bufio"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"argus/internal/data"
)

func TestHandleMetrics_ServesParseableExposition(t *testing.T) {
	pool := authTestPool(t)
	// A token is mandatory now — an unconfigured hub answers 503 and serves
	// no exposition at all (metrics_auth_test.go). This test is about the
	// exposition FORMAT, so it configures a token and presents it, rather
	// than exercising the refusal path a second time.
	t.Setenv(MetricsTokenEnv, "s3cr3t-scrape-token")
	s := &Server{db: &data.DB{Pool: pool}}

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	req.Header.Set("Authorization", "Bearer s3cr3t-scrape-token")
	rec := httptest.NewRecorder()
	s.handleMetrics(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("GET /metrics returned %d, want 200", rec.Code)
	}
	ct := rec.Header().Get("Content-Type")
	if !strings.HasPrefix(ct, "text/plain") {
		t.Errorf("Content-Type = %q, want a text/plain exposition content type", ct)
	}

	body := rec.Body.String()
	if body == "" {
		t.Fatal("GET /metrics returned an empty body — at least argus_incidents_by_state should be present after RefreshIncidentStateMetrics runs")
	}

	// Every non-comment, non-blank line must parse as either
	// `name{labels} value` or `name value` — the same shape a real
	// Prometheus text-format parser requires. This is a light structural
	// check, not a full grammar, but it would catch a malformed label set,
	// a missing value, or a stray line — the failure modes an ad hoc writer
	// (rather than a vetted library) could plausibly introduce.
	sawIncidentsByState := false
	scanner := bufio.NewScanner(strings.NewReader(body))
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			t.Fatalf("blank line in /metrics exposition output")
		}
		if strings.HasPrefix(line, "# HELP") || strings.HasPrefix(line, "# TYPE") {
			continue
		}
		if strings.HasPrefix(line, "argus_incidents_by_state{") {
			sawIncidentsByState = true
		}
		fields := strings.Fields(line)
		if len(fields) != 2 {
			t.Errorf("malformed exposition line (want exactly a name/labels field and a value field): %q", line)
			continue
		}
		if strings.Contains(fields[0], "{") != strings.Contains(fields[0], "}") {
			t.Errorf("unbalanced label braces: %q", line)
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("scan exposition body: %v", err)
	}
	if !sawIncidentsByState {
		t.Errorf("expected at least one argus_incidents_by_state{...} series after RefreshIncidentStateMetrics ran against a real database, got body:\n%s", body)
	}
}
