package api

// GET /metrics must refuse a request with no (or the wrong) bearer token,
// and must serve normally with the right one — proven against the real
// handler, not just against checkMetricsAuth in isolation, since the wiring
// between the two (the status codes, the WWW-Authenticate header, and the
// fact that RefreshIncidentStateMetrics never runs for a refused request)
// is exactly what a unit test of the pure function alone would miss.
//
// The load-bearing test in this file is
// TestHandleMetrics_UnconfiguredServesNoMetricsToAnyone. The endpoint used
// to serve openly when ARGUS_METRICS_TOKEN was unset, and that hole is the
// specific thing that must not silently reopen: it would reopen as a
// PASSING 200 on a path nobody re-reads, not as a compile error. That test
// asserts both halves — a non-200 status AND the absence of any argus_*
// series in the body — so neither "it 200s but with an empty body" nor "it
// 503s but still wrote the exposition" can slip through.
//
// t.Setenv is used throughout rather than a bare os.Setenv: it restores the
// previous value automatically at the end of each (sub)test, so these tests
// cannot leak ARGUS_METRICS_TOKEN into whichever test in this package's
// suite happens to run next — this env var is process-global and this
// package's tests run in the same binary.

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"argus/internal/data"
)

func TestHandleMetrics_401WithoutToken(t *testing.T) {
	t.Setenv(MetricsTokenEnv, "s3cr3t-scrape-token")

	s := &Server{db: &data.DB{}}
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rec := httptest.NewRecorder()
	s.handleMetrics(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("GET /metrics with no Authorization header and a configured token returned %d, want 401", rec.Code)
	}
	if got := rec.Header().Get("WWW-Authenticate"); got == "" {
		t.Errorf("expected a WWW-Authenticate header on a 401, got none")
	}
	if rec.Body.Len() == 0 {
		t.Errorf("expected an RFC 9457 problem body on a 401, got an empty body")
	}
}

func TestHandleMetrics_401WithWrongToken(t *testing.T) {
	t.Setenv(MetricsTokenEnv, "s3cr3t-scrape-token")

	s := &Server{db: &data.DB{}}
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	req.Header.Set("Authorization", "Bearer not-the-right-token")
	rec := httptest.NewRecorder()
	s.handleMetrics(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("GET /metrics with a WRONG bearer token returned %d, want 401", rec.Code)
	}
}

func TestHandleMetrics_200WithCorrectToken(t *testing.T) {
	pool := authTestPool(t)
	t.Setenv(MetricsTokenEnv, "s3cr3t-scrape-token")

	s := &Server{db: &data.DB{Pool: pool}}
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	req.Header.Set("Authorization", "Bearer s3cr3t-scrape-token")
	rec := httptest.NewRecorder()
	s.handleMetrics(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("GET /metrics with the CORRECT bearer token returned %d, want 200 (body: %s)", rec.Code, rec.Body.String())
	}
	if rec.Body.Len() == 0 {
		t.Errorf("expected a non-empty exposition body, got none")
	}
}

// TestHandleMetrics_UnconfiguredServesNoMetricsToAnyone is the regression
// guard for the disclosure this endpoint used to have by default: with
// ARGUS_METRICS_TOKEN unset it served fleet-wide cluster and incident
// counts, a live tunnel-connection heartbeat and accumulated AI spend to
// any anonymous caller.
//
// It deliberately needs NO database, so it runs on every machine rather
// than t.Skip-ing on the CI runners without ARGUS_TEST_DATABASE_URL — a
// guard against a security regression is worth nothing if the run that
// would catch it skips. A &data.DB{} with a nil Pool is safe precisely
// BECAUSE the refusal happens before orchestrator.RefreshIncidentStateMetrics
// is reached (the same reason the 401 tests above use one). If the
// enforcement is ever removed, this test fails either way: the handler
// reaches the nil pool and panics, or it serves 200 and the assertions
// below fire. There is no arrangement of this test that passes with the
// hole reopened.
//
// Every caller shape is covered, because the old code authorized on the
// SERVER's empty token rather than on anything the client sent — so a
// client that sends nothing, a client that sends a guess, and a client that
// sends the empty string must all be refused identically.
func TestHandleMetrics_UnconfiguredServesNoMetricsToAnyone(t *testing.T) {
	cases := []struct {
		name   string
		header string // "" means send no Authorization header at all
	}{
		{"no Authorization header", ""},
		{"a guessed bearer token", "Bearer anything-at-all"},
		{"an empty bearer token", "Bearer "},
		{"a non-bearer scheme", "Basic Zm9vOmJhcg=="},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(MetricsTokenEnv, "") // explicit empty, not merely "not set by this test"

			s := &Server{db: &data.DB{}}
			req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
			if tc.header != "" {
				req.Header.Set("Authorization", tc.header)
			}
			rec := httptest.NewRecorder()
			s.handleMetrics(rec, req)

			if rec.Code == http.StatusOK {
				t.Fatalf("GET /metrics with %s unset returned 200 — the unauthenticated disclosure has reopened; body:\n%s", MetricsTokenEnv, rec.Body.String())
			}
			if rec.Code != http.StatusServiceUnavailable {
				t.Errorf("status = %d, want 503 (not 401: no credential the caller could send would help, so the refusal must point at the hub's own configuration)", rec.Code)
			}
			// The half a status-code-only assertion would miss: a future
			// refactor that writes the exposition before (or as well as)
			// the problem body still leaks every series.
			if body := rec.Body.String(); strings.Contains(body, "argus_") {
				t.Errorf("response body contains argus_* metric series despite the refusal — metrics were served to an unauthenticated caller:\n%s", body)
			}
			if ct := rec.Header().Get("Content-Type"); ct != "application/problem+json" {
				t.Errorf("Content-Type = %q, want application/problem+json (an RFC 9457 refusal, not an exposition body)", ct)
			}
			if got := rec.Header().Get("WWW-Authenticate"); got != "" {
				t.Errorf("WWW-Authenticate = %q, want none: challenging for a credential when the hub has none configured sends the operator to fix the wrong end", got)
			}
			if body := rec.Body.String(); !strings.Contains(body, MetricsTokenEnv) {
				t.Errorf("refusal body does not name %s, so an operator cannot tell from the response what to configure:\n%s", MetricsTokenEnv, body)
			}
		})
	}
}

// TestCheckMetricsAuth_NeverAllowsWithoutAConfiguredToken guards the same
// property one layer down, at the single function where "no token
// configured means everyone is authorized" could be reintroduced. The
// handler test above would catch that too, but this one names the exact
// line, so a failure reads as "the decision function regressed" rather than
// "something about /metrics is wrong."
func TestCheckMetricsAuth_NeverAllowsWithoutAConfiguredToken(t *testing.T) {
	t.Setenv(MetricsTokenEnv, "")
	for _, header := range []string{"", "Bearer x", "Bearer ", "Basic x"} {
		req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
		if header != "" {
			req.Header.Set("Authorization", header)
		}
		if got := checkMetricsAuth(req); got != metricsNotConfigured {
			t.Errorf("checkMetricsAuth with %s unset and Authorization=%q = %v, want metricsNotConfigured (never metricsAllowed)", MetricsTokenEnv, header, got)
		}
	}
}

func TestBearerToken_ParsesStandardHeader(t *testing.T) {
	cases := []struct {
		name      string
		header    string
		wantToken string
		wantOK    bool
	}{
		{"well-formed", "Bearer abc123", "abc123", true},
		{"missing header", "", "", false},
		{"wrong scheme", "Basic abc123", "", false},
		{"empty token", "Bearer ", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
			if tc.header != "" {
				req.Header.Set("Authorization", tc.header)
			}
			token, ok := bearerToken(req)
			if ok != tc.wantOK || token != tc.wantToken {
				t.Errorf("bearerToken(%q) = (%q, %v), want (%q, %v)", tc.header, token, ok, tc.wantToken, tc.wantOK)
			}
		})
	}
}
