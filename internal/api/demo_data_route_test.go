package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// PROJECT.md D14: demo data is a test fixture, not a product feature, and the
// only thing standing between a real install and an endpoint that writes
// fabricated root causes, approval decisions attributed to the caller by name,
// execution records and metered spend into the real tables is that these two
// routes are not registered.
//
// Deliberately asserted at the MUX, not at the handler: the point is that the
// pattern does not exist, so the request dies before auth and before any
// capability check. A test that called handleGenerateDemoData directly would
// pass just as happily with the routes registered unconditionally.
//
// Note the disabled status is 405, not 404 — `GET /` is registered as the
// embedded-SPA catch-all (server.go), so Go's ServeMux matches the PATH and
// rejects the METHOD. Asserting 404 here would fail for the right reason and
// the wrong cause, so this pins the property that actually matters: unset,
// the request never reaches requireAuth; set, it does (401, no credentials).
func TestDemoDataRoutesRegisteredOnlyWhenEnabled(t *testing.T) {
	for _, tc := range []struct {
		name    string
		enabled bool
		want    int
	}{
		{name: "disabled (every real install)", enabled: false, want: http.StatusMethodNotAllowed},
		{name: "enabled (dev compose, for web/e2e)", enabled: true, want: http.StatusUnauthorized},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := &Server{mux: http.NewServeMux(), demoDataEnabled: tc.enabled}
			s.routes()
			for _, method := range []string{http.MethodPost, http.MethodDelete} {
				rec := httptest.NewRecorder()
				s.mux.ServeHTTP(rec, httptest.NewRequest(method, "/api/v1/demo-data", nil))
				if rec.Code != tc.want {
					t.Errorf("%s /api/v1/demo-data with demoDataEnabled=%v: status %d, want %d", method, tc.enabled, rec.Code, tc.want)
				}
			}
		})
	}
}
