package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"argus/internal/logging"
	"argus/internal/metrics"
)

// These tests cover PROJECT.md T23's HTTP half (a correlation id an
// operator can quote) and the one property of T24's HTTP metrics that
// would be a real defect rather than a missing number: the route label
// must be the registered PATTERN, never the request path.

// testServerWithRoute builds the minimum Server the observability wrapper
// needs: a mux with one registered pattern. No database, no auth — this is
// about the wrapper, not the handler.
func testServerWithRoute(pattern string, h http.HandlerFunc) *Server {
	s := &Server{mux: http.NewServeMux()}
	s.mux.HandleFunc(pattern, h)
	return s
}

func TestRequestIDIsMintedAndReturnedInTheProblemBody(t *testing.T) {
	s := testServerWithRoute("GET /api/v1/incidents/{id}", func(w http.ResponseWriter, r *http.Request) {
		writeProblem(w, http.StatusNotFound, "https://argus.io/errors/not-found", "Not found", "")
	})

	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/incidents/inc_01j", nil))

	header := rec.Header().Get(RequestIDHeader)
	if !strings.HasPrefix(header, logging.RequestIDPrefix+"_") {
		t.Fatalf("%s = %q, want a minted req_ id", RequestIDHeader, header)
	}

	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("problem body is not JSON: %v", err)
	}
	if body["requestId"] != header {
		t.Fatalf("problem body requestId = %v, want it to match the response header %q — an operator quotes one string, and it has to be the same one either way",
			body["requestId"], header)
	}
	// The RFC 9457 members the spec requires are untouched by the addition.
	for _, k := range []string{"type", "title", "status", "detail"} {
		if _, ok := body[k]; !ok {
			t.Errorf("problem body lost its required member %q", k)
		}
	}
}

func TestInboundRequestIDIsAdoptedOnlyWhenItIsBoring(t *testing.T) {
	cases := map[string]bool{
		"trace-abc123":          true,
		"REQ_0001":              true,
		"":                      false,
		"has space":             false,
		"has\nnewline":          false,
		`inject"} {"evil":1`:    false,
		strings.Repeat("x", 65): false,
		strings.Repeat("x", 64): true,
		"semi;colon":            false,
	}
	for in, adopt := range cases {
		s := testServerWithRoute("GET /x", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})
		req := httptest.NewRequest(http.MethodGet, "/x", nil)
		if in != "" {
			req.Header.Set(RequestIDHeader, in)
		}
		rec := httptest.NewRecorder()
		s.ServeHTTP(rec, req)

		got := rec.Header().Get(RequestIDHeader)
		if adopt && got != in {
			t.Errorf("inbound %q should have been adopted, got %q", in, got)
		}
		if !adopt {
			if got == in {
				t.Errorf("inbound %q should have been rejected, but was echoed back", in)
			}
			if !strings.HasPrefix(got, logging.RequestIDPrefix+"_") {
				t.Errorf("rejecting inbound %q should mint a fresh id, got %q", in, got)
			}
		}
	}
}

// TestHTTPMetricsLabelTheRouteNotThePath is the privacy and cardinality
// property from internal/metrics/metrics.go's header, exercised end to
// end: an incident id in the URL must not become a label value, and an
// unrouted path must not mint a series of its own.
func TestHTTPMetricsLabelTheRouteNotThePath(t *testing.T) {
	s := testServerWithRoute("GET /api/v1/incidents/{id}", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	s.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/api/v1/incidents/inc_secret_id", nil))
	s.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/api/v1/nothing-here", nil))

	var buf bytes.Buffer
	metrics.DefaultRegistry.WriteExposition(&buf)
	out := buf.String()

	if strings.Contains(out, "inc_secret_id") {
		t.Fatalf("the request path leaked into a metric label:\n%s", out)
	}
	if !strings.Contains(out, `route="GET /api/v1/incidents/{id}"`) {
		t.Fatalf("expected the registered pattern as the route label:\n%s", out)
	}
	if !strings.Contains(out, `route="unmatched"`) {
		t.Fatalf("expected an unrouted request to land in the single \"unmatched\" bucket:\n%s", out)
	}
	if !strings.Contains(out, `argus_http_requests_total{method="GET",route="GET /api/v1/incidents/{id}",status="200"}`) {
		t.Fatalf("expected a status-labeled request counter:\n%s", out)
	}
}
