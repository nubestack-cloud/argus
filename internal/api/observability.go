package api

import (
	"bufio"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"time"

	"argus/internal/logging"
	"argus/internal/metrics"
)

// This file is the HTTP entry point's half of PROJECT.md T23 (a correlation
// id minted per request and carried on its context) and T24 (request rate,
// latency and status by route). They are one wrapper because they need the
// same two things — the matched route pattern and the final status code —
// and splitting them would mean two passes over the mux for one request.
//
// var logger is this package's package-local slog logger (T22). Every
// converted call site in internal/api writes through it; the rest still go
// through the standard log package, which logging.Setup bridges into the
// same JSON chain (see internal/logging's doc comment on the incremental
// migration).
var logger = logging.For("api")

// RequestIDHeader is the correlation id's name on the wire. Set on every
// response, accepted on a request so a caller that already has a trace id
// of its own (a reverse proxy, a script driving the API, the e2e harness)
// can have its logs and the hub's join up.
//
// X-Request-Id rather than W3C traceparent: this is a request correlation
// id, not a span in a trace, and adopting the traceparent header would
// imply a propagation contract (sampling flags, parent span ids) that
// nothing here honours.
const RequestIDHeader = "X-Request-Id"

// maxInboundRequestIDLen bounds an accepted caller-supplied id.
const maxInboundRequestIDLen = 64

// acceptInboundRequestID decides whether to adopt a caller's id or mint a
// fresh one.
//
// The id ends up in log records, in an RFC 9457 problem body, and on an
// analyses row, so it is untrusted input that reaches durable storage and
// an operator's terminal. It is NOT an authorization or identity claim —
// nothing branches on it — but a caller-chosen id containing a newline, an
// ANSI escape, or ten kilobytes of text would still be a log-injection and
// a storage problem. So: a short, boring identifier shape or nothing.
// Rejecting rather than sanitizing, because a truncated or mangled id is
// worse than a fresh one — it looks like the caller's id and is not.
func acceptInboundRequestID(v string) bool {
	if v == "" || len(v) > maxInboundRequestIDLen {
		return false
	}
	for i := 0; i < len(v); i++ {
		c := v[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '_', c == '-':
		default:
			return false
		}
	}
	return true
}

// observe wraps the whole mux: it mints or adopts the request's correlation
// id, puts it on the request context and on the response, and records the
// request-duration histogram and status counter.
//
// Why here and not inside requireAuth: unauthenticated routes are requests
// too. A failed login, a 401 from an expired token and an unrouted path are
// all things a support question gets asked about, and all of them happen
// before requireAuth would have run. requireAuth still mints an id when it
// does not find one (see middleware.go), which is both what PROJECT.md T23
// asks for literally and what keeps the many tests that drive s.mux
// directly, bypassing this wrapper, working the same way.
func (s *Server) observe(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestID := r.Header.Get(RequestIDHeader)
		if !acceptInboundRequestID(requestID) {
			requestID = logging.NewRequestID()
		}
		ctx := logging.ContextWithRequestID(r.Context(), requestID)
		w.Header().Set(RequestIDHeader, requestID)

		route := s.routeLabel(r)
		rec := &statusRecorder{ResponseWriter: w}

		start := time.Now()
		next.ServeHTTP(rec, r.WithContext(ctx))
		elapsed := time.Since(start)

		status := rec.statusCode()
		metrics.HTTPRequestDurationSeconds.Observe(elapsed.Seconds(), r.Method, route)
		metrics.HTTPRequestsTotal.Inc(r.Method, route, strconv.Itoa(status))

		// One completion line per request — the backbone of PROJECT.md
		// T23's "reconstruct it from logs alone". Without it, a request
		// that SUCCEEDS leaves no trace at all, since every converted call
		// site under it is an error branch; the correlation id would then
		// join up only the trails nobody needs to reconstruct.
		//
		// The level tracks the outcome so an operator can turn the volume
		// down without losing the failures: 5xx is an error, 4xx a
		// warning, anything else informational. Health probes and the
		// metrics scrape drop to DEBUG — they arrive every few seconds
		// forever and would bury everything else in the default bundle,
		// while telling nobody anything they could not read off
		// argus_http_requests_total.
		level := slog.LevelInfo
		switch {
		case status >= 500:
			level = slog.LevelError
		case status >= 400:
			level = slog.LevelWarn
		case isProbeRoute(route):
			level = slog.LevelDebug
		}
		logger.LogAttrs(ctx, level, "http request",
			slog.String("method", r.Method),
			slog.String("route", route),
			slog.Int("status", status),
			slog.Int64("duration_ms", elapsed.Milliseconds()))
	})
}

// isProbeRoute names the endpoints a kubelet or a Prometheus scraper hits
// on a fixed interval forever. Matched on the registered pattern, so it
// cannot be fooled by a request path.
func isProbeRoute(route string) bool {
	switch route {
	case "GET /healthz", "GET /readyz", "GET /metrics":
		return true
	}
	return false
}

// routeLabel resolves the REGISTERED PATTERN this request matched, which is
// what the metric is labeled with — never r.URL.Path.
//
// That distinction is the whole cardinality and privacy argument for these
// two metrics (see internal/metrics/metrics.go's header): a path carries
// incident ids, cluster ids and filenames, and an unmatched path carries
// whatever a scanner sends. A pattern comes from internal/api/server.go's
// own route table, so the label set is bounded by the source file.
//
// net/http's ServeMux.Handler does the match without invoking the handler;
// the mux then matches a second time when it actually serves. That second
// pass is a tree walk over a few hundred patterns, which is cheap next to
// anything else a request does here, and it is the only way to get the
// pattern without wrapping all ~200 registrations.
func (s *Server) routeLabel(r *http.Request) string {
	_, pattern := s.mux.Handler(r)
	if pattern == "" {
		// No pattern matched: a 404 from the mux itself, or a method
		// mismatch. One bucket, deliberately — the alternative is a series
		// per URL a scanner invents.
		return "unmatched"
	}
	return pattern
}

// statusRecorder observes the status code without buffering the body.
//
// Deliberately NOT internal/api/middleware.go's bufferedResponseWriter, and
// the difference matters: that one buffers so requireAuth can decide what
// the client receives after the transaction resolves, and it deliberately
// implements neither Hijacker nor Flusher so that a streaming route wired
// through requireAuth fails visibly. This one wraps EVERY route including
// the two that cannot be buffered — GET /ws/events hijacks its connection
// and GET / serves the embedded UI — so it must be transparent: it passes
// Hijack and Flush straight through, and it holds no bytes.
type statusRecorder struct {
	http.ResponseWriter
	status   int
	hijacked bool
}

func (w *statusRecorder) WriteHeader(code int) {
	if w.status == 0 {
		w.status = code
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusRecorder) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK // implicit 200, exactly like net/http
	}
	return w.ResponseWriter.Write(b)
}

// statusCode is what the metric records. A handler that wrote nothing at
// all (no status, no body) has returned 200 as far as net/http is
// concerned, so that is what is reported.
//
// A hijacked connection is reported as 101: no HTTP status was ever
// written for it, and recording the /ws/events upgrade as a 200 would put
// long-lived WebSocket lifetimes into the same latency series as ordinary
// requests to the same route.
func (w *statusRecorder) statusCode() int {
	if w.hijacked {
		return http.StatusSwitchingProtocols
	}
	if w.status == 0 {
		return http.StatusOK
	}
	return w.status
}

// Hijack passes through to the underlying writer so GET /ws/events keeps
// working. Errors rather than panicking if the underlying writer is not a
// Hijacker, which is the contract net/http itself documents.
func (w *statusRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	h, ok := w.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, errors.New("api: the underlying ResponseWriter is not an http.Hijacker")
	}
	conn, rw, err := h.Hijack()
	if err == nil {
		w.hijacked = true
	}
	return conn, rw, err
}

func (w *statusRecorder) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}
