// GET /metrics — the hub's Prometheus exposition endpoint. Registered in
// server.go alongside GET /healthz and /readyz. See internal/metrics' own
// package doc comment for why this is a hand-rolled exposition writer rather
// than github.com/prometheus/client_golang, and docs/METRICS.md for the
// operator-facing description.
//
// # A bearer token is MANDATORY, and it is not the ordinary session kind
//
// A scrape is not a user session — it has no cookie, no login flow, and
// nothing to authorize against internal/authz's capability model, so this
// does NOT go through requireAuth/requireCapability the way every other
// route in this file does. Threading a Prometheus scrape through that
// machinery would be the wrong shape for it, not just an unnecessary one.
//
// Instead, ARGUS_METRICS_TOKEN is the endpoint's entire auth story, and it
// is required:
//
//   - Set: a request must present it as `Authorization: Bearer <token>` or
//     get 401, compared in constant time.
//   - Unset: the endpoint is DISABLED. Every scrape gets 503 and no metric
//     data at all. It does not fall back to serving openly.
//
// This is a change from the endpoint's original behaviour, where an unset
// token meant "serve to anyone." That default was never neutral — see the
// next section — and argus-design-review's safety-critical rule against
// revealing a count or a heartbeat to an anonymous visitor applies to a
// scrape target exactly as it applies to a screen. Prometheus has supported
// `authorization`/`bearer_token_file`/`basic_auth` in a scrape_config for
// years, so requiring a credential costs an operator one line of scrape
// config, not a redesign.
//
// # Why 503 rather than 401 when no token is configured
//
// 401 would be a lie about whose problem it is. Nothing the scraper can
// send will ever satisfy an endpoint with no configured secret, so the
// honest answer is "this server is not configured to serve this," which
// points the operator at the hub's environment instead of at their own
// scrape_config. The problem body says exactly which variable is missing,
// and LogMetricsAuthMode has already said the same thing once at startup —
// so the state is discoverable from a log line without anyone having to
// curl the endpoint first.
//
// # Why this does not refuse to start the hub instead
//
// A hard startup failure would be the stronger control if /metrics were an
// opt-in feature, because a route that 503s forever is a worse failure than
// one that never comes up. It is not opt-in: server.go registers GET
// /metrics unconditionally, there is no metrics.enabled switch anywhere, and
// no existing deployment supplies a token (deploy/compose/docker-compose.yaml
// does not set one, and the Helm chart only wired one when an operator
// opted in). Failing startup would therefore turn "metrics stop being
// scraped" into "the hub — UI, API and the agent tunnel with it — does not
// come up at all" for every deployment on upgrade. Trading total
// unavailability for metrics unavailability is not a defensible upgrade
// story, so the refusal lives at the request, and the loud line lives at
// startup. The Helm chart closes the gap from the other end: it now
// generates a token when none is supplied (secret-metrics.yaml), so a
// default install gets a hub whose /metrics actually serves.
//
// # What the token protects
//
// No metric here carries a cluster name — see internal/metrics/metrics.go's
// own label-safety argument — but several ARE exactly a count or a
// heartbeat: argus_clusters_by_state (fleet size and health),
// argus_incidents_by_state (incident volume),
// argus_tunnel_connections_active (a live-connection heartbeat), and
// argus_analysis_cost_usd_total (accumulated spend).
package api

import (
	"crypto/subtle"
	"log/slog"
	"net/http"
	"os"
	"strings"

	"argus/internal/metrics"
	"argus/internal/orchestrator"
)

// MetricsTokenEnv is the environment variable that gates GET /metrics behind
// a bearer token. It is required: unset (the zero value os.Getenv returns)
// disables the endpoint rather than opening it — see this file's own doc
// comment.
const MetricsTokenEnv = "ARGUS_METRICS_TOKEN"

// LogMetricsAuthMode logs one line, once, at hub startup — not lazily on the
// first scrape — describing which of the two states GET /metrics is in, so
// an operator learns that metrics are disabled from the hub's own log rather
// than from a 503 their scraper reports hours later. Called from NewServer,
// which runs exactly once per hub process.
//
// (Replaces WarnIfMetricsUnauthenticated, whose line announced an
// unauthenticated endpoint that no longer exists.)
func LogMetricsAuthMode() {
	if os.Getenv(MetricsTokenEnv) == "" {
		logger.Warn("GET /metrics is DISABLED and will answer every scrape with 503; no metrics are served to anyone, authenticated or not. Set this environment variable to a secret of your choosing and put the same value in your Prometheus scrape_config (see docs/METRICS.md). The endpoint no longer serves unauthenticated, as it once did",
			slog.String("env", MetricsTokenEnv))
		return
	}
	// Worded as "a bearer token in the Authorization header" rather than
	// showing the header literally: internal/logging's redacting handler
	// runs internal/redact's pattern layer over every log message, and the
	// literal `Authorization: Bearer ...` form trips its generic
	// credential-implying-key rule — which would rewrite this purely
	// instructional line to `Authorization: [REDACTED] <token>`. The filter
	// is behaving exactly as designed (it cannot tell documentation from a
	// real header, and erring that way is the whole point); the line is what
	// changes, not the filter.
	logger.Info("GET /metrics requires a bearer token in the Authorization header and answers 401 without one (see docs/METRICS.md)",
		slog.String("env", MetricsTokenEnv))
}

// metricsAuthResult is the three-way outcome of resolving a scrape against
// ARGUS_METRICS_TOKEN. Three, not two, because "no token is configured" and
// "the wrong token was presented" are different operator problems and must
// not collapse into one response — see this file's doc comment on 503 vs
// 401.
type metricsAuthResult int

const (
	// metricsNotConfigured: ARGUS_METRICS_TOKEN is unset. The endpoint is
	// disabled; nothing a caller sends can change that.
	metricsNotConfigured metricsAuthResult = iota
	// metricsUnauthorized: a token is configured and the request did not
	// present it (or presented the wrong one).
	metricsUnauthorized
	// metricsAllowed: a token is configured and the request matched it.
	metricsAllowed
)

// checkMetricsAuth resolves a scrape against ARGUS_METRICS_TOKEN, read fresh
// per request (an env var, not something that changes at runtime in
// practice, but resolving it once at startup and caching it would just be a
// second thing that could drift from the actual environment — os.Getenv is a
// map lookup, not worth avoiding here).
//
// The configured token is compared in constant time
// (crypto/subtle.ConstantTimeCompare) — the same discipline
// internal/authz/password.go and sso_handoff.go already apply to every other
// secret comparison in this codebase, so a byte-at-a-time early-exit compare
// can't be used to guess the token faster than brute force alone would
// allow.
//
// There is deliberately no branch here that returns metricsAllowed with an
// empty `want`. An unset variable can only produce metricsNotConfigured, so
// the "no token configured means everyone is authorized" path is absent from
// the code rather than merely unreachable — this function is the single
// place that decision could be reintroduced by accident.
func checkMetricsAuth(r *http.Request) metricsAuthResult {
	want := os.Getenv(MetricsTokenEnv)
	if want == "" {
		return metricsNotConfigured
	}
	got, ok := bearerToken(r)
	if !ok {
		return metricsUnauthorized
	}
	// Equal-length requirement first: ConstantTimeCompare itself returns 0
	// (not equal) for mismatched lengths without indexing out of bounds, but
	// doing the length check explicitly keeps the intent legible — this is
	// not itself a timing oracle (Go's short-circuit `&&` on a length
	// comparison leaks nothing about the SECRET's bytes, only its length,
	// which ARGUS_METRICS_TOKEN's own operator already knows).
	if len(got) == len(want) && subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1 {
		return metricsAllowed
	}
	return metricsUnauthorized
}

// bearerToken extracts the credential from a standard
// `Authorization: Bearer <token>` header. ok is false for a missing header,
// a different scheme, or an empty token — never treated as "provided the
// empty string," which is what would let an unset ARGUS_METRICS_TOKEN's own
// zero value be satisfied by a request that sent no credential at all.
func bearerToken(r *http.Request) (token string, ok bool) {
	const prefix = "Bearer "
	h := r.Header.Get("Authorization")
	if !strings.HasPrefix(h, prefix) {
		return "", false
	}
	token = strings.TrimPrefix(h, prefix)
	if token == "" {
		return "", false
	}
	return token, true
}

func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	switch checkMetricsAuth(r) {
	case metricsNotConfigured:
		// No WWW-Authenticate header: there is no credential that would
		// help, and advertising a challenge here would send the operator to
		// fix the wrong end. Deliberately no Retry-After either — this does
		// not become available by waiting, only by configuring the hub.
		writeProblem(w, http.StatusServiceUnavailable, "https://argus.io/errors/metrics-not-configured",
			"Metrics endpoint is disabled",
			"The hub has no "+MetricsTokenEnv+" configured, so GET /metrics serves nothing. Set that environment variable on the hub (Helm: api.metricsToken or api.metricsTokenExistingSecret) and send the same value as a bearer token. See docs/METRICS.md.")
		return
	case metricsUnauthorized:
		w.Header().Set("WWW-Authenticate", `Bearer realm="argus-metrics"`)
		writeProblem(w, http.StatusUnauthorized, "https://argus.io/errors/unauthorized",
			"Missing or invalid metrics bearer token", "")
		return
	}
	// This handler otherwise does nothing beyond triggering the two
	// DB-backed gauges' own bounded, TTL-gated refresh and then writing
	// whatever internal/metrics.DefaultRegistry currently holds — every
	// other metric this hub exports is updated at its own event, not here.
	// See internal/orchestrator.RefreshIncidentStateMetrics' own doc
	// comment for why calling it on every scrape is safe;
	// internal/gateway.HealthMonitor's cluster-state gauge needs no
	// equivalent call here at all, because it refreshes on its own
	// health-sweep tick, not on scrape.
	//
	// Note this runs only on the authorized path: an unauthenticated or
	// unconfigured scrape must not be able to make the hub query Postgres.
	orchestrator.RefreshIncidentStateMetrics(r.Context(), s.db.Pool)
	metrics.Handler().ServeHTTP(w, r)
}
