// Package metrics is ARGUS's own Prometheus exposition endpoint (PROJECT.md
// T11's metrics half — see that row for the full defect this closes:
// "nothing exports finding ingestion, incident counts by state, analysis
// latency and cost, tunnel state, queue depth, delivery failures or
// execution outcomes ... every measurement on this board was taken by hand
// against Postgres"). It is deliberately NOT a wrapper around
// github.com/prometheus/client_golang.
//
// # Why hand-rolled rather than the standard client
//
// This repo added a dependency-vulnerability gate this same increment
// (scripts/govulncheck-gate.sh) with an EMPTY baseline — any new
// call-reachable finding in a newly-added dependency fails it outright, and
// client_golang pulls in its own transitive tree (beorn7/perks,
// cespare/xxhash/v2, prometheus/client_model, prometheus/common, and that
// package's own further dependencies) that this module has never vetted and
// does not otherwise need. The Prometheus TEXT EXPOSITION FORMAT itself
// (https://prometheus.io/docs/instrumenting/exposition_formats/) is a small,
// stable, plain-text line format — "# HELP", "# TYPE", and
// `metric{labels} value` lines — not a wire protocol that benefits from a
// shared implementation the way, say, gRPC or JWT would. Writing the ~150
// lines that produce it correctly is a smaller, more auditable surface than
// a new supply-chain dependency, for a hub that otherwise imports nothing
// Prometheus-flavoured at all. If a second consumer of richer Prometheus
// features (e.g. OpenMetrics exemplars, push gateways, client-side
// histograms with configurable exemplar sampling) ever shows up, that is the
// point at which taking the real dependency and running the vuln gate against
// it becomes the better trade — not before.
//
// # What this package is not
//
// It has no notion of a "collector" that computes its value lazily at scrape
// time from an expensive source — every metric here is a plain in-memory
// counter/gauge/histogram that some other package updates as the event it
// describes actually happens, or (for the two DB-backed gauges,
// IncidentsByState and ClustersByState) is refreshed on a bounded interval
// decoupled from Prometheus's own scrape cadence — see
// internal/orchestrator's and internal/gateway's own refresh functions for
// why each is safe to query on its own schedule. Scraping this endpoint
// itself never touches Postgres.
package metrics

import (
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// family is the common interface every metric type below satisfies so
// Registry can hold a heterogeneous list of them and write each out in
// registration order (registration order is itself deterministic here,
// since every metric is a package-level var in internal/metrics/metrics.go
// initialized in source order — Go guarantees package-level var
// initialization runs in declaration order within a file).
type family interface {
	writeExposition(w io.Writer)
}

// Registry holds every metric family this process has created. There is
// exactly one, DefaultRegistry, used by every metric constructor in this
// package — this codebase has no need for an isolated registry per test or
// per subsystem, and a second one would only invite a metric registered in
// the wrong place and silently never scraped.
type Registry struct {
	mu       sync.Mutex
	families []family
}

// DefaultRegistry is the registry every New* constructor in this package
// registers into, and the one Handler serves.
var DefaultRegistry = &Registry{}

func (r *Registry) register(f family) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.families = append(r.families, f)
}

// WriteExposition writes every registered family to w in Prometheus text
// exposition format (version 0.0.4 — the stable, widely-supported subset;
// no exemplars, no OpenMetrics-only constructs).
func (r *Registry) WriteExposition(w io.Writer) {
	r.mu.Lock()
	fams := make([]family, len(r.families))
	copy(fams, r.families)
	r.mu.Unlock()

	for _, f := range fams {
		f.writeExposition(w)
	}
}

// Handler serves DefaultRegistry's current state as a Prometheus scrape
// target.
//
// This function itself performs no authorization — it only writes the
// exposition body. The credential check happens at the call site, in
// internal/api's handleMetrics, and it is MANDATORY: a bearer token
// matching ARGUS_METRICS_TOKEN, with the endpoint disabled (503) when no
// token is configured rather than open. (This comment used to read
// "deliberately unauthenticated"; that default was removed — see
// internal/api/metrics.go's doc comment for why, and for why a scrape is
// still not routed through requireAuth.)
//
// The other half of this endpoint's safety is a property of the metrics
// themselves, and it is decided in metrics.go rather than here: every label
// attached to every metric is a closed, reviewed, low-cardinality enum this
// codebase already defines elsewhere (an orchestrator.State*, a
// remediation.ActionType, an outcome string) — never a cluster display
// name, namespace, object name, or any other value that identifies a
// specific object or fleet member. See each metric's own comment in
// metrics.go for that argument made per-label, not asserted once here.
func Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// text/plain with an explicit version parameter is the exposition
		// format's own registered content type — see the format doc linked
		// in this package's doc comment. Prometheus's scraper accepts plain
		// "text/plain" too, but naming the version is what tells a human
		// curling this endpoint, or a second scraper with stricter content
		// negotiation, exactly what they're looking at.
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		DefaultRegistry.WriteExposition(w)
	})
}

// escapeLabelValue applies the exposition format's own escaping rule for a
// quoted label value: backslash and double-quote are backslash-escaped,
// and a literal newline (which cannot appear in a valid Prometheus label
// value at all) is escaped defensively anyway rather than trusted to be
// absent — every label value this package ever writes is a closed enum
// constant from this codebase's own Go source (see Handler's doc comment),
// never external input, but escaping costs nothing and a future label that
// forgets that invariant fails safe instead of producing a line Prometheus
// cannot parse.
func escapeLabelValue(v string) string {
	v = strings.ReplaceAll(v, `\`, `\\`)
	v = strings.ReplaceAll(v, `"`, `\"`)
	v = strings.ReplaceAll(v, "\n", `\n`)
	return v
}

// formatFloat renders a metric value the way the exposition format expects —
// Go's default float formatting ("%v"/strconv.FormatFloat with -1 precision)
// already produces "5", "0.02", etc. without a trailing ".0" for integral
// values written as float64, which is valid and idiomatic here; Prometheus
// parses both forms identically.
func formatFloat(v float64) string {
	return strconv.FormatFloat(v, 'f', -1, 64)
}

// writeHelpAndType writes the two leading comment lines every metric family
// carries, shared by Counter/Gauge/Histogram's own writeExposition.
func writeHelpAndType(w io.Writer, name, help, typ string) {
	if help != "" {
		fmt.Fprintf(w, "# HELP %s %s\n", name, escapeHelp(help))
	}
	fmt.Fprintf(w, "# TYPE %s %s\n", name, typ)
}

// escapeHelp escapes a HELP line's free-text description — backslash and
// newline only; HELP text is not quoted, so a double-quote needs no escaping,
// but an embedded newline would otherwise break the line-oriented format.
func escapeHelp(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, "\n", `\n`)
	return s
}

// labelKey joins label values into one map key. "\xff" is not valid UTF-8
// and cannot appear in any label value this package ever writes (all closed
// Go string-constant enums — see Handler's doc comment), so it cannot
// collide two distinct label tuples into one key.
func labelKey(values []string) string {
	return strings.Join(values, "\xff")
}

// sortedSeriesKeys returns m's keys sorted for deterministic exposition
// output — not load-bearing for Prometheus itself (which does not care about
// line order), but it is what makes this package's own tests, and a human
// diffing two scrapes, sane.
func sortedSeriesKeys(m map[string][]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
