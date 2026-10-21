// Package logging is ARGUS's structured-logging foundation (PROJECT.md T22,
// and the emission half of T23's correlation id).
//
// # What this replaces, and why it is a package rather than a convention
//
// Before this package the hub logged through the standard library's `log`
// package at 846 call sites: no levels, no fields, no JSON. A single
// investigation's trail could not be isolated without grepping free text, a
// noisy subsystem could not be turned down in production, and nothing could
// be shipped to Loki or ELK with usable fields. For a self-hosted product
// whose support story is "send us a redacted diagnostics bundle", that is
// the operability defect T22 names.
//
// Three things had to be true at once, which is what makes this a package
// and not a one-line slog.SetDefault in cmd/hub:
//
//  1. **The migration has to be incremental.** T22 says so explicitly, and a
//     one-pass rewrite of 846 call sites is exactly the kind of diff that
//     hides a real change among the mechanical ones. So Setup also BRIDGES
//     the standard `log` package into this handler chain (see bridge.go):
//     an unconverted log.Printf still comes out as a JSON record, with a
//     level, a timestamp and the same redaction pass — it simply carries no
//     structured fields and no correlation id, which is precisely what
//     converting a call site buys. There is no window in which half the
//     hub's output is JSON and half is plain text.
//
//  2. **A structured field must not become a redaction bypass.** The
//     pattern layer in internal/redact applies to freeform log text today;
//     it applies to every attribute value here too, in the handler, not at
//     the call site. See redacthandler.go — and redact_egress_test.go in
//     this package, which is the structural enforcement, modelled on
//     internal/agent/redact_egress_test.go's precedent.
//
//  3. **A package-level logger var must work regardless of init order.**
//     `var logger = logging.For("api")` runs during package initialization,
//     before main() has had a chance to call Setup. A logger built over
//     slog.Default() at that moment would be frozen to the pre-Setup
//     handler forever. For() therefore returns a logger over an indirect
//     handler that resolves the installed root handler at log time, cached
//     against a generation counter so the indirection costs one atomic load
//     per record rather than a rebuilt handler chain.
//
// # The fixed attribute set
//
// T22 names four attributes, and they are the join keys the whole point of
// this exercise rests on: incident_id, cluster_id, actor_id, request_id.
// They are declared once here as constants and set through the helpers
// below so that "the same field spelled two ways" cannot happen — a
// log-aggregation index keyed on `incident_id` and a stray `incidentID`
// somewhere are, from a support engineer's point of view, a missing trail.
//
// Three of the four are usually already known where the log line is
// written. request_id is not: it is minted at an entry point (an HTTP
// request in internal/api's requireAuth, or one background worker's unit of
// work) and has to reach call sites several packages deep that never asked
// for it. That is what ContextWith/NewUnitOfWork and the context handler
// are for: the attributes ride on context.Context, and any call site using
// the *Context logging methods (InfoContext, ErrorContext, ...) picks them
// up without naming them.
package logging

import (
	"context"
	"io"
	"log/slog"
	"os"
	"strings"
	"sync"
	"sync/atomic"

	"argus/internal/domain"
)

// The fixed attribute set from PROJECT.md T22, plus the two structural keys
// every record carries. Snake case, matching the Prometheus/Loki label
// convention this hub's metrics already use, and matching the column names
// these values have in Postgres (incidents.id is exposed as incident_id
// everywhere it is a foreign key) — so an operator moving between a log
// query and a SQL query is typing the same identifier.
const (
	KeyIncidentID = "incident_id"
	KeyClusterID  = "cluster_id"
	KeyActorID    = "actor_id"
	KeyRequestID  = "request_id"

	// KeyComponent names the subsystem that emitted the record — "api",
	// "gateway", "autoanalyze", .... Set once by For() rather than at each
	// call site.
	KeyComponent = "component"

	// KeyError is where an error's text goes. A single spelling, because
	// "error" vs "err" is the same index-splitting problem as incident_id
	// vs incidentID.
	KeyError = "error"
)

// RequestIDPrefix is the domain.NewID prefix for a correlation id. Not in
// internal/domain's own prefix list: a correlation id is not a persisted
// domain object with a table of its own — it is stamped onto other rows
// (analyses.request_id) and onto log records. Keeping it here keeps
// domain's list a list of things that exist as rows.
const RequestIDPrefix = "req"

// NewRequestID mints a correlation id. A prefixed ULID like every other id
// in this codebase, for two reasons beyond consistency: it sorts
// lexicographically by mint time, and the `req_` prefix makes it
// unmistakable in a log line or a support ticket ("quote the requestId from
// the error you saw") which kind of id an operator has been handed.
func NewRequestID() string { return domain.NewID(RequestIDPrefix) }

// Attribute constructors. Thin, but they are what make the fixed set
// enforceable by grep and by review: a call site that writes
// slog.String("incident_id", id) is indistinguishable from one that writes
// slog.String("incidentId", id) until someone reads it, whereas
// logging.IncidentID(id) cannot be spelled wrong.

func IncidentID(id string) slog.Attr { return slog.String(KeyIncidentID, id) }
func ClusterID(id string) slog.Attr  { return slog.String(KeyClusterID, id) }
func ActorID(id string) slog.Attr    { return slog.String(KeyActorID, id) }
func RequestID(id string) slog.Attr  { return slog.String(KeyRequestID, id) }

// Err renders an error as a string attribute rather than slog.Any(err).
//
// Two reasons, both load-bearing. First, slog's JSONHandler marshals an
// Any-valued attribute with encoding/json, and most error types marshal to
// `{}` — the message, which is the entire content of the log line, would be
// silently dropped. Second, an error string is freeform text that routinely
// carries a connection string, a URL with userinfo, or a provider's echo of
// a token; as a plain string it goes through the redacting handler's string
// path (see redacthandler.go) rather than its structured fallback.
//
// A nil error yields an empty-valued attr rather than being omitted, so a
// "logged the error branch with no error" bug is visible in the output
// instead of looking like a successful line.
func Err(err error) slog.Attr {
	if err == nil {
		return slog.String(KeyError, "")
	}
	return slog.String(KeyError, err.Error())
}

// --------------------------------------------------------------- the root

// root is the installed handler chain. Held here rather than read back out
// of slog.Default() so that For()'s indirection has one authoritative
// source even in a test binary that never calls Setup (where slog.Default()
// is the standard library's own text handler, writing through the `log`
// package — which, once bridged, would be a loop).
//
// The pre-Setup default is a real chain, not a discard: a package that logs
// during init, or a test that logs, should produce readable output rather
// than nothing. It writes to stderr at Info, the same place and level the
// standard log package would have.
var (
	rootMu sync.RWMutex
	root   = newChain(os.Stderr, slog.LevelInfo, formatJSON)
	// rootGen is bumped on every install so indirectHandler's per-logger
	// cache knows to rebuild. An atomic rather than a lock on the log path.
	rootGen atomic.Int64
)

type format int

const (
	formatJSON format = iota
	formatText
)

// newChain assembles the handler chain, outermost first:
//
//	contextHandler  — copies the attributes riding on context.Context onto
//	                  the record, so a call site that passes ctx gets
//	                  request_id/incident_id without naming them
//	redactHandler   — applies internal/redact's pattern layer to the message
//	                  and to every attribute value
//	slog.JSONHandler — the exposition
//
// Redaction sits INSIDE the context handler deliberately: attributes
// injected from the context are redacted on the same terms as attributes
// named at the call site. There is no path to the encoder that skips it.
func newChain(w io.Writer, level slog.Level, f format) slog.Handler {
	opts := &slog.HandlerOptions{Level: level}
	var base slog.Handler
	if f == formatText {
		base = slog.NewTextHandler(w, opts)
	} else {
		base = slog.NewJSONHandler(w, opts)
	}
	return &contextHandler{next: &redactHandler{next: base, jsonEncoder: f != formatText}}
}

// Setup installs the process-wide handler chain from the environment and
// bridges the standard `log` package into it. Called once, early, from a
// binary's main — everything else in the tree either uses a package-local
// logger from For() or logs through the bridged `log` package.
//
// Environment:
//
//	ARGUS_LOG_LEVEL   debug | info | warn | error   (default info)
//	ARGUS_LOG_FORMAT  json | text                   (default json)
//
// text is for a human tailing a local hub; json is the default because the
// deployed case — shipping to Loki or ELK, or being collected into a
// support bundle — is the one T22 exists for, and a default that has to be
// switched on in production is a default that will be missing from the
// bundle that matters.
//
// An unrecognised value for either is a warning and the default, never a
// fatal: a typo in a log setting must not stop a hub from starting.
func Setup() {
	install(os.Stderr, LevelFromEnv(), formatFromEnv())
	bridgeStandardLog()
}

// SetupForTesting installs a chain writing to w and returns a function that
// restores the previous one. Exported for this package's own tests and for
// a test elsewhere that needs to assert on emitted records; never called by
// production code.
func SetupForTesting(w io.Writer, level slog.Level) func() {
	rootMu.Lock()
	prev := root
	rootMu.Unlock()
	install(w, level, formatJSON)
	return func() {
		rootMu.Lock()
		root = prev
		rootMu.Unlock()
		rootGen.Add(1)
		slog.SetDefault(slog.New(prev))
	}
}

func install(w io.Writer, level slog.Level, f format) {
	h := newChain(w, level, f)
	rootMu.Lock()
	root = h
	rootMu.Unlock()
	rootGen.Add(1)
	// slog.Default() is set too, so a third-party or future call site using
	// the package-level slog functions lands in the same chain — including
	// the same redaction pass — rather than in slog's own default handler.
	slog.SetDefault(slog.New(h))
}

func currentRoot() slog.Handler {
	rootMu.RLock()
	defer rootMu.RUnlock()
	return root
}

// LevelFromEnv resolves ARGUS_LOG_LEVEL. Exported because cmd/hub logs the
// resolved level at startup: "why am I not seeing debug lines" is answered
// by the hub's own first log line rather than by reading this function.
func LevelFromEnv() slog.Level {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("ARGUS_LOG_LEVEL"))) {
	case "", "info":
		return slog.LevelInfo
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

func formatFromEnv() format {
	if strings.EqualFold(strings.TrimSpace(os.Getenv("ARGUS_LOG_FORMAT")), "text") {
		return formatText
	}
	return formatJSON
}

// ------------------------------------------------------ package loggers

// For returns the package-local logger a converted package holds in a
// package-level var:
//
//	var logger = logging.For("autoanalyze")
//
// Every record it emits carries component=<name>. The returned logger
// resolves the installed root handler at log time (see this package's doc
// comment, point 3), so it is safe to build one during package
// initialization, before main has called Setup.
func For(component string) *slog.Logger {
	return slog.New(&indirectHandler{component: component})
}

// indirectHandler defers to whatever chain is installed when a record is
// actually written, instead of capturing one at construction.
//
// ops records WithAttrs/WithGroup calls in the order they were made,
// because that order is semantically load-bearing in slog (attributes added
// before a group belong outside it) and cannot be reconstructed from two
// separate slices.
type indirectHandler struct {
	component string
	ops       []handlerOp

	mu    sync.Mutex
	gen   int64
	built slog.Handler
}

type handlerOp struct {
	group string      // non-empty for a WithGroup
	attrs []slog.Attr // non-nil for a WithAttrs
}

func (h *indirectHandler) resolve() slog.Handler {
	gen := rootGen.Load()
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.built != nil && h.gen == gen {
		return h.built
	}
	built := currentRoot()
	if h.component != "" {
		built = built.WithAttrs([]slog.Attr{slog.String(KeyComponent, h.component)})
	}
	for _, op := range h.ops {
		if op.group != "" {
			built = built.WithGroup(op.group)
			continue
		}
		built = built.WithAttrs(op.attrs)
	}
	h.built = built
	h.gen = gen
	return built
}

func (h *indirectHandler) Enabled(ctx context.Context, l slog.Level) bool {
	return h.resolve().Enabled(ctx, l)
}

func (h *indirectHandler) Handle(ctx context.Context, r slog.Record) error {
	return h.resolve().Handle(ctx, r)
}

func (h *indirectHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	if len(attrs) == 0 {
		return h
	}
	return &indirectHandler{component: h.component, ops: appendOp(h.ops, handlerOp{attrs: attrs})}
}

func (h *indirectHandler) WithGroup(name string) slog.Handler {
	if name == "" {
		return h
	}
	return &indirectHandler{component: h.component, ops: appendOp(h.ops, handlerOp{group: name})}
}

// appendOp copies rather than appending in place: slog handlers are shared
// across goroutines once a logger is stored in a package var, and two
// derived loggers appending into the same backing array would corrupt each
// other's op list.
func appendOp(ops []handlerOp, op handlerOp) []handlerOp {
	out := make([]handlerOp, len(ops), len(ops)+1)
	copy(out, ops)
	return append(out, op)
}
