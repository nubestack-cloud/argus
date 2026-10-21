package logging

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"argus/internal/redact"
)

// redactHandler is T22's non-negotiable half: "a structured field must not
// become a redaction bypass."
//
// # What the defect would have been
//
// internal/redact's pattern layer already applies to freeform log text —
// the container log lines and event messages the agent captures are run
// through redact.Text before they cross the tunnel, and that is the control
// that keeps a bearer token out of a log line. Structured logging adds a
// second shape for the same data: instead of "pod restarted: <line>" as one
// interpolated string, a converted call site writes
// slog.String("reason", line). Nothing about that new shape is covered by
// the old argument, and the natural place to put "the interesting value" in
// a structured record is exactly an attribute. So the pass happens HERE, in
// the handler, where no call site can be written that skips it — not at the
// call sites, which is a convention, and conventions are what the 2026-09-23
// review found 846 instances of.
//
// # Relationship to capture-time redaction — read this before changing it
//
// internal/redact's package doc says every caller lives in internal/agent,
// on the path between a Kubernetes API response and a tunnel write, and
// that a hub-side caller must not be added and the rule considered
// satisfied. That rule stands and this does not weaken it. This is not a
// relocation of the control: it is a second, independent pass on a
// DIFFERENT egress path — the hub's own log stream, which leaves the
// product in a diagnostics bundle. Capture-time redaction in the agent is
// still what stops secret material entering the hub at all; this stops what
// the hub itself formats (a connection string in a pgx error, a provider's
// echo of an API key, an Authorization header in an outbound-request debug
// line) from entering the bundle. Weakening either on the strength of the
// other is the mistake.
//
// # What it covers, and what it does not
//
// Covered: the record's message; every string attribute, including ones
// added via WithAttrs on a derived logger and ones injected from the
// context; strings nested inside groups; error and fmt.Stringer values; and
// any other non-primitive value, by marshalling it to JSON and running
// internal/redact's full two-layer Object filter over that.
//
// Not covered, and honestly so: numbers, booleans, durations and times pass
// through untouched (no recognised credential format is a float64), and the
// pattern layer itself is explicitly best-effort — a credential with no
// recognisable format in an unnamed field can still cross, exactly as
// internal/redact's own doc comment says. redact_egress_test.go in this
// package pins the covered set structurally.
type redactHandler struct {
	next slog.Handler
	// jsonEncoder is true when the handler below writes JSON. It decides
	// only how a non-primitive value's redacted form is handed on: as a
	// json.RawMessage (which slog's JSON encoder emits as real nested JSON)
	// or as a plain string (which is what stays readable under the text
	// handler, where a RawMessage would render as a byte slice). It never
	// decides WHETHER something is redacted.
	jsonEncoder bool
}

func (h *redactHandler) Enabled(ctx context.Context, l slog.Level) bool {
	return h.next.Enabled(ctx, l)
}

func (h *redactHandler) Handle(ctx context.Context, r slog.Record) error {
	nr := slog.NewRecord(r.Time, r.Level, redact.Text(r.Message), r.PC)
	r.Attrs(func(a slog.Attr) bool {
		nr.AddAttrs(h.redactAttr(a))
		return true
	})
	return h.next.Handle(ctx, nr)
}

// WithAttrs redacts at the moment the derived handler is built rather than
// on every record it writes — the values are fixed, so redacting them once
// is both cheaper and equivalent.
func (h *redactHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &redactHandler{next: h.next.WithAttrs(h.redactAttrs(attrs)), jsonEncoder: h.jsonEncoder}
}

func (h *redactHandler) WithGroup(name string) slog.Handler {
	return &redactHandler{next: h.next.WithGroup(name), jsonEncoder: h.jsonEncoder}
}

func (h *redactHandler) redactAttrs(attrs []slog.Attr) []slog.Attr {
	out := make([]slog.Attr, len(attrs))
	for i, a := range attrs {
		out[i] = h.redactAttr(a)
	}
	return out
}

// redactAttr rewrites one attribute's value. The key is never rewritten: a
// key is chosen from a Go string constant at the call site, and redacting
// it would destroy the field name a log query keys on while protecting
// nothing.
func (h *redactHandler) redactAttr(a slog.Attr) slog.Attr {
	a.Value = h.redactValue(a.Value, 0)
	return a
}

// maxGroupDepth bounds the recursion into nested groups. Groups are built
// from Go source at call sites, not from cluster data, so a pathological
// depth is not reachable today — this is the same cheap structural bound
// internal/redact's own walk uses, so a future call site that builds a
// group from a decoded object cannot turn a log line into a stack
// overflow.
const maxGroupDepth = 8

func (h *redactHandler) redactValue(v slog.Value, depth int) slog.Value {
	switch v.Kind() {
	case slog.KindString:
		return slog.StringValue(redact.Text(v.String()))

	case slog.KindGroup:
		if depth >= maxGroupDepth {
			return slog.StringValue(redact.Marker)
		}
		attrs := v.Group()
		out := make([]slog.Attr, len(attrs))
		for i, a := range attrs {
			a.Value = h.redactValue(a.Value, depth+1)
			out[i] = a
		}
		return slog.GroupValue(out...)

	case slog.KindLogValuer:
		// Resolve first, then redact what it resolved to. A LogValuer is
		// application code choosing what to expose; whatever it chooses
		// still goes through this filter.
		if depth >= maxGroupDepth {
			return slog.StringValue(redact.Marker)
		}
		return h.redactValue(v.Resolve(), depth+1)

	case slog.KindAny:
		return h.redactAny(v, depth)

	default:
		// Bool, Int64, Uint64, Float64, Duration, Time. None of these can
		// carry a credential in a recognisable format, and converting them
		// to strings to run a regex over would cost more than it buys.
		return v
	}
}

// redactAny handles the escape hatch: slog.Any with something that is not a
// primitive. This is where a struct full of request parameters, a decoded
// Kubernetes object, or an error would arrive.
func (h *redactHandler) redactAny(v slog.Value, depth int) slog.Value {
	switch x := v.Any().(type) {
	case nil:
		return v
	case string:
		return slog.StringValue(redact.Text(x))
	case []byte:
		return slog.StringValue(redact.Text(string(x)))
	case error:
		// Before the string case for fmt.Stringer, because an error that
		// also implements Stringer should be rendered as its error text.
		return slog.StringValue(redact.Text(x.Error()))
	case fmt.Stringer:
		return slog.StringValue(redact.Text(x.String()))
	case json.RawMessage:
		return h.structured(redact.Object(x))
	case time.Time, time.Duration, bool,
		int, int8, int16, int32, int64,
		uint, uint8, uint16, uint32, uint64,
		float32, float64:
		return v
	}

	// Anything else: render it as JSON and run internal/redact's FULL
	// two-layer filter over the result, not just the pattern layer.
	// redact.Object drops whole field classes structurally (every
	// env[*].value, every data/stringData value), which is the layer that
	// catches a credential whose name and format give nothing away — and an
	// arbitrary struct handed to slog.Any is precisely the case where the
	// author has not thought about what is inside it.
	//
	// Fails closed in the same sense internal/redact does: a value that
	// cannot be marshalled is rendered with %v and put through the pattern
	// layer rather than passed to the encoder untouched.
	raw, err := json.Marshal(v.Any())
	if err != nil {
		return slog.StringValue(redact.Text(fmt.Sprintf("%v", v.Any())))
	}
	return h.structured(redact.Object(raw))
}

// structured hands already-redacted JSON to the encoder in the shape that
// encoder renders readably — see redactHandler.jsonEncoder.
func (h *redactHandler) structured(raw []byte) slog.Value {
	if h.jsonEncoder {
		return slog.AnyValue(json.RawMessage(raw))
	}
	return slog.StringValue(string(raw))
}
