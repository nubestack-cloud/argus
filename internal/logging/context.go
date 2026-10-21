package logging

import (
	"context"
	"log/slog"
)

// This file is PROJECT.md T23's propagation mechanism: the correlation id,
// and the other fixed attributes that are known at an entry point rather
// than at the call site, ride on context.Context and are stamped onto every
// record whose call site passed that context.
//
// Why the context and not an explicit parameter: the id is minted at an
// entry point (requireAuth, or one background worker's unit of work) and
// needed several packages deep — internal/gateway's tunnel tool call,
// internal/llm's model call, internal/api's audit write. Every one of those
// already takes a ctx, and none of them should grow a correlationID string
// parameter that every intermediate function has to thread through and that
// one of them will eventually forget. The ctx is the only thing that
// already reaches all of them.
//
// The cost of that choice, stated plainly: a call site that logs with
// Info() instead of InfoContext() gets no correlation id, silently. That is
// the one thing to check when a converted line turns out not to join up.

type ctxAttrsKey struct{}

// ContextWith returns a context carrying attrs in addition to whatever the
// parent already carried. Attributes accumulate, and a later value for the
// same key replaces the earlier one (see dedupe in contextHandler.Handle),
// so a worker may narrow a broad context with a more specific incident_id
// without the outer one having to be removed first.
func ContextWith(ctx context.Context, attrs ...slog.Attr) context.Context {
	if len(attrs) == 0 {
		return ctx
	}
	existing := AttrsFrom(ctx)
	merged := make([]slog.Attr, 0, len(existing)+len(attrs))
	merged = append(merged, existing...)
	merged = append(merged, attrs...)
	return context.WithValue(ctx, ctxAttrsKey{}, merged)
}

// AttrsFrom returns the attributes riding on ctx, or nil. The returned
// slice must not be modified — ContextWith copies rather than appending in
// place for exactly that reason.
func AttrsFrom(ctx context.Context) []slog.Attr {
	if ctx == nil {
		return nil
	}
	attrs, _ := ctx.Value(ctxAttrsKey{}).([]slog.Attr)
	return attrs
}

// ContextWithRequestID stamps a correlation id onto ctx.
func ContextWithRequestID(ctx context.Context, id string) context.Context {
	if id == "" {
		return ctx
	}
	return ContextWith(ctx, RequestID(id))
}

// RequestIDFrom reads the correlation id back out of ctx, or "" if there is
// none. Used where the id has to leave the logging system and be persisted
// or returned: analyses.request_id (internal/api's PersistAnalysis) and the
// RFC 9457 problem body's requestId member.
func RequestIDFrom(ctx context.Context) string {
	attrs := AttrsFrom(ctx)
	// Backwards: a nested unit of work may have narrowed an outer id, and
	// the innermost one is the one the record will carry.
	for i := len(attrs) - 1; i >= 0; i-- {
		if attrs[i].Key == KeyRequestID {
			if s := attrs[i].Value.String(); s != "" {
				return s
			}
		}
	}
	return ""
}

// NewUnitOfWork is T23's background-worker half: it mints a correlation id
// for one discrete piece of background work and returns the context that
// carries it, plus the id itself.
//
// "One unit of work" is deliberately not "one worker" and not "one
// process". A sweeper that ticks every 30 seconds for a month is not a
// thing anybody can ask a question about; one tick, or one incident's
// investigation inside that tick, is. The board's own wording — "each
// background worker's own unit of work, since those are where the hard
// questions arise" — is about being able to ask "what happened in the run
// that touched this incident", so the granularity is chosen per caller: a
// sweep tick for the cheap sweepers, one incident's investigation for
// internal/autoanalyze.
//
// The returned context inherits the parent's cancellation, so a unit of
// work started off a worker context still stops when the hub drains.
func NewUnitOfWork(ctx context.Context, attrs ...slog.Attr) (context.Context, string) {
	id := NewRequestID()
	ctx = ContextWith(ctx, append([]slog.Attr{RequestID(id)}, attrs...)...)
	return ctx, id
}

// contextHandler copies the context's attributes onto each record before
// passing it down the chain. Outermost in the chain (see newChain) so the
// redacting handler below it treats a context-injected attribute exactly
// like one named at the call site.
type contextHandler struct {
	next slog.Handler
}

func (h *contextHandler) Enabled(ctx context.Context, l slog.Level) bool {
	return h.next.Enabled(ctx, l)
}

func (h *contextHandler) Handle(ctx context.Context, r slog.Record) error {
	attrs := AttrsFrom(ctx)
	if len(attrs) == 0 {
		return h.next.Handle(ctx, r)
	}
	// A fresh record rather than r.AddAttrs on the original: Record's
	// documented copy semantics make in-place mutation of a record the
	// caller may still hold unsafe.
	nr := slog.NewRecord(r.Time, r.Level, r.Message, r.PC)

	// The call site wins over the context for a key they both set, and the
	// context's later value wins over its own earlier one. slog's JSON
	// encoder emits duplicate keys verbatim rather than collapsing them,
	// and two incident_id fields in one record is worse than either value
	// alone: a log query matching on the field would match a record that is
	// only half about that incident.
	callSite := make(map[string]struct{}, r.NumAttrs())
	r.Attrs(func(a slog.Attr) bool {
		callSite[a.Key] = struct{}{}
		return true
	})
	seen := make(map[string]int, len(attrs))
	kept := make([]slog.Attr, 0, len(attrs))
	for _, a := range attrs {
		if _, ok := callSite[a.Key]; ok {
			continue
		}
		if i, ok := seen[a.Key]; ok {
			kept[i] = a
			continue
		}
		seen[a.Key] = len(kept)
		kept = append(kept, a)
	}
	nr.AddAttrs(kept...)
	r.Attrs(func(a slog.Attr) bool {
		nr.AddAttrs(a)
		return true
	})
	return h.next.Handle(ctx, nr)
}

func (h *contextHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &contextHandler{next: h.next.WithAttrs(attrs)}
}

func (h *contextHandler) WithGroup(name string) slog.Handler {
	return &contextHandler{next: h.next.WithGroup(name)}
}
