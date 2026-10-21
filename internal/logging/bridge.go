package logging

import (
	"context"
	"log"
	"log/slog"
	"strings"
)

// bridgeStandardLog points the standard library's `log` package at this
// package's handler chain.
//
// This is what makes T22's "migrate incrementally" instruction safe rather
// than merely cheap. There are hundreds of log.Printf call sites left; with
// this bridge every one of them still produces a JSON record with a
// timestamp, a level, and the same redaction pass as a converted call site.
// What an unconverted line does NOT get is the thing conversion is actually
// for: structured fields, and — since log.Printf takes no context — the
// correlation id. So the output is uniform from day one and the remaining
// work is purely about join keys, not about format.
//
// The bridged record carries unstructured=true. That is not decoration: it
// is the query that answers "how much of this trail is still unconverted",
// and it is how a support engineer reading a bundle knows that the absence
// of a request_id on a line is a migration gap rather than evidence that
// the line happened outside any request.
//
// No recursion risk: the chain's encoder writes to its io.Writer (stderr)
// directly, never back through the `log` package.
func bridgeStandardLog() {
	// The standard logger's own timestamp prefix has to go — the handler
	// writes a structured, RFC3339 `time` field, and leaving log's
	// "2026/09/24 11:22:33 " prefix in place would bake a second, differently
	// formatted timestamp into the message text of every bridged line.
	log.SetFlags(0)
	log.SetPrefix("")
	log.SetOutput(bridgeWriter{})
}

type bridgeWriter struct{}

func (bridgeWriter) Write(p []byte) (int, error) {
	msg := strings.TrimRight(string(p), "\n")
	if msg == "" {
		return len(p), nil
	}
	// Level inference is deliberately minimal — one rule, for the one
	// convention this codebase actually follows (cmd/hub's startup checks
	// and several sweepers write "...: WARNING: ..."). Guessing a level
	// from the presence of the word "error" or "failed" in free text would
	// be wrong often enough to be worse than a uniform Info: a line reading
	// "no error budget configured" is not an error. Real level fidelity is
	// what converting a call site buys, and pretending to have it here
	// would hide how much is left to convert.
	level := slog.LevelInfo
	if strings.Contains(msg, "WARNING") {
		level = slog.LevelWarn
	}
	bridgeLogger.LogAttrs(context.Background(), level, msg, slog.Bool("unstructured", true))
	return len(p), nil
}

// bridgeLogger has no component attribute: a bridged line's origin package
// is not knowable from its bytes, and inventing one (say, from the "api: "
// prefix most of these lines happen to carry) would produce a component
// field that is right most of the time, which is the worst kind.
var bridgeLogger = For("")
