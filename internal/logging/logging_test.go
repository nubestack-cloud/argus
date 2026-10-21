package logging

import (
	"bytes"
	"context"
	"encoding/json"
	"log"
	"log/slog"
	"strings"
	"testing"
)

// decodeRecords parses the buffer as one JSON object per line.
func decodeRecords(t *testing.T, buf *bytes.Buffer) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, line := range strings.Split(strings.TrimRight(buf.String(), "\n"), "\n") {
		if line == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("log line is not JSON: %v\nline: %s", err, line)
		}
		out = append(out, m)
	}
	return out
}

// TestPackageLoggerBuiltBeforeSetupStillUsesTheInstalledChain is the
// init-order property this package's doc comment calls point 3: a
// package-level `var logger = logging.For("x")` is constructed during
// package initialization, long before main calls Setup, and must still
// write through whatever chain Setup later installs.
func TestPackageLoggerBuiltBeforeSetupStillUsesTheInstalledChain(t *testing.T) {
	logger := For("earlybird") // built BEFORE the install below, on purpose

	var buf bytes.Buffer
	restore := SetupForTesting(&buf, slog.LevelDebug)
	defer restore()

	logger.Info("hello")

	recs := decodeRecords(t, &buf)
	if len(recs) != 1 {
		t.Fatalf("got %d records, want 1: %s", len(recs), buf.String())
	}
	if recs[0][KeyComponent] != "earlybird" {
		t.Fatalf("component = %v, want earlybird", recs[0][KeyComponent])
	}
}

// TestContextAttributesReachTheRecord is T23's propagation in miniature:
// an id minted at an entry point reaches a call site several frames down
// that never named it.
func TestContextAttributesReachTheRecord(t *testing.T) {
	var buf bytes.Buffer
	restore := SetupForTesting(&buf, slog.LevelDebug)
	defer restore()

	ctx, id := NewUnitOfWork(context.Background(), IncidentID("inc_1"), ClusterID("cl_1"))
	if !strings.HasPrefix(id, RequestIDPrefix+"_") {
		t.Fatalf("minted id %q does not carry the %q prefix", id, RequestIDPrefix)
	}
	if got := RequestIDFrom(ctx); got != id {
		t.Fatalf("RequestIDFrom = %q, want %q", got, id)
	}

	For("worker").InfoContext(ctx, "did a thing", ActorID("usr_1"))

	recs := decodeRecords(t, &buf)
	if len(recs) != 1 {
		t.Fatalf("got %d records, want 1", len(recs))
	}
	for key, want := range map[string]string{
		KeyRequestID:  id,
		KeyIncidentID: "inc_1",
		KeyClusterID:  "cl_1",
		KeyActorID:    "usr_1",
		KeyComponent:  "worker",
	} {
		if got := recs[0][key]; got != want {
			t.Errorf("%s = %v, want %v", key, got, want)
		}
	}
}

// TestCallSiteWinsOverContextForTheSameKey — a nested unit of work, or a
// handler logging about an incident other than the one its request context
// names, must produce ONE value for the key, not two fields with the same
// name (which slog's JSON encoder would otherwise emit verbatim).
func TestCallSiteWinsOverContextForTheSameKey(t *testing.T) {
	var buf bytes.Buffer
	restore := SetupForTesting(&buf, slog.LevelDebug)
	defer restore()

	ctx := ContextWith(context.Background(), IncidentID("inc_outer"))
	For("x").InfoContext(ctx, "m", IncidentID("inc_inner"))

	line := buf.String()
	if strings.Count(line, `"`+KeyIncidentID+`"`) != 1 {
		t.Fatalf("expected exactly one %s field, got: %s", KeyIncidentID, line)
	}
	recs := decodeRecords(t, &buf)
	if recs[0][KeyIncidentID] != "inc_inner" {
		t.Fatalf("incident_id = %v, want the call site's inc_inner", recs[0][KeyIncidentID])
	}
}

// TestContextWithOverridesItsOwnEarlierValue — narrowing a context twice
// with the same key must not leave both values on the record.
func TestContextWithOverridesItsOwnEarlierValue(t *testing.T) {
	var buf bytes.Buffer
	restore := SetupForTesting(&buf, slog.LevelDebug)
	defer restore()

	ctx := ContextWith(context.Background(), ClusterID("cl_a"))
	ctx = ContextWith(ctx, ClusterID("cl_b"))
	For("x").InfoContext(ctx, "m")

	if strings.Count(buf.String(), `"`+KeyClusterID+`"`) != 1 {
		t.Fatalf("expected exactly one %s field, got: %s", KeyClusterID, buf.String())
	}
	if recs := decodeRecords(t, &buf); recs[0][KeyClusterID] != "cl_b" {
		t.Fatalf("cluster_id = %v, want cl_b", recs[0][KeyClusterID])
	}
}

// TestBridgedStandardLogIsStructuredAndMarked — the incremental-migration
// property: an unconverted log.Printf still produces a levelled JSON
// record, and it is marked so the remaining migration surface is a query
// rather than a guess.
func TestBridgedStandardLogIsStructuredAndMarked(t *testing.T) {
	var buf bytes.Buffer
	restore := SetupForTesting(&buf, slog.LevelDebug)
	defer restore()
	prevOut, prevFlags := log.Writer(), log.Flags()
	bridgeStandardLog()
	defer func() { log.SetOutput(prevOut); log.SetFlags(prevFlags) }()

	log.Printf("api: something happened")
	log.Printf("api: WARNING: something else")

	recs := decodeRecords(t, &buf)
	if len(recs) != 2 {
		t.Fatalf("got %d records, want 2: %s", len(recs), buf.String())
	}
	if recs[0]["msg"] != "api: something happened" {
		t.Errorf("msg = %v", recs[0]["msg"])
	}
	if recs[0]["level"] != "INFO" {
		t.Errorf("level = %v, want INFO", recs[0]["level"])
	}
	if recs[0]["unstructured"] != true {
		t.Errorf("unstructured = %v, want true", recs[0]["unstructured"])
	}
	if recs[1]["level"] != "WARN" {
		t.Errorf("WARNING line level = %v, want WARN", recs[1]["level"])
	}
}

// TestLevelFromEnv covers the one thing an operator will get wrong at 3am:
// an unrecognised value must not silence the hub or stop it starting.
func TestLevelFromEnv(t *testing.T) {
	for in, want := range map[string]slog.Level{
		"":        slog.LevelInfo,
		"debug":   slog.LevelDebug,
		"DEBUG":   slog.LevelDebug,
		" warn ":  slog.LevelWarn,
		"warning": slog.LevelWarn,
		"error":   slog.LevelError,
		"verbose": slog.LevelInfo, // unrecognised -> default, never a failure
	} {
		t.Setenv("ARGUS_LOG_LEVEL", in)
		if got := LevelFromEnv(); got != want {
			t.Errorf("ARGUS_LOG_LEVEL=%q -> %v, want %v", in, got, want)
		}
	}
}

// TestLevelFiltering proves the level is actually applied — the "turn noise
// down in production, debug up temporarily" half of T22.
func TestLevelFiltering(t *testing.T) {
	var buf bytes.Buffer
	restore := SetupForTesting(&buf, slog.LevelWarn)
	defer restore()

	l := For("x")
	l.Debug("dropped")
	l.Info("dropped")
	l.Warn("kept")
	l.Error("kept")

	if recs := decodeRecords(t, &buf); len(recs) != 2 {
		t.Fatalf("got %d records, want 2: %s", len(recs), buf.String())
	}
}
