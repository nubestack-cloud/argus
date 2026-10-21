package api

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// TestBuildEvidenceSummaryFoldsGroupedRows covers the aggregate's Go half —
// the part getEvidenceSummary's GROUP BY (tool, outcome) query hands over, and
// the reason that fold lives in Go at all (see toolCallGroup's doc comment):
// per-tool counts must sum across BOTH outcomes of the same tool, the total
// must count every call, and failures must be counted separately while
// remaining part of that total.
//
// The 13-call shape here is the real investigation that motivated this
// feature (BACKLOG.md D3), with one failure added.
func TestBuildEvidenceSummaryFoldsGroupedRows(t *testing.T) {
	got := buildEvidenceSummary([]toolCallGroup{
		{Tool: "describe_resource", Outcome: "ok", Count: 4},
		{Tool: "get_events", Outcome: "ok", Count: 4},
		{Tool: "get_events", Outcome: "error", Count: 1},
		{Tool: "get_owner_chain", Outcome: "ok", Count: 2},
		{Tool: "get_gitops_ownership", Outcome: "ok", Count: 2},
	})
	if got == nil {
		t.Fatal("buildEvidenceSummary returned nil for 13 recorded calls")
	}

	if got.TotalCalls != 13 {
		t.Errorf("TotalCalls = %d, want 13", got.TotalCalls)
	}
	// Counted separately, and still inside the total: a call that failed was
	// still a question asked.
	if got.FailedCalls != 1 {
		t.Errorf("FailedCalls = %d, want 1", got.FailedCalls)
	}
	want := map[string]int{
		"describe_resource":    4,
		"get_events":           5, // 4 ok + 1 error, folded into one per-tool count
		"get_owner_chain":      2,
		"get_gitops_ownership": 2,
	}
	if len(got.ByTool) != len(want) {
		t.Errorf("ByTool = %v, want %v", got.ByTool, want)
	}
	for tool, count := range want {
		if got.ByTool[tool] != count {
			t.Errorf("ByTool[%q] = %d, want %d", tool, got.ByTool[tool], count)
		}
	}
}

// TestBuildEvidenceSummaryCountsOnlyFailures guards the failure branch against
// the two ways it could be wrong in a way no total would reveal: an all-failed
// incident (every call must be counted as failed AND as a call) and an
// unrecognised outcome value, which must not be silently counted as a failure.
func TestBuildEvidenceSummaryCountsOnlyFailures(t *testing.T) {
	allFailed := buildEvidenceSummary([]toolCallGroup{
		{Tool: "get_logs", Outcome: "error", Count: 3},
	})
	if allFailed == nil {
		t.Fatal("an investigation whose every call failed still gathered evidence; got nil")
	}
	if allFailed.TotalCalls != 3 || allFailed.FailedCalls != 3 {
		t.Errorf("all-failed: TotalCalls/FailedCalls = %d/%d, want 3/3", allFailed.TotalCalls, allFailed.FailedCalls)
	}

	unknown := buildEvidenceSummary([]toolCallGroup{
		{Tool: "get_logs", Outcome: "something_new", Count: 2},
	})
	if unknown.FailedCalls != 0 {
		t.Errorf("FailedCalls = %d for an outcome that is not %q, want 0 — only a recorded error counts as a failure",
			unknown.FailedCalls, toolCallOutcomeError)
	}
	if unknown.TotalCalls != 2 {
		t.Errorf("TotalCalls = %d, want 2 — an unrecognised outcome is still a call", unknown.TotalCalls)
	}
}

// TestBuildEvidenceSummaryIsNilWhenNothingWasRecorded is the honesty case, not
// an empty-input formality: every analysis produced before migration 000037
// gathered real evidence that was never recorded, so "no rows" must mean
// "unknown" (nil, which the incident response marshals as null and the UI
// renders as nothing at all) rather than a "0 tool calls" block that would
// state something false about an investigation that made thirteen.
func TestBuildEvidenceSummaryIsNilWhenNothingWasRecorded(t *testing.T) {
	if got := buildEvidenceSummary(nil); got != nil {
		t.Errorf("buildEvidenceSummary(nil) = %+v, want nil", got)
	}
	if got := buildEvidenceSummary([]toolCallGroup{}); got != nil {
		t.Errorf("buildEvidenceSummary(empty) = %+v, want nil", got)
	}
	// A zero-count group is the same case arriving a different way (it cannot
	// come out of count(*), but it can come out of a future query shape).
	if got := buildEvidenceSummary([]toolCallGroup{{Tool: "get_events", Outcome: "ok", Count: 0}}); got != nil {
		t.Errorf("buildEvidenceSummary(zero-count group) = %+v, want nil", got)
	}
}

// failingBeginner is a database that cannot start a transaction — the shape of
// every way this can fail before any SQL runs (pool exhausted, Postgres down,
// context already dead).
type failingBeginner struct{ calls int }

func (f *failingBeginner) Begin(context.Context) (pgx.Tx, error) {
	f.calls++
	return nil, errors.New("pool exhausted")
}

// TestRecordMCPToolCallReportsFailureInsteadOfPanicking is the api-side half of
// "recording must not break an investigation" (internal/mcp's
// TestRecordingFailureDoesNotFailTheToolCall is the other half): with the
// database unavailable this must return an ordinary error for cmd/hub to log,
// and must not panic — a panic in the MCP request goroutine would take down the
// very tool call whose bookkeeping this is.
func TestRecordMCPToolCallReportsFailureInsteadOfPanicking(t *testing.T) {
	db := &failingBeginner{}
	err := RecordMCPToolCall(context.Background(), db, "cl_1", "inc_1", "get_events", 42*time.Millisecond, nil)
	if err == nil {
		t.Fatal("expected an error when the database cannot begin a transaction")
	}
	if db.calls != 1 {
		t.Errorf("Begin called %d times, want exactly 1 — recording never retries on the investigation's hot path", db.calls)
	}
}

// TestRecordMCPToolCallSurvivesACancelledCallerContext pins the
// context.WithoutCancel decision: the caller's context is the MCP request's,
// which is already cancelled in exactly the case most worth recording (the CLI
// hung up, or the tool call hit its deadline). Reaching Begin at all proves the
// cancellation was detached; inheriting it would have short-circuited before
// any work.
func TestRecordMCPToolCallSurvivesACancelledCallerContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	db := &failingBeginner{}
	_ = RecordMCPToolCall(ctx, db, "cl_1", "inc_1", "get_logs", time.Second, errors.New("stream closed"))
	if db.calls != 1 {
		t.Errorf("Begin called %d times, want 1 — a cancelled caller context must not skip recording", db.calls)
	}
}

// TestRecordMCPToolCallRefusesAnIncidentlessGrant: a row stored against an
// empty incident id can never be shown on any incident page, so it is silently
// useless rather than harmlessly extra — refused before it reaches the pool.
func TestRecordMCPToolCallRefusesAnIncidentlessGrant(t *testing.T) {
	db := &failingBeginner{}
	if err := RecordMCPToolCall(context.Background(), db, "cl_1", "", "get_events", time.Second, nil); err == nil {
		t.Fatal("expected an error for a grant with no incident id")
	}
	if db.calls != 0 {
		t.Errorf("Begin called %d times, want 0 — the refusal must come before any database work", db.calls)
	}
}
