package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"argus/internal/orchestrator"
	"argus/internal/settings"
)

// PROJECT.md M1: POST /incidents/{id}/analyze answers 202 and runs the
// investigation in the background. These pin the pure halves of that —
// what counts as a run in flight, where a failed run puts the incident, how
// a refused claim is answered, and the run's context — without a database.
// analyze_async_db_test.go covers the claim and failure recording against
// a real Postgres.

func TestAnalysisRunInFlight(t *testing.T) {
	now := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	recent := now.Add(-time.Minute)
	old := now.Add(-time.Hour)
	staleAfter := 6 * time.Minute
	cases := []struct {
		name      string
		state     string
		startedAt *time.Time
		want      bool
	}{
		{"investigating, started a minute ago", orchestrator.StateInvestigating, &recent, true},
		// A hub that died mid-run leaves exactly this behind; it must not
		// block a new run forever.
		{"investigating, started past the run budget", orchestrator.StateInvestigating, &old, false},
		{"investigating with no stamp (pre-000127 or never committed)", orchestrator.StateInvestigating, nil, false},
		{"not investigating, recent stamp from a finished run", orchestrator.StateDiagnosed, &recent, false},
		{"detected, never analysed", orchestrator.StateDetected, nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := analysisRunInFlight(tc.state, tc.startedAt, now, staleAfter); got != tc.want {
				t.Errorf("analysisRunInFlight = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestAnalysisFailureRestoreState(t *testing.T) {
	cases := map[string]string{
		// Restored exactly: an edge out of Investigating reaches them.
		orchestrator.StateDetected:                orchestrator.StateDetected,
		orchestrator.StateNeedsHumanInvestigation: orchestrator.StateNeedsHumanInvestigation,
		orchestrator.StateAwaitingApproval:        orchestrator.StateAwaitingApproval,
		orchestrator.StateDiagnosed:               orchestrator.StateDiagnosed,
		// No edge back — a person needs to look.
		orchestrator.StatePlanRejected: orchestrator.StateNeedsHumanInvestigation,
		orchestrator.StateValidating:   orchestrator.StateNeedsHumanInvestigation,
		orchestrator.StateFailed:       orchestrator.StateNeedsHumanInvestigation,
		orchestrator.StateReopened:     orchestrator.StateNeedsHumanInvestigation,
		// A stale run taken over: never "restore" Investigating itself, which
		// would leave the incident reading as busy with nothing running.
		orchestrator.StateInvestigating: orchestrator.StateNeedsHumanInvestigation,
	}
	for prior, want := range cases {
		got := analysisFailureRestoreState(prior)
		if got != want {
			t.Errorf("analysisFailureRestoreState(%q) = %q, want %q", prior, got, want)
		}
		if !orchestrator.CanTransition(orchestrator.StateInvestigating, got) {
			t.Errorf("analysisFailureRestoreState(%q) = %q, which SetState would refuse from Investigating", prior, got)
		}
	}
}

func TestAnalysisClaimProblem(t *testing.T) {
	started := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		name       string
		err        error
		wantOK     bool
		wantStatus int
		wantType   string
		wantDetail string
	}{
		{"duplicate with a stamp", &analysisInProgressError{StartedAt: &started}, true, http.StatusConflict, "https://argus.io/errors/analysis-in-progress", "2026-10-10T12:00:00Z"},
		{"duplicate seen only by its lock", fmt.Errorf("wrapped: %w", &analysisInProgressError{}), true, http.StatusConflict, "https://argus.io/errors/analysis-in-progress", "possibly an automatic one"},
		{"terminal incident", &orchestrator.IllegalTransitionError{IncidentID: "inc_1", From: orchestrator.StateDismissed, To: orchestrator.StateInvestigating}, true, http.StatusConflict, "https://argus.io/errors/invalid-state", orchestrator.StateDismissed},
		{"incident gone", fmt.Errorf("%w: inc_1", orchestrator.ErrIncidentNotFound), true, http.StatusNotFound, "https://argus.io/errors/not-found", ""},
		{"server error is not the caller's to act on", errors.New("connection reset"), false, 0, "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := analysisClaimProblem(tc.err)
			if ok != tc.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tc.wantOK)
			}
			if !ok {
				return
			}
			if got.status != tc.wantStatus || got.typ != tc.wantType {
				t.Errorf("got %d %s, want %d %s", got.status, got.typ, tc.wantStatus, tc.wantType)
			}
			if !strings.Contains(got.detail, tc.wantDetail) {
				t.Errorf("detail %q does not mention %q", got.detail, tc.wantDetail)
			}
		})
	}
}

func TestAnalysisSourceFromConfig(t *testing.T) {
	if got := analysisSourceFromConfig(settings.Config{LLMProviderKind: settings.ProviderKindAPI, LLMModel: "m1"}); got.Backend != "api" || got.Model != "m1" {
		t.Errorf("api source = %+v", got)
	}
	// A cli row can carry a leftover model column; it is not what the CLI
	// agent will run, so it must not be reported as the run's model.
	if got := analysisSourceFromConfig(settings.Config{LLMProviderKind: settings.ProviderKindCLI, LLMModel: "stale"}); got.Backend != "cli" || got.Model != "" {
		t.Errorf("cli source = %+v", got)
	}
}

type analyzeRunTestKey struct{}

// The property the whole change exists for: the client going away (net/http
// cancels r.Context() when the connection closes, and a proxy idle timeout
// closes it) must not cancel the investigation it started.
func TestLaunchAnalysisRunSurvivesRequestCancellation(t *testing.T) {
	s := &Server{}
	reqCtx, cancelReq := context.WithCancel(context.WithValue(context.Background(), analyzeRunTestKey{}, "req-123"))

	proceed := make(chan struct{})
	type observed struct {
		errAfterCancel error
		value          any
		hasDeadline    bool
	}
	result := make(chan observed, 1)
	s.launchAnalysisRun(reqCtx, time.Minute, func(ctx context.Context) {
		<-proceed
		_, hasDeadline := ctx.Deadline()
		result <- observed{errAfterCancel: ctx.Err(), value: ctx.Value(analyzeRunTestKey{}), hasDeadline: hasDeadline}
	}, nil)

	cancelReq() // the browser navigated away / the proxy cut the request
	close(proceed)

	select {
	case got := <-result:
		if got.errAfterCancel != nil {
			t.Errorf("run context was cancelled with the request: %v", got.errAfterCancel)
		}
		if got.value != "req-123" {
			t.Errorf("run context lost the request's values (request id, log attributes): got %v", got.value)
		}
		if !got.hasDeadline {
			t.Error("run context has no deadline — a run must stay bounded by its budget")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("run never completed")
	}
	if !s.DrainAnalyses(context.Background(), time.Second) {
		t.Error("DrainAnalyses reported an unfinished run after it returned")
	}
}

func TestLaunchAnalysisRunIsBoundedByItsBudget(t *testing.T) {
	s := &Server{}
	done := make(chan error, 1)
	s.launchAnalysisRun(context.Background(), 20*time.Millisecond, func(ctx context.Context) {
		<-ctx.Done()
		done <- ctx.Err()
	}, nil)
	select {
	case err := <-done:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Errorf("run ended with %v, want its deadline", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("run outlived its budget")
	}
}

func TestLaunchAnalysisRunRecoversPanic(t *testing.T) {
	s := &Server{}
	recovered := make(chan any, 1)
	s.launchAnalysisRun(context.Background(), time.Minute, func(context.Context) {
		panic("boom")
	}, func(ctx context.Context, p any) {
		recovered <- p
	})
	select {
	case p := <-recovered:
		if p != "boom" {
			t.Errorf("onPanic got %v", p)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("panic was not handed to onPanic")
	}
	if !s.DrainAnalyses(context.Background(), time.Second) {
		t.Error("a panicked run still counts as running")
	}
}

// DrainAnalyses waits, then cancels what is left so each run can record its
// interruption instead of leaving its incident Investigating.
func TestDrainAnalysesCancelsRunsLeftAfterTheWait(t *testing.T) {
	s := &Server{}
	recorded := make(chan error, 1)
	s.launchAnalysisRun(context.Background(), time.Hour, func(ctx context.Context) {
		<-ctx.Done()
		recorded <- ctx.Err()
	}, nil)

	waitCtx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if s.DrainAnalyses(waitCtx, 5*time.Second) {
		t.Error("DrainAnalyses reported every run finished on its own, but one had to be cancelled")
	}
	select {
	case err := <-recorded:
		if !errors.Is(err, context.Canceled) {
			t.Errorf("run ended with %v, want cancellation by the drain", err)
		}
	default:
		t.Fatal("DrainAnalyses returned before the cancelled run finished recording")
	}
}

func TestTruncateRunes(t *testing.T) {
	if got := truncateRunes("héllo", 10); got != "héllo" {
		t.Errorf("short string changed: %q", got)
	}
	if got := truncateRunes("héllo", 2); got != "hé…" {
		t.Errorf("truncated on a byte boundary: %q", got)
	}
}
