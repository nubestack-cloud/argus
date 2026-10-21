package autoanalyze

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"argus/internal/llm"
	"argus/internal/orchestrator"
)

// A failed automatic investigation used to leave the incident in
// Investigating, which candidateQuery excludes — so it was never retried and
// nothing ever moved it again. It read as "an investigation is running now"
// permanently, for an investigation that had already failed, with the reason
// recorded nowhere but a log line.
//
// These are the DB-free halves of that fix. failed_analysis_db_test.go drives
// recordAnalysisFailure against real Postgres.

// TestFailedAnalysisReturnsToASelectableState is the invariant that would have
// caught the original bug on its own, without anyone having to notice the
// interaction: whatever state a failed automatic analysis leaves an incident
// in must be a state the candidate query can select again.
//
// The old code left it in Investigating. Investigating is in candidateQuery's
// own NOT IN list — deliberately, because an analysis in flight must not be
// started twice — so "leave it where it is" and "never look at it again" were
// the same instruction, and nothing in either place said so.
func TestFailedAnalysisReturnsToASelectableState(t *testing.T) {
	const landing = orchestrator.StateDetected

	if strings.Contains(candidateQuery, "'"+landing+"'") {
		t.Fatalf("recordAnalysisFailure returns incidents to %s, but candidateQuery excludes that state — a retryable failure would never be retried, which is exactly the original defect", landing)
	}
	if !orchestrator.CanTransition(orchestrator.StateInvestigating, landing) {
		t.Fatalf("Investigating -> %s is not a legal transition, so a failed automatic investigation cannot leave the state it set", landing)
	}
	// And the state it must NOT be left in is still excluded, because that
	// exclusion is correct and must not be relaxed to make the fix easier.
	if !strings.Contains(candidateQuery, "'Investigating'") {
		t.Error("candidateQuery no longer excludes Investigating — an incident already being investigated would be investigated again concurrently")
	}
}

// TestCandidateQueryHonoursTheRetryBackoff: bounded retries need a gate, and
// the gate has to be in the SQL, or an incident with a backoff set is
// re-selected on the very next 15-second tick and the backoff means nothing.
func TestCandidateQueryHonoursTheRetryBackoff(t *testing.T) {
	if !strings.Contains(candidateQuery, "auto_analysis_retry_after") {
		t.Fatal("candidateQuery does not consult auto_analysis_retry_after — a failed incident would be retried every poll interval, which is the hot-loop the original 'at most once' rule existed to prevent")
	}
	if !strings.Contains(candidateQuery, "auto_analysis_retry_after IS NULL") {
		t.Error("the backoff clause must treat NULL as eligible, or every incident that has never failed is excluded from automatic analysis entirely")
	}
	if !strings.Contains(candidateQuery, "incidents.auto_analysis_attempts") {
		t.Error("candidateQuery no longer selects auto_analysis_attempts — the bounded-retry decision would restart from zero on every attempt and never terminate")
	}
}

// TestAutoAnalysisBackoffIsBoundedAndIncreasing: the retry has to be worth
// something (long enough for a rate limit or a restart to clear) and bounded
// (never so long it is indistinguishable from giving up silently).
func TestAutoAnalysisBackoffIsBoundedAndIncreasing(t *testing.T) {
	var previous time.Duration
	for attempts := 1; attempts < maxAutoAnalysisAttempts; attempts++ {
		got := autoAnalysisBackoff(attempts)
		if got < time.Minute {
			t.Errorf("autoAnalysisBackoff(%d) = %s — too short to outlast anything that is actually transient", attempts, got)
		}
		if got > time.Hour {
			t.Errorf("autoAnalysisBackoff(%d) = %s — long enough that an operator would read it as nothing happening", attempts, got)
		}
		if got < previous {
			t.Errorf("autoAnalysisBackoff(%d) = %s, shorter than the previous attempt's %s", attempts, got, previous)
		}
		previous = got
	}
	// Hostile inputs must not produce a zero or negative window, which would
	// be a hot loop rather than a backoff.
	for _, attempts := range []int{-1000, -1, 0} {
		if got := autoAnalysisBackoff(attempts); got <= 0 {
			t.Errorf("autoAnalysisBackoff(%d) = %s, want a positive window", attempts, got)
		}
	}
}

// TestFailureSummaryDistinguishesTheThreeOutcomes: the whole point of writing
// this to the timeline is that a reader can tell what will happen next without
// reading hub logs. Three genuinely different answers, three different
// sentences.
func TestFailureSummaryDistinguishesTheThreeOutcomes(t *testing.T) {
	willRetry := autoAnalysisFailureSummary("transient", "provider returned 503", 1, true)
	gaveUp := autoAnalysisFailureSummary("transient", "provider returned 503", maxAutoAnalysisAttempts, false)
	config := autoAnalysisFailureSummary("configuration", llm.ErrNotConfigured.Error(), 0, true)

	if !strings.Contains(willRetry, "will be retried") {
		t.Errorf("a retryable failure must say so: %s", willRetry)
	}
	if !strings.Contains(gaveUp, "given up") || !strings.Contains(gaveUp, "by hand") {
		t.Errorf("an exhausted failure must say nothing further happens automatically and name the manual route: %s", gaveUp)
	}
	if !strings.Contains(config, "hub configuration problem") {
		t.Errorf("a configuration failure must not read as a problem with the incident: %s", config)
	}
	if willRetry == gaveUp || gaveUp == config || willRetry == config {
		t.Error("two of the three outcomes produce the same sentence — a reader cannot tell them apart")
	}
	// The reason itself always survives; that is the point of recording it.
	for name, s := range map[string]string{"willRetry": willRetry, "gaveUp": gaveUp, "config": config} {
		if !strings.Contains(s, "503") && !strings.Contains(s, "no usable AI provider") {
			t.Errorf("%s: the underlying error text was dropped: %s", name, s)
		}
	}
}

// TestProviderBackoffIsBoundedAndSelfHealing covers the poller-level throttle a
// configuration failure arms instead of spending the incident's own retry
// budget.
func TestProviderBackoffIsBoundedAndSelfHealing(t *testing.T) {
	p := &Poller{}
	if p.providerBackoffActive() {
		t.Fatal("a fresh poller must not start backed off")
	}

	p.noteProviderUnusable("inc_1", llm.ErrNotConfigured)
	if !p.providerBackoffActive() {
		t.Fatal("the poller did not stand down after discovering no usable AI provider — every subsequent tick would attempt, and fail, another incident")
	}
	first := p.providerBackoff
	if first != providerBackoffFloor {
		t.Errorf("first backoff = %s, want the floor %s", first, providerBackoffFloor)
	}

	// Consecutive failures back off further, and stop at the ceiling.
	for i := 0; i < 20; i++ {
		p.noteProviderUnusable("inc_1", llm.ErrNotConfigured)
	}
	if p.providerBackoff != providerBackoffCeiling {
		t.Errorf("backoff = %s after repeated failures, want it capped at %s", p.providerBackoff, providerBackoffCeiling)
	}

	// And one success restores the full cadence immediately rather than
	// leaving an hour-long window in place on a hub that is now fine.
	p.noteProviderUsable()
	if p.providerBackoffActive() {
		t.Error("the backoff survived a successful investigation — a hub that has just been configured would stay paused for up to an hour")
	}
	if p.providerBackoff != 0 {
		t.Errorf("providerBackoff = %s after recovery, want 0 so the next failure starts from the floor again", p.providerBackoff)
	}
}

// TestConfigurationFailuresAreRecognised: the classification is what decides
// whether an incident's retry budget is spent, so it has to actually match the
// error the provider layer produces — including through the wrapping every real
// call site adds.
func TestConfigurationFailuresAreRecognised(t *testing.T) {
	wrapped := fmt.Errorf("investigate incident inc_1: %w",
		fmt.Errorf("%w: provider kind %q selected but no API backend is wired", llm.ErrNotConfigured, "api"))
	if !errors.Is(wrapped, llm.ErrNotConfigured) {
		t.Fatal("a wrapped ErrNotConfigured is not recognised — every eligible incident would have its retry budget spent on a hub misconfiguration")
	}
	if errors.Is(errors.New("provider returned 503"), llm.ErrNotConfigured) {
		t.Fatal("an ordinary transient failure is being classified as a configuration error, so it would never be retried")
	}
}

// TestStaleClosureBlockedRefusesActionsInFlight is Finding 5's rule, stated as
// a table. The incident this sweeper closes is closed with no analysis, no
// approval and no human — so what it refuses to touch is the entire safety
// property.
func TestStaleClosureBlockedRefusesActionsInFlight(t *testing.T) {
	cases := []struct {
		name                              string
		state                             string
		hasPR, prMerged, prClosedUnmerged bool
		wantBlocked                       bool
		why                               string
	}{
		{
			name: "a pull request is open", state: orchestrator.StateAwaitingMerge,
			hasPR: true, wantBlocked: true,
			why: "nothing closes the pull request when the incident closes, so resolving here leaves a live change proposal with no incident explaining it",
		},
		{
			name: "a pull request is open even if the state was moved elsewhere", state: orchestrator.StateFailed,
			hasPR: true, wantBlocked: true,
			why: "the PR predicate is the structural version of the state check; orphaning a live proposal must not depend on a state name",
		},
		{
			name: "a plan is queued for approval", state: orchestrator.StateAwaitingApproval,
			wantBlocked: true,
			why:         "the unattended executor keys on exactly this state; closing the incident silently withdraws a question a human was asked",
		},
		{
			name: "a mutation is in flight", state: orchestrator.StateExecuting,
			wantBlocked: true, why: "another writer owns the state",
		},
		{
			name: "an analysis is in flight", state: orchestrator.StateInvestigating,
			wantBlocked: true, why: "another writer owns the state, and Resolved is not even a legal transition from here",
		},
		{
			name: "a fix is being validated", state: orchestrator.StateValidating,
			wantBlocked: true,
			why:         "the object disappearing is the EXPECTED result of a fix rolling its pods; the validation sweeper is better informed",
		},
		{
			name: "the pull request was merged", state: orchestrator.StateFailed,
			hasPR: true, prMerged: true, wantBlocked: false,
			why: "a merged pull request is not in flight; there is nothing left to orphan",
		},
		{
			name: "the pull request was closed unmerged", state: orchestrator.StateReopened,
			hasPR: true, prClosedUnmerged: true, wantBlocked: false,
			why: "same — the proposal is over",
		},
		{
			name: "a failed execution with nothing pending", state: orchestrator.StateFailed,
			wantBlocked: false,
			why:         "the execution is over; this is an ordinary candidate for 'the thing this was about is gone'",
		},
		{
			name: "a reopened symptom with nothing pending", state: orchestrator.StateReopened,
			wantBlocked: false, why: "same",
		},
		{
			name: "never investigated", state: orchestrator.StateDetected,
			wantBlocked: false, why: "the original, correct case",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := staleClosureBlocked(tc.state, tc.hasPR, tc.prMerged, tc.prClosedUnmerged)
			if got != tc.wantBlocked {
				t.Errorf("staleClosureBlocked(%q, hasPR=%v, merged=%v, closed=%v) = %v, want %v — %s",
					tc.state, tc.hasPR, tc.prMerged, tc.prClosedUnmerged, got, tc.wantBlocked, tc.why)
			}
		})
	}
}

// TestExistenceTargetPrefersSomethingThatSurvivesAPodRoll is Finding 5's other
// half. The sweeper asked "does incidents.object_key still exist?" — and
// object_key is a Pod for the great majority of incidents. Pods are replaced by
// every rollout, drain, eviction and restart, so that question mostly measured
// Kubernetes rather than the fault, and the answer was being read as "there is
// nothing here any more".
func TestExistenceTargetPrefersSomethingThatSurvivesAPodRoll(t *testing.T) {
	const (
		pod        = "v1/Pod|prod|api-6679f7f545-w2xmp"
		deployment = "apps/v1/Deployment|prod|api"
		configMap  = "v1/ConfigMap|prod|api-config"
	)
	cases := []struct {
		name string
		c    staleCandidate
		want string
		why  string
	}{
		{
			name: "the remediation target wins",
			c:    staleCandidate{ObjectKey: pod, WorkloadKey: deployment, TargetKey: configMap},
			want: configMap,
			why:  "that is literally the object the proposed fix would act on; if it is still there the fix still has something to act on",
		},
		{
			name: "the workload wins over the pod that reported the symptom",
			c:    staleCandidate{ObjectKey: pod, WorkloadKey: deployment},
			want: deployment,
			why:  "a replaced pod is the ordinary consequence of a rollout, not evidence the incident is moot",
		},
		{
			name: "an unowned object is its own identity",
			c:    staleCandidate{ObjectKey: pod},
			want: pod,
			why:  "a bare pod with no owner and no plan has nothing else to ask about — this is the case the original check was right about",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, kind := tc.c.existenceTarget()
			if got != tc.want {
				t.Errorf("existenceTarget() = %q, want %q — %s", got, tc.want, tc.why)
			}
			if kind == "" {
				t.Error("existenceTarget returned no description, so the closure log line cannot say what was actually checked")
			}
		})
	}
}

// TestBothClosurePathsAskTheSameQuestion: this package resolves an incident on
// a not-found in TWO places — the stale sweep, and investigateOne's pre-flight
// skip — and both used to ask about incidents.object_key alone. Fixing one and
// leaving the other would have left the same defect reachable by a different
// route, on incidents that have never been analysed at all.
func TestBothClosurePathsAskTheSameQuestion(t *testing.T) {
	const (
		pod        = "v1/Pod|prod|api-6679f7f545-w2xmp"
		deployment = "apps/v1/Deployment|prod|api"
	)
	// The stale sweep's candidate.
	stale, _ := staleCandidate{ObjectKey: pod, WorkloadKey: deployment}.existenceTarget()
	// investigateOne's, which never has a live recommendation to consider (it
	// only ever selects incidents with no analysis yet) and so passes "".
	direct, _ := existenceTargetFor("", deployment, pod)
	if stale != direct {
		t.Errorf("the two closure paths ask about different objects (%q vs %q) — one of them still closes incidents because a pod name went away", stale, direct)
	}
	if direct != deployment {
		t.Errorf("existenceTargetFor asked about %q, want the workload %q", direct, deployment)
	}
	if !strings.Contains(candidateQuery, "COALESCE(incidents.workload_key") {
		t.Error("candidateQuery no longer selects workload_key — investigateOne would fall back to the pod name, and a NULL would break the scan for every incident whose object has no owner")
	}
}
