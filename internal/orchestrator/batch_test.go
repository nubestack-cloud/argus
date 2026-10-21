package orchestrator

import (
	"testing"
	"time"
)

func TestWaveOneSize(t *testing.T) {
	cases := []struct {
		total int
		want  int
	}{
		{2, 1},
		{3, 1},
		{4, 2},
		{5, 2},
		{30, 2},
	}
	for _, c := range cases {
		if got := waveOneSize(c.total); got != c.want {
			t.Errorf("waveOneSize(%d) = %d, want %d", c.total, got, c.want)
		}
	}
}

func TestClassifyIncidentState(t *testing.T) {
	cases := []struct {
		state string
		want  waveOutcome
	}{
		{StateResolved, waveOutcomeSuccess},
		{StateAwaitingApproval, waveOutcomePending},
		{StateExecuting, waveOutcomePending},
		{StateValidating, waveOutcomePending},
		{StateReopened, waveOutcomeFailure},
		{StateDismissed, waveOutcomeFailure},
		{StateFailed, waveOutcomeFailure},
		{StateInvestigating, waveOutcomeFailure},
		{"SomeFutureStateNobodyWroteYet", waveOutcomeFailure},
	}
	for _, c := range cases {
		if got := classifyIncidentState(c.state); got != c.want {
			t.Errorf("classifyIncidentState(%q) = %v, want %v", c.state, got, c.want)
		}
	}
}

// TestDecideBatchOutcomeAllResolvedReleases is the happy path: every wave-1
// incident held, so wave 2 is released.
func TestDecideBatchOutcomeAllResolvedReleases(t *testing.T) {
	status, changed := decideBatchOutcome([]string{StateResolved, StateResolved}, time.Minute)
	if !changed || status != BatchStatusReleased {
		t.Fatalf("decideBatchOutcome(all Resolved) = (%q, %v), want (%q, true)", status, changed, BatchStatusReleased)
	}
}

// TestDecideBatchOutcomeAnyReopenedBlocks is the safety-critical case this
// whole feature exists for: one wave-1 incident's fix did not hold, so wave
// 2 must never auto-execute the same fix.
func TestDecideBatchOutcomeAnyReopenedBlocks(t *testing.T) {
	status, changed := decideBatchOutcome([]string{StateResolved, StateReopened}, time.Minute)
	if !changed || status != BatchStatusBlocked {
		t.Fatalf("decideBatchOutcome(one Reopened) = (%q, %v), want (%q, true)", status, changed, BatchStatusBlocked)
	}
}

// TestDecideBatchOutcomeFailureWinsOverPending: a failure must block
// immediately even while a sibling wave-1 incident is still in flight —
// waiting for the rest of wave 1 to also finish before blocking would delay
// the one signal that matters most.
func TestDecideBatchOutcomeFailureWinsOverPending(t *testing.T) {
	status, changed := decideBatchOutcome([]string{StateReopened, StateExecuting}, time.Minute)
	if !changed || status != BatchStatusBlocked {
		t.Fatalf("decideBatchOutcome(Reopened + Executing) = (%q, %v), want (%q, true)", status, changed, BatchStatusBlocked)
	}
}

// TestDecideBatchOutcomeStillPending: nothing has concluded yet and the
// batch is young — no change, no premature release or block.
func TestDecideBatchOutcomeStillPending(t *testing.T) {
	status, changed := decideBatchOutcome([]string{StateAwaitingApproval, StateExecuting}, time.Minute)
	if changed {
		t.Fatalf("decideBatchOutcome(still in flight) changed to %q, want no change", status)
	}
}

// TestDecideBatchOutcomeEmptyWave1IsNotVacuouslySuccessful guards against the
// "all() of an empty slice is true" bug: a batch whose wave-1 membership
// rows are (for whatever reason) not yet visible must NOT read as "all
// succeeded" just because there is nothing to disagree with that.
func TestDecideBatchOutcomeEmptyWave1IsNotVacuouslySuccessful(t *testing.T) {
	status, changed := decideBatchOutcome(nil, time.Minute)
	if changed || status == BatchStatusReleased {
		t.Fatalf("decideBatchOutcome(no wave-1 states) = (%q, %v), want no change and definitely not released", status, changed)
	}
}

// TestDecideBatchOutcomeAbandonsAfterHoldDuration: wave 1 never concluded
// (every candidate kept losing to the blast-radius cap, say), and enough
// time has passed that this package gives up watching rather than holding
// wave 2 forever with no bound.
func TestDecideBatchOutcomeAbandonsAfterHoldDuration(t *testing.T) {
	status, changed := decideBatchOutcome([]string{StateAwaitingApproval}, maxBatchHoldDuration+time.Minute)
	if !changed || status != BatchStatusAbandoned {
		t.Fatalf("decideBatchOutcome(still pending, past the hold duration) = (%q, %v), want (%q, true)", status, changed, BatchStatusAbandoned)
	}
}

func TestBatchMembershipEligible(t *testing.T) {
	cases := []struct {
		name string
		m    BatchMembership
		want bool
	}{
		{"wave 1, batch still pending", BatchMembership{WaveNumber: 1, BatchStatus: BatchStatusWave1Pending}, true},
		{"wave 1, batch blocked", BatchMembership{WaveNumber: 1, BatchStatus: BatchStatusBlocked}, true},
		{"wave 2, batch pending", BatchMembership{WaveNumber: 2, BatchStatus: BatchStatusWave1Pending}, false},
		{"wave 2, batch blocked", BatchMembership{WaveNumber: 2, BatchStatus: BatchStatusBlocked}, false},
		{"wave 2, batch abandoned", BatchMembership{WaveNumber: 2, BatchStatus: BatchStatusAbandoned}, false},
		{"wave 2, batch released", BatchMembership{WaveNumber: 2, BatchStatus: BatchStatusReleased}, true},
	}
	for _, c := range cases {
		if got := c.m.Eligible(); got != c.want {
			t.Errorf("%s: Eligible() = %v, want %v", c.name, got, c.want)
		}
	}
}
