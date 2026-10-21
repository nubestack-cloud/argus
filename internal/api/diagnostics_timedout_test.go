package api

// PROJECT.md P19's residual at the hub: "one check timed out" and "the
// sweep failed" must be distinguishable here, not just on the wire. Before
// tunnel.DetectorStatus.TimedOutChecks existed they arrived in the same two
// fields and the bundle could only say "failing" for both — or, once
// LastSuccessAt was allowed to advance through a timeout, would have said
// plain "ok" for a pass that was in fact partly blind.

import (
	"testing"
	"time"

	"argus/internal/tunnel"
)

func TestDiagnosticsStatusForDistinguishesATimeoutFromAFailure(t *testing.T) {
	now := time.Now().UTC()

	t.Run("a check that did not answer is degraded, not ok and not failing", func(t *testing.T) {
		got := diagnosticsStatusFor(tunnel.DetectorStatus{
			// The shape the agent now reports for a timed-out pass: the
			// pass ran (LastSuccessAt advanced), the timeout is named, and
			// the same fact is also in Error behind the stable prefix for
			// any hub that predates the field.
			LastSuccessAt:  now,
			Error:          "sweep checker timeout: service no endpoints (no response within 30s; the other 21 of 22 checks in this pass still ran)",
			ErrorAt:        now,
			TimedOutChecks: []string{"service no endpoints"},
		})
		if got.Status != "degraded" {
			t.Errorf("Status = %q, want %q — the detector is running, but claiming plain \"ok\" would assert a coverage this pass did not have", got.Status, "degraded")
		}
		if len(got.TimedOutChecks) != 1 || got.TimedOutChecks[0] != "service no endpoints" {
			t.Errorf("TimedOutChecks = %v, want the check named so an operator knows WHICH read is slow", got.TimedOutChecks)
		}
		if got.LastSuccessAt == "" {
			t.Error("LastSuccessAt dropped — the whole point of the residual is that a hung check no longer freezes this timestamp")
		}
	})

	t.Run("a hard failure still wins over a timeout in the same pass", func(t *testing.T) {
		got := diagnosticsStatusFor(tunnel.DetectorStatus{
			LastSuccessAt:  now.Add(-time.Hour),
			Error:          "jobs: forbidden",
			ErrorAt:        now,
			TimedOutChecks: []string{"service no endpoints"},
		})
		if got.Status != "failing" {
			t.Errorf("Status = %q, want %q — a read that is refused outright is the more actionable of the two", got.Status, "failing")
		}
		if len(got.TimedOutChecks) != 1 {
			t.Errorf("TimedOutChecks = %v, want the timed-out check still reported alongside the failure rather than swallowed by it", got.TimedOutChecks)
		}
	})

	t.Run("a clean pass is plain ok with nothing named", func(t *testing.T) {
		got := diagnosticsStatusFor(tunnel.DetectorStatus{LastSuccessAt: now})
		if got.Status != "ok" {
			t.Errorf("Status = %q, want %q", got.Status, "ok")
		}
		if len(got.TimedOutChecks) != 0 {
			t.Errorf("TimedOutChecks = %v, want empty", got.TimedOutChecks)
		}
	})

	t.Run("an agent that predates the field is not called degraded", func(t *testing.T) {
		// Same timeout, reported the only way an older agent can: the
		// prefixed Error text with no named field. It must not silently
		// become "degraded" (this hub cannot tell that apart from any other
		// error) and must not lose the text either.
		got := diagnosticsStatusFor(tunnel.DetectorStatus{
			LastSuccessAt: now.Add(-time.Hour),
			Error:         "sweep checker timeout: service no endpoints (no response within 30s; the other 21 of 22 checks in this pass still ran)",
			ErrorAt:       now,
		})
		if got.Status != "failing" {
			t.Errorf("Status = %q, want %q — with no TimedOutChecks this hub has exactly the information it had before, and must behave exactly as it did", got.Status, "failing")
		}
		if got.Error == "" {
			t.Error("the prefixed timeout text was dropped — that text is the whole signal for an agent older than TimedOutChecks")
		}
	})
}
