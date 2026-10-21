package orchestrator

import (
	"strings"
	"testing"
	"time"
)

func intp(n int) *int { return &n }

// A blank field must NOT mean unlimited. That is the worst possible reading of
// an empty input on a screen that enables unattended cluster mutation, and it is
// why these columns follow analysis.maxIterations' null-means-fall-back
// convention rather than detection's null-means-off one.
func TestResolveUnattendedLimits_BlankMeansConservativeNotUnlimited(t *testing.T) {
	got := ResolveUnattendedLimits(true, nil, nil, nil)
	if !got.Enabled {
		t.Error("enabled was not carried through")
	}
	if got.MaxPerCluster != DefaultUnattendedLimits.MaxPerCluster ||
		got.MaxFleetWide != DefaultUnattendedLimits.MaxFleetWide ||
		got.Window != DefaultUnattendedLimits.Window {
		t.Errorf("blank policy = %+v, want the conservative defaults %+v", got, DefaultUnattendedLimits)
	}
	if got.MaxPerCluster <= 0 || got.MaxFleetWide <= 0 {
		t.Fatal("a default of zero or below would either block everything or, worse, be read as unlimited by a caller comparing with >=")
	}
}

func TestResolveUnattendedLimits_OverridesApply(t *testing.T) {
	got := ResolveUnattendedLimits(true, intp(7), intp(20), intp(1800))
	if got.MaxPerCluster != 7 || got.MaxFleetWide != 20 || got.Window != 30*time.Minute {
		t.Errorf("got %+v", got)
	}
}

// Zero and negative are refused by a CHECK constraint at the database level, but
// a hand-built Config could still carry them, and treating 0 as "no limit" would
// invert the control completely.
func TestResolveUnattendedLimits_IgnoresNonPositive(t *testing.T) {
	got := ResolveUnattendedLimits(true, intp(0), intp(-5), intp(0))
	if got.MaxPerCluster != DefaultUnattendedLimits.MaxPerCluster || got.MaxFleetWide != DefaultUnattendedLimits.MaxFleetWide {
		t.Errorf("non-positive overrides were honoured: %+v", got)
	}
}

// The decision logic, exercised without a database by checking the reasoning a
// caller depends on. The DB-backed counting half is covered by the live
// verification recorded in the WORKLOG.
func TestBlastRadiusReasoning(t *testing.T) {
	limits := UnattendedLimits{Enabled: true, MaxPerCluster: 3, MaxFleetWide: 10, Window: time.Hour}

	cases := []struct {
		name                     string
		clusterCount, fleetCount int
		wantAllowed              bool
		wantIn                   string
	}{
		{"well within budget", 0, 0, true, "within budget"},
		{"one below the cluster cap", 2, 5, true, "within budget"},
		{"at the cluster cap", 3, 5, false, "this cluster has already run 3"},
		{"over the cluster cap", 9, 9, false, "this cluster has already run 9"},
		{"at the fleet cap with cluster room", 1, 10, false, "the fleet has run 10"},
		// The correlated case this whole mechanism exists for: every cluster has
		// executed only once, so no per-cluster limit fires, yet the fleet total
		// is at its cap.
		{"correlated fleet-wide burst", 1, 30, false, "the fleet has run 30"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := decide(tc.clusterCount, tc.fleetCount, limits)
			if d.Allowed != tc.wantAllowed {
				t.Fatalf("allowed = %v, want %v (reason: %s)", d.Allowed, tc.wantAllowed, d.Reason)
			}
			if !strings.Contains(d.Reason, tc.wantIn) {
				t.Errorf("reason %q does not contain %q", d.Reason, tc.wantIn)
			}
		})
	}
}

// The per-cluster limit is structurally unable to see a correlated burst, which
// is why both counters exist. Asserted directly so a future "simplification"
// that drops one has to fail this test first.
func TestFleetCapCatchesWhatPerClusterCapCannot(t *testing.T) {
	limits := UnattendedLimits{Enabled: true, MaxPerCluster: 3, MaxFleetWide: 10, Window: time.Hour}
	// 30 clusters, one execution each: every per-cluster count is 1.
	d := decide(1, 30, limits)
	if d.Allowed {
		t.Fatal("a 30-cluster correlated burst was allowed — the fleet-wide cap is the ONLY thing that can catch this, since one execution per cluster trips no per-cluster limit")
	}
	if !strings.Contains(d.Reason, "one shared cause") {
		t.Errorf("the refusal does not explain why a fleet-wide burst is the dangerous case: %s", d.Reason)
	}
}

func TestDisabledIsRefusedNotAllowed(t *testing.T) {
	d := decide(0, 0, UnattendedLimits{Enabled: false, MaxPerCluster: 3, MaxFleetWide: 10, Window: time.Hour})
	if d.Allowed {
		t.Fatal("unattended execution was allowed while disabled")
	}
	if !strings.Contains(d.Reason, "not enabled") {
		t.Errorf("reason = %q", d.Reason)
	}
}

// The window appears in text an operator reads, so "1h0m0s" would be a defect.
func TestHumanWindow(t *testing.T) {
	cases := map[time.Duration]string{
		time.Hour:        "hour",
		2 * time.Hour:    "2 hours",
		30 * time.Minute: "30 minutes",
		90 * time.Second: "1m30s",
	}
	for d, want := range cases {
		if got := humanWindow(d); got != want {
			t.Errorf("humanWindow(%s) = %q, want %q", d, got, want)
		}
	}
}

// The singular case is the most conservative configuration an operator can set,
// so it is the one they are most likely to see first. "1 unattended
// remediations" on the safest possible setting is a small thing that reads as
// carelessness in exactly the message meant to justify a refusal.
func TestRefusalReasonReadsCorrectlyAtALimitOfOne(t *testing.T) {
	d := decide(1, 1, UnattendedLimits{Enabled: true, MaxPerCluster: 1, MaxFleetWide: 1, Window: time.Hour})
	if d.Allowed {
		t.Fatal("a count of 1 against a limit of 1 was allowed")
	}
	if !strings.Contains(d.Reason, "1 unattended remediation in the last hour") {
		t.Errorf("reason reads %q, want the singular form", d.Reason)
	}
	if strings.Contains(d.Reason, "remediations") {
		t.Errorf("reason uses a plural noun for a count of 1: %q", d.Reason)
	}

	many := decide(4, 4, UnattendedLimits{Enabled: true, MaxPerCluster: 3, MaxFleetWide: 3, Window: time.Hour})
	if !strings.Contains(many.Reason, "4 unattended remediations") {
		t.Errorf("plural count reads %q, want the plural form", many.Reason)
	}
}
