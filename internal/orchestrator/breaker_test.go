package orchestrator

import (
	"testing"
	"time"
)

func intPtr(v int) *int { return &v }

// TestResolveBreakerLimits covers the convention that matters on a safety
// setting: a blank field falls back to a real default, never to "no limit".
func TestResolveBreakerLimits(t *testing.T) {
	t.Run("all blank falls back to the defaults", func(t *testing.T) {
		got := ResolveBreakerLimits(true, nil, nil, nil)
		if got.MaxPerCluster != DefaultBreakerLimits.MaxPerCluster ||
			got.MaxFleetWide != DefaultBreakerLimits.MaxFleetWide ||
			got.Window != DefaultBreakerLimits.Window {
			t.Fatalf("got %+v, want the defaults %+v", got, DefaultBreakerLimits)
		}
		if !got.Enabled {
			t.Error("Enabled = false, want the passed-in true")
		}
	})

	t.Run("each field overrides independently", func(t *testing.T) {
		got := ResolveBreakerLimits(true, intPtr(7), nil, intPtr(120))
		if got.MaxPerCluster != 7 {
			t.Errorf("MaxPerCluster = %d, want 7", got.MaxPerCluster)
		}
		if got.MaxFleetWide != DefaultBreakerLimits.MaxFleetWide {
			t.Errorf("MaxFleetWide = %d, want the default %d — an override of one field must not disturb another", got.MaxFleetWide, DefaultBreakerLimits.MaxFleetWide)
		}
		if got.Window != 120*time.Second {
			t.Errorf("Window = %s, want 2m", got.Window)
		}
	})

	t.Run("a stored zero or negative falls back rather than disabling the limit", func(t *testing.T) {
		// The CHECK constraints should make these unreachable from the DB. If one
		// ever arrives anyway, treating it as "tolerate zero bad outcomes" would
		// trip the breaker permanently, and treating it as "no limit" would remove
		// the safety net silently. Falling back does neither.
		got := ResolveBreakerLimits(true, intPtr(0), intPtr(-5), intPtr(0))
		if got.MaxPerCluster != DefaultBreakerLimits.MaxPerCluster ||
			got.MaxFleetWide != DefaultBreakerLimits.MaxFleetWide ||
			got.Window != DefaultBreakerLimits.Window {
			t.Fatalf("got %+v, want the defaults %+v", got, DefaultBreakerLimits)
		}
	})

	t.Run("disabled is carried through", func(t *testing.T) {
		if ResolveBreakerLimits(false, nil, nil, nil).Enabled {
			t.Error("Enabled = true, want false")
		}
	})
}

// TestBreakerDefaultsCanActuallyTrip is the assertion that the two defaults are
// related rather than independently plausible numbers.
//
// A breaker threshold at or above the blast-radius cap can never fire: the cap
// stops the loop before that many bad outcomes can accumulate in the same window.
// This is the check that would have caught picking a round number.
func TestBreakerDefaultsCanActuallyTrip(t *testing.T) {
	if DefaultBreakerLimits.Window != DefaultUnattendedLimits.Window {
		t.Fatalf("breaker window %s != volume-cap window %s — the comparison below only holds when both count over the same period",
			DefaultBreakerLimits.Window, DefaultUnattendedLimits.Window)
	}
	if DefaultBreakerLimits.MaxPerCluster > DefaultUnattendedLimits.MaxPerCluster {
		t.Errorf("per-cluster breaker trips at %d bad outcomes but the volume cap only permits %d executions per window — the breaker could never fire",
			DefaultBreakerLimits.MaxPerCluster, DefaultUnattendedLimits.MaxPerCluster)
	}
	if DefaultBreakerLimits.MaxFleetWide > DefaultUnattendedLimits.MaxFleetWide {
		t.Errorf("fleet-wide breaker trips at %d bad outcomes but the volume cap only permits %d executions per window — the breaker could never fire",
			DefaultBreakerLimits.MaxFleetWide, DefaultUnattendedLimits.MaxFleetWide)
	}
}

// TestBreakerDisabledSkipsEverything asserts the disabled path does no work at
// all — it must not need a transaction, because CheckBreaker is called with one
// per candidate and an operator who turned the breaker off should pay nothing.
func TestBreakerDisabledSkipsEverything(t *testing.T) {
	// A nil pgx.Tx would panic the moment anything queried through it, so
	// reaching a decision here proves nothing was queried.
	got, err := CheckBreaker(nil, nil, "org_x", "cl_x", BreakerLimits{Enabled: false})
	if err != nil {
		t.Fatalf("CheckBreaker: %v", err)
	}
	if !got.Allowed {
		t.Error("Allowed = false, want true when the breaker is disabled")
	}
	if got.TrippedNow {
		t.Error("TrippedNow = true, want false — a disabled breaker must never trip")
	}
}
