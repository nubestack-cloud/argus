package orchestrator

import (
	"testing"
	"time"
)

// TestEscalationTierBelowFirstThreshold is the "almost every incident,
// almost all the time" case: age hasn't crossed the first tier yet, so
// there is nothing to escalate.
func TestEscalationTierBelowFirstThreshold(t *testing.T) {
	for _, age := range []time.Duration{0, time.Minute, time.Hour, mergeStalenessThreshold - time.Second} {
		if _, _, ok := escalationTier(age); ok {
			t.Errorf("escalationTier(%s) = ok, want not-yet-escalating", age)
		}
		if key, _, ok := escalationNotifyKey("X", age); ok {
			t.Errorf("escalationNotifyKey(%s) = (%q, ok), want (\"\", false)", age, key)
		}
	}
}

// TestEscalationTierWidensWithAge walks ages across the documented schedule
// (48h, 5d, 12d, then weekly) and checks both the threshold crossed and the
// tier's zero-based depth — the depth is what escalationUrgencyPrefix keys
// its wording on, so getting it right matters beyond just the notify key.
func TestEscalationTierWidensWithAge(t *testing.T) {
	day := 24 * time.Hour
	for _, tc := range []struct {
		name          string
		age           time.Duration
		wantThreshold time.Duration
		wantIndex     int
	}{
		{"just past the first tier", mergeStalenessThreshold + time.Minute, mergeStalenessThreshold, 0},
		{"still in the first tier, just under the second", 5*day - time.Minute, mergeStalenessThreshold, 0},
		{"exactly the second tier", 5 * day, 5 * day, 1},
		{"between the second and third tiers", 8 * day, 5 * day, 1},
		{"exactly the third tier", 12 * day, 12 * day, 2},
		{"one week past the third tier", 19 * day, 19 * day, 3},
		{"two weeks past the third tier", 26 * day, 26 * day, 4},
		{"many weeks past the third tier", 12*day + 52*7*day, 12*day + 52*7*day, 2 + 52},
	} {
		t.Run(tc.name, func(t *testing.T) {
			threshold, index, ok := escalationTier(tc.age)
			if !ok {
				t.Fatalf("escalationTier(%s) = not escalating, want escalating", tc.age)
			}
			if threshold != tc.wantThreshold {
				t.Errorf("threshold = %s, want %s", threshold, tc.wantThreshold)
			}
			if index != tc.wantIndex {
				t.Errorf("index = %d, want %d", index, tc.wantIndex)
			}
		})
	}
}

// TestEscalationTierKeyDiffersAcrossTiers is the exact property T3's brief
// asks for a test of: "does tier N's key differ from tier N-1's?" A key
// that stays the same across a tier boundary would silently collide with
// notify.NotifyTransition's own dedup guard and the widening escalation
// would never actually re-send anything past the first nudge — exactly the
// bug this task exists to fix.
func TestEscalationTierKeyDiffersAcrossTiers(t *testing.T) {
	day := 24 * time.Hour
	ages := []time.Duration{
		mergeStalenessThreshold + time.Hour, // tier 0 (48h)
		5 * day,                             // tier 1 (5d)
		12 * day,                            // tier 2 (12d)
		19 * day,                            // tier 3 (19d)
	}
	seen := map[string]time.Duration{}
	for _, age := range ages {
		key, _, ok := escalationNotifyKey("AwaitingMerge:StalePR", age)
		if !ok {
			t.Fatalf("escalationNotifyKey(%s) = not escalating, want escalating", age)
		}
		if prior, dup := seen[key]; dup {
			t.Fatalf("age %s produced key %q, which age %s already produced — tiers must never share a key", age, key, prior)
		}
		seen[key] = age
	}
}

// TestEscalationTierKeySameTierTwiceIsIdentical is the flip side of the
// above, and the property notify.NotifyTransition's own dedup guard relies
// on: two different sweep ticks that both observe an age still inside the
// SAME tier must produce the IDENTICAL key, or a plain "still stale, no
// change" tick would look like a fresh escalation.
func TestEscalationTierKeySameTierTwiceIsIdentical(t *testing.T) {
	first, _, ok1 := escalationNotifyKey("AwaitingApproval:Stale", mergeStalenessThreshold+time.Hour)
	second, _, ok2 := escalationNotifyKey("AwaitingApproval:Stale", mergeStalenessThreshold+2*time.Hour)
	if !ok1 || !ok2 {
		t.Fatalf("both ages should escalate: ok1=%v ok2=%v", ok1, ok2)
	}
	if first != second {
		t.Fatalf("two ages inside the same tier produced different keys: %q vs %q", first, second)
	}
}

// TestEscalationNotifyKeyPrefixIsPreserved checks the caller's condition
// prefix survives intact — mergewatch.go and approvalwatch.go each pass a
// different, fixed prefix naming which STUCK CONDITION is escalating, and a
// bug that dropped or mangled it would make the two conditions
// indistinguishable in incident_notifications.
func TestEscalationNotifyKeyPrefixIsPreserved(t *testing.T) {
	key, _, ok := escalationNotifyKey("AwaitingApproval:Stale", 6*24*time.Hour)
	if !ok {
		t.Fatal("expected escalation at 6 days")
	}
	const wantPrefix = "AwaitingApproval:Stale:"
	if len(key) <= len(wantPrefix) || key[:len(wantPrefix)] != wantPrefix {
		t.Errorf("key = %q, want it to start with %q", key, wantPrefix)
	}
}

// TestEscalationUrgencyPrefixScalesWithDepth is a light sanity check that
// urgency wording actually changes with tier depth rather than silently
// staying the same sentence at every tier (T3's brief: "consider whether
// escalating tiers should say something different").
func TestEscalationUrgencyPrefixScalesWithDepth(t *testing.T) {
	first := escalationUrgencyPrefix(0)
	second := escalationUrgencyPrefix(1)
	third := escalationUrgencyPrefix(2)
	fourth := escalationUrgencyPrefix(5)
	if first != "" {
		t.Errorf("tier 0 prefix = %q, want empty (matches the pre-existing, unwidened first nudge)", first)
	}
	if second == first || second == "" {
		t.Errorf("tier 1 prefix = %q, want distinct, non-empty urgency language", second)
	}
	if third == second || third == "" {
		t.Errorf("tier 2 prefix = %q, want distinct, non-empty urgency language from tier 1 (%q)", third, second)
	}
	if fourth != third {
		t.Errorf("tier 5 prefix = %q, want the same steady-state wording as tier 2 (%q) — depth beyond 2 shouldn't need a new sentence each time", fourth, third)
	}
}
