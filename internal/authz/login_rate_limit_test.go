package authz

import (
	"testing"
	"time"
)

// TestLoginRateLimiterAllowsUntilThreshold covers the ordinary shape: the
// first LoginRateLimitMaxAttempts failures are allowed, the next is not.
func TestLoginRateLimiterAllowsUntilThreshold(t *testing.T) {
	l := NewLoginRateLimiter()
	for i := 0; i < LoginRateLimitMaxAttempts; i++ {
		if !l.Allow("user@example.com", "1.2.3.4") {
			t.Fatalf("attempt %d should still be allowed", i+1)
		}
		l.RecordFailure("user@example.com", "1.2.3.4")
	}
	if l.Allow("user@example.com", "1.2.3.4") {
		t.Fatal("the attempt past the threshold must be refused")
	}
}

// TestLoginRateLimiterKeyedPerPair guards the scope of the limit: a different
// account from the same IP, and the same account from a different IP, must
// each get their own budget — this is the documented trade-off (not a global
// or per-IP-only limit), so it must actually behave that way.
func TestLoginRateLimiterKeyedPerPair(t *testing.T) {
	l := NewLoginRateLimiter()
	for i := 0; i < LoginRateLimitMaxAttempts; i++ {
		l.RecordFailure("victim@example.com", "1.2.3.4")
	}
	if l.Allow("victim@example.com", "1.2.3.4") {
		t.Fatal("victim@example.com from 1.2.3.4 should be exhausted")
	}
	if !l.Allow("other@example.com", "1.2.3.4") {
		t.Error("a different account from the SAME ip must not be affected")
	}
	if !l.Allow("victim@example.com", "5.6.7.8") {
		t.Error("the same account from a DIFFERENT ip must not be affected")
	}
}

// TestLoginRateLimiterCaseInsensitiveEmail guards against the exact bypass an
// attacker varying case would attempt.
func TestLoginRateLimiterCaseInsensitiveEmail(t *testing.T) {
	l := NewLoginRateLimiter()
	for i := 0; i < LoginRateLimitMaxAttempts; i++ {
		l.RecordFailure("User@Example.com", "1.2.3.4")
	}
	if l.Allow("user@example.com", "1.2.3.4") {
		t.Fatal("varying email case must not reset or bypass the limit")
	}
}

// TestLoginRateLimiterWindowExpires guards that this is a THROTTLE, not a
// permanent lockout — old failures outside the window must stop counting.
func TestLoginRateLimiterWindowExpires(t *testing.T) {
	l := NewLoginRateLimiter()
	now := time.Now()
	// Directly populate old failures rather than sleeping in a test.
	key := loginRateLimitKey("user@example.com", "1.2.3.4")
	old := make([]time.Time, LoginRateLimitMaxAttempts)
	for i := range old {
		old[i] = now.Add(-LoginRateLimitWindow - time.Minute)
	}
	l.attempts[key] = &loginAttempts{failures: old}

	if !l.Allow("user@example.com", "1.2.3.4") {
		t.Fatal("failures outside the window must not count against the limit")
	}
}

// TestLoginRateLimiterSuccessDoesNotCount guards the documented rule: only
// RecordFailure adds to the count. Allow() alone (as a legitimate login flow
// would call, succeed, and never call RecordFailure) must never itself count
// as an attempt.
func TestLoginRateLimiterSuccessDoesNotCount(t *testing.T) {
	l := NewLoginRateLimiter()
	for i := 0; i < LoginRateLimitMaxAttempts*3; i++ {
		if !l.Allow("user@example.com", "1.2.3.4") {
			t.Fatalf("check %d: Allow() alone must never exhaust the limit", i)
		}
	}
}

// TestLoginRateLimiterPrunesOtherKeys guards against unbounded map growth
// from one-off failures against many different (email, IP) pairs that are
// never retried.
func TestLoginRateLimiterPrunesOtherKeys(t *testing.T) {
	l := NewLoginRateLimiter()
	now := time.Now()
	staleKey := loginRateLimitKey("stale@example.com", "9.9.9.9")
	l.attempts[staleKey] = &loginAttempts{failures: []time.Time{now.Add(-LoginRateLimitWindow - time.Minute)}}

	l.RecordFailure("fresh@example.com", "1.2.3.4")

	if _, stillThere := l.attempts[staleKey]; stillThere {
		t.Error("a key with only expired failures should have been pruned")
	}
}
