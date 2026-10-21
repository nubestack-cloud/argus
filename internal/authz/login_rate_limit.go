package authz

import (
	"strings"
	"sync"
	"time"
)

// LoginRateLimitWindow/LoginRateLimitMaxAttempts bound how many failed login
// attempts one (email, sourceIP) pair may make before being refused —
// STATUS.md/BACKLOG.md's G7: "no rate limiting on POST /auth/login" (the
// timing-oracle fix already made a guess cost symmetric, not bounded).
//
// Sized generously on purpose. This is a first mitigation layer, not a
// complete answer to credential stuffing — see LoginRateLimiter's own doc
// comment for what it deliberately does not attempt — and a threshold tight
// enough to meaningfully slow a real attacker (which needs thousands of
// guesses) is also tight enough to lock out a real user who mistypes a
// password a few times in a row. 10 attempts per 5 minutes is closer to "an
// automated script gets slowed to a crawl" than "one legitimate user is ever
// blocked by their own typos."
const (
	LoginRateLimitWindow      = 5 * time.Minute
	LoginRateLimitMaxAttempts = 10
)

// loginAttempts is one (email, sourceIP) pair's recent failure history —
// timestamps of failed attempts still inside the window, oldest first.
type loginAttempts struct {
	failures []time.Time
}

// LoginRateLimiter tracks failed login attempts per (email, sourceIP) pair
// and refuses further attempts once LoginRateLimitMaxAttempts is reached
// inside LoginRateLimitWindow.
//
// # WHAT THIS DELIBERATELY DOES NOT ATTEMPT
//
// This is a first, cheap mitigation layer, not the complete answer to
// credential-stuffing or brute-force login abuse:
//   - Keyed on (email, sourceIP), not sourceIP alone — an attacker spraying
//     many DIFFERENT accounts from one IP, or one account from many IPs
//     (a botnet), is throttled per-pair, not stopped outright. A real defense
//     against either needs a broader signal (global attempt rate, known-bad
//     IP reputation, CAPTCHA) that is a genuinely separate feature.
//   - In-memory and single-hub, matching this package's own established
//     convention (WSTicketIssuer, GuardrailConfirmationIssuer) and for the
//     identical reason: this only needs to survive minutes on the process
//     handling the request, and a hub restart resetting the counters is an
//     acceptable, bounded cost — not a security regression, since the
//     underlying passwords/hashing are unaffected.
//   - Counts FAILURES only, not successful logins — a legitimate user who
//     gets their password right on the first or second try never interacts
//     with this limiter at all.
//
// This closes the specific gap named in BACKLOG.md G7: an attacker could make
// unlimited password guesses against one account with no cost beyond the
// (now-symmetric, per the timing-oracle fix) per-request latency. It does not
// claim to close every login-abuse vector.
type LoginRateLimiter struct {
	mu       sync.Mutex
	attempts map[string]*loginAttempts
}

// NewLoginRateLimiter constructs an empty limiter.
func NewLoginRateLimiter() *LoginRateLimiter {
	return &LoginRateLimiter{attempts: make(map[string]*loginAttempts)}
}

// Allow reports whether a login attempt for (email, sourceIP) may proceed —
// call BEFORE checking the password, so a rate-limited request costs nothing
// beyond this in-memory lookup, no database round trip. Pure query: this does
// NOT record anything by itself. Call RecordFailure separately, only on an
// actual failed attempt, so a correct password on attempt 3 does not count
// attempts 1-2 against some later, unrelated failure streak.
func (l *LoginRateLimiter) Allow(email, sourceIP string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	key := loginRateLimitKey(email, sourceIP)
	a, found := l.attempts[key]
	if !found {
		return true
	}
	a.failures = pruneOldFailures(a.failures, time.Now())
	return len(a.failures) < LoginRateLimitMaxAttempts
}

// RecordFailure records one failed attempt for (email, sourceIP). Call this,
// and only this, on the specific branch that already writes a "login_failed"
// audit event — the two should always happen together, since both exist to
// answer "was this a real failed attempt."
//
// Opportunistically prunes every OTHER key's expired entries on each call
// (same amortized-cleanup convention as WSTicketIssuer.pruneExpiredLocked),
// so this map cannot grow unboundedly from one-off failures that are never
// retried — an attacker who tries once against a thousand different
// (email, IP) pairs and never returns must not leave a thousand permanent map
// entries behind.
func (l *LoginRateLimiter) RecordFailure(email, sourceIP string) {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	key := loginRateLimitKey(email, sourceIP)
	a, found := l.attempts[key]
	if !found {
		a = &loginAttempts{}
		l.attempts[key] = a
	}
	a.failures = append(pruneOldFailures(a.failures, now), now)

	for k, other := range l.attempts {
		if k == key {
			continue
		}
		other.failures = pruneOldFailures(other.failures, now)
		if len(other.failures) == 0 {
			delete(l.attempts, k)
		}
	}
}

// pruneOldFailures drops every failure timestamp older than
// LoginRateLimitWindow, keeping the slice's oldest-first ordering.
func pruneOldFailures(failures []time.Time, now time.Time) []time.Time {
	cutoff := now.Add(-LoginRateLimitWindow)
	i := 0
	for i < len(failures) && failures[i].Before(cutoff) {
		i++
	}
	return failures[i:]
}

// loginRateLimitKey combines email and source IP into one map key.
// Lower-cased email to match handleLogin's own case-insensitive lookup
// (`WHERE lower(email) = lower($1)`) — without this, "User@x.com" and
// "user@x.com" would rate-limit as two different accounts, which is exactly
// the gap an attacker varying case would walk straight through.
func loginRateLimitKey(email, sourceIP string) string {
	return strings.ToLower(email) + "|" + sourceIP
}
