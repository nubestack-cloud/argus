package authz

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"sync"
	"time"
)

// GuardrailConfirmationTTL bounds how long a refusal's confirmation token stays
// redeemable. Generous relative to WSTicketTTL — this one is meant to survive
// an operator actually reading the refusal message and deciding, not an
// immediate machine-to-machine round trip — but still short enough that a
// token cannot function as a standing "always allowed" credential if it leaks
// into a log or a browser history entry.
const GuardrailConfirmationTTL = 10 * time.Minute

// guardrailTokenBytes matches wsTicketBytes' reasoning exactly: 256 bits of
// entropy, single-use, short-lived — well beyond brute-force range for a
// value with this lifetime.
const guardrailTokenBytes = 32

// guardrailConfirmation is one issued-but-not-yet-redeemed token's state.
type guardrailConfirmation struct {
	planID    string
	guardrail string
	expiresAt time.Time
}

// GuardrailConfirmationIssuer answers WORKLOG.md §97's finding G5: two
// remediation guardrails (scale-from-zero, GitOps-managed) refuse by default
// and accept a per-request boolean override — confirmScaleFromZero,
// confirmGitOpsManaged — that an operator sets after seeing the refusal.
//
// The gap the review named: nothing distinguished "an operator saw the 409 and
// deliberately confirmed" from "this client always sends true". A scripted
// approver, a UI regression, or simply a third and fourth guardrail (making
// "set every flag" the path of least resistance) could set the boolean without
// the refusal ever having been shown to anyone. The audit trail recorded the
// boolean, not evidence that a human read the refusal it answers.
//
// The fix is the same shape WSTicketIssuer already uses for an unrelated
// problem with an identical structure (a short-lived, single-use credential
// that only ever needs to survive a few seconds-to-minutes on the one hub
// process that issued it): a REFUSAL now mints a token bound to
// (planID, guardrail-kind), returned to the client as part of the problem
// response. Approving again must ECHO that token back, not just flip the
// boolean — so the boolean can no longer be pre-armed; it can only ever be a
// response to a refusal that genuinely happened, on genuinely this plan.
//
// Deliberately in-memory and single-hub, matching WSTicketIssuer's own
// reasoning verbatim: this needs to survive minutes, not a hub restart or a
// second replica, and a lost token on restart just means the operator sees the
// same refusal again and gets a fresh one — no worse than the ticket case's
// "the WS connect flow retries from the top."
type GuardrailConfirmationIssuer struct {
	mu     sync.Mutex
	tokens map[string]guardrailConfirmation
}

// NewGuardrailConfirmationIssuer constructs an empty issuer.
func NewGuardrailConfirmationIssuer() *GuardrailConfirmationIssuer {
	return &GuardrailConfirmationIssuer{tokens: make(map[string]guardrailConfirmation)}
}

// Issue mints a fresh single-use token proving a refusal for (planID,
// guardrail) genuinely happened. Called from the guardrail's own refusal path,
// never speculatively — a token that could be minted without a real refusal
// would defeat the entire point.
//
// guardrail is a short, stable identifier ("scaleFromZero", "gitOpsManaged"),
// not the human-readable refusal message — the message can be reworded freely
// without invalidating in-flight tokens, and a caller comparing guardrail
// strings is comparing intent, not prose.
func (g *GuardrailConfirmationIssuer) Issue(planID, guardrail string) (token string, err error) {
	raw := make([]byte, guardrailTokenBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generate confirmation token entropy: %w", err)
	}
	token = base64.RawURLEncoding.EncodeToString(raw)

	g.mu.Lock()
	defer g.mu.Unlock()
	g.pruneExpiredLocked()
	g.tokens[token] = guardrailConfirmation{
		planID: planID, guardrail: guardrail, expiresAt: time.Now().Add(GuardrailConfirmationTTL),
	}
	return token, nil
}

// Redeem consumes token if it exists, has not expired, and was issued for
// EXACTLY this (planID, guardrail) pair — a token minted for the scale-from-
// zero refusal on plan A must not confirm the GitOps guardrail on plan A, and
// must not confirm the scale-from-zero guardrail on a re-proposed plan B for
// the same incident, even though a human might reasonably think of both as
// "the same approval."
//
// Single-use regardless of outcome: whether or not the token was valid, it
// is removed from the table before Redeem returns, so a captured or logged
// token is worthless for a second attempt — matching WSTicketIssuer.Redeem's
// identical guarantee and identical reasoning (there is nothing here to
// constant-time-compare against; this is an exact map-key lookup, not a
// caller-supplied value being checked against one known secret, which is
// what SR-19's constant-time rule is scoped to).
func (g *GuardrailConfirmationIssuer) Redeem(token, planID, guardrail string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()

	c, found := g.tokens[token]
	if !found {
		return false
	}
	delete(g.tokens, token)
	if time.Now().After(c.expiresAt) {
		return false
	}
	return c.planID == planID && c.guardrail == guardrail
}

// pruneExpiredLocked drops expired entries, called opportunistically from
// Issue exactly like WSTicketIssuer.pruneExpiredLocked, for the same reason: a
// caller who is refused and never retries (fixes the underlying problem
// instead, or simply walks away) must not leak an entry forever.
func (g *GuardrailConfirmationIssuer) pruneExpiredLocked() {
	now := time.Now()
	for k, c := range g.tokens {
		if now.After(c.expiresAt) {
			delete(g.tokens, k)
		}
	}
}
