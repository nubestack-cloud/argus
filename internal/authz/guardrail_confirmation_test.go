package authz

import (
	"testing"
	"time"
)

// TestGuardrailConfirmationRoundTrip covers the ordinary case: a token issued
// for (planID, guardrail) redeems for exactly that pair.
func TestGuardrailConfirmationRoundTrip(t *testing.T) {
	g := NewGuardrailConfirmationIssuer()
	token, err := g.Issue("plan_1", "scaleFromZero")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if !g.Redeem(token, "plan_1", "scaleFromZero") {
		t.Fatal("Redeem should succeed for the exact (planID, guardrail) it was issued for")
	}
}

// TestGuardrailConfirmationSingleUse is the property the whole mechanism rests
// on: a captured or logged token must be worthless for a second attempt.
func TestGuardrailConfirmationSingleUse(t *testing.T) {
	g := NewGuardrailConfirmationIssuer()
	token, _ := g.Issue("plan_1", "scaleFromZero")
	if !g.Redeem(token, "plan_1", "scaleFromZero") {
		t.Fatal("first redemption should succeed")
	}
	if g.Redeem(token, "plan_1", "scaleFromZero") {
		t.Fatal("second redemption of the same token must fail — this is what makes it proof of a fresh refusal, not a standing credential")
	}
}

// TestGuardrailConfirmationBoundToExactPair is the finding this mechanism
// exists to close: a token must not confirm a DIFFERENT guardrail, or the
// SAME guardrail on a different plan, even though a human might reasonably
// think of both as "the same approval."
func TestGuardrailConfirmationBoundToExactPair(t *testing.T) {
	g := NewGuardrailConfirmationIssuer()

	t.Run("wrong guardrail on the same plan", func(t *testing.T) {
		token, _ := g.Issue("plan_1", "scaleFromZero")
		if g.Redeem(token, "plan_1", "gitOpsManaged") {
			t.Fatal("a token minted for scaleFromZero must not confirm gitOpsManaged")
		}
	})

	t.Run("same guardrail on a different plan", func(t *testing.T) {
		token, _ := g.Issue("plan_1", "scaleFromZero")
		if g.Redeem(token, "plan_2", "scaleFromZero") {
			t.Fatal("a token minted for plan_1 must not confirm plan_2, even for the same guardrail")
		}
	})

	t.Run("unknown token", func(t *testing.T) {
		if g.Redeem("this-was-never-issued", "plan_1", "scaleFromZero") {
			t.Fatal("an unissued token must never redeem")
		}
	})
}

// TestGuardrailConfirmationExpires guards the TTL, which exists so a token
// cannot function as a long-lived standing credential if it leaks into a log.
func TestGuardrailConfirmationExpires(t *testing.T) {
	g := NewGuardrailConfirmationIssuer()
	token, _ := g.Issue("plan_1", "scaleFromZero")

	// Reach into the map directly to simulate time passing, rather than
	// sleeping in a test — GuardrailConfirmationTTL is 10 minutes.
	g.mu.Lock()
	c := g.tokens[token]
	c.expiresAt = time.Now().Add(-time.Second)
	g.tokens[token] = c
	g.mu.Unlock()

	if g.Redeem(token, "plan_1", "scaleFromZero") {
		t.Fatal("an expired token must not redeem")
	}
}

// TestGuardrailConfirmationTokensAreUnique guards against a degenerate issuer
// that could hand out the same token twice, which would let one operator's
// confirmation be replayed against a different, unrelated refusal.
func TestGuardrailConfirmationTokensAreUnique(t *testing.T) {
	g := NewGuardrailConfirmationIssuer()
	seen := map[string]bool{}
	for i := 0; i < 100; i++ {
		token, err := g.Issue("plan_1", "scaleFromZero")
		if err != nil {
			t.Fatalf("Issue: %v", err)
		}
		if seen[token] {
			t.Fatalf("duplicate token issued: %q", token)
		}
		seen[token] = true
	}
}
