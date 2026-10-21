package authz

import (
	"testing"
	"time"
)

func TestSSOHandoffIsSingleUse(t *testing.T) {
	h := NewSSOHandoffIssuer()
	code, _, err := h.Issue("usr_1", "org_1")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	userID, tenantID, ok := h.Redeem(code)
	if !ok || userID != "usr_1" || tenantID != "org_1" {
		t.Fatalf("first Redeem = (%q, %q, %v), want (usr_1, org_1, true)", userID, tenantID, ok)
	}

	// The whole point: a captured redirect URL must not be replayable.
	if _, _, ok := h.Redeem(code); ok {
		t.Fatal("second Redeem succeeded — a handoff code must be single-use")
	}
}

func TestSSOHandoffRejectsUnknownAndEmpty(t *testing.T) {
	h := NewSSOHandoffIssuer()
	if _, _, ok := h.Redeem(""); ok {
		t.Error("empty code was accepted")
	}
	if _, _, ok := h.Redeem("not-a-real-code"); ok {
		t.Error("unknown code was accepted")
	}
}

// TestSSOHandoffExpiredCodeIsDeadNotMerelyRejected pins the posture that an
// expired code is removed, so it cannot be retried if a clock moves or a
// caller loops.
func TestSSOHandoffExpiredCodeIsDeadNotMerelyRejected(t *testing.T) {
	h := NewSSOHandoffIssuer()
	code, _, err := h.Issue("usr_1", "org_1")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	h.mu.Lock()
	entry := h.codes[code]
	entry.expiresAt = time.Now().Add(-time.Second)
	h.codes[code] = entry
	h.mu.Unlock()

	if _, _, ok := h.Redeem(code); ok {
		t.Fatal("expired code was accepted")
	}

	h.mu.Lock()
	_, still := h.codes[code]
	h.mu.Unlock()
	if still {
		t.Fatal("expired code is still in the map — Redeem must delete on any hit")
	}
}

// TestSSOHandoffCodesAreDistinct guards against the failure where every login
// gets the same code, which would let one person's handoff redeem another's
// session.
func TestSSOHandoffCodesAreDistinct(t *testing.T) {
	h := NewSSOHandoffIssuer()
	seen := map[string]bool{}
	for i := 0; i < 100; i++ {
		code, _, err := h.Issue("usr_1", "org_1")
		if err != nil {
			t.Fatalf("Issue: %v", err)
		}
		if seen[code] {
			t.Fatal("Issue returned a duplicate code")
		}
		seen[code] = true
	}
}

// TestSSOHandoffIsNotAWSTicket is the regression guard for the confused-deputy
// concern the type's own doc comment describes: the two pools must stay
// separate, so a ticket minted for a WebSocket handshake cannot be spent at
// the token endpoint or the reverse.
func TestSSOHandoffIsNotAWSTicket(t *testing.T) {
	h := NewSSOHandoffIssuer()
	w := NewWSTicketIssuer()

	handoff, _, err := h.Issue("usr_1", "org_1")
	if err != nil {
		t.Fatalf("Issue handoff: %v", err)
	}
	ticket, _, err := w.Issue("usr_1", "org_1")
	if err != nil {
		t.Fatalf("Issue ws ticket: %v", err)
	}

	if _, _, ok := w.Redeem(handoff); ok {
		t.Error("an SSO handoff code was redeemable as a WebSocket ticket")
	}
	if _, _, ok := h.Redeem(ticket); ok {
		t.Error("a WebSocket ticket was redeemable as an SSO handoff code")
	}
}
