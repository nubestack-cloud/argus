package authz

import (
	"testing"
	"time"
)

func TestWSTicketIssueThenRedeemSucceedsOnce(t *testing.T) {
	w := NewWSTicketIssuer()
	ticket, expiresAt, err := w.Issue("usr_1", "org_1")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if ticket == "" {
		t.Fatal("Issue returned an empty ticket")
	}
	if !expiresAt.After(time.Now()) {
		t.Fatalf("expiresAt %v is not in the future", expiresAt)
	}

	userID, tenantID, ok := w.Redeem(ticket)
	if !ok {
		t.Fatal("Redeem: expected ok=true for a freshly issued ticket")
	}
	if userID != "usr_1" || tenantID != "org_1" {
		t.Errorf("Redeem: got (%q, %q), want (%q, %q)", userID, tenantID, "usr_1", "org_1")
	}

	// Single-use: redeeming the same ticket again must fail.
	if _, _, ok := w.Redeem(ticket); ok {
		t.Fatal("Redeem: expected ok=false when redeeming an already-redeemed ticket")
	}
}

func TestWSTicketRedeemUnknownFails(t *testing.T) {
	w := NewWSTicketIssuer()
	if _, _, ok := w.Redeem("not-a-real-ticket"); ok {
		t.Fatal("Redeem: expected ok=false for an unknown ticket")
	}
}

func TestWSTicketExpires(t *testing.T) {
	w := NewWSTicketIssuer()
	ticket, _, err := w.Issue("usr_1", "org_1")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	// Force this ticket into the past rather than sleeping WSTicketTTL.
	w.mu.Lock()
	entry := w.tickets[ticket]
	entry.expiresAt = time.Now().Add(-time.Second)
	w.tickets[ticket] = entry
	w.mu.Unlock()

	if _, _, ok := w.Redeem(ticket); ok {
		t.Fatal("Redeem: expected ok=false for an expired ticket")
	}
}

func TestWSTicketIssueTwiceProducesDistinctTickets(t *testing.T) {
	w := NewWSTicketIssuer()
	t1, _, err := w.Issue("usr_1", "org_1")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	t2, _, err := w.Issue("usr_1", "org_1")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if t1 == t2 {
		t.Fatal("two Issue calls produced the same ticket value")
	}
}
