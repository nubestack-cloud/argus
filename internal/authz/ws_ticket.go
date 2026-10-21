package authz

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"sync"
	"time"
)

// WSTicketTTL is how long a WebSocket connect ticket stays redeemable
// after issuance. Short by design: the ticket travels as a URL query
// parameter (browsers cannot attach an Authorization header to a
// WebSocket handshake — see WSTicketIssuer's own doc comment for the full
// reasoning behind this whole mechanism), so anything with a long lifetime
// there would be exactly the kind of credential this codebase already
// works hard to keep out of URLs/browser history/server access logs. 30s
// is generous for "issue a ticket, then immediately open a WebSocket with
// it" (the only thing this ticket is ever used for) while being far too
// short to be useful to anyone who might otherwise observe it in transit,
// in a log line, or in browser history.
const WSTicketTTL = 30 * time.Second

// wsTicketBytes is the raw entropy size of an issued ticket, before
// base64url encoding — 256 bits, well beyond brute-force range for a
// value that's already single-use and expires in WSTicketTTL.
const wsTicketBytes = 32

// wsTicket is one issued-but-not-yet-redeemed ticket's state.
type wsTicket struct {
	userID    string
	tenantID  string
	expiresAt time.Time
}

// WSTicketIssuer implements this codebase's chosen answer to "how does a
// WebSocket upgrade request authenticate, given the app's normal
// Authorization: Bearer <JWT> convention doesn't carry over to a browser
// WebSocket handshake" (the browser WebSocket API has no way to set a
// custom header on the upgrade request, so the JWT-in-header convention
// every other route uses literally cannot apply here).
//
// Chosen mechanism: a short-lived, single-use ticket. The client first
// makes a normal, fully-authenticated REST call (POST /api/v1/ws/ticket,
// requireAuth-gated exactly like every other route) to mint one, then
// immediately opens the WebSocket with the ticket as a query parameter
// (GET /ws/events?ticket=...). This was chosen over the other reasonable
// option this task's brief names — a long-lived token/JWT directly in the
// query string — specifically because a query-string value that short-
// lived and single-use cannot function as a standing credential even if
// it leaks into browser history or a server access log: by the time
// anyone could read it back out of either place, it has already either
// been redeemed (and is now permanently dead — Redeem below deletes it on
// first use, successful or not) or expired (WSTicketTTL). A raw access
// JWT in the URL would have neither property: it would remain valid, and
// replayable, for its entire AccessTokenTTL (15 minutes) every place it
// was ever logged.
//
// Deliberately in-memory, guarded by a mutex, exactly like
// internal/events.Bus and for the identical reason stated there: this
// only ever needs to survive the few seconds between issuance and the
// WebSocket upgrade that redeems it, on the one hub process that issued
// it, so there is nothing here worth persisting across a restart or
// sharing across replicas. A hub restart between issuance and redemption
// simply means that one ticket 404s the WS upgrade — the client's own
// connect flow (mint a ticket, then connect) can just retry from the top
// exactly the way a dropped WebSocket already needs to reconnect from
// scratch per lld/11-ui-design.md §5's backoff requirement.
type WSTicketIssuer struct {
	mu      sync.Mutex
	tickets map[string]wsTicket
}

// NewWSTicketIssuer constructs an empty WSTicketIssuer.
func NewWSTicketIssuer() *WSTicketIssuer {
	return &WSTicketIssuer{tickets: make(map[string]wsTicket)}
}

// Issue mints a fresh single-use ticket for userID/tenantID (the already-
// authenticated caller's identity, resolved by requireAuth exactly like
// any other route), valid until the returned expiry. Opportunistically
// prunes already-expired tickets on every call so this map can never grow
// unboundedly from callers who mint a ticket and never redeem it (a
// closed browser tab, a connection attempt that never happens) — cheap to
// do here since Issue is already O(1) plus this sweep, and this codebase
// has no other natural place to run a periodic GC for something this
// short-lived.
func (w *WSTicketIssuer) Issue(userID, tenantID string) (ticket string, expiresAt time.Time, err error) {
	raw := make([]byte, wsTicketBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", time.Time{}, fmt.Errorf("generate ticket entropy: %w", err)
	}
	ticket = base64.RawURLEncoding.EncodeToString(raw)
	expiresAt = time.Now().Add(WSTicketTTL)

	w.mu.Lock()
	defer w.mu.Unlock()
	w.pruneExpiredLocked()
	w.tickets[ticket] = wsTicket{userID: userID, tenantID: tenantID, expiresAt: expiresAt}
	return ticket, expiresAt, nil
}

// Redeem consumes ticket if it exists and has not yet expired, returning
// the (userID, tenantID) it was issued for. Single-use: whether or not the
// ticket was valid, it is removed from the table by the time Redeem
// returns, so a captured/replayed ticket value is worthless for a second
// connection attempt. Constant-time comparison isn't meaningful here (this
// looks a ticket up by exact map key, not by comparing against one known
// value — there's nothing to time-oracle against), matching how this
// codebase's other constant-time-comparison rule (SR-19) is scoped to
// comparing a caller-supplied value against ONE secret, which this is not.
func (w *WSTicketIssuer) Redeem(ticket string) (userID, tenantID string, ok bool) {
	w.mu.Lock()
	defer w.mu.Unlock()

	t, found := w.tickets[ticket]
	if !found {
		return "", "", false
	}
	delete(w.tickets, ticket)
	if time.Now().After(t.expiresAt) {
		return "", "", false
	}
	return t.userID, t.tenantID, true
}

// pruneExpiredLocked removes every already-expired ticket. Callers must
// already hold w.mu.
func (w *WSTicketIssuer) pruneExpiredLocked() {
	now := time.Now()
	for k, t := range w.tickets {
		if now.After(t.expiresAt) {
			delete(w.tickets, k)
		}
	}
}
