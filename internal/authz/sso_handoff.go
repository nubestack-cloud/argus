package authz

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"sync"
	"time"
)

// SSOHandoffTTL bounds the window between the OIDC callback redirecting a
// browser and the SPA exchanging the handoff code for real tokens.
//
// Fifteen seconds: the exchange is one immediate fetch from a page that has
// just loaded, so this is generous already. It is deliberately shorter than
// anything a person is involved in, because nobody has to read or type it.
const SSOHandoffTTL = 15 * time.Second

const ssoHandoffBytes = 32

type ssoHandoff struct {
	userID    string
	tenantID  string
	expiresAt time.Time
}

// SSOHandoffIssuer solves the problem that an OIDC callback arrives as a
// browser REDIRECT while this application authenticates with bearer tokens
// held in JavaScript.
//
// # Why a handoff code at all
//
// The callback has just authenticated somebody and holds a freshly minted
// access/refresh token pair, but it cannot hand them to the SPA the way
// POST /auth/login does, because its response is a 302 and not JSON. The
// available options and why this one:
//
//   - Put the tokens in the redirect fragment (`/#access_token=...`). Rejected:
//     tokens land in browser history, in any referrer, and in the URL bar. This
//     is the classic OAuth implicit-flow mistake and it is deprecated for
//     exactly this reason.
//   - Set an httpOnly session cookie. Rejected here for THIS handoff
//     specifically, though PROJECT.md B164 (2026-09-18) later did exactly
//     this for the refresh token itself (internal/api/auth.go's
//     setRefreshCookie) — narrowly, for the two routes that ever read it
//     back, both POST, both SameSite=Lax, so CSRF stays re-established for
//     that one exposure (lld/01-threat-model.md's B1 row) rather than
//     reopened across every mutating route. That doesn't change the
//     reasoning HERE: this handoff is a one-shot, 15-second, single-use
//     credential redeemed once, immediately, by the SPA that just loaded —
//     a cookie buys it nothing a code doesn't already have, and every OTHER
//     route (this one included) still authenticates on `Authorization:
//     Bearer` alone, never on a cookie.
//   - A single-use handoff code the SPA exchanges for the tokens. Chosen. The
//     code is worthless after one use and after fifteen seconds, so its
//     appearance in history is not an authentication event.
//
// # Why not reuse WSTicketIssuer
//
// It is the same shape and the same reasoning, and reusing it was the first
// instinct. It is deliberately NOT reused: a WS ticket is redeemed by the
// WebSocket handshake and an SSO handoff is redeemed at a token endpoint, so a
// shared pool would let a ticket minted for one purpose be spent at the other.
// That is a confused deputy, and the cost of avoiding it is one small type.
// The same argument the ID-prefix convention makes — a value alone should not
// be ambiguous about what it authorises — applies to a credential far more
// than to an identifier.
type SSOHandoffIssuer struct {
	mu    sync.Mutex
	codes map[string]ssoHandoff
}

func NewSSOHandoffIssuer() *SSOHandoffIssuer {
	return &SSOHandoffIssuer{codes: make(map[string]ssoHandoff)}
}

// Issue mints a single-use handoff code for an already-authenticated identity.
//
// The caller must have completed and verified the OIDC flow first. This
// function performs no authentication of its own — it is a courier, and
// issuing a code IS the assertion that authentication succeeded.
func (h *SSOHandoffIssuer) Issue(userID, tenantID string) (code string, expiresAt time.Time, err error) {
	raw := make([]byte, ssoHandoffBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", time.Time{}, fmt.Errorf("generate sso handoff entropy: %w", err)
	}
	code = base64.RawURLEncoding.EncodeToString(raw)
	expiresAt = time.Now().Add(SSOHandoffTTL)

	h.mu.Lock()
	defer h.mu.Unlock()
	h.pruneExpiredLocked()
	h.codes[code] = ssoHandoff{userID: userID, tenantID: tenantID, expiresAt: expiresAt}
	return code, expiresAt, nil
}

// Redeem consumes a handoff code, returning the identity it stands for.
//
// The code is deleted on ANY lookup that finds it, successful or expired, so a
// code cannot be retried and a captured redirect URL cannot be replayed.
//
// The comparison walks the map rather than indexing it, so that a caller
// cannot learn anything from timing about which prefixes exist. Map lookup on
// a string is not constant-time with respect to the key's content, and while
// guessing 32 bytes of entropy is not a realistic threat, SR-19 makes
// constant-time comparison the house rule for anything credential-shaped
// rather than a judgement call per site.
func (h *SSOHandoffIssuer) Redeem(code string) (userID, tenantID string, ok bool) {
	if code == "" {
		return "", "", false
	}
	h.mu.Lock()
	defer h.mu.Unlock()

	var (
		foundKey string
		found    ssoHandoff
		hit      bool
	)
	for k, v := range h.codes {
		if subtle.ConstantTimeCompare([]byte(k), []byte(code)) == 1 {
			foundKey, found, hit = k, v, true
			break
		}
	}
	if !hit {
		return "", "", false
	}
	delete(h.codes, foundKey)
	if time.Now().After(found.expiresAt) {
		// Deleted above, so an expired code is permanently dead rather than
		// merely rejected — the same posture WSTicketIssuer takes.
		return "", "", false
	}
	return found.userID, found.tenantID, true
}

// pruneExpiredLocked drops expired entries. Called on Issue so the map cannot
// grow without bound in a hub nobody ever finishes a login against; the caller
// must hold h.mu.
func (h *SSOHandoffIssuer) pruneExpiredLocked() {
	now := time.Now()
	for k, v := range h.codes {
		if now.After(v.expiresAt) {
			delete(h.codes, k)
		}
	}
}
