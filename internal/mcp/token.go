package mcp

// Scoped MCP tokens — lld/01-threat-model.md SR-24, the inbound half of the
// B12 boundary.
//
// The requirement this file implements, verbatim from SR-24: "An MCP token
// issued to a runner is scoped to a single investigation, a single cluster,
// and read-only tools; the hub resolves cluster identity from the token and
// never from runner-supplied parameters."
//
// That last clause is the one that does the work. The runner (and the CLI
// inside it, and therefore anything that successfully injects instructions
// into evidence content — T21) never gets to say which cluster it is asking
// about. It presents a token; the hub looks up which single cluster that
// token was minted for. A compromised runner cannot enumerate the fleet
// because there is no parameter through which to try.
//
// Deliberately in-memory rather than a table. A token's whole life is one
// investigation — minutes at most — so persisting it would add a migration,
// a cleanup job, and a read on every tool call to buy exactly one property:
// surviving a hub restart mid-investigation. An investigation whose hub
// restarted is already failed, so that property is worth nothing here. If the
// hub ever runs multiple replicas that must share these, this is the file
// that has to change, and that constraint is stated in Store's doc comment
// rather than left for someone to discover.

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"sync"
	"time"
)

// DefaultTokenTTL bounds how long a minted token stays valid. Generous
// relative to a normal investigation (which is bounded independently by the
// analysis time limit and by the runner's own hard process deadline) but
// short in absolute terms, so a leaked token is a narrow window rather than a
// standing credential. A token is also revoked explicitly the moment its
// investigation finishes, so the TTL only matters for the case where that
// revocation never runs — a panicking or killed hub goroutine.
const DefaultTokenTTL = 15 * time.Minute

// Grant is what one token authorizes: one cluster, one investigation, one
// fixed set of tool names, until one expiry.
type Grant struct {
	ClusterID  string
	IncidentID string
	// AllowedTools is the exact set of callable tool names. Empty means
	// nothing is callable — never "everything," which is the failure mode a
	// nil-means-all convention would eventually produce.
	AllowedTools map[string]struct{}
	ExpiresAt    time.Time
	// Principal is set only on a grant from the user-facing mount's personal
	// access token (PROJECT.md AD3), where the scope is a PERSON rather than
	// one cluster and one investigation: ClusterID and IncidentID are then
	// empty, and the ToolFunc resolves that person's grants on every call.
	// Nil on every per-investigation grant this Store mints.
	Principal *Principal
}

// Principal is who a personal-token grant acts as. Resolved by the hub from
// the token row, never from anything the client sends.
type Principal struct {
	TenantID string
	UserID   string
	TokenID  string
	// SourceIP is the caller's address, for the audit record.
	SourceIP string
}

// Store mints, validates and revokes scoped tokens.
//
// Single-process only, by construction (see the file comment). Safe for
// concurrent use within that process.
type Store struct {
	mu     sync.Mutex
	grants map[string]Grant
	ttl    time.Duration
	now    func() time.Time
}

// NewStore builds a Store. ttl <= 0 selects DefaultTokenTTL. now may be nil,
// in which case time.Now is used — it exists to make expiry testable without
// sleeping.
func NewStore(ttl time.Duration, now func() time.Time) *Store {
	if ttl <= 0 {
		ttl = DefaultTokenTTL
	}
	if now == nil {
		now = time.Now
	}
	return &Store{grants: make(map[string]Grant), ttl: ttl, now: now}
}

// Mint issues a token for one cluster/incident, limited to allowedTools.
// Returns the opaque token string; the caller passes it to the runner and is
// responsible for calling Revoke when the investigation ends.
func (s *Store) Mint(clusterID, incidentID string, allowedTools []string) (string, error) {
	if clusterID == "" {
		return "", fmt.Errorf("mcp: refusing to mint a token with no cluster scope")
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("mcp: generate token: %w", err)
	}
	token := base64.RawURLEncoding.EncodeToString(raw)

	allowed := make(map[string]struct{}, len(allowedTools))
	for _, name := range allowedTools {
		allowed[name] = struct{}{}
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	// Opportunistic sweep on write rather than a background goroutine: mints
	// are rare (one per investigation) and this keeps the map from growing
	// without adding another lifecycle to manage.
	s.evictExpiredLocked()
	s.grants[token] = Grant{
		ClusterID:    clusterID,
		IncidentID:   incidentID,
		AllowedTools: allowed,
		ExpiresAt:    s.now().Add(s.ttl),
	}
	return token, nil
}

// Lookup resolves a presented token to its Grant. The second return is false
// for an unknown, expired, or empty token — callers must not distinguish
// those cases to the client, since telling an attacker "that token existed
// but expired" is free information.
//
// Comparison is constant-time (SR-19) against each candidate rather than a
// plain map hit on the secret: a direct map lookup on attacker-supplied bytes
// is not itself timing-safe in the way SR-19 asks for, and the map is small
// enough (one entry per in-flight investigation) that a linear scan costs
// nothing measurable.
func (s *Store) Lookup(token string) (Grant, bool) {
	if token == "" {
		return Grant{}, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	for candidate, grant := range s.grants {
		if subtle.ConstantTimeCompare([]byte(candidate), []byte(token)) != 1 {
			continue
		}
		if now.After(grant.ExpiresAt) {
			delete(s.grants, candidate)
			return Grant{}, false
		}
		return grant, true
	}
	return Grant{}, false
}

// Revoke invalidates a token immediately. Safe to call with an unknown or
// already-revoked token, so callers can defer it unconditionally.
func (s *Store) Revoke(token string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.grants, token)
}

// Allows reports whether this grant permits calling the named tool.
func (g Grant) Allows(tool string) bool {
	_, ok := g.AllowedTools[tool]
	return ok
}

func (s *Store) evictExpiredLocked() {
	now := s.now()
	for token, grant := range s.grants {
		if now.After(grant.ExpiresAt) {
			delete(s.grants, token)
		}
	}
}
