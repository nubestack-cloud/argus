// Package idp is ARGUS's OIDC relying-party implementation: the code that
// turns "somebody came back from an identity provider with a code" into "this
// is a known person, and here is what they may do".
//
// # Why OIDC only
//
// ARGUS federates through exactly one protocol. Migration 000103's header has
// the full argument; the short version is that an OIDC relying party reaches
// every OIDC provider directly and reaches LDAP, Active Directory and SAML
// through a broker (Dex, which lld/01-threat-model.md's asset table already
// assumed), whereas a provider catalogue is an enumeration that grows one
// entry per vendor and would have to be maintained forever.
//
// # What is deliberately delegated
//
// Discovery, JWKS fetching and rotation, and ID-token signature/claim
// verification are github.com/coreos/go-oidc's job, not this package's.
// Hand-rolling ID-token verification is a well-known way to ship an
// authentication bypass -- the failure modes (accepting `alg: none`, not
// checking `aud`, not re-fetching a rotated signing key, comparing `iss` with
// a prefix match) are subtle and have all appeared in real products. This
// package supplies configuration and consumes a verified token; it never
// parses a JWT itself.
//
// # What this package does own
//
//   - Building the authorization URL with state, nonce and PKCE.
//   - Deciding which claim carries identity: (issuer, subject), never email.
//   - Extracting groups from a configurable claim, tolerating the several
//     shapes real providers emit.
//
// Everything about sessions, users, grants and the database lives in
// internal/api -- this package has no database handle on purpose, so it can be
// tested without one.
package idp

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"argus/internal/outbound"
)

// StateTTL bounds how long an in-flight login may take: the window between
// ARGUS redirecting to the IdP and the browser coming back with a code.
//
// Ten minutes rather than something tighter because a first-time login can
// legitimately include entering a password, satisfying an MFA prompt, and
// approving a consent screen -- and rather than something looser because the
// state row is what binds the callback to the request that started it, so its
// lifetime is the window in which a stolen state value is worth anything.
const StateTTL = 10 * time.Minute

// Config is one configured provider, as stored in identity_providers.
//
// ClientSecret is the decrypted value and is expected to be zeroed by the
// caller once a Provider has been built from it; see internal/secretbox.Zero.
type Config struct {
	ID           string
	DisplayName  string
	Issuer       string
	ClientID     string
	ClientSecret string
	Scopes       []string
	GroupsClaim  string
	RedirectURI  string
}

// Provider is a Config with live discovery results attached: the IdP's
// endpoints and its verified signing keys.
//
// Construct one with Discover. A Provider holds a JWKS cache internally
// (go-oidc's KeySet), so it is worth keeping rather than rebuilding per
// request -- rebuilding means a fresh discovery round trip and a cold key
// cache on every login.
type Provider struct {
	cfg      Config
	provider *oidc.Provider
	verifier *oidc.IDTokenVerifier
	oauth    *oauth2.Config
	// client is the hardened transport discovery was performed with. Kept
	// so CompleteLogin can inject it back into the context for the token
	// exchange and userinfo/JWKS calls, which otherwise use whatever
	// *http.Client the caller's own ctx carries (or none) rather than the
	// one that validated the issuer at Discover time.
	client *http.Client
}

// Discover performs OIDC discovery against cfg.Issuer and returns a Provider
// ready to start and complete logins.
//
// go-oidc verifies that the discovery document's own `issuer` field equals
// cfg.Issuer exactly. That check is the reason an attacker who can make ARGUS
// fetch a document of their choosing still cannot impersonate the real IdP,
// and it is why the issuer is stored as configuration rather than derived from
// anything in a request.
//
// # Outbound hardening (lld/01-threat-model.md T15)
//
// cfg.Issuer is admin-configured, so this is the same class of gap a
// notification webhook or a repository BaseURL is: a compromised admin
// session or a tampered config value could point it at cloud metadata or
// an internal-only endpoint. Unlike those two callers, though, a
// self-hosted broker (Dex, most commonly) legitimately runs on localhost
// or a private address, so — like internal/knowledge's Ollama client —
// this caller's Policy allows private/loopback destinations by default.
// Cloud metadata is still refused unconditionally regardless
// (internal/outbound's one absolute). The client built here is injected
// into ctx via oidc.ClientContext, which go-oidc documents as sharing the
// same context key golang.org/x/oauth2 reads — so it also covers the
// discovered JWKS endpoint (cached on the returned *oidc.Provider) without
// a second wiring point.
func Discover(ctx context.Context, cfg Config) (*Provider, error) {
	if cfg.Issuer == "" || cfg.ClientID == "" || cfg.RedirectURI == "" {
		return nil, fmt.Errorf("idp: issuer, client_id and redirect_uri are all required")
	}
	client := outbound.NewClient(outbound.Policy{
		AllowPrivate: true,
		Reason:       "self-hosted OIDC broker (e.g. Dex) commonly runs on localhost or a private address",
	}, 15*time.Second)
	ctx = oidc.ClientContext(ctx, client)
	p, err := oidc.NewProvider(ctx, cfg.Issuer)
	if err != nil {
		// Wrapped without the issuer's response body: a discovery failure
		// often echoes the remote server's error page, and this string reaches
		// an operator-facing configuration test.
		return nil, fmt.Errorf("idp: discovery against %s failed: %w", cfg.Issuer, err)
	}

	// "openid" is mandatory per the spec and is added regardless of what was
	// configured, so a provider row that omitted it still works rather than
	// failing with an opaque IdP error.
	scopes := []string{oidc.ScopeOpenID}
	for _, s := range cfg.Scopes {
		if s != oidc.ScopeOpenID && s != "" {
			scopes = append(scopes, s)
		}
	}

	return &Provider{
		cfg:      cfg,
		provider: p,
		// ClientID here is what makes the verifier check the `aud` claim. An
		// ID token minted for a DIFFERENT client of the same IdP is a valid
		// token that must not be accepted here, and this is the check that
		// rejects it.
		verifier: p.Verifier(&oidc.Config{ClientID: cfg.ClientID}),
		oauth: &oauth2.Config{
			ClientID:     cfg.ClientID,
			ClientSecret: cfg.ClientSecret,
			Endpoint:     p.Endpoint(),
			RedirectURL:  cfg.RedirectURI,
			Scopes:       scopes,
		},
		client: client,
	}, nil
}

// Config returns the configuration this Provider was built from, minus the
// secret. Used for rendering the login button and for diagnostics.
func (p *Provider) Config() Config {
	c := p.cfg
	c.ClientSecret = ""
	return c
}

// LoginStart is everything a caller must persist before redirecting a browser
// to the IdP, plus the URL to redirect it to.
//
// State and Nonce are returned in plaintext because the caller has to store a
// hash of each; Verifier is returned in plaintext because PKCE requires
// replaying it verbatim at the token endpoint and it therefore cannot be
// stored hashed.
type LoginStart struct {
	AuthURL  string
	State    string
	Nonce    string
	Verifier string
}

// BeginLogin mints the three single-use secrets an authorization-code flow
// needs and builds the authorization URL.
//
// The three do different jobs and none substitutes for another:
//
//   - state binds the callback to the browser that started the login. Without
//     it, an attacker can complete a login in a victim's browser with their
//     own code (login CSRF).
//   - nonce binds the ID TOKEN to this login. Without it, a token obtained
//     elsewhere can be replayed here.
//   - the PKCE verifier binds the code exchange to whoever started the flow.
//     For a confidential client the secret already does that, so this is
//     defence in depth -- kept because it costs nothing and covers the case
//     where the secret leaks.
func (p *Provider) BeginLogin() (LoginStart, error) {
	state, err := randomToken()
	if err != nil {
		return LoginStart{}, fmt.Errorf("idp: generate state: %w", err)
	}
	nonce, err := randomToken()
	if err != nil {
		return LoginStart{}, fmt.Errorf("idp: generate nonce: %w", err)
	}
	verifier := oauth2.GenerateVerifier()

	return LoginStart{
		AuthURL: p.oauth.AuthCodeURL(state,
			oidc.Nonce(nonce),
			oauth2.S256ChallengeOption(verifier),
		),
		State:    state,
		Nonce:    nonce,
		Verifier: verifier,
	}, nil
}

// Identity is a verified federated identity: who the IdP says this is, and
// which groups it says they are in.
type Identity struct {
	// Issuer and Subject together are the ONLY stable identifier OIDC
	// guarantees. Email is explicitly not stable -- providers reassign
	// addresses -- so it is carried for display and never used to match an
	// existing account.
	Issuer  string
	Subject string

	Email         string
	EmailVerified bool
	DisplayName   string
	Groups        []string
}

// CompleteLogin exchanges an authorization code for tokens, verifies the ID
// token, and extracts the identity.
//
// nonce must be the plaintext nonce from the login this callback belongs to;
// verifier the PKCE verifier from the same. A mismatch on either fails here
// rather than returning a partly-trusted result.
func (p *Provider) CompleteLogin(ctx context.Context, code, nonce, verifier string) (Identity, error) {
	// The caller's ctx (an HTTP request context) carries no HTTP client of
	// its own, so without this the token-endpoint exchange and any
	// userinfo/JWKS refetch during Verify would use go-oidc/oauth2's plain
	// http.DefaultClient — unvalidated, unlike the client Discover
	// hardened this Provider with. See Discover's doc comment.
	ctx = oidc.ClientContext(ctx, p.client)
	tok, err := p.oauth.Exchange(ctx, code, oauth2.VerifierOption(verifier))
	if err != nil {
		return Identity{}, fmt.Errorf("idp: code exchange failed: %w", err)
	}

	rawID, ok := tok.Extra("id_token").(string)
	if !ok || rawID == "" {
		// An access token without an ID token means this is an OAuth2
		// provider, not an OIDC one. Refusing is correct: an access token
		// says what the bearer may do at the IdP, not who they are, and
		// treating one as an identity assertion is a known confusion.
		return Identity{}, fmt.Errorf("idp: provider returned no id_token — is %s an OIDC provider?", p.cfg.Issuer)
	}

	// Signature, issuer, audience and expiry are all checked here.
	idToken, err := p.verifier.Verify(ctx, rawID)
	if err != nil {
		return Identity{}, fmt.Errorf("idp: id_token verification failed: %w", err)
	}

	// Replay protection. Constant-time is not required -- the nonce is not a
	// long-lived secret and both values are already known to this process --
	// but the comparison must happen, and it must happen after signature
	// verification so an unsigned token cannot choose its own nonce.
	if idToken.Nonce != nonce {
		return Identity{}, fmt.Errorf("idp: id_token nonce does not match this login")
	}

	var claims struct {
		Email         string `json:"email"`
		EmailVerified *bool  `json:"email_verified"`
		Name          string `json:"name"`
		PreferredUser string `json:"preferred_username"`
	}
	if err := idToken.Claims(&claims); err != nil {
		return Identity{}, fmt.Errorf("idp: decode id_token claims: %w", err)
	}

	groups, err := extractGroups(idToken, p.cfg.GroupsClaim)
	if err != nil {
		return Identity{}, err
	}

	id := Identity{
		Issuer:        idToken.Issuer,
		Subject:       idToken.Subject,
		Email:         strings.TrimSpace(claims.Email),
		EmailVerified: claims.EmailVerified == nil || *claims.EmailVerified,
		DisplayName:   firstNonEmpty(claims.Name, claims.PreferredUser, claims.Email, idToken.Subject),
		Groups:        groups,
	}
	if id.Subject == "" {
		return Identity{}, fmt.Errorf("idp: id_token carries no subject claim")
	}
	return id, nil
}

// extractGroups reads the configured groups claim, accepting the shapes real
// providers actually emit.
//
// There is no single convention here, which is why the claim NAME is
// configurable and its SHAPE is tolerated rather than assumed:
//
//   - Dex and Keycloak emit a JSON array of strings.
//   - Some SAML-to-OIDC bridges emit a single string when there is exactly
//     one group, and an array when there are several.
//   - A few emit a space- or comma-delimited string.
//
// An absent claim is NOT an error: it means "this IdP told us nothing about
// groups", which correctly results in no mapped grants rather than a failed
// login. A malformed claim IS an error, because silently treating it as "no
// groups" would turn an IdP misconfiguration into a silent
// loss-of-authorisation that looks like a permissions bug.
func extractGroups(idToken *oidc.IDToken, claimName string) ([]string, error) {
	if claimName == "" {
		return nil, nil
	}
	var all map[string]json.RawMessage
	if err := idToken.Claims(&all); err != nil {
		return nil, fmt.Errorf("idp: decode id_token claims: %w", err)
	}
	raw, ok := all[claimName]
	if !ok || len(raw) == 0 || string(raw) == "null" {
		return nil, nil
	}

	var asList []string
	if err := json.Unmarshal(raw, &asList); err == nil {
		return normaliseGroups(asList), nil
	}

	var asString string
	if err := json.Unmarshal(raw, &asString); err == nil {
		if strings.ContainsAny(asString, " ,") {
			return normaliseGroups(strings.FieldsFunc(asString, func(r rune) bool {
				return r == ' ' || r == ','
			})), nil
		}
		return normaliseGroups([]string{asString}), nil
	}

	return nil, fmt.Errorf("idp: groups claim %q is neither a string nor an array of strings", claimName)
}

// normaliseGroups trims surrounding whitespace and drops empties.
//
// It deliberately does NOT lowercase or otherwise canonicalise: an LDAP
// distinguished name arrives verbatim through Dex, and a group's identity is
// the IdP's business, not ARGUS's. Case-folding here would make two distinct
// directory groups collide.
func normaliseGroups(in []string) []string {
	out := make([]string, 0, len(in))
	seen := make(map[string]bool, len(in))
	for _, g := range in {
		g = strings.TrimSpace(g)
		if g == "" || seen[g] {
			continue
		}
		seen[g] = true
		out = append(out, g)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if s := strings.TrimSpace(v); s != "" {
			return s
		}
	}
	return ""
}

// HashState is how a state or nonce value is stored: SHA-256, hex-encoded.
//
// The plaintext only ever has to exist inside one request, so persisting a
// hash means a database read yields nothing usable.
func HashState(v string) string {
	sum := sha256.Sum256([]byte(v))
	return fmt.Sprintf("%x", sum)
}

// randomToken returns 32 bytes of crypto/rand as unpadded base64url — long
// enough that guessing is not a threat model, and URL-safe so it survives a
// query parameter unescaped.
func randomToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// SafeReturnTo bounds where a completed login may send the browser.
//
// Only a same-site absolute path is allowed. Anything else -- an absolute URL,
// a protocol-relative //host path, a path with a scheme -- collapses to "/".
// Without this the callback is an open redirect: an attacker sends someone a
// login link that lands them on a lookalike host, already authenticated, with
// ARGUS's own domain in the referrer chain.
func SafeReturnTo(v string) string {
	if v == "" {
		return "/"
	}
	// A leading "//" is protocol-relative and resolves to another host.
	if strings.HasPrefix(v, "//") || !strings.HasPrefix(v, "/") {
		return "/"
	}
	u, err := url.Parse(v)
	if err != nil || u.Scheme != "" || u.Host != "" {
		return "/"
	}
	return u.RequestURI()
}
