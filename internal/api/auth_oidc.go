package api

// Federated login: GET /api/v1/auth/sso/providers, /auth/sso/start,
// /auth/sso/callback, and POST /auth/sso/exchange (PROJECT.md S2).
//
// All four are UNAUTHENTICATED by necessity — they are how somebody becomes
// authenticated — so every one of them resolves its tenant from
// data.SingleOrganisationID and never from anything in the request. That is
// convention 4's "resolve (actor, capability, scope) from authenticated
// context, never from client-supplied IDs" applied to the one case where there
// is no authenticated context yet: the answer is a server-side constant, not
// a parameter.
//
// # The shape of the flow, and why it has four endpoints
//
//	GET  /auth/sso/providers  -> what buttons the login screen should render
//	GET  /auth/sso/start      -> 302 to the IdP, with state/nonce/PKCE recorded
//	GET  /auth/sso/callback   -> IdP returns here; 302 to the SPA with a handoff code
//	POST /auth/sso/exchange   -> SPA trades the handoff code for real tokens
//
// The last two are separate because the callback's response is a redirect and
// this application authenticates with bearer tokens held in JavaScript. See
// authz.SSOHandoffIssuer for why a handoff code rather than a URL fragment or
// a cookie.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	"github.com/jackc/pgx/v5"

	"argus/internal/audit"
	"argus/internal/authz"
	"argus/internal/buildinfo"
	"argus/internal/data"
	"argus/internal/domain"
	"argus/internal/idp"
	"argus/internal/logging"
	"argus/internal/secretbox"
	"argus/internal/settings"
)

// loginCapability is what an authentication event is recorded against.
//
// A package-level var rather than an inline literal because audit.Event takes
// a *string, and taking the address of a constant is not legal Go. Shared with
// nothing else on purpose: it names the act of signing in, not a capability
// anything is gated on.
var loginCapability = "auth:login"

// ssoProvider is one login button.
type ssoProvider struct {
	ID          string `json:"id"`
	DisplayName string `json:"displayName"`
}

type ssoProvidersResponse struct {
	Providers []ssoProvider `json:"providers"`
	// LocalLoginAvailable tells the login screen whether to render the
	// password form at all. It stays true whenever any local account could
	// still sign in — see localLoginAllowedFor — because a screen that hides
	// the password box when break-glass is still possible would lock an
	// operator out of their own hub during exactly the incident where they
	// need in.
	LocalLoginAvailable bool `json:"localLoginAvailable"`
	// LoginStyle is which sign-in layout to render, chosen in Settings
	// (org_settings.login_style, migration 000105).
	//
	// It rides on this endpoint rather than getting its own because this is
	// already the one unauthenticated call the login screen makes, and a second
	// round trip would mean the page either renders the default style first and
	// then reflows, or blocks on two requests before showing a password field.
	// The endpoint's NAME is now narrower than what it returns — it is really
	// "everything the sign-in screen needs before anyone is authenticated" —
	// which is worth the trade rather than renaming a route that
	// scripts/smoke-test.sh and every deployed agent-side tool already knows.
	//
	// WHAT MAY BE ADDED HERE IS LIMITED, and this is the line to hold: anyone
	// on the network can read this response without credentials. A style
	// identifier from a closed set of four is safe. An install name, a
	// hostname, a cluster count or a custom message is not — that is fleet
	// information, and the sign-in screen is exactly where it must not appear.
	LoginStyle string `json:"loginStyle"`
	// Version is this hub build's version, printed in the sign-in screens'
	// footers. The supplied designs hardcoded "v2.4.1"; a version on a login
	// page is either the real one or it should not be there.
	//
	// Safe to serve unauthenticated on the same reasoning as LoginStyle: it is
	// a build identifier, not fleet information. It is also already inferable
	// from the served asset hashes, so withholding it buys nothing.
	Version string `json:"version"`
}

// handleSSOProviders lists the enabled providers for the login screen.
//
// Deliberately returns nothing that is not already public: an opaque id and a
// display name. Not the issuer, not the client id — neither is secret, but a
// pre-authentication endpoint should publish the minimum that makes the screen
// work.
func (s *Server) handleSSOProviders(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	tx, err := s.db.Pool.Begin(ctx)
	if err != nil {
		logger.ErrorContext(ctx, "beginning the provider-list transaction failed", logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not start transaction", "")
		return
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	tenantID, err := data.SingleOrganisationID(ctx, tx)
	if err != nil {
		logger.ErrorContext(ctx, "resolving the organisation for the provider list failed", logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not resolve organisation", "")
		return
	}
	if err := data.SetRequestScope(ctx, tx, tenantID, nil); err != nil {
		logger.ErrorContext(ctx, "setting the request scope for the provider list failed", logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not set request scope", "")
		return
	}

	rows, err := s.idpStore.EnabledProviders(ctx, tx, tenantID)
	if err != nil {
		logger.ErrorContext(ctx, "listing the identity providers failed", logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not list identity providers", "")
		return
	}

	// settings.Resolve normalises this: an unset or unrecognised column resolves
	// to settings.DefaultLoginStyle, so the login screen always receives one of
	// the four known values and never has to decide what to do with a surprise.
	loginStyle := settings.DefaultLoginStyle
	if cfg, err := settings.Resolve(ctx, tx); err != nil {
		// Deliberately not fatal. A sign-in screen that will not render because
		// a branding lookup failed is a worse outage than one rendering the
		// default style, and this is the screen an operator needs during an
		// outage. Same argument the provider list above degrades on.
		logger.ErrorContext(ctx, "loading the settings for the login style failed; serving the fallback",
			slog.String("login_style", loginStyle), logging.Err(err))
	} else {
		loginStyle = cfg.LoginStyle
	}

	resp := ssoProvidersResponse{
		Providers:  make([]ssoProvider, 0, len(rows)),
		LoginStyle: loginStyle,
		Version:    buildinfo.Version(),
		// Always true: break-glass local login survives SSO being enabled, so
		// the form is always offered. handleLogin is what actually enforces
		// who may use it — a hidden control is not authorization
		// (non-negotiable 4).
		LocalLoginAvailable: true,
	}
	for _, p := range rows {
		resp.Providers = append(resp.Providers, ssoProvider{ID: p.ID, DisplayName: p.DisplayName})
	}
	writeJSON(w, http.StatusOK, resp)
}

// handleSSOStart begins an authorization-code flow and redirects to the IdP.
func (s *Server) handleSSOStart(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	providerID := r.URL.Query().Get("provider")
	if providerID == "" {
		writeProblem(w, http.StatusBadRequest, "https://argus.io/errors/invalid-request", "A provider id is required", "")
		return
	}

	tx, err := s.db.Pool.Begin(ctx)
	if err != nil {
		logger.ErrorContext(ctx, "beginning the SSO login-start transaction failed", logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not start transaction", "")
		return
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	tenantID, err := data.SingleOrganisationID(ctx, tx)
	if err != nil {
		logger.ErrorContext(ctx, "resolving the organisation for an SSO login start failed", logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not resolve organisation", "")
		return
	}
	if err := data.SetRequestScope(ctx, tx, tenantID, nil); err != nil {
		logger.ErrorContext(ctx, "setting the request scope for an SSO login start failed", logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not set request scope", "")
		return
	}

	provider, cfg, err := s.oidcProvider(ctx, tx, tenantID, providerID)
	if err != nil {
		// The real error names the issuer and often quotes the IdP; the
		// caller gets none of it (convention 7).
		logger.ErrorContext(ctx, "the identity provider named in the start request is unusable",
			slog.String("provider_id", providerID), logging.Err(err))
		writeProblem(w, http.StatusBadRequest, "https://argus.io/errors/invalid-request",
			"That identity provider is not available", "")
		return
	}
	defer secretbox.Zero([]byte(cfg.ClientSecret))

	ls, err := provider.BeginLogin()
	if err != nil {
		logger.ErrorContext(ctx, "beginning the SSO login failed", logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not start login", "")
		return
	}
	if err := s.idpStore.SaveLoginState(ctx, tx, tenantID, providerID, ls, r.URL.Query().Get("returnTo")); err != nil {
		logger.ErrorContext(ctx, "saving the SSO login state failed", logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not start login", "")
		return
	}
	if err := tx.Commit(ctx); err != nil {
		logger.ErrorContext(ctx, "committing an SSO login start failed", logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not start login", "")
		return
	}

	// The state row must be committed before the browser can come back with
	// it, which is why the commit is here and not after the redirect is
	// written.
	http.Redirect(w, r, ls.AuthURL, http.StatusFound)
}

// handleSSOCallback completes the flow: verify, provision, sync grants, and
// hand the SPA a single-use code.
//
// Every failure below redirects to the login screen with a generic reason
// rather than rendering an error, because this endpoint is reached by a
// browser navigation and a raw problem document is a dead end for a person.
// The specific cause is always logged.
func (s *Server) handleSSOCallback(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	q := r.URL.Query()

	// An IdP-reported error (consent denied, for instance) arrives as
	// ?error=... with no code. Not a failure of ours, and not worth an
	// alarming message.
	if e := q.Get("error"); e != "" {
		logger.WarnContext(ctx, "the identity provider returned an error at the callback",
			slog.String("provider_error", e), slog.String("provider_error_description", q.Get("error_description")))
		redirectToLogin(w, r, "sso_declined")
		return
	}
	code, state := q.Get("code"), q.Get("state")
	if code == "" || state == "" {
		redirectToLogin(w, r, "sso_failed")
		return
	}

	tx, err := s.db.Pool.Begin(ctx)
	if err != nil {
		logger.ErrorContext(ctx, "beginning the SSO callback transaction failed", logging.Err(err))
		redirectToLogin(w, r, "sso_failed")
		return
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	tenantID, err := data.SingleOrganisationID(ctx, tx)
	if err != nil {
		logger.ErrorContext(ctx, "resolving the organisation for an SSO callback failed", logging.Err(err))
		redirectToLogin(w, r, "sso_failed")
		return
	}
	if err := data.SetRequestScope(ctx, tx, tenantID, nil); err != nil {
		logger.ErrorContext(ctx, "setting the request scope for an SSO callback failed", logging.Err(err))
		redirectToLogin(w, r, "sso_failed")
		return
	}

	// Consuming the state proves this callback belongs to a login THIS hub
	// started, and does so exactly once.
	pending, err := s.idpStore.ConsumeLoginState(ctx, tx, tenantID, state)
	if err != nil {
		if errors.Is(err, idp.ErrNoSuchState) {
			logger.WarnContext(ctx, "unknown or expired SSO state presented at the callback", slog.String("source_ip", clientIP(r)))
			redirectToLogin(w, r, "sso_expired")
			return
		}
		logger.ErrorContext(ctx, "consuming the SSO login state failed", logging.Err(err))
		redirectToLogin(w, r, "sso_failed")
		return
	}

	provider, cfg, err := s.oidcProvider(ctx, tx, tenantID, pending.ProviderID)
	if err != nil {
		logger.ErrorContext(ctx, "the identity provider named in the callback is unusable",
			slog.String("provider_id", pending.ProviderID), logging.Err(err))
		redirectToLogin(w, r, "sso_failed")
		return
	}
	defer secretbox.Zero([]byte(cfg.ClientSecret))

	identity, err := provider.CompleteLogin(ctx, code, pending.Nonce, pending.Verifier)
	if err != nil {
		// Covers a bad signature, a wrong audience, an expired token, a
		// mismatched nonce and a failed code exchange. All are "this login
		// is not trustworthy" and none is worth distinguishing to a caller.
		logger.WarnContext(ctx, "SSO login verification failed", logging.Err(err))
		redirectToLogin(w, r, "sso_failed")
		return
	}

	userID, err := s.provisionFederatedUser(ctx, tx, tenantID, pending.ProviderID, identity)
	if err != nil {
		logger.ErrorContext(ctx, "provisioning the SSO identity failed",
			slog.String("issuer", identity.Issuer), slog.String("subject", identity.Subject), logging.Err(err))
		redirectToLogin(w, r, "sso_failed")
		return
	}

	if err := audit.RecordEvent(ctx, tx, audit.Event{
		TenantID:        tenantID,
		ActorID:         &userID,
		ActorAuthMethod: "oidc",
		SourceIP:        clientIP(r),
		Capability:      &loginCapability,
		Outcome:         audit.OutcomeSuccess,
		Details: map[string]any{
			"provider_id": pending.ProviderID,
			"issuer":      identity.Issuer,
			// The subject is the durable identifier and belongs in the audit
			// trail; the groups claim does too, because it is what decided
			// this person's authorisation and a later "why did they have that
			// role" question cannot be answered without it.
			"subject": identity.Subject,
			"groups":  identity.Groups,
		},
	}); err != nil {
		logger.ErrorContext(ctx, "recording an SSO sign-in in the audit log failed", logging.Err(err))
		redirectToLogin(w, r, "sso_failed")
		return
	}

	if err := tx.Commit(ctx); err != nil {
		logger.ErrorContext(ctx, "committing an SSO sign-in failed", logging.Err(err))
		redirectToLogin(w, r, "sso_failed")
		return
	}

	handoff, _, err := s.ssoHandoff.Issue(userID, tenantID)
	if err != nil {
		logger.ErrorContext(ctx, "issuing the SSO handoff token failed", logging.Err(err))
		redirectToLogin(w, r, "sso_failed")
		return
	}

	// The handoff code is issued only AFTER the commit: a code that resolves
	// to a user whose provisioning was rolled back would be a session for an
	// account that does not exist.
	dest := fmt.Sprintf("/auth/sso/complete?code=%s&returnTo=%s",
		url.QueryEscape(handoff), url.QueryEscape(idp.SafeReturnTo(pending.ReturnTo)))
	http.Redirect(w, r, dest, http.StatusFound)
}

type ssoExchangeRequest struct {
	Code string `json:"code"`
}

// handleSSOExchange trades a single-use handoff code for a real token pair.
//
// This is where a federated session is actually minted, and it deliberately
// mints exactly the same thing handleLogin does — same access token, same
// refresh token, same TTL — so that every downstream route, sweeper and
// capability check is identical for a federated and a local user. A separate
// "SSO session" concept would be a second authorization path to keep correct.
func (s *Server) handleSSOExchange(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var req ssoExchangeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeProblem(w, http.StatusBadRequest, "https://argus.io/errors/malformed-request", "Malformed request body", "")
		return
	}

	userID, tenantID, ok := s.ssoHandoff.Redeem(req.Code)
	if !ok {
		// Single-use and 15 seconds. A replayed or stale code lands here.
		writeProblem(w, http.StatusUnauthorized, "https://argus.io/errors/unauthenticated",
			"That sign-in link has already been used or has expired", "")
		return
	}

	tx, err := s.db.Pool.Begin(ctx)
	if err != nil {
		logger.ErrorContext(ctx, "beginning the SSO exchange transaction failed", logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not start transaction", "")
		return
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	if err := data.SetRequestScope(ctx, tx, tenantID, nil); err != nil {
		logger.ErrorContext(ctx, "setting the request scope for an SSO exchange failed", logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not set request scope", "")
		return
	}

	// Re-checked at exchange time rather than trusted from the handoff: the
	// window is short, but an account disabled between callback and exchange
	// must not get a session.
	// disabled_at and token_generation come from one SELECT inside the scoped
	// transaction, the same way handleLogin reads them, rather than via
	// authz.CurrentTokenGeneration — that helper takes a *pgxpool.Pool and so
	// would run OUTSIDE this transaction's request scope, which is the shape
	// of the RLS bugs this codebase has already shipped three times in auth
	// code.
	var (
		disabledAt *string
		generation int64
	)
	if err := tx.QueryRow(ctx,
		`SELECT disabled_at::text, token_generation FROM users WHERE tenant_id = $1 AND id = $2`,
		tenantID, userID).Scan(&disabledAt, &generation); err != nil {
		logger.ErrorContext(ctx, "reloading the user during an SSO exchange failed", logging.ActorID(userID), logging.Err(err))
		writeProblem(w, http.StatusUnauthorized, "https://argus.io/errors/unauthenticated", "Could not complete sign-in", "")
		return
	}
	if disabledAt != nil {
		logger.WarnContext(ctx, "refusing an SSO handoff exchange: the user is disabled", logging.ActorID(userID))
		writeProblem(w, http.StatusForbidden, "https://argus.io/errors/forbidden", "This account is disabled", "")
		return
	}
	accessToken, err := s.signer.IssueAccessToken(userID, generation)
	if err != nil {
		logger.ErrorContext(ctx, "issuing an access token after an SSO exchange failed", logging.ActorID(userID), logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not complete sign-in", "")
		return
	}
	refreshToken, err := authz.IssueRefreshToken(ctx, tx, tenantID, userID)
	if err != nil {
		logger.ErrorContext(ctx, "issuing a refresh token after an SSO exchange failed", logging.ActorID(userID), logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not complete sign-in", "")
		return
	}
	if err := tx.Commit(ctx); err != nil {
		logger.ErrorContext(ctx, "committing an SSO handoff exchange failed", logging.ActorID(userID), logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not complete sign-in", "")
		return
	}

	// The refresh token travels ONLY as the cookie, same as every other
	// sign-in path — see internal/api/auth.go's setRefreshCookie doc comment
	// (PROJECT.md B164).
	setRefreshCookie(w, r, refreshToken)
	writeJSON(w, http.StatusOK, loginResponse{
		AccessToken: accessToken,
		ExpiresIn:   int(authz.AccessTokenTTL.Seconds()),
		// Always false for a federated user: there is no local password to
		// change, and the users table's CHECK constraint enforces that.
		MustChangePassword: false,
	})
}

// provisionFederatedUser finds or creates the local user row for a verified
// federated identity, then re-syncs its IdP-derived grants.
//
// Matching is on (idp_issuer, idp_subject) and NEVER on email. OIDC does not
// guarantee email stability, and an IdP that reassigns an address would
// otherwise hand one person another person's grants.
func (s *Server) provisionFederatedUser(ctx context.Context, tx pgx.Tx, tenantID, providerID string, id idp.Identity) (string, error) {
	var userID string
	err := tx.QueryRow(ctx,
		`SELECT id FROM users WHERE tenant_id = $1 AND idp_issuer = $2 AND idp_subject = $3`,
		tenantID, id.Issuer, id.Subject).Scan(&userID)

	switch {
	case err == nil:
		// Keep the display fields current: a person who changes their name or
		// address at the IdP should not have to be re-created here.
		if _, err := tx.Exec(ctx,
			`UPDATE users SET email = $3, display_name = $4 WHERE tenant_id = $1 AND id = $2`,
			tenantID, userID, federatedEmail(id), id.DisplayName); err != nil {
			return "", fmt.Errorf("refresh federated user: %w", err)
		}
	case errors.Is(err, pgx.ErrNoRows):
		// A local account already using this email is a real collision an
		// operator has to resolve, not something to paper over by linking:
		// silently attaching a federated identity to an existing local
		// account would let whoever controls that address at the IdP inherit
		// its grants.
		var clash bool
		if err := tx.QueryRow(ctx,
			`SELECT EXISTS(SELECT 1 FROM users
			   WHERE tenant_id = $1 AND lower(email) = lower($2) AND idp_subject IS NULL)`,
			tenantID, federatedEmail(id)).Scan(&clash); err != nil {
			return "", fmt.Errorf("check for local account collision: %w", err)
		}
		if clash {
			return "", fmt.Errorf("a local account already uses %s; remove or rename it before federating that address", federatedEmail(id))
		}

		userID = domain.NewID(domain.PrefixUser)
		if _, err := tx.Exec(ctx,
			`INSERT INTO users (id, tenant_id, email, display_name, idp_issuer, idp_subject)
			 VALUES ($1, $2, $3, $4, $5, $6)`,
			userID, tenantID, federatedEmail(id), id.DisplayName, id.Issuer, id.Subject); err != nil {
			return "", fmt.Errorf("create federated user: %w", err)
		}
	default:
		return "", fmt.Errorf("look up federated user: %w", err)
	}

	if err := s.syncFederatedGrants(ctx, tx, tenantID, providerID, userID, id.Groups); err != nil {
		return "", err
	}
	return userID, nil
}

// syncFederatedGrants makes this user's idp_sync grants exactly match what
// their current group membership maps to.
//
// Re-synced on EVERY login, and scoped strictly to source='idp_sync' rows.
// Both halves matter:
//
//   - Re-syncing every login is what makes removing somebody from a directory
//     group actually remove their access here, rather than leaving a grant
//     that outlives their membership. Offboarding in the IdP is the whole
//     reason to map groups.
//   - Touching only source='idp_sync' is what keeps a manually-granted role
//     (source='manual') from being revoked by an IdP that has never heard of
//     it. The grants table has carried that column since migration 000001
//     with exactly these two values, so this distinction is the schema's own
//     design rather than something invented here.
func (s *Server) syncFederatedGrants(ctx context.Context, tx pgx.Tx, tenantID, providerID, userID string, groups []string) error {
	mappings, err := s.idpStore.GroupMappings(ctx, tx, tenantID, providerID)
	if err != nil {
		return err
	}

	inGroup := make(map[string]bool, len(groups))
	for _, g := range groups {
		inGroup[g] = true
	}

	// Revoke rather than delete: an audit trail that loses the fact somebody
	// once held a role is not an audit trail. revoked_at is what every other
	// grant read already filters on (activeGrantsWhere).
	if _, err := tx.Exec(ctx,
		`UPDATE grants SET revoked_at = now()
		  WHERE tenant_id = $1 AND principal_type = 'user' AND principal_id = $2
		    AND source = 'idp_sync' AND revoked_at IS NULL`,
		tenantID, userID); err != nil {
		return fmt.Errorf("revoke superseded idp grants: %w", err)
	}

	for _, m := range mappings {
		if !inGroup[m.GroupName] {
			continue
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO grants (id, tenant_id, principal_type, principal_id, role_id, scope, source, granted_by)
			 VALUES ($1, $2, 'user', $3, $4, $5, 'idp_sync', $6)`,
			domain.NewID(domain.PrefixGrant), tenantID, userID, m.RoleID, m.Scope,
			// granted_by names the mapping, not a person: no human granted
			// this, and recording an administrator's id here would misattribute
			// it. The mapping id is what an auditor needs to answer "why does
			// this person hold this role".
			"idp_mapping:"+m.ID); err != nil {
			return fmt.Errorf("apply idp grant for group %q: %w", m.GroupName, err)
		}
	}
	return nil
}

// federatedEmail is what goes in users.email for a federated account.
//
// Falls back to subject@issuer-host when the IdP sends no email claim, because
// the column is NOT NULL and is what the UI displays. A synthetic value is
// better than refusing the login: an IdP configured without the email scope is
// an operator's oversight, not a reason nobody can sign in.
func federatedEmail(id idp.Identity) string {
	if id.Email != "" {
		return id.Email
	}
	host := id.Issuer
	if i := strings.Index(host, "://"); i >= 0 {
		host = host[i+3:]
	}
	host = strings.TrimSuffix(strings.SplitN(host, "/", 2)[0], ":")
	return id.Subject + "@" + host
}

// oidcProvider resolves a provider id to a discovered, ready-to-use Provider.
//
// Discovery results are cached per (provider id, issuer, client id): a cold
// Provider means a discovery round trip and a cold JWKS cache on every login,
// and the cache key includes the fields that would invalidate it so an
// operator editing the issuer does not keep authenticating against the old
// one.
//
// The returned Config carries the decrypted client secret; the caller zeroes
// it.
func (s *Server) oidcProvider(ctx context.Context, tx pgx.Tx, tenantID, providerID string) (*idp.Provider, idp.Config, error) {
	cfg, err := s.idpStore.LoadConfig(ctx, tx, tenantID, providerID)
	if err != nil {
		return nil, idp.Config{}, err
	}

	key := providerID + "\x00" + cfg.Issuer + "\x00" + cfg.ClientID
	s.oidcMu.Lock()
	cached, ok := s.oidcCache[key]
	s.oidcMu.Unlock()
	if ok {
		return cached, cfg, nil
	}

	provider, err := idp.Discover(ctx, cfg)
	if err != nil {
		return nil, idp.Config{}, err
	}
	s.oidcMu.Lock()
	if s.oidcCache == nil {
		s.oidcCache = make(map[string]*idp.Provider)
	}
	s.oidcCache[key] = provider
	s.oidcMu.Unlock()
	return provider, cfg, nil
}

// invalidateOIDCCache drops cached discovery for a provider, so a settings
// change takes effect on the next login rather than after a hub restart.
func (s *Server) invalidateOIDCCache(providerID string) {
	s.oidcMu.Lock()
	defer s.oidcMu.Unlock()
	for k := range s.oidcCache {
		if strings.HasPrefix(k, providerID+"\x00") {
			delete(s.oidcCache, k)
		}
	}
}

// localLoginAllowedFor decides whether a user may authenticate with a
// password.
//
// The rule, and the owner decision behind it (PROJECT.md S2, 2026-09-09):
// local password login survives SSO being turned on, but ONLY as a break-glass
// path for an account that holds super-admin. Everyone else must federate.
//
// # Why "holds super-admin" and not "is admin@localhost"
//
// The bootstrap account is created with a literal email
// (internal/authz/bootstrap.go), and keying break-glass off that string would
// break the moment somebody renamed it, and would silently GRANT break-glass
// to anyone who later took that address. Keying off the role instead means:
//
//   - Renaming or replacing the bootstrap account keeps working.
//   - An org that federates every super-admin gets local login closed
//     automatically, with no second switch to remember — the pure-SSO posture
//     falls out of the rule rather than needing to be configured.
//   - The set of accounts that can bypass the IdP is exactly the set that
//     could disable the IdP anyway, so break-glass grants no authority its
//     holder did not already have.
//
// # Why not close local login entirely
//
// It was offered and declined. An IdP outage, an expired signing certificate
// or a mistyped issuer would otherwise lock every operator out of the hub —
// during precisely the incident they need it for. Break-glass is the standard
// answer for self-hosted software and it is what an operator would expect.
//
// A federated user is refused unconditionally regardless of role: their row
// has no password_hash (the users table's CHECK enforces that), so they cannot
// reach here with a valid password anyway. Returning false is belt and braces.
func (s *Server) localLoginAllowedFor(ctx context.Context, tx pgx.Tx, tenantID, userID string) (bool, error) {
	var anyEnabled bool
	if err := tx.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM identity_providers WHERE tenant_id = $1 AND enabled)`,
		tenantID).Scan(&anyEnabled); err != nil {
		return false, fmt.Errorf("check for enabled identity providers: %w", err)
	}
	if !anyEnabled {
		// No SSO configured: nothing has changed for anyone.
		return true, nil
	}

	var isSuperAdmin bool
	if err := tx.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM grants
		   WHERE tenant_id = $1 AND principal_type = 'user' AND principal_id = $2
		     AND role_id = 'super-admin' AND `+activeGrantsWhere+`)`,
		tenantID, userID).Scan(&isSuperAdmin); err != nil {
		return false, fmt.Errorf("check super-admin grant: %w", err)
	}
	return isSuperAdmin, nil
}

// redirectToLogin sends a browser back to the login screen with a machine-
// readable reason the SPA turns into a message.
//
// A reason code rather than a message: the string is chosen by this server and
// rendered by the client, so nothing an IdP said can reach a page unescaped.
func redirectToLogin(w http.ResponseWriter, r *http.Request, reason string) {
	http.Redirect(w, r, "/login?ssoError="+url.QueryEscape(reason), http.StatusFound)
}
