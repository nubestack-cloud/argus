package api

// Identity-provider administration (PROJECT.md S2), all gated on
// authz.CapIdentityManage — super-admin only.
//
// Every handler here takes rc *requestContext, so its transaction is already
// RLS-scoped by requireAuth and the tenant comes from the authenticated
// session rather than from the request (convention 4). Contrast auth_oidc.go,
// which cannot do that because it runs before anyone is authenticated.
//
// # The one rule worth stating up front
//
// The client secret is WRITE-ONLY over this API. No read path returns it, and
// there is no "reveal" endpoint. lld/01-threat-model.md rates it an
// authentication trust anchor, and an operator who has lost it should rotate
// it at the IdP rather than read it back from here.

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	"argus/internal/audit"
	"argus/internal/authz"
	"argus/internal/idp"
	"argus/internal/logging"
)

type idpProviderResponse struct {
	ID          string   `json:"id"`
	DisplayName string   `json:"displayName"`
	Issuer      string   `json:"issuer"`
	ClientID    string   `json:"clientId"`
	Scopes      []string `json:"scopes"`
	GroupsClaim string   `json:"groupsClaim"`
	RedirectURI string   `json:"redirectUri"`
	Enabled     bool     `json:"enabled"`
	// HasClientSecret rather than the secret itself: a settings form needs to
	// know whether one is stored (to render "leave blank to keep") without
	// being handed it.
	HasClientSecret bool                    `json:"hasClientSecret"`
	GroupMappings   []idpGroupMappingOutput `json:"groupMappings"`
}

type idpGroupMappingOutput struct {
	ID        string `json:"id"`
	GroupName string `json:"groupName"`
	RoleID    string `json:"roleId"`
}

// handleListIdentityProviders returns every configured provider with its group
// mappings.
func (s *Server) handleListIdentityProviders(w http.ResponseWriter, r *http.Request, rc *requestContext) {
	ctx := r.Context()
	rows, err := s.idpStore.ListProviders(ctx, rc.Tx, rc.TenantID)
	if err != nil {
		logger.ErrorContext(ctx, "listing identity providers failed", logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not list identity providers", "")
		return
	}

	out := make([]idpProviderResponse, 0, len(rows))
	for _, p := range rows {
		mappings, err := s.idpStore.GroupMappings(ctx, rc.Tx, rc.TenantID, p.ID)
		if err != nil {
			logger.ErrorContext(ctx, "reading an identity provider's group mappings failed", slog.String("provider_id", p.ID), logging.Err(err))
			writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not list group mappings", "")
			return
		}
		mo := make([]idpGroupMappingOutput, 0, len(mappings))
		for _, m := range mappings {
			mo = append(mo, idpGroupMappingOutput{ID: m.ID, GroupName: m.GroupName, RoleID: m.RoleID})
		}
		out = append(out, idpProviderResponse{
			ID: p.ID, DisplayName: p.DisplayName, Issuer: p.Issuer, ClientID: p.ClientID,
			Scopes: p.Scopes, GroupsClaim: p.GroupsClaim, RedirectURI: p.RedirectURI,
			Enabled: p.Enabled, HasClientSecret: p.HasSecret, GroupMappings: mo,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"providers": out})
}

type saveIdentityProviderRequest struct {
	DisplayName string   `json:"displayName"`
	Issuer      string   `json:"issuer"`
	ClientID    string   `json:"clientId"`
	Scopes      []string `json:"scopes"`
	GroupsClaim string   `json:"groupsClaim"`
	RedirectURI string   `json:"redirectUri"`
	Enabled     bool     `json:"enabled"`
	// ClientSecret is a POINTER so the three cases stay distinguishable:
	// absent means "keep what is stored", "" means "become a public client",
	// a value means "replace". A settings form that cannot read the secret
	// back needs exactly that distinction — see idp.SaveProviderInput.
	ClientSecret *string `json:"clientSecret"`
}

// handleSaveIdentityProvider creates or updates a provider.
//
// Discovery is attempted BEFORE the row is written when the provider is being
// enabled. A configuration that cannot discover cannot authenticate anyone, so
// storing it enabled would present a broken login button — and the operator
// would find out from a user, not from this API.
func (s *Server) handleSaveIdentityProvider(w http.ResponseWriter, r *http.Request, rc *requestContext) {
	ctx := r.Context()
	var req saveIdentityProviderRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeProblem(w, http.StatusBadRequest, "https://argus.io/errors/malformed-request", "Malformed request body", err.Error())
		return
	}

	// id comes from the path for an update, empty for a create.
	providerID := r.PathValue("id")

	if detail := validateProviderInput(&req); detail != "" {
		writeProblem(w, http.StatusBadRequest, "https://argus.io/errors/invalid-request", "Invalid identity provider configuration", detail)
		return
	}

	in := idp.SaveProviderInput{
		ID:           providerID,
		DisplayName:  strings.TrimSpace(req.DisplayName),
		Issuer:       strings.TrimSpace(req.Issuer),
		ClientID:     strings.TrimSpace(req.ClientID),
		ClientSecret: req.ClientSecret,
		Scopes:       req.Scopes,
		GroupsClaim:  strings.TrimSpace(req.GroupsClaim),
		RedirectURI:  strings.TrimSpace(req.RedirectURI),
		Enabled:      req.Enabled,
	}
	if in.GroupsClaim == "" {
		in.GroupsClaim = "groups"
	}
	if len(in.Scopes) == 0 {
		in.Scopes = []string{"openid", "email", "profile", "groups"}
	}

	if in.Enabled {
		// A discovery probe against the issuer, with whatever secret this
		// request supplies. Deliberately not fatal for a DISABLED provider:
		// an operator part-way through configuring one should be able to save
		// their progress against an issuer that is not reachable yet.
		probe := idp.Config{
			Issuer: in.Issuer, ClientID: in.ClientID, RedirectURI: in.RedirectURI,
			Scopes: in.Scopes, GroupsClaim: in.GroupsClaim,
		}
		if _, err := idp.Discover(ctx, probe); err != nil {
			logger.WarnContext(ctx, "the identity provider's OIDC discovery probe failed", slog.String("issuer", in.Issuer), logging.Err(err))
			writeProblem(w, http.StatusBadRequest, "https://argus.io/errors/invalid-request",
				"Could not reach that identity provider",
				"OIDC discovery against the issuer failed. Check the issuer URL is exact (no trailing slash) and reachable from the hub.")
			return
		}
	}

	id, err := s.idpStore.SaveProvider(ctx, rc.Tx, rc.TenantID, in)
	if err != nil {
		logger.ErrorContext(ctx, "saving the identity provider failed", logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not save identity provider", "")
		return
	}

	capability := authz.CapIdentityManage
	if err := audit.RecordEvent(ctx, rc.Tx, audit.Event{
		TenantID:        rc.TenantID,
		ActorID:         &rc.UserID,
		ActorAuthMethod: "jwt",
		SourceIP:        clientIP(r),
		Capability:      &capability,
		Outcome:         audit.OutcomeSuccess,
		Details: map[string]any{
			"action":      "identity_provider_saved",
			"provider_id": id,
			"issuer":      in.Issuer,
			"enabled":     in.Enabled,
			// Whether the secret changed is auditable; its value is not.
			"client_secret_changed": in.ClientSecret != nil,
		},
	}); err != nil {
		logger.ErrorContext(ctx, "recording an identity-provider save in the audit log failed", logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not record audit event", "")
		return
	}

	// Discovery for this provider may be cached from before this edit; drop it
	// so the next login uses the new issuer rather than the old one. Queued
	// after commit because a rolled-back edit must not invalidate a cache
	// entry that is still correct.
	rc.OnCommit(func() { s.invalidateOIDCCache(id) })

	writeJSON(w, http.StatusOK, map[string]any{"id": id})
}

// validateProviderInput rejects what would otherwise fail later and less
// clearly. Returns a caller-safe detail, or "" when the input is acceptable.
func validateProviderInput(req *saveIdentityProviderRequest) string {
	if strings.TrimSpace(req.DisplayName) == "" {
		return "displayName is required — it is the label on the login button"
	}
	issuer := strings.TrimSpace(req.Issuer)
	if issuer == "" {
		return "issuer is required"
	}
	u, err := url.Parse(issuer)
	if err != nil || u.Host == "" {
		return "issuer must be an absolute URL, for example https://idp.example.com"
	}
	if u.Scheme != "https" && u.Hostname() != "localhost" && u.Hostname() != "127.0.0.1" {
		// An http issuer means ID tokens and the client secret cross the
		// network in clear. Permitted for localhost only, because that is how
		// a Dex or Keycloak instance is exercised on a developer machine.
		return "issuer must use https (http is permitted only for localhost)"
	}
	if strings.HasSuffix(issuer, "/") {
		// go-oidc compares the discovery document's own issuer against this
		// string EXACTLY, and a trailing slash is the single most common
		// reason a correct-looking configuration fails with an opaque
		// mismatch. Rejecting here turns a confusing runtime failure into a
		// clear configuration error.
		return "issuer must not end in a slash — it is compared exactly against the discovery document"
	}
	if strings.TrimSpace(req.ClientID) == "" {
		return "clientId is required"
	}
	redirect := strings.TrimSpace(req.RedirectURI)
	if redirect == "" {
		return "redirectUri is required — it must exactly match what is registered at the identity provider"
	}
	if ru, err := url.Parse(redirect); err != nil || ru.Host == "" {
		return "redirectUri must be an absolute URL"
	}
	return ""
}

// handleDeleteIdentityProvider removes a provider, its mappings and its
// secret.
//
// Grants already issued from its mappings are deliberately NOT revoked here.
// Deleting a provider stops future logins through it; revoking live access is
// a separate, more disruptive act an operator should choose explicitly, and
// doing it silently as a side effect of a configuration change is how people
// lose access mid-incident. The response says so.
func (s *Server) handleDeleteIdentityProvider(w http.ResponseWriter, r *http.Request, rc *requestContext) {
	ctx := r.Context()
	providerID := r.PathValue("id")
	if providerID == "" {
		writeProblem(w, http.StatusBadRequest, "https://argus.io/errors/invalid-request", "A provider id is required", "")
		return
	}

	if err := s.idpStore.DeleteProvider(ctx, rc.Tx, rc.TenantID, providerID); err != nil {
		logger.ErrorContext(ctx, "deleting the identity provider failed", logging.Err(err))
		writeProblem(w, http.StatusNotFound, "https://argus.io/errors/not-found", "No such identity provider", "")
		return
	}

	capability := authz.CapIdentityManage
	if err := audit.RecordEvent(ctx, rc.Tx, audit.Event{
		TenantID:        rc.TenantID,
		ActorID:         &rc.UserID,
		ActorAuthMethod: "jwt",
		SourceIP:        clientIP(r),
		Capability:      &capability,
		Outcome:         audit.OutcomeSuccess,
		Details:         map[string]any{"action": "identity_provider_deleted", "provider_id": providerID},
	}); err != nil {
		logger.ErrorContext(ctx, "recording an identity-provider deletion in the audit log failed", logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not record audit event", "")
		return
	}

	rc.OnCommit(func() { s.invalidateOIDCCache(providerID) })
	writeJSON(w, http.StatusOK, map[string]any{
		"deleted": providerID,
		"note":    "Existing sessions and IdP-derived grants are unchanged. Revoke them separately if that is the intent.",
	})
}

type addGroupMappingRequest struct {
	GroupName string `json:"groupName"`
	RoleID    string `json:"roleId"`
}

// handleAddIdentityGroupMapping maps one IdP group to one ARGUS role.
//
// The role must be one this hub actually has, checked here rather than at
// login: a mapping naming a nonexistent role would silently grant nothing,
// and the operator would have no way to tell that from "nobody is in that
// group".
func (s *Server) handleAddIdentityGroupMapping(w http.ResponseWriter, r *http.Request, rc *requestContext) {
	ctx := r.Context()
	providerID := r.PathValue("id")
	var req addGroupMappingRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeProblem(w, http.StatusBadRequest, "https://argus.io/errors/malformed-request", "Malformed request body", err.Error())
		return
	}
	group := strings.TrimSpace(req.GroupName)
	role := strings.TrimSpace(req.RoleID)
	if group == "" || role == "" {
		writeProblem(w, http.StatusBadRequest, "https://argus.io/errors/invalid-request",
			"groupName and roleId are both required", "")
		return
	}

	known, err := s.roleExists(ctx, rc, role)
	if err != nil {
		logger.ErrorContext(ctx, "resolving the role named in an identity group mapping failed", slog.String("role", role), logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not resolve role", "")
		return
	}
	if !known {
		writeProblem(w, http.StatusBadRequest, "https://argus.io/errors/invalid-request",
			"No such role", fmt.Sprintf("%q is neither a built-in role nor a custom role in this organisation", role))
		return
	}

	// AllClusters, matching what bootstrap.go grants and what every built-in
	// role's scope means today. A narrower scope per mapping is a real future
	// want, but inventing the field now without a UI to set it would leave a
	// column nothing writes — see PROJECT.md rather than guessing here.
	const scope = `{"type":"AllClusters"}`

	id, err := s.idpStore.AddGroupMapping(ctx, rc.Tx, rc.TenantID, providerID, group, role, []byte(scope))
	if err != nil {
		logger.ErrorContext(ctx, "adding the identity group mapping failed", logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not add group mapping", "")
		return
	}

	capability := authz.CapIdentityManage
	if err := audit.RecordEvent(ctx, rc.Tx, audit.Event{
		TenantID:        rc.TenantID,
		ActorID:         &rc.UserID,
		ActorAuthMethod: "jwt",
		SourceIP:        clientIP(r),
		Capability:      &capability,
		Outcome:         audit.OutcomeSuccess,
		Details: map[string]any{
			"action": "identity_group_mapping_added", "provider_id": providerID,
			"group_name": group, "role_id": role,
		},
	}); err != nil {
		logger.ErrorContext(ctx, "recording an identity group-mapping addition in the audit log failed", logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not record audit event", "")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"id": id})
}

func (s *Server) handleDeleteIdentityGroupMapping(w http.ResponseWriter, r *http.Request, rc *requestContext) {
	ctx := r.Context()
	mappingID := r.PathValue("mappingId")
	if err := s.idpStore.DeleteGroupMapping(ctx, rc.Tx, rc.TenantID, mappingID); err != nil {
		logger.ErrorContext(ctx, "deleting the identity group mapping failed", logging.Err(err))
		writeProblem(w, http.StatusNotFound, "https://argus.io/errors/not-found", "No such group mapping", "")
		return
	}

	capability := authz.CapIdentityManage
	if err := audit.RecordEvent(ctx, rc.Tx, audit.Event{
		TenantID:        rc.TenantID,
		ActorID:         &rc.UserID,
		ActorAuthMethod: "jwt",
		SourceIP:        clientIP(r),
		Capability:      &capability,
		Outcome:         audit.OutcomeSuccess,
		Details:         map[string]any{"action": "identity_group_mapping_deleted", "mapping_id": mappingID},
	}); err != nil {
		logger.ErrorContext(ctx, "recording an identity group-mapping deletion in the audit log failed", logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not record audit event", "")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"deleted": mappingID})
}

// roleExists reports whether a role id is a built-in or a custom role in this
// organisation.
func (s *Server) roleExists(ctx context.Context, rc *requestContext, roleID string) (bool, error) {
	if authz.IsBuiltinRole(roleID) {
		return true, nil
	}
	var exists bool
	if err := rc.Tx.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM custom_roles WHERE tenant_id = $1 AND id = $2)`,
		rc.TenantID, roleID).Scan(&exists); err != nil {
		return false, err
	}
	return exists, nil
}
