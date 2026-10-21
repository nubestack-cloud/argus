package api

import (
	"context"
	"crypto/rand"
	"encoding/base32"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"argus/internal/audit"
	"argus/internal/authz"
	"argus/internal/domain"
	"argus/internal/logging"
)

// This file implements the admin console's user/grant management surface —
// the AdminConsole component lld/11-ui-design.md §3 describes ("Users/roles/
// grants... every sub-panel independently gated by its own capability"),
// backed by the capability catalogue and grants table that already existed
// (authz/permissions.go's CapUserRead/CapUserManage, migration 000001's
// users/grants tables) but had no API or UI until now.
//
// Deliberately bounded, matching this round's scope:
//   - Custom-role authoring exists now (internal/api/custom_roles.go,
//     BACKLOG.md S3) but lives entirely in that file — this file's role
//     resolution (authz.ResolveRoleCapabilities, used by handleCreateUser and
//     handleCreateGrant below) simply tries a custom role after a builtin
//     one, exactly as it already tried nothing else before. There is still
//     no SECOND assignment mechanism: a custom role is granted through this
//     file's existing POST /users/{id}/grants, the same as any builtin role.
//   - Scope now also accepts "ClusterGroup" (validateGrantScope below), now
//     that BACKLOG.md S3 gave cluster_groups real membership
//     (internal/api/cluster_groups.go) and authz.AccessibleClusterIDs can
//     resolve it — this scope type used to be rejected here specifically
//     because accepting it would have been fake with no membership to
//     resolve against.
//   - No ad hoc capability-set grants — every grant created through this file
//     sets grants.role_id, never grants.capability_set, matching the schema's
//     CHECK ((role_id IS NULL) <> (capability_set IS NULL)) constraint. A
//     custom role's capability_set lives on custom_roles, not on the grant
//     row itself — the grant still only ever stores a role_id.
//   - No HARD user deletion, deliberately. DELETE /users/{id} is implemented
//     as a soft removal (deleted_at + disabled_at + grant/session revocation),
//     because a real DELETE FROM users would orphan every audit_events.actor_id,
//     grants.principal_id/granted_by, and incidents/org_settings reference
//     pointing at that row — actively harmful for a product whose audit trail
//     (package audit's own doc comment) is supposed to be a permanent,
//     trustworthy record. "Disable" remains the reversible "pause this account"
//     state; "remove" is the irreversible admin-console removal from active
//     user management and authentication.

// grantView is one grants row as returned by the API — mirrors
// authz.EffectiveGrant's Scope shape but carries the grant's own identity
// (id, role, timestamps) since this is grant *management*, not the resolved
// effective-permissions view GET /users/me/effective-permissions already
// serves.
type grantView struct {
	ID        string      `json:"id"`
	Role      string      `json:"role"` // empty for a pre-existing ad hoc (capability_set-based) grant — none are ever CREATED via this API, but a row like that could already exist, and must render without crashing rather than panicking on a nil role_id.
	Scope     authz.Scope `json:"scope"`
	GrantedBy string      `json:"grantedBy"`
	GrantedAt string      `json:"grantedAt"`
	ExpiresAt *string     `json:"expiresAt"`
	// Justification is the free-text reason an admin gave when creating the
	// grant. Nullable column, omitted when absent — and it was absent on every
	// row until 2026-08-22, because insertGrant has always accepted and stored
	// one while no UI collected it and nothing read it back. That left "why does
	// this person have this access", the question an access review opens with,
	// unanswerable from ARGUS. Optional by owner decision: a reason on the
	// grants someone will actually ask about beats a mandatory field filled with
	// "asdf" under time pressure.
	Justification *string `json:"justification,omitempty"`
}

// userView is one users row plus its currently-active (non-revoked,
// non-expired) grants — the exact same activity filter
// authz.ResolveEffectivePermissions itself applies, so "active" means the
// same thing here as it does everywhere else authorization is decided.
type userView struct {
	ID                 string      `json:"id"`
	Email              string      `json:"email"`
	DisplayName        string      `json:"displayName"`
	MustChangePassword bool        `json:"mustChangePassword"`
	DisabledAt         *string     `json:"disabledAt"`
	CreatedAt          string      `json:"createdAt"`
	Grants             []grantView `json:"grants"`
}

// scanGrantViewRow scans one row shaped like the shared grants SELECT used
// by both handleListUsers (per-user) and handleCreateGrant/handleRevokeGrant
// (single-row) below.
func scanGrantViewRow(row pgx.Row) (grantView, error) {
	var g grantView
	var roleID *string
	var scopeJSON []byte
	var grantedAt time.Time
	var expiresAt *time.Time
	if err := row.Scan(&g.ID, &roleID, &scopeJSON, &g.GrantedBy, &grantedAt, &expiresAt, &g.Justification); err != nil {
		return grantView{}, err
	}
	if roleID != nil {
		g.Role = *roleID
	}
	if err := json.Unmarshal(scopeJSON, &g.Scope); err != nil {
		return grantView{}, fmt.Errorf("unmarshal scope: %w", err)
	}
	g.GrantedAt = formatRFC3339(grantedAt)
	if expiresAt != nil {
		f := formatRFC3339(*expiresAt)
		g.ExpiresAt = &f
	}
	return g, nil
}

const activeGrantsWhere = `revoked_at IS NULL AND (expires_at IS NULL OR expires_at > now())`

// handleListUsers is GET /api/v1/users. Requires user:read. Not paginated —
// this is a small admin list (a handful to low hundreds of users), not a
// fleet-scale table.
func (s *Server) handleListUsers(w http.ResponseWriter, r *http.Request, rc *requestContext) {
	ctx := r.Context()

	rows, err := rc.Tx.Query(ctx,
		`SELECT id, email, display_name, must_change_password, disabled_at, created_at
		   FROM users WHERE deleted_at IS NULL ORDER BY lower(email)`)
	if err != nil {
		logger.ErrorContext(ctx, "querying users failed", logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not list users", "")
		return
	}
	defer rows.Close()

	users := []userView{}
	for rows.Next() {
		var u userView
		var disabledAt *time.Time
		var createdAt time.Time
		if err := rows.Scan(&u.ID, &u.Email, &u.DisplayName, &u.MustChangePassword, &disabledAt, &createdAt); err != nil {
			logger.ErrorContext(ctx, "scanning a user row failed", logging.Err(err))
			writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not list users", "")
			return
		}
		if disabledAt != nil {
			f := formatRFC3339(*disabledAt)
			u.DisabledAt = &f
		}
		u.CreatedAt = formatRFC3339(createdAt)
		u.Grants = []grantView{}
		users = append(users, u)
	}
	if err := rows.Err(); err != nil {
		logger.ErrorContext(ctx, "iterating the user rows failed", logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not list users", "")
		return
	}

	// Second query, not a JOIN: the grants-per-user shape (a slice field,
	// zero-to-many) is awkward to build directly from a joined result set,
	// and this list is small enough (see this handler's doc comment) that a
	// second round trip is simpler than either a JOIN-and-regroup or a
	// per-user query in a loop (which would be N+1 for no benefit here since
	// this single query already fetches every active grant this tenant has).
	grantRows, err := rc.Tx.Query(ctx,
		`SELECT principal_id, id, role_id, scope, granted_by, granted_at, expires_at, justification
		   FROM grants
		   WHERE principal_type = 'user' AND `+activeGrantsWhere+`
			AND EXISTS (SELECT 1 FROM users u WHERE u.id = grants.principal_id AND u.deleted_at IS NULL)
		   ORDER BY granted_at`)
	if err != nil {
		logger.ErrorContext(ctx, "querying grants failed", logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not list users", "")
		return
	}
	defer grantRows.Close()

	grantsByUser := map[string][]grantView{}
	for grantRows.Next() {
		var principalID string
		var g grantView
		var roleID *string
		var scopeJSON []byte
		var grantedAt time.Time
		var expiresAt *time.Time
		if err := grantRows.Scan(&principalID, &g.ID, &roleID, &scopeJSON, &g.GrantedBy, &grantedAt, &expiresAt, &g.Justification); err != nil {
			logger.ErrorContext(ctx, "scanning a grant row failed", logging.Err(err))
			writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not list users", "")
			return
		}
		if roleID != nil {
			g.Role = *roleID
		}
		if err := json.Unmarshal(scopeJSON, &g.Scope); err != nil {
			logger.ErrorContext(ctx, "unmarshalling a grant's scope failed", logging.Err(err))
			writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not list users", "")
			return
		}
		g.GrantedAt = formatRFC3339(grantedAt)
		if expiresAt != nil {
			f := formatRFC3339(*expiresAt)
			g.ExpiresAt = &f
		}
		grantsByUser[principalID] = append(grantsByUser[principalID], g)
	}
	if err := grantRows.Err(); err != nil {
		logger.ErrorContext(ctx, "iterating the grant rows failed", logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not list users", "")
		return
	}

	for i := range users {
		if gs, ok := grantsByUser[users[i].ID]; ok {
			users[i].Grants = gs
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{"users": users})
}

// generateTemporaryPassword returns a fresh, high-entropy password — the
// exact same shape (20 random bytes, unpadded base32) as
// authz.bootstrapPassword's generated-password path, reused here because a
// newly admin-created user needs the identical "shown once, never logged,
// never stored anywhere but its hash" discipline the bootstrap super-admin
// already gets.
func generateTemporaryPassword() (string, error) {
	buf := make([]byte, 20) // 160 bits
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate temporary password: %w", err)
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(buf), nil
}

// validateGrantScope checks the SHAPE of a requested scope — "AllClusters",
// "Cluster" with a non-empty clusterId, or "ClusterGroup" with a non-empty
// clusterGroupId. It does not check that a named cluster/group actually
// EXISTS in this tenant — clusterExists/clusterGroupExists below do that
// separately, matching the existing split for "Cluster" (this function has
// never opened a transaction, and callers already have one open when they
// need the existence check).
func validateGrantScope(scope authz.Scope) error {
	switch scope.Type {
	case "AllClusters":
		return nil
	case "Cluster":
		if strings.TrimSpace(scope.ClusterID) == "" {
			return fmt.Errorf(`scope type "Cluster" requires a non-empty clusterId`)
		}
		return nil
	case "ClusterGroup":
		if strings.TrimSpace(scope.GroupID) == "" {
			return fmt.Errorf(`scope type "ClusterGroup" requires a non-empty clusterGroupId`)
		}
		return nil
	default:
		return fmt.Errorf(`unsupported scope type %q — only "Cluster", "ClusterGroup" and "AllClusters" are supported here`, scope.Type)
	}
}

// clusterExists is a small existence check shared by handleCreateUser and
// handleCreateGrant when the requested scope names a specific cluster — a
// typo'd clusterId would otherwise silently create a grant that can never
// apply to anything.
func clusterExists(ctx context.Context, tx pgx.Tx, clusterID string) (bool, error) {
	var exists bool
	err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM clusters WHERE id = $1)`, clusterID).Scan(&exists)
	if err != nil {
		return false, err
	}
	return exists, nil
}

// clusterGroupExists is clusterExists' counterpart for a "ClusterGroup"
// scope — a typo'd or long-deleted clusterGroupId would otherwise silently
// create a grant that authz.AccessibleClusterIDs later resolves to "reaches
// nothing" with no indication to the admin that anything was wrong at
// creation time.
func clusterGroupExists(ctx context.Context, tx pgx.Tx, groupID string) (bool, error) {
	var exists bool
	err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM cluster_groups WHERE id = $1)`, groupID).Scan(&exists)
	if err != nil {
		return false, err
	}
	return exists, nil
}

// insertGrant is the shared insert used by handleCreateUser's optional
// initial grant and handleCreateGrant — always role-based (capability_set
// stays NULL), always source='manual'.
func insertGrant(ctx context.Context, tx pgx.Tx, tenantID, userID, role string, scope authz.Scope, grantedBy string, justification string) (grantView, error) {
	scopeJSON, err := json.Marshal(scope)
	if err != nil {
		return grantView{}, fmt.Errorf("marshal scope: %w", err)
	}
	var justificationPtr *string
	if justification != "" {
		justificationPtr = &justification
	}

	id := domain.NewID(domain.PrefixGrant)
	row := tx.QueryRow(ctx,
		`INSERT INTO grants (id, tenant_id, principal_type, principal_id, role_id, scope, source, granted_by, justification)
		 VALUES ($1, $2, 'user', $3, $4, $5, 'manual', $6, $7)
		 RETURNING id, role_id, scope, granted_by, granted_at, expires_at, justification`,
		id, tenantID, userID, role, scopeJSON, grantedBy, justificationPtr)
	return scanGrantViewRow(row)
}

type createUserInitialGrant struct {
	Role  string      `json:"role"`
	Scope authz.Scope `json:"scope"`
}

type createUserRequest struct {
	Email        string                  `json:"email"`
	DisplayName  string                  `json:"displayName"`
	InitialGrant *createUserInitialGrant `json:"initialGrant"`
}

type createUserResponse struct {
	User              userView `json:"user"`
	TemporaryPassword string   `json:"temporaryPassword"`
}

// handleCreateUser is POST /api/v1/users. Requires user:manage. Creates a
// user with a server-generated temporary password and mustChangePassword =
// true — the exact same "local password + forced change on first login"
// mechanism handleLogin/EnsureBootstrap already implement, not a new
// email-invite flow. The temporary password is returned exactly once, in
// this response only — it is never logged (not even at debug level) and
// never appears in the audit event this handler records, matching
// handleCreateEnrollmentToken's discipline for its own server-generated
// secret.
//
// Optionally grants an initial role+scope atomically in the same request —
// simpler than requiring a second POST /users/{id}/grants call for the
// overwhelmingly common case of "create a user who can immediately do
// something."
func (s *Server) handleCreateUser(w http.ResponseWriter, r *http.Request, rc *requestContext) {
	var req createUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeProblem(w, http.StatusBadRequest, "https://argus.io/errors/malformed-request", "Malformed request body", err.Error())
		return
	}

	email := strings.TrimSpace(req.Email)
	if email == "" || !strings.Contains(email, "@") {
		writeProblem(w, http.StatusBadRequest, "https://argus.io/errors/invalid-request", "A valid email is required", "")
		return
	}
	displayName := strings.TrimSpace(req.DisplayName)
	if displayName == "" {
		displayName = email
	}

	var initialRole string
	var initialScope authz.Scope
	if req.InitialGrant != nil {
		initialRole = req.InitialGrant.Role
		initialScope = req.InitialGrant.Scope

		capSet, found, err := authz.ResolveRoleCapabilities(r.Context(), rc.Tx, initialRole)
		if err != nil {
			logger.ErrorContext(r.Context(), "resolving the new user's initial role failed", slog.String("role", initialRole), logging.Err(err))
			writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not validate role", "")
			return
		}
		if !found {
			writeProblem(w, http.StatusBadRequest, "https://argus.io/errors/invalid-request",
				"Unknown role", fmt.Sprintf("role %q is not a builtin role or a custom role in this tenant", initialRole))
			return
		}
		// No escalation through delegation — see handleCreateGrant's identical
		// check below for the full reasoning; this is the same rule applied at
		// the OTHER place a grant is minted (creating a user with an initial
		// grant, rather than adding one to an existing user).
		if missing := authz.CapabilitiesNotHeldByCapSet(rc.Grants, capSet); len(missing) > 0 {
			s.recordCapabilityDenial(r.Context(), rc, missing[0], clientIP(r))
			writeProblem(w, http.StatusForbidden, "https://argus.io/errors/scope-denied",
				"Cannot grant a role with more privileges than you hold",
				fmt.Sprintf("granting %q would confer %d capability/ies you do not hold, including %q",
					initialRole, len(missing), missing[0]))
			return
		}

		if err := validateGrantScope(initialScope); err != nil {
			writeProblem(w, http.StatusBadRequest, "https://argus.io/errors/invalid-request", "Invalid scope", err.Error())
			return
		}
		if initialScope.Type == "Cluster" {
			exists, err := clusterExists(r.Context(), rc.Tx, initialScope.ClusterID)
			if err != nil {
				logger.ErrorContext(r.Context(), "checking that the new user's initial cluster exists failed", logging.Err(err))
				writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not validate scope", "")
				return
			}
			if !exists {
				writeProblem(w, http.StatusBadRequest, "https://argus.io/errors/invalid-request", "Unknown cluster in scope", "")
				return
			}
		}
		if initialScope.Type == "ClusterGroup" {
			exists, err := clusterGroupExists(r.Context(), rc.Tx, initialScope.GroupID)
			if err != nil {
				logger.ErrorContext(r.Context(), "checking that the new user's initial cluster group exists failed", logging.Err(err))
				writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not validate scope", "")
				return
			}
			if !exists {
				writeProblem(w, http.StatusBadRequest, "https://argus.io/errors/invalid-request", "Unknown cluster group in scope", "")
				return
			}
		}
	}

	password, err := generateTemporaryPassword()
	if err != nil {
		logger.ErrorContext(r.Context(), "generating a temporary password failed", logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not create user", "")
		return
	}
	hash, err := authz.HashPassword(password)
	if err != nil {
		logger.ErrorContext(r.Context(), "hashing a temporary password failed", logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not create user", "")
		return
	}

	ctx := r.Context()
	userID := domain.NewID(domain.PrefixUser)
	var createdAt time.Time
	err = rc.Tx.QueryRow(ctx,
		`INSERT INTO users (id, tenant_id, email, display_name, password_hash, must_change_password)
		 VALUES ($1, $2, $3, $4, $5, true)
		 RETURNING created_at`,
		userID, rc.TenantID, email, displayName, hash).Scan(&createdAt)
	if err != nil {
		if isUniqueViolation(err) {
			writeProblem(w, http.StatusConflict, "https://argus.io/errors/already-exists", "A user with this email already exists", "")
			return
		}
		logger.ErrorContext(ctx, "inserting a new user failed", logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not create user", "")
		return
	}

	user := userView{
		ID:                 userID,
		Email:              email,
		DisplayName:        displayName,
		MustChangePassword: true,
		CreatedAt:          formatRFC3339(createdAt),
		Grants:             []grantView{},
	}

	auditDetails := map[string]any{
		"action":        "create_user",
		"createdUserId": userID,
		"email":         email,
	}

	if req.InitialGrant != nil {
		g, err := insertGrant(ctx, rc.Tx, rc.TenantID, userID, initialRole, initialScope, rc.UserID, "")
		if err != nil {
			logger.ErrorContext(ctx, "inserting a new user's initial grant failed", logging.Err(err))
			writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "User created, but could not create the initial grant", "")
			return
		}
		user.Grants = []grantView{g}
		auditDetails["initialGrantRole"] = initialRole
		auditDetails["initialGrantScope"] = initialScope
	}

	capability := authz.CapUserManage
	if err := audit.RecordEvent(ctx, rc.Tx, audit.Event{
		TenantID:        rc.TenantID,
		ActorID:         &rc.UserID,
		ActorAuthMethod: "jwt",
		SourceIP:        clientIP(r),
		Capability:      &capability,
		Outcome:         audit.OutcomeSuccess,
		Details:         auditDetails, // never includes the temporary password
	}); err != nil {
		logger.ErrorContext(ctx, "recording a user creation in the audit log failed", logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not record audit event", "")
		return
	}

	writeJSON(w, http.StatusCreated, createUserResponse{User: user, TemporaryPassword: password})
}

type createGrantRequest struct {
	Role          string      `json:"role"`
	Scope         authz.Scope `json:"scope"`
	Justification string      `json:"justification"`
}

// handleCreateGrant is POST /api/v1/users/{id}/grants. Requires user:manage.
func (s *Server) handleCreateGrant(w http.ResponseWriter, r *http.Request, rc *requestContext) {
	userID := r.PathValue("id")
	ctx := r.Context()

	var exists bool
	if err := rc.Tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM users WHERE id = $1 AND deleted_at IS NULL)`, userID).Scan(&exists); err != nil {
		logger.ErrorContext(ctx, "checking that the grant's subject user exists failed", logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not look up user", "")
		return
	}
	if !exists {
		writeProblem(w, http.StatusNotFound, "https://argus.io/errors/not-found", "User not found", "")
		return
	}

	var req createGrantRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeProblem(w, http.StatusBadRequest, "https://argus.io/errors/malformed-request", "Malformed request body", err.Error())
		return
	}

	// authz.ResolveRoleCapabilities tries a builtin role name first, then a
	// custom_roles row (BACKLOG.md S3) — this used to be authz.IsBuiltinRole
	// alone, back when there was no other kind of role to grant.
	capSet, found, err := authz.ResolveRoleCapabilities(ctx, rc.Tx, req.Role)
	if err != nil {
		logger.ErrorContext(ctx, "resolving the grant's role failed", slog.String("role", req.Role), logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not validate role", "")
		return
	}
	if !found {
		writeProblem(w, http.StatusBadRequest, "https://argus.io/errors/invalid-request",
			"Unknown role", fmt.Sprintf("role %q is not a builtin role or a custom role in this tenant", req.Role))
		return
	}

	// No escalation through delegation: an actor may only grant a role whose
	// capabilities they already hold in full. Without this, `user:manage`
	// alone was enough to grant ANY builtin role — so a tenant-admin (who has
	// user:manage but is deliberately denied audit:read and
	// org:settings:write) could grant themselves super-admin and read both.
	// A real privilege-escalation hole, found in review 2026-08-21; see
	// authz.CapabilitiesNotHeldBy. Now applied via CapabilitiesNotHeldByCapSet
	// against the resolved set directly, so the identical rule reaches a
	// custom role exactly as it always reached a builtin one — composing a
	// bundle from capabilities the DEFINER didn't hold is blocked at
	// custom-role-creation time (internal/api/custom_roles.go), but a custom
	// role could still in principle carry a capability the GRANTOR here
	// doesn't hold even though its definer did, and this is the check that
	// catches that.
	//
	// Deliberately a 403, not a 400: the request is well-formed and the role
	// exists — the caller simply isn't allowed to confer it. The response names
	// the specific capabilities they lack, since "forbidden" with no reason is
	// the kind of error an admin cannot act on.
	if missing := authz.CapabilitiesNotHeldByCapSet(rc.Grants, capSet); len(missing) > 0 {
		s.recordCapabilityDenial(ctx, rc, missing[0], clientIP(r))
		writeProblem(w, http.StatusForbidden, "https://argus.io/errors/scope-denied",
			"Cannot grant a role with more privileges than you hold",
			fmt.Sprintf("granting %q would confer %d capability/ies you do not hold, including %q",
				req.Role, len(missing), missing[0]))
		return
	}

	if err := validateGrantScope(req.Scope); err != nil {
		writeProblem(w, http.StatusBadRequest, "https://argus.io/errors/invalid-request", "Invalid scope", err.Error())
		return
	}
	if req.Scope.Type == "Cluster" {
		clusterOk, err := clusterExists(ctx, rc.Tx, req.Scope.ClusterID)
		if err != nil {
			logger.ErrorContext(ctx, "checking that the grant's cluster exists failed", logging.Err(err))
			writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not validate scope", "")
			return
		}
		if !clusterOk {
			writeProblem(w, http.StatusBadRequest, "https://argus.io/errors/invalid-request", "Unknown cluster in scope", "")
			return
		}
	}
	if req.Scope.Type == "ClusterGroup" {
		groupOk, err := clusterGroupExists(ctx, rc.Tx, req.Scope.GroupID)
		if err != nil {
			logger.ErrorContext(ctx, "checking that the grant's cluster group exists failed", logging.Err(err))
			writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not validate scope", "")
			return
		}
		if !groupOk {
			writeProblem(w, http.StatusBadRequest, "https://argus.io/errors/invalid-request", "Unknown cluster group in scope", "")
			return
		}
	}

	g, err := insertGrant(ctx, rc.Tx, rc.TenantID, userID, req.Role, req.Scope, rc.UserID, req.Justification)
	if err != nil {
		logger.ErrorContext(ctx, "inserting a grant failed", logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not create grant", "")
		return
	}

	capability := authz.CapUserManage
	if err := audit.RecordEvent(ctx, rc.Tx, audit.Event{
		TenantID:        rc.TenantID,
		ActorID:         &rc.UserID,
		ActorAuthMethod: "jwt",
		SourceIP:        clientIP(r),
		Capability:      &capability,
		Outcome:         audit.OutcomeSuccess,
		Details: map[string]any{
			"action":  "create_grant",
			"userId":  userID,
			"grantId": g.ID,
			"role":    req.Role,
			"scope":   req.Scope,
		},
	}); err != nil {
		logger.ErrorContext(ctx, "recording a grant creation in the audit log failed", logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not record audit event", "")
		return
	}

	writeJSON(w, http.StatusCreated, g)
}

// handleRevokeGrant is DELETE /api/v1/users/{id}/grants/{grantId}. Requires
// user:manage. Sets revoked_at (the schema's existing revocation convention
// — the same column ResolveEffectivePermissions' "non-revoked" filter
// already reads) rather than deleting the row, so a revoked grant's history
// (who granted what, when, and who/when it was revoked) stays intact for
// audit purposes.
func (s *Server) handleRevokeGrant(w http.ResponseWriter, r *http.Request, rc *requestContext) {
	userID := r.PathValue("id")
	grantID := r.PathValue("grantId")
	ctx := r.Context()

	var principalID, roleID *string
	var scopeJSON []byte
	var revokedAt *time.Time
	err := rc.Tx.QueryRow(ctx,
		`SELECT principal_id, role_id, scope, revoked_at FROM grants
		   WHERE id = $1 AND principal_type = 'user'`,
		grantID).Scan(&principalID, &roleID, &scopeJSON, &revokedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			writeProblem(w, http.StatusNotFound, "https://argus.io/errors/not-found", "Grant not found", "")
			return
		}
		logger.ErrorContext(ctx, "looking up the grant to revoke failed", slog.String("grant_id", grantID), logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not look up grant", "")
		return
	}
	if principalID == nil || *principalID != userID {
		// Exists, but not as a grant belonging to THIS user — treated as
		// not-found from this URL's point of view rather than leaking that a
		// grant with this id exists under some other user.
		writeProblem(w, http.StatusNotFound, "https://argus.io/errors/not-found", "Grant not found", "")
		return
	}
	if revokedAt != nil {
		writeProblem(w, http.StatusConflict, "https://argus.io/errors/invalid-state", "Grant is already revoked", "")
		return
	}

	if _, err := rc.Tx.Exec(ctx, `UPDATE grants SET revoked_at = now() WHERE id = $1`, grantID); err != nil {
		logger.ErrorContext(ctx, "revoking a grant failed", slog.String("grant_id", grantID), logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not revoke grant", "")
		return
	}

	details := map[string]any{
		"action":  "revoke_grant",
		"userId":  userID,
		"grantId": grantID,
	}
	if roleID != nil {
		details["role"] = *roleID
	}
	var scope authz.Scope
	if err := json.Unmarshal(scopeJSON, &scope); err == nil {
		details["scope"] = scope
	}

	capability := authz.CapUserManage
	if err := audit.RecordEvent(ctx, rc.Tx, audit.Event{
		TenantID:        rc.TenantID,
		ActorID:         &rc.UserID,
		ActorAuthMethod: "jwt",
		SourceIP:        clientIP(r),
		Capability:      &capability,
		Outcome:         audit.OutcomeSuccess,
		Details:         details,
	}); err != nil {
		logger.ErrorContext(ctx, "recording a grant revocation in the audit log failed", slog.String("grant_id", grantID), logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not record audit event", "")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"grantId": grantID, "status": "revoked"})
}

type resetPasswordResponse struct {
	TemporaryPassword string `json:"temporaryPassword"`
}

// handleResetPassword is POST /api/v1/users/{id}/reset-password. Requires
// user:manage. Generates a fresh high-entropy temporary password — reusing
// generateTemporaryPassword exactly as handleCreateUser does, not a second
// implementation of the same "shown once, never logged" generation — forces
// must_change_password back to true, and ends every session the target user
// currently holds: both refresh-token sessions (authz.RevokeAllRefreshTokens)
// and any outstanding, not-yet-expired access token (bumping
// token_generation, which requireAuth checks on every request — see
// accessTokenClaims' doc comment, internal/authz/jwt.go). A password reset
// that left an already-issued session alive would not actually be a reset —
// this is the whole point of the task this endpoint exists for: an admin
// who resets a compromised user's password must be able to end whatever
// session an attacker is already holding, not just gate the NEXT login.
//
// Unlike handleChangePassword, no new token pair is issued here — the acting
// admin is not the target user, so there is no session of theirs to hand
// back new tokens for. The target user must sign in fresh with the returned
// temporary password (and will immediately be forced to change it again).
func (s *Server) handleResetPassword(w http.ResponseWriter, r *http.Request, rc *requestContext) {
	userID := r.PathValue("id")
	ctx := r.Context()

	var exists bool
	if err := rc.Tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM users WHERE id = $1 AND deleted_at IS NULL)`, userID).Scan(&exists); err != nil {
		logger.ErrorContext(ctx, "checking that the user whose password is being reset exists failed", slog.String("target_user_id", userID), logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not look up user", "")
		return
	}
	if !exists {
		writeProblem(w, http.StatusNotFound, "https://argus.io/errors/not-found", "User not found", "")
		return
	}

	password, err := generateTemporaryPassword()
	if err != nil {
		logger.ErrorContext(ctx, "generating a temporary password failed", logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not reset password", "")
		return
	}
	hash, err := authz.HashPassword(password)
	if err != nil {
		logger.ErrorContext(ctx, "hashing a temporary password failed", logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not reset password", "")
		return
	}

	if _, err := rc.Tx.Exec(ctx,
		`UPDATE users SET password_hash = $1, must_change_password = true, token_generation = token_generation + 1
		 WHERE id = $2`,
		hash, userID); err != nil {
		logger.ErrorContext(ctx, "storing a reset password failed", slog.String("target_user_id", userID), logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not reset password", "")
		return
	}

	if err := authz.RevokeAllRefreshTokens(ctx, rc.Tx, userID); err != nil {
		logger.ErrorContext(ctx, "revoking the refresh tokens of a user whose password was reset failed", slog.String("target_user_id", userID), logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not reset password", "")
		return
	}

	capability := authz.CapUserManage
	if err := audit.RecordEvent(ctx, rc.Tx, audit.Event{
		TenantID:        rc.TenantID,
		ActorID:         &rc.UserID,
		ActorAuthMethod: "jwt",
		SourceIP:        clientIP(r),
		Capability:      &capability,
		Outcome:         audit.OutcomeSuccess,
		Details: map[string]any{
			"action": "reset_password",
			"userId": userID,
		}, // never the temporary password itself
	}); err != nil {
		logger.ErrorContext(ctx, "recording a password reset in the audit log failed", slog.String("target_user_id", userID), logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not record audit event", "")
		return
	}

	writeJSON(w, http.StatusOK, resetPasswordResponse{TemporaryPassword: password})
}

// userLifecycleResponse is the shared response shape for both
// handleDisableUser and handleEnableUser — same "id + new status string"
// convention handleRevokeGrant's response already established for a
// state-transition write.
type userLifecycleResponse struct {
	UserID string `json:"userId"`
	Status string `json:"status"`
}

const superAdminRole = "super-admin"

// hasActiveRole reports whether userID currently holds a non-revoked,
// non-expired grant for the given builtin role — the same "active" filter
// (activeGrantsWhere) every other grant read in this file already applies.
func hasActiveRole(ctx context.Context, tx pgx.Tx, userID, role string) (bool, error) {
	var exists bool
	err := tx.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM grants
		   WHERE principal_type = 'user' AND principal_id = $1 AND role_id = $2 AND `+activeGrantsWhere+`)`,
		userID, role).Scan(&exists)
	if err != nil {
		return false, err
	}
	return exists, nil
}

// countOtherActiveSuperAdmins counts users OTHER than excludeUserID who both
// hold an active super-admin grant and are not themselves disabled — the
// exact population that could still administer the system if excludeUserID
// were disabled right now. Joined against users (not just grants) because a
// super-admin grant belonging to an already-disabled user doesn't count:
// that account can't act either.
func countOtherActiveSuperAdmins(ctx context.Context, tx pgx.Tx, excludeUserID string) (int, error) {
	var count int
	err := tx.QueryRow(ctx,
		`SELECT COUNT(DISTINCT g.principal_id) FROM grants g
		   JOIN users u ON u.id = g.principal_id
		   WHERE g.principal_type = 'user' AND g.role_id = $1 AND `+activeGrantsWhere+`
		     AND u.disabled_at IS NULL AND u.deleted_at IS NULL AND g.principal_id != $2`,
		superAdminRole, excludeUserID).Scan(&count)
	if err != nil {
		return 0, err
	}
	return count, nil
}

// selfDisableWouldStrandAdmin implements this task's guardrail exactly as
// scoped: it only ever returns true when userID is BOTH a currently-active
// super-admin AND disabling them would leave zero other active,
// non-disabled super-admins able to administer the system. Per the task
// brief, this check applies ONLY to a super-admin disabling THEMSELVES —
// handleDisableUser only calls this when rc.UserID == the target userID.
// A self-disable by anyone else (a non-super-admin disabling their own
// account) or disabling a non-super-admin target never needs this check at
// all, and a super-admin disabling a DIFFERENT super-admin is deliberately
// out of this round's scope too (the brief frames the guard as specific to
// self-disable).
func selfDisableWouldStrandAdmin(ctx context.Context, tx pgx.Tx, userID string) (bool, error) {
	isSuperAdmin, err := hasActiveRole(ctx, tx, userID, superAdminRole)
	if err != nil {
		return false, fmt.Errorf("check super-admin role: %w", err)
	}
	if !isSuperAdmin {
		return false, nil
	}
	others, err := countOtherActiveSuperAdmins(ctx, tx, userID)
	if err != nil {
		return false, fmt.Errorf("count other active super-admins: %w", err)
	}
	return others == 0, nil
}

// revokeUserPersonalTokens revokes every personal AI tool (MCP) token userID
// still holds, inside the caller's transaction, and returns how many it ended.
// Called by disable and remove so that the token rows themselves say revoked:
// lookupPersonalToken already refuses a disabled or removed owner, but that
// refusal lasts only as long as the account stays off, and a token that
// outlives its account's disablement would start working again on re-enable.
func revokeUserPersonalTokens(ctx context.Context, tx pgx.Tx, userID string) (int64, error) {
	tag, err := tx.Exec(ctx,
		`UPDATE mcp_personal_tokens SET revoked_at = now() WHERE user_id = $1 AND revoked_at IS NULL`, userID)
	if err != nil {
		return 0, fmt.Errorf("revoke personal tokens: %w", err)
	}
	return tag.RowsAffected(), nil
}

// handleDisableUser is POST /api/v1/users/{id}/disable. Requires
// user:manage. This is the disable half of the "user lifecycle management
// is missing" gap: sets disabled_at = now(), which handleLogin's existing
// `WHERE ... AND disabled_at IS NULL` clause already refuses to
// authenticate against, AND — matching handleResetPassword's exact
// precedent — ends every session the target currently holds right now,
// not just future ones: every outstanding refresh token is revoked
// (authz.RevokeAllRefreshTokens) and token_generation is bumped, which
// requireAuth checks on every request (see accessTokenClaims' doc comment,
// internal/authz/jwt.go) and therefore invalidates any already-issued,
// not-yet-expired access token immediately too. A disable that left an
// already-issued session alive would not actually disable the user — they
// could keep working right up until their token's natural 15-minute expiry.
//
// Idempotent-conflict, not idempotent-success: disabling an already-disabled
// user is rejected with 409, the same "already in a terminal state" shape
// handleDecommissionCluster uses for re-decommissioning an already-Archived
// cluster, rather than silently succeeding a second time.
//
// Guardrail: a super-admin may not disable THEMSELVES if doing so would
// leave no other active, non-disabled super-admin able to administer the
// system (selfDisableWouldStrandAdmin above) — checked only for a
// self-disable by a super-admin, per this task's exact scope.
func (s *Server) handleDisableUser(w http.ResponseWriter, r *http.Request, rc *requestContext) {
	userID := r.PathValue("id")
	ctx := r.Context()

	var disabledAt *time.Time
	err := rc.Tx.QueryRow(ctx, `SELECT disabled_at FROM users WHERE id = $1 AND deleted_at IS NULL`, userID).Scan(&disabledAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			writeProblem(w, http.StatusNotFound, "https://argus.io/errors/not-found", "User not found", "")
			return
		}
		logger.ErrorContext(ctx, "looking up the user to disable failed", slog.String("target_user_id", userID), logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not look up user", "")
		return
	}
	if disabledAt != nil {
		writeProblem(w, http.StatusConflict, "https://argus.io/errors/invalid-state", "User is already disabled", "")
		return
	}

	if userID == rc.UserID {
		stranded, err := selfDisableWouldStrandAdmin(ctx, rc.Tx, userID)
		if err != nil {
			logger.ErrorContext(ctx, "checking the last-super-admin guard failed", slog.String("target_user_id", userID), logging.Err(err))
			writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not validate disable request", "")
			return
		}
		if stranded {
			writeProblem(w, http.StatusConflict, "https://argus.io/errors/last-super-admin",
				"Cannot disable the last remaining super-admin",
				"disabling this account would leave no active super-admin able to administer the system")
			return
		}
	}

	if _, err := rc.Tx.Exec(ctx,
		`UPDATE users SET disabled_at = now(), token_generation = token_generation + 1 WHERE id = $1`,
		userID); err != nil {
		logger.ErrorContext(ctx, "disabling a user failed", slog.String("target_user_id", userID), logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not disable user", "")
		return
	}

	if err := authz.RevokeAllRefreshTokens(ctx, rc.Tx, userID); err != nil {
		logger.ErrorContext(ctx, "revoking a disabled user's refresh tokens failed", slog.String("target_user_id", userID), logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not disable user", "")
		return
	}

	tokensRevoked, err := revokeUserPersonalTokens(ctx, rc.Tx, userID)
	if err != nil {
		logger.ErrorContext(ctx, "revoking a disabled user's AI tool tokens failed", slog.String("target_user_id", userID), logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not disable user", "")
		return
	}

	capability := authz.CapUserManage
	if err := audit.RecordEvent(ctx, rc.Tx, audit.Event{
		TenantID:        rc.TenantID,
		ActorID:         &rc.UserID,
		ActorAuthMethod: "jwt",
		SourceIP:        clientIP(r),
		Capability:      &capability,
		Outcome:         audit.OutcomeSuccess,
		Details: map[string]any{
			"action":                "disable_user",
			"userId":                userID,
			"selfDisable":           userID == rc.UserID,
			"personalTokensRevoked": tokensRevoked,
		},
	}); err != nil {
		logger.ErrorContext(ctx, "recording a user disable in the audit log failed", slog.String("target_user_id", userID), logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not record audit event", "")
		return
	}

	writeJSON(w, http.StatusOK, userLifecycleResponse{UserID: userID, Status: "disabled"})
}

// handleEnableUser is POST /api/v1/users/{id}/enable. Requires user:manage.
// The natural inverse of handleDisableUser: clears disabled_at back to NULL,
// letting handleLogin's `disabled_at IS NULL` clause succeed again for this
// user on their next login attempt. Deliberately does NOT touch sessions or
// token_generation — re-enabling isn't a security-sensitive reversal the
// way disabling is; there is nothing live to revoke (disabling already
// ended every session this user had), and the re-enabled user simply signs
// in fresh with their existing password like anyone else with no active
// session. The same goes for their personal AI tool tokens: disabling
// revoked them (revokeUserPersonalTokens) and re-enabling does not bring them
// back — the user mints new ones, so a token that leaked while the account was
// off can never quietly start working again. Idempotent-conflict like
// handleDisableUser: enabling an
// already-enabled user is rejected with 409 rather than silently
// succeeding again.
func (s *Server) handleEnableUser(w http.ResponseWriter, r *http.Request, rc *requestContext) {
	userID := r.PathValue("id")
	ctx := r.Context()

	var disabledAt *time.Time
	err := rc.Tx.QueryRow(ctx, `SELECT disabled_at FROM users WHERE id = $1 AND deleted_at IS NULL`, userID).Scan(&disabledAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			writeProblem(w, http.StatusNotFound, "https://argus.io/errors/not-found", "User not found", "")
			return
		}
		logger.ErrorContext(ctx, "looking up the user to re-enable failed", slog.String("target_user_id", userID), logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not look up user", "")
		return
	}
	if disabledAt == nil {
		writeProblem(w, http.StatusConflict, "https://argus.io/errors/invalid-state", "User is already enabled", "")
		return
	}

	if _, err := rc.Tx.Exec(ctx, `UPDATE users SET disabled_at = NULL WHERE id = $1`, userID); err != nil {
		logger.ErrorContext(ctx, "re-enabling a user failed", slog.String("target_user_id", userID), logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not enable user", "")
		return
	}

	capability := authz.CapUserManage
	if err := audit.RecordEvent(ctx, rc.Tx, audit.Event{
		TenantID:        rc.TenantID,
		ActorID:         &rc.UserID,
		ActorAuthMethod: "jwt",
		SourceIP:        clientIP(r),
		Capability:      &capability,
		Outcome:         audit.OutcomeSuccess,
		Details: map[string]any{
			"action": "enable_user",
			"userId": userID,
		},
	}); err != nil {
		logger.ErrorContext(ctx, "recording a user re-enable in the audit log failed", slog.String("target_user_id", userID), logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not record audit event", "")
		return
	}

	writeJSON(w, http.StatusOK, userLifecycleResponse{UserID: userID, Status: "enabled"})
}

// handleRemoveUser is DELETE /api/v1/users/{id}. Requires user:remove, which
// only the builtin super-admin role receives. This is deliberately a
// soft-removal, not DELETE FROM users: old audit rows, grant history, and
// "who did this?" references remain readable forever, while the removed user
// disappears from active user management and can no longer authenticate.
//
// Removing a user is stricter than disabling:
//   - it is irreversible through the API;
//   - it revokes every active role grant so the account has no live
//     authorization state if an old token ever appears;
//   - it revokes refresh tokens and bumps token_generation, killing already
//     issued sessions immediately;
//   - it revokes the user's personal AI tool tokens (revokeUserPersonalTokens);
//   - it refuses self-removal, which avoids a single-click super-admin lockout.
func (s *Server) handleRemoveUser(w http.ResponseWriter, r *http.Request, rc *requestContext) {
	userID := r.PathValue("id")
	ctx := r.Context()

	if userID == rc.UserID {
		writeProblem(w, http.StatusConflict, "https://argus.io/errors/self-removal",
			"Cannot remove your own user",
			"sign in as another super-admin before removing this account")
		return
	}

	var disabledAt *time.Time
	err := rc.Tx.QueryRow(ctx, `SELECT disabled_at FROM users WHERE id = $1 AND deleted_at IS NULL`, userID).Scan(&disabledAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			writeProblem(w, http.StatusNotFound, "https://argus.io/errors/not-found", "User not found", "")
			return
		}
		logger.ErrorContext(ctx, "looking up the user to remove failed", slog.String("target_user_id", userID), logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not look up user", "")
		return
	}

	isSuperAdmin, err := hasActiveRole(ctx, rc.Tx, userID, superAdminRole)
	if err != nil {
		logger.ErrorContext(ctx, "checking whether the user holds the super-admin role failed", slog.String("target_user_id", userID), logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not validate removal request", "")
		return
	}
	if isSuperAdmin {
		others, err := countOtherActiveSuperAdmins(ctx, rc.Tx, userID)
		if err != nil {
			logger.ErrorContext(ctx, "counting the other active super-admins failed", slog.String("target_user_id", userID), logging.Err(err))
			writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not validate removal request", "")
			return
		}
		if others == 0 {
			writeProblem(w, http.StatusConflict, "https://argus.io/errors/last-super-admin",
				"Cannot remove the last remaining super-admin",
				"removing this account would leave no active super-admin able to administer the system")
			return
		}
	}

	if _, err := rc.Tx.Exec(ctx,
		`UPDATE grants SET revoked_at = now()
		   WHERE principal_type = 'user' AND principal_id = $1 AND revoked_at IS NULL`,
		userID); err != nil {
		logger.ErrorContext(ctx, "revoking a removed user's grants failed", slog.String("target_user_id", userID), logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not remove user", "")
		return
	}

	if _, err := rc.Tx.Exec(ctx,
		`UPDATE users
		   SET deleted_at = now(),
		       disabled_at = COALESCE(disabled_at, now()),
		       must_change_password = false,
		       token_generation = token_generation + 1
		 WHERE id = $1 AND deleted_at IS NULL`,
		userID); err != nil {
		logger.ErrorContext(ctx, "marking a user as removed failed", slog.String("target_user_id", userID), logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not remove user", "")
		return
	}

	if err := authz.RevokeAllRefreshTokens(ctx, rc.Tx, userID); err != nil {
		logger.ErrorContext(ctx, "revoking a removed user's refresh tokens failed", slog.String("target_user_id", userID), logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not remove user", "")
		return
	}

	tokensRevoked, err := revokeUserPersonalTokens(ctx, rc.Tx, userID)
	if err != nil {
		logger.ErrorContext(ctx, "revoking a removed user's AI tool tokens failed", slog.String("target_user_id", userID), logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not remove user", "")
		return
	}

	capability := authz.CapUserRemove
	if err := audit.RecordEvent(ctx, rc.Tx, audit.Event{
		TenantID:        rc.TenantID,
		ActorID:         &rc.UserID,
		ActorAuthMethod: "jwt",
		SourceIP:        clientIP(r),
		Capability:      &capability,
		Outcome:         audit.OutcomeSuccess,
		Details: map[string]any{
			"action":                "remove_user",
			"userId":                userID,
			"wasDisabledBefore":     disabledAt != nil,
			"personalTokensRevoked": tokensRevoked,
		},
	}); err != nil {
		logger.ErrorContext(ctx, "recording a user removal in the audit log failed", slog.String("target_user_id", userID), logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not record audit event", "")
		return
	}

	writeJSON(w, http.StatusOK, userLifecycleResponse{UserID: userID, Status: "removed"})
}
