package api

import (
	"encoding/json"
	"errors"
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

// This file implements custom-role authoring (BACKLOG.md S3): an admin
// composes an arbitrary subset of internal/authz/permissions.go's EXISTING
// capability catalogue into a new, named, reusable bundle — never a new
// permission. It is the feature internal/api/users.go's own doc comment
// (2026-08-22) and internal/authz.IsBuiltinRole's doc comment both flagged
// as deliberately out of scope at the time ("no custom-role authoring... a
// grant's role is always one of the 5 fixed builtin role names"); both are
// now superseded by this file.
//
// A custom role is assigned to a user through the EXACT SAME mechanism a
// builtin role already is — POST /api/v1/users/{id}/grants' `role` field
// (internal/api/users.go), which now resolves via
// authz.ResolveRoleCapabilities (builtin first, then this table) rather than
// authz.IsBuiltinRole alone. There is no second, parallel assignment route.

// customRoleView is one custom_roles row as returned by the API.
type customRoleView struct {
	ID           string   `json:"id"`
	Name         string   `json:"name"`
	Capabilities []string `json:"capabilities"`
	CreatedBy    string   `json:"createdBy"`
	CreatedAt    string   `json:"createdAt"`
}

func scanCustomRoleViewRow(row pgx.Row) (customRoleView, error) {
	var v customRoleView
	var capJSON []byte
	var createdAt time.Time
	if err := row.Scan(&v.ID, &v.Name, &capJSON, &v.CreatedBy, &createdAt); err != nil {
		return customRoleView{}, err
	}
	if err := json.Unmarshal(capJSON, &v.Capabilities); err != nil {
		return customRoleView{}, err
	}
	v.CreatedAt = formatRFC3339(createdAt)
	return v, nil
}

// handleListCustomRoles is GET /api/v1/custom-roles. Requires user:read —
// the same floor GET /api/v1/users already uses: a custom role's name and
// capability set is exactly the kind of thing someone deciding what to grant
// (or wondering why they can't do something) needs to see, and it is no more
// sensitive than the grants list that route already returns holding the same
// capability names. Unlike GET /api/v1/roles (the builtin reference,
// ungated), this returns real tenant-authored rows, so it is gated like any
// other tenant data.
func (s *Server) handleListCustomRoles(w http.ResponseWriter, r *http.Request, rc *requestContext) {
	ctx := r.Context()
	rows, err := rc.Tx.Query(ctx,
		`SELECT id, name, capability_set, created_by, created_at FROM custom_roles ORDER BY lower(name)`)
	if err != nil {
		logger.ErrorContext(ctx, "querying custom roles failed", logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not list custom roles", "")
		return
	}
	defer rows.Close()

	roles := []customRoleView{}
	for rows.Next() {
		v, err := scanCustomRoleViewRow(rows)
		if err != nil {
			logger.ErrorContext(ctx, "scanning a custom-role row failed", logging.Err(err))
			writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not list custom roles", "")
			return
		}
		roles = append(roles, v)
	}
	if err := rows.Err(); err != nil {
		logger.ErrorContext(ctx, "iterating the custom-role rows failed", logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not list custom roles", "")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"roles": roles})
}

type createCustomRoleRequest struct {
	Name         string   `json:"name"`
	Capabilities []string `json:"capabilities"`
}

// handleCreateCustomRole is POST /api/v1/custom-roles. Requires role:manage.
//
// Two independent checks on the requested capability set, and both matter:
//   - authz.ValidateCustomRoleCapabilitySet rejects any string that is not a
//     REAL, current capability (BACKLOG.md S3's explicit requirement — never
//     accept an arbitrary/typo'd string, the same "capability catalogue
//     ahead of its handlers" debt pattern BACKLOG.md P7 names).
//   - authz.CapabilitiesNotHeldByCapSet rejects a set that would confer
//     something the CREATOR does not themselves hold — the identical
//     no-escalation-through-delegation rule handleCreateGrant already
//     enforces for granting a role, applied one step earlier: composing a
//     bundle you don't fully hold and handing it to someone else (including
//     yourself, later) is the same escalation shape.
func (s *Server) handleCreateCustomRole(w http.ResponseWriter, r *http.Request, rc *requestContext) {
	var req createCustomRoleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeProblem(w, http.StatusBadRequest, "https://argus.io/errors/malformed-request", "Malformed request body", err.Error())
		return
	}

	name := strings.TrimSpace(req.Name)
	if name == "" {
		writeProblem(w, http.StatusBadRequest, "https://argus.io/errors/invalid-request", "A role name is required", "")
		return
	}
	if authz.IsBuiltinRole(name) {
		writeProblem(w, http.StatusBadRequest, "https://argus.io/errors/invalid-request",
			"That name is reserved", "a custom role may not reuse one of the five builtin role names")
		return
	}

	capSet, err := authz.ValidateCustomRoleCapabilitySet(req.Capabilities)
	if err != nil {
		writeProblem(w, http.StatusBadRequest, "https://argus.io/errors/invalid-request", "Invalid capability set", err.Error())
		return
	}

	if missing := authz.CapabilitiesNotHeldByCapSet(rc.Grants, capSet); len(missing) > 0 {
		s.recordCapabilityDenial(r.Context(), rc, missing[0], clientIP(r))
		writeProblem(w, http.StatusForbidden, "https://argus.io/errors/scope-denied",
			"Cannot create a role with more privileges than you hold",
			"the requested capability set includes "+missing[0]+", which you do not hold — creating this role would let it later be granted to yourself or someone else, conferring a privilege you never had")
		return
	}

	ctx := r.Context()
	capJSON, err := json.Marshal(capSet)
	if err != nil {
		logger.ErrorContext(ctx, "marshalling the new custom role's capability set failed", logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not create custom role", "")
		return
	}

	id := domain.NewID(domain.PrefixCustomRole)
	var createdAt time.Time
	err = rc.Tx.QueryRow(ctx,
		`INSERT INTO custom_roles (id, tenant_id, name, capability_set, created_by)
		 VALUES ($1, $2, $3, $4, $5) RETURNING created_at`,
		id, rc.TenantID, name, capJSON, rc.UserID).Scan(&createdAt)
	if err != nil {
		if isUniqueViolation(err) {
			writeProblem(w, http.StatusConflict, "https://argus.io/errors/already-exists", "A custom role with this name already exists", "")
			return
		}
		logger.ErrorContext(ctx, "inserting the custom role failed", logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not create custom role", "")
		return
	}

	capability := authz.CapRoleManage
	if err := audit.RecordEvent(ctx, rc.Tx, audit.Event{
		TenantID:        rc.TenantID,
		ActorID:         &rc.UserID,
		ActorAuthMethod: "jwt",
		SourceIP:        clientIP(r),
		Capability:      &capability,
		Outcome:         audit.OutcomeSuccess,
		Details: map[string]any{
			"action":       "create_custom_role",
			"roleId":       id,
			"name":         name,
			"capabilities": capSet,
		},
	}); err != nil {
		logger.ErrorContext(ctx, "recording a custom-role creation in the audit log failed", logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not record audit event", "")
		return
	}

	writeJSON(w, http.StatusCreated, customRoleView{
		ID: id, Name: name, Capabilities: capSet, CreatedBy: rc.UserID, CreatedAt: formatRFC3339(createdAt),
	})
}

type updateCustomRoleRequest struct {
	Capabilities []string `json:"capabilities"`
}

// handleUpdateCustomRole is PUT /api/v1/custom-roles/{id}. Requires
// role:manage. The name is immutable by this route (a rename would be
// harmless on its own, but is out of this round's scope — every grant
// referencing the role holds its id, not its name, so nothing depends on
// this); only the capability set can change, subject to the identical two
// checks handleCreateCustomRole applies.
func (s *Server) handleUpdateCustomRole(w http.ResponseWriter, r *http.Request, rc *requestContext) {
	id := r.PathValue("id")
	ctx := r.Context()

	var existingName string
	if err := rc.Tx.QueryRow(ctx, `SELECT name FROM custom_roles WHERE id = $1`, id).Scan(&existingName); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			writeProblem(w, http.StatusNotFound, "https://argus.io/errors/not-found", "Custom role not found", "")
			return
		}
		logger.ErrorContext(ctx, "looking up the custom role to update failed", slog.String("role_id", id), logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not look up custom role", "")
		return
	}

	var req updateCustomRoleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeProblem(w, http.StatusBadRequest, "https://argus.io/errors/malformed-request", "Malformed request body", err.Error())
		return
	}

	capSet, err := authz.ValidateCustomRoleCapabilitySet(req.Capabilities)
	if err != nil {
		writeProblem(w, http.StatusBadRequest, "https://argus.io/errors/invalid-request", "Invalid capability set", err.Error())
		return
	}

	if missing := authz.CapabilitiesNotHeldByCapSet(rc.Grants, capSet); len(missing) > 0 {
		s.recordCapabilityDenial(ctx, rc, missing[0], clientIP(r))
		writeProblem(w, http.StatusForbidden, "https://argus.io/errors/scope-denied",
			"Cannot expand a role to include more privileges than you hold",
			"the requested capability set includes "+missing[0]+", which you do not hold")
		return
	}

	capJSON, err := json.Marshal(capSet)
	if err != nil {
		logger.ErrorContext(ctx, "marshalling the custom role's capability set failed", slog.String("role_id", id), logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not update custom role", "")
		return
	}
	if _, err := rc.Tx.Exec(ctx, `UPDATE custom_roles SET capability_set = $1 WHERE id = $2`, capJSON, id); err != nil {
		logger.ErrorContext(ctx, "updating the custom role failed", slog.String("role_id", id), logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not update custom role", "")
		return
	}

	capability := authz.CapRoleManage
	if err := audit.RecordEvent(ctx, rc.Tx, audit.Event{
		TenantID:        rc.TenantID,
		ActorID:         &rc.UserID,
		ActorAuthMethod: "jwt",
		SourceIP:        clientIP(r),
		Capability:      &capability,
		Outcome:         audit.OutcomeSuccess,
		Details: map[string]any{
			"action":       "update_custom_role",
			"roleId":       id,
			"capabilities": capSet,
		},
	}); err != nil {
		logger.ErrorContext(ctx, "recording a custom-role update in the audit log failed", logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not record audit event", "")
		return
	}

	writeJSON(w, http.StatusOK, customRoleView{ID: id, Name: existingName, Capabilities: capSet})
}

// handleDeleteCustomRole is DELETE /api/v1/custom-roles/{id}. Requires
// role:manage. Refuses to delete a role while any non-revoked, non-expired
// grant still names it (409) rather than silently orphaning those grants —
// the same caution lld/02-authz-spec.md §7 names for deleting an IdP
// connector a live identity_mapping still references. A caller who really
// wants to remove access granted through this role must revoke those grants
// first (DELETE /api/v1/users/{id}/grants/{grantId}), which is the existing,
// audited path for that.
func (s *Server) handleDeleteCustomRole(w http.ResponseWriter, r *http.Request, rc *requestContext) {
	id := r.PathValue("id")
	ctx := r.Context()

	var name string
	if err := rc.Tx.QueryRow(ctx, `SELECT name FROM custom_roles WHERE id = $1`, id).Scan(&name); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			writeProblem(w, http.StatusNotFound, "https://argus.io/errors/not-found", "Custom role not found", "")
			return
		}
		logger.ErrorContext(ctx, "looking up the custom role to delete failed", slog.String("role_id", id), logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not look up custom role", "")
		return
	}

	var inUse bool
	if err := rc.Tx.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM grants WHERE role_id = $1 AND `+activeGrantsWhere+`)`, id).Scan(&inUse); err != nil {
		logger.ErrorContext(ctx, "checking whether the custom role is in use failed", slog.String("role_id", id), logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not check whether the role is in use", "")
		return
	}
	if inUse {
		writeProblem(w, http.StatusConflict, "https://argus.io/errors/in-use",
			"This role is still granted to at least one user",
			"revoke every grant referencing it first, then delete it")
		return
	}

	if _, err := rc.Tx.Exec(ctx, `DELETE FROM custom_roles WHERE id = $1`, id); err != nil {
		logger.ErrorContext(ctx, "deleting the custom role failed", slog.String("role_id", id), logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not delete custom role", "")
		return
	}

	capability := authz.CapRoleManage
	if err := audit.RecordEvent(ctx, rc.Tx, audit.Event{
		TenantID:        rc.TenantID,
		ActorID:         &rc.UserID,
		ActorAuthMethod: "jwt",
		SourceIP:        clientIP(r),
		Capability:      &capability,
		Outcome:         audit.OutcomeSuccess,
		Details:         map[string]any{"action": "delete_custom_role", "roleId": id, "name": name},
	}); err != nil {
		logger.ErrorContext(ctx, "recording a custom-role deletion in the audit log failed", logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not record audit event", "")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"roleId": id, "status": "deleted"})
}
