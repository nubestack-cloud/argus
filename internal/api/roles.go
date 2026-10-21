package api

import (
	"net/http"

	"argus/internal/authz"
)

// This file implements GET /api/v1/roles — a small, read-only reference
// listing every builtin role and the exact capabilities it carries, sourced
// directly from internal/authz/permissions.go's builtinRoleCapabilities (via
// authz.AllBuiltinRoleCapabilities), which is lld/02-authz-spec.md §5's
// actual permission matrix. It exists to back the "Roles" tab on
// SettingsPage.tsx (web/src/pages/SettingsPage.tsx): before this endpoint,
// the only place a role's capabilities were explained in the UI was a
// hand-transcribed, hover-only tooltip on an already-assigned role badge
// (UsersPage.tsx's ROLE_DESCRIPTIONS) — no standalone, browsable place to
// see all five roles side by side. Rather than hand-transcribing a SECOND
// copy of the same matrix into the frontend (which is exactly the kind of
// copy that silently drifts the moment a capability is added, removed, or
// moved between roles — see ROLE_DESCRIPTIONS' own doc comment admitting
// this tradeoff), this endpoint returns the raw capability strings straight
// from the Go source of truth; only the human-readable grouping/labels for
// each capability string are a hand-maintained frontend concern (a
// presentation detail, not the authorization data itself), documented as
// such where that mapping lives.
//
// Requires only requireAuth — no specific capability gate. This mirrors GET
// /api/v1/users/me/effective-permissions (auth.go)'s precedent: knowing
// what a role CAN do is not itself sensitive (every capability a user
// personally holds is already visible to them via effective-permissions),
// and every plausible reader of this reference — someone deciding what to
// grant another user, or wondering why they personally can't do something —
// benefits from seeing the full matrix regardless of which capabilities
// they hold themselves. Deny-by-default still applies to every actual
// action; this route only ever describes the catalogue, never grants or
// exercises anything.
type roleView struct {
	Capabilities []string `json:"capabilities"`
}

func (s *Server) handleListRoles(w http.ResponseWriter, r *http.Request, rc *requestContext) {
	all := authz.AllBuiltinRoleCapabilities()
	roles := make(map[string]roleView, len(all))
	for id, caps := range all {
		roles[id] = roleView{Capabilities: caps}
	}
	writeJSON(w, http.StatusOK, map[string]any{"roles": roles})
}
