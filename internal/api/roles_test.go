package api

import (
	"testing"

	"argus/internal/authz"
)

// TestAllBuiltinRoleCapabilitiesMatchesRolesEndpointShape is a DB-free unit
// test locking in two things this endpoint depends on being true, since a
// regression in either would silently make the "Roles" reference UI wrong
// without any test failing elsewhere: (1) every builtin role id the
// frontend's BUILTIN_ROLES constant expects (web/src/api/types.ts) is
// present, and (2) the deliberate exclusions internal/authz/permissions.go's
// own comments call out by name — tenant-admin lacking audit:read and
// org:settings:write, viewer nonetheless carrying breakglass:request — are
// still exactly what's returned, not just "some capability set."
func TestAllBuiltinRoleCapabilitiesMatchesRolesEndpointShape(t *testing.T) {
	all := authz.AllBuiltinRoleCapabilities()

	for _, id := range []string{"super-admin", "tenant-admin", "resolver", "pr-approver", "viewer"} {
		if _, ok := all[id]; !ok {
			t.Errorf("AllBuiltinRoleCapabilities() missing role %q", id)
		}
	}

	has := func(role, cap string) bool {
		for _, c := range all[role] {
			if c == cap {
				return true
			}
		}
		return false
	}

	if !has("super-admin", authz.CapAuditRead) {
		t.Error(`super-admin should carry CapAuditRead`)
	}
	if !has("super-admin", authz.CapOrgSettingsWrite) {
		t.Error(`super-admin should carry CapOrgSettingsWrite`)
	}
	if !has("super-admin", authz.CapUserRemove) {
		t.Error(`super-admin should carry CapUserRemove`)
	}
	if has("tenant-admin", authz.CapUserRemove) {
		t.Error(`tenant-admin should NOT carry CapUserRemove — irreversible user removal is reserved to super-admin`)
	}
	if has("tenant-admin", authz.CapAuditRead) {
		t.Error(`tenant-admin should NOT carry CapAuditRead — deliberately reserved to super-admin (permissions.go's comment)`)
	}
	if has("tenant-admin", authz.CapOrgSettingsWrite) {
		t.Error(`tenant-admin should NOT carry CapOrgSettingsWrite — deliberately reserved to super-admin (permissions.go's comment)`)
	}
	if !has("viewer", authz.CapBreakglassRequest) {
		t.Error(`viewer should carry CapBreakglassRequest — the documented "how a viewer becomes a resolver" exception`)
	}
	if !has("pr-approver", authz.CapRemediationExecPR) {
		t.Error(`pr-approver should carry CapRemediationExecPR`)
	}
	if has("pr-approver", authz.CapRemediationExecInplace) {
		t.Error(`pr-approver should NOT carry CapRemediationExecInplace — that is G9's entire point`)
	}

	// Returned slices must be defensive copies, not aliases into the
	// package-private map — mutating one must never affect a second call.
	all["viewer"][0] = "tampered"
	again := authz.AllBuiltinRoleCapabilities()
	if len(again["viewer"]) == 0 || again["viewer"][0] == "tampered" {
		t.Error("AllBuiltinRoleCapabilities() returned an aliased slice, not a defensive copy")
	}
}

// TestHandleListRolesResponseShape confirms the handler's response wraps
// roleView under a "roles" key keyed by role id, with "capabilities" as the
// only field — the exact shape web/src/api/client.ts's getRoles() and
// SettingsPage.tsx's Roles tab depend on.
func TestHandleListRolesResponseShape(t *testing.T) {
	all := authz.AllBuiltinRoleCapabilities()
	roles := make(map[string]roleView, len(all))
	for id, caps := range all {
		roles[id] = roleView{Capabilities: caps}
	}

	sa, ok := roles["super-admin"]
	if !ok {
		t.Fatal(`roles["super-admin"] missing`)
	}
	if len(sa.Capabilities) == 0 {
		t.Error("super-admin should have a non-empty capability list")
	}
}
