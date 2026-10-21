package authz

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"

	"argus/internal/logging"

	"github.com/jackc/pgx/v5"
)

// logger is internal/authz's package-local structured logger (PROJECT.md
// T22). component=authz on every record it writes.
var logger = logging.For("authz")

// Capability catalogue, per lld/02-authz-spec.md §4. Kept as named constants so a
// typo in a capability string is a compile error at every call site, not a typo
// that silently never matches anything at authorization-check time.
const (
	CapIncidentRead    = "incident:read"
	CapIncidentSilence = "incident:silence"
	// CapIncidentTriage gates the human close-out actions on an incident —
	// resolve ("this is fixed") and dismiss ("this needs no action")
	// — internal/api/incident_triage.go.
	//
	// A capability of its own rather than reusing CapRemediationReject (which
	// rejects a proposed PLAN, a narrower thing) or CapIncidentSilence (which
	// means stop notifying about it, not close it). Granted to exactly the
	// roles that already hold CapRemediationApprove: someone trusted to
	// approve a real mutation of a customer cluster is plainly trusted to
	// close an incident, which changes nothing outside this database.
	CapIncidentTriage         = "incident:triage"
	CapIncidentReanalyse      = "incident:reanalyse"
	CapAnalysisRead           = "analysis:read"
	CapRemediationApprove     = "remediation:approve"
	CapRemediationReject      = "remediation:reject"
	CapRemediationExecInplace = "remediation:execute:inplace"
	CapRemediationExecPR      = "remediation:execute:pr"
	CapRemediationRollback    = "remediation:rollback"
	CapPolicyRead             = "policy:read"
	CapPolicyWrite            = "policy:write"
	CapPolicyDryrun           = "policy:dryrun"
	CapClusterRead            = "cluster:read"
	// CapClusterInspect gates on-demand reads of live cluster detail through
	// the agent — an object's redacted YAML, its events, a pod's logs, its
	// relationships (docs/CLUSTER_INSIGHT_SPECS.md CI-S6). Separate from
	// CapClusterRead (fleet metadata) because it is a different disclosure:
	// without it a person sees only what an investigation already captured.
	CapClusterInspect    = "cluster:inspect"
	CapClusterOnboard    = "cluster:onboard"
	CapClusterAccept     = "cluster:accept"
	CapClusterDelete     = "cluster:delete"
	CapRepoRead          = "repo:read"
	CapRepoWrite         = "repo:write"
	CapIntegrationRead   = "integration:read"
	CapIntegrationWrite  = "integration:write"
	CapUserRead          = "user:read"
	CapUserManage        = "user:manage"
	CapUserRemove        = "user:remove"
	CapAuditRead         = "audit:read"
	CapSpendRead         = "spend:read"
	CapSpendManage       = "spend:manage"
	CapAgentUpgrade      = "agent:upgrade"
	CapBreakglassRequest = "breakglass:request"
	CapBreakglassApprove = "breakglass:approve"
	CapOrgSettingsWrite  = "org:settings:write"
	// CapIdentityManage gates configuring an external identity provider and
	// the IdP-group-to-role mappings that decide what a federated login is
	// authorised to do (PROJECT.md S2).
	//
	// Deliberately NOT folded into CapOrgSettingsWrite, even though an IdP is
	// nominally "a setting". lld/01-threat-model.md's asset table rates the
	// OIDC client secret an "Authentication trust anchor -- compromise =
	// ability to mint sessions", and the group mappings are strictly more
	// powerful than user:manage: assigning a role grants one person one role,
	// whereas editing a mapping re-grants everyone in a directory group at
	// once, on their next login, with no per-user action to audit. A
	// capability that can silently re-authorise a whole group deserves its
	// own gate rather than riding on the one that also sets the spend
	// ceiling.
	//
	// Reserved to super-admin alone -- see builtinRoleCapabilities below,
	// where tenant-admin's exclusion list already reserves CapOrgSettingsWrite
	// on the same reasoning.
	CapIdentityManage = "identity:manage"
	// CapRoleManage gates authoring a CUSTOM role (BACKLOG.md S3): defining a
	// new named bundle composed from this same catalogue's existing
	// capabilities (internal/api/custom_roles.go). Deliberately separate from
	// CapUserManage, which only ever ASSIGNS an already-existing role
	// (builtin or custom) to a user — composing a brand-new capability
	// bundle is the more sensitive act (it decides what a role CAN mean, not
	// just who holds one already-defined role), so it gets its own gate
	// rather than piggybacking on user:manage. Reserved to the same two
	// roles as every other role/user-administration capability; see
	// builtinRoleCapabilities below.
	CapRoleManage = "role:manage"
	// CapClusterGroupManage gates creating a cluster group and changing its
	// membership (BACKLOG.md S3, "cluster groups and team ownership" —
	// internal/api/cluster_groups.go). Modeled on cluster:onboard/accept/
	// delete's own pattern: a fleet-lifecycle action reserved to
	// super-admin/tenant-admin, never resolver (which only ever reads
	// clusters, never administers the fleet's shape).
	CapClusterGroupManage = "cluster:group:manage"
	// CapMCPUse gates holding and using a personal access token for the
	// user-facing MCP endpoint (PROJECT.md AD3, internal/api/mcp_user.go) —
	// pointing one's own AI tool at the hub.
	//
	// It grants NO data access of its own. Every tool call made with such a
	// token re-resolves the owner's grants and needs that tool's own
	// capability (cluster:read, cluster:inspect, incident:read) on the
	// cluster concerned, exactly as the REST route would. What this
	// capability decides is narrower and separate: whether this person may
	// mint a long-lived, out-of-browser credential at all. That is a
	// different risk from reading the same data in the UI (the token lives in
	// a config file on a laptop, and an AI client acts with it unattended),
	// so an organisation can withhold it from a custom role without
	// withholding the reads. Granted to every builtin role, since every
	// builtin role already holds cluster:inspect; checked again on every MCP
	// request, so removing it stops existing tokens working immediately.
	CapMCPUse = "mcp:use"
)

// builtinRoleCapabilities implements lld/02-authz-spec.md §5's permission matrix.
// "Org" vs "Scoped" is a property of the capability itself (org-only capabilities
// are marked in orgOnlyCapabilities below), not encoded separately here — a role
// simply grants a capability, and the scope stored on the grant row (or forced to
// org-wide for an org-only capability) determines where it applies.
var builtinRoleCapabilities = map[string][]string{
	"super-admin": {
		CapIncidentRead, CapIncidentSilence, CapIncidentReanalyse, CapIncidentTriage,
		CapAnalysisRead,
		CapRemediationApprove, CapRemediationReject, CapRemediationExecInplace, CapRemediationExecPR, CapRemediationRollback,
		CapPolicyRead, CapPolicyWrite, CapPolicyDryrun,
		CapClusterRead, CapClusterInspect, CapMCPUse, CapClusterOnboard, CapClusterAccept, CapClusterDelete,
		CapRepoRead, CapRepoWrite,
		CapIntegrationRead, CapIntegrationWrite,
		CapUserRead, CapUserManage, CapUserRemove,
		CapAuditRead,
		CapSpendRead, CapSpendManage,
		CapAgentUpgrade,
		CapBreakglassRequest, CapBreakglassApprove,
		CapOrgSettingsWrite,
		CapIdentityManage,
		CapRoleManage, CapClusterGroupManage,
	},
	"tenant-admin": {
		CapIncidentRead, CapIncidentSilence, CapIncidentReanalyse, CapIncidentTriage,
		CapAnalysisRead,
		CapRemediationApprove, CapRemediationReject, CapRemediationExecInplace, CapRemediationExecPR, CapRemediationRollback,
		CapPolicyRead, CapPolicyWrite, CapPolicyDryrun,
		CapClusterRead, CapClusterInspect, CapMCPUse, CapClusterOnboard, CapClusterAccept, CapClusterDelete,
		CapRepoRead, CapRepoWrite,
		CapIntegrationRead, CapIntegrationWrite,
		CapUserRead, CapUserManage,
		CapSpendRead, CapSpendManage,
		CapAgentUpgrade,
		CapBreakglassRequest, CapBreakglassApprove,
		CapRoleManage, CapClusterGroupManage,
		// Deliberately excluded: CapAuditRead, CapOrgSettingsWrite — reserved to
		// super-admin (lld/02-authz-spec.md §5's explicit note) — and
		// CapIdentityManage, on the stronger version of the same reasoning: a
		// tenant-admin can already assign roles to people, but editing an IdP
		// group mapping re-authorises everyone in a directory group at once,
		// and pointing the issuer at a different IdP would let whoever controls
		// it mint sessions here. That is a trust-anchor change, not
		// administration.
	},
	"resolver": {
		CapIncidentRead, CapIncidentSilence, CapIncidentReanalyse, CapIncidentTriage,
		CapAnalysisRead,
		CapRemediationApprove, CapRemediationReject, CapRemediationExecInplace, CapRemediationExecPR, CapRemediationRollback,
		CapPolicyRead, CapPolicyWrite, CapPolicyDryrun,
		CapClusterRead, CapClusterInspect, CapMCPUse,
		CapSpendRead,
		CapBreakglassRequest, CapBreakglassApprove,
	},
	// pr-approver: BACKLOG.md G9. "May approve a pull request, may never touch
	// a cluster in place" was expressible in the model (CapRemediationExecInplace
	// and CapRemediationExecPR are already distinct, fail-closed-checked
	// capabilities, per planApprovalGates in internal/api/approvals.go) but
	// unobtainable in the product, since every role holding CapRemediationApprove
	// also held CapRemediationExecInplace. Otherwise resolver's bundle, minus
	// CapRemediationExecInplace. CapRemediationRollback is also withheld: undoing
	// an execution always re-checks CapRemediationExecInplace too
	// (internal/api/rollback.go's scope-aware check requires both), so granting
	// Rollback alone here would be a capability that can never actually be used —
	// confusing to show as held, so it is left off rather than granted inertly.
	"pr-approver": {
		CapIncidentRead, CapIncidentSilence, CapIncidentReanalyse, CapIncidentTriage,
		CapAnalysisRead,
		CapRemediationApprove, CapRemediationReject, CapRemediationExecPR,
		CapPolicyRead, CapPolicyWrite, CapPolicyDryrun,
		CapClusterRead, CapClusterInspect, CapMCPUse,
		CapSpendRead,
		CapBreakglassRequest, CapBreakglassApprove,
	},
	"viewer": {
		CapIncidentRead, CapAnalysisRead, CapClusterRead, CapClusterInspect, CapMCPUse, CapPolicyRead,
		CapBreakglassRequest, // §5's explicit case: this is how a viewer becomes a resolver
	},
}

// IsBuiltinRole reports whether roleID names one of the fixed builtin roles
// (super-admin/tenant-admin/resolver/pr-approver/viewer).
//
// This comment used to read "the only role identifiers a grant's role_id
// column may ever hold, since this codebase has no custom-role-authoring
// feature". Both halves went stale and are corrected here 2026-09-08: there
// are five builtin roles, not four — pr-approver was added so that approving
// a pull request can be granted without granting in-place cluster execution —
// and custom-role authoring DOES exist (internal/api/custom_roles.go, gated
// on role:manage). internal/api/users.go's own header already records that.
// So role_id may hold a custom role id too, and this function is what
// distinguishes builtin from custom rather than what bounds the column.
// internal/api/users.go validates
// an admin-requested role name against this exact function rather than a
// second, driftable list of role-name strings.
func IsBuiltinRole(roleID string) bool {
	_, ok := builtinRoleCapabilities[roleID]
	return ok
}

// AllBuiltinRoleCapabilities returns the full role→capability-set catalogue
// (a defensive copy — callers can't mutate builtinRoleCapabilities through
// it) implementing lld/02-authz-spec.md §5's permission matrix. Added for
// GET /api/v1/roles (internal/api/roles.go), which backs the "Roles"
// reference tab on SettingsPage.tsx: that screen renders this exact map
// (grouped/labeled for readability on the frontend, per that code's own
// comment), so a capability change here is reflected there automatically
// instead of requiring a second, hand-maintained copy to be kept in sync.
// The returned map has no defined key order (Go maps never do); callers
// that need a display order look up by a known role id instead of
// iterating it.
func AllBuiltinRoleCapabilities() map[string][]string {
	out := make(map[string][]string, len(builtinRoleCapabilities))
	for role, caps := range builtinRoleCapabilities {
		capsCopy := make([]string, len(caps))
		copy(capsCopy, caps)
		out[role] = capsCopy
	}
	return out
}

// ValidCapabilities returns every real capability constant this build
// recognises, as a set — used to validate a custom role's capability_set
// (BACKLOG.md S3) at write time so an unknown or typo'd string is rejected
// outright rather than silently stored and silently never matching anything
// at authorization-check time. That is the same "capability catalogue ahead
// of its handlers" debt pattern BACKLOG.md P7 names for capability constants
// with no route behind them yet; this closes the mirror-image hole (a
// capability STRING with no constant behind it at all) for custom roles
// specifically.
//
// Derived from super-admin's own bundle rather than a second, hand-maintained
// list: builtinRoleCapabilities' own doc comment already establishes
// super-admin as holding the complete catalogue, so this can never silently
// drift the way a parallel list could — add a capability constant, add it to
// super-admin (already required so super-admin stays complete), and it is
// automatically valid for a custom role too.
func ValidCapabilities() map[string]bool {
	all := builtinRoleCapabilities["super-admin"]
	out := make(map[string]bool, len(all))
	for _, c := range all {
		out[c] = true
	}
	return out
}

// ValidateCustomRoleCapabilitySet checks that every entry in capSet is a
// real, known capability (ValidCapabilities above) and returns a
// deduplicated, sorted copy suitable for storage. Rejects an empty set: a
// role that grants nothing is not a role, and storing one would just be a
// confusing way to spell "no access."
func ValidateCustomRoleCapabilitySet(capSet []string) ([]string, error) {
	if len(capSet) == 0 {
		return nil, fmt.Errorf("a custom role must include at least one capability")
	}
	valid := ValidCapabilities()
	seen := make(map[string]bool, len(capSet))
	out := make([]string, 0, len(capSet))
	for _, c := range capSet {
		if !valid[c] {
			return nil, fmt.Errorf("unknown capability %q", c)
		}
		if seen[c] {
			continue
		}
		seen[c] = true
		out = append(out, c)
	}
	sort.Strings(out)
	return out, nil
}

// ResolveRoleCapabilities returns the capability set roleID names, whether it
// is one of the five fixed builtin roles or a tenant-defined custom_roles row
// (BACKLOG.md S3) — tried in that order since builtin names are a compile-time
// closed set (IsBuiltinRole) and never collide with a generated custom-role id
// (domain.PrefixCustomRole). The custom-role lookup runs in the SAME
// RLS-scoped transaction the caller already holds, so a custom role belonging
// to a different tenant is exactly as invisible here as any other
// tenant-scoped row would be — no separate tenant check is needed or made.
// ok is false, with a nil error, when roleID names neither.
func ResolveRoleCapabilities(ctx context.Context, tx pgx.Tx, roleID string) (capSet []string, ok bool, err error) {
	if caps, isBuiltin := builtinRoleCapabilities[roleID]; isBuiltin {
		out := make([]string, len(caps))
		copy(out, caps)
		return out, true, nil
	}

	var capJSON []byte
	err = tx.QueryRow(ctx, `SELECT capability_set FROM custom_roles WHERE id = $1`, roleID).Scan(&capJSON)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("look up custom role %q: %w", roleID, err)
	}
	if err := json.Unmarshal(capJSON, &capSet); err != nil {
		return nil, false, fmt.Errorf("unmarshal custom role %q capability set: %w", roleID, err)
	}
	return capSet, true, nil
}

// orgOnlyCapabilities never apply at a narrower scope than the whole organisation —
// lld/02-authz-spec.md §4's note that user/audit/org-settings management aren't
// cluster-shaped concerns.
var orgOnlyCapabilities = map[string]bool{
	CapUserManage: true, CapUserRead: true, CapUserRemove: true, CapAuditRead: true, CapIdentityManage: true, CapOrgSettingsWrite: true,
}

// Grant mirrors the persisted row (lld/05-data-model.md's `grants` table).
type Grant struct {
	RoleID        *string
	CapabilitySet []string
	Scope         Scope
}

// Scope mirrors lld/02-authz-spec.md §3's grammar.
type Scope struct {
	Type      string `json:"type"` // "Cluster" | "ClusterGroup" | "AllClusters"
	ClusterID string `json:"clusterId,omitempty"`
	GroupID   string `json:"clusterGroupId,omitempty"`
}

// EffectiveGrant is one (capability, scope) pair in a principal's resolved
// permission set — the response shape for GET /api/v1/users/me/effective-permissions
// (lld/02-authz-spec.md §6).
type EffectiveGrant struct {
	Capability string `json:"capability"`
	Scope      Scope  `json:"scope"`
}

// ResolveEffectivePermissions computes the union of every non-revoked, non-expired
// grant's (capability, scope) pairs for a user — never cached beyond the request,
// per lld/02-authz-spec.md §6 (a stale cache here is the exact "authorization
// version" problem HLD §18.2 warns about).
func ResolveEffectivePermissions(ctx context.Context, tx pgx.Tx, userID string) ([]EffectiveGrant, error) {
	rows, err := tx.Query(ctx,
		`SELECT role_id, capability_set, scope FROM grants
		 WHERE principal_type = 'user' AND principal_id = $1
		   AND revoked_at IS NULL
		   AND (expires_at IS NULL OR expires_at > now())`,
		userID)
	if err != nil {
		return nil, fmt.Errorf("query grants: %w", err)
	}

	// Drained into a slice, and rows.Close()d, BEFORE resolving any role below
	// (rather than looking up a custom role's capability set mid-iteration):
	// pgx allows only one query in flight per connection/transaction, and
	// ResolveRoleCapabilities' custom-role branch below issues its own
	// QueryRow on this same tx.
	type grantRow struct {
		roleID *string
		caps   []byte
		scope  Scope
	}
	var grantRows []grantRow
	for rows.Next() {
		var roleID *string
		var capSetJSON, scopeJSON []byte
		if err := rows.Scan(&roleID, &capSetJSON, &scopeJSON); err != nil {
			rows.Close()
			return nil, fmt.Errorf("scan grant row: %w", err)
		}
		var scope Scope
		if err := json.Unmarshal(scopeJSON, &scope); err != nil {
			rows.Close()
			return nil, fmt.Errorf("unmarshal scope: %w", err)
		}
		grantRows = append(grantRows, grantRow{roleID: roleID, caps: capSetJSON, scope: scope})
	}
	rowsErr := rows.Err()
	rows.Close()
	if rowsErr != nil {
		return nil, fmt.Errorf("iterate grants: %w", rowsErr)
	}

	var out []EffectiveGrant
	for _, gr := range grantRows {
		var caps []string
		if gr.roleID != nil {
			resolved, ok, err := ResolveRoleCapabilities(ctx, tx, *gr.roleID)
			if err != nil {
				return nil, fmt.Errorf("resolve role %q: %w", *gr.roleID, err)
			}
			if !ok {
				// The role this grant names no longer exists — a custom role
				// deleted out from under an active grant (custom_roles has no
				// FK from grants.role_id, by design: role_id also holds
				// builtin names with no row anywhere). Contributes no
				// capabilities rather than failing this user's whole login;
				// the dangling grant remains visible/revocable through the
				// normal grant-management UI, matching AccessibleClusterIDs'
				// "an empty, restricted result is a real state" precedent
				// just below rather than erroring on it.
				continue
			}
			caps = resolved
		} else {
			if err := json.Unmarshal(gr.caps, &caps); err != nil {
				return nil, fmt.Errorf("unmarshal capability_set: %w", err)
			}
		}

		for _, c := range caps {
			effScope := gr.scope
			if orgOnlyCapabilities[c] {
				effScope = Scope{Type: "AllClusters"} // org-only capabilities are never narrower than org-wide
			}
			out = append(out, EffectiveGrant{Capability: c, Scope: effScope})
		}
	}
	return out, nil
}

// HasCapability is a convenience check used by route handlers/middleware — true if
// ANY effective grant matches the capability, regardless of scope (scope-specific
// authorization for cluster-bearing routes is a separate, per-route concern once
// cluster-scoped endpoints exist — see lld/02-authz-spec.md §10.1).
func HasCapability(grants []EffectiveGrant, capability string) bool {
	for _, g := range grants {
		if g.Capability == capability {
			return true
		}
	}
	return false
}

// CapabilitiesNotHeldBy returns the capabilities that granting roleID would
// confer but that the actor's own grants do not already include — i.e. exactly
// the privileges the actor would be handing out without holding them.
//
// This exists to close a real privilege-escalation hole found in review
// (2026-08-21): `POST /users/{id}/grants` validated only that the role name was
// a known builtin, so any holder of `user:manage` could grant **any** role,
// including `super-admin`. `tenant-admin` holds `user:manage` and is
// deliberately denied `audit:read` and `org:settings:write` (see the matrix
// above), so a tenant-admin could grant themselves super-admin, log back in,
// and read the audit log and the IdP/spend configuration — defeating the
// reservation lld/02-authz-spec.md §5 states explicitly.
//
// The rule enforced by the caller is the standard no-escalation-through-
// delegation one: **you may only grant a role whose capability set you already
// hold in full.** Deliberately not special-cased to super-admin: any future
// custom role that happens to exceed the actor's own privileges is the same
// problem, and a subset check covers all of them without an allowlist to
// maintain.
//
// Returns nil for an unknown role (the caller validates that separately) and
// for a role the actor fully covers.
//
// Only ever resolves BUILTIN roles — a custom role's capability set lives in
// the database, not in this package's static catalogue, so a caller granting
// one must resolve it first (authz.ResolveRoleCapabilities) and call
// CapabilitiesNotHeldByCapSet directly with the result. This function is kept
// exactly as it was (rather than threading a tx through it) so every existing
// caller and test is unaffected.
func CapabilitiesNotHeldBy(grants []EffectiveGrant, roleID string) []string {
	roleCaps, ok := builtinRoleCapabilities[roleID]
	if !ok {
		return nil
	}
	return CapabilitiesNotHeldByCapSet(grants, roleCaps)
}

// CapabilitiesNotHeldByCapSet is CapabilitiesNotHeldBy's lower-level sibling:
// the caller has already resolved a role — builtin or custom — to its
// concrete capability set (authz.ResolveRoleCapabilities), and this applies
// the identical no-escalation-through-delegation subset check
// CapabilitiesNotHeldBy's own doc comment describes. It is what makes that
// same guarantee reach custom roles (BACKLOG.md S3), which
// CapabilitiesNotHeldBy alone cannot: it only ever looks up
// builtinRoleCapabilities. Also used when an admin CREATES or EDITS a custom
// role in the first place (internal/api/custom_roles.go) — defining a bundle
// that includes a capability the definer does not themselves hold is the
// same escalation shape one step earlier: grant the definer their own
// under-privileged role next, and they would hold something they never had.
func CapabilitiesNotHeldByCapSet(grants []EffectiveGrant, capSet []string) []string {
	held := make(map[string]struct{}, len(grants))
	for _, g := range grants {
		held[g.Capability] = struct{}{}
	}
	var missing []string
	for _, c := range capSet {
		if _, ok := held[c]; !ok {
			missing = append(missing, c)
		}
	}
	return missing
}

// Scope enforcement — lld/02-authz-spec.md §3's grammar, actually applied.
//
// # The state this replaces, which was worse than "unimplemented"
//
// The scope grammar has been in the schema, the API and the UI from the start: an
// admin can grant `remediation:approve` scoped to one cluster, the API validates
// that the cluster exists, the grant is stored, and UsersPage renders it as
// "Cluster: rke2". Nothing enforced it. `HasCapability` compared capability names
// and ignored scope entirely, and every caller of `data.SetRequestScope` passed nil
// accessible clusters, so RLS never narrowed either.
//
// So this was not a feature waiting to be built — it was a **security control that
// appeared to work**. An admin could scope a grant to one cluster, see it listed as
// scoped, and the holder could read and act across the whole fleet. BACKLOG.md S1
// described it as a multi-team prerequisite; the more accurate description is a
// false guarantee in a screen operators trust.
//
// # Two halves, because either alone is insufficient
//
// **Reading** is bounded by RLS, via AccessibleClusterIDs: a caller cannot see rows
// for a cluster no grant of theirs reaches. **Acting** is bounded by
// HasCapabilityForCluster: holding a capability on cluster X is not holding it on
// cluster Y. RLS alone would let a scoped principal act on a cluster it cannot see
// (the write would be refused by the policy, but as an opaque error rather than a
// 403 with a reason); the capability check alone would leave the data readable.

// AccessibleClusterIDs resolves which clusters a principal's grants reach.
//
// unrestricted=true means "every cluster" and the caller should pass nil to
// data.SetRequestScope — which is what any AllClusters grant produces, and
// therefore what every existing installation produces today. That is the property
// that makes this safe to ship: behaviour is unchanged until somebody creates a
// narrower grant.
//
// An unresolvable scope type returns an error rather than contributing nothing.
// Contributing nothing would silently deny a principal all access, and widening on
// it would silently grant everything; both are worse than a 500 that says the grant
// cannot be interpreted.
//
// ClusterGroup (BACKLOG.md S3) is now resolved for real, via
// clusterGroupMemberIDs — migration 000078's cluster_group_members, queried
// on the SAME tx the caller already holds. It takes ctx/tx for exactly this:
// before this, the function was pure. It runs inside
// internal/api/middleware.go's requireAuth BEFORE app.accessible_cluster_ids
// is narrowed (still whatever the prior SetRequestScope call left it as —
// nil/tenant-only at this point in the request), which is why
// cluster_group_members is tenant-scoped rather than cluster_id-scoped: see
// migration 000078's own comment for why the obvious cluster_id-keyed policy
// would be circular here (it would need accessible_cluster_ids to already be
// the value this function is computing).
func AccessibleClusterIDs(ctx context.Context, tx pgx.Tx, grants []EffectiveGrant) (ids []string, unrestricted bool, err error) {
	seen := map[string]bool{}
	for _, g := range grants {
		switch g.Scope.Type {
		case "AllClusters":
			return nil, true, nil
		case "Cluster":
			if g.Scope.ClusterID == "" {
				return nil, false, fmt.Errorf("a Cluster-scoped grant for %q names no cluster", g.Capability)
			}
			seen[g.Scope.ClusterID] = true
		case "ClusterGroup":
			if g.Scope.GroupID == "" {
				return nil, false, fmt.Errorf("a ClusterGroup-scoped grant for %q names no cluster group", g.Capability)
			}
			members, err := clusterGroupMemberIDs(ctx, tx, g.Scope.GroupID)
			if err != nil {
				return nil, false, fmt.Errorf("resolve cluster group %q for %q: %w", g.Scope.GroupID, g.Capability, err)
			}
			// A group with no members (or a group id nothing in this tenant
			// recognises — cluster_group_members' own RLS policy already
			// makes a foreign tenant's group id resolve to zero rows, same as
			// any other tenant-scoped lookup) contributes nothing, exactly
			// like the "no grants" case below: an empty, restricted result is
			// a real state, not an error.
			for _, id := range members {
				seen[id] = true
			}
		default:
			return nil, false, fmt.Errorf("grant for %q has unrecognised scope type %q", g.Capability, g.Scope.Type)
		}
	}
	for id := range seen {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	// An empty, restricted result is a real state: a principal with grants that
	// name no cluster reaches nothing. Returning it as such (rather than as
	// unrestricted) is what keeps "no grants" from meaning "all access".
	return ids, false, nil
}

// clusterGroupMemberIDs returns the cluster ids currently assigned to
// groupID (migration 000078's cluster_group_members, membership_changed
// audited at internal/api/cluster_groups.go's write side). Deliberately a
// plain SELECT with no existence check on cluster_groups itself: an unknown
// or foreign-tenant group id simply returns zero rows via
// cluster_group_members' own tenant-scoped RLS policy, and "resolves to
// nothing" is exactly the honest answer AccessibleClusterIDs' caller wants
// for that case.
func clusterGroupMemberIDs(ctx context.Context, tx pgx.Tx, groupID string) ([]string, error) {
	rows, err := tx.Query(ctx, `SELECT cluster_id FROM cluster_group_members WHERE cluster_group_id = $1`, groupID)
	if err != nil {
		return nil, fmt.Errorf("query cluster_group_members: %w", err)
	}
	defer rows.Close()

	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("scan cluster_group_members row: %w", err)
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate cluster_group_members: %w", err)
	}
	return ids, nil
}

// ScopeIncludesCluster reports whether scope covers clusterID — the same
// question AccessibleClusterIDs/HasCapabilityForCluster answer for a GRANT's
// scope, exposed directly for a caller matching something else's stored
// Scope against one specific cluster (BACKLOG.md F30: scm.ObjectMapping's
// own Scope field, checked at resolution time against the incident's
// cluster) rather than against a principal's whole grant set.
//
// Reuses clusterGroupMemberIDs rather than duplicating the membership query
// — this is the one other place "does this scope reach this cluster" is
// asked, and it should stay asking it the same way.
func ScopeIncludesCluster(ctx context.Context, tx pgx.Tx, scope Scope, clusterID string) (bool, error) {
	switch scope.Type {
	case "", "AllClusters":
		// An empty Type is F30's own backward-compatibility default: every
		// ObjectMapping written before Scope existed, and every one written
		// today through a caller that has no scope picker of its own, means
		// exactly what it always did — matches on every cluster. Treating
		// "" as an error here would turn every mapping registered before
		// this field existed into a silent fleet-wide match failure.
		return true, nil
	case "Cluster":
		return scope.ClusterID != "" && scope.ClusterID == clusterID, nil
	case "ClusterGroup":
		if scope.GroupID == "" {
			return false, nil
		}
		members, err := clusterGroupMemberIDs(ctx, tx, scope.GroupID)
		if err != nil {
			return false, fmt.Errorf("resolve cluster group %q: %w", scope.GroupID, err)
		}
		for _, id := range members {
			if id == clusterID {
				return true, nil
			}
		}
		return false, nil
	default:
		return false, fmt.Errorf("scope has unrecognised type %q", scope.Type)
	}
}

// HasCapabilityForCluster reports whether the principal holds capability on the
// given cluster.
//
// clusterID may be empty for an org-level action, in which case an AllClusters
// grant is required: a principal scoped to one cluster (or one cluster group)
// does not thereby hold an org-wide capability. That direction is the one
// worth being careful about — treating "" as a wildcard would turn every
// cluster-scoped grant into a fleet-wide one for any route that happens not
// to know its cluster.
//
// Takes ctx/tx because a ClusterGroup-scoped grant needs a membership lookup
// to answer this (reusing ScopeIncludesCluster's query rather than a third
// copy of it — see that function's own doc comment). Before this, a grant
// scoped to a ClusterGroup matched neither the "AllClusters" nor "Cluster"
// case here, so it fell through to false for every cluster in the group —
// AccessibleClusterIDs correctly resolved group membership for READING (the
// grant appeared in listings), but every write-side gate that calls this
// function denied it outright. Fails closed, so not an escalation, but a
// real correctness gap in exactly the "two halves" scope model this file's
// header comment describes.
func HasCapabilityForCluster(ctx context.Context, tx pgx.Tx, grants []EffectiveGrant, capability, clusterID string) (bool, error) {
	for _, g := range grants {
		if g.Capability != capability {
			continue
		}
		switch g.Scope.Type {
		case "AllClusters":
			return true, nil
		case "Cluster":
			if clusterID != "" && g.Scope.ClusterID == clusterID {
				return true, nil
			}
		case "ClusterGroup":
			if clusterID == "" || g.Scope.GroupID == "" {
				continue
			}
			included, err := ScopeIncludesCluster(ctx, tx, g.Scope, clusterID)
			if err != nil {
				return false, fmt.Errorf("resolve cluster group %q for %q: %w", g.Scope.GroupID, capability, err)
			}
			if included {
				return true, nil
			}
		}
	}
	return false, nil
}
