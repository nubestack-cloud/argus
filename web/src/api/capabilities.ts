// Named capability constants, mirroring internal/authz/permissions.go's
// catalogue — only the subset the UI currently checks. Never inline a
// capability string literal at a call site (same discipline
// argus-context's implementation-conventions section requires on the Go
// side); add to this file as new screens need new checks.
export const CAP_CLUSTER_READ = 'cluster:read'
export const CAP_CLUSTER_INSPECT = 'cluster:inspect'
export const CAP_CLUSTER_ONBOARD = 'cluster:onboard'
export const CAP_CLUSTER_ACCEPT = 'cluster:accept'
export const CAP_CLUSTER_DELETE = 'cluster:delete'

// Granted to every non-super-admin role already (authz-spec §5's permission
// matrix) — nothing on IncidentsPage/IncidentDetailPage currently gates on
// this (no action buttons exist yet, only reads), but it's declared here
// now, unused, the same way CAP_CLUSTER_READ already is, so it's ready the
// moment a future action needs it.
export const CAP_INCIDENT_READ = 'incident:read'

// Reading an AI investigation's own output. Paired with CAP_INCIDENT_READ by
// GET /api/v1/insights and GET /api/v1/changes, both of which genuinely read
// analyses as well as incidents. Every builtin role holding one holds the
// other (internal/authz/permissions.go's builtinRoleCapabilities), so in
// practice the pair changes nothing about who can see those screens — it
// documents the real dependency instead of picking one capability arbitrarily.
export const CAP_ANALYSIS_READ = 'analysis:read'

// Gates the "Analyze" button (IncidentDetailPage) — granted to super-admin/
// tenant-admin/resolver, not viewer (authz-spec §5's matrix).
export const CAP_INCIDENT_REANALYSE = 'incident:reanalyse'

// Gates the Resolve/Dismiss controls (IncidentDetailPage) — the human
// close-out actions. Granted to super-admin/tenant-admin/resolver, not
// viewer. Separate from remediation:approve because most incidents never
// produce a plan to approve, yet all of them eventually need closing.
export const CAP_INCIDENT_TRIAGE = 'incident:triage'

// Gates the "Tolerate…" action (IncidentDetailPage) and the tolerations
// management surface (TolerationsPage: list + remove) — the "mute switch"
// declared in internal/authz/permissions.go since the first authz pass and
// granted to the same roles as CAP_INCIDENT_TRIAGE (super-admin/tenant-admin/
// resolver, not viewer).
export const CAP_INCIDENT_SILENCE = 'incident:silence'

// BACKLOG L1's capability. Defined in internal/authz since the start and granted

// Gates both reading and writing org-level settings (SettingsPage) — there
// is deliberately no separate read capability, and this one is super-admin
// only, not even tenant-admin.
export const CAP_ORG_SETTINGS_WRITE = 'org:settings:write'

// Gates the Identity provider section of SettingsPage — configuring the OIDC
// provider and the group-to-role mappings (PROJECT.md S2). Super-admin only,
// and deliberately NOT the same capability as CAP_ORG_SETTINGS_WRITE even
// though it lives on the same page: editing a group mapping re-authorises
// everyone in a directory group on their next login, which is a strictly
// bigger act than any other setting on that screen. See
// internal/authz/permissions.go's CapIdentityManage for the full reasoning.
export const CAP_IDENTITY_MANAGE = 'identity:manage'

// Gates AuditLogPage (both GET /api/v1/audit-events and
// GET /api/v1/audit-events/{id}) — like CAP_ORG_SETTINGS_WRITE, deliberately
// super-admin only, excluded even from tenant-admin (authz/permissions.go's
// builtinRoleCapabilities, per lld/02-authz-spec.md §5's explicit note).
export const CAP_AUDIT_READ = 'audit:read'

// Gates UsersPage. Unlike settings, user management DOES have a separate
// read capability — CAP_USER_READ gates seeing the page/list at all;
// CAP_USER_MANAGE additionally gates every write action (create user,
// create grant, revoke grant, enable/disable) within it, disabled-not-hidden
// per lld/11-ui-design.md §6. Both are granted to super-admin/tenant-admin,
// neither to resolver/viewer (authz-spec §5's matrix). CAP_USER_REMOVE is
// intentionally narrower: only super-admin receives it, because removal is
// an irreversible admin-console lifecycle transition.
export const CAP_USER_READ = 'user:read'
export const CAP_USER_MANAGE = 'user:manage'
export const CAP_USER_REMOVE = 'user:remove'

// Gates authoring/editing/deleting a CUSTOM role (SettingsPage's "Roles &
// access" tab, CustomRolesCard.tsx — BACKLOG.md S3). Deliberately separate
// from CAP_USER_MANAGE, which only ever ASSIGNS an already-existing role
// (builtin or custom) to a user — composing a brand-new capability bundle is
// the more sensitive act, so it gets its own gate. Granted to super-admin/
// tenant-admin only, same as CAP_USER_MANAGE (internal/authz/permissions.go).
export const CAP_ROLE_MANAGE = 'role:manage'

// Gates creating a cluster group and changing its membership
// (SettingsPage's ClusterGroupsCard.tsx — BACKLOG.md S3). Reading the list
// only needs CAP_CLUSTER_READ, matching GET /api/v1/clusters' own floor.
// Modeled on CAP_CLUSTER_ONBOARD/ACCEPT/DELETE's own "fleet-lifecycle
// action, admin only" gating — never granted to resolver/pr-approver/viewer.
export const CAP_CLUSTER_GROUP_MANAGE = 'cluster:group:manage'

// Gates creating a personal access token for the MCP endpoint (Settings →
// AI tools & tokens, PROJECT.md AD3). Grants no data access of its own: every
// tool call made with such a token needs that tool's own capability. Listing
// and revoking your own tokens need no capability at all, so losing this
// never strands a token you can no longer revoke.
export const CAP_MCP_USE = 'mcp:use'

// Gates ApprovalsPage. CAP_REMEDIATION_APPROVE gates BOTH viewing the queue
// (GET /api/v1/approvals) and the Approve action — internal/api/approvals.go's
// own doc comment explains why one capability covers both here, matching
// CAP_ORG_SETTINGS_WRITE's precedent. CAP_REMEDIATION_REJECT gates Reject
// specifically — a distinct capability, though today's five builtin roles
// always grant both together (authz-spec §5's matrix). Both granted to
// resolver/pr-approver/tenant-admin/super-admin, neither to viewer.
export const CAP_REMEDIATION_APPROVE = 'remediation:approve'
export const CAP_REMEDIATION_REJECT = 'remediation:reject'

// Gates GET /api/v1/spend/today (InsightsPage's "Today's spend" tile) —
// deliberately narrower than CAP_ORG_SETTINGS_WRITE, which gates the "cost"
// section of SettingsPage that actually configures pricing/the daily spend
// ceiling: granted to resolver/tenant-admin/super-admin, not viewer
// (authz-spec §5's matrix), so a resolver can see today's real spend
// without needing full admin-settings access. The first real use anywhere
// in this codebase of a capability that's been declared in
// internal/authz/permissions.go's catalogue since the very first authz
// pass, but never implemented by anything until now.
export const CAP_SPEND_READ = 'spend:read'

// Gates the Git repositories tab in Settings (RepositoriesCard): CAP_REPO_READ
// lists the bindings, CAP_REPO_WRITE registers, checks and removes them. Both
// have been in internal/authz/permissions.go's catalogue since the first authz
// pass with nothing behind them; the repository-binding surface is what they
// now gate.
export const CAP_REPO_READ = 'repo:read'
export const CAP_REPO_WRITE = 'repo:write'

// Gates "Propose this change as a pull request" on IncidentDetailPage. The
// route requires all THREE together (internal/api/repository_change.go's header
// says why): repo:write because it writes to a registered repository,
// remediation:approve because it authorises a remediation like every other
// approval route, and this one because it is the PR channel's own execution
// capability. lld/02-authz-spec.md §6's headline example is a principal who
// "may approve PRs but never touch a cluster in place" — reusing the same
// capability approvals.go maps ActionOpenPR to is what keeps that grant
// meaningful now that the PR channel does something.
export const CAP_REMEDIATION_EXECUTE_PR = 'remediation:execute:pr'

// Gates the Undo control on an executed remediation (RemediationPlanCard).
// The route requires BOTH: remediation:rollback because reversing a change is
// its own decision, and remediation:execute:inplace because it writes to a live
// cluster — lld/02-authz-spec.md §6's "may approve PRs but never touch a cluster
// in place" grant has to hold in the undo direction too, or it is only true
// going forwards.
//
// CAP_REMEDIATION_ROLLBACK has been in internal/authz's catalogue since the
// first authz pass, granted to resolver/tenant-admin/super-admin, and enforced
// by no handler until the rollback executor shipped.
export const CAP_REMEDIATION_ROLLBACK = 'remediation:rollback'
export const CAP_REMEDIATION_EXECUTE_INPLACE = 'remediation:execute:inplace'
export const CAP_AGENT_UPGRADE = 'agent:upgrade'
