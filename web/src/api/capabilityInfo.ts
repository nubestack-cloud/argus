// Plain-language grouping/labelling for internal/authz/permissions.go's raw
// capability strings — shared between SettingsPage.tsx's "Roles & access"
// builtin-role reference and CustomRolesCard.tsx's custom-role authoring UI
// (BACKLOG.md S3), which used to be two independent hand-maintained copies of
// almost the same map before custom roles existed to need a second one.
//
// This is a presentation-only concern: there is no "friendly description"
// field in the Go catalogue to read instead, so hand-maintaining group/label
// per capability string can't be avoided — but the risk is bounded, not
// silent. A capability this map doesn't yet recognize (one just added to
// permissions.go) still renders verbatim under "Other" rather than being
// dropped — see groupCapabilities below. Whoever adds a new capability
// constant to permissions.go should add a matching entry here too, but
// forgetting to is a cosmetic gap, not a correctness bug — unlike hand-
// copying the role→capability MAPPING itself, which neither screen does
// (both fetch the real mapping live, from GET /api/v1/roles or a custom
// role's own stored capability_set).

export type CapabilityGroupId =
  | 'incidents'
  | 'remediation'
  | 'policies'
  | 'clusters'
  | 'repos'
  | 'integrations'
  | 'usersAudit'
  | 'spend'
  | 'breakglass'
  | 'orgSettings'

// Display order groups appear in — incidents-and-response concerns first,
// org-wide administration last.
export const CAPABILITY_GROUP_ORDER: CapabilityGroupId[] = [
  'incidents',
  'remediation',
  'policies',
  'clusters',
  'repos',
  'integrations',
  'spend',
  'breakglass',
  'usersAudit',
  'orgSettings',
]

export const CAPABILITY_GROUP_LABELS: Record<CapabilityGroupId, string> = {
  incidents: 'Incidents & analysis',
  remediation: 'Remediation',
  policies: 'Policies',
  clusters: 'Clusters',
  repos: 'Repositories',
  integrations: 'Integrations',
  usersAudit: 'Users & audit',
  spend: 'Spend',
  breakglass: 'Breakglass access',
  orgSettings: 'Organization settings',
}

// One entry per raw capability string in internal/authz/permissions.go's
// catalogue, cross-checked against that file directly (not written from
// memory) as of this writing. agent:upgrade is grouped under "clusters"
// (upgrading the per-cluster agent is a cluster-lifecycle action, the same
// group cluster:onboard/accept/delete already sit in) rather than getting a
// group of its own for one capability. role:manage and cluster:group:manage
// (BACKLOG.md S3) join usersAudit/clusters respectively for the identical
// reason: each is one more administrative action alongside others already in
// that group, not a new subject on its own.
export const CAPABILITY_INFO: Record<string, { group: CapabilityGroupId; label: string }> = {
  'incident:read': { group: 'incidents', label: 'View incidents' },
  'incident:silence': { group: 'incidents', label: 'Silence a noisy incident' },
  'incident:reanalyse': { group: 'incidents', label: 'Trigger a fresh AI investigation' },
  // Was missing from this map's original (SettingsPage-only) copy — CapIncidentTriage
  // has existed in the Go catalogue since incident resolve/dismiss shipped, so it was
  // rendering under "Other" rather than under Incidents. Filled in as part of moving
  // this map here (BACKLOG.md S3), since it was found along the way.
  'incident:triage': { group: 'incidents', label: 'Resolve or dismiss an incident' },
  'analysis:read': { group: 'incidents', label: 'View AI investigation results' },
  'remediation:approve': { group: 'remediation', label: 'Approve a proposed remediation' },
  'remediation:reject': { group: 'remediation', label: 'Reject a proposed remediation' },
  'remediation:execute:inplace': {
    group: 'remediation',
    label: 'Apply a remediation directly to a live cluster',
  },
  'remediation:execute:pr': {
    group: 'remediation',
    label: 'Open a pull request to apply a remediation via GitOps',
  },
  'remediation:rollback': {
    group: 'remediation',
    label: 'Roll back a remediation that was already applied',
  },
  'policy:read': { group: 'policies', label: 'View remediation policies' },
  'policy:write': { group: 'policies', label: 'Create or change remediation policies' },
  'policy:dryrun': { group: 'policies', label: 'Dry-run a policy against past incidents' },
  'cluster:read': { group: 'clusters', label: 'View clusters and their status' },
  'cluster:inspect': { group: 'clusters', label: 'Inspect live objects, events and logs on demand' },
  // PROJECT.md AD3. Grouped with cluster:inspect rather than given a group of
  // its own: it is how a person reads those same clusters from their own AI
  // tool, and it grants no data access by itself.
  'mcp:use': { group: 'clusters', label: 'Use ARGUS from your own AI tools with a personal access token' },
  'cluster:onboard': { group: 'clusters', label: 'Generate a token to enroll a new cluster' },
  'cluster:accept': { group: 'clusters', label: 'Accept a cluster pending approval' },
  'cluster:delete': { group: 'clusters', label: 'Decommission a cluster' },
  'cluster:group:manage': { group: 'clusters', label: 'Create cluster groups and manage their membership' },
  'agent:upgrade': { group: 'clusters', label: 'Upgrade the per-cluster agent version' },
  'repo:read': { group: 'repos', label: 'View connected Git repositories' },
  'repo:write': { group: 'repos', label: 'Connect or configure a Git repository' },
  'integration:read': { group: 'integrations', label: 'View configured integrations' },
  'integration:write': { group: 'integrations', label: 'Configure integrations' },
  'user:read': { group: 'usersAudit', label: 'View users and their role grants' },
  'user:manage': { group: 'usersAudit', label: 'Create users and grant or revoke roles' },
  'user:remove': { group: 'usersAudit', label: 'Remove users from active access' },
  'role:manage': { group: 'usersAudit', label: 'Create and edit custom roles' },
  'audit:read': { group: 'usersAudit', label: 'Read the audit log' },
  'spend:read': { group: 'spend', label: 'View AI/cloud spend' },
  'spend:manage': { group: 'spend', label: 'Set spend budgets and limits' },
  'breakglass:request': {
    group: 'breakglass',
    label: 'Request temporary emergency access to act on an incident',
  },
  'breakglass:approve': { group: 'breakglass', label: "Approve someone else's breakglass request" },
  'org:settings:write': {
    group: 'orgSettings',
    label: 'Change organization-wide settings (AI provider, notifications, retention)',
  },
}

// Buckets a list of raw capability strings into named groups, in
// CAPABILITY_GROUP_ORDER's display order, skipping any group that list has
// nothing in. Anything not found in CAPABILITY_INFO (a capability this
// hand-maintained map hasn't caught up with yet) is collected into a
// trailing "Other" group instead of being silently dropped.
export function groupCapabilities(capabilities: string[]): Array<{ groupLabel: string; items: string[] }> {
  const byGroup = new Map<CapabilityGroupId, string[]>()
  const other: string[] = []
  for (const cap of capabilities) {
    const info = CAPABILITY_INFO[cap]
    if (!info) {
      other.push(cap)
      continue
    }
    const items = byGroup.get(info.group) ?? []
    items.push(info.label)
    byGroup.set(info.group, items)
  }

  const groups = CAPABILITY_GROUP_ORDER.filter((g) => byGroup.has(g)).map((g) => ({
    groupLabel: CAPABILITY_GROUP_LABELS[g],
    items: byGroup.get(g)!,
  }))
  if (other.length > 0) {
    groups.push({ groupLabel: 'Other', items: other })
  }
  return groups
}

// Buckets the raw capability KEYS (not labels) the same way, for a
// checkbox-list author needs (CustomRolesCard.tsx) rather than a read-only
// display list (RoleCard). Capabilities with no CAPABILITY_INFO entry are
// omitted rather than landing in an unlabelled "Other" checkbox — a custom
// role can still be typo-free without this map having caught up, since the
// hub itself (authz.ValidCapabilities) is the real validation.
export function groupedCapabilityOptions(): Array<{ groupLabel: string; items: Array<{ value: string; label: string }> }> {
  const byGroup = new Map<CapabilityGroupId, Array<{ value: string; label: string }>>()
  for (const [value, info] of Object.entries(CAPABILITY_INFO)) {
    const items = byGroup.get(info.group) ?? []
    items.push({ value, label: info.label })
    byGroup.set(info.group, items)
  }
  return CAPABILITY_GROUP_ORDER.filter((g) => byGroup.has(g)).map((g) => ({
    groupLabel: CAPABILITY_GROUP_LABELS[g],
    items: byGroup.get(g)!,
  }))
}

// ---------------------------------------------- human missing-capability copy
//
// Everything above turns a raw capability into a LABEL for a list. These two
// turn it into a SENTENCE for someone who just found a control they cannot use.
//
// The problem they fix: this app's disabled-not-hidden rule (lld/11 §6) was
// implemented everywhere as `title={`Missing capability: ${CAP_X}`}`, so the
// only explanation a blocked operator ever got was a raw wire constant —
// "Missing capability: remediation:execute:inplace". That is the identifier the
// hub checks, not an answer to "why can't I press this", and for two nested
// capabilities it degraded further into a comma-joined pair of them.
//
// Both halves are kept deliberately. The prose says what the operator cannot
// DO; the constant, in parentheses, is what they have to ASK FOR, and dropping
// it would make the message friendlier and useless — a support request for
// "permission to undo things" is not actionable, a request for
// `remediation:rollback` is. Which is also why an unknown capability still
// renders verbatim rather than being swallowed, exactly as groupCapabilities
// above already does for the same reason.

// capabilityAction renders a capability as an infinitive phrase that can follow
// "permission to …" — the CAPABILITY_INFO label with its leading capital
// lowered, since every label in that map starts with a verb ("View incidents",
// "Roll back a remediation that was already applied").
export function capabilityAction(capability: string): string {
  const info = CAPABILITY_INFO[capability]
  if (!info) {
    // Not in the map yet (a capability just added to permissions.go). Say the
    // raw name rather than inventing a description of what it permits.
    return `use "${capability}"`
  }
  return info.label.charAt(0).toLowerCase() + info.label.slice(1)
}

// missingCapabilityMessage is the sentence to put in a tooltip, a disabled
// control's title, or the body of a "you cannot see this" panel.
//
// Takes the capabilities the caller is MISSING — not the ones the route
// requires — so a viewer holding one of a nested pair is told about the one
// they actually lack rather than both.
export function missingCapabilityMessage(missing: string[]): string {
  const named = missing.filter(Boolean)
  if (named.length === 0) {
    // Defensive: a caller that computed an empty list has already decided the
    // control is usable, and a message here would contradict it.
    return ''
  }
  const parts = named.map((capability) => `to ${capabilityAction(capability)} (${capability})`)
  const joined =
    parts.length === 1
      ? parts[0]
      : `${parts.slice(0, -1).join(', ')} or ${parts[parts.length - 1]}`
  const ask = named.length === 1 ? 'Ask an administrator to grant it.' : 'Ask an administrator to grant them.'
  return `You do not have permission ${joined}. ${ask}`
}
